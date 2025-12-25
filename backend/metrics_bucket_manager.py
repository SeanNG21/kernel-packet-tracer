"""
Metrics Bucket Manager - Quản lý việc tạo time-series buckets từ realtime stats

Chức năng:
- Theo dõi snapshot cuối cùng của stats (total_packets, verdicts)
- Tự động tạo bucket mỗi 10 phút
- Flush bucket cuối cùng khi disable (dù <10 phút)
- Sử dụng delta thay vì cumulative
- DIRECT SAVE: Lưu trực tiếp vào aggregator tables (không qua sync):
  + packet_metrics_10m (UTC datetimes)
  + verdict_metrics_10m (UTC datetimes)
"""
import time
import threading
from datetime import datetime
from typing import Dict, Optional

from models import db
from metrics_models import PacketMetrics10m, VerdictMetrics10m


class MetricsBucketManager:
    """
    Quản lý việc tạo buckets 10 phút từ realtime stats

    Flow:
    1. Khi enable: reset snapshot
    2. Mỗi 10 phút: tính delta từ snapshot cuối → tạo bucket → update snapshot
    3. Khi disable: flush bucket cuối (có thể <10 phút)
    """

    BUCKET_INTERVAL_SECONDS = 600  # 10 minutes

    def __init__(self, source='realtime_global'):
        """
        Args:
            source: Identifier cho metrics source (global hoặc session_id)
        """
        self.source = source
        self.lock = threading.Lock()

        # Snapshot state
        self.last_snapshot_time = None  # epoch seconds
        self.last_snapshot_packets = 0
        self.last_snapshot_verdicts = {
            'ACCEPT': 0,
            'DROP': 0,
            'QUEUE': 0,
            'CONTINUE': 0,
            'STOLEN': 0,
            'BREAK': 0,
            'RETURN': 0
        }

        # Tracking
        self.enabled = False
        self.start_time = None  # epoch seconds khi enable

        print(f"[MetricsBucketManager] Initialized for source: {source}")

    def enable(self, current_stats: Dict):
        """
        Bắt đầu tracking metrics (called khi /api/realtime/enable)

        Args:
            current_stats: Current stats từ RealtimeStats.get_summary()
        """
        with self.lock:
            now = time.time()
            self.enabled = True
            self.start_time = now
            self.last_snapshot_time = now

            # Initialize snapshot với current state
            self.last_snapshot_packets = current_stats.get('total_packets', 0)

            # Get current verdicts
            total_verdicts = current_stats.get('total_verdicts', {})
            for verdict in self.last_snapshot_verdicts.keys():
                self.last_snapshot_verdicts[verdict] = total_verdicts.get(verdict, 0)

            print(f"[MetricsBucketManager] Enabled at {datetime.fromtimestamp(now).isoformat()}")
            print(f"  Initial packets: {self.last_snapshot_packets}")
            print(f"  Initial verdicts: {self.last_snapshot_verdicts}")

    def disable(self, current_stats: Dict, app_context):
        """
        Dừng tracking và flush bucket cuối cùng (called khi /api/realtime/disable)

        Args:
            current_stats: Current stats từ RealtimeStats.get_summary()
            app_context: Flask app context để access database
        """
        with self.lock:
            if not self.enabled:
                return

            now = time.time()

            # Flush last bucket (có thể <10 phút)
            self._flush_bucket(
                bucket_start=self.last_snapshot_time,
                bucket_end=now,
                current_stats=current_stats,
                app_context=app_context
            )

            self.enabled = False
            print(f"[MetricsBucketManager] Disabled at {datetime.fromtimestamp(now).isoformat()}")

    def maybe_flush_bucket(self, current_stats: Dict, app_context):
        """
        Kiểm tra và flush bucket nếu đã đủ 10 phút

        Called định kỳ (ví dụ mỗi 1 giây từ broadcast loop)

        Args:
            current_stats: Current stats từ RealtimeStats.get_summary()
            app_context: Flask app context để access database

        Returns:
            bool: True nếu đã flush bucket
        """
        with self.lock:
            if not self.enabled:
                return False

            now = time.time()
            time_since_last_bucket = now - self.last_snapshot_time

            # Chưa đủ 10 phút
            if time_since_last_bucket < self.BUCKET_INTERVAL_SECONDS:
                return False

            # Đủ 10 phút → flush bucket
            bucket_start = self.last_snapshot_time
            bucket_end = bucket_start + self.BUCKET_INTERVAL_SECONDS

            self._flush_bucket(
                bucket_start=bucket_start,
                bucket_end=bucket_end,
                current_stats=current_stats,
                app_context=app_context
            )

            # Update snapshot time để tính bucket tiếp theo
            self.last_snapshot_time = bucket_end

            return True

    def _flush_bucket(self, bucket_start: float, bucket_end: float,
                      current_stats: Dict, app_context):
        """
        Tạo và lưu bucket vào database

        Args:
            bucket_start: Start time (epoch seconds)
            bucket_end: End time (epoch seconds)
            current_stats: Current stats từ RealtimeStats.get_summary()
            app_context: Flask app context
        """
        # Calculate deltas
        current_packets = current_stats.get('total_packets', 0)
        packets_delta = current_packets - self.last_snapshot_packets

        current_verdicts = current_stats.get('total_verdicts', {})
        verdict_deltas = {}
        for verdict in self.last_snapshot_verdicts.keys():
            current_count = current_verdicts.get(verdict, 0)
            last_count = self.last_snapshot_verdicts[verdict]
            verdict_deltas[verdict] = current_count - last_count

        # Không tạo bucket nếu không có data
        if packets_delta == 0 and all(v == 0 for v in verdict_deltas.values()):
            print(f"[MetricsBucketManager] Skipping empty bucket [{datetime.fromtimestamp(bucket_start).isoformat()} - {datetime.fromtimestamp(bucket_end).isoformat()}]")
            return

        # Create database records - DIRECT to aggregator tables
        with app_context.app_context():
            # Convert epoch to UTC datetime
            bucket_start_dt = datetime.utcfromtimestamp(bucket_start)
            bucket_end_dt = datetime.utcfromtimestamp(bucket_end)

            # 1. Save to packet_metrics_10m
            packet_metric = PacketMetrics10m.query.filter_by(
                bucket_start=bucket_start_dt
            ).first()

            if packet_metric:
                # Update existing
                packet_metric.total_packets = packets_delta
                packet_metric.bucket_end = bucket_end_dt
                packet_metric.updated_at = datetime.utcnow()
            else:
                # Create new
                packet_metric = PacketMetrics10m(
                    bucket_start=bucket_start_dt,
                    bucket_end=bucket_end_dt,
                    total_packets=packets_delta
                )
                db.session.add(packet_metric)

            # 2. Save to verdict_metrics_10m
            verdict_metric = VerdictMetrics10m.query.filter_by(
                bucket_start=bucket_start_dt
            ).first()

            if verdict_metric:
                # Update existing
                verdict_metric.bucket_end = bucket_end_dt
                verdict_metric.accept_count = verdict_deltas.get('ACCEPT', 0)
                verdict_metric.drop_count = verdict_deltas.get('DROP', 0)
                verdict_metric.continue_count = verdict_deltas.get('CONTINUE', 0)
                verdict_metric.queue_count = verdict_deltas.get('QUEUE', 0)
                verdict_metric.break_count = verdict_deltas.get('BREAK', 0)
                verdict_metric.return_count = verdict_deltas.get('RETURN', 0)
                verdict_metric.stolen_count = verdict_deltas.get('STOLEN', 0)
                # jump, goto, repeat, stop not tracked in realtime
                verdict_metric.updated_at = datetime.utcnow()
            else:
                # Create new
                verdict_metric = VerdictMetrics10m(
                    bucket_start=bucket_start_dt,
                    bucket_end=bucket_end_dt,
                    accept_count=verdict_deltas.get('ACCEPT', 0),
                    drop_count=verdict_deltas.get('DROP', 0),
                    continue_count=verdict_deltas.get('CONTINUE', 0),
                    queue_count=verdict_deltas.get('QUEUE', 0),
                    break_count=verdict_deltas.get('BREAK', 0),
                    return_count=verdict_deltas.get('RETURN', 0),
                    stolen_count=verdict_deltas.get('STOLEN', 0),
                    jump_count=0,
                    goto_count=0,
                    repeat_count=0,
                    stop_count=0
                )
                db.session.add(verdict_metric)

            # Commit all changes
            db.session.commit()

            print(f"[MetricsBucketManager] ✓ Flushed bucket (DIRECT to aggregator):")
            print(f"  Time: [{datetime.utcfromtimestamp(bucket_start).isoformat()} - {datetime.utcfromtimestamp(bucket_end).isoformat()}] UTC")
            print(f"  Duration: {bucket_end - bucket_start:.1f}s")
            print(f"  Packets: {packets_delta}")
            print(f"  Verdicts: ACCEPT={verdict_deltas['ACCEPT']} DROP={verdict_deltas['DROP']} CONTINUE={verdict_deltas['CONTINUE']}")
            print(f"  ✅ Saved to: packet_metrics_10m")
            print(f"  ✅ Saved to: verdict_metrics_10m")

        # Update snapshot
        self.last_snapshot_packets = current_packets
        for verdict in self.last_snapshot_verdicts.keys():
            self.last_snapshot_verdicts[verdict] = current_verdicts.get(verdict, 0)

    def get_status(self) -> Dict:
        """Get current status of bucket manager"""
        with self.lock:
            if not self.enabled:
                return {'enabled': False}

            now = time.time()
            return {
                'enabled': True,
                'source': self.source,
                'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
                'last_bucket_time': datetime.fromtimestamp(self.last_snapshot_time).isoformat(),
                'time_since_last_bucket': now - self.last_snapshot_time,
                'next_bucket_in': max(0, self.BUCKET_INTERVAL_SECONDS - (now - self.last_snapshot_time)),
                'last_snapshot_packets': self.last_snapshot_packets,
                'last_snapshot_verdicts': dict(self.last_snapshot_verdicts)
            }
