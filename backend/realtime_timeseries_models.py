"""
Realtime Timeseries Metrics Models

Lưu trữ metrics từ realtime tracer theo bucket 10 phút
Data được tự động flush khi:
- Đủ 10 phút kể từ bucket trước
- User disable realtime trace
"""
from datetime import datetime
from models import db


class RealtimeTimeseriesMetric(db.Model):
    """
    Time-series metrics từ realtime tracer (10-minute buckets)

    Khác với packet_metrics_10m (aggregation-based):
    - Data này được tạo TRỰC TIẾP từ RealtimeTracer khi trace đang chạy
    - Không cần chạy aggregator riêng
    - Flush tự động mỗi 10 phút hoặc khi disable
    """
    __tablename__ = 'realtime_timeseries_metrics'

    id = db.Column(db.Integer, primary_key=True)

    # Source của metrics (global hoặc session-specific)
    source = db.Column(db.String(128), nullable=False, default='realtime_global', index=True)

    # Bucket time boundaries (epoch seconds)
    bucket_start_ts = db.Column(db.Integer, nullable=False, index=True)
    bucket_end_ts = db.Column(db.Integer, nullable=False, index=True)

    # Packet metrics (per-interval, NOT cumulative)
    total_packets = db.Column(db.Integer, nullable=False, default=0)

    # Verdict breakdown (per-interval, NOT cumulative)
    verdict_accept = db.Column(db.Integer, nullable=False, default=0)
    verdict_drop = db.Column(db.Integer, nullable=False, default=0)
    verdict_queue = db.Column(db.Integer, nullable=False, default=0)
    verdict_continue = db.Column(db.Integer, nullable=False, default=0)
    verdict_stolen = db.Column(db.Integer, nullable=False, default=0)
    verdict_break = db.Column(db.Integer, nullable=False, default=0)
    verdict_return = db.Column(db.Integer, nullable=False, default=0)

    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<RealtimeTimeseriesMetric {self.source} [{self.bucket_start_ts}-{self.bucket_end_ts}]: {self.total_packets}p>'

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'source': self.source,
            'bucket_start': datetime.fromtimestamp(self.bucket_start_ts).isoformat(),
            'bucket_end': datetime.fromtimestamp(self.bucket_end_ts).isoformat(),
            'bucket_start_ts': self.bucket_start_ts,
            'bucket_end_ts': self.bucket_end_ts,
            'total_packets': self.total_packets,
            'verdict_accept': self.verdict_accept,
            'verdict_drop': self.verdict_drop,
            'verdict_queue': self.verdict_queue,
            'verdict_continue': self.verdict_continue,
            'verdict_stolen': self.verdict_stolen,
            'verdict_break': self.verdict_break,
            'verdict_return': self.verdict_return,
            'created_at': self.created_at.isoformat()
        }
