# #!/usr/bin/env python3
# """
# Metrics Aggregation Job - Tổng hợp metrics theo bucket 10 phút

# Chức năng:
# - Đọc raw packet events từ bảng raw_packet_events (hoặc từ realtime extension)
# - Group events theo bucket 10 phút
# - Tổng hợp thành packet_metrics_10m và verdict_metrics_10m
# - Đánh dấu events đã được xử lý

# Cách chạy:
# 1. Manual: python3 metrics_aggregator.py
# 2. Cron: */10 * * * * cd /path/to/backend && python3 metrics_aggregator.py
# 3. APScheduler: tích hợp vào app.py
# """

# import os
# import sys
# import time
# from datetime import datetime, timedelta
# from collections import defaultdict
# from typing import Dict, List, Tuple

# from sqlalchemy import func, and_
# from flask import Flask

# # Import models
# from models import db
# from metrics_models import PacketMetrics10m, VerdictMetrics10m, RawPacketEvent


# # Verdict mapping (same as in app.py and realtime_extension.py)
# VERDICT_MAP = {
#     0: "DROP",      # NF_DROP
#     1: "ACCEPT",    # NF_ACCEPT
#     2: "STOLEN",    # NF_STOLEN
#     3: "QUEUE",     # NF_QUEUE
#     4: "REPEAT",    # NF_REPEAT
#     5: "STOP",      # NF_STOP
#     10: "CONTINUE", # NFT_CONTINUE
#     11: "RETURN",   # NFT_RETURN
#     12: "JUMP",     # NFT_JUMP
#     13: "GOTO",     # NFT_GOTO
#     14: "BREAK",    # NFT_BREAK
# }


# def create_app():
#     """Create Flask app with database configuration"""
#     app = Flask(__name__)

#     # Database configuration (same as in app.py)
#     DB_PATH = os.path.join(os.path.dirname(__file__), "nft_tracer.db")
#     app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
#     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#     # Initialize database
#     db.init_app(app)

#     return app


# def get_bucket_boundaries(dt: datetime) -> Tuple[datetime, datetime]:
#     """
#     Calculate 10-minute bucket boundaries for a given datetime

#     Args:
#         dt: Input datetime

#     Returns:
#         Tuple of (bucket_start, bucket_end)

#     Example:
#         2025-11-26 10:07:32 -> (2025-11-26 10:00:00, 2025-11-26 10:10:00)
#         2025-11-26 10:15:18 -> (2025-11-26 10:10:00, 2025-11-26 10:20:00)
#     """
#     # Round down to nearest 10 minutes
#     minutes = (dt.minute // 10) * 10
#     bucket_start = dt.replace(minute=minutes, second=0, microsecond=0)
#     bucket_end = bucket_start + timedelta(minutes=10)

#     return bucket_start, bucket_end


# def aggregate_from_raw_events(app):
#     """
#     Aggregate metrics from raw_packet_events table

#     This function:
#     1. Fetches unaggregated events from raw_packet_events
#     2. Groups them into 10-minute buckets
#     3. Calculates packet counts and verdict counts
#     4. Saves to packet_metrics_10m and verdict_metrics_10m
#     5. Marks events as aggregated
#     """
#     with app.app_context():
#         print("[*] Starting aggregation from raw_packet_events...")

#         # Fetch unaggregated events
#         unaggregated_events = RawPacketEvent.query.filter_by(is_aggregated=False).all()

#         if not unaggregated_events:
#             print("[i] No unaggregated events found")
#             return

#         print(f"[*] Found {len(unaggregated_events)} unaggregated events")

#         # Group events by bucket
#         buckets_packets = defaultdict(set)  # Use set to avoid counting duplicates
#         buckets_verdicts = defaultdict(lambda: defaultdict(int))

#         for event in unaggregated_events:
#             bucket_start, bucket_end = get_bucket_boundaries(event.timestamp)
#             bucket_key = bucket_start

#             # Count unique packets (by skb_addr or by unique combination)
#             packet_id = event.skb_addr or f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}"
#             buckets_packets[bucket_key].add(packet_id)

#             # Count verdicts
#             if event.verdict is not None:
#                 verdict_str = VERDICT_MAP.get(event.verdict, "UNKNOWN").lower()
#                 buckets_verdicts[bucket_key][verdict_str] += 1

#         # Save aggregated metrics to database
#         now = datetime.utcnow()

#         for bucket_start in sorted(buckets_packets.keys()):
#             bucket_end = bucket_start + timedelta(minutes=10)
#             total_packets = len(buckets_packets[bucket_start])

#             # Update or create PacketMetrics10m
#             packet_metric = PacketMetrics10m.query.filter_by(bucket_start=bucket_start).first()
#             if packet_metric:
#                 packet_metric.total_packets += total_packets
#                 packet_metric.updated_at = now
#             else:
#                 packet_metric = PacketMetrics10m(
#                     bucket_start=bucket_start,
#                     bucket_end=bucket_end,
#                     total_packets=total_packets
#                 )
#                 db.session.add(packet_metric)

#             # Update or create VerdictMetrics10m
#             verdict_metric = VerdictMetrics10m.query.filter_by(bucket_start=bucket_start).first()
#             if verdict_metric:
#                 # Increment counts
#                 verdict_metric.accept_count += buckets_verdicts[bucket_start].get('accept', 0)
#                 verdict_metric.drop_count += buckets_verdicts[bucket_start].get('drop', 0)
#                 verdict_metric.continue_count += buckets_verdicts[bucket_start].get('continue', 0)
#                 verdict_metric.queue_count += buckets_verdicts[bucket_start].get('queue', 0)
#                 verdict_metric.break_count += buckets_verdicts[bucket_start].get('break', 0)
#                 verdict_metric.return_count += buckets_verdicts[bucket_start].get('return', 0)
#                 verdict_metric.jump_count += buckets_verdicts[bucket_start].get('jump', 0)
#                 verdict_metric.goto_count += buckets_verdicts[bucket_start].get('goto', 0)
#                 verdict_metric.stolen_count += buckets_verdicts[bucket_start].get('stolen', 0)
#                 verdict_metric.repeat_count += buckets_verdicts[bucket_start].get('repeat', 0)
#                 verdict_metric.stop_count += buckets_verdicts[bucket_start].get('stop', 0)
#                 verdict_metric.updated_at = now
#             else:
#                 verdict_metric = VerdictMetrics10m(
#                     bucket_start=bucket_start,
#                     bucket_end=bucket_end,
#                     accept_count=buckets_verdicts[bucket_start].get('accept', 0),
#                     drop_count=buckets_verdicts[bucket_start].get('drop', 0),
#                     continue_count=buckets_verdicts[bucket_start].get('continue', 0),
#                     queue_count=buckets_verdicts[bucket_start].get('queue', 0),
#                     break_count=buckets_verdicts[bucket_start].get('break', 0),
#                     return_count=buckets_verdicts[bucket_start].get('return', 0),
#                     jump_count=buckets_verdicts[bucket_start].get('jump', 0),
#                     goto_count=buckets_verdicts[bucket_start].get('goto', 0),
#                     stolen_count=buckets_verdicts[bucket_start].get('stolen', 0),
#                     repeat_count=buckets_verdicts[bucket_start].get('repeat', 0),
#                     stop_count=buckets_verdicts[bucket_start].get('stop', 0)
#                 )
#                 db.session.add(verdict_metric)

#             print(f"[✓] Bucket {bucket_start.isoformat()}: {total_packets} packets, verdicts={dict(buckets_verdicts[bucket_start])}")

#         # Mark all events as aggregated
#         for event in unaggregated_events:
#             event.is_aggregated = True
#             event.aggregated_at = now

#         # Commit all changes
#         db.session.commit()
#         print(f"[✓] Successfully aggregated {len(unaggregated_events)} events into {len(buckets_packets)} buckets")


# def aggregate_from_realtime_extension(app):
#     """
#     Alternative: Aggregate metrics directly from RealtimeExtension's in-memory stats

#     This is more efficient if you don't want to store raw events in DB.
#     Instead, you can periodically aggregate from the realtime extension's memory.

#     NOTE: This requires integration with realtime_extension.py
#     """
#     # TODO: Implement this if you want to aggregate from realtime extension
#     # You would need to:
#     # 1. Import RealtimeExtension
#     # 2. Access its stats/events
#     # 3. Aggregate and clear processed events
#     pass


# def cleanup_old_raw_events(app, days_to_keep=7):
#     """
#     Clean up old raw packet events to prevent database bloat

#     Args:
#         app: Flask app instance
#         days_to_keep: Number of days to keep raw events (default: 7)
#     """
#     with app.app_context():
#         cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

#         # Delete old aggregated events
#         deleted_count = RawPacketEvent.query.filter(
#             and_(
#                 RawPacketEvent.is_aggregated == True,
#                 RawPacketEvent.aggregated_at < cutoff_date
#             )
#         ).delete()

#         db.session.commit()

#         if deleted_count > 0:
#             print(f"[✓] Cleaned up {deleted_count} old raw events (older than {days_to_keep} days)")


# def run_aggregation():
#     """Main aggregation function"""
#     print("=" * 70)
#     print("METRICS AGGREGATION - 10-Minute Buckets")
#     print("=" * 70)
#     print(f"Start time: {datetime.now().isoformat()}")
#     print()

#     app = create_app()

#     try:
#         # Run aggregation
#         aggregate_from_raw_events(app)

#         # Clean up old events (optional)
#         cleanup_old_raw_events(app, days_to_keep=7)

#         print()
#         print("=" * 70)
#         print("[✓] Aggregation completed successfully!")
#         print("=" * 70)

#     except Exception as e:
#         print(f"\n[✗] Aggregation failed: {e}")
#         import traceback
#         traceback.print_exc()
#         sys.exit(1)


# if __name__ == '__main__':
#     run_aggregation()
