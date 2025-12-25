#!/usr/bin/env python3
"""
Sync Realtime Metrics to Aggregator Tables

Script này đồng bộ dữ liệu từ bảng realtime_timeseries_metrics
sang hai bảng aggregator (packet_metrics_10m và verdict_metrics_10m)

Use cases:
1. Chạy thủ công: python3 sync_realtime_to_aggregator.py
2. Tích hợp vào cron: */10 * * * * cd /path/to/backend && python3 sync_realtime_to_aggregator.py
3. Gọi từ code: from sync_realtime_to_aggregator import sync_realtime_to_10m; sync_realtime_to_10m(app)
"""

from datetime import datetime
from models import db
from metrics_models import PacketMetrics10m, VerdictMetrics10m
from realtime_timeseries_models import RealtimeTimeseriesMetric


def sync_realtime_to_10m(app, source_filter='realtime_global', dry_run=False):
    """
    Đồng bộ dữ liệu từ realtime_timeseries_metrics sang packet_metrics_10m và verdict_metrics_10m

    Args:
        app: Flask application instance (for app context)
        source_filter: Chỉ sync data từ source này (default: 'realtime_global')
        dry_run: Nếu True, chỉ in ra thông tin mà không commit vào DB

    Returns:
        dict: Thống kê kết quả sync {
            'total_realtime_buckets': int,
            'packet_buckets_created': int,
            'packet_buckets_updated': int,
            'verdict_buckets_created': int,
            'verdict_buckets_updated': int,
            'errors': []
        }
    """
    with app.app_context():
        stats = {
            'total_realtime_buckets': 0,
            'packet_buckets_created': 0,
            'packet_buckets_updated': 0,
            'verdict_buckets_created': 0,
            'verdict_buckets_updated': 0,
            'errors': []
        }

        print(f"\n{'='*60}")
        print(f"🔄 SYNC REALTIME METRICS → AGGREGATOR TABLES")
        print(f"{'='*60}")
        print(f"Source filter: {source_filter}")
        print(f"Dry run: {dry_run}")
        print()

        # Query tất cả realtime metrics (chưa sync hoặc cần update)
        realtime_metrics = RealtimeTimeseriesMetric.query.filter_by(
            source=source_filter
        ).order_by(
            RealtimeTimeseriesMetric.bucket_start_ts
        ).all()

        stats['total_realtime_buckets'] = len(realtime_metrics)

        if not realtime_metrics:
            print("⚠️  No realtime metrics found to sync")
            return stats

        print(f"📊 Found {len(realtime_metrics)} realtime metric buckets to sync\n")

        # Process từng bucket
        for idx, rt_metric in enumerate(realtime_metrics, 1):
            try:
                # Convert epoch timestamps to datetime (MUST use UTC!)
                bucket_start_dt = datetime.utcfromtimestamp(rt_metric.bucket_start_ts)
                bucket_end_dt = datetime.utcfromtimestamp(rt_metric.bucket_end_ts)

                # Duration for logging
                duration = rt_metric.bucket_end_ts - rt_metric.bucket_start_ts

                print(f"[{idx}/{len(realtime_metrics)}] Processing bucket:")
                print(f"  Time: {bucket_start_dt} → {bucket_end_dt} ({duration}s)")
                print(f"  Packets: {rt_metric.total_packets}")
                print(f"  Verdicts: A={rt_metric.verdict_accept} D={rt_metric.verdict_drop} C={rt_metric.verdict_continue}")

                # ============================================================
                # 1. Sync to PacketMetrics10m
                # ============================================================
                packet_metric = PacketMetrics10m.query.filter_by(
                    bucket_start=bucket_start_dt
                ).first()

                if packet_metric:
                    # Update existing
                    old_count = packet_metric.total_packets
                    packet_metric.total_packets = rt_metric.total_packets
                    packet_metric.bucket_end = bucket_end_dt
                    packet_metric.updated_at = datetime.utcnow()

                    stats['packet_buckets_updated'] += 1
                    print(f"  ✏️  Updated PacketMetrics10m (ID={packet_metric.id}): {old_count} → {rt_metric.total_packets} packets")
                else:
                    # Create new
                    packet_metric = PacketMetrics10m(
                        bucket_start=bucket_start_dt,
                        bucket_end=bucket_end_dt,
                        total_packets=rt_metric.total_packets
                    )
                    db.session.add(packet_metric)

                    stats['packet_buckets_created'] += 1
                    print(f"  ✅ Created PacketMetrics10m: {rt_metric.total_packets} packets")

                # ============================================================
                # 2. Sync to VerdictMetrics10m
                # ============================================================
                verdict_metric = VerdictMetrics10m.query.filter_by(
                    bucket_start=bucket_start_dt
                ).first()

                if verdict_metric:
                    # Update existing
                    verdict_metric.bucket_end = bucket_end_dt
                    verdict_metric.accept_count = rt_metric.verdict_accept
                    verdict_metric.drop_count = rt_metric.verdict_drop
                    verdict_metric.continue_count = rt_metric.verdict_continue
                    verdict_metric.queue_count = rt_metric.verdict_queue
                    verdict_metric.break_count = rt_metric.verdict_break
                    verdict_metric.return_count = rt_metric.verdict_return
                    verdict_metric.stolen_count = rt_metric.verdict_stolen
                    # Note: realtime model doesn't have jump/goto/repeat/stop, keep existing values
                    verdict_metric.updated_at = datetime.utcnow()

                    stats['verdict_buckets_updated'] += 1
                    print(f"  ✏️  Updated VerdictMetrics10m (ID={verdict_metric.id})")
                else:
                    # Create new
                    verdict_metric = VerdictMetrics10m(
                        bucket_start=bucket_start_dt,
                        bucket_end=bucket_end_dt,
                        accept_count=rt_metric.verdict_accept,
                        drop_count=rt_metric.verdict_drop,
                        continue_count=rt_metric.verdict_continue,
                        queue_count=rt_metric.verdict_queue,
                        break_count=rt_metric.verdict_break,
                        return_count=rt_metric.verdict_return,
                        stolen_count=rt_metric.verdict_stolen,
                        # Fields not in realtime model (set to 0)
                        jump_count=0,
                        goto_count=0,
                        repeat_count=0,
                        stop_count=0
                    )
                    db.session.add(verdict_metric)

                    stats['verdict_buckets_created'] += 1
                    print(f"  ✅ Created VerdictMetrics10m")

                print()

            except Exception as e:
                error_msg = f"Error processing bucket {rt_metric.id}: {str(e)}"
                stats['errors'].append(error_msg)
                print(f"  ❌ {error_msg}\n")
                continue

        # Commit hoặc rollback nếu dry run
        if dry_run:
            db.session.rollback()
            print("🔍 DRY RUN - No changes committed to database")
        else:
            try:
                db.session.commit()
                print("✅ All changes committed successfully!")
            except Exception as e:
                db.session.rollback()
                error_msg = f"Failed to commit changes: {str(e)}"
                stats['errors'].append(error_msg)
                print(f"❌ {error_msg}")

        # Print summary
        print(f"\n{'='*60}")
        print(f"📊 SYNC SUMMARY")
        print(f"{'='*60}")
        print(f"Total realtime buckets processed: {stats['total_realtime_buckets']}")
        print(f"\nPacketMetrics10m:")
        print(f"  Created: {stats['packet_buckets_created']}")
        print(f"  Updated: {stats['packet_buckets_updated']}")
        print(f"\nVerdictMetrics10m:")
        print(f"  Created: {stats['verdict_buckets_created']}")
        print(f"  Updated: {stats['verdict_buckets_updated']}")

        if stats['errors']:
            print(f"\n⚠️  Errors: {len(stats['errors'])}")
            for err in stats['errors']:
                print(f"  - {err}")
        else:
            print(f"\n✨ No errors!")

        print(f"{'='*60}\n")

        return stats


def main():
    """Run sync as standalone script"""
    import sys
    from app import app

    # Parse command line arguments
    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv
    source = 'realtime_global'

    # Allow custom source filter
    for arg in sys.argv:
        if arg.startswith('--source='):
            source = arg.split('=')[1]

    # Run sync
    stats = sync_realtime_to_10m(app, source_filter=source, dry_run=dry_run)

    # Exit with error code if there were errors
    sys.exit(1 if stats['errors'] else 0)


if __name__ == '__main__':
    main()
