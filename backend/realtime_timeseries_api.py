"""
API Endpoints for Realtime Time-Series Metrics

Provides REST API endpoints for querying realtime metrics (10-minute buckets):
- GET /api/metrics/realtime/packets - Packet volume from realtime tracer
- GET /api/metrics/realtime/verdicts - Verdict statistics from realtime tracer
- GET /api/metrics/realtime/summary - Summary statistics

Priority: These endpoints take precedence over aggregation-based metrics
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from sqlalchemy import and_

from models import db
from realtime_timeseries_models import RealtimeTimeseriesMetric
from auth import token_required


# Create blueprint for realtime metrics API
realtime_metrics_bp = Blueprint('realtime_metrics', __name__, url_prefix='/api/metrics/realtime')


def parse_time_range(from_param, to_param, range_param):
    """
    Parse time range parameters (same logic as metrics_api.py)

    Args:
        from_param: ISO timestamp string or None
        to_param: ISO timestamp string or None
        range_param: Relative range like "1h", "24h", "7d" or None

    Returns:
        Tuple of (from_datetime, to_datetime)
    """
    now = datetime.utcnow()

    # If range parameter is provided, use it
    if range_param:
        range_param = range_param.lower()

        # Parse range like "1h", "24h", "7d"
        if range_param.endswith('h'):
            hours = int(range_param[:-1])
            from_dt = now - timedelta(hours=hours)
            to_dt = now
        elif range_param.endswith('d'):
            days = int(range_param[:-1])
            from_dt = now - timedelta(days=days)
            to_dt = now
        elif range_param.endswith('m'):
            minutes = int(range_param[:-1])
            from_dt = now - timedelta(minutes=minutes)
            to_dt = now
        else:
            # Default to 2 hours
            from_dt = now - timedelta(hours=2)
            to_dt = now

        return from_dt, to_dt

    # Otherwise, use from/to parameters
    if from_param:
        try:
            from_dt = datetime.fromisoformat(from_param.replace('Z', '+00:00'))
        except:
            from_dt = now - timedelta(hours=2)
    else:
        from_dt = now - timedelta(hours=2)

    if to_param:
        try:
            to_dt = datetime.fromisoformat(to_param.replace('Z', '+00:00'))
        except:
            to_dt = now
    else:
        to_dt = now

    return from_dt, to_dt


@realtime_metrics_bp.route('/packets', methods=['GET'])
@token_required
def get_realtime_packet_metrics(user=None):
    """
    Get packet volume time-series from realtime tracer

    Query Parameters:
        - from: ISO timestamp (optional)
        - to: ISO timestamp (optional)
        - range: Relative range (optional, e.g., "1h", "24h", "7d")
        - source: Metrics source (optional, default: "realtime_global")

    Returns:
        JSON with packet metrics per 10-minute bucket
    """
    try:
        # Parse time range
        from_param = request.args.get('from')
        to_param = request.args.get('to')
        range_param = request.args.get('range', '2h')
        source = request.args.get('source', 'realtime_global')

        from_dt, to_dt = parse_time_range(from_param, to_param, range_param)

        # Convert to epoch seconds
        from_ts = int(from_dt.timestamp())
        to_ts = int(to_dt.timestamp())

        # Query metrics from database
        metrics = RealtimeTimeseriesMetric.query.filter(
            and_(
                RealtimeTimeseriesMetric.source == source,
                RealtimeTimeseriesMetric.bucket_start_ts >= from_ts,
                RealtimeTimeseriesMetric.bucket_start_ts < to_ts
            )
        ).order_by(RealtimeTimeseriesMetric.bucket_start_ts).all()

        # Calculate totals
        total_packets = sum(m.total_packets for m in metrics)

        # Format response
        buckets = []
        for metric in metrics:
            buckets.append({
                'start': datetime.utcfromtimestamp(metric.bucket_start_ts).isoformat() + 'Z',  # FIXED: Use UTC and add 'Z' suffix
                'end': datetime.utcfromtimestamp(metric.bucket_end_ts).isoformat() + 'Z',      # FIXED: Use UTC and add 'Z' suffix
                'total_packets': metric.total_packets
            })

        return jsonify({
            'source': 'realtime_tracer',  # Indicate this is from realtime tracer
            'from': from_dt.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
            'to': to_dt.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
            'total_buckets': len(buckets),
            'total_packets': total_packets,
            'buckets': buckets
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@realtime_metrics_bp.route('/verdicts', methods=['GET'])
@token_required
def get_realtime_verdict_metrics(user=None):
    """
    Get verdict statistics time-series from realtime tracer

    Query Parameters:
        - from: ISO timestamp (optional)
        - to: ISO timestamp (optional)
        - range: Relative range (optional, e.g., "1h", "24h", "7d")
        - source: Metrics source (optional, default: "realtime_global")

    Returns:
        JSON with verdict metrics per 10-minute bucket
    """
    try:
        # Parse time range
        from_param = request.args.get('from')
        to_param = request.args.get('to')
        range_param = request.args.get('range', '2h')
        source = request.args.get('source', 'realtime_global')

        from_dt, to_dt = parse_time_range(from_param, to_param, range_param)

        # Convert to epoch seconds
        from_ts = int(from_dt.timestamp())
        to_ts = int(to_dt.timestamp())

        # Query metrics from database
        metrics = RealtimeTimeseriesMetric.query.filter(
            and_(
                RealtimeTimeseriesMetric.source == source,
                RealtimeTimeseriesMetric.bucket_start_ts >= from_ts,
                RealtimeTimeseriesMetric.bucket_start_ts < to_ts
            )
        ).order_by(RealtimeTimeseriesMetric.bucket_start_ts).all()

        # Calculate totals
        totals = {
            'accept': sum(m.verdict_accept for m in metrics),
            'drop': sum(m.verdict_drop for m in metrics),
            'continue': sum(m.verdict_continue for m in metrics),
            'queue': sum(m.verdict_queue for m in metrics),
            'stolen': sum(m.verdict_stolen for m in metrics),
            'break': sum(m.verdict_break for m in metrics),
            'return': sum(m.verdict_return for m in metrics)
        }

        # Format response
        buckets = []
        for metric in metrics:
            buckets.append({
                'start': datetime.utcfromtimestamp(metric.bucket_start_ts).isoformat() + 'Z',  # FIXED: Use UTC and add 'Z' suffix
                'end': datetime.utcfromtimestamp(metric.bucket_end_ts).isoformat() + 'Z',      # FIXED: Use UTC and add 'Z' suffix
                'accept': metric.verdict_accept,
                'drop': metric.verdict_drop,
                'continue': metric.verdict_continue,
                'queue': metric.verdict_queue,
                'stolen': metric.verdict_stolen,
                'break': metric.verdict_break,
                'return': metric.verdict_return
            })

        return jsonify({
            'source': 'realtime_tracer',  # Indicate this is from realtime tracer
            'from': from_dt.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
            'to': to_dt.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
            'total_buckets': len(buckets),
            'totals': totals,
            'buckets': buckets
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@realtime_metrics_bp.route('/summary', methods=['GET'])
@token_required
def get_realtime_metrics_summary(user=None):
    """
    Get summary statistics for realtime metrics

    Query Parameters:
        - range: Relative range (optional, e.g., "1h", "24h", "7d")
        - source: Metrics source (optional, default: "realtime_global")

    Returns:
        JSON with summary statistics
    """
    try:
        # Parse time range
        range_param = request.args.get('range', '2h')
        source = request.args.get('source', 'realtime_global')

        from_dt, to_dt = parse_time_range(None, None, range_param)

        # Convert to epoch seconds
        from_ts = int(from_dt.timestamp())
        to_ts = int(to_dt.timestamp())

        # Query metrics
        metrics = RealtimeTimeseriesMetric.query.filter(
            and_(
                RealtimeTimeseriesMetric.source == source,
                RealtimeTimeseriesMetric.bucket_start_ts >= from_ts,
                RealtimeTimeseriesMetric.bucket_start_ts < to_ts
            )
        ).order_by(RealtimeTimeseriesMetric.bucket_start_ts).all()

        # Calculate statistics
        total_packets = sum(m.total_packets for m in metrics)
        total_buckets = len(metrics)
        avg_packets = total_packets / total_buckets if total_buckets > 0 else 0

        # Find peak bucket
        peak_bucket = None
        if metrics:
            peak_metric = max(metrics, key=lambda m: m.total_packets)
            peak_bucket = {
                'start': datetime.fromtimestamp(peak_metric.bucket_start_ts).isoformat(),
                'packets': peak_metric.total_packets
            }

        # Calculate verdict totals
        total_verdicts = {
            'accept': sum(m.verdict_accept for m in metrics),
            'drop': sum(m.verdict_drop for m in metrics),
            'continue': sum(m.verdict_continue for m in metrics),
            'queue': sum(m.verdict_queue for m in metrics),
            'other': sum(
                m.verdict_stolen + m.verdict_break + m.verdict_return
                for m in metrics
            )
        }

        return jsonify({
            'source': 'realtime_tracer',
            'range': range_param,
            'from': from_dt.isoformat(),
            'to': to_dt.isoformat(),
            'total_packets': total_packets,
            'total_verdicts': total_verdicts,
            'avg_packets_per_bucket': round(avg_packets, 2),
            'peak_packets_bucket': peak_bucket
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@realtime_metrics_bp.route('/status', methods=['GET'])
@token_required
def get_realtime_metrics_status(user=None):
    """
    Get status of realtime metrics collection

    Returns:
        JSON with status information
    """
    try:
        source = request.args.get('source', 'realtime_global')

        # Get latest bucket
        latest = RealtimeTimeseriesMetric.query.filter_by(source=source).order_by(
            RealtimeTimeseriesMetric.bucket_start_ts.desc()
        ).first()

        # Get oldest bucket
        oldest = RealtimeTimeseriesMetric.query.filter_by(source=source).order_by(
            RealtimeTimeseriesMetric.bucket_start_ts.asc()
        ).first()

        # Count total buckets
        total_buckets = RealtimeTimeseriesMetric.query.filter_by(source=source).count()

        return jsonify({
            'source': source,
            'total_buckets': total_buckets,
            'has_data': total_buckets > 0,
            'latest_bucket': {
                'start': datetime.fromtimestamp(latest.bucket_start_ts).isoformat(),
                'end': datetime.fromtimestamp(latest.bucket_end_ts).isoformat(),
                'packets': latest.total_packets
            } if latest else None,
            'oldest_bucket': {
                'start': datetime.fromtimestamp(oldest.bucket_start_ts).isoformat(),
                'end': datetime.fromtimestamp(oldest.bucket_end_ts).isoformat()
            } if oldest else None,
            'data_range_hours': (latest.bucket_end_ts - oldest.bucket_start_ts) / 3600 if (latest and oldest) else 0
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def register_realtime_metrics_api(app):
    """
    Register realtime metrics API blueprint with Flask app

    Args:
        app: Flask application instance
    """
    app.register_blueprint(realtime_metrics_bp)
    print("[✓] Realtime metrics API endpoints registered")
