"""
API Endpoints for Time-Series Metrics

Provides REST API endpoints for querying 10-minute aggregated metrics:
- GET /api/metrics/packets - Packet volume time-series
- GET /api/metrics/verdicts - Verdict statistics time-series
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from sqlalchemy import and_

from models import db
from metrics_models import PacketMetrics10m, VerdictMetrics10m
from auth import token_required


# Create blueprint for metrics API
metrics_bp = Blueprint('metrics', __name__, url_prefix='/api/metrics')


def parse_time_range(from_param, to_param, range_param):
    """
    Parse time range parameters

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


@metrics_bp.route('/packets', methods=['GET'])
@token_required
def get_packet_metrics(user=None):
    """
    Get packet volume time-series data

    Query Parameters:
        - from: ISO timestamp (optional, e.g., "2025-11-26T10:00:00")
        - to: ISO timestamp (optional, e.g., "2025-11-26T12:00:00")
        - range: Relative range (optional, e.g., "1h", "24h", "7d")

    Returns:
        JSON with packet metrics per 10-minute bucket:
        {
            "from": "2025-11-26T10:00:00",
            "to": "2025-11-26T12:00:00",
            "total_buckets": 12,
            "total_packets": 3250,
            "buckets": [
                {
                    "start": "2025-11-26T10:00:00",
                    "end": "2025-11-26T10:10:00",
                    "total_packets": 320
                },
                ...
            ]
        }
    """
    try:
        # Parse time range
        from_param = request.args.get('from')
        to_param = request.args.get('to')
        range_param = request.args.get('range', '2h')  # Default: last 2 hours

        from_dt, to_dt = parse_time_range(from_param, to_param, range_param)

        # Query metrics from database
        metrics = PacketMetrics10m.query.filter(
            and_(
                PacketMetrics10m.bucket_start >= from_dt,
                PacketMetrics10m.bucket_start < to_dt
            )
        ).order_by(PacketMetrics10m.bucket_start).all()

        # Calculate totals
        total_packets = sum(m.total_packets for m in metrics)

        # Format response
        buckets = []
        for metric in metrics:
            buckets.append({
                'start': metric.bucket_start.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
                'end': metric.bucket_end.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
                'total_packets': metric.total_packets
            })

        return jsonify({
            'from': from_dt.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
            'to': to_dt.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
            'total_buckets': len(buckets),
            'total_packets': total_packets,
            'buckets': buckets
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@metrics_bp.route('/verdicts', methods=['GET'])
@token_required
def get_verdict_metrics(user=None):
    """
    Get verdict statistics time-series data

    Query Parameters:
        - from: ISO timestamp (optional)
        - to: ISO timestamp (optional)
        - range: Relative range (optional, e.g., "1h", "24h", "7d")

    Returns:
        JSON with verdict metrics per 10-minute bucket:
        {
            "from": "2025-11-26T10:00:00",
            "to": "2025-11-26T12:00:00",
            "total_buckets": 12,
            "totals": {
                "accept": 2800,
                "drop": 150,
                "continue": 300
            },
            "buckets": [
                {
                    "start": "2025-11-26T10:00:00",
                    "end": "2025-11-26T10:10:00",
                    "accept": 300,
                    "drop": 15,
                    "continue": 5,
                    "queue": 0,
                    ...
                },
                ...
            ]
        }
    """
    try:
        # Parse time range
        from_param = request.args.get('from')
        to_param = request.args.get('to')
        range_param = request.args.get('range', '2h')  # Default: last 2 hours

        from_dt, to_dt = parse_time_range(from_param, to_param, range_param)

        # Query metrics from database
        metrics = VerdictMetrics10m.query.filter(
            and_(
                VerdictMetrics10m.bucket_start >= from_dt,
                VerdictMetrics10m.bucket_start < to_dt
            )
        ).order_by(VerdictMetrics10m.bucket_start).all()

        # Calculate totals
        totals = {
            'accept': sum(m.accept_count for m in metrics),
            'drop': sum(m.drop_count for m in metrics),
            'continue': sum(m.continue_count for m in metrics),
            'queue': sum(m.queue_count for m in metrics),
            'break': sum(m.break_count for m in metrics),
            'return': sum(m.return_count for m in metrics),
            'jump': sum(m.jump_count for m in metrics),
            'goto': sum(m.goto_count for m in metrics),
            'stolen': sum(m.stolen_count for m in metrics),
            'repeat': sum(m.repeat_count for m in metrics),
            'stop': sum(m.stop_count for m in metrics)
        }

        # Format response
        buckets = []
        for metric in metrics:
            buckets.append({
                'start': metric.bucket_start.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
                'end': metric.bucket_end.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
                'accept': metric.accept_count,
                'drop': metric.drop_count,
                'continue': metric.continue_count,
                'queue': metric.queue_count,
                'break': metric.break_count,
                'return': metric.return_count,
                'jump': metric.jump_count,
                'goto': metric.goto_count,
                'stolen': metric.stolen_count,
                'repeat': metric.repeat_count,
                'stop': metric.stop_count
            })

        return jsonify({
            'from': from_dt.isoformat() + 'Z',  # Add 'Z' suffix to indicate UTC
            'to': to_dt.isoformat() + 'Z',      # Add 'Z' suffix to indicate UTC
            'total_buckets': len(buckets),
            'totals': totals,
            'buckets': buckets
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@metrics_bp.route('/summary', methods=['GET'])
@token_required
def get_metrics_summary(user=None):
    """
    Get summary statistics for metrics

    Query Parameters:
        - range: Relative range (optional, e.g., "1h", "24h", "7d")

    Returns:
        JSON with summary statistics:
        {
            "range": "2h",
            "from": "...",
            "to": "...",
            "total_packets": 3250,
            "total_verdicts": {
                "accept": 2800,
                "drop": 150,
                "continue": 300
            },
            "avg_packets_per_bucket": 270.8,
            "peak_packets_bucket": {
                "start": "...",
                "packets": 450
            }
        }
    """
    try:
        # Parse time range
        range_param = request.args.get('range', '2h')
        from_dt, to_dt = parse_time_range(None, None, range_param)

        # Query packet metrics
        packet_metrics = PacketMetrics10m.query.filter(
            and_(
                PacketMetrics10m.bucket_start >= from_dt,
                PacketMetrics10m.bucket_start < to_dt
            )
        ).order_by(PacketMetrics10m.bucket_start).all()

        # Query verdict metrics
        verdict_metrics = VerdictMetrics10m.query.filter(
            and_(
                VerdictMetrics10m.bucket_start >= from_dt,
                VerdictMetrics10m.bucket_start < to_dt
            )
        ).order_by(VerdictMetrics10m.bucket_start).all()

        # Calculate statistics
        total_packets = sum(m.total_packets for m in packet_metrics)
        total_buckets = len(packet_metrics)
        avg_packets = total_packets / total_buckets if total_buckets > 0 else 0

        # Find peak bucket
        peak_bucket = None
        if packet_metrics:
            peak_metric = max(packet_metrics, key=lambda m: m.total_packets)
            peak_bucket = {
                'start': peak_metric.bucket_start.isoformat(),
                'packets': peak_metric.total_packets
            }

        # Calculate verdict totals
        total_verdicts = {
            'accept': sum(m.accept_count for m in verdict_metrics),
            'drop': sum(m.drop_count for m in verdict_metrics),
            'continue': sum(m.continue_count for m in verdict_metrics),
            'queue': sum(m.queue_count for m in verdict_metrics),
            'other': sum(
                m.break_count + m.return_count + m.jump_count + m.goto_count +
                m.stolen_count + m.repeat_count + m.stop_count
                for m in verdict_metrics
            )
        }

        return jsonify({
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


def register_metrics_api(app):
    """
    Register metrics API blueprint with Flask app

    Args:
        app: Flask application instance
    """
    app.register_blueprint(metrics_bp)
    print("[✓] Metrics API endpoints registered")
