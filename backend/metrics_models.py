"""
Database models for time-series metrics (10-minute buckets)
"""
from datetime import datetime, timedelta
from models import db


class PacketMetrics10m(db.Model):
    """Packet count metrics aggregated per 10-minute bucket"""
    __tablename__ = 'packet_metrics_10m'

    id = db.Column(db.Integer, primary_key=True)
    bucket_start = db.Column(db.DateTime, nullable=False, unique=True, index=True)
    bucket_end = db.Column(db.DateTime, nullable=False, index=True)
    total_packets = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'bucket_start': self.bucket_start.isoformat(),
            'bucket_end': self.bucket_end.isoformat(),
            'total_packets': self.total_packets,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    def __repr__(self):
        return f'<PacketMetrics10m {self.bucket_start} - {self.bucket_end}: {self.total_packets} packets>'


class VerdictMetrics10m(db.Model):
    """Verdict statistics aggregated per 10-minute bucket"""
    __tablename__ = 'verdict_metrics_10m'

    id = db.Column(db.Integer, primary_key=True)
    bucket_start = db.Column(db.DateTime, nullable=False, unique=True, index=True)
    bucket_end = db.Column(db.DateTime, nullable=False, index=True)

    # Main verdicts (most commonly used)
    accept_count = db.Column(db.Integer, nullable=False, default=0)
    drop_count = db.Column(db.Integer, nullable=False, default=0)
    continue_count = db.Column(db.Integer, nullable=False, default=0)

    # Additional verdicts (optional, less common)
    queue_count = db.Column(db.Integer, nullable=False, default=0)
    break_count = db.Column(db.Integer, nullable=False, default=0)
    return_count = db.Column(db.Integer, nullable=False, default=0)
    jump_count = db.Column(db.Integer, nullable=False, default=0)
    goto_count = db.Column(db.Integer, nullable=False, default=0)
    stolen_count = db.Column(db.Integer, nullable=False, default=0)
    repeat_count = db.Column(db.Integer, nullable=False, default=0)
    stop_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'bucket_start': self.bucket_start.isoformat(),
            'bucket_end': self.bucket_end.isoformat(),
            'accept': self.accept_count,
            'drop': self.drop_count,
            'continue': self.continue_count,
            'queue': self.queue_count,
            'break': self.break_count,
            'return': self.return_count,
            'jump': self.jump_count,
            'goto': self.goto_count,
            'stolen': self.stolen_count,
            'repeat': self.repeat_count,
            'stop': self.stop_count,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    def __repr__(self):
        return f'<VerdictMetrics10m {self.bucket_start} - {self.bucket_end}: A={self.accept_count} D={self.drop_count} C={self.continue_count}>'


class RawPacketEvent(db.Model):
    """
    Raw packet events from eBPF tracer (temporary storage before aggregation)
    This table stores individual packet events that will be aggregated into 10-minute buckets
    """
    __tablename__ = 'raw_packet_events'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    session_id = db.Column(db.String(128), nullable=False, index=True)

    # Packet info
    skb_addr = db.Column(db.String(64), nullable=True)
    protocol = db.Column(db.Integer, nullable=True)
    src_ip = db.Column(db.String(45), nullable=True)
    dst_ip = db.Column(db.String(45), nullable=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)

    # Netfilter info
    hook = db.Column(db.Integer, nullable=True)
    verdict = db.Column(db.Integer, nullable=True)

    # Processing status
    is_aggregated = db.Column(db.Boolean, default=False, nullable=False, index=True)
    aggregated_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'session_id': self.session_id,
            'skb_addr': self.skb_addr,
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'hook': self.hook,
            'verdict': self.verdict,
            'is_aggregated': self.is_aggregated,
            'aggregated_at': self.aggregated_at.isoformat() if self.aggregated_at else None,
            'created_at': self.created_at.isoformat()
        }

    def __repr__(self):
        return f'<RawPacketEvent {self.id} {self.timestamp} session={self.session_id}>'
