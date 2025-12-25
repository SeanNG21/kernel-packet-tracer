#!/usr/bin/env python3
"""
Unified Event Format - Single Source of Truth for Event Schema

This module defines the unified event format used across:
- Realtime tracing (emitted via WebSocket + logged to file)
- Offline full session trace (replayed from event log file)

Key Principles:
1. ONE event schema for both realtime and offline
2. JSON serializable for easy logging and transmission
3. Contains ALL fields needed by SessionStatsTracker.process_event()
4. Backward compatible with existing WebSocket clients

Author: NFT Tracer Team
"""

import json
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class UnifiedEvent:
    """
    Unified event schema for packet tracing.

    This represents a single event in the packet processing pipeline.
    All fields match what SessionStatsTracker.process_event() expects.
    """

    # Timestamp (float, seconds since epoch)
    timestamp: float

    # Session identification
    session_id: str

    # Packet identification
    skb_addr: int  # SKB address (unique packet identifier)

    # Event type (matching BPF constants)
    event_type: int

    # Function/location info
    func_name: Optional[str] = None
    function: Optional[str] = None  # Alias for func_name (for compatibility)

    # Hook info
    hook: int = 255  # Netfilter hook (0-4), 255 = UNKNOWN
    hook_name: str = "UNKNOWN"

    # Layer/Pipeline info
    layer: str = "Unknown"
    trace_type: Optional[str] = None  # "chain_entry", "chain_exit", "rule_eval", etc.

    # Verdict info
    verdict: int = 255  # Raw verdict value
    verdict_name: str = "UNKNOWN"
    verdict_raw: Optional[int] = None

    # Network info
    protocol: int = 0
    src_ip: int = 0
    dst_ip: int = 0
    src_port: int = 0
    dst_port: int = 0

    # Direction
    direction: str = "Unknown"  # "Inbound", "Outbound", "Forward"

    # Error info
    error_code: int = 0

    # NFT-specific fields
    chain_addr: Optional[int] = None
    expr_addr: Optional[int] = None
    chain_depth: int = 0
    rule_seq: Optional[int] = None
    rule_handle: Optional[int] = None
    queue_num: int = 0
    has_queue_bypass: bool = False

    # Process info
    pid: int = 0
    cpu_id: int = 0
    comm: str = ""

    # Packet length
    length: int = 0

    def __post_init__(self):
        """Ensure function field is set for compatibility"""
        if self.function is None and self.func_name is not None:
            self.function = self.func_name
        elif self.func_name is None and self.function is not None:
            self.func_name = self.function

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string (one line, for logging)"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UnifiedEvent':
        """Create event from dictionary (for replay)"""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> 'UnifiedEvent':
        """Create event from JSON string (for replay)"""
        data = json.loads(json_str)
        return cls.from_dict(data)


class EventLogger:
    """
    Event logger for writing unified events to file.

    Used by realtime tracer to log all events for offline replay.
    Format: One JSON event per line (JSONL/NDJSON format).
    """

    def __init__(self, log_file_path: str):
        """
        Initialize event logger.

        Args:
            log_file_path: Path to event log file
        """
        self.log_file_path = log_file_path
        self.file_handle = None
        self.events_logged = 0

    def open(self):
        """Open log file for writing"""
        self.file_handle = open(self.log_file_path, 'w')
        self.events_logged = 0

    def log_event(self, event: UnifiedEvent):
        """
        Log a single event to file.

        Args:
            event: UnifiedEvent to log
        """
        if self.file_handle is None:
            raise RuntimeError("EventLogger not opened. Call open() first.")

        # Write event as single JSON line
        self.file_handle.write(event.to_json() + '\n')
        self.file_handle.flush()  # Ensure immediate write
        self.events_logged += 1

    def close(self):
        """Close log file"""
        if self.file_handle is not None:
            self.file_handle.close()
            self.file_handle = None

    def __enter__(self):
        """Context manager support"""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support"""
        self.close()


class EventReader:
    """
    Event reader for reading unified events from file.

    Used by offline replay to read logged events.
    Format: One JSON event per line (JSONL/NDJSON format).
    """

    def __init__(self, log_file_path: str):
        """
        Initialize event reader.

        Args:
            log_file_path: Path to event log file
        """
        self.log_file_path = log_file_path
        self.file_handle = None
        self.events_read = 0

    def open(self):
        """Open log file for reading"""
        self.file_handle = open(self.log_file_path, 'r')
        self.events_read = 0

    def read_event(self) -> Optional[UnifiedEvent]:
        """
        Read next event from file.

        Returns:
            UnifiedEvent or None if EOF
        """
        if self.file_handle is None:
            raise RuntimeError("EventReader not opened. Call open() first.")

        line = self.file_handle.readline()
        if not line:
            return None  # EOF

        self.events_read += 1
        return UnifiedEvent.from_json(line.strip())

    def read_all_events(self):
        """
        Generator to read all events from file.

        Yields:
            UnifiedEvent instances
        """
        while True:
            event = self.read_event()
            if event is None:
                break
            yield event

    def close(self):
        """Close log file"""
        if self.file_handle is not None:
            self.file_handle.close()
            self.file_handle = None

    def __enter__(self):
        """Context manager support"""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support"""
        self.close()


# ============================================================================
# Helper Functions
# ============================================================================

def ip_to_str(ip_int: int) -> str:
    """Convert integer IP to string (e.g., 167772161 -> '10.0.0.1')"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def create_event_from_bpf(
    session_id: str,
    bpf_event: Any,
    func_name: str,
    hook_name: str,
    layer: str,
    verdict_name: str,
    direction: str,
    trace_type: Optional[str] = None
) -> UnifiedEvent:
    """
    Create UnifiedEvent from BPF event data.

    This is a helper function to convert raw BPF events to unified format.

    Args:
        session_id: Session ID
        bpf_event: Raw BPF event struct
        func_name: Function name (resolved)
        hook_name: Hook name (e.g., "PRE_ROUTING")
        layer: Layer name (e.g., "Netfilter PREROUTING")
        verdict_name: Verdict name (e.g., "ACCEPT", "DROP")
        direction: Direction ("Inbound", "Outbound", "Forward")
        trace_type: Trace type (optional, e.g., "chain_exit")

    Returns:
        UnifiedEvent instance
    """
    return UnifiedEvent(
        timestamp=float(bpf_event.timestamp) / 1_000_000_000.0,  # Convert ns to seconds
        session_id=session_id,
        skb_addr=bpf_event.skb_addr,
        event_type=bpf_event.event_type,
        func_name=func_name,
        function=func_name,
        hook=bpf_event.hook,
        hook_name=hook_name,
        layer=layer,
        trace_type=trace_type,
        verdict=bpf_event.verdict if hasattr(bpf_event, 'verdict') else 255,
        verdict_name=verdict_name,
        verdict_raw=bpf_event.verdict_raw if hasattr(bpf_event, 'verdict_raw') else None,
        protocol=bpf_event.protocol,
        src_ip=bpf_event.src_ip,
        dst_ip=bpf_event.dst_ip,
        src_port=bpf_event.src_port,
        dst_port=bpf_event.dst_port,
        direction=direction,
        error_code=bpf_event.error_code if hasattr(bpf_event, 'error_code') else 0,
        chain_addr=bpf_event.chain_addr if hasattr(bpf_event, 'chain_addr') else None,
        expr_addr=bpf_event.expr_addr if hasattr(bpf_event, 'expr_addr') else None,
        chain_depth=bpf_event.chain_depth if hasattr(bpf_event, 'chain_depth') else 0,
        rule_seq=bpf_event.rule_seq if hasattr(bpf_event, 'rule_seq') else None,
        rule_handle=bpf_event.rule_handle if hasattr(bpf_event, 'rule_handle') else None,
        queue_num=bpf_event.queue_num if hasattr(bpf_event, 'queue_num') else 0,
        has_queue_bypass=bool(bpf_event.has_queue_bypass) if hasattr(bpf_event, 'has_queue_bypass') else False,
        pid=bpf_event.pid if hasattr(bpf_event, 'pid') else 0,
        cpu_id=bpf_event.cpu_id if hasattr(bpf_event, 'cpu_id') else 0,
        comm=bpf_event.comm.decode('utf-8', errors='ignore').strip() if hasattr(bpf_event, 'comm') else "",
        length=bpf_event.length if hasattr(bpf_event, 'length') else 0,
    )
