#!/usr/bin/env python3
"""
Session Stats Engine - Shared Engine for Realtime and Offline Tracing

This module provides a unified stats engine that can be used by both:
1. Realtime tracing (process events from BPF, emit to WebSocket, log to file)
2. Offline replay (read events from file, rebuild stats)

Key Principles:
1. Uses SessionStatsTracker as the single source of truth for stats logic
2. Accepts UnifiedEvent format for consistency
3. Provides same API for both realtime and offline modes
4. Ensures 100% identical stats between realtime and offline

Author: NFT Tracer Team
"""

import time
import threading
from typing import Dict, Any, Optional
from collections import defaultdict, deque

# Import unified event format
from unified_event import UnifiedEvent, EventLogger

# Import SessionStatsTracker from realtime_extension
# NOTE: We import the ENTIRE SessionStatsTracker logic to ensure consistency
from realtime_extension import (
    SessionStatsTracker,
    PacketEvent,
    # Constants (INBOUND)
    EVENT_TYPE_FUNCTION_CALL, EVENT_TYPE_NFT_CHAIN, EVENT_TYPE_NFT_RULE,
    EVENT_TYPE_NF_VERDICT, EVENT_TYPE_GRO_IN, EVENT_TYPE_TC_IN,
    EVENT_TYPE_TC_VERDICT,
    EVENT_TYPE_CT_IN, EVENT_TYPE_CT_VERDICT, EVENT_TYPE_ROUTE_IN,
    EVENT_TYPE_ROUTE_VERDICT, EVENT_TYPE_TCP_IN, EVENT_TYPE_TCP_DROP,
    EVENT_TYPE_UDP_IN, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_TCP_IN,
    EVENT_TYPE_SOCK_UDP_IN, EVENT_TYPE_SOCK_DROP,
    # Constants (OUTBOUND)
    EVENT_TYPE_APP_TCP_SEND, EVENT_TYPE_APP_UDP_SEND, EVENT_TYPE_TCP_OUT,
    EVENT_TYPE_UDP_OUT, EVENT_TYPE_ROUTE_OUT_LOOKUP, EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT,
    EVENT_TYPE_ROUTE_OUT, EVENT_TYPE_ROUTE_OUT_DISCARD, EVENT_TYPE_TC_EGRESS_IN,
    EVENT_TYPE_TC_EGRESS_VERDICT, EVENT_TYPE_DRIVER_TX, EVENT_TYPE_DRIVER_TX_FAIL,
)

# Import pipeline model constants
from pipeline_model import (
    VERDICT_MAP, HOOK_MAP, PROTO_MAP,
    FUNCTION_TO_LAYER, EVENT_TYPE_TO_LAYER,
)


class SessionEngine:
    """
    Unified session stats engine.

    This engine wraps SessionStatsTracker and provides:
    - Unified event processing (via UnifiedEvent format)
    - Event logging (for offline replay)
    - Stats API (compatible with existing frontend)
    """

    def __init__(self, session_id: str, mode: str = "full", enable_logging: bool = True, log_file_path: Optional[str] = None):
        """
        Initialize session engine.

        Args:
            session_id: Unique session identifier
            mode: Tracing mode ("nft", "full", "multifunction")
            enable_logging: Whether to log events to file (default: True)
            log_file_path: Path to event log file (default: data/output/<session_id>_events.jsonl)
        """
        self.session_id = session_id
        self.mode = mode
        self.enable_logging = enable_logging

        # Initialize SessionStatsTracker (single source of truth)
        self.stats_tracker = SessionStatsTracker(session_id=session_id, mode=mode)

        # Event logger
        self.event_logger = None
        if enable_logging:
            if log_file_path is None:
                import os
                log_file_path = os.path.join(
                    os.path.dirname(__file__),
                    "data",
                    "output",
                    f"{session_id}_events.jsonl"
                )
            self.log_file_path = log_file_path
            # Create directory if needed
            import os
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        else:
            self.log_file_path = None

        # Lock for thread safety
        self.lock = threading.Lock()

        # Track whether we've started logging
        self.logging_started = False

    def start_logging(self):
        """Start event logging"""
        if self.enable_logging and not self.logging_started:
            self.event_logger = EventLogger(self.log_file_path)
            self.event_logger.open()
            self.logging_started = True

    def stop_logging(self):
        """Stop event logging"""
        if self.event_logger is not None:
            self.event_logger.close()
            self.event_logger = None
            self.logging_started = False

    def process_unified_event(self, event: UnifiedEvent):
        """
        Process a unified event through the stats tracker.

        This is the MAIN entry point for event processing.
        It converts UnifiedEvent to PacketEvent and feeds it to SessionStatsTracker.

        Args:
            event: UnifiedEvent to process
        """
        with self.lock:
            # Log event to file (if logging enabled)
            if self.logging_started and self.event_logger is not None:
                self.event_logger.log_event(event)

            # Convert UnifiedEvent to PacketEvent for SessionStatsTracker
            packet_event = self._convert_to_packet_event(event)

            # Process through SessionStatsTracker (expects dict, not dataclass)
            from dataclasses import asdict
            self.stats_tracker.process_event(asdict(packet_event))

    def _convert_to_packet_event(self, event: UnifiedEvent) -> PacketEvent:
        """
        Convert UnifiedEvent to PacketEvent.

        This ensures compatibility with SessionStatsTracker.process_event().
        """
        # Convert IPs to string format if needed
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        if isinstance(src_ip, int):
            src_ip = self._ip_to_str(src_ip)
        if isinstance(dst_ip, int):
            dst_ip = self._ip_to_str(dst_ip)

        # Convert SKB addr to string (hex format)
        skb_addr = hex(event.skb_addr) if event.skb_addr else None

        # Protocol name
        protocol_name = PROTO_MAP.get(event.protocol, f"PROTO_{event.protocol}")

        # Error name
        error_name = "NONE" if event.error_code == 0 else f"ERROR_{event.error_code}"

        # CRITICAL: Only pass fields that exist in PacketEvent dataclass
        # Fields NOT in PacketEvent: expr_addr, chain_depth, has_queue_bypass, verdict_raw
        return PacketEvent(
            timestamp=event.timestamp,
            skb_addr=skb_addr,
            cpu_id=event.cpu_id,
            pid=event.pid,
            event_type=event.event_type,
            hook=event.hook,
            hook_name=event.hook_name,
            pf=2,  # IPv4 (default)
            protocol=event.protocol,
            protocol_name=protocol_name,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            length=event.length,
            verdict=event.verdict,
            verdict_name=event.verdict_name,
            error_code=event.error_code,
            error_name=error_name,
            function=event.function or "",
            layer=event.layer,
            comm=event.comm,
            # NFT-specific fields (only the ones PacketEvent supports)
            chain_addr=hex(event.chain_addr) if event.chain_addr else None,
            rule_seq=event.rule_seq,
            rule_handle=hex(event.rule_handle) if event.rule_handle else None,
            queue_num=event.queue_num,
            trace_type=event.trace_type,
        )

    def _ip_to_str(self, ip_int: int) -> str:
        """Convert integer IP to string"""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current statistics.

        Returns same format as SessionStatsTracker.get_summary()
        for API compatibility.
        """
        with self.lock:
            return self.stats_tracker.get_summary()

    def reset_stats(self):
        """Reset statistics (but keep logging)"""
        with self.lock:
            # Re-initialize stats tracker
            old_start_time = self.stats_tracker.start_time
            self.stats_tracker = SessionStatsTracker(session_id=self.session_id, mode=self.mode)
            # Preserve start time
            self.stats_tracker.start_time = old_start_time

    def __enter__(self):
        """Context manager support"""
        self.start_logging()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support"""
        self.stop_logging()


# ============================================================================
# Convenience Functions
# ============================================================================

def create_session_engine(session_id: str, mode: str = "full", enable_logging: bool = True, log_file_path: Optional[str] = None) -> SessionEngine:
    """
    Create a new session engine.

    Args:
        session_id: Unique session identifier
        mode: Tracing mode ("nft", "full", "multifunction")
        enable_logging: Whether to log events to file
        log_file_path: Custom log file path (optional)

    Returns:
        SessionEngine instance
    """
    return SessionEngine(
        session_id=session_id,
        mode=mode,
        enable_logging=enable_logging,
        log_file_path=log_file_path
    )
