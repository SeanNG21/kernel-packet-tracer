# #!/usr/bin/env python3
# """
# Offline Event Replay - Rebuild Session Stats from Event Log

# This module reads event logs (JSONL format) and replays them through
# the SessionEngine to rebuild statistics.

# This ensures 100% consistency between:
# - Realtime session stats (counted during live trace)
# - Offline full session stats (rebuilt from event log)

# Key Principles:
# 1. Read events from JSONL file (one UnifiedEvent per line)
# 2. Feed each event through SessionEngine.process_unified_event()
# 3. Use SAME logic (SessionStatsTracker) as realtime
# 4. Return SAME stats format as realtime

# Author: NFT Tracer Team
# """

# import os
# import time
# from typing import Dict, Any, Optional, List

# from unified_event import UnifiedEvent, EventReader
# from session_engine import SessionEngine


# class OfflineReplayEngine:
#     """
#     Offline replay engine for rebuilding session stats from event log.

#     Usage:
#         engine = OfflineReplayEngine(log_file_path)
#         stats = engine.replay()
#         print(stats['total_packets'])
#     """

#     def __init__(self, log_file_path: str, session_id: Optional[str] = None, mode: str = "full"):
#         """
#         Initialize offline replay engine.

#         Args:
#             log_file_path: Path to event log file (JSONL format)
#             session_id: Session ID (extracted from log if None)
#             mode: Tracing mode (default: "full")
#         """
#         self.log_file_path = log_file_path
#         self.mode = mode

#         # Extract session_id from log file name if not provided
#         if session_id is None:
#             basename = os.path.basename(log_file_path)
#             # Expected format: <session_id>_events.jsonl
#             if basename.endswith('_events.jsonl'):
#                 session_id = basename[:-14]  # Remove "_events.jsonl"
#             else:
#                 session_id = f"offline_{int(time.time())}"

#         self.session_id = session_id

#         # Create session engine (WITHOUT logging to avoid duplication)
#         self.engine = SessionEngine(
#             session_id=session_id,
#             mode=mode,
#             enable_logging=False  # IMPORTANT: Don't log during replay!
#         )

#         # Event reader
#         self.event_reader = EventReader(log_file_path)

#         # Replay stats
#         self.events_replayed = 0
#         self.replay_start_time = None
#         self.replay_end_time = None

#     def replay(self, progress_callback=None) -> Dict[str, Any]:
#         """
#         Replay all events and return final stats.

#         Args:
#             progress_callback: Optional callback(events_processed, event) for progress tracking

#         Returns:
#             Stats dictionary (same format as SessionStatsTracker.get_summary())
#         """
#         self.replay_start_time = time.time()
#         self.events_replayed = 0

#         with self.event_reader as reader:
#             for event in reader.read_all_events():
#                 # Process event through engine
#                 self.engine.process_unified_event(event)
#                 self.events_replayed += 1

#                 # Progress callback
#                 if progress_callback is not None:
#                     progress_callback(self.events_replayed, event)

#         self.replay_end_time = time.time()

#         # Return final stats
#         return self.engine.get_stats()

#     def get_replay_info(self) -> Dict[str, Any]:
#         """Get replay process information"""
#         replay_duration = None
#         if self.replay_start_time and self.replay_end_time:
#             replay_duration = self.replay_end_time - self.replay_start_time

#         return {
#             'session_id': self.session_id,
#             'log_file': self.log_file_path,
#             'events_replayed': self.events_replayed,
#             'replay_duration_seconds': replay_duration,
#             'events_per_second': self.events_replayed / replay_duration if replay_duration and replay_duration > 0 else 0
#         }

#     def get_stats(self) -> Dict[str, Any]:
#         """Get current stats (can be called during or after replay)"""
#         return self.engine.get_stats()


# # ============================================================================
# # Convenience Functions
# # ============================================================================

# def replay_session_from_log(log_file_path: str, session_id: Optional[str] = None, mode: str = "full") -> Dict[str, Any]:
#     """
#     Quick replay function - read log file and return stats.

#     Args:
#         log_file_path: Path to event log file
#         session_id: Session ID (auto-detected if None)
#         mode: Tracing mode

#     Returns:
#         Stats dictionary
#     """
#     engine = OfflineReplayEngine(log_file_path, session_id=session_id, mode=mode)
#     stats = engine.replay()
#     return stats


# def replay_session_with_info(log_file_path: str, session_id: Optional[str] = None, mode: str = "full") -> tuple[Dict[str, Any], Dict[str, Any]]:
#     """
#     Replay and return both stats and replay info.

#     Args:
#         log_file_path: Path to event log file
#         session_id: Session ID (auto-detected if None)
#         mode: Tracing mode

#     Returns:
#         Tuple of (stats, replay_info)
#     """
#     engine = OfflineReplayEngine(log_file_path, session_id=session_id, mode=mode)
#     stats = engine.replay()
#     info = engine.get_replay_info()
#     return stats, info


# # ============================================================================
# # Multi-Session Batch Replay
# # ============================================================================

# def replay_multiple_sessions(log_files: List[str], mode: str = "full") -> Dict[str, Dict[str, Any]]:
#     """
#     Replay multiple session logs and return stats for each.

#     Args:
#         log_files: List of event log file paths
#         mode: Tracing mode

#     Returns:
#         Dictionary mapping session_id -> stats
#     """
#     results = {}

#     for log_file in log_files:
#         try:
#             engine = OfflineReplayEngine(log_file, mode=mode)
#             stats = engine.replay()
#             results[engine.session_id] = {
#                 'stats': stats,
#                 'info': engine.get_replay_info()
#             }
#         except Exception as e:
#             # Log error but continue with other files
#             print(f"Error replaying {log_file}: {e}")
#             results[log_file] = {
#                 'error': str(e)
#             }

#     return results


# # ============================================================================
# # Legacy Support - Convert Old Full Trace to New Format
# # ============================================================================

# def convert_old_trace_to_events(old_trace_data: Dict[str, Any], output_file: str):
#     """
#     Convert old full trace format to new unified event format.

#     This is for migration from old PacketTrace format to new UnifiedEvent format.
#     NOT NEEDED if you're starting fresh with new unified format.

#     Args:
#         old_trace_data: Old trace data (from app.py's PacketTrace format)
#         output_file: Output JSONL file path
#     """
#     # This would need to be implemented based on old PacketTrace format
#     # For now, we skip this as the requirement is to rebuild from scratch
#     raise NotImplementedError(
#         "Old trace conversion not implemented. "
#         "Please use new unified event logging from the start."
#     )
