#!/usr/bin/env python3

import os
import sys
import json
import time
import threading
import socket
import struct
import platform
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import psutil

from discovery.btf_skb_discoverer import BTFSKBDiscoverer
from integrations.nftables_manager import NFTablesManager
from models import db, User
from auth import init_default_user, authenticate_user, create_tokens, token_required, change_password
from metrics_api import register_metrics_api
from realtime_timeseries_api import register_realtime_metrics_api

from pipeline_model import (
    # Constants
    HOOK_MAP, VERDICT_MAP, ERROR_MAP, PROTO_MAP,
    # Event types (INBOUND)
    EVENT_TYPE_FUNCTION_CALL, EVENT_TYPE_NFT_CHAIN, EVENT_TYPE_NFT_RULE,
    EVENT_TYPE_NF_VERDICT, EVENT_TYPE_GRO_IN, EVENT_TYPE_TC_IN,
    EVENT_TYPE_TC_VERDICT,
    EVENT_TYPE_CT_IN, EVENT_TYPE_CT_VERDICT, EVENT_TYPE_ROUTE_IN,
    EVENT_TYPE_ROUTE_VERDICT, EVENT_TYPE_TCP_IN, EVENT_TYPE_TCP_DROP,
    EVENT_TYPE_UDP_IN, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_TCP_IN,
    EVENT_TYPE_SOCK_UDP_IN, EVENT_TYPE_SOCK_DROP,
    # Event types (OUTBOUND)
    EVENT_TYPE_APP_TCP_SEND, EVENT_TYPE_APP_UDP_SEND, EVENT_TYPE_TCP_OUT,
    EVENT_TYPE_UDP_OUT, EVENT_TYPE_ROUTE_OUT_LOOKUP, EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT,
    EVENT_TYPE_ROUTE_OUT, EVENT_TYPE_ROUTE_OUT_DISCARD, EVENT_TYPE_TC_EGRESS_IN,
    EVENT_TYPE_TC_EGRESS_VERDICT, EVENT_TYPE_DRIVER_TX, EVENT_TYPE_DRIVER_TX_FAIL,
    # Mappings
    FUNCTION_TO_LAYER, EVENT_TYPE_TO_LAYER, PIPELINE_TOPOLOGY,
    # Functions
    refine_layer_by_hook, detect_packet_direction,
    get_layer_from_function, get_layer_from_event_type,
    # Classes
    NodeStats, PipelineStats, BasePipelineEngine,
    # Filters
    EXCLUDED_PORTS as UNIFIED_EXCLUDED_PORTS, should_filter_event
)


from unified_event import UnifiedEvent, create_event_from_bpf
from session_engine import SessionEngine, create_session_engine

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("WARNING: BCC not available - Install: pip3 install bcc")

app = Flask(__name__)


DB_PATH = os.path.join(os.path.dirname(__file__), "nft_tracer.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')


db.init_app(app)
jwt = JWTManager(app)

CORS(app, resources={r"/api/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

try:
    from flask_socketio import SocketIO
    from realtime_extension import RealtimeExtension, add_realtime_routes

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                       logger=False, engineio_logger=False)
    realtime = RealtimeExtension(app, socketio)
    add_realtime_routes(app, realtime)

    REALTIME_AVAILABLE = True
    print("[✓] Realtime visualization module loaded")
except ImportError as e:
    REALTIME_AVAILABLE = False
    socketio = None
    realtime = None
    print(f"[!] Realtime not available: {e}")
    print("[!] Install: pip3 install flask-socketio python-socketio")


OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data", "output")
NFT_TRACER_PATH = os.path.join(os.path.dirname(__file__), "ebpf", "nft_tracer.bpf.c")
FULL_TRACER_PATH = os.path.join(os.path.dirname(__file__), "ebpf", "full_tracer.bpf.c")
FUNCTIONS_CACHE = os.path.join(os.path.dirname(__file__), "data", "cache", "skb_functions.json")

EXCLUDED_PORTS = set([
    int(os.environ.get('BACKEND_PORT', 5000)),
    int(os.environ.get('FRONTEND_PORT', 3000)),
    int(os.environ.get('SOCKETIO_PORT', 5001)),
])
TRACE_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "data", "cache", "trace_config.json")


MAX_COMPLETED_TRACES = 5000

CLEANUP_BATCH_SIZE = 1000

os.makedirs(OUTPUT_DIR, exist_ok=True)


FIXED_TRACE_FUNCTIONS = list(FUNCTION_TO_LAYER.keys())



LAYER_ORDER = {}
for direction, pipeline_info in PIPELINE_TOPOLOGY.items():
    layers = pipeline_info['nodes']
    for idx, layer in enumerate(layers):
        LAYER_ORDER[f"{direction}:{layer}"] = idx

CRITICAL_FUNCTIONS = FIXED_TRACE_FUNCTIONS

BLACKLIST_PATTERNS = [
    'nf_getsockopt', 'nf_setsockopt', 'nf_hook_entries_', 'nf_hook_direct_',
    'nf_register_', 'nf_unregister_', 'nf_log_', '__nf_hook_',
    'nf_ct_', 'nf_tables_',
]

def is_blacklisted(func_name: str) -> bool:
    for pattern in BLACKLIST_PATTERNS:
        if pattern in func_name:
            return True
    return False




    return base_layer

def detect_packet_direction(func_name: str, layer: str) -> str:
    inbound_layers = [
        'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress', 'IP Receive',
        'Netfilter PREROUTING', 'Netfilter INPUT', 'Netfilter FORWARD',
        'Conntrack', 'Routing Decision',
        'Local Delivery', 'Socket'
    ]

    outbound_layers = [
        'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
        'Routing Lookup', 'TC Egress', 'Netfilter POSTROUTING',
        'Driver TX'
    ]

    if layer in inbound_layers:
        return 'Inbound'
    if layer in outbound_layers:
        return 'Outbound'

    inbound_keywords = ['rcv', 'receive', 'input', 'ingress', 'deliver']
    outbound_keywords = ['sendmsg', 'xmit', 'transmit', 'output', 'egress']

    func_lower = func_name.lower()
    for keyword in inbound_keywords:
        if keyword in func_lower:
            return 'Inbound'
    for keyword in outbound_keywords:
        if keyword in func_lower:
            return 'Outbound'

    if layer in ['TCP/UDP', 'Forward']:
        if 'sendmsg' in func_lower:
            return 'Outbound'
        return 'Inbound'

    return 'Inbound'

class KallsymsLookup:

    def __init__(self):
        self.symbols: Dict[int, str] = {}
        self.sorted_addrs: List[int] = []
        self._load_kallsyms()

    def _load_kallsyms(self):
        print("[*] Loading kallsyms...")
        count = 0
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr_str, sym_type, name = parts[0], parts[1], parts[2]
                        if sym_type in ['T', 't']:
                            try:
                                addr = int(addr_str, 16)
                                if addr > 0:
                                    self.symbols[addr] = name
                                    count += 1
                            except ValueError:
                                continue

            self.sorted_addrs = sorted(self.symbols.keys())
            print(f"[✓] Loaded {count} kernel symbols")
        except Exception as e:
            print(f"[!] Failed to load kallsyms: {e}")

    def lookup(self, func_ip: int) -> Optional[str]:
        if not self.sorted_addrs or func_ip == 0:
            return None

        left, right = 0, len(self.sorted_addrs) - 1
        result_addr = None

        while left <= right:
            mid = (left + right) // 2
            addr = self.sorted_addrs[mid]

            if addr == func_ip:
                result_addr = addr
                break
            elif addr < func_ip:
                result_addr = addr
                left = mid + 1
            else:
                right = mid - 1

        if result_addr is not None:
            return self.symbols.get(result_addr)

        return None

kallsyms = KallsymsLookup()

@dataclass
class NFTEvent:
    timestamp: int
    cpu_id: int
    pid: int
    skb_addr: int
    chain_addr: int
    expr_addr: int
    regs_addr: int
    hook: int
    chain_depth: int
    trace_type: int
    pf: int
    verdict: int
    verdict_raw: int
    queue_num: int
    rule_seq: int
    has_queue_bypass: int
    protocol: int
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    rule_handle: int
    comm: str

    @staticmethod
    def from_bpf_event(event):
        return NFTEvent(
            timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
            skb_addr=event.skb_addr, chain_addr=event.chain_addr,
            expr_addr=event.expr_addr, regs_addr=event.regs_addr,
            hook=event.hook, chain_depth=event.chain_depth,
            trace_type=event.trace_type, pf=event.pf,
            verdict=event.verdict, verdict_raw=event.verdict_raw,
            queue_num=event.queue_num, rule_seq=event.rule_seq,
            has_queue_bypass=event.has_queue_bypass, protocol=event.protocol,
            src_ip=event.src_ip, dst_ip=event.dst_ip,
            src_port=event.src_port, dst_port=event.dst_port,
            rule_handle=event.rule_handle,
            comm=event.comm.decode('utf-8', errors='ignore')
        )

@dataclass
class UniversalEvent:
    timestamp: int
    cpu_id: int
    pid: int
    skb_addr: int
    func_name: str
    protocol: int
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    length: int
    comm: str
    verdict: int = 255  
    error_code: int = 0  

@dataclass
class PacketTrace:
    skb_addr: int
    first_seen: int
    last_seen: int
    events: List[Dict]

    protocol: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    final_verdict: Optional[int] = None
    final_verdict_str: Optional[str] = None
    hook: Optional[int] = None
    total_rules_evaluated: int = 0
    verdict_changes: int = 0

    layer_drop_detected: bool = False
    drop_layer: Optional[str] = None
    drop_function: Optional[str] = None
    drop_timestamp: Optional[int] = None
    drop_verdict_code: Optional[int] = None


    layer_verdict_count: int = 0  
    layer_verdicts_by_type: Dict[str, int] = None  

    drops_by_layer: Dict[str, int] = None  

    functions_called: List[str] = None
    unique_functions: int = 0

    direction: Optional[str] = None
    pipeline_stages: List[Dict] = None
    layer_counts: Dict[str, int] = None

    mode: str = "full"

    def __post_init__(self):
        if self.functions_called is None:
            self.functions_called = []
        if self.pipeline_stages is None:
            self.pipeline_stages = []
        if self.layer_counts is None:
            self.layer_counts = defaultdict(int)
        if self.layer_verdicts_by_type is None:
            self.layer_verdicts_by_type = defaultdict(int)
        if self.drops_by_layer is None:
            self.drops_by_layer = defaultdict(int)

        self._func_last_seen = {}

    def add_nft_event(self, event: NFTEvent):
        DEDUP_WINDOW_NS = 5000

        if self.direction is None and event.hook != 255:
            if event.hook in [0, 1, 2]:  # PREROUTING, INPUT, FORWARD
                self.direction = 'Inbound'
            elif event.hook in [3, 4]:  # OUTPUT, POSTROUTING
                self.direction = 'Outbound'
            else:
                self.direction = 'Unknown'

        if event.expr_addr > 0:
            dedup_key = (event.skb_addr, event.expr_addr)

            if hasattr(self, '_last_expr_eval'):
                last_key, last_ts = self._last_expr_eval
                if (last_key == dedup_key and
                    abs(event.timestamp - last_ts) < DEDUP_WINDOW_NS):
                    return

            self._last_expr_eval = (dedup_key, event.timestamp)

        if event.trace_type == 0 and event.verdict == 1:
            self.last_seen = event.timestamp
            if event.protocol > 0 and self.protocol is None:
                self.protocol = event.protocol
                self.src_ip = self._format_ip(event.src_ip)
                self.dst_ip = self._format_ip(event.dst_ip)
                self.src_port = event.src_port if event.src_port > 0 else None
                self.dst_port = event.dst_port if event.dst_port > 0 else None
            if event.hook != 255 and self.hook is None:
                self.hook = event.hook
            return

        event_dict = {
            'timestamp': event.timestamp,
            'trace_type': self._trace_type_str(event.trace_type),
            'verdict': self._verdict_str(event.verdict),
            'verdict_code': event.verdict,
            'verdict_raw': event.verdict_raw,
            'rule_seq': event.rule_seq,
            'rule_handle': event.rule_handle,
            'expr_addr': hex(event.expr_addr) if event.expr_addr > 0 else None,
            'chain_addr': hex(event.chain_addr) if event.chain_addr > 0 else None,
            'chain_depth': event.chain_depth, 'cpu_id': event.cpu_id,
            'comm': event.comm, 'hook': event.hook, 'pf': event.pf
        }

        if len(self.events) > 0:
            for prev_event in reversed(self.events):
                if prev_event.get('trace_type') in ['chain_exit', 'rule_eval', 'hook_exit']:
                    if prev_event.get('verdict_code') != event.verdict:
                        self.verdict_changes += 1
                    break

        self.events.append(event_dict)
        self.last_seen = event.timestamp

        if event.protocol > 0 and self.protocol is None:
            self.protocol = event.protocol
            self.src_ip = self._format_ip(event.src_ip)
            self.dst_ip = self._format_ip(event.dst_ip)
            self.src_port = event.src_port if event.src_port > 0 else None
            self.dst_port = event.dst_port if event.dst_port > 0 else None

        if event.hook != 255 and self.hook is None:
            self.hook = event.hook

        if event.trace_type == 0:
            self.final_verdict = event.verdict
            self.final_verdict_str = self._verdict_str(event.verdict)

        if event.trace_type == 1:
            self.total_rules_evaluated += 1

    def add_universal_event(self, event: UniversalEvent, hook: int = 255):
        func_name = event.func_name

        if func_name in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[func_name]
            layer = refine_layer_by_hook(func_name, base_layer, hook)
        else:
            layer = "Unknown"

        direction = detect_packet_direction(func_name, layer)

        if self.direction is None:
            self.direction = direction

        dedup_key = (func_name, layer)
        last_ts = self._func_last_seen.get(dedup_key, 0)
        if event.timestamp - last_ts < 100000:  
            return
        self._func_last_seen[dedup_key] = event.timestamp


        node = layer

        event_dict = {
            'timestamp': event.timestamp,
            'trace_type': 'function_call',
            'function': func_name,
            'layer': layer,
            'node': node,         
            'direction': direction, 
            'cpu_id': event.cpu_id,
            'comm': event.comm
        }


        if event.verdict != 255:
            verdict_str = self._verdict_str(event.verdict)
            event_dict['layer_verdict'] = verdict_str
            event_dict['layer_verdict_code'] = event.verdict

            self.layer_verdict_count += 1
            self.layer_verdicts_by_type[verdict_str] += 1


            if verdict_str == 'DROP':
                self.drops_by_layer[layer] += 1

            if verdict_str == 'DROP' and not self.layer_drop_detected:
                self.layer_drop_detected = True
                self.drop_layer = layer
                self.drop_function = func_name
                self.drop_timestamp = event.timestamp
                self.drop_verdict_code = event.verdict


        if event.error_code > 0:
            event_dict['error_code'] = event.error_code

        self.events.append(event_dict)
        self.last_seen = event.timestamp

        if func_name not in self.functions_called:
            self.functions_called.append(func_name)
            self.unique_functions += 1

        self.pipeline_stages.append({
            'timestamp': event.timestamp,
            'function': func_name,
            'layer': layer,
            'direction': direction
        })
        self.layer_counts[layer] += 1

        if event.protocol > 0 and self.protocol is None:
            self.protocol = event.protocol
            self.src_ip = self._format_ip(event.src_ip)
            self.dst_ip = self._format_ip(event.dst_ip)
            self.src_port = event.src_port if event.src_port > 0 else None
            self.dst_port = event.dst_port if event.dst_port > 0 else None

    @staticmethod
    def _verdict_str(verdict: int) -> str:
        verdicts = {
            0: "DROP", 1: "ACCEPT", 2: "STOLEN", 3: "QUEUE",
            4: "REPEAT", 5: "STOP", 10: "CONTINUE", 11: "RETURN",
            12: "JUMP", 13: "GOTO", 14: "BREAK", 255: "UNKNOWN"
        }
        return verdicts.get(verdict, f"UNKNOWN_{verdict}")

    @staticmethod
    def _trace_type_str(trace_type: int) -> str:
        types = {0: "chain_exit", 1: "rule_eval", 2: "hook_exit"}
        return types.get(trace_type, f"unknown_{trace_type}")

    @staticmethod
    def _hook_str(hook: int) -> str:
        """Map Netfilter hook number to hook name."""
        hooks = {
            0: "PREROUTING",
            1: "INPUT",
            2: "FORWARD",
            3: "OUTPUT",
            4: "POSTROUTING",
            5: "INGRESS",
        }
        return hooks.get(hook, f"UNKNOWN_{hook}")

    @staticmethod
    def _format_ip(ip: int) -> Optional[str]:
        if ip == 0:
            return None
        return socket.inet_ntoa(ip.to_bytes(4, byteorder='little'))

    def _build_realtime_stats(self) -> Dict:
        # Group pipeline stages by direction
        stats_by_direction = {
            'Inbound': defaultdict(lambda: {'count': 0, 'drops': 0}),
            'Outbound': defaultdict(lambda: {'count': 0, 'drops': 0}),
            'Forward': defaultdict(lambda: {'count': 0, 'drops': 0})
        }


        edges_by_direction = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int),
            'Forward': defaultdict(int)
        }

        prev_layer = None
        prev_direction = None

        for stage in sorted(self.pipeline_stages, key=lambda x: x['timestamp']):
            layer = stage['layer']
            direction = stage['direction']

            stats_by_direction[direction][layer]['count'] += 1
            if prev_layer and prev_direction == direction:
                edge_key = f"{prev_layer} -> {layer}"
                edges_by_direction[direction][edge_key] += 1

            prev_layer = layer
            prev_direction = direction

        for event in self.events:
            if event.get('layer_verdict') == 'DROP':
                layer = event.get('layer', 'Unknown')
                direction = event.get('direction', 'Inbound')
                stats_by_direction[direction][layer]['drops'] += 1

        pipelines = {}
        for direction in ['Inbound', 'Outbound', 'Forward']:
            if stats_by_direction[direction]:
                nodes = []
                for layer, stats in stats_by_direction[direction].items():
                    nodes.append({
                        'name': layer,
                        'count': stats['count'],
                        'packets_in': stats['count'],
                        'drops': stats['drops']
                    })

                edges = []
                for edge_key, count in edges_by_direction[direction].items():
                    from_node, to_node = edge_key.split(' -> ')
                    edges.append({
                        'from': from_node,
                        'to': to_node,
                        'count': count
                    })

                pipelines[direction] = {
                    'nodes': nodes,
                    'edges': edges,
                    'total_packets': len([s for s in self.pipeline_stages if s['direction'] == direction])
                }

        return {
            'pipelines': pipelines,
            'total_stages': len(self.pipeline_stages),
            'unique_layers': len(set(s['layer'] for s in self.pipeline_stages))
        }

    def is_valuable_trace(self) -> bool:

        if self.direction == 'Outbound':
            return True

        if self.src_port in EXCLUDED_PORTS or self.dst_port in EXCLUDED_PORTS:
            return False

        has_complete_info = (
            self.protocol is not None and
            self.src_ip is not None and
            self.dst_ip is not None
        )

        has_multiple_events = len(self.events) >= 2

        has_nft_activity = self.total_rules_evaluated > 0

        has_verdict_changes = self.verdict_changes > 0

        duration_ns = self.last_seen - self.first_seen
        has_significant_duration = duration_ns >= 10000

        return (
            has_complete_info or
            has_multiple_events or
            has_nft_activity or
            has_verdict_changes or
            has_significant_duration
        )

    def to_summary(self) -> Dict:
        sorted_events = sorted(self.events, key=lambda x: x['timestamp'])

        if self.mode == 'full':
            simplified_events = []
            nft_events = []
            total_function_calls = 0

            for event in sorted_events:
                trace_type = event.get('trace_type')
                if trace_type == 'function_call':
                    total_function_calls += 1
                    simple_event = {
                        'timestamp': event['timestamp'],
                        'function': event['function'],
                        'layer': event['layer'],
                        'node': event.get('node', event['layer']),  
                        'direction': event.get('direction', 'Unknown'), 
                        'cpu_id': event['cpu_id'],
                        'comm': event['comm']
                    }

                    if 'layer_verdict' in event:
                        simple_event['layer_verdict'] = event['layer_verdict']
                        simple_event['layer_verdict_code'] = event['layer_verdict_code']
                    if 'error_code' in event:
                        simple_event['error_code'] = event['error_code']
                    simplified_events.append(simple_event)
                elif trace_type in ['chain_exit', 'rule_eval', 'hook_exit']:
                    if trace_type == 'chain_exit' and event.get('chain_depth', 0) > 0:
                        continue  
                    nft_events.append(event)


            realtime_like_stats = self._build_realtime_stats()
            branch = "UNKNOWN"
            if self.direction == "Inbound":
                all_layers = [e.get('layer', '') for e in sorted_events if e.get('trace_type') == 'function_call']

                if any('INPUT' in layer or 'Local Delivery' in layer for layer in all_layers):
                    branch = "LOCAL_DELIVERY"
                elif any('FORWARD' in layer for layer in all_layers):
                    branch = "FORWARD"
                else:
                    nft_hooks = [e.get('hook') for e in sorted_events
                                if e.get('trace_type') in ['chain_exit', 'hook_exit', 'rule_eval']]
                    if 1 in nft_hooks:  
                        branch = "LOCAL_DELIVERY"
                    elif 2 in nft_hooks:  
                        branch = "FORWARD"
                    else:
                        branch = "LOCAL_DELIVERY"  
            elif self.direction == "Outbound":
                branch = "OUTPUT"

            if self.layer_drop_detected:
                final_verdict = "DROP"
                drop_info = {
                    'reason': 'layer_drop',
                    'layer': self.drop_layer,
                    'function': self.drop_function,
                    'timestamp': self.drop_timestamp,
                    'verdict_code': self.drop_verdict_code
                }
            elif self.final_verdict_str:
                final_verdict = self.final_verdict_str
                drop_info = None
            else:
                final_verdict = "ACCEPT"
                drop_info = None

            result = {
                'skb_addr': hex(self.skb_addr) if self.skb_addr > 0 else f"synthetic_{self.skb_addr}",
                'protocol': self.protocol,
                'protocol_name': self._protocol_name(self.protocol),
                'src_ip': self.src_ip,
                'dst_ip': self.dst_ip,
                'src_port': self.src_port,
                'dst_port': self.dst_port,
                'first_seen': self.first_seen,
                'last_seen': self.last_seen,
                'duration_ns': self.last_seen - self.first_seen,
                'direction': self.direction or 'Unknown',  
                'branch': branch,
                'functions_path': self.functions_called,
                'unique_functions': self.unique_functions,
                'total_functions_called': total_function_calls,
                'final_verdict': final_verdict, 
                'total_rules_evaluated': self.total_rules_evaluated,
                'verdict_changes': self.verdict_changes,
                'layer_verdict_count': self.layer_verdict_count,  
                'layer_verdicts_by_type': dict(self.layer_verdicts_by_type),  
                'drops_by_layer': dict(self.drops_by_layer), 
                'total_layer_drops': sum(self.drops_by_layer.values()),  
                'events': simplified_events,
                'nft_events': nft_events,
                'all_events_count': len(simplified_events),
                'nft_events_count': len(nft_events),
                'realtime_like_stats': realtime_like_stats  
            }


            if drop_info:
                result['drop_info'] = drop_info

            return result

        function_events = []
        nft_events = []

        for event in sorted_events:
            trace_type = event.get('trace_type')
            if trace_type in ['chain_exit', 'rule_eval', 'hook_exit']:
                nft_events.append(event)
            elif trace_type == 'function_call':
                function_events.append(event)

        sorted_stages = sorted(self.pipeline_stages, key=lambda x: x['timestamp'])

        pipeline_summary = []
        seen_layers = set()
        for stage in sorted_stages:
            layer = stage['layer']
            if layer not in seen_layers:
                pipeline_summary.append({
                    'layer': layer,
                    'first_timestamp': stage['timestamp'],
                    'count': self.layer_counts.get(layer, 0),
                })
                seen_layers.add(layer)

        if self.layer_drop_detected:
            final_verdict = "DROP"
            drop_info = {
                'reason': 'layer_drop',
                'layer': self.drop_layer,
                'function': self.drop_function,
                'timestamp': self.drop_timestamp,
                'verdict_code': self.drop_verdict_code
            }
        elif self.final_verdict_str:
            final_verdict = self.final_verdict_str
            drop_info = None
        else:
            final_verdict = "ACCEPT"
            drop_info = None

        result = {
            'packet_id': hex(self.skb_addr) if self.skb_addr > 0 else f"synthetic_{self.skb_addr}",
            'skb_addr': hex(self.skb_addr) if self.skb_addr > 0 else f"synthetic_{self.skb_addr}",

            'direction': self.direction or 'Unknown',
            'stages': sorted_stages,
            'pipeline_summary': pipeline_summary,

            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'duration_ns': self.last_seen - self.first_seen,

            'protocol': self.protocol,
            'protocol_name': self._protocol_name(self.protocol),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,

            'hook': self.hook,
            'hook_name': self._hook_name(self.hook),
            'final_verdict': final_verdict,  
            'total_rules_evaluated': self.total_rules_evaluated,
            'verdict_changes': self.verdict_changes,

            'layer_counts': dict(self.layer_counts),
            'unique_layers': len(seen_layers),
            'total_events': len(sorted_stages),
            'functions_path': self.functions_called,
            'unique_functions': self.unique_functions,

            'all_events': sorted_events,
            'all_events_count': len(sorted_events),

            'nft_events': nft_events,
            'nft_events_count': len(nft_events),
        }

        if drop_info:
            result['drop_info'] = drop_info

        return result

    @staticmethod
    def _protocol_name(proto):
        if proto is None:
            return None
        protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protos.get(proto, f'PROTO_{proto}')

    @staticmethod
    def _hook_name(hook):
        if hook is None:
            return None
        hooks = {0: 'PREROUTING', 1: 'INPUT', 2: 'FORWARD', 3: 'OUTPUT', 4: 'POSTROUTING'}
        return hooks.get(hook, f'HOOK_{hook}')

class TraceSession:

    def __init__(self, session_id: str, mode: str = "nft", pcap_filter: str = "",
                 max_functions: int = 30, trace_filter: dict = None):
        self.session_id = session_id
        self.mode = mode
        self.pcap_filter = pcap_filter
        self.max_functions = max_functions
        self.start_time = datetime.now()
        self.end_time = None
        self.running = False
        self.bpf_nft = None
        self.bpf_full = None
        self.thread = None

        self.trace_filter = trace_filter or {}
        self.filter_enabled = bool(trace_filter and any(trace_filter.values()))

        self.packet_traces: Dict[str, PacketTrace] = {}
        self.completed_traces: List[PacketTrace] = []
        self.lock = threading.Lock()

        self.total_events = 0
        self.events_per_second = 0
        self.last_stats_time = time.time()
        self.last_event_count = 0

        self.hostname = socket.gethostname()
        self.kernel_version = platform.release()
        self.cpu_count = psutil.cpu_count()

        self.synthetic_id_counter = -1
        self.skb_zero_count = 0

        self.functions = []
        self.func_id_to_name = {}
        self.events_by_func = defaultdict(int)

        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }


        self.nft_verdicts = defaultdict(int)  
        self.layer_verdicts = defaultdict(int)  

        self.drops_by_layer = defaultdict(int)  

        self.session_engine: Optional[SessionEngine] = None
        if mode == "full":
            log_file_path = os.path.join(OUTPUT_DIR, f"{session_id}_events.jsonl")
            self.session_engine = create_session_engine(
                session_id=session_id,
                mode=mode,
                enable_logging=True,
                log_file_path=log_file_path
            )
            print(f"[✓] Session engine created with event logging: {log_file_path}")

        self.trace_timeout_ns = 1 * 1_000_000_000

        print(f"[DEBUG] Session {session_id} created in {mode.upper()} mode")
        print(f"[DEBUG] Excluded ports (no self-tracing): {sorted(EXCLUDED_PORTS)}")
        if self.filter_enabled:
            print(f"[DEBUG] Trace filter active: {self.trace_filter}")

    def _matches_filter(self, event) -> bool:
        if not self.filter_enabled:
            return True

        def format_ip(ip_int):
            if ip_int == 0:
                return None
            return socket.inet_ntoa(struct.pack('!I', ip_int))

        if self.trace_filter.get('src_ip'):
            event_src_ip = format_ip(event.src_ip) if hasattr(event, 'src_ip') else None
            if event_src_ip != self.trace_filter['src_ip']:
                return False

        if self.trace_filter.get('dst_ip'):
            event_dst_ip = format_ip(event.dst_ip) if hasattr(event, 'dst_ip') else None
            if event_dst_ip != self.trace_filter['dst_ip']:
                return False

        if self.trace_filter.get('src_port'):
            event_src_port = event.src_port if hasattr(event, 'src_port') else 0
            if event_src_port != int(self.trace_filter['src_port']):
                return False

        if self.trace_filter.get('dst_port'):
            event_dst_port = event.dst_port if hasattr(event, 'dst_port') else 0
            if event_dst_port != int(self.trace_filter['dst_port']):
                return False

        if self.trace_filter.get('protocol'):
            event_protocol = event.protocol if hasattr(event, 'protocol') else 0
            if event_protocol != int(self.trace_filter['protocol']):
                return False

        if self.trace_filter.get('comm'):
            event_comm = event.comm.decode('utf-8', errors='ignore') if hasattr(event, 'comm') else ''
            filter_comm = self.trace_filter['comm']
            if filter_comm.lower() not in event_comm.lower():
                return False

        return True

    def _add_completed_trace(self, trace):
        self.completed_traces.append(trace)
        if len(self.completed_traces) > MAX_COMPLETED_TRACES:
            del self.completed_traces[:CLEANUP_BATCH_SIZE]

    def start(self) -> bool:
        if not BCC_AVAILABLE:
            return False

        try:
            if self.mode == 'nft':
                return self._start_nft_only()
            elif self.mode == 'full':
                return self._start_full_mode()
            else:
                print(f"[ERROR] Unknown mode: {self.mode}")
                return False

        except Exception as e:
            print(f"[ERROR] Starting session: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _start_nft_only(self) -> bool:
        with open(NFT_TRACER_PATH, 'r') as f:
            bpf_code = f.read()
        self.bpf_nft = BPF(text=bpf_code)
        self.bpf_nft.attach_kprobe(event="nft_do_chain", fn_name="kprobe__nft_do_chain")
        self.bpf_nft.attach_kretprobe(event="nft_do_chain", fn_name="kretprobe__nft_do_chain")
        self.bpf_nft.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")
        self.bpf_nft.attach_kretprobe(event="nf_hook_slow", fn_name="kretprobe__nf_hook_slow")
        self.bpf_nft["events"].open_perf_buffer(
            self._handle_nft_event,
            page_cnt=512
        )
        self.running = True
        self.thread = threading.Thread(target=self._poll_nft_events)
        self.thread.daemon = True
        self.thread.start()
        print(f"[✓] NFT mode started")
        return True

    def _start_full_mode(self) -> bool:
        print("[*] Starting FULL mode (Integrated: Functions + NFT verdicts)...")
        print("[*] Using FIXED set of representative functions across all layers...")
        EXCLUDED_FROM_GENERIC_TRACE = {
            # Optimized inbound layer functions
            'dev_gro_receive',      
            'tcf_classify',         
            'nf_conntrack_in',      
            'ip_route_input_noref', 
            'tcp_v4_rcv',           
            'tcp_v4_send_reset',    
            '__udp4_lib_rcv',       
            'tcp_queue_rcv',       
            'udp_queue_rcv_skb',    
            # Netfilter/NFT functions
            'nft_do_chain',         
            'nft_immediate_eval',   
            'nf_hook_slow',         
        }

        functions_to_trace = [
            f for f in FIXED_TRACE_FUNCTIONS
            if not is_blacklisted(f) and f not in EXCLUDED_FROM_GENERIC_TRACE
        ]

        self.functions = functions_to_trace
        print(f"[*] Fixed function set: {len(self.functions)} functions")
        print(f"[*] Excluded from generic trace: {', '.join(EXCLUDED_FROM_GENERIC_TRACE)}")
        print(f"[*] Coverage: XDP, Driver, TC, IP (RX/FWD/TX), Netfilter, Routing, TCP, UDP, CT")

        with open(FULL_TRACER_PATH, 'r') as f:
            bpf_code = f.read()

        self.bpf_full = BPF(text=bpf_code)

        print("[*] Attaching DEDICATED layer-specific hooks...")
        print("[*] These functions use dedicated handlers (NOT trace_skb_func):")
        try:
            # === Optimized Inbound Layer Hooks ===
            # GRO
            self.bpf_full.attach_kprobe(event="dev_gro_receive", fn_name="kprobe__dev_gro_receive")
            print("    • dev_gro_receive: GRO entry")

            # TC Ingress
            self.bpf_full.attach_kprobe(event="tcf_classify", fn_name="kprobe__tcf_classify")
            self.bpf_full.attach_kretprobe(event="tcf_classify", fn_name="kretprobe__tcf_classify")
            print("    • tcf_classify: TC Ingress entry + verdict")

            # Conntrack
            self.bpf_full.attach_kprobe(event="nf_conntrack_in", fn_name="kprobe__nf_conntrack_in")
            self.bpf_full.attach_kretprobe(event="nf_conntrack_in", fn_name="kretprobe__nf_conntrack_in")
            print("    • nf_conntrack_in: Conntrack entry + verdict")

            # Routing Decision
            self.bpf_full.attach_kprobe(event="ip_route_input_noref", fn_name="kprobe__ip_route_input_noref")
            self.bpf_full.attach_kretprobe(event="ip_route_input_noref", fn_name="kretprobe__ip_route_input_noref")
            print("    • ip_route_input_noref: Routing Decision entry + verdict")

            # TCP/UDP Transport
            self.bpf_full.attach_kprobe(event="tcp_v4_rcv", fn_name="kprobe__tcp_v4_rcv")
            print("    • tcp_v4_rcv: TCP transport entry")

            self.bpf_full.attach_kprobe(event="tcp_v4_send_reset", fn_name="kprobe__tcp_v4_send_reset")
            print("    • tcp_v4_send_reset: TCP drop (no socket)")

            self.bpf_full.attach_kprobe(event="__udp4_lib_rcv", fn_name="kprobe____udp4_lib_rcv")
            print("    • __udp4_lib_rcv: UDP transport entry")

            # Socket Layer
            self.bpf_full.attach_kprobe(event="tcp_queue_rcv", fn_name="kprobe__tcp_queue_rcv")
            print("    • tcp_queue_rcv: TCP socket queue")

            self.bpf_full.attach_kprobe(event="udp_queue_rcv_skb", fn_name="kprobe__udp_queue_rcv_skb")
            print("    • udp_queue_rcv_skb: UDP socket queue")

            # === Netfilter/NFT Hooks ===
            self.bpf_full.attach_kprobe(event="nf_hook_slow", fn_name="kprobe__nf_hook_slow")
            self.bpf_full.attach_kretprobe(event="nf_hook_slow", fn_name="kretprobe__nf_hook_slow")
            print("    • nf_hook_slow: Netfilter hook tracking")

            self.bpf_full.attach_kprobe(event="nft_do_chain", fn_name="kprobe__nft_do_chain")
            self.bpf_full.attach_kretprobe(event="nft_do_chain", fn_name="kretprobe__nft_do_chain")
            print("    • nft_do_chain: NFT chain entry/exit + verdict")

            self.bpf_full.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")
            print("    • nft_immediate_eval: NFT rule evaluation")

            # ===== OUTBOUND LAYER HOOKS =====
            print("\n[*] Attaching OUTBOUND layer hooks...")

            # Application Layer - tcp_sendmsg, udp_sendmsg
            # NOTE: These have skb_addr=0, but we trace them anyway for visibility
            try:
                self.bpf_full.attach_kprobe(event="tcp_sendmsg", fn_name="kprobe__tcp_sendmsg")
                print("    • tcp_sendmsg: Application TCP send")
            except:
                print("    ✗ tcp_sendmsg: Not available")

            try:
                self.bpf_full.attach_kprobe(event="udp_sendmsg", fn_name="kprobe__udp_sendmsg")
                print("    • udp_sendmsg: Application UDP send")
            except:
                print("    ✗ udp_sendmsg: Not available")

            # Transport Layer Out - TCP functions (try ALL, don't break early)
            print("  [Transport Layer - TCP Output]")
            tcp_funcs = [
                ("tcp_write_xmit", "kprobe__tcp_write_xmit", "TCP write transmit queue"),
                ("tcp_transmit_skb", "kprobe__tcp_transmit_skb", "TCP transmit SKB (wrapper)"),
                ("__tcp_transmit_skb", "kprobe____tcp_transmit_skb", "TCP transmit SKB (core)"),
                ("tcp_send_mss", "kprobe__tcp_send_mss", "TCP send MSS probe"),
                ("tcp_send_ack", "kprobe__tcp_send_ack", "TCP send ACK"),
            ]

            for func_name, bpf_name, description in tcp_funcs:
                try:
                    self.bpf_full.attach_kprobe(event=func_name, fn_name=bpf_name)
                    print(f"    • {func_name}: {description}")
                except Exception as e:
                    print(f"    ✗ {func_name}: Not available")

            # Transport Layer Out - UDP
            try:
                self.bpf_full.attach_kprobe(event="udp_send_skb", fn_name="kprobe__udp_send_skb")
                print("    • udp_send_skb: UDP transport output")
            except:
                print("    ✗ udp_send_skb: Not available")

            # Routing Layer Out
            print("  [Routing Layer - Outbound]")
            try:
                self.bpf_full.attach_kprobe(event="ip_route_output_flow", fn_name="kprobe__ip_route_output_flow")
                print("    • ip_route_output_flow: Outbound routing lookup")
            except:
                print("    ✗ ip_route_output_flow: Not available")

            try:
                self.bpf_full.attach_kprobe(event="ip_local_out", fn_name="kprobe__ip_local_out")
                print("    • ip_local_out: IP local output")
            except:
                print("    ✗ ip_local_out: Not available")

            try:
                self.bpf_full.attach_kprobe(event="dst_discard_out", fn_name="kprobe__dst_discard_out")
                print("    • dst_discard_out: Route discard/blackhole")
            except:
                print("    ✗ dst_discard_out: Not available")

            # TC Egress / QDisc Layer
            print("  [TC Egress / QDisc Layer]")
            try:
                self.bpf_full.attach_kprobe(event="sch_direct_xmit", fn_name="kprobe__sch_direct_xmit")
                print("    • sch_direct_xmit: QDisc direct transmit")
            except:
                print("    ✗ sch_direct_xmit: Not available")

            try:
                self.bpf_full.attach_kprobe(event="__dev_queue_xmit", fn_name="kprobe____dev_queue_xmit")
                print("    • __dev_queue_xmit: Device queue transmit (core)")
            except:
                print("    ✗ __dev_queue_xmit: Not available")

            try:
                self.bpf_full.attach_kprobe(event="dev_queue_xmit", fn_name="kprobe__dev_queue_xmit")
                print("    • dev_queue_xmit: Device queue transmit (wrapper)")
            except:
                print("    ✗ dev_queue_xmit: Not available")

            # Driver TX
            print("  [Driver TX Layer]")
            try:
                self.bpf_full.attach_kprobe(event="dev_hard_start_xmit", fn_name="kprobe__dev_hard_start_xmit")
                self.bpf_full.attach_kretprobe(event="dev_hard_start_xmit", fn_name="kretprobe__dev_hard_start_xmit")
                print("    • dev_hard_start_xmit: Driver TX")
            except:
                print("    ✗ dev_hard_start_xmit: Not available")

            print("[✓] All dedicated layer hooks attached successfully")
        except Exception as e:
            print(f"[!] Warning: Layer hooks failed - {e}")

        print("[*] Attaching packet path functions...")

        layer_stats = {
            'XDP': 0, 'Driver RX': 0, 'Driver TX': 0, 'TC': 0,
            'IP RX': 0, 'IP Forward': 0, 'IP TX': 0,
            'Netfilter': 0, 'ConnTrack': 0, 'Routing': 0,
            'TCP': 0, 'UDP': 0, 'Other': 0
        }

        def categorize_function(fname):
            if 'xdp' in fname:
                return 'XDP'
            elif fname in ['napi_gro_receive', 'netif_receive_skb', '__netif_receive_skb_core',
                          'netif_receive_skb_internal', 'eth_type_trans', 'netif_receive_skb_list_internal']:
                return 'Driver RX'
            elif fname in ['dev_queue_xmit', '__dev_queue_xmit', 'dev_hard_start_xmit', 'sch_direct_xmit']:
                return 'Driver TX'
            elif 'tc' in fname or fname == 'dev_queue_xmit_nit':
                return 'TC'
            elif fname in ['ip_rcv', 'ip_rcv_core', 'ip_rcv_finish', 'ip_local_deliver', 'ip_local_deliver_finish']:
                return 'IP RX'
            elif 'forward' in fname:
                return 'IP Forward'
            elif fname in ['ip_local_out', '__ip_local_out', 'ip_output', 'ip_finish_output', 'ip_finish_output2']:
                return 'IP TX'
            elif 'nf_hook' in fname or 'nf_queue' in fname or 'nf_reinject' in fname:
                return 'Netfilter'
            elif 'conntrack' in fname or 'nf_confirm' in fname:
                return 'ConnTrack'
            elif 'route' in fname or 'fib_' in fname:
                return 'Routing'
            elif 'tcp_' in fname:
                return 'TCP'
            elif 'udp_' in fname:
                return 'UDP'
            else:
                return 'Other'

        attached_total = 0
        failed_total = 0

        for func_name in self.functions:
            try:
                self.bpf_full.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                layer = categorize_function(func_name)
                layer_stats[layer] += 1
                attached_total += 1
            except:
                failed_total += 1

        print(f"[✓] Successfully attached {attached_total}/{len(self.functions)} functions")
        if failed_total > 0:
            print(f"[!] Failed to attach {failed_total} functions (may not exist in this kernel)")
        print("[*] Attachment by layer:")
        for layer, count in layer_stats.items():
            if count > 0:
                print(f"    • {layer:12s}: {count:2d} functions")

        self.bpf_full["events"].open_perf_buffer(
            self._handle_full_event,
            page_cnt=512
        )

        self.running = True
        self.thread = threading.Thread(target=self._poll_full_events)
        self.thread.daemon = True
        self.thread.start()

        self.cleanup_thread = threading.Thread(target=self._cleanup_old_traces)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

        # START: Activate session engine logging for JSONL export
        if self.session_engine:
            self.session_engine.start_logging()
            print(f"[✓] Session engine event logging started: {self.session_engine.log_file_path}")

        print("[✓] FULL MODE READY!")
        return True

    def stop(self) -> str:
        import gc

        self.running = False
        self.end_time = datetime.now()

        if hasattr(self, 'thread') and self.thread:
            self.thread.join(timeout=2.0)

        with self.lock:
            all_traces = list(self.packet_traces.items())

            # Separate by direction
            outbound_traces = [(k, t) for k, t in all_traces if t.direction == 'Outbound']
            other_traces = [(k, t) for k, t in all_traces if t.direction != 'Outbound']
            for skb_addr, trace in outbound_traces:
                self._add_completed_trace(trace)


            remaining_limit = max(0, 1000 - len(outbound_traces))
            for skb_addr, trace in other_traces[:remaining_limit]:
                self._add_completed_trace(trace)

            print(f"[STOP DEBUG] Moved {len(outbound_traces)} outbound + {min(remaining_limit, len(other_traces))} other traces to export")
            self.packet_traces.clear()

        output_path = self._export_json()


        with self.lock:
            self.completed_traces.clear()
            self.events_by_func.clear()
            self.stats_by_direction_layer = {
                'Inbound': defaultdict(int),
                'Outbound': defaultdict(int)
            }
            # Clear verdict and drop tracking
            self.nft_verdicts.clear()
            self.layer_verdicts.clear()
            self.drops_by_layer.clear()
            self.func_id_to_name.clear()
            self.functions = []

        if hasattr(self, 'session_engine') and self.session_engine:
            try:
                self.session_engine.stop_logging()
                print(f"[✓] Session engine logging stopped. Events logged: {self.session_engine.event_logger.events_logged if self.session_engine.event_logger else 0}")
                self.session_engine = None
            except Exception as e:
                print(f"[Warning] Error stopping session engine: {e}")
                pass

        if self.bpf_nft:
            try:
                for map_name in ['skb_info_map', 'depth_map', 'hook_map', 'hook_skb_map']:
                    try:
                        bpf_map = self.bpf_nft.get_table(map_name)
                        bpf_map.clear()
                    except:
                        pass
                self.bpf_nft.cleanup()
                self.bpf_nft = None
            except:
                pass

        if hasattr(self, 'bpf_full') and self.bpf_full:
            try:
                for map_name in ['skb_info_map', 'depth_map', 'hook_map', 'hook_skb_map', 'packet_info_map']:
                    try:
                        bpf_map = self.bpf_full.get_table(map_name)
                        bpf_map.clear()
                    except:
                        pass
                self.bpf_full.cleanup()
                self.bpf_full = None
            except:
                pass
        gc.collect()

        return output_path

    def _poll_nft_events(self):
        while self.running:
            try:
                self.bpf_nft.perf_buffer_poll(timeout=10)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] NFT polling: {e}")
                break

    def _poll_full_events(self):
        while self.running:
            try:
                self.bpf_full.perf_buffer_poll(timeout=10)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] FULL mode polling: {e}")
                break

    def _cleanup_old_traces(self):
        while self.running:
            time.sleep(2)
            now = time.time_ns()
            to_complete = []

            with self.lock:
                for packet_key, trace in list(self.packet_traces.items()):
                    if now - trace.last_seen > self.trace_timeout_ns:
                        to_complete.append(packet_key)

                for packet_key in to_complete:
                    trace = self.packet_traces.pop(packet_key)
                    self._add_completed_trace(trace)

    def _handle_nft_event(self, cpu, data, size):
        event = self.bpf_nft["events"].event(data)
        nft_event = NFTEvent.from_bpf_event(event)

        if not self._matches_filter(event):
            return  

        with self.lock:
            self.total_events += 1
            self._update_stats()

            skb_addr = self._get_skb_addr(nft_event.skb_addr, nft_event.chain_addr)

            packet_key = f"{skb_addr:x}"

            if packet_key not in self.packet_traces:
                self.packet_traces[packet_key] = PacketTrace(
                    skb_addr=skb_addr, first_seen=nft_event.timestamp,
                    last_seen=nft_event.timestamp, events=[], mode="nft"
                )

            trace = self.packet_traces[packet_key]
            trace.add_nft_event(nft_event)

            if nft_event.trace_type == 0:
                if nft_event.verdict in [0, 2]:
                    self._add_completed_trace(trace)
                    del self.packet_traces[packet_key]

    def _handle_full_event(self, cpu, data, size):
        import ctypes as ct

        class FullEvent(ct.Structure):
            _fields_ = [
                ("timestamp", ct.c_ulonglong), ("skb_addr", ct.c_ulonglong),
                ("cpu_id", ct.c_uint), ("pid", ct.c_uint),
                ("event_type", ct.c_ubyte), ("hook", ct.c_ubyte),
                ("pf", ct.c_ubyte), ("protocol", ct.c_ubyte),
                ("src_ip", ct.c_uint), ("dst_ip", ct.c_uint),
                ("src_port", ct.c_ushort), ("dst_port", ct.c_ushort),
                ("length", ct.c_uint), ("chain_addr", ct.c_ulonglong),
                ("expr_addr", ct.c_ulonglong), ("chain_depth", ct.c_ubyte),
                ("rule_seq", ct.c_ushort), ("rule_handle", ct.c_ulonglong),
                ("verdict_raw", ct.c_int), ("verdict", ct.c_uint),
                ("queue_num", ct.c_ushort), ("has_queue_bypass", ct.c_ubyte),
                ("error_code", ct.c_ubyte),
                ("func_ip", ct.c_ulonglong), ("function_name", ct.c_char * 64),
                ("comm", ct.c_char * 16), ("trace_type", ct.c_ubyte),
            ]

        event = ct.cast(data, ct.POINTER(FullEvent)).contents

        if not self._matches_filter(event):
            return 

        with self.lock:
            self.total_events += 1
            self._update_stats()

            skb_addr = event.skb_addr if event.skb_addr != 0 else event.chain_addr
            if skb_addr == 0:
                return

            direction = "Unknown"

            if event.event_type == EVENT_TYPE_FUNCTION_CALL:  
                func_name = kallsyms.lookup(event.func_ip)
                if not func_name:
                    func_name = event.function_name.decode('utf-8', errors='ignore').strip()
                if not func_name:
                    func_name = f"unknown_{hex(event.func_ip)}"

                if func_name in FUNCTION_TO_LAYER:
                    base_layer = FUNCTION_TO_LAYER[func_name]
                    layer = refine_layer_by_hook(func_name, base_layer, event.hook)
                    direction = detect_packet_direction(func_name, layer)
            elif event.event_type in [EVENT_TYPE_NFT_CHAIN, EVENT_TYPE_NFT_RULE, EVENT_TYPE_NF_VERDICT]:
                if event.hook in [0, 1, 2]:  
                    direction = 'Inbound'
                elif event.hook in [3, 4]:   
                    direction = 'Outbound'
            elif event.event_type >= 10 and event.event_type <= 41:  
                layer = EVENT_TYPE_TO_LAYER.get(event.event_type, 'Unknown')
                if event.event_type >= 10 and event.event_type <= 25:
                    direction = 'Inbound'
                elif event.event_type >= 30 and event.event_type <= 41:
                    direction = 'Outbound'
                else:
                    func_name_temp = event.function_name.decode('utf-8', errors='ignore').strip() if hasattr(event, 'function_name') else ''
                    direction = detect_packet_direction(func_name_temp, layer, event.hook)

            packet_key = self._make_packet_key(
                skb_addr, event.src_ip, event.dst_ip,
                event.src_port, event.dst_port, event.protocol,
                direction  
            )

            if packet_key not in self.packet_traces:
                self.packet_traces[packet_key] = PacketTrace(
                    skb_addr=skb_addr, first_seen=event.timestamp,
                    last_seen=event.timestamp, events=[], mode="full"
                )

                if self.total_events % 100 == 0:  
                    print(f"[DEBUG] New trace: key={packet_key[:80]}... direction={direction}")

            trace = self.packet_traces[packet_key]

            if event.event_type == 0:

                self.events_by_func[func_name] += 1

                if len(self.events_by_func) > 500:
                    sorted_funcs = sorted(self.events_by_func.items(), key=lambda x: x[1], reverse=True)
                    self.events_by_func = defaultdict(int, dict(sorted_funcs[:300]))

                if func_name in FUNCTION_TO_LAYER:
                    base_layer = FUNCTION_TO_LAYER[func_name]
                    layer = refine_layer_by_hook(func_name, base_layer, event.hook)
                    self.stats_by_direction_layer[direction][layer] += 1

                hook_value = event.hook if hasattr(event, 'hook') else 255
                hook_name = PacketTrace._hook_str(hook_value) if hook_value != 255 else "UNKNOWN"

                universal_event = UniversalEvent(
                    timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
                    skb_addr=event.skb_addr, func_name=func_name,
                    protocol=event.protocol, src_ip=event.src_ip, dst_ip=event.dst_ip,
                    src_port=event.src_port, dst_port=event.dst_port,
                    length=event.length, comm=event.comm.decode('utf-8', errors='ignore'),
                    verdict=255,  
                    error_code=0 
                )
                trace.add_universal_event(universal_event, hook=hook_value)

                if self.session_engine:
                    try:
                        unified_event = UnifiedEvent(
                            timestamp=event.timestamp,
                            session_id=self.session_id,
                            skb_addr=event.skb_addr,
                            event_type=EVENT_TYPE_FUNCTION_CALL,
                            func_name=func_name,
                            function=func_name,
                            hook=hook_value,
                            hook_name=hook_name,
                            layer=layer,
                            trace_type="function_call",
                            verdict=255,
                            verdict_name="UNKNOWN",
                            protocol=event.protocol,
                            src_ip=event.src_ip,
                            dst_ip=event.dst_ip,
                            src_port=event.src_port,
                            dst_port=event.dst_port,
                            direction=direction,
                            error_code=0,
                            pid=event.pid,
                            cpu_id=event.cpu_id,
                            comm=event.comm.decode('utf-8', errors='ignore'),
                            length=event.length
                        )
                        self.session_engine.process_unified_event(unified_event)

                        if direction == 'Outbound' and self.total_events % 100 == 0:
                            print(f"[OUTBOUND] {func_name} -> {layer} (skb={hex(event.skb_addr)})")
                    except Exception as e:
                        pass  

                if REALTIME_AVAILABLE and realtime:
                    try:
                        base_layer = FUNCTION_TO_LAYER.get(func_name, 'Unknown')
                        layer = refine_layer_by_hook(func_name, base_layer, event.hook)
                        direction = detect_packet_direction(func_name, layer)

                        realtime.process_session_event({
                            'hook': event.hook,
                            'func_name': func_name,
                            'layer': layer,        
                            'direction': direction, 
                            'verdict': event.verdict,
                            'protocol': event.protocol,
                            'src_ip': trace._format_ip(event.src_ip),
                            'dst_ip': trace._format_ip(event.dst_ip),
                            'timestamp': time.time(),
                            'skb_addr': hex(event.skb_addr) if event.skb_addr else None
                        }, self.session_id)
                    except Exception as e:
                        pass

            elif event.event_type >= 10 and event.event_type <= 41:  
                layer = EVENT_TYPE_TO_LAYER.get(event.event_type, 'Unknown')
                func_name = event.function_name.decode('utf-8', errors='ignore').strip()
                if not func_name:
                    event_type_func_map = {
                        # INBOUND
                        EVENT_TYPE_GRO_IN: 'dev_gro_receive',
                        EVENT_TYPE_TC_IN: 'tcf_classify',
                        EVENT_TYPE_TC_VERDICT: 'tcf_classify',
                        EVENT_TYPE_CT_IN: 'nf_conntrack_in',
                        EVENT_TYPE_CT_VERDICT: 'nf_conntrack_in',
                        EVENT_TYPE_ROUTE_IN: 'ip_route_input_noref',
                        EVENT_TYPE_ROUTE_VERDICT: 'ip_route_input_noref',
                        EVENT_TYPE_TCP_IN: 'tcp_v4_rcv',
                        EVENT_TYPE_TCP_DROP: 'tcp_v4_send_reset',
                        EVENT_TYPE_UDP_IN: '__udp4_lib_rcv',
                        EVENT_TYPE_UDP_DROP: '__udp4_lib_rcv',
                        EVENT_TYPE_SOCK_TCP_IN: 'tcp_queue_rcv',
                        EVENT_TYPE_SOCK_UDP_IN: 'udp_queue_rcv_skb',
                        EVENT_TYPE_SOCK_DROP: 'tcp_queue_rcv',
                        # OUTBOUND
                        EVENT_TYPE_APP_TCP_SEND: 'tcp_sendmsg',
                        EVENT_TYPE_APP_UDP_SEND: 'udp_sendmsg',
                        EVENT_TYPE_TCP_OUT: '__tcp_transmit_skb',
                        EVENT_TYPE_UDP_OUT: 'udp_send_skb',
                        EVENT_TYPE_ROUTE_OUT_LOOKUP: 'ip_route_output_flow',
                        EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT: 'ip_route_output_flow',
                        EVENT_TYPE_ROUTE_OUT: 'ip_local_out',
                        EVENT_TYPE_ROUTE_OUT_DISCARD: 'dst_discard_out',
                        EVENT_TYPE_TC_EGRESS_IN: '__dev_queue_xmit',
                        EVENT_TYPE_TC_EGRESS_VERDICT: '__dev_queue_xmit',
                        EVENT_TYPE_DRIVER_TX: 'dev_hard_start_xmit',
                        EVENT_TYPE_DRIVER_TX_FAIL: 'dev_hard_start_xmit',
                    }
                    func_name = event_type_func_map.get(event.event_type, 'unknown')

                self.stats_by_direction_layer[direction][layer] += 1
                self.events_by_func[func_name] += 1
                is_verdict_event = event.event_type in [
                    # INBOUND VERDICTS
                    EVENT_TYPE_TC_VERDICT, EVENT_TYPE_CT_VERDICT,
                    EVENT_TYPE_ROUTE_VERDICT, EVENT_TYPE_TCP_DROP, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_DROP,
                    # OUTBOUND VERDICTS
                    EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT, EVENT_TYPE_ROUTE_OUT_DISCARD,
                    EVENT_TYPE_TC_EGRESS_VERDICT, EVENT_TYPE_DRIVER_TX_FAIL
                ]

                # NEW: Count layer verdicts (separate from NFT verdicts)
                if is_verdict_event and event.verdict != 255:
                    verdict_name = PacketTrace._verdict_str(event.verdict)
                    self.layer_verdicts[verdict_name] += 1

                    # Count drops per layer
                    if verdict_name == 'DROP':
                        self.drops_by_layer[layer] += 1

                hook_value = event.hook if hasattr(event, 'hook') else 255
                hook_name = PacketTrace._hook_str(hook_value) if hook_value != 255 else "UNKNOWN"
                verdict_value = event.verdict if is_verdict_event else 255
                verdict_name = PacketTrace._verdict_str(verdict_value) if verdict_value != 255 else "UNKNOWN"

                universal_event = UniversalEvent(
                    timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
                    skb_addr=event.skb_addr, func_name=func_name,
                    protocol=event.protocol, src_ip=event.src_ip, dst_ip=event.dst_ip,
                    src_port=event.src_port, dst_port=event.dst_port,
                    length=event.length, comm=event.comm.decode('utf-8', errors='ignore'),
                    verdict=verdict_value,
                    error_code=event.error_code if is_verdict_event else 0
                )
                trace.add_universal_event(universal_event, hook=hook_value)

                # NEW: Feed event to session engine for JSONL logging
                if self.session_engine:
                    try:
                        unified_event = UnifiedEvent(
                            timestamp=event.timestamp,
                            session_id=self.session_id,
                            skb_addr=event.skb_addr,
                            event_type=event.event_type,
                            func_name=func_name,
                            function=func_name,
                            hook=hook_value,
                            hook_name=hook_name,
                            layer=layer,
                            trace_type="verdict" if is_verdict_event else "layer_entry",
                            verdict=verdict_value,
                            verdict_name=verdict_name,
                            protocol=event.protocol,
                            src_ip=event.src_ip,
                            dst_ip=event.dst_ip,
                            src_port=event.src_port,
                            dst_port=event.dst_port,
                            direction=direction,
                            error_code=event.error_code if is_verdict_event else 0,
                            pid=event.pid,
                            cpu_id=event.cpu_id,
                            comm=event.comm.decode('utf-8', errors='ignore'),
                            length=event.length
                        )
                        self.session_engine.process_unified_event(unified_event)
                    except Exception as e:
                        pass  # Don't let logging errors break tracing

                # Send to realtime if available
                if REALTIME_AVAILABLE and realtime:
                    try:
                        realtime.process_session_event({
                            'hook': event.hook,
                            'func_name': func_name,
                            'layer': layer,
                            'direction': direction,
                            'verdict': event.verdict,
                            'protocol': event.protocol,
                            'src_ip': trace._format_ip(event.src_ip),
                            'dst_ip': trace._format_ip(event.dst_ip),
                            'timestamp': time.time(),
                            'skb_addr': hex(event.skb_addr) if event.skb_addr else None
                        }, self.session_id)
                    except Exception as e:
                        pass

            elif event.event_type in [1, 2, 3]:
                nft_event = NFTEvent(
                    timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
                    skb_addr=event.skb_addr, chain_addr=event.chain_addr,
                    expr_addr=event.expr_addr, regs_addr=0,
                    hook=event.hook, chain_depth=event.chain_depth,
                    trace_type=event.event_type - 1, pf=event.pf,
                    verdict=event.verdict, verdict_raw=event.verdict_raw,
                    queue_num=event.queue_num, rule_seq=event.rule_seq,
                    has_queue_bypass=event.has_queue_bypass, protocol=event.protocol,
                    src_ip=event.src_ip, dst_ip=event.dst_ip,
                    src_port=event.src_port, dst_port=event.dst_port,
                    rule_handle=event.rule_handle,
                    comm=event.comm.decode('utf-8', errors='ignore')
                )
                trace.add_nft_event(nft_event)

                # NEW: Count NFT verdicts (only for chain_exit events = trace_type 0)
                if event.event_type == 1 and event.verdict != 255:  # chain_exit (event_type = 1)
                    verdict_name = PacketTrace._verdict_str(event.verdict)
                    self.nft_verdicts[verdict_name] += 1

                # NEW: Feed NFT event to session engine for JSONL logging
                if self.session_engine:
                    try:
                        # Map trace_type: 0=chain_exit, 1=rule_eval, 2=hook_exit
                        trace_type_val = event.event_type - 1
                        trace_type_map = {0: "chain_exit", 1: "rule_eval", 2: "hook_exit"}
                        trace_type_str = trace_type_map.get(trace_type_val, f"unknown_{trace_type_val}")

                        # DEBUG: Log NFT rule evaluations (verdicts)
                        if event.event_type == 2 and self.total_events % 50 == 0:  # NFT_RULE
                            print(f"[NFT VERDICT] rule_eval: verdict={PacketTrace._verdict_str(event.verdict)} hook={event.hook} skb={hex(event.skb_addr)}")

                        # Map NFT events to Netfilter layer based on hook
                        hook_layer_map = {
                            0: 'Netfilter PREROUTING',
                            1: 'Netfilter INPUT',
                            2: 'Netfilter FORWARD',
                            3: 'Netfilter OUTPUT',
                            4: 'Netfilter POSTROUTING',
                        }
                        nft_layer = hook_layer_map.get(event.hook, 'Netfilter')

                        # Detect direction based on hook
                        if event.hook in [0, 1, 2]:  # PREROUTING, INPUT, FORWARD
                            nft_direction = 'Inbound'
                        elif event.hook in [3, 4]:   # OUTPUT, POSTROUTING
                            nft_direction = 'Outbound'
                        else:
                            nft_direction = 'Unknown'

                        hook_name = PacketTrace._hook_str(event.hook)
                        verdict_val = event.verdict if event.verdict != 255 else 255
                        verdict_name_str = PacketTrace._verdict_str(verdict_val) if verdict_val != 255 else "UNKNOWN"

                        unified_event = UnifiedEvent(
                            timestamp=event.timestamp,
                            session_id=self.session_id,
                            skb_addr=event.skb_addr,
                            event_type=event.event_type,
                            func_name='nft_do_chain',
                            function='nft_do_chain',
                            hook=event.hook,
                            hook_name=hook_name,
                            layer=nft_layer,
                            trace_type=trace_type_str,
                            verdict=verdict_val,
                            verdict_name=verdict_name_str,
                            verdict_raw=event.verdict_raw,
                            protocol=event.protocol,
                            src_ip=event.src_ip,
                            dst_ip=event.dst_ip,
                            src_port=event.src_port,
                            dst_port=event.dst_port,
                            direction=nft_direction,
                            error_code=0,
                            chain_addr=event.chain_addr,
                            expr_addr=event.expr_addr,
                            chain_depth=event.chain_depth,
                            rule_seq=event.rule_seq,
                            rule_handle=event.rule_handle,
                            queue_num=event.queue_num,
                            has_queue_bypass=event.has_queue_bypass,
                            pid=event.pid,
                            cpu_id=event.cpu_id,
                            comm=event.comm.decode('utf-8', errors='ignore'),
                            length=0  # NFT events don't have length
                        )
                        self.session_engine.process_unified_event(unified_event)
                    except Exception as e:
                        # DEBUG: Print errors instead of silently failing
                        print(f"[ERROR] Failed to log NFT event to session engine: {e}")
                        import traceback
                        traceback.print_exc()

                if REALTIME_AVAILABLE and realtime:
                    try:
                        # Map trace_type: 0=chain_exit, 1=rule_eval, 2=hook_exit
                        trace_type = event.event_type - 1
                        trace_type_map = {0: "chain_exit", 1: "rule_eval", 2: "hook_exit"}
                        trace_type_str = trace_type_map.get(trace_type, f"unknown_{trace_type}")

                        # CRITICAL: Map NFT events to Netfilter layer based on hook
                        hook_layer_map = {
                            0: 'Netfilter PREROUTING',
                            1: 'Netfilter INPUT',
                            2: 'Netfilter FORWARD',
                            3: 'Netfilter OUTPUT',
                            4: 'Netfilter POSTROUTING',
                        }
                        layer = hook_layer_map.get(event.hook, 'Netfilter')

                        # Detect direction based on hook
                        if event.hook in [0, 1, 2]:  # PREROUTING, INPUT, FORWARD
                            direction = 'Inbound'
                        elif event.hook in [3, 4]:   # OUTPUT, POSTROUTING
                            direction = 'Outbound'
                        else:
                            direction = 'Unknown'

                        realtime.process_session_event({
                            'hook': event.hook,
                            'func_name': 'nft_do_chain',
                            'layer': layer,         # ADD: Netfilter layer based on hook
                            'direction': direction, # ADD: Direction based on hook
                            'verdict': event.verdict,
                            'protocol': event.protocol,
                            'src_ip': trace._format_ip(event.src_ip),
                            'dst_ip': trace._format_ip(event.dst_ip),
                            'timestamp': time.time(),
                            'trace_type': trace_type_str,
                            'skb_addr': hex(event.skb_addr) if event.skb_addr else None
                        }, self.session_id)
                    except Exception as e:
                        pass

                # FIX: Only complete trace on main chain exit (depth=0), not nested chains
                if event.event_type == 1:  # chain_exit
                    # Only complete on DROP/STOLEN verdict AND main chain (depth=0)
                    if event.verdict in [0, 2] and event.chain_depth == 0:
                        if packet_key in self.packet_traces:
                            self._add_completed_trace(trace)
                            del self.packet_traces[packet_key]

    def _get_skb_addr(self, skb_addr: int, chain_addr: int) -> int:
        if skb_addr == 0:
            self.skb_zero_count += 1
            if chain_addr != 0:
                return chain_addr
            else:
                addr = self.synthetic_id_counter
                self.synthetic_id_counter -= 1
                return addr
        return skb_addr

    def _make_packet_key(self, skb_addr: int, src_ip: int, dst_ip: int,
                         src_port: int, dst_port: int, protocol: int,
                         direction: str = "Unknown") -> str:
        if src_ip == 0 and dst_ip == 0 and src_port == 0 and dst_port == 0:
            return f"{skb_addr:x}:{direction}"

        try:
            src_ip_str = socket.inet_ntoa(struct.pack('<I', src_ip)) if src_ip else "0.0.0.0"
            dst_ip_str = socket.inet_ntoa(struct.pack('<I', dst_ip)) if dst_ip else "0.0.0.0"
        except:
            src_ip_str = "0.0.0.0"
            dst_ip_str = "0.0.0.0"


        return f"{skb_addr:x}:{protocol}:{src_ip_str}:{src_port}:{dst_ip_str}:{dst_port}:{direction}"

    def _update_stats(self):
        now = time.time()
        if now - self.last_stats_time >= 1.0:
            self.events_per_second = self.total_events - self.last_event_count
            self.last_event_count = self.total_events
            self.last_stats_time = now

    def _export_json(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"trace_{self.mode}_{self.session_id}_{timestamp}.json"
        output_path = os.path.join(OUTPUT_DIR, filename)

        valuable_traces = [trace for trace in self.completed_traces if trace.is_valuable_trace()]

        inbound_completed = sum(1 for t in self.completed_traces if t.direction == 'Inbound')
        outbound_completed = sum(1 for t in self.completed_traces if t.direction == 'Outbound')
        inbound_valuable = sum(1 for t in valuable_traces if t.direction == 'Inbound')
        outbound_valuable = sum(1 for t in valuable_traces if t.direction == 'Outbound')

        print(f"\n[EXPORT DEBUG] Total completed traces: {len(self.completed_traces)}")
        print(f"[EXPORT DEBUG]   - Inbound: {inbound_completed} (valuable: {inbound_valuable})")
        print(f"[EXPORT DEBUG]   - Outbound: {outbound_completed} (valuable: {outbound_valuable})")
        print(f"[EXPORT DEBUG] Exporting {len(valuable_traces)} valuable traces to JSON\n")

        total_traces = len(self.completed_traces)
        filtered_count = total_traces - len(valuable_traces)

        summary = {
            'session': {
                'id': self.session_id, 'mode': self.mode,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.end_time else 0,
                'hostname': self.hostname, 'kernel_version': self.kernel_version,
                'excluded_ports': list(EXCLUDED_PORTS),
            },
            'statistics': {
                'total_events': self.total_events,
                'total_packets': total_traces,
                'valuable_packets': len(valuable_traces),
                'filtered_packets': filtered_count,
                'filter_reduction_pct': round((filtered_count / total_traces * 100), 2) if total_traces > 0 else 0,
            },
            'traces': [trace.to_summary() for trace in valuable_traces]
        }

        if self.mode == 'full':
            summary['statistics'].update({
                'functions_traced': len(self.functions),
                'functions_hit': len(self.events_by_func),
                'top_functions': dict(sorted(self.events_by_func.items(),
                                            key=lambda x: x[1], reverse=True)[:20])
            })
            summary['functions_list'] = self.functions

            summary['statistics'].update({
                'pipeline_stats': {
                    'Inbound': dict(self.stats_by_direction_layer['Inbound']),
                    'Outbound': dict(self.stats_by_direction_layer['Outbound'])
                },
                'inbound_packets': sum(1 for t in self.completed_traces if t.direction == 'Inbound'),
                'outbound_packets': sum(1 for t in self.completed_traces if t.direction == 'Outbound'),
                'layer_verdicts': dict(self.layer_verdicts),
                'nft_verdicts': dict(self.nft_verdicts),
                'total_layer_verdicts': sum(self.layer_verdicts.values()),
                'total_nft_verdicts': sum(self.nft_verdicts.values()),
                'drops_by_layer': dict(self.drops_by_layer),
                'total_drops': sum(self.drops_by_layer.values())
            })

        if self.mode in ['nft', 'full']:
            drops = sum(1 for t in self.completed_traces if t.final_verdict in [0, 2])
            accepts = sum(1 for t in self.completed_traces if t.final_verdict == 1)
            summary['statistics'].update({
                'packets_dropped': drops,
                'packets_accepted': accepts,
            })

        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"[✓] Exported {len(valuable_traces)} valuable traces to {output_path}")
        if filtered_count > 0:
            print(f"[i] Filtered out {filtered_count} low-value traces ({summary['statistics']['filter_reduction_pct']}% reduction)")
        return output_path

    def get_stats(self) -> Dict:
        with self.lock:
            stats = {
                'session_id': self.session_id, 'mode': self.mode,
                'running': self.running, 'total_events': self.total_events,
                'events_per_second': self.events_per_second,
                'active_packets': len(self.packet_traces),
                'completed_packets': len(self.completed_traces),
                'functions_traced': len(self.functions) if self.mode == 'full' else 0,
                'functions_hit': len(self.events_by_func) if self.mode == 'full' else 0,
                'start_time': self.start_time.isoformat(),
                'uptime_seconds': (datetime.now() - self.start_time).total_seconds(),
                'filter_enabled': self.filter_enabled,
                'trace_filter': self.trace_filter if self.filter_enabled else None
            }

            if self.mode == 'full':
                stats.update({
                    'stats': {
                        'Inbound': dict(self.stats_by_direction_layer['Inbound']),
                        'Outbound': dict(self.stats_by_direction_layer['Outbound'])
                    },
                    'layer_verdicts': dict(self.layer_verdicts),
                    'nft_verdicts': dict(self.nft_verdicts),
                    'total_layer_verdicts': sum(self.layer_verdicts.values()),
                    'total_nft_verdicts': sum(self.nft_verdicts.values()),
                    'drops_by_layer': dict(self.drops_by_layer),
                    'total_drops': sum(self.drops_by_layer.values())
                })

            return stats

class SessionManager:
    def __init__(self, realtime_ext=None):
        self.sessions: Dict[str, TraceSession] = {}
        self.lock = threading.Lock()
        self.realtime = realtime_ext
    def create_session(self, session_id: str, mode: str = "nft",
                      pcap_filter: str = "", max_functions: int = 30,
                      trace_filter: dict = None) -> bool:
        with self.lock:
            if session_id in self.sessions:
                return False

            session = TraceSession(session_id, mode, pcap_filter, max_functions, trace_filter)
            if session.start():
                self.sessions[session_id] = session
                return True
            return False

    def stop_session(self, session_id: str) -> Optional[str]:
        with self.lock:
            if session_id not in self.sessions:
                return None
            session = self.sessions[session_id]
            output_path = session.stop()
            del self.sessions[session_id]
            return output_path

    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        with self.lock:
            if session_id not in self.sessions:
                return None
            return self.sessions[session_id].get_stats()

    def list_sessions(self) -> List[Dict]:
        with self.lock:
            return [session.get_stats() for session in self.sessions.values()]

session_manager = SessionManager(realtime_ext=realtime if REALTIME_AVAILABLE else None)

# Create database tables
with app.app_context():
    db.create_all()
    init_default_user()
    print("[✓] Database initialized")

# Register metrics API routes
register_metrics_api(app)
register_realtime_metrics_api(app)

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user and return JWT tokens"""
    try:
        data = request.json or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')

        user, error = authenticate_user(username, password)
        if error:
            return jsonify({'error': error}), 401

        tokens = create_tokens(user.id)
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'user': user.to_dict(),
            'first_login': user.first_login,
            **tokens
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(user=None):
    """Get current user info"""
    return jsonify({
        'status': 'success',
        'user': user.to_dict() if user else None
    }), 200


@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401

        tokens = create_tokens(user.id)
        return jsonify({
            'status': 'success',
            'message': 'Token refreshed',
            **tokens
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout(user=None):
    """Logout user (client-side token deletion)"""
    return jsonify({
        'status': 'success',
        'message': 'Logout successful. Please delete the token on client-side.'
    }), 200


@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_pwd(user=None):
    """Change user password (required after first login)"""
    try:
        data = request.json or {}
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')

        if not old_password or not new_password:
            return jsonify({'error': 'Old password and new password are required'}), 400

        success, error = change_password(user.id, old_password, new_password)
        if not success:
            return jsonify({'error': error}), 400

        # Refresh user data
        user = User.query.get(user.id)
        return jsonify({
            'status': 'success',
            'message': 'Password changed successfully',
            'user': user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok', 'bcc_available': BCC_AVAILABLE,
        'realtime_available': REALTIME_AVAILABLE,
        'timestamp': datetime.now().isoformat(),
        'kernel': platform.release(), 'hostname': socket.gethostname()
    })

@app.route('/api/discover', methods=['POST'])
def discover_functions():
    try:
        data = request.json or {}
        discoverer = BTFSKBDiscoverer()
        functions = discoverer.discover_from_btf()
        functions = discoverer.filter_by_priority(data.get('max_priority', 2))
        discoverer.export_json(FUNCTIONS_CACHE)
        return jsonify({
            'status': 'success', 'total_discovered': len(functions),
            'functions': [f.name for f in functions[:50]]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/functions', methods=['GET'])
def get_functions():
    if not os.path.exists(FUNCTIONS_CACHE):
        return jsonify({'error': 'Functions not discovered'}), 404
    with open(FUNCTIONS_CACHE, 'r') as f:
        return jsonify(json.load(f))

@app.route('/api/functions/fixed', methods=['GET'])
def get_fixed_functions():

    function_map = {
        'XDP Layer': {
            'functions': ['xdp_do_redirect', 'xdp_do_generic_redirect'],
            'hooks': ['PREROUTING'],
            'description': 'eXpress Data Path - Fast packet processing'
        },
        'Driver RX (Receive)': {
            'functions': ['napi_gro_receive', 'netif_receive_skb', '__netif_receive_skb_core',
                         'netif_receive_skb_internal', 'eth_type_trans', 'netif_receive_skb_list_internal'],
            'hooks': ['PREROUTING'],
            'description': 'Network device driver receive path'
        },
        'Driver TX (Transmit)': {
            'functions': ['dev_queue_xmit', '__dev_queue_xmit', 'dev_hard_start_xmit', 'sch_direct_xmit'],
            'hooks': ['POSTROUTING'],
            'description': 'Network device driver transmit path'
        },
        'TC (Traffic Control)': {
            'functions': ['dev_queue_xmit_nit', 'tcf_classify'],
            'hooks': ['PREROUTING', 'POSTROUTING'],
            'description': 'Traffic control and QoS'
        },
        'IP Layer - Receive': {
            'functions': ['ip_rcv', 'ip_rcv_core', 'ip_rcv_finish', 'ip_local_deliver', 'ip_local_deliver_finish'],
            'hooks': ['PREROUTING', 'INPUT'],
            'description': 'IP receive and local delivery'
        },
        'IP Layer - Forward': {
            'functions': ['ip_forward', 'ip_forward_finish', 'ip_forward_options'],
            'hooks': ['FORWARD'],
            'description': 'IP packet forwarding'
        },
        'IP Layer - Output': {
            'functions': ['ip_local_out', '__ip_local_out', 'ip_output', 'ip_finish_output', 'ip_finish_output2'],
            'hooks': ['OUTPUT', 'POSTROUTING'],
            'description': 'IP output and transmission'
        },
        'Netfilter Core': {
            'functions': ['nf_hook_slow', 'nf_hook_thresh', 'nf_reinject', 'nf_queue'],
            'hooks': ['ALL'],
            'description': 'Core netfilter hook processing'
        },
        'Connection Tracking': {
            'functions': ['nf_conntrack_in', 'nf_confirm', 'nf_conntrack_alloc'],
            'hooks': ['PREROUTING', 'OUTPUT'],
            'description': 'Connection tracking subsystem'
        },
        'Routing': {
            'functions': ['ip_route_input_slow', 'ip_route_input_noref', 'ip_route_output_key_hash', 'fib_validate_source'],
            'hooks': ['PREROUTING', 'OUTPUT'],
            'description': 'IP routing decision'
        },
        'TCP Transport': {
            'functions': ['tcp_v4_rcv', 'tcp_v4_do_rcv', 'tcp_rcv_established', 'tcp_sendmsg', 'tcp_write_xmit', 'tcp_transmit_skb'],
            'hooks': ['INPUT', 'OUTPUT'],
            'description': 'TCP protocol processing'
        },
        'UDP Transport': {
            'functions': ['udp_rcv', 'udp_unicast_rcv_skb', 'udp_sendmsg', 'udp_send_skb'],
            'hooks': ['INPUT', 'OUTPUT'],
            'description': 'UDP protocol processing'
        },
        'Additional': {
            'functions': ['ip_sabotage_in', 'ip_sabotage_out'],
            'hooks': ['INPUT', 'OUTPUT'],
            'description': 'Additional kernel hooks'
        }
    }

    return jsonify({
        'total_functions': len(FIXED_TRACE_FUNCTIONS),
        'function_map': function_map,
        'functions_list': FIXED_TRACE_FUNCTIONS,
        'hook_mapping': {
            'PREROUTING': 0,
            'INPUT': 1,
            'FORWARD': 2,
            'OUTPUT': 3,
            'POSTROUTING': 4
        }
    })

@app.route('/api/sessions', methods=['GET'])
@token_required
def list_sessions(user=None):
    return jsonify({'sessions': session_manager.list_sessions()})

@app.route('/api/sessions', methods=['POST'])
@token_required
def create_session(user=None):
    data = request.json
    session_id = data.get('session_id', f"trace_{int(time.time() * 1000)}")
    mode = data.get('mode', 'nft')

    if mode not in ['nft', 'full']:
        return jsonify({'error': 'Invalid mode. Use: nft or full'}), 400

    # NEW: Parse trace filter
    trace_filter = data.get('trace_filter', {})
    # Clean empty values from filter
    trace_filter = {k: v for k, v in trace_filter.items() if v}

    success = session_manager.create_session(
        session_id, mode, data.get('pcap_filter', ''), data.get('max_functions', 50),
        trace_filter
    )

    if success:
        return jsonify({'status': 'started', 'session_id': session_id, 'mode': mode}), 201
    return jsonify({'error': 'Failed to start'}), 400

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@token_required
def stop_session(session_id, user=None):
    output_path = session_manager.stop_session(session_id)
    if output_path:
        return jsonify({'status': 'stopped', 'output_file': os.path.basename(output_path)})
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/sessions/<session_id>/stats', methods=['GET'])
@token_required
def get_session_stats(session_id, user=None):
    stats = session_manager.get_session_stats(session_id)
    if stats:
        return jsonify(stats)
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/download/<filename>', methods=['GET'])
@token_required
def download_file(filename, user=None):
    file_path = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/files', methods=['GET'])
@token_required
def list_files(user=None):
    files = []
    for filename in os.listdir(OUTPUT_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(OUTPUT_DIR, filename)
            stat = os.stat(filepath)
            files.append({
                'filename': filename, 'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
    files.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({'files': files})

@app.route('/api/modes', methods=['GET'])
def get_modes():
    return jsonify({
        'modes': [
            {'id': 'nft', 'name': 'NFT Tracer',
             'description': 'Trace nftables rules và verdicts'},
            {'id': 'full', 'name': 'Full Tracer (Recommended)',
             'description': 'Trace ĐẦY ĐỦ: ở tất cả layers (XDP, TC, Netfilter, Routing, Driver,...)',
             'function_count': len(FIXED_TRACE_FUNCTIONS),
             'recommended': True}
        ]
    })

class TraceAnalyzer:

    @staticmethod
    def load_trace_file(filename: str) -> Optional[Dict]:
        file_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading trace file {filename}: {e}")
            return None

    @staticmethod
    def filter_packets(traces: List[Dict], filters: Dict) -> List[Dict]:
        filtered = traces

        if 'src_ip' in filters and filters['src_ip']:
            filtered = [t for t in filtered if t.get('src_ip') == filters['src_ip']]
        if 'dst_ip' in filters and filters['dst_ip']:
            filtered = [t for t in filtered if t.get('dst_ip') == filters['dst_ip']]

        if 'src_port' in filters and filters['src_port']:
            try:
                port = int(filters['src_port'])
                filtered = [t for t in filtered if t.get('src_port') == port]
            except ValueError:
                pass
        if 'dst_port' in filters and filters['dst_port']:
            try:
                port = int(filters['dst_port'])
                filtered = [t for t in filtered if t.get('dst_port') == port]
            except ValueError:
                pass

        if 'protocol' in filters and filters['protocol']:
            proto = filters['protocol'].upper()
            filtered = [t for t in filtered if t.get('protocol_name') == proto]

        if 'skb' in filters and filters['skb']:
            filtered = [t for t in filtered if filters['skb'].lower() in str(t.get('skb_addr', '')).lower()]

        if 'hook' in filters and filters['hook']:
            hook = filters['hook'].upper()
            filtered = [t for t in filtered if t.get('hook_name') == hook]

        if 'verdict' in filters and filters['verdict']:
            verdict = filters['verdict'].upper()
            filtered = [t for t in filtered if t.get('final_verdict') == verdict]

        if 'any_verdict' in filters and filters['any_verdict']:
            verdict = filters['any_verdict'].upper()
            def has_verdict(trace):
                if trace.get('final_verdict') == verdict:
                    return True

                nft_events = trace.get('nft_events', [])
                for event in nft_events:
                    event_verdict = event.get('verdict')
                    if event_verdict:
                        if isinstance(event_verdict, str) and event_verdict.upper() == verdict:
                            return True
                        elif isinstance(event_verdict, int):
                            verdict_map = {0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
                                          3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
                                          -1: 'JUMP', -2: 'GOTO', -3: 'RETURN'}
                            if verdict_map.get(event_verdict, '').upper() == verdict:
                                return True

                events = trace.get('important_events', [])
                for event in events:
                    event_verdict = event.get('verdict_str') or event.get('verdict')
                    if event_verdict:
                        if isinstance(event_verdict, str) and event_verdict.upper() == verdict:
                            return True
                        elif isinstance(event_verdict, int):
                            verdict_map = {0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
                                          3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
                                          -1: 'JUMP', -2: 'GOTO', -3: 'RETURN'}
                            if verdict_map.get(event_verdict, '').upper() == verdict:
                                return True
                return False
            filtered = [t for t in filtered if has_verdict(t)]

        if 'had_verdict_change' in filters and filters['had_verdict_change']:
            if filters['had_verdict_change'].lower() in ['true', '1', 'yes']:
                filtered = [t for t in filtered if t.get('verdict_changes', 0) > 0]

        if 'function' in filters and filters['function']:
            func = filters['function'].lower()
            filtered = [t for t in filtered
                       if any(func in f.lower() for f in t.get('functions_path', []))]

        if 'keyword' in filters and filters['keyword']:
            keyword = filters['keyword'].lower()
            filtered = [t for t in filtered
                       if keyword in json.dumps(t).lower()]

        return filtered

    @staticmethod
    def get_packet_detail(trace_data: Dict, packet_index: int) -> Optional[Dict]:
        traces = trace_data.get('traces', [])
        if packet_index < 0 or packet_index >= len(traces):
            return None

        packet = traces[packet_index]


        analysis = TraceAnalyzer._analyze_packet_flow(packet)

        return {
            **packet,
            'packet_index': packet_index,
            'analysis': analysis
        }

    @staticmethod
    def _analyze_packet_flow(packet: Dict) -> Dict:
        analysis = {
            'verdict_chain': [],
            'jump_goto_chain': [],
            'drop_reason': None,
            'flow_summary': []
        }

        verdict_map = {
            0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
            3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
            -1: 'JUMP', -2: 'GOTO', -3: 'RETURN'
        }

        nft_events = packet.get('nft_events', [])
        for event in nft_events:
            trace_type = event.get('trace_type')

            if trace_type in ['chain_exit', 'hook_exit', 'rule_eval']:
                verdict_str = event.get('verdict')
                if isinstance(verdict_str, int):
                    verdict_str = verdict_map.get(verdict_str, f'UNKNOWN({verdict_str})')

                verdict_info = {
                    'timestamp': event.get('timestamp'),
                    'type': trace_type,
                    'verdict': verdict_str,
                    'hook': event.get('hook'),
                    'hook_name': f'HOOK_{event.get("hook")}' if event.get('hook') is not None else None,
                    'chain_addr': event.get('chain_addr'),
                    'chain_depth': event.get('chain_depth'),
                    'pf': event.get('pf')
                }

                if trace_type == 'rule_eval':
                    verdict_info['rule_handle'] = event.get('rule_handle')
                    verdict_info['rule_seq'] = event.get('rule_seq')

                analysis['verdict_chain'].append(verdict_info)

                if verdict_str in ['JUMP', 'GOTO']:
                    analysis['jump_goto_chain'].append({
                        'source_chain': event.get('chain_addr'),
                        'target_chain': None,
                        'verdict_type': verdict_str
                    })

        if not nft_events:
            events = packet.get('important_events', [])
            for event in events:
                trace_type = event.get('trace_type')

                if trace_type in ['chain_exit', 'hook_exit']:
                    verdict_info = {
                        'timestamp': event.get('timestamp'),
                        'type': trace_type,
                        'verdict': event.get('verdict_str'),
                        'hook': event.get('hook_name'),
                        'chain': event.get('chain_name'),
                        'table': event.get('table_name')
                    }
                    analysis['verdict_chain'].append(verdict_info)

                    if event.get('verdict_str') in ['JUMP', 'GOTO']:
                        analysis['jump_goto_chain'].append({
                            'source_chain': event.get('chain_name'),
                            'target_chain': event.get('target_chain'),
                            'verdict_type': event.get('verdict_str')
                        })

                elif trace_type == 'rule_eval':
                    pass

        final_verdict = packet.get('final_verdict')
        if final_verdict == 'DROP':
            last_verdict = analysis['verdict_chain'][-1] if analysis['verdict_chain'] else None
            if last_verdict:
                analysis['drop_reason'] = {
                    'hook': last_verdict.get('hook'),
                    'chain': last_verdict.get('chain'),
                    'table': last_verdict.get('table'),
                    'reason': f"Packet dropped at {last_verdict.get('hook')} in chain {last_verdict.get('chain')}"
                }

        functions = packet.get('functions_path', [])
        if functions:
            layers = {
                'Network Device': ['netif_receive_skb', '__netif_receive_skb_core'],
                'IP Layer': ['ip_rcv', 'ip_rcv_finish', 'ip_local_deliver', 'ip_forward', 'ip_output'],
                'Transport': ['tcp_v4_rcv', 'udp_rcv'],
                'Netfilter': ['nf_hook_slow', 'nf_conntrack_in'],
            }

            for layer, layer_funcs in layers.items():
                matched = [f for f in functions if any(lf in f for lf in layer_funcs)]
                if matched:
                    analysis['flow_summary'].append({
                        'layer': layer,
                        'functions': matched
                    })

        return analysis

@app.route('/api/traces/<filename>', methods=['GET'])
@token_required
def get_trace_file(filename, user=None):
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    return jsonify(trace_data)

@app.route('/api/traces/<filename>/packets', methods=['GET'])
@token_required
def get_trace_packets(filename, user=None):
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    filters = {
        'src_ip': request.args.get('src_ip'),
        'dst_ip': request.args.get('dst_ip'),
        'src_port': request.args.get('src_port'),
        'dst_port': request.args.get('dst_port'),
        'protocol': request.args.get('protocol'),
        'skb': request.args.get('skb'),
        'hook': request.args.get('hook'),
        'verdict': request.args.get('verdict'),
        'any_verdict': request.args.get('any_verdict'),
        'had_verdict_change': request.args.get('had_verdict_change'),
        'function': request.args.get('function'),
        'keyword': request.args.get('keyword')
    }

    filters = {k: v for k, v in filters.items() if v}

    traces = trace_data.get('traces', [])

    for i, trace in enumerate(traces):
        trace['original_index'] = i

    filtered_traces = TraceAnalyzer.filter_packets(traces, filters)

    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 100))
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'session': trace_data.get('session'),
        'statistics': trace_data.get('statistics'),
        'filters_applied': filters,
        'total_packets': len(filtered_traces),
        'page': page,
        'per_page': per_page,
        'packets': filtered_traces[start:end]
    })

@app.route('/api/traces/<filename>/packets/<int:packet_index>', methods=['GET'])
@token_required
def get_packet_detail(filename, packet_index, user=None):
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    packet_detail = TraceAnalyzer.get_packet_detail(trace_data, packet_index)
    if packet_detail is None:
        return jsonify({'error': 'Packet not found'}), 404

    return jsonify(packet_detail)


@app.route('/api/nft/health', methods=['GET'])
@token_required
def nft_health(user=None):
    available, message = NFTablesManager.check_nft_available()
    return jsonify({
        'available': available,
        'message': message
    })

@app.route('/api/nft/rules', methods=['GET'])
@token_required
def get_nft_rules(user=None):
    success, ruleset, error = NFTablesManager.get_ruleset()

    if not success:
        return jsonify({'error': error}), 500

    tree = NFTablesManager.parse_ruleset_to_tree(ruleset)

    return jsonify({
        'success': True,
        'raw_ruleset': ruleset,
        'tree': tree
    })

@app.route('/api/nft/tables', methods=['GET'])
@token_required
def get_nft_tables(user=None):
    success, tables, error = NFTablesManager.get_tables()

    if not success:
        return jsonify({'error': error}), 500

    return jsonify({
        'success': True,
        'tables': tables
    })

@app.route('/api/nft/chains/<family>/<table>', methods=['GET'])
@token_required
def get_nft_chains(family, table, user=None):
    success, chains, error = NFTablesManager.get_chains(family, table)

    if not success:
        return jsonify({'error': error}), 500

    return jsonify({
        'success': True,
        'chains': chains
    })

@app.route('/api/nft/rule/add', methods=['POST'])
@token_required
def add_nft_rule(user=None):
    data = request.get_json()

    family = data.get('family')
    table = data.get('table')
    chain = data.get('chain')
    rule_text = data.get('rule_text')

    if not all([family, table, chain, rule_text]):
        return jsonify({
            'success': False,
            'error': 'Missing required parameters: family, table, chain, rule_text'
        }), 400

    success, error = NFTablesManager.add_rule(family, table, chain, rule_text)

    if not success:
        return jsonify({
            'success': False,
            'error': error
        }), 500

    return jsonify({
        'success': True,
        'message': 'Rule added successfully'
    })

@app.route('/api/nft/rule/delete', methods=['POST'])
@token_required
def delete_nft_rule(user=None):
    data = request.get_json()

    family = data.get('family')
    table = data.get('table')
    chain = data.get('chain')
    handle = data.get('handle')

    if not all([family, table, chain]) or handle is None:
        return jsonify({
            'success': False,
            'error': 'Missing required parameters: family, table, chain, handle'
        }), 400

    success, error = NFTablesManager.delete_rule(family, table, chain, handle)

    if not success:
        return jsonify({
            'success': False,
            'error': error
        }), 500

    return jsonify({
        'success': True,
        'message': 'Rule deleted successfully'
    })

@app.route('/api/nft/rule/update', methods=['POST'])
@token_required
def update_nft_rule(user=None):
    data = request.get_json()

    family = data.get('family')
    table = data.get('table')
    chain = data.get('chain')
    handle = data.get('handle')
    new_rule_text = data.get('new_rule_text')

    if not all([family, table, chain, new_rule_text]) or handle is None:
        return jsonify({
            'success': False,
            'error': 'Missing required parameters: family, table, chain, handle, new_rule_text'
        }), 400

    success, error = NFTablesManager.update_rule(family, table, chain, handle, new_rule_text)

    if not success:
        return jsonify({
            'success': False,
            'error': error
        }), 500

    return jsonify({
        'success': True,
        'message': 'Rule updated successfully'
    })

if __name__ == '__main__':
    print("=" * 70)
    print("KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION")
    print("=" * 70)
    print(f"BCC: {'✓' if BCC_AVAILABLE else '✗'}")
    print(f"Realtime: {'✓' if REALTIME_AVAILABLE else '✗'}")
    print(f"Kernel: {platform.release()}")
    print(f"Hostname: {socket.gethostname()}")
    print("=" * 70)
    print("MODES:")
    print("  • nft       - NFT rules only")
    print("  • full      - 50 FIXED FUNCTIONS across all layers + NFT verdicts (recommended!)")
    print("              Covers: XDP, Driver, TC, IP (RX/FWD/TX), Netfilter, Routing, TCP, UDP, NAT, CT")
    print("=" * 70)

    if REALTIME_AVAILABLE:
        print("REALTIME VISUALIZATION:")
        print("  • WebSocket: ws://localhost:5000/realtime")
        print("  • Enable: POST /api/realtime/enable")
        print("  • Disable: POST /api/realtime/disable")
        print("  • Stats: GET /api/realtime/stats")
        print("=" * 70)

    print("\nAPI Endpoints:")
    print("  GET  /api/health")
    print("  POST /api/discover")
    print("  GET  /api/functions")
    print("  GET  /api/sessions")
    print("  POST /api/sessions")
    print("  DELETE /api/sessions/<id>")
    print("  GET  /api/sessions/<id>/stats")
    print("=" * 70)

    if REALTIME_AVAILABLE and socketio:
        print("\n[✓] Starting with SocketIO support (Realtime enabled)")
        print("[*] Server running on http://0.0.0.0:5000")
        print("[*] WebSocket endpoint: ws://0.0.0.0:5000/socket.io/")
        print("[*] CORS: enabled for all origins")
        print("-" * 70)
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False,
            log_output=True
        )
    else:
        print("\n[✓] Starting standard Flask server (No realtime)")
        print("[*] Server running on http://0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)