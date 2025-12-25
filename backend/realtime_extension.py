#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from bcc import BPF
import ctypes as ct

# Monitoring module
from monitoring.alert_engine import AlertEngine

# Metrics bucket manager for time-series
from metrics_bucket_manager import MetricsBucketManager
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
    EXCLUDED_PORTS, should_filter_event
)


HOOK_ORDER = ["PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"]

LAYER_MAP = {
    "Ingress": [
        "netif_receive_skb", "__netif_receive_skb_core",
        "__netif_receive_skb_one_core", "netif_rx"
    ],
    "L2": [
        "br_handle_frame", "br_forward", "br_nf_pre_routing",
        "br_nf_forward"
    ],
    "IP": [
        "ip_rcv", "ip_rcv_finish", "ip_forward", "ip_forward_finish",
        "ip_local_deliver", "ip_local_deliver_finish",
        "ip_output", "ip_finish_output", "ip_finish_output2",
        "ipv4_mtu", "ip_route_input_slow", "ip_route_output_key_hash"
    ],
    "Firewall": [
        "nf_hook_slow", "nft_do_chain", "nft_immediate_eval",
        "nf_conntrack_in", "nf_nat_packet", "nf_nat_manip_pkt",
        "ipt_do_table", "xt_match_target"
    ],
    "Socket": [
        "tcp_v4_rcv", "tcp_v4_do_rcv", "tcp_rcv_established",
        "tcp_transmit_skb", "tcp_write_xmit",
        "udp_rcv", "__udp4_lib_rcv", "udp_sendmsg",
        "inet_sendmsg", "inet_recvmsg", "__sk_receive_skb"
    ],
    "Egress": [
        "dev_queue_xmit", "__dev_queue_xmit", "dev_hard_start_xmit",
        "sch_direct_xmit", "__dev_xmit_skb"
    ]
}

HOOK_LAYER_MAP = {
    "PRE_ROUTING": ["Ingress", "L2", "IP", "Firewall"],
    "LOCAL_IN": ["IP", "Firewall", "Socket"],
    "FORWARD": ["IP", "Firewall"],
    "LOCAL_OUT": ["Socket", "Firewall", "IP", "Egress"],
    "POST_ROUTING": ["Firewall", "Egress"],
    "UNKNOWN": ["Ingress", "L2", "IP", "Firewall", "Socket", "Egress"]
}

LAYER_ORDER = ["Ingress", "L2", "IP", "Firewall", "Socket", "Egress"]


@dataclass
class NodeStats:
    count: int = 0
    unique_skbs: set = field(default_factory=set)

    # MEMORY LEAK FIX: Replace unbounded list with streaming statistics
    # Instead of storing ALL latency values (22+ MB/sec growth!), keep only summary stats
    latency_count: int = 0
    latency_sum: float = 0.0
    latency_min: float = float('inf')
    latency_max: float = 0.0
    # Keep only last 1000 samples for percentile calculation
    latencies_us: deque = field(default_factory=lambda: deque(maxlen=1000))

    function_calls: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_count: int = 0
    drop_count: int = 0
    truncated_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    in_flight_packets: set = field(default_factory=set)  # packets currently on this node

    # For packet rate calculation
    previous_count: int = 0
    previous_ts: Optional[float] = None

    def add_event(self, skb_addr: str, latency_us: float = 0, function: str = None,
                  verdict: str = None, error: bool = False):
        self.count += 1

   
        if skb_addr and skb_addr != '':
            self.unique_skbs.add(skb_addr)
            if len(self.unique_skbs) > 5000:
                # Keep only recent 3000 SKBs
                skb_list = list(self.unique_skbs)
                self.unique_skbs = set(skb_list[-3000:])

        if latency_us > 0:
            self.latency_count += 1
            self.latency_sum += latency_us
            self.latency_min = min(self.latency_min, latency_us)
            self.latency_max = max(self.latency_max, latency_us)
            self.latencies_us.append(latency_us) 

 
        if function:
            self.function_calls[function] += 1
            if len(self.function_calls) > 200:

                sorted_funcs = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)
                self.function_calls = defaultdict(int, dict(sorted_funcs[:100]))


        if verdict and verdict != 'UNKNOWN':
            self.verdict_breakdown[verdict] += 1
            if verdict == 'DROP':
                self.drop_count += 1

            if len(self.verdict_breakdown) > 50:
                sorted_verdicts = sorted(self.verdict_breakdown.items(), key=lambda x: x[1], reverse=True)
                self.verdict_breakdown = defaultdict(int, dict(sorted_verdicts[:20]))

        if error:
            self.error_count += 1

    def get_latency_percentiles(self) -> Dict[str, float]:
        if self.latency_count == 0:
            return {'p50': 0, 'p90': 0, 'p99': 0, 'avg': 0, 'min': 0, 'max': 0}

        # Use streaming average for efficiency
        avg = self.latency_sum / self.latency_count

        # Calculate percentiles from last 1000 samples (if available)
        if len(self.latencies_us) > 0:
            import numpy as np
            latencies = np.array(list(self.latencies_us))
            return {
                'p50': float(np.percentile(latencies, 50)),
                'p90': float(np.percentile(latencies, 90)),
                'p99': float(np.percentile(latencies, 99)),
                'avg': float(avg),
                'min': float(self.latency_min),
                'max': float(self.latency_max)
            }
        else:
            return {
                'p50': float(avg),
                'p90': float(avg),
                'p99': float(avg),
                'avg': float(avg),
                'min': float(self.latency_min),
                'max': float(self.latency_max)
            }

    def get_top_functions(self, limit: int = 3) -> List[Dict]:
        if not self.function_calls:
            return []

        total = sum(self.function_calls.values())
        top_funcs = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)[:limit]

        return [
            {
                'name': func,
                'count': count,
                'pct': round((count / total) * 100, 1) if total > 0 else 0
            }
            for func, count in top_funcs
        ]

    def calculate_packet_rate(self, current_ts: float) -> float:
        if self.previous_ts is None:
            # First calculation - initialize
            self.previous_count = self.count
            self.previous_ts = current_ts
            return 0.0

        time_delta = current_ts - self.previous_ts
        if time_delta <= 0:
            return 0.0

        count_delta = self.count - self.previous_count
        rate = count_delta / time_delta

        # Update for next calculation
        self.previous_count = self.count
        self.previous_ts = current_ts

        return round(rate, 1)

    def to_dict(self, current_ts: Optional[float] = None) -> Dict:
        latency = self.get_latency_percentiles()
        verdict_dict = dict(self.verdict_breakdown) if self.verdict_breakdown else None

        # Calculate packet rate if timestamp provided
        packet_rate = 0.0
        if current_ts is not None:
            packet_rate = self.calculate_packet_rate(current_ts)

        return {
            'count': self.count,
            'unique_packets': len(self.unique_skbs),
            'latency': latency,
            'top_functions': self.get_top_functions(3),
            'verdict': verdict_dict,
            'errors': self.error_count,
            'drops': self.drop_count,
            'truncated': self.truncated_count,
            'in_flight': len(self.in_flight_packets),
            'packet_rate': packet_rate  # packets/sec
        }

@dataclass
class EdgeStats:
    from_node: str
    to_node: str
    count: int = 0

    def to_dict(self) -> Dict:
        return {
            'from': self.from_node,
            'to': self.to_node,
            'count': self.count
        }

@dataclass
class PipelineStats:
    unique_skbs: set = field(default_factory=set)  # all SKBs that ever entered this pipeline
    active_nodes: set = field(default_factory=set)  # nodes that belong to this pipeline

    def to_dict(self, nodes_dict: Dict[str, 'NodeStats']) -> Dict:
        started = len(self.unique_skbs)
        in_flight = self.calculate_in_flight_from_nodes(nodes_dict)
        completed = started - in_flight

        return {
            'started': started,
            'completed': completed,
            'in_progress': in_flight,  # renamed from in_progress to match
            'calculated_in_flight': in_flight
        }

    def calculate_in_flight_from_nodes(self, nodes_dict: Dict[str, 'NodeStats']) -> int:
        """Calculate total in-flight packets from nodes belonging to this pipeline"""
        total = 0
        for node_name in self.active_nodes:
            if node_name in nodes_dict:
                total += len(nodes_dict[node_name].in_flight_packets)
        return total

@dataclass
class PacketEvent:
    timestamp: float
    skb_addr: str
    cpu_id: int
    pid: int
    event_type: int
    hook: int
    hook_name: str
    pf: int
    protocol: int
    protocol_name: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    verdict: int
    verdict_name: str
    error_code: int
    error_name: str
    function: str
    layer: str
    comm: str
    
    chain_addr: Optional[str] = None
    rule_seq: Optional[int] = None
    rule_handle: Optional[int] = None
    queue_num: Optional[int] = None
    trace_type: Optional[str] = None  # NEW: "rule_eval", "chain_exit", "hook_exit" for NFT events

@dataclass
class LayerStats:
    packets_in: int = 0
    packets_out: int = 0
    drops: int = 0
    accepts: int = 0
    errors: int = 0
    total_latency_ns: int = 0
    latency_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    function_calls: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    @property
    def avg_latency_ms(self) -> float:
        if self.latency_count == 0:
            return 0.0
        return (self.total_latency_ns / self.latency_count) / 1_000_000
    
    @property
    def drop_rate(self) -> float:
        total = self.packets_in
        if total == 0:
            return 0.0
        return (self.drops / total) * 100
    
    def to_dict(self) -> Dict:
        top_func = None
        top_func_count = 0
        if self.function_calls:
            top_func, top_func_count = max(
                self.function_calls.items(), 
                key=lambda x: x[1]
            )
        
        verdict_pct = {}
        if self.packets_in > 0:
            for verdict, count in self.verdict_breakdown.items():
                verdict_pct[verdict] = round((count / self.packets_in) * 100, 1)
        
        return {
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'drops': self.drops,
            'accepts': self.accepts,
            'errors': self.errors,
            'avg_latency_ms': round(self.avg_latency_ms, 3),
            'drop_rate': round(self.drop_rate, 2),
            'verdict_breakdown': dict(self.verdict_breakdown),
            'verdict_percentages': verdict_pct,
            'error_breakdown': dict(self.error_breakdown),
            'function_calls': dict(sorted(
                self.function_calls.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_function': top_func,
            'top_function_calls': top_func_count,
            'first_ts': self.first_ts,
            'last_ts': self.last_ts
        }

@dataclass
class HookStats:
    layers: Dict[str, LayerStats] = field(default_factory=dict)
    packets_total: int = 0
    
    def get_layer(self, layer_name: str) -> LayerStats:
        if layer_name not in self.layers:
            self.layers[layer_name] = LayerStats()
        return self.layers[layer_name]
    
    def to_dict(self) -> Dict:
        return {
            'packets_total': self.packets_total,
            'layers': {
                name: stats.to_dict() 
                for name, stats in self.layers.items()
            }
        }

class RealtimeStats:

    def __init__(self, trace_filter: dict = None):
        self.hooks: Dict[str, HookStats] = {}
        self.skb_tracking: Dict[str, Dict] = {}
        self.recent_events: deque = deque(maxlen=1000)
        self.total_packets = 0
        self.start_time = time.time()
        self._lock = threading.Lock()


        self.trace_filter = trace_filter or {}
        self.filter_enabled = any(v for v in self.trace_filter.values())
        self.filtered_events = 0  # Count of events filtered out

        self.packet_verdicts = defaultdict(int) 
        self.seen_verdicts = set()  
        self.seen_packets = set()  
        self.skb_state = {}  
      
        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        self.nodes: Dict[str, NodeStats] = {}  
        self.edges: Dict[tuple, EdgeStats] = {}  
        self.skb_paths: Dict[str, List[str]] = {}  
        self.pipeline_order = ['Inbound', 'Outbound', 'Local Delivery', 'Forward']
        self.pipelines: Dict[str, PipelineStats] = {
            'Inbound': PipelineStats(active_nodes={
                'GRO', 'TC Ingress', 'IP Receive',
                'Netfilter PREROUTING', 'Conntrack', 'Routing Decision'
            }),
            'Outbound': PipelineStats(active_nodes={
                'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                'Routing Lookup', 'TC Egress', 'Driver TX'
            }),
            'Local Delivery': PipelineStats(active_nodes={
                'Netfilter INPUT', 'TCP/UDP', 'Socket'
            }),
            'Forward': PipelineStats(active_nodes={
                'Netfilter FORWARD', 'Netfilter POSTROUTING', 'NIC TX'
            })
        }
    
    def get_hook(self, hook_name: str) -> HookStats:
        if hook_name not in self.hooks:
            self.hooks[hook_name] = HookStats()
        return self.hooks[hook_name]

    def get_node(self, node_name: str) -> NodeStats:
        if node_name not in self.nodes:
            self.nodes[node_name] = NodeStats()
        return self.nodes[node_name]

    def add_edge(self, from_node: str, to_node: str):
        edge_key = (from_node, to_node)
        if edge_key not in self.edges:
            self.edges[edge_key] = EdgeStats(from_node=from_node, to_node=to_node)
        self.edges[edge_key].count += 1

        if len(self.edges) > 500:
            # Keep only top 300 edges by count
            sorted_edges = sorted(self.edges.items(), key=lambda x: x[1].count, reverse=True)
            self.edges = dict(sorted_edges[:300])

    def count_packet_verdict(
        self,
        skb_addr: str,
        verdict_name: str,
        event_type: int,
        func_name: str,
        trace_type: Optional[str],
    ):

        if not skb_addr or not verdict_name or verdict_name == 'UNKNOWN':
            return


        if skb_addr not in self.skb_state:
            self.skb_state[skb_addr] = {
                'saw_nf_hook_slow': False,
                'has_rule_eval': False,
                'accept_counted': False,
            }


        if event_type == EVENT_TYPE_NFT_RULE:
            key = (skb_addr, verdict_name)
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts[verdict_name] += 1
                self.skb_state[skb_addr]['has_rule_eval'] = True
            return

        if event_type in [EVENT_TYPE_TC_VERDICT,
                          EVENT_TYPE_CT_VERDICT, EVENT_TYPE_ROUTE_VERDICT,
                          EVENT_TYPE_TCP_DROP, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_DROP]:
            key = (skb_addr, verdict_name)
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts[verdict_name] += 1
            return


        if verdict_name == 'ACCEPT':
            key = (skb_addr, 'ACCEPT')
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts['ACCEPT'] += 1

    def _detect_direction(self, hook_name: str, layer_name: str, function: str, hook: int) -> str:
        # First try to use function-based detection with unified mapping
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return detect_packet_direction(function, refined_layer, hook)

        # Fallback to hook-based detection
        if hook_name in ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD']:
            return 'Inbound'
        elif hook_name in ['LOCAL_OUT', 'POST_ROUTING']:
            return 'Outbound'

        # Layer-based fallback (old layer names)
        if layer_name in ['Ingress', 'L2']:
            return 'Inbound'
        elif layer_name == 'Egress':
            return 'Outbound'

        # Function-based fallback
        if function:
            func_lower = function.lower()
            if any(kw in func_lower for kw in ['rcv', 'receive', 'input', 'ingress', 'deliver']):
                return 'Inbound'
            elif any(kw in func_lower for kw in ['sendmsg', 'xmit', 'transmit', 'output', 'egress']):
                return 'Outbound'

        # Default to Inbound
        return 'Inbound'

    def _map_to_pipeline_layer(self, layer_name: str, function: str, hook: int) -> str:
        """Map function to new pipeline layer name using FUNCTION_TO_LAYER"""
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return refined_layer

        layer_map = {
            'IP': 'Routing Decision',
            'Firewall': 'Netfilter',
            'Socket': 'TCP/UDP',
            'Egress': 'Driver TX'
        }

        if layer_name in layer_map:
            return layer_map[layer_name]

        if function:
            func_lower = function.lower()
            if 'gro' in func_lower:
                return 'GRO'
            elif 'tc' in func_lower:
                return 'TC Ingress' if 'ingress' in func_lower else 'TC Egress'
            elif 'conntrack' in func_lower:
                return 'Conntrack'
            elif 'nat' in func_lower:
                if hook == 0:
                    return 'NAT PREROUTING'
                return 'NAT'
            elif 'route' in func_lower:
                if 'input' in func_lower:
                    return 'Routing Decision'
                elif 'output' in func_lower:
                    return 'Routing Lookup'
                return 'Routing'
            elif 'local_deliver' in func_lower:
                return 'Local Delivery'
            elif 'forward' in func_lower:
                return 'Forward'
            elif 'tcp' in func_lower or 'udp' in func_lower:
                if 'sendmsg' in func_lower or 'write' in func_lower or 'xmit' in func_lower:
                    return 'TCP/UDP Output'
                return 'TCP/UDP'
            elif 'sendmsg' in func_lower:
                return 'Application'

        return layer_name

    def _track_pipeline_membership(self, skb_addr: str, node_name: str):
        # Check which pipelines this node belongs to
        for pipeline_name, pipeline_stats in self.pipelines.items():
            if node_name in pipeline_stats.active_nodes:
                # Add this SKB to the pipeline's unique set
                pipeline_stats.unique_skbs.add(skb_addr)

                if len(pipeline_stats.unique_skbs) > 10000:
                    # Convert to list, remove oldest 2000, convert back to set
                    skb_list = list(pipeline_stats.unique_skbs)
                    pipeline_stats.unique_skbs = set(skb_list[2000:])

    def _matches_filter(self, event: PacketEvent) -> bool:
        if not self.filter_enabled:
            return True

        # Check src_ip
        if self.trace_filter.get('src_ip'):
            if event.src_ip != self.trace_filter['src_ip']:
                return False

        # Check dst_ip
        if self.trace_filter.get('dst_ip'):
            if event.dst_ip != self.trace_filter['dst_ip']:
                return False

        # Check src_port
        if self.trace_filter.get('src_port'):
            try:
                filter_port = int(self.trace_filter['src_port'])
                if event.src_port != filter_port:
                    return False
            except (ValueError, TypeError):
                pass

        # Check dst_port
        if self.trace_filter.get('dst_port'):
            try:
                filter_port = int(self.trace_filter['dst_port'])
                if event.dst_port != filter_port:
                    return False
            except (ValueError, TypeError):
                pass

        # Check protocol
        if self.trace_filter.get('protocol'):
            try:
                filter_protocol = int(self.trace_filter['protocol'])
                if event.protocol != filter_protocol:
                    return False
            except (ValueError, TypeError):
                pass

        # Check comm (process name)
        if self.trace_filter.get('comm'):
            if event.comm != self.trace_filter['comm']:
                return False

        return True

    def process_event(self, event: PacketEvent):
        """Process a single packet event and update statistics"""
        with self._lock:
            # Apply 5-tuple filtering if enabled
            if self.filter_enabled and not self._matches_filter(event):
                self.filtered_events += 1
                return  
            if event.skb_addr:
               
                self.seen_packets.add(event.skb_addr)

         
                if event.skb_addr not in self.skb_state:
                    self.skb_state[event.skb_addr] = {
                        'saw_nf_hook_slow': False,
                        'has_rule_eval': False,   
                        'accept_counted': False,
                    }

                
                if event.function and 'nf_hook_slow' in event.function:
                    self.skb_state[event.skb_addr]['saw_nf_hook_slow'] = True

               
                if len(self.skb_state) > 10000:
                    oldest = list(self.skb_state.keys())[:2000]
                    for k in oldest:
                        del self.skb_state[k]

        
            if event.verdict_name and event.verdict_name != 'UNKNOWN' and event.skb_addr:
                self.count_packet_verdict(
                    skb_addr=event.skb_addr,
                    verdict_name=event.verdict_name,
                    event_type=event.event_type,
                    func_name=event.function or "",
                    trace_type=event.trace_type,
                )

                # GC cho seen_verdicts
                if len(self.seen_verdicts) > 10000:
                    oldest = list(self.seen_verdicts)[:2000]
                    for k in oldest:
                        self.seen_verdicts.discard(k)


            if event.event_type == EVENT_TYPE_NF_VERDICT:
                return


            hook_name = event.hook_name
            layer_name = event.layer


            if hook_name == "UNKNOWN" or not layer_name:
                return

            hook = event.hook if event.hook != 255 else 0
            direction = self._detect_direction(hook_name, layer_name, event.function or '', hook)
            pipeline_layer = self._map_to_pipeline_layer(layer_name, event.function or '', hook)
            self.stats_by_direction_layer[direction][pipeline_layer] += 1

            node = self.get_node(pipeline_layer)

            latency_us = 0.0
            if event.skb_addr and event.skb_addr in self.skb_tracking:
                first_ts = self.skb_tracking[event.skb_addr]['first_ts']
                latency_us = (event.timestamp - first_ts) * 1_000_000

            verdict_to_count = None
            if event.event_type == EVENT_TYPE_NFT_RULE:
                verdict_to_count = event.verdict_name
            elif event.event_type in [EVENT_TYPE_TC_VERDICT,
                                       EVENT_TYPE_CT_VERDICT, EVENT_TYPE_ROUTE_VERDICT,
                                       EVENT_TYPE_TCP_DROP, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_DROP]:
          
                verdict_to_count = event.verdict_name

            node.add_event(
                skb_addr=event.skb_addr or '',
                latency_us=latency_us,
                function=event.function,
                verdict=verdict_to_count,
                error=(event.error_code > 0)
            )

          
            if event.skb_addr:
                if event.skb_addr not in self.skb_paths:
                    self.skb_paths[event.skb_addr] = []

                if self.skb_paths[event.skb_addr]:
                    prev = self.skb_paths[event.skb_addr][-1]
                    if prev != pipeline_layer:
                        self.add_edge(prev, pipeline_layer)
                        self.get_node(prev).in_flight_packets.discard(event.skb_addr)

                node.in_flight_packets.add(event.skb_addr)
                self.skb_paths[event.skb_addr].append(pipeline_layer)
                self._track_pipeline_membership(event.skb_addr, pipeline_layer)

                if len(self.skb_paths) > 5000:
                    oldest = list(self.skb_paths.keys())[:1000]
                    for k in oldest:
                        for ns in self.nodes.values():
                            ns.in_flight_packets.discard(k)
                        del self.skb_paths[k]

            hook_stats = self.get_hook(hook_name)
            hook_stats.packets_total += 1
            self.total_packets += 1

            layer_stats = hook_stats.get_layer(layer_name)
            layer_stats.packets_in += 1

            if layer_stats.first_ts is None:
                layer_stats.first_ts = event.timestamp
            layer_stats.last_ts = event.timestamp

            if event.verdict_name:
                layer_stats.verdict_breakdown[event.verdict_name] += 1
                if event.verdict_name == "DROP":
                    layer_stats.drops += 1
                elif event.verdict_name == "ACCEPT":
                    layer_stats.accepts += 1
                    layer_stats.packets_out += 1

            if event.error_code > 0:
                layer_stats.errors += 1
                layer_stats.error_breakdown[event.error_name] += 1

            if event.function:
                layer_stats.function_calls[event.function] += 1

            if event.skb_addr:
                if event.skb_addr not in self.skb_tracking:
                    self.skb_tracking[event.skb_addr] = {
                        'first_ts': event.timestamp,
                        'hooks': []
                    }

                skb_info = self.skb_tracking[event.skb_addr]
                skb_info['hooks'].append({
                    'hook': hook_name,
                    'layer': layer_name,
                    'ts': event.timestamp
                })

                latency_ns = int((event.timestamp - skb_info['first_ts']) * 1_000_000_000)
                layer_stats.total_latency_ns += latency_ns
                layer_stats.latency_count += 1

                if len(self.skb_tracking) > 5000:
                    oldest = list(self.skb_tracking.keys())[:1000]
                    for k in oldest:
                        del self.skb_tracking[k]

            self.recent_events.append(asdict(event))

    def _compute_drop_from_nodes(self) -> int:
        drop_total = 0
        for node_name, node_stats in self.nodes.items():
            if node_name.startswith("Netfilter"):
                drop_total += node_stats.drop_count
        return drop_total

    def get_summary(self) -> Dict:
        with self._lock:

            for skb_addr, state in self.skb_state.items():
                if state.get('saw_nf_hook_slow') and not state.get('has_rule_eval') and not state.get('accept_counted'):
                    verdict_key = (skb_addr, 'ACCEPT')
                    if verdict_key not in self.seen_verdicts:
                        self.seen_verdicts.add(verdict_key)
                        self.packet_verdicts['ACCEPT'] += 1
                        state['accept_counted'] = True

            uptime = time.time() - self.start_time
            current_ts = time.time()

            hooks_data = {}
            for hook_name in HOOK_ORDER:
                if hook_name in self.hooks:
                    hooks_data[hook_name] = self.hooks[hook_name].to_dict()

            for hook_name, hook_stats in self.hooks.items():
                if hook_name not in HOOK_ORDER:
                    hooks_data[hook_name] = hook_stats.to_dict()

            nodes_data = {}
            for node_name, node_stats in self.nodes.items():
                nodes_data[node_name] = node_stats.to_dict(current_ts)

            edges_data = []
            for edge_stats in self.edges.values():
                edges_data.append(edge_stats.to_dict())

            pipelines_data = []
            for pipeline_name in self.pipeline_order:
                if pipeline_name in self.pipelines:
                    pipeline_stats = self.pipelines[pipeline_name]
                    pipeline_dict = pipeline_stats.to_dict(self.nodes)
                    pipeline_dict['name'] = pipeline_name
                    pipelines_data.append(pipeline_dict)

           
            latency_ranking = []
            total_latency = 0
            for node_name, node_stats in self.nodes.items():
                if node_stats.latencies_us:
                    import numpy as np
                    avg_latency = float(np.mean(node_stats.latencies_us))
                    latency_ranking.append({
                        'node': node_name,
                        'avg_latency_us': round(avg_latency, 1),
                        'count': len(node_stats.latencies_us)
                    })
                    total_latency += avg_latency

            # Sort by latency descending and calculate percentage
            latency_ranking.sort(key=lambda x: x['avg_latency_us'], reverse=True)
            for item in latency_ranking[:10]:  # Top 10
                if total_latency > 0:
                    item['percentage'] = round((item['avg_latency_us'] / total_latency) * 100, 1)
                else:
                    item['percentage'] = 0

            # Use packet-level unique count
            total_unique_packets = len(self.seen_packets)

            # Compute total_verdicts with DROP override from NodeStats
            # ACCEPT: Keep packet-level count (as-is)
            # DROP: Override with node-level drop_count to synchronize with Pipeline Flow panel
            total_verdicts = dict(self.packet_verdicts)
            total_verdicts['DROP'] = self._compute_drop_from_nodes()

            return {
                'total_packets': total_unique_packets,  # CHANGED: Use packet-level count
                'uptime_seconds': round(uptime, 2),
                'packets_per_second': round(total_unique_packets / max(uptime, 1), 2),
                'hooks': hooks_data,
                'recent_events': list(self.recent_events)[-100:],
                # NEW: Pipeline stats for Inbound/Outbound visualization
                'stats': {
                    'Inbound': dict(self.stats_by_direction_layer['Inbound']),
                    'Outbound': dict(self.stats_by_direction_layer['Outbound'])
                },
                # ENHANCED: Detailed node and edge statistics
                'nodes': nodes_data,
                'edges': edges_data,
                # ENHANCED: Pipeline completion statistics
                'pipelines': pipelines_data,
                # CHANGED: Use node-level DROP count, packet-level ACCEPT
                'total_verdicts': total_verdicts,
                # ENHANCED: Top latency contributors for hotspot analysis
                'top_latency': latency_ranking[:10],
                # NEW: Filter information
                'filter_enabled': self.filter_enabled,
                'trace_filter': self.trace_filter if self.filter_enabled else None,
                'filtered_events': self.filtered_events
            }
    
    def reset(self):
        """Reset all statistics"""
        with self._lock:
            self.hooks.clear()
            self.skb_tracking.clear()
            self.recent_events.clear()
            self.total_packets = 0
            self.start_time = time.time()

            # PACKET-LEVEL VERDICT COUNTING: Reset new variables
            self.packet_verdicts = defaultdict(int)
            self.seen_verdicts = set()
            self.seen_packets = set()
            self.skb_state = {}

            # NEW: Reset pipeline stats
            self.stats_by_direction_layer = {
                'Inbound': defaultdict(int),
                'Outbound': defaultdict(int)
            }
            # ENHANCED: Reset nodes and edges
            self.nodes.clear()
            self.edges.clear()
            self.skb_paths.clear()

            # Reset pipelines
            self.pipelines = {
                'Inbound': PipelineStats(active_nodes={
                    'GRO', 'TC Ingress',
                    'Netfilter PREROUTING', 'Conntrack', 'Routing Decision'
                }),
                'Outbound': PipelineStats(active_nodes={
                    'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                    'Routing Lookup', 'TC Egress', 'Driver TX'
                }),
                'Local Delivery': PipelineStats(active_nodes={
                    'Netfilter INPUT', 'TCP/UDP', 'Socket'
                }),
                'Forward': PipelineStats(active_nodes={
                    'Netfilter FORWARD', 'Netfilter POSTROUTING', 'NIC TX'
                })
            }

def format_ip(ip_int: int) -> str:
    """Format IP address from integer"""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack('<I', ip_int))
    except:
        return "0.0.0.0"

def get_layer_from_function(func_name: str) -> str:
    """Determine layer from function name"""
    for layer, functions in LAYER_MAP.items():
        if func_name in functions:
            return layer
    
    func_lower = func_name.lower()
    if 'netif' in func_lower or 'rx' in func_lower:
        return "Ingress"
    elif 'br_' in func_lower:
        return "L2"
    elif 'ip_' in func_lower or 'ipv4' in func_lower or 'ipv6' in func_lower:
        return "IP"
    elif 'nf_' in func_lower or 'nft_' in func_lower or 'ipt_' in func_lower:
        return "Firewall"
    elif 'tcp_' in func_lower or 'udp_' in func_lower or 'sock' in func_lower:
        return "Socket"
    elif 'xmit' in func_lower or 'dev_queue' in func_lower:
        return "Egress"
    
    return "UNKNOWN"

def resolve_function_name(bpf_obj, func_ip: int) -> str:
    """Resolve function name from instruction pointer"""
    try:
        sym = bpf_obj.ksym(func_ip)
        if sym:
            return sym.decode('utf-8', errors='ignore')
    except:
        pass
    return f"func_{hex(func_ip)}"



class RealtimeTracer:

    def __init__(self, socketio: SocketIO, bpf_code_path: str = None, trace_filter: dict = None):
        self.socketio = socketio
        self.bpf = None
        self.stats = RealtimeStats(trace_filter=trace_filter)
        self.running = False

        # Initialize alert engine
        self.alert_engine = AlertEngine()

        # Register alert callback to broadcast alerts via WebSocket
        def alert_callback(alert):
            self.socketio.emit('alert', alert.to_dict())

        self.alert_engine.register_callback(alert_callback)

        # Initialize metrics bucket manager for time-series
        self.bucket_manager = None
        self.flask_app = None  # Will be set by start() if needed
        
        if bpf_code_path:
            self.bpf_code_path = bpf_code_path
        else:
            possible_paths = [
                "/mnt/user-data/uploads/full_tracer_bpf.c",
                os.path.join(os.path.dirname(__file__), "ebpf", "full_tracer.bpf.c"),
                os.path.join(os.getcwd(), "full_tracer.bpf.c"),
                os.path.join(os.getcwd(), "full_tracer_bpf.c"),
                os.path.join(os.path.dirname(__file__), "full_tracer.bpf.c"),
                os.path.join(os.path.dirname(__file__), "full_tracer_bpf.c"),
            ]
            
            self.bpf_code_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    self.bpf_code_path = path
                    print(f"[*] Found BPF code at: {path}")
                    break
            
            if not self.bpf_code_path:
                self.bpf_code_path = possible_paths[0]
        
        self.func_name_cache = {}
        
    def load_bpf(self) -> bool:
        """Load and compile BPF program"""
        try:
            if not os.path.exists(self.bpf_code_path):
                print(f"[!] BPF code not found: {self.bpf_code_path}")
                return False
            
            with open(self.bpf_code_path, 'r') as f:
                bpf_code = f.read()
            
            print("[*] Compiling BPF program...")
            self.bpf = BPF(text=bpf_code)
            
           
            functions_to_trace = [
                # === INBOUND PIPELINE ===
                # NIC Layer
                'napi_gro_receive',
                'netif_receive_skb',
                'netif_receive_skb_list_internal',

                # Driver (NAPI)
                'napi_poll',
                'net_rx_action',
                'process_backlog',

                # GRO
                'gro_normal_list',
                'dev_gro_receive',
                'skb_gro_receive',

                # TC Ingress
                'tcf_classify',
                'ingress_redirect',
                'dev_queue_xmit_nit',

                # Netfilter (refined by hook)
                'nf_hook_slow',
                'nf_hook_thresh',
                'nf_reinject',

                # Conntrack
                'nf_conntrack_in',
                'nf_ct_invert_tuple',
                'nf_confirm',

                # NAT
                'nf_nat_ipv4_pre_routing',
                'nf_nat_ipv4_fn',

                # Routing Decision
                'ip_route_input_slow',
                'fib_validate_source',
                'ip_route_output_key_hash',

                # Local Delivery
                'ip_local_deliver',
                'ip_local_deliver_finish',

                # NFT/Queue
                'nf_queue',

                # TCP/UDP (Inbound)
                'tcp_v4_rcv',
                'tcp_v4_do_rcv',
                'tcp_rcv_established',
                'udp_rcv',
                'udp_unicast_rcv_skb',

                # Socket
                # 'sock_def_readable',  
                'sk_filter_trim_cap',

                # Forward
                'ip_forward',
                'ip_forward_finish',

                # === OUTBOUND PIPELINE ===
                # Application
                'tcp_sendmsg',
                'udp_sendmsg',

                # TCP/UDP Output
                'tcp_write_xmit',
                'tcp_transmit_skb',
                'udp_send_skb',

                # Routing Lookup (outbound)
                'ip_route_output_flow',

                # NAT (outbound)
                'nf_nat_ipv4_out',
                'nf_nat_ipv4_local_fn',

                # TC Egress
                'sch_direct_xmit',

                # Driver TX / NIC TX
                'dev_queue_xmit',
                '__dev_queue_xmit',
                'dev_hard_start_xmit',
            ]
            
            attached_count = 0
            for func_name in functions_to_trace:
                try:
                    self.bpf.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                    attached_count += 1
                except Exception as e:
                    pass
            
            print(f"[✓] Attached to {attached_count} functions")
            print("[✓] NFT hooks attached via kprobe/kretprobe")
            
            return True
            
        except Exception as e:
            print(f"[✗] Failed to load BPF: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_event(self, cpu, data, size):
        """Handle event from eBPF perf buffer"""
        try:
            class TraceEvent(ct.Structure):
                _fields_ = [
                    ("timestamp", ct.c_uint64),
                    ("skb_addr", ct.c_uint64),
                    ("cpu_id", ct.c_uint32),
                    ("pid", ct.c_uint32),
                    ("event_type", ct.c_uint8),
                    ("hook", ct.c_uint8),
                    ("pf", ct.c_uint8),
                    ("protocol", ct.c_uint8),
                    ("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_port", ct.c_uint16),
                    ("dst_port", ct.c_uint16),
                    ("length", ct.c_uint32),
                    ("chain_addr", ct.c_uint64),
                    ("expr_addr", ct.c_uint64),
                    ("chain_depth", ct.c_uint8),
                    ("rule_seq", ct.c_uint16),
                    ("rule_handle", ct.c_uint64),
                    ("verdict_raw", ct.c_int32),
                    ("verdict", ct.c_uint32),
                    ("queue_num", ct.c_uint16),
                    ("has_queue_bypass", ct.c_uint8),
                    ("error_code", ct.c_uint8),
                    ("func_ip", ct.c_uint64),
                    ("function_name", ct.c_char * 64),
                    ("comm", ct.c_char * 16),
                    ("trace_type", ct.c_uint8),  
                ]
            
            event = ct.cast(data, ct.POINTER(TraceEvent)).contents
            
            ts = time.time()
            
            func_name = event.function_name.decode('utf-8', errors='ignore').strip('\x00')
            if not func_name and event.func_ip != 0:
                if event.func_ip in self.func_name_cache:
                    func_name = self.func_name_cache[event.func_ip]
                else:
                    func_name = resolve_function_name(self.bpf, event.func_ip)
                    self.func_name_cache[event.func_ip] = func_name


                    if len(self.func_name_cache) > 1000:
                        keys_to_remove = list(self.func_name_cache.keys())[:200]
                        for key in keys_to_remove:
                            del self.func_name_cache[key]

            # Get layer from event type first (for verdict events), fallback to function
            layer = EVENT_TYPE_TO_LAYER.get(event.event_type, get_layer_from_function(func_name))

            # Map trace_type from BPF (if available)
            # 0=none, 1=rule_eval, 2=chain_exit, 3=hook_exit
            trace_type_map = {
                0: None,
                1: "rule_eval",
                2: "chain_exit",
                3: "hook_exit"
            }
            trace_type_value = getattr(event, 'trace_type', 0)  # Default to 0 if not available
            trace_type_str = trace_type_map.get(trace_type_value, None)

            packet_event = PacketEvent(
                timestamp=ts,
                skb_addr=hex(event.skb_addr) if event.skb_addr else None,
                cpu_id=event.cpu_id,
                pid=event.pid,
                event_type=event.event_type,
                hook=event.hook,
                hook_name=HOOK_MAP.get(event.hook, "UNKNOWN"),
                pf=event.pf,
                protocol=event.protocol,
                protocol_name=PROTO_MAP.get(event.protocol, f"PROTO_{event.protocol}"),
                src_ip=format_ip(event.src_ip),
                dst_ip=format_ip(event.dst_ip),
                src_port=event.src_port,
                dst_port=event.dst_port,
                length=event.length,
                verdict=event.verdict,
                verdict_name=VERDICT_MAP.get(event.verdict, "UNKNOWN"),
                error_code=event.error_code,
                error_name=ERROR_MAP.get(event.error_code, "UNKNOWN"),
                function=func_name,
                layer=layer,
                comm=event.comm.decode('utf-8', errors='ignore'),
                chain_addr=hex(event.chain_addr) if event.chain_addr else None,
                rule_seq=event.rule_seq if event.rule_seq > 0 else None,
                rule_handle=event.rule_handle if event.rule_handle > 0 else None,
                queue_num=event.queue_num if event.queue_num > 0 else None,
                trace_type=trace_type_str  
            )
            

            self.stats.process_event(packet_event)

            
        except Exception as e:
            print(f"[!] Error handling event: {e}")
    
    def start(self, flask_app=None) -> bool:
        """
        Start tracing

        Args:
            flask_app: Flask app instance (needed for bucket manager database access)
        """
        if not self.load_bpf():
            return False

        # Store flask app for bucket manager
        self.flask_app = flask_app

        # Initialize and enable bucket manager
        if flask_app:
            self.bucket_manager = MetricsBucketManager(source='realtime_global')
            current_stats = self.stats.get_summary()
            self.bucket_manager.enable(current_stats)
            print("[✓] Metrics bucket manager enabled (10-minute buckets)")
        self.bpf["events"].open_perf_buffer(
            self.handle_event,
            page_cnt=512  # 512 * 4KB = 2MB buffer
        )
        self.running = True

        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()

        self.stats_thread = threading.Thread(target=self._stats_broadcast_loop, daemon=True)
        self.stats_thread.start()

        print("[✓] Realtime tracer started")
        return True
    
    def _poll_loop(self):
        """Poll eBPF perf buffer - poll frequently to avoid buffer overflow"""
        while self.running:
            try:
                # Faster polling = less chance of buffer overflow
                self.bpf.perf_buffer_poll(timeout=10)
            except Exception as e:
                if self.running:
                    print(f"[!] Poll error: {e}")
                break
    
    def _stats_broadcast_loop(self):
        """Broadcast statistics every 1 second for optimal readability"""
        while self.running:
            time.sleep(1.0)  # 1s for optimal readability
            try:
                summary = self.stats.get_summary()
                self.socketio.emit('stats_update', summary)

                # Check metrics against alert rules
                try:
                    self.alert_engine.check_metrics(summary)
                except Exception as alert_error:
                    print(f"[!] AlertEngine check error: {alert_error}")

                # Check and flush bucket if needed (every 10 minutes)
                if self.bucket_manager and self.flask_app:
                    try:
                        flushed = self.bucket_manager.maybe_flush_bucket(summary, self.flask_app)
                        if flushed:
                            print("[✓] Auto-flushed 10-minute metrics bucket")
                    except Exception as bucket_error:
                        print(f"[!] Bucket flush error: {bucket_error}")

            except Exception as e:
                print(f"[!] Stats broadcast error: {e}")
    
    def stop(self):
        """Stop tracing and cleanup all resources"""
        import gc

        self.running = False
        print("[*] Stopping tracer threads...")
        time.sleep(0.5)  


        print("[*] Cleaning up memory...")


        if self.bucket_manager and self.flask_app:
            try:
                current_stats = self.stats.get_summary()
                self.bucket_manager.disable(current_stats, self.flask_app)
                print("[✓] Flushed last metrics bucket on disable")
            except Exception as e:
                print(f"[!] Final bucket flush error: {e}")


        self.func_name_cache.clear()
        self.stats.reset()


        if hasattr(self, 'alert_engine') and self.alert_engine:
            try:

                if hasattr(self.alert_engine, 'recent_alerts'):
                    self.alert_engine.recent_alerts.clear()
                self.alert_engine = None
            except:
                pass

        if hasattr(self, 'bucket_manager') and self.bucket_manager:
            try:
                self.bucket_manager = None
            except:
                pass

        if self.bpf:
            try:
                for map_name in ['skb_info_map', 'depth_map', 'hook_map', 'hook_skb_map']:
                    try:
                        bpf_map = self.bpf.get_table(map_name)
                        bpf_map.clear()
                    except:
                        pass

                self.bpf.cleanup()
                self.bpf = None
            except Exception as e:
                print(f"[!] BPF cleanup error: {e}")

        gc.collect()

        print("[✓] Realtime tracer stopped and memory cleaned")
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.get_summary()
    
    def reset_stats(self):
        """Reset statistics"""
        self.func_name_cache.clear()
        self.stats.reset()



app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet-tracer-realtime-2024'
app.config['JSON_SORT_KEYS'] = False
CORS(app)


socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    logger=False,              
    engineio_logger=False,    
    ping_timeout=60,           
    ping_interval=25          
)

# Global tracer instance
tracer: Optional[RealtimeTracer] = None

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    """Serve index page"""
    html_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
    if os.path.exists(html_path):
        return send_from_directory('static', 'index.html')
    
    return jsonify({
        'status': 'running',
        'message': 'Realtime Packet Tracer Backend',
        'version': '2.0 Final',
        'endpoints': {
            'start': '/api/start',
            'stop': '/api/stop',
            'stats': '/api/stats',
            'reset': '/api/reset',
            'realtime_enable': '/api/realtime/enable',
            'realtime_disable': '/api/realtime/disable',
            'realtime_stats': '/api/realtime/stats',
            'realtime_reset': '/api/realtime/reset'
        }
    })



# @app.route('/api/start', methods=['POST'])
# def start_trace():
#     """Start tracing"""
#     global tracer
    
#     if tracer and tracer.running:
#         return jsonify({'error': 'Tracer already running'}), 400
    
#     tracer = RealtimeTracer(socketio)
    
#     if tracer.start():
#         return jsonify({'status': 'started'})
#     else:
#         return jsonify({'error': 'Failed to start tracer'}), 500

# @app.route('/api/stop', methods=['POST'])
# def stop_trace():
#     """Stop tracing"""
#     global tracer
    
#     if not tracer or not tracer.running:
#         return jsonify({'error': 'Tracer not running'}), 400
    
#     tracer.stop()
#     return jsonify({'status': 'stopped'})

# @app.route('/api/stats', methods=['GET'])
# def get_stats():
#     """Get current statistics"""
#     global tracer
    
#     if not tracer:
#         return jsonify({
#             'total_packets': 0,
#             'uptime_seconds': 0,
#             'packets_per_second': 0,
#             'hooks': {}
#         })
    
#     return jsonify(tracer.get_stats())

# @app.route('/api/reset', methods=['POST'])
# def reset_stats():
#     """Reset statistics"""
#     global tracer
    
#     if not tracer:
#         return jsonify({'error': 'Tracer not initialized'}), 400
    
#     tracer.reset_stats()
#     return jsonify({'status': 'reset'})

# ============================================
# NEW API ROUTES (For new frontend)
# ============================================

@app.route('/api/realtime/enable', methods=['POST'])
def enable_realtime():
    """Enable realtime tracing with optional 5-tuple filter"""
    global tracer

    try:
        if tracer and tracer.running:
            return jsonify({'status': 'already_enabled'})

        # Get trace_filter from request body (optional)
        data = request.json or {}
        trace_filter = data.get('trace_filter', {})

        tracer = RealtimeTracer(socketio, trace_filter=trace_filter)

        if tracer.start():
            socketio.emit('status', {'enabled': True})
            return jsonify({
                'status': 'enabled',
                'filter_enabled': tracer.stats.filter_enabled,
                'trace_filter': tracer.stats.trace_filter
            })
        else:
            return jsonify({'error': 'Failed to start realtime tracer'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/disable', methods=['POST'])
def disable_realtime():
    """Disable realtime tracing"""
    global tracer
    
    try:
        if not tracer or not tracer.running:
            return jsonify({'status': 'already_disabled'})
        
        tracer.stop()
        socketio.emit('status', {'enabled': False})
        return jsonify({'status': 'disabled'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/stats', methods=['GET'])
def get_realtime_stats():
    """Get realtime statistics"""
    global tracer
    
    try:
        if not tracer:
            return jsonify({
                'enabled': False,
                'total_packets': 0,
                'uptime_seconds': 0,
                'packets_per_second': 0,
                'hooks': {}
            })
        
        stats = tracer.get_stats()
        stats['enabled'] = tracer.running
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/reset', methods=['POST'])
def reset_realtime_stats():
    """Reset realtime statistics"""
    global tracer

    try:
        if not tracer:
            return jsonify({'error': 'Tracer not initialized'}), 400

        tracer.reset_stats()
        return jsonify({'status': 'reset'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('[*] Client connected')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('[*] Client disconnected')

@socketio.on('request_stats')
def handle_stats_request():
    """Client requests current stats"""
    global tracer
    if tracer:
        emit('stats_update', tracer.get_stats())


class SessionStatsTracker:
    """Track realtime stats for a specific trace session"""

    def __init__(self, session_id: str, mode: str, trace_filter: dict = None):
        self.session_id = session_id
        self.mode = mode
        self.start_time = time.time()

        # Trace filter (5-tuple filtering)
        self.trace_filter = trace_filter or {}
        self.filter_enabled = any(v for v in self.trace_filter.values())

        # Overall stats
        self.total_packets = 0
        self.total_events = 0
        self.filtered_events = 0  # Count of events filtered out

     
        self.packet_verdicts = defaultdict(int) 
        self.seen_verdicts = set()  
        self.seen_packets = set()  
        self.skb_state = {}  
      
        self.seen_layer_verdicts = set() 
        self.seen_node_verdicts = set()   

        self.hooks = defaultdict(lambda: {
            'packets_total': 0,
            'packets_in': 0,
            'packets_out': 0,
            'layers': defaultdict(lambda: {
                'packets_in': 0,
                'packets_out': 0,
                'drop_rate': 0.0,
                'verdict_breakdown': defaultdict(int),
                'function_calls': defaultdict(int),
                'top_function': '',
                'top_function_calls': 0,
                'avg_latency_ms': 0.0,
                'total_latency_ms': 0.0,
                'latency_count': 0
            })
        })

        self.nodes: Dict[str, NodeStats] = {}  # node_name -> NodeStats
        self.skb_tracking: Dict[str, Dict] = {}  # skb_addr -> {'first_ts': float, 'last_node': str}
        self.skb_paths: Dict[str, List[str]] = {}  # skb_addr -> [node1, node2, ...]
        self.edges: Dict[tuple, EdgeStats] = {}  # (from, to) -> EdgeStats
        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        self.pipeline_order = ['Inbound', 'Outbound', 'Local Delivery', 'Forward']
        self.pipelines: Dict[str, PipelineStats] = {
            'Inbound': PipelineStats(active_nodes={
                'GRO', 'TC Ingress', 'IP Receive',
                'Netfilter PREROUTING', 'Conntrack', 'Routing Decision'
            }),
            'Outbound': PipelineStats(active_nodes={
                'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                'Routing Lookup', 'TC Egress', 'Driver TX'
            }),
            'Local Delivery': PipelineStats(active_nodes={
                'Netfilter INPUT', 'TCP/UDP', 'Socket'
            }),
            'Forward': PipelineStats(active_nodes={
                'Netfilter FORWARD', 'Netfilter POSTROUTING', 'NIC TX'
            })
        }

        self.stats_by_layer = defaultdict(int)
        self.stats_by_hook = defaultdict(int)
        self.stats_by_verdict = defaultdict(int)

        self.recent_events = deque(maxlen=50)

        self.lock = threading.Lock()

    def _matches_filter(self, event: Dict) -> bool:
        if not self.filter_enabled:
            return True

        # Check src_ip
        if self.trace_filter.get('src_ip'):
            if event.get('src_ip') != self.trace_filter['src_ip']:
                return False

        # Check dst_ip
        if self.trace_filter.get('dst_ip'):
            if event.get('dst_ip') != self.trace_filter['dst_ip']:
                return False

        # Check src_port
        if self.trace_filter.get('src_port'):
            try:
                filter_port = int(self.trace_filter['src_port'])
                if event.get('src_port') != filter_port:
                    return False
            except (ValueError, TypeError):
                pass

        # Check dst_port
        if self.trace_filter.get('dst_port'):
            try:
                filter_port = int(self.trace_filter['dst_port'])
                if event.get('dst_port') != filter_port:
                    return False
            except (ValueError, TypeError):
                pass

        # Check protocol
        if self.trace_filter.get('protocol'):
            try:
                filter_protocol = int(self.trace_filter['protocol'])
                if event.get('protocol') != filter_protocol:
                    return False
            except (ValueError, TypeError):
                pass

        # Check comm (process name)
        if self.trace_filter.get('comm'):
            if event.get('comm') != self.trace_filter['comm']:
                return False

        return True

    def get_node(self, node_name: str) -> NodeStats:
        """Get or create a node's statistics"""
        if node_name not in self.nodes:
            self.nodes[node_name] = NodeStats()
        return self.nodes[node_name]

    def add_edge(self, from_node: str, to_node: str):
        """Track an edge (transition) between two nodes"""
        edge_key = (from_node, to_node)
        if edge_key not in self.edges:
            self.edges[edge_key] = EdgeStats(from_node=from_node, to_node=to_node)
        self.edges[edge_key].count += 1

        # MEMORY LEAK FIX: Limit edges dictionary size
        # Edges can grow to O(n²) with n nodes, limit to reasonable size
        if len(self.edges) > 500:
            # Keep only top 300 edges by count
            sorted_edges = sorted(self.edges.items(), key=lambda x: x[1].count, reverse=True)
            self.edges = dict(sorted_edges[:300])

    def count_packet_verdict(
        self,
        skb_addr: str,
        verdict_name: str,
        event_type: int,
        func_name: str,
        trace_type: Optional[str],
    ):
        """
        Đếm verdict ở mức packet (packet-level), với dedupe theo (skb_addr, verdict_name).

        Logic chuẩn:
        - Nếu event_type == EVENT_TYPE_NFT_RULE:
            -> Đếm tất cả verdict_name (DROP, ACCEPT, QUEUE, CONTINUE, JUMP, GOTO, ...)
            -> Mỗi (skb_addr, verdict_name) chỉ đếm một lần.
            -> Đánh dấu self.skb_state[skb_addr]['has_rule_eval'] = True

        - Ngược lại:
            -> Chỉ đếm ACCEPT (verdict_name == 'ACCEPT'), 1 lần / skb_addr.
        """
        if not skb_addr or not verdict_name or verdict_name == 'UNKNOWN':
            return

        # Đảm bảo skb_state tồn tại
        if skb_addr not in self.skb_state:
            self.skb_state[skb_addr] = {
                'saw_nf_hook_slow': False,
                'has_rule_eval': False,
                'accept_counted': False,
            }


        if event_type == EVENT_TYPE_NFT_RULE:
            key = (skb_addr, verdict_name)
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts[verdict_name] += 1
                self.skb_state[skb_addr]['has_rule_eval'] = True
            return

        if event_type in [EVENT_TYPE_TC_VERDICT,
                          EVENT_TYPE_CT_VERDICT, EVENT_TYPE_ROUTE_VERDICT,
                          EVENT_TYPE_TCP_DROP, EVENT_TYPE_UDP_DROP, EVENT_TYPE_SOCK_DROP]:
            key = (skb_addr, verdict_name)
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts[verdict_name] += 1
            return
        if verdict_name == 'ACCEPT':
            key = (skb_addr, 'ACCEPT')
            if key not in self.seen_verdicts:
                self.seen_verdicts.add(key)
                self.packet_verdicts['ACCEPT'] += 1

    def _track_pipeline_membership(self, skb_addr: str, node_name: str):

        for pipeline_name, pipeline_stats in self.pipelines.items():
            if node_name in pipeline_stats.active_nodes:

                pipeline_stats.unique_skbs.add(skb_addr)

                if len(pipeline_stats.unique_skbs) > 10000:

                    skb_list = list(pipeline_stats.unique_skbs)
                    pipeline_stats.unique_skbs = set(skb_list[2000:])

    def process_event(self, event: Dict):
        """Process a single event"""
        with self.lock:
            self.total_events += 1


            if self.filter_enabled and not self._matches_filter(event):
                self.filtered_events += 1
                return  

            if self.total_events <= 5:
                print(f"[SessionStats {self.session_id}] Event #{self.total_events}: hook={event.get('hook')}, func={event.get('func_name', 'N/A')}, type={event.get('event_type', 'normal')}")

            raw_event_type = event.get('event_type')

            is_multifunction = (raw_event_type == 'multifunction')

            event_type_num = raw_event_type if isinstance(raw_event_type, int) else None

            hook_num = event.get('hook', 255)
            hook_name = HOOK_MAP.get(hook_num, 'UNKNOWN')
            func_name = event.get('func_name', '')
            verdict = event.get('verdict', 255)
            verdict_name = VERDICT_MAP.get(verdict, 'UNKNOWN')
            protocol = event.get('protocol', 0)
            src_ip = event.get('src_ip', '0.0.0.0')
            dst_ip = event.get('dst_ip', '0.0.0.0')
            trace_type = event.get('trace_type', None) 
            skb_addr = event.get('skb_addr', '')  

            if is_multifunction and 'layer' in event:
                layer_name_raw = event['layer'] 
                layer_name = self._map_multifunction_layer(layer_name_raw, hook_name)
            else:
                layer_name = self._determine_layer(func_name, hook_name)

            if is_multifunction:
                if layer_name and layer_name != 'Unknown':
                    self.stats_by_layer[layer_name] += 1

                if hook_num != 255:
                    self.stats_by_hook[hook_name] += 1

                if verdict != 255 and func_name == 'nft_immediate_eval':
                    self.stats_by_verdict[verdict_name] += 1

            hook_stats = self.hooks[hook_name]
            hook_stats['packets_total'] += 1

            layer_stats = hook_stats['layers'][layer_name]
            layer_stats['packets_in'] += 1

            if self.total_events <= 10 and verdict != 255:
                print(f"[SessionStats {self.session_id}] Verdict event #{self.total_events}: "
                      f"func={func_name}, verdict={verdict_name} ({verdict}), hook={hook_name}, trace_type={trace_type}, skb={skb_addr}")


            if skb_addr:
                self.seen_packets.add(skb_addr)

                # Track packet state
                if skb_addr not in self.skb_state:
                    self.skb_state[skb_addr] = {
                        'saw_nf_hook_slow': False,
                        'has_rule_eval': False,
                        'accept_counted': False
                    }

                # Track nf_hook_slow
                if func_name and 'nf_hook_slow' in func_name:
                    self.skb_state[skb_addr]['saw_nf_hook_slow'] = True

                if len(self.skb_state) > 10000:
                    oldest_keys = list(self.skb_state.keys())[:2000]
                    for key in oldest_keys:
                        del self.skb_state[key]

            if verdict != 255 and verdict_name != 'UNKNOWN' and skb_addr:
                is_rule_eval_packet = (trace_type == 'rule_eval')
                logical_event_type = (
                    EVENT_TYPE_NFT_RULE if is_rule_eval_packet else EVENT_TYPE_FUNCTION_CALL
                )

                self.count_packet_verdict(
                    skb_addr=skb_addr,
                    verdict_name=verdict_name,
                    event_type=logical_event_type,
                    func_name=func_name or "",
                    trace_type=trace_type,
                )

                is_rule_eval_layer = (trace_type == 'rule_eval')

                if is_rule_eval_layer:
                    layer_key = (skb_addr, hook_name, layer_name, verdict_name)
                    if layer_key not in self.seen_layer_verdicts:
                        self.seen_layer_verdicts.add(layer_key)
                        layer_stats['verdict_breakdown'][verdict_name] += 1
                elif verdict_name == 'ACCEPT':
                    layer_stats['verdict_breakdown'][verdict_name] += 1

                if len(self.seen_verdicts) > 10000:
                    old_entries = list(self.seen_verdicts)[:2000]
                    for entry in old_entries:
                        self.seen_verdicts.discard(entry)

            if isinstance(raw_event_type, int) and raw_event_type == EVENT_TYPE_NF_VERDICT:
                return

            if func_name:
                layer_stats['function_calls'][func_name] += 1
                
                if layer_stats['function_calls'][func_name] > layer_stats['top_function_calls']:
                    layer_stats['top_function'] = func_name
                    layer_stats['top_function_calls'] = layer_stats['function_calls'][func_name]
            
            total_in = layer_stats['packets_in']
            drops = layer_stats['verdict_breakdown'].get('DROP', 0)
            layer_stats['drop_rate'] = (drops / total_in * 100) if total_in > 0 else 0.0
            if not is_multifunction:
                self.recent_events.append({
                    'type': 'nft' if func_name == 'nft_do_chain' else 'trace',
                    'hook_name': hook_name,
                    'func_name': func_name,
                    'verdict_name': verdict_name,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'timestamp': time.time()
                })

            if self.mode == 'full':
                pipeline_layer = self._map_to_pipeline_layer(layer_name, func_name, hook_num)

                direction = self._detect_direction(hook_name, layer_name, func_name, hook_num)

                self.stats_by_direction_layer[direction][pipeline_layer] += 1

                node = self.get_node(pipeline_layer)

                skb_addr = event.get('skb_addr', '')
                timestamp = event.get('timestamp', time.time())
                latency_us = 0.0

                if skb_addr:
                    if skb_addr not in self.skb_tracking:
                        self.skb_tracking[skb_addr] = {
                            'first_ts': timestamp,
                            'last_node': pipeline_layer
                        }
                    else:
                        first_ts = self.skb_tracking[skb_addr]['first_ts']
                        latency_us = (timestamp - first_ts) * 1_000_000  # microseconds
                        self.skb_tracking[skb_addr]['last_node'] = pipeline_layer


                    if len(self.skb_tracking) > 5000:
                        oldest_keys = list(self.skb_tracking.keys())[:1000]
                        for key in oldest_keys:
                            del self.skb_tracking[key]

                verdict_to_count = None
                if verdict_name != 'UNKNOWN' and skb_addr and trace_type == 'rule_eval':
                    node_key = (skb_addr, pipeline_layer, verdict_name)
                    if node_key not in self.seen_node_verdicts:
                        self.seen_node_verdicts.add(node_key)
                        verdict_to_count = verdict_name

                node.add_event(
                    skb_addr=skb_addr,
                    latency_us=latency_us,
                    function=func_name,
                    verdict=verdict_to_count,
                    error=(event.get('error_code', 0) > 0)
                )
                if skb_addr:
                    if skb_addr not in self.skb_paths:
                        self.skb_paths[skb_addr] = []

                    if self.skb_paths[skb_addr]:
                        prev_node = self.skb_paths[skb_addr][-1]
                        if prev_node != pipeline_layer: 
                            self.add_edge(prev_node, pipeline_layer)
                            prev_node_stats = self.get_node(prev_node)
                            prev_node_stats.in_flight_packets.discard(skb_addr)

                    node.in_flight_packets.add(skb_addr)

                    self.skb_paths[skb_addr].append(pipeline_layer)

                    self._track_pipeline_membership(skb_addr, pipeline_layer)

                    if len(self.skb_paths) > 5000:
                        oldest_keys = list(self.skb_paths.keys())[:1000]
                        for key in oldest_keys:
                            for node_stats in self.nodes.values():
                                node_stats.in_flight_packets.discard(key)
                            del self.skb_paths[key]

            self.total_packets = max(self.total_packets, sum(h['packets_total'] for h in self.hooks.values()) // max(len(self.hooks), 1))
    
    def _detect_direction(self, hook_name: str, layer_name: str, function: str, hook: int) -> str:

        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return detect_packet_direction(function, refined_layer, hook)

        # Fallback to hook-based detection
        if hook_name in ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD']:
            return 'Inbound'
        elif hook_name in ['LOCAL_OUT', 'POST_ROUTING']:
            return 'Outbound'

        # Layer-based fallback
        if layer_name in ['Ingress', 'L2']:
            return 'Inbound'
        elif layer_name == 'Egress':
            return 'Outbound'

        return 'Inbound'  # Default

    def _map_to_pipeline_layer(self, layer_name: str, function: str, hook: int) -> str:
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            # Refine by hook if needed
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return refined_layer

        # Fallback: Old layer name mappings
        layer_map = {
            'IP': 'Routing Decision',
            'Firewall': 'Netfilter',
            'Socket': 'TCP/UDP',
            'Egress': 'Driver TX'
        }

        if layer_name in layer_map:
            return layer_map[layer_name]

        # Function-based heuristics
        if function:
            func_lower = function.lower()
            if 'gro' in func_lower:
                return 'GRO'
            elif 'tc' in func_lower:
                return 'TC Ingress' if 'ingress' in func_lower else 'TC Egress'

        return layer_name or 'Unknown'

    def _map_multifunction_layer(self, bpf_layer: str, hook_name: str) -> str:
        """Map BPF layer names to frontend layer names"""
        # Mapping from BPF trace_config.json layers to frontend LAYER_MAP
        layer_mapping = {
            'Device': 'Ingress',
            'GRO': 'Ingress',
            'L2': 'L2',
            'Bridge': 'L2',
            'IPv4': 'IP',
            'IPv6': 'IP',
            'IP': 'IP',
            'Routing': 'IP',
            'Netfilter': 'Firewall',
            'NFT': 'Firewall',
            'Conntrack': 'Firewall',
            'TCP': 'Socket',
            'UDP': 'Socket',
            'ICMP': 'Socket',
            'Socket': 'Socket',
            'Xmit': 'Egress',
            'Qdisc': 'Egress',
            'SoftIRQ': 'Ingress'
        }

        frontend_layer = layer_mapping.get(bpf_layer, bpf_layer)

        valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
        if frontend_layer in valid_layers:
            return frontend_layer

        if valid_layers:
            if 'Firewall' in valid_layers and bpf_layer in ['Netfilter', 'NFT']:
                return 'Firewall'
            # Otherwise return first valid layer
            return valid_layers[0]

        return frontend_layer

    def _determine_layer(self, func_name: str, hook_name: str) -> str:
        if not func_name:
            return "Unknown"

        # Check each layer's functions
        for layer, functions in LAYER_MAP.items():
            for func in functions:
                if func in func_name:
                    # Verify layer is valid for this hook
                    valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
                    if layer in valid_layers:
                        return layer

        # Default to first valid layer for hook
        valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
        return valid_layers[0] if valid_layers else "Unknown"

    def _compute_drop_from_nodes(self) -> int:
        drop_total = 0
        for node_name, node_stats in self.nodes.items():
            if node_name.startswith("Netfilter"):
                drop_total += node_stats.drop_count
        return drop_total

    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self.lock:
            for skb_addr, state in self.skb_state.items():
                if state.get('saw_nf_hook_slow') and not state.get('has_rule_eval') and not state.get('accept_counted'):
                    verdict_key = (skb_addr, 'ACCEPT')
                    if verdict_key not in self.seen_verdicts:
                        self.seen_verdicts.add(verdict_key)
                        self.packet_verdicts['ACCEPT'] += 1
                        state['accept_counted'] = True

            uptime = time.time() - self.start_time
            pps = self.total_events / uptime if uptime > 0 else 0

            hooks_dict = {}
            for hook_name, hook_data in self.hooks.items():
                layers_dict = {}
                for layer_name, layer_data in hook_data['layers'].items():
                    layers_dict[layer_name] = {
                        'packets_in': layer_data['packets_in'],
                        'packets_out': layer_data['packets_out'],
                        'drop_rate': layer_data['drop_rate'],
                        'verdict_breakdown': dict(layer_data['verdict_breakdown']),
                        'top_function': layer_data['top_function'],
                        'top_function_calls': layer_data['top_function_calls'],
                        'avg_latency_ms': layer_data['avg_latency_ms']
                    }

                hooks_dict[hook_name] = {
                    'packets_total': hook_data['packets_total'],
                    'packets_in': hook_data['packets_in'],
                    'packets_out': hook_data['packets_out'],
                    'layers': layers_dict
                }

            total_verdicts = dict(self.packet_verdicts)
            total_verdicts['DROP'] = self._compute_drop_from_nodes()

            stats = {
                'session_id': self.session_id,
                'mode': self.mode,
                'total_packets': len(self.seen_packets),  
                'filtered_events': self.filtered_events,  
                'uptime_seconds': uptime,
                'packets_per_second': pps,
                'hooks': hooks_dict,
                'total_verdicts': total_verdicts,  
                'trace_filter': self.trace_filter if self.filter_enabled else None, 
                'filter_enabled': self.filter_enabled
            }


            if self.mode == 'multifunction':
                stats['stats_by_layer'] = dict(self.stats_by_layer)
                stats['stats_by_hook'] = dict(self.stats_by_hook)
                stats['stats_by_verdict'] = dict(self.stats_by_verdict)
            else:
                stats['recent_events'] = list(self.recent_events)


            if self.mode == 'full':
                current_ts = time.time()
                nodes_data = {}
                for node_name, node_stats in self.nodes.items():
                    nodes_data[node_name] = node_stats.to_dict(current_ts)
                stats['nodes'] = nodes_data

                edges_data = []
                for edge_stats in self.edges.values():
                    edges_data.append(edge_stats.to_dict())
                stats['edges'] = edges_data
                pipelines_data = []
                for pipeline_name in self.pipeline_order:
                    if pipeline_name in self.pipelines:
                        pipeline_stats = self.pipelines[pipeline_name]
                        pipeline_dict = pipeline_stats.to_dict(self.nodes)
                        pipeline_dict['name'] = pipeline_name
                        pipelines_data.append(pipeline_dict)
                stats['pipelines'] = pipelines_data

                latency_ranking = []
                total_latency = 0
                for node_name, node_stats in self.nodes.items():
                    if node_stats.latencies_us:
                        import numpy as np
                        avg_latency = float(np.mean(node_stats.latencies_us))
                        latency_ranking.append({
                            'node': node_name,
                            'avg_latency_us': round(avg_latency, 1),
                            'count': len(node_stats.latencies_us)
                        })
                        total_latency += avg_latency

                latency_ranking.sort(key=lambda x: x['avg_latency_us'], reverse=True)
                for item in latency_ranking[:10]:  # Top 10
                    if total_latency > 0:
                        item['percentage'] = round((item['avg_latency_us'] / total_latency) * 100, 1)
                    else:
                        item['percentage'] = 0
                stats['top_latency'] = latency_ranking[:10]

            return stats

class RealtimeExtension:
    
    def __init__(self, app: Flask, socketio: SocketIO):
        self.app = app
        self.socketio = socketio
        self.tracer: Optional[RealtimeTracer] = None
        
        self.session_trackers = {}  
        self.session_lock = threading.Lock()
        self._session_stats_thread = None
        self._session_stats_running = False
        
        self._setup_session_handlers()
        
        print("[*] RealtimeExtension initialized")
    
    def enable(self, trace_filter: dict = None) -> bool:
        if self.tracer and self.tracer.running:
            return True

        self.tracer = RealtimeTracer(self.socketio, trace_filter=trace_filter)

        if self.tracer.start(flask_app=self.app):
            self.socketio.emit('status', {'enabled': True})
            return True
        else:
            return False
    
    def disable(self) -> bool:
        """Disable realtime tracing"""
        if not self.tracer or not self.tracer.running:
            return True
        
        self.tracer.stop()
        self.socketio.emit('status', {'enabled': False})
        return True
    
    def is_enabled(self) -> bool:
        return self.tracer is not None and self.tracer.running
    
    def has_session(self, session_id: str) -> bool:
        with self.session_lock:
            return session_id in self.session_trackers
    
    def get_stats(self) -> Dict:
        if not self.tracer:
            return {
                'enabled': False,
                'total_packets': 0,
                'uptime_seconds': 0,
                'packets_per_second': 0,
                'hooks': {}
            }
        
        stats = self.tracer.get_stats()
        stats['enabled'] = self.tracer.running
        return stats
    
    def reset_stats(self):
        """Reset statistics"""
        if self.tracer:
            self.tracer.reset_stats()

    
    def _setup_session_handlers(self):
        @self.socketio.on('join_session')
        def handle_join_session(data):
            session_id = data.get('session_id')
            if session_id:
                from flask_socketio import join_room
                join_room(f"session_{session_id}")
                print(f"[WebSocket] Client joined session room: session_{session_id}")
                emit('joined_session', {'session_id': session_id})
        
        @self.socketio.on('leave_session')
        def handle_leave_session(data):
            session_id = data.get('session_id')
            if session_id:
                from flask_socketio import leave_room
                leave_room(f"session_{session_id}")
                print(f"[WebSocket] Client left session room: session_{session_id}")
    
    def start_session_tracking(self, session_id: str, mode: str, trace_filter: dict = None):
        print(f"[DEBUG] start_session_tracking called: session_id={session_id}, mode={mode}, filter={trace_filter}")
        with self.session_lock:
            if session_id not in self.session_trackers:
                tracker = SessionStatsTracker(session_id, mode, trace_filter)
                self.session_trackers[session_id] = tracker
                print(f"[Session] Started tracking for session: {session_id} (mode: {mode}, filter: {trace_filter})")
                print(f"[DEBUG] Active session trackers: {list(self.session_trackers.keys())}")

                if not self._session_stats_running:
                    self._session_stats_running = True
                    self._session_stats_thread = threading.Thread(
                        target=self._emit_session_stats_loop,
                        daemon=True
                    )
                    self._session_stats_thread.start()
                    print(f"[DEBUG] Stats emission thread started")
            else:
                print(f"[DEBUG] Session {session_id} already exists in trackers")
    
    def stop_session_tracking(self, session_id: str):
        """Stop tracking for a specific session"""
        with self.session_lock:
            if session_id in self.session_trackers:
                del self.session_trackers[session_id]
                print(f"[Session] Stopped tracking for session: {session_id}")
    
    def process_session_event(self, event: Dict, session_id: str):
        """Process an event for a specific session"""
        with self.session_lock:
            if session_id in self.session_trackers:
                self.session_trackers[session_id].process_event(event)
            else:
                # Debug: session not found
                if not hasattr(self, '_session_not_found_logged'):
                    self._session_not_found_logged = set()
                if session_id not in self._session_not_found_logged:
                    print(f"[Warning] Session {session_id} not found in trackers. Available: {list(self.session_trackers.keys())}")
                    self._session_not_found_logged.add(session_id)

                    # MEMORY LEAK FIX: Limit logged session IDs
                    if len(self._session_not_found_logged) > 100:
                        # Clear old entries when limit reached
                        self._session_not_found_logged = set(list(self._session_not_found_logged)[-50:])
    
    def _emit_session_stats_loop(self):
        print(f"[DEBUG] _emit_session_stats_loop started (1s interval)")
        iteration = 0
        while self._session_stats_running:
            time.sleep(1.0) 
            iteration += 1

            with self.session_lock:
                if iteration <= 3: 
                    print(f"[DEBUG] Emit iteration #{iteration}, active_sessions: {list(self.session_trackers.keys())}")

                for session_id, tracker in list(self.session_trackers.items()):
                    try:
                        stats = tracker.get_stats()

                        if iteration <= 3: 
                            print(f"[DEBUG] Emitting session stats for {session_id}: total_events={stats['total_events']}, total_packets={stats['total_packets']}")

                        # Emit to session-specific room
                        self.socketio.emit('session_stats_update', {
                            'session_id': session_id,
                            'stats': stats
                        }, room=f"session_{session_id}")
                    except Exception as e:
                        print(f"[Error] Failed to emit stats for session {session_id}: {e}")
                        import traceback
                        traceback.print_exc()


def add_realtime_routes(app: Flask, realtime: RealtimeExtension):
    """Add realtime API routes to Flask app (for backward compatibility)"""

    @app.route('/api/realtime/enable', methods=['POST'])
    def enable_realtime_compat():
        try:
            data = request.json or {}
            trace_filter = data.get('trace_filter', {})

            print(f"[Realtime] Enabling with filter: {trace_filter}")

            if realtime.enable(trace_filter=trace_filter):
                return jsonify({
                    'status': 'enabled',
                    'filter_enabled': realtime.tracer.stats.filter_enabled if realtime.tracer else False,
                    'trace_filter': realtime.tracer.stats.trace_filter if realtime.tracer else {}
                })
            else:
                return jsonify({'error': 'Failed to start realtime tracer'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/realtime/disable', methods=['POST'])
    def disable_realtime_compat():
        try:
            realtime.disable()
            return jsonify({'status': 'disabled'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/realtime/stats', methods=['GET'])
    def get_realtime_stats_compat():
        try:
            stats = realtime.get_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/realtime/reset', methods=['POST'])
    def reset_realtime_stats_compat():
        try:
            realtime.reset_stats()
            return jsonify({'status': 'reset'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


    @app.route('/api/monitoring/alerts', methods=['GET'])
    def get_alerts():
        """Get active alerts"""
        try:
            if not realtime or not realtime.tracer:
                return jsonify([])

            alerts = realtime.tracer.alert_engine.get_active_alerts()
            return jsonify(alerts)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/monitoring/alerts/history', methods=['GET'])
    def get_alerts_history():
        """Get alert history"""
        try:
            if not realtime or not realtime.tracer:
                return jsonify([])

            limit = request.args.get('limit', 50, type=int)
            history = realtime.tracer.alert_engine.get_alert_history(limit)
            return jsonify(history)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/monitoring/alerts/rules', methods=['GET'])
    def get_alert_rules():
        """Get all alert rules"""
        try:
            if not realtime or not realtime.tracer:
                return jsonify([])

            rules = realtime.tracer.alert_engine.get_rules()
            return jsonify(rules)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/monitoring/alerts/clear', methods=['POST'])
    def clear_alerts():
        """Clear all active alerts"""
        try:
            if not realtime or not realtime.tracer:
                return jsonify({'error': 'Tracer not initialized'}), 400

            realtime.tracer.alert_engine.clear_alerts()
            return jsonify({'status': 'cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/monitoring/alerts/stats', methods=['GET'])
    def get_alert_stats():
        """Get alert engine statistics"""
        try:
            if not realtime or not realtime.tracer:
                return jsonify({
                    'total_rules': 0,
                    'active_alerts': 0,
                    'total_alerts_raised': 0,
                    'rules_enabled': 0
                })

            stats = realtime.tracer.alert_engine.get_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    print("[✓] Realtime API routes registered: /api/realtime/{enable,disable,stats,reset}")
    print("[✓] Monitoring API routes registered: /api/monitoring/alerts/*")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Realtime Packet Tracer Backend - Final Version')
    parser.add_argument('--port', '-p', type=int, default=5000,
                       help='Flask port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Flask host (default: 0.0.0.0)')
    parser.add_argument('--auto-start', action='store_true',
                       help='Auto-start tracing on launch')
    parser.add_argument('--bpf-code', 
                       help='Path to BPF code')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        sys.exit(1)
    
    if args.auto_start:
        print("[*] Auto-starting tracer...")
        global tracer
        tracer = RealtimeTracer(socketio, args.bpf_code)
        if tracer.start():
            print("[✓] Tracer auto-started")
        else:
            print("[✗] Failed to auto-start tracer")
    
    try:
        socketio.run(
            app, 
            host=args.host, 
            port=args.port, 
            debug=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        if tracer:
            tracer.stop()

if __name__ == '__main__':
    main()