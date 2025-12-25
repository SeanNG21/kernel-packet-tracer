"""
Pipeline Model - Single Source of Truth for NFT Tracer

This module provides unified layer mapping, direction detection, and pipeline
topology for both Trace Session and Realtime tracing.

Key Principles:
1. ONE mapping: function → layer → node → direction
2. ONE pipeline topology: nodes + edges + order
3. ONE stats model: base classes for tracking packets/drops/latency
4. NO duplication: both app.py and realtime_extension.py use this module

Author: NFT Tracer Team
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import time

# ============================================================================
# CONSTANTS - Protocol, Verdict, Error Maps
# ============================================================================

PROTO_MAP = {
    1: "ICMP",
    2: "IGMP",
    4: "IPIP",      # IP-in-IP encapsulation
    6: "TCP",
    17: "UDP",
    41: "IPv6",     # IPv6 encapsulation
    47: "GRE",      # Generic Routing Encapsulation
    50: "ESP",      # Encapsulating Security Payload
    51: "AH",       # Authentication Header
    58: "ICMPv6",
    132: "SCTP"
}

VERDICT_MAP = {
    0: "DROP",      # NF_DROP
    1: "ACCEPT",    # NF_ACCEPT
    2: "STOLEN",    # NF_STOLEN
    3: "QUEUE",     # NF_QUEUE
    4: "REPEAT",    # NF_REPEAT
    5: "STOP",      # NF_STOP
    10: "CONTINUE", # NFT_CONTINUE
    11: "RETURN",   # NFT_RETURN
    12: "JUMP",     # NFT_JUMP
    13: "GOTO",     # NFT_GOTO
    14: "BREAK",    # NFT_BREAK
    255: "UNKNOWN"
}

ERROR_MAP = {
    0: "NONE",
    1: "CHECKSUM_FAIL",
    2: "NO_ROUTE",
    3: "INVALID_VERDICT",
    4: "QUEUE_OVERFLOW",
    5: "TTL_EXPIRED"
}

HOOK_MAP = {
    0: "PRE_ROUTING",
    1: "LOCAL_IN",
    2: "FORWARD",
    3: "LOCAL_OUT",
    4: "POST_ROUTING",
    255: "UNKNOWN"
}

# Event type constants matching BPF definitions
EVENT_TYPE_FUNCTION_CALL = 0
EVENT_TYPE_NFT_CHAIN     = 1
EVENT_TYPE_NFT_RULE      = 2
EVENT_TYPE_NF_VERDICT    = 3

# Layer-specific event types (INBOUND)
EVENT_TYPE_GRO_IN        = 10
EVENT_TYPE_TC_IN         = 11
EVENT_TYPE_TC_VERDICT    = 12
# REMOVED: NAT_PRE events (were duplicates of Conntrack)
# EVENT_TYPE_NAT_PRE_IN    = 13
# EVENT_TYPE_NAT_PRE_VERDICT = 14
EVENT_TYPE_CT_IN         = 15
EVENT_TYPE_CT_VERDICT    = 16
EVENT_TYPE_ROUTE_IN      = 17
EVENT_TYPE_ROUTE_VERDICT = 18
EVENT_TYPE_TCP_IN        = 19
EVENT_TYPE_TCP_DROP      = 20
EVENT_TYPE_UDP_IN        = 21
EVENT_TYPE_UDP_DROP      = 22
EVENT_TYPE_SOCK_TCP_IN   = 23
EVENT_TYPE_SOCK_UDP_IN   = 24
EVENT_TYPE_SOCK_DROP     = 25

# Layer-specific event types (OUTBOUND)
EVENT_TYPE_APP_TCP_SEND  = 30
EVENT_TYPE_APP_UDP_SEND  = 31
EVENT_TYPE_TCP_OUT       = 32
EVENT_TYPE_UDP_OUT       = 33
EVENT_TYPE_ROUTE_OUT_LOOKUP = 34
EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT = 35
EVENT_TYPE_ROUTE_OUT     = 36
EVENT_TYPE_ROUTE_OUT_DISCARD = 37
EVENT_TYPE_TC_EGRESS_IN  = 38
EVENT_TYPE_TC_EGRESS_VERDICT = 39
EVENT_TYPE_DRIVER_TX     = 40
EVENT_TYPE_DRIVER_TX_FAIL = 41

# ============================================================================
# LAYER & NODE DEFINITIONS - Single Source of Truth
# ============================================================================

# Function → Layer mapping (NEW optimized tracing)
FUNCTION_TO_LAYER = {
    # === INBOUND PIPELINE ===
    # GRO
    'gro_normal_list': 'GRO',
    'dev_gro_receive': 'GRO',
    'skb_gro_receive': 'GRO',

    # TC Ingress
    'tcf_classify': 'TC Ingress',
    'ingress_redirect': 'TC Ingress',
    'dev_queue_xmit_nit': 'TC Ingress',

    # Netfilter (will be refined by hook value)
    'nf_hook_slow': 'Netfilter',
    'nf_hook_thresh': 'Netfilter',
    'nf_reinject': 'Netfilter',
    'nft_do_chain': 'Netfilter',
    'nft_immediate_eval': 'Netfilter',

    # Conntrack
    'nf_conntrack_in': 'Conntrack',
    'nf_ct_invert_tuple': 'Conntrack',
    'nf_confirm': 'Conntrack',

    # Routing Decision
    'ip_route_input_noref': 'Routing Decision',
    'ip_route_input_slow': 'Routing Decision',
    'fib_validate_source': 'Routing Decision',
    'ip_route_output_key_hash': 'Routing',

    # IP Receive (before local delivery decision)
    'ip_rcv': 'IP Receive',
    'ip_rcv_core': 'IP Receive',
    'ip_rcv_finish': 'IP Receive',

    # Local Delivery
    'ip_local_deliver': 'Local Delivery',
    'ip_local_deliver_finish': 'Local Delivery',

    # Netfilter INPUT
    'nf_queue': 'Netfilter',

    # TCP/UDP (Inbound)
    'tcp_v4_rcv': 'TCP/UDP',
    'tcp_v4_send_reset': 'TCP/UDP',
    'tcp_v4_do_rcv': 'TCP/UDP',
    'tcp_rcv_established': 'TCP/UDP',
    '__udp4_lib_rcv': 'TCP/UDP',
    'udp_rcv': 'TCP/UDP',
    'udp_unicast_rcv_skb': 'TCP/UDP',

    # Socket
    'tcp_queue_rcv': 'Socket',
    'udp_queue_rcv_skb': 'Socket',
    'sk_filter_trim_cap': 'Socket',

    # Forward
    'ip_forward': 'Forward',
    'ip_forward_finish': 'Forward',

    # === OUTBOUND PIPELINE ===
    # Application
    'tcp_sendmsg': 'Application',
    'udp_sendmsg': 'Application',

    # TCP/UDP Output (multiple function names for same layer)
    'tcp_write_xmit': 'TCP/UDP Output',         # Alternative TCP output function
    'tcp_transmit_skb': 'TCP/UDP Output',       # Without underscore prefix
    '__tcp_transmit_skb': 'TCP/UDP Output',     # With underscore prefix
    'tcp_send_mss': 'TCP/UDP Output',           # MSS calculation
    'tcp_send_ack': 'TCP/UDP Output',           # ACK transmission
    'udp_send_skb': 'TCP/UDP Output',

    # Routing Lookup (outbound)
    'ip_route_output_flow': 'Routing Lookup',
    'ip_local_out': 'Routing Lookup',
    'dst_discard_out': 'Routing Lookup',

    # TC Egress
    'sch_direct_xmit': 'TC Egress',
    '__dev_queue_xmit': 'TC Egress',

    # Driver TX
    'dev_queue_xmit': 'Driver TX',
    'dev_hard_start_xmit': 'Driver TX',
}

# Event type → Layer mapping (for verdict events)
EVENT_TYPE_TO_LAYER = {
    # INBOUND
    10: 'GRO',              # GRO_IN
    11: 'TC Ingress',       # TC_IN
    12: 'TC Ingress',       # TC_VERDICT
    # REMOVED: NAT_PRE (13, 14) - were duplicates of Conntrack
    15: 'Conntrack',        # CT_IN
    16: 'Conntrack',        # CT_VERDICT
    17: 'Routing Decision', # ROUTE_IN
    18: 'Routing Decision', # ROUTE_VERDICT
    19: 'TCP/UDP',          # TCP_IN
    20: 'TCP/UDP',          # TCP_DROP
    21: 'TCP/UDP',          # UDP_IN
    22: 'TCP/UDP',          # UDP_DROP
    23: 'Socket',           # SOCK_TCP_IN
    24: 'Socket',           # SOCK_UDP_IN
    25: 'Socket',           # SOCK_DROP

    # OUTBOUND
    30: 'Application',      # APP_TCP_SEND
    31: 'Application',      # APP_UDP_SEND
    32: 'TCP/UDP Output',   # TCP_OUT
    33: 'TCP/UDP Output',   # UDP_OUT
    34: 'Routing Lookup',   # ROUTE_OUT_LOOKUP
    35: 'Routing Lookup',   # ROUTE_OUT_LOOKUP_VERDICT
    36: 'Routing Lookup',   # ROUTE_OUT
    37: 'Routing Lookup',   # ROUTE_OUT_DISCARD
    38: 'TC Egress',        # TC_EGRESS_IN
    39: 'TC Egress',        # TC_EGRESS_VERDICT
    40: 'Driver TX',        # DRIVER_TX
    41: 'Driver TX',        # DRIVER_TX_FAIL

    # NETFILTER
    1: 'Netfilter',         # NFT_CHAIN
    2: 'Netfilter',         # NFT_RULE
    3: 'Netfilter',         # NF_VERDICT
}

# Pipeline topology - defines node order and edges
PIPELINE_TOPOLOGY = {
    'Inbound': {
        'nodes': [
            'GRO',
            'TC Ingress',
            'IP Receive',           # ip_rcv, ip_rcv_finish
            'Netfilter PREROUTING',
            'Conntrack',
            'Routing Decision',
            'Local Delivery',
            'Netfilter INPUT',
            'TCP/UDP',
            'Socket',
        ],
        'edges': [
            ('GRO', 'TC Ingress'),
            ('TC Ingress', 'IP Receive'),
            ('IP Receive', 'Netfilter PREROUTING'),
            ('Netfilter PREROUTING', 'Conntrack'),
            ('Conntrack', 'Routing Decision'),
            ('Routing Decision', 'Local Delivery'),
            ('Local Delivery', 'Netfilter INPUT'),
            ('Netfilter INPUT', 'TCP/UDP'),
            ('TCP/UDP', 'Socket'),
        ]
    },
    'Outbound': {
        'nodes': [
            'Application',
            'TCP/UDP Output',
            'Netfilter OUTPUT',
            'Routing Lookup',
            'Netfilter POSTROUTING',
            'TC Egress',
            'Driver TX',
        ],
        'edges': [
            ('Application', 'TCP/UDP Output'),
            ('TCP/UDP Output', 'Netfilter OUTPUT'),
            ('Netfilter OUTPUT', 'Routing Lookup'),
            ('Routing Lookup', 'Netfilter POSTROUTING'),
            ('Netfilter POSTROUTING', 'TC Egress'),
            ('TC Egress', 'Driver TX'),
        ]
    },
    'Forward': {
        'nodes': [
            'GRO',
            'TC Ingress',
            'Netfilter PREROUTING',
            'Routing Decision',
            'Forward',
            'Netfilter FORWARD',
            'Netfilter POSTROUTING',
            'TC Egress',
            'Driver TX',
        ],
        'edges': [
            ('GRO', 'TC Ingress'),
            ('TC Ingress', 'Netfilter PREROUTING'),
            ('Netfilter PREROUTING', 'Routing Decision'),
            ('Routing Decision', 'Forward'),
            ('Forward', 'Netfilter FORWARD'),
            ('Netfilter FORWARD', 'Netfilter POSTROUTING'),
            ('Netfilter POSTROUTING', 'TC Egress'),
            ('TC Egress', 'Driver TX'),
        ]
    }
}

# ============================================================================
# LAYER REFINEMENT & DIRECTION DETECTION - Unified Logic
# ============================================================================

def refine_layer_by_hook(func_name: str, base_layer: str, hook: int) -> str:
    """
    Refine generic layer name based on netfilter hook value.
    Hook values: 0=PREROUTING, 1=INPUT, 2=FORWARD, 3=OUTPUT, 4=POSTROUTING

    This is the ONLY place where layer refinement happens.
    Both Trace Session and Realtime use this function.
    """
    # Netfilter functions need to be refined by hook
    if base_layer == 'Netfilter' or 'nf_hook' in func_name or 'nf_queue' in func_name:
        hook_map = {
            0: 'Netfilter PREROUTING',
            1: 'Netfilter INPUT',
            2: 'Netfilter FORWARD',
            3: 'Netfilter OUTPUT',
            4: 'Netfilter POSTROUTING',
        }
        return hook_map.get(hook, base_layer)

    # Routing functions
    if 'Routing' in base_layer:
        if 'input' in func_name:
            return 'Routing Decision'
        elif 'output' in func_name:
            return 'Routing Lookup'
        return base_layer

    return base_layer


def detect_packet_direction(func_name: str, layer: str, hook: int = 255) -> str:
    """
    Detect packet direction (Inbound/Outbound/Forward) from function name and layer.

    This is the ONLY place where direction detection happens.
    Both Trace Session and Realtime use this function.

    Priority:
    1. Layer-based detection (most reliable)
    2. Hook-based detection (for netfilter)
    3. Keyword-based detection (fallback)
    """
    # Define inbound/outbound/forward layers
    inbound_layers = [
        'GRO', 'TC Ingress', 'IP Receive',
        'Netfilter PREROUTING', 'Netfilter INPUT',
        'Conntrack', 'Routing Decision',
        'Local Delivery', 'TCP/UDP', 'Socket'
    ]

    outbound_layers = [
        'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
        'Routing Lookup', 'Netfilter POSTROUTING',
        'TC Egress', 'Driver TX'
    ]

    forward_layers = [
        'Forward', 'Netfilter FORWARD'
    ]

    # 1. Layer-based detection
    if layer in inbound_layers:
        return 'Inbound'
    if layer in outbound_layers:
        return 'Outbound'
    if layer in forward_layers:
        return 'Forward'

    # 2. Hook-based detection (for netfilter)
    if hook != 255:
        if hook in [0, 1]:  # PREROUTING, INPUT
            return 'Inbound'
        elif hook == 2:  # FORWARD
            return 'Forward'
        elif hook in [3, 4]:  # OUTPUT, POSTROUTING
            return 'Outbound'

    # 3. Keyword-based detection (fallback)
    inbound_keywords = ['rcv', 'receive', 'input', 'ingress', 'deliver']
    outbound_keywords = ['sendmsg', 'xmit', 'transmit', 'output', 'egress']
    forward_keywords = ['forward', 'fwd']

    func_lower = func_name.lower()
    for keyword in inbound_keywords:
        if keyword in func_lower:
            return 'Inbound'
    for keyword in outbound_keywords:
        if keyword in func_lower:
            return 'Outbound'
    for keyword in forward_keywords:
        if keyword in func_lower:
            return 'Forward'

    # Default to Inbound (most packets are inbound)
    return 'Inbound'


def get_layer_from_function(func_name: str) -> str:
    """Get layer name from function name using FUNCTION_TO_LAYER"""
    return FUNCTION_TO_LAYER.get(func_name, 'Unknown')


def get_layer_from_event_type(event_type: int) -> str:
    """Get layer name from event type (for verdict events)"""
    return EVENT_TYPE_TO_LAYER.get(event_type, 'Unknown')


def get_pipeline_for_direction(direction: str) -> Dict:
    """Get pipeline topology for a given direction"""
    return PIPELINE_TOPOLOGY.get(direction, PIPELINE_TOPOLOGY['Inbound'])


# ============================================================================
# BASE STATS CLASSES - Shared by Trace Session and Realtime
# ============================================================================

@dataclass
class NodeStats:
    """
    Statistics for a single pipeline node.
    Used by both Trace Session and Realtime.
    """
    packets_in: int = 0
    packets_out: int = 0
    drops: int = 0
    accepts: int = 0
    errors: int = 0
    total_latency_us: float = 0.0
    latency_count: int = 0
    in_flight_packets: Set[str] = field(default_factory=set)
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    function_calls: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def avg_latency_us(self) -> float:
        """Average latency in microseconds"""
        if self.latency_count == 0:
            return 0.0
        return self.total_latency_us / self.latency_count

    @property
    def drop_rate(self) -> float:
        """Drop rate percentage"""
        total = self.packets_in
        if total == 0:
            return 0.0
        return (self.drops / total) * 100

    def add_event(self, skb_addr: str, latency_us: float = 0.0,
                  function: str = None, verdict: str = None, error: bool = False):
        """Add an event to this node's statistics"""
        self.packets_in += 1

        if latency_us > 0:
            self.total_latency_us += latency_us
            self.latency_count += 1

        if function:
            self.function_calls[function] += 1

        if verdict:
            self.verdict_breakdown[verdict] += 1
            if verdict == 'DROP':
                self.drops += 1
            elif verdict == 'ACCEPT':
                self.accepts += 1

        if error:
            self.errors += 1

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        top_func = None
        top_func_count = 0
        if self.function_calls:
            top_func, top_func_count = max(
                self.function_calls.items(),
                key=lambda x: x[1]
            )

        return {
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'drops': self.drops,
            'accepts': self.accepts,
            'errors': self.errors,
            'avg_latency_us': round(self.avg_latency_us, 3),
            'drop_rate': round(self.drop_rate, 2),
            'in_flight': len(self.in_flight_packets),
            'verdict_breakdown': dict(self.verdict_breakdown),
            'error_breakdown': dict(self.error_breakdown),
            'function_calls': dict(sorted(
                self.function_calls.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_function': top_func,
            'top_function_calls': top_func_count,
        }


@dataclass
class PipelineStats:
    """
    Statistics for a complete pipeline (Inbound/Outbound/Forward).
    Used by both Trace Session and Realtime.
    """
    name: str
    nodes: Dict[str, NodeStats] = field(default_factory=dict)
    edges: Dict[Tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    unique_skbs: Set[str] = field(default_factory=set)

    @property
    def started(self) -> int:
        """Number of packets that entered this pipeline"""
        return len(self.unique_skbs)

    @property
    def in_flight(self) -> int:
        """Number of packets currently in this pipeline"""
        total = 0
        for node in self.nodes.values():
            total += len(node.in_flight_packets)
        return total

    @property
    def completed(self) -> int:
        """Number of packets that left this pipeline"""
        return self.started - self.in_flight

    def get_or_create_node(self, node_name: str) -> NodeStats:
        """Get existing node or create new one"""
        if node_name not in self.nodes:
            self.nodes[node_name] = NodeStats()
        return self.nodes[node_name]

    def add_edge(self, from_node: str, to_node: str):
        """Add an edge between two nodes"""
        self.edges[(from_node, to_node)] += 1

    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization"""
        return {
            'name': self.name,
            'started': self.started,
            'in_flight': self.in_flight,
            'completed': self.completed,
            'nodes': {name: node.to_dict() for name, node in self.nodes.items()},
            'edges': [
                {'from': from_node, 'to': to_node, 'count': count}
                for (from_node, to_node), count in self.edges.items()
            ]
        }


class BasePipelineEngine:
    """
    Base class for pipeline event processing.
    Both Trace Session and Realtime inherit from this.

    This ensures IDENTICAL logic for:
    - Layer mapping
    - Direction detection
    - Node/edge tracking
    - Stats counting
    """

    def __init__(self):
        self.pipelines: Dict[str, PipelineStats] = {
            'Inbound': PipelineStats('Inbound'),
            'Outbound': PipelineStats('Outbound'),
            'Forward': PipelineStats('Forward'),
        }
        self.skb_tracking: Dict[str, Dict] = {}  # Track SKB state
        self.skb_paths: Dict[str, List[str]] = {}  # Track path each SKB took

    def process_event(self, event: Dict) -> Tuple[str, str, str]:
        """
        Process a single event and update pipeline stats.

        Returns: (layer_name, node_name, direction)

        This is the CORE method that both Trace Session and Realtime use.
        """
        # Extract event info
        skb_addr = event.get('skb_addr')
        func_name = event.get('func_name', event.get('function', ''))
        event_type = event.get('event_type', 0)
        hook = event.get('hook', 255)
        verdict = event.get('verdict')
        verdict_name = event.get('verdict_name', VERDICT_MAP.get(verdict, 'UNKNOWN'))
        timestamp = event.get('timestamp', time.time())

        # Determine layer
        if event_type >= 10 and event_type <= 25:
            # Layer-specific event
            layer = get_layer_from_event_type(event_type)
        elif func_name:
            # Function call event
            layer = get_layer_from_function(func_name)
        else:
            layer = 'Unknown'

        # Refine layer by hook
        if hook != 255:
            layer = refine_layer_by_hook(func_name, layer, hook)

        # Detect direction
        direction = detect_packet_direction(func_name, layer, hook)

        # Node name = refined layer name
        node_name = layer

        # Track SKB state
        if skb_addr:
            if skb_addr not in self.skb_tracking:
                self.skb_tracking[skb_addr] = {
                    'first_ts': timestamp,
                    'last_ts': timestamp,
                }
            else:
                self.skb_tracking[skb_addr]['last_ts'] = timestamp

            # Track path
            if skb_addr not in self.skb_paths:
                self.skb_paths[skb_addr] = []

            # Add to path if not duplicate
            if not self.skb_paths[skb_addr] or self.skb_paths[skb_addr][-1] != node_name:
                self.skb_paths[skb_addr].append(node_name)

        # Get pipeline and node
        pipeline = self.pipelines[direction]
        node = pipeline.get_or_create_node(node_name)

        # Calculate latency
        latency_us = 0.0
        if skb_addr and skb_addr in self.skb_tracking:
            first_ts = self.skb_tracking[skb_addr]['first_ts']
            latency_us = (timestamp - first_ts) * 1_000_000

        # Update node stats
        node.add_event(
            skb_addr=skb_addr or '',
            latency_us=latency_us,
            function=func_name,
            verdict=verdict_name if verdict_name != 'UNKNOWN' else None,
            error=event.get('error', False)
        )

        # Track SKB in pipeline
        if skb_addr:
            pipeline.unique_skbs.add(skb_addr)
            node.in_flight_packets.add(skb_addr)

        # Update edges (transition from previous node)
        if skb_addr and len(self.skb_paths.get(skb_addr, [])) >= 2:
            path = self.skb_paths[skb_addr]
            prev_node = path[-2]
            curr_node = path[-1]
            if prev_node != curr_node:
                pipeline.add_edge(prev_node, curr_node)
                # Remove from previous node's in-flight
                prev_node_stats = pipeline.get_or_create_node(prev_node)
                prev_node_stats.in_flight_packets.discard(skb_addr)
                prev_node_stats.packets_out += 1

        return (layer, node_name, direction)

    def get_pipeline_stats(self, direction: str = None) -> Dict:
        """Get pipeline stats for JSON serialization"""
        if direction:
            return self.pipelines[direction].to_dict()
        else:
            return {
                name: pipeline.to_dict()
                for name, pipeline in self.pipelines.items()
            }

# ============================================================================
# FILTER CONFIGURATION - Shared by Trace Session and Realtime
# ============================================================================

EXCLUDED_PORTS = {3000, 5000, 5001}  # Frontend, Backend, SocketIO

def should_filter_event(event: Dict) -> bool:
    """
    Determine if an event should be filtered out.
    Used by both Trace Session and Realtime to ensure consistent filtering.
    """
    src_port = event.get('src_port', 0)
    dst_port = event.get('dst_port', 0)

    # Filter backend/frontend traffic
    if src_port in EXCLUDED_PORTS or dst_port in EXCLUDED_PORTS:
        return True

    # Filter invalid events
    if event.get('protocol', 0) == 0 and event.get('src_ip') == 0:
        return True

    return False
