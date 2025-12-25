// Educational descriptions for each pipeline node
// Helps users understand what each kernel component does

export const NODE_DESCRIPTIONS = {
  // === INBOUND PIPELINE ===
  'GRO': {
    title: 'Generic Receive Offload',
    description: 'Combines multiple related packets into one larger packet to reduce processing overhead.',
    details: 'Why packets decrease here: GRO merges TCP segments. Example: 10 small packets → 1 large packet = 90% reduction!'
  },

  'TC Ingress': {
    title: 'Traffic Control Ingress',
    description: 'Linux Traffic Control ingress hook for QoS, shaping, and filtering incoming traffic.',
    details: 'Can apply tc filters, rate limiting, packet marking (DSCP/TOS), and redirection.'
  },

  'Netfilter PREROUTING': {
    title: 'Netfilter Hook: PREROUTING',
    description: 'First netfilter hook - inspects packets BEFORE routing decision.',
    details: 'Used for: DNAT (destination NAT), connection tracking, packet mangling. Runs before kernel decides where packet goes.'
  },

  'Conntrack': {
    title: 'Connection Tracking (conntrack)',
    description: 'Tracks connection state (NEW, ESTABLISHED, RELATED, INVALID) for stateful filtering.',
    details: 'Maintains table of all connections. Essential for NAT and stateful firewall rules. High traffic can cause table overflow!'
  },

  'NAT PREROUTING': {
    title: 'Network Address Translation (PREROUTING)',
    description: 'Rewrites destination IP/port for incoming packets (DNAT).',
    details: 'Example: Public IP 1.2.3.4:80 → Private IP 192.168.1.10:8080 for port forwarding.'
  },

  'Routing Decision': {
    title: 'IP Routing Decision',
    description: 'Kernel decides packet destination: local delivery, forward to another host, or drop.',
    details: 'Checks routing table. Determines if packet is for this machine (→ INPUT) or needs forwarding (→ FORWARD).'
  },

  // === LOCAL DELIVERY BRANCH ===
  'Netfilter INPUT': {
    title: 'Netfilter Hook: INPUT',
    description: 'Filters packets destined for local processes on this machine.',
    details: 'Last firewall checkpoint before packet reaches application. Common place for DROP/ACCEPT rules.'
  },

  'TCP/UDP': {
    title: 'Transport Layer (TCP/UDP Processing)',
    description: 'TCP/UDP protocol processing: checksum validation, reassembly, flow control.',
    details: 'TCP: handles ACKs, retransmissions, congestion control. UDP: simple validation and delivery.'
  },

  'Socket': {
    title: 'Application Socket',
    description: 'Final destination: packet delivered to application socket (e.g., web server, database).',
    details: 'Application reads data via recv()/read() system calls. Journey complete!'
  },

  // === FORWARD BRANCH ===
  'Netfilter FORWARD': {
    title: 'Netfilter Hook: FORWARD',
    description: 'Filters packets being routed/forwarded through this machine (router/gateway mode).',
    details: 'Only active if ip_forward=1. Used in routers, VPNs, Docker bridges to filter transit traffic.'
  },

  'Netfilter POSTROUTING': {
    title: 'Netfilter Hook: POSTROUTING',
    description: 'Last netfilter hook AFTER routing decision, just before packet leaves.',
    details: 'Used for: SNAT (source NAT/masquerading), final packet modifications. Common for internet sharing (NAT).'
  },

  // === OUTBOUND PIPELINE ===
  'Application': {
    title: 'Application Process',
    description: 'User-space application sending data (e.g., curl, browser, database client).',
    details: 'App calls send()/write(), kernel creates sk_buff (socket buffer) to represent packet.'
  },

  'TCP/UDP Output': {
    title: 'Transport Layer Output',
    description: 'TCP/UDP adds headers, calculates checksums, handles segmentation.',
    details: 'TCP: adds sequence numbers, ACK numbers, flags. UDP: simple header only.'
  },

  'Netfilter OUTPUT': {
    title: 'Netfilter Hook: OUTPUT',
    description: 'Filters locally-generated packets before routing.',
    details: 'Can drop/modify packets from local applications. Useful for blocking outbound connections.'
  },

  'Routing Lookup': {
    title: 'Routing Table Lookup',
    description: 'Determines which interface to send packet out and next-hop gateway.',
    details: 'Checks routing table for best match. Selects source IP if not specified.'
  },

  'NAT POSTROUTING': {
    title: 'NAT POSTROUTING (SNAT/Masquerade)',
    description: 'Rewrites source IP/port for outgoing packets.',
    details: 'Example: Private IP 192.168.1.10 → Public IP 1.2.3.4 (SNAT/masquerade for internet access).'
  },

  'TC Egress': {
    title: 'Traffic Control Egress',
    description: 'QoS, rate limiting, and shaping for outbound traffic.',
    details: 'Can implement HTB, TBF, FQ_CODEL queuing disciplines for bandwidth control.'
  },

  'Driver TX': {
    title: 'Network Driver Transmit',
    description: 'Driver prepares packet for hardware transmission.',
    details: 'Adds hardware headers (Ethernet), handles TSO (TCP Segmentation Offload) if supported.'
  }
};

// Helper function to get description
export function getNodeDescription(nodeName) {
  return NODE_DESCRIPTIONS[nodeName] || {
    title: nodeName,
    description: 'Kernel network stack component.',
    details: 'Part of Linux packet processing pipeline.'
  };
}

// Get short summary (1 line)
export function getNodeSummary(nodeName) {
  const desc = NODE_DESCRIPTIONS[nodeName];
  return desc ? desc.description : 'Network processing node';
}
