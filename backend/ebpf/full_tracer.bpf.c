// ROBUST KERNEL-VERSION-INDEPENDENT TRACER
// Uses proper kernel headers instead of hardcoded offsets
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/icmp.h>

// NOTE: We read nft_pktinfo and nf_hook_state fields directly by offset
// instead of declaring struct instances (BCC limitation).
//
// struct nft_pktinfo layout:
//   offset 0: struct sk_buff *skb
//   offset 8: struct nf_hook_state *state
//
// struct nf_hook_state layout:
//   offset 0: u8 hook
//   offset 1: u8 pf

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Netfilter hooks
#define NF_INET_PRE_ROUTING  0
#define NF_INET_LOCAL_IN     1
#define NF_INET_FORWARD      2
#define NF_INET_LOCAL_OUT    3
#define NF_INET_POST_ROUTING 4

// TC actions
#define TC_ACT_OK        0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT      2
#define TC_ACT_PIPE      3
#define TC_ACT_STOLEN    4
#define TC_ACT_QUEUED    5
#define TC_ACT_REPEAT    6
#define TC_ACT_REDIRECT  7

// Netfilter verdicts
#define NF_DROP    0
#define NF_ACCEPT  1
#define NF_STOLEN  2
#define NF_QUEUE   3
#define NF_REPEAT  4

// ICMP types
#define ICMP_DEST_UNREACH 3
#define ICMP_PORT_UNREACH 3

// Event types
#define EVENT_TYPE_FUNCTION_CALL 0
#define EVENT_TYPE_NFT_CHAIN     1
#define EVENT_TYPE_NFT_RULE      2
#define EVENT_TYPE_NF_VERDICT    3

// Layer-specific event types (INBOUND)
#define EVENT_TYPE_GRO_IN        10
#define EVENT_TYPE_TC_IN         11
#define EVENT_TYPE_TC_VERDICT    12
// REMOVED: NAT_PRE events (duplicates of Conntrack)
// #define EVENT_TYPE_NAT_PRE_IN    13
// #define EVENT_TYPE_NAT_PRE_VERDICT 14
#define EVENT_TYPE_CT_IN         15
#define EVENT_TYPE_CT_VERDICT    16
#define EVENT_TYPE_ROUTE_IN      17
#define EVENT_TYPE_ROUTE_VERDICT 18
#define EVENT_TYPE_TCP_IN        19
#define EVENT_TYPE_TCP_DROP      20
#define EVENT_TYPE_UDP_IN        21
#define EVENT_TYPE_UDP_DROP      22
#define EVENT_TYPE_SOCK_TCP_IN   23
#define EVENT_TYPE_SOCK_UDP_IN   24
#define EVENT_TYPE_SOCK_DROP     25

// Layer-specific event types (OUTBOUND)
#define EVENT_TYPE_APP_TCP_SEND  30
#define EVENT_TYPE_APP_UDP_SEND  31
#define EVENT_TYPE_TCP_OUT       32
#define EVENT_TYPE_UDP_OUT       33
#define EVENT_TYPE_ROUTE_OUT_LOOKUP 34
#define EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT 35
#define EVENT_TYPE_ROUTE_OUT     36
#define EVENT_TYPE_ROUTE_OUT_DISCARD 37
#define EVENT_TYPE_TC_EGRESS_IN  38
#define EVENT_TYPE_TC_EGRESS_VERDICT 39
#define EVENT_TYPE_DRIVER_TX     40
#define EVENT_TYPE_DRIVER_TX_FAIL 41

// Layer IDs (INBOUND)
#define LAYER_GRO             3
#define LAYER_TC_INGRESS      4
#define LAYER_NAT_PREROUTING  6
#define LAYER_CONNTRACK       7
#define LAYER_ROUTING         8
#define LAYER_TRANSPORT_TCP   10
#define LAYER_TRANSPORT_UDP   11
#define LAYER_SOCKET          12

// Layer IDs (OUTBOUND)
#define LAYER_APP_TCP         20
#define LAYER_APP_UDP         21
#define LAYER_TCP_OUT         22
#define LAYER_UDP_OUT         23
#define LAYER_ROUTING_OUT     24
#define LAYER_TC_EGRESS       25
#define LAYER_DRIVER_TX       26

struct trace_event {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;

    u8 event_type;
    u8 hook;
    u8 pf;
    u8 protocol;

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;

    u64 chain_addr;
    u64 expr_addr;
    u8 chain_depth;
    u16 rule_seq;
    u64 rule_handle;

    s32 verdict_raw;
    u32 verdict;
    u16 queue_num;
    u8 has_queue_bypass;

    u64 func_ip;
    char function_name[64];
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// MEMORY OPTIMIZATION: Reduced map sizes (was 10240, now 2048)
BPF_HASH(skb_info_map, u64, struct trace_event, 2048);
BPF_HASH(depth_map, u64, u8, 2048);

struct hook_state {
    u8 hook;
    u8 pf;
};
BPF_HASH(hook_map, u64, struct hook_state, 2048);

// MEMORY LEAK FIX: Track skb_addr per thread for cleanup
BPF_HASH(hook_skb_map, u64, u64, 2048);

// Packet info cache for enrichment across events
struct packet_info {
    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;
};
BPF_HASH(packet_info_map, u64, struct packet_info, 2048);

// Layer tracking - track which layer each packet passed through
BPF_HASH(last_layer_map, u64, u8, 2048);

// TC classify return value tracking (tid -> skb_addr)
BPF_HASH(tc_skb_map, u64, u64, 2048);

// NAT PREROUTING hooknum tracking (tid -> hooknum)
BPF_HASH(nat_pre_hooknum_map, u64, u32, 1024);

// Conntrack tracking (tid -> skb_addr)
BPF_HASH(ct_skb_map, u64, u64, 2048);

// Conntrack hooknum tracking (tid -> hooknum) - NEW for all hooks
BPF_HASH(ct_hook_map, u64, u32, 2048);

// Routing tracking (tid -> skb_addr)
BPF_HASH(route_skb_map, u64, u64, 2048);

// UDP queue tracking (tid -> skb_addr)
BPF_HASH(udp_queue_skb_map, u64, u64, 1024);

static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // NF_CONTINUE
            case -2: return 11;  // NF_RETURN
            case -3: return 12;  // NF_JUMP
            case -4: return 13;  // NF_GOTO
            case -5: return 14;  // NF_BREAK
            default: return 0;
        }
    }

    u32 verdict = raw_u32 & 0xFFu;
    if (verdict > 5) return 255;
    return verdict;
}

static __always_inline void read_comm_safe(char *dest, u32 size)
{
    #pragma unroll
    for (int i = 0; i < 16 && i < size; i++) {
        dest[i] = 0;
    }

    long ret = bpf_get_current_comm(dest, size);
    if (ret != 0) {
        dest[0] = '?';
        dest[1] = 0;
    }
}

static __always_inline u64 extract_rule_handle(void *expr)
{
    if (!expr)
        return 0;

    // Try multiple offsets to find rule handle (varies by kernel version)
    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96};

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u64 potential_handle = 0;

        if (bpf_probe_read_kernel(&potential_handle, sizeof(potential_handle),
                                   (char *)expr + offsets[i]) == 0) {
            if (potential_handle > 0 &&
                potential_handle < 0x100000 &&
                potential_handle != 0xFFFFFFFFFFFFFFFFULL) {
                return potential_handle;
            }
        }
    }

    return 0;
}

// EARLY-LAYER PACKET EXTRACTION (for GRO, TC Ingress)
// Uses skb->data directly for very early layers where headers aren't set yet
static __always_inline int extract_packet_info_from_skb_early(struct sk_buff *skb, struct trace_event *evt)
{
    if (!skb)
        return 0;

    evt->skb_addr = (u64)skb;

    // Read length
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    evt->length = len;

    // Read network protocol
    __be16 protocol_be = 0;
    bpf_probe_read_kernel(&protocol_be, sizeof(protocol_be), &skb->protocol);
    u16 eth_protocol = bpf_ntohs(protocol_be);

    // Only process IPv4 (0x0800)
    if (eth_protocol != 0x0800)
        return 0;

    // For early layers, use skb->data directly
    unsigned char *data = NULL;
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);

    if (!data)
        return 0;

    // Assume Ethernet header (14 bytes) + IP header
    // Try to skip Ethernet header to get to IP header
    void *ip_header = data + 14;

    // Read IP header
    u8 ihl_version = 0;
    u8 ip_protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header);
    u8 version = (ihl_version >> 4) & 0x0F;

    // Verify IPv4
    if (version != 4)
        return 0;

    // Read protocol, source IP, dest IP
    bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), ip_header + offsetof(struct iphdr, protocol));
    bpf_probe_read_kernel(&saddr, sizeof(saddr), ip_header + offsetof(struct iphdr, saddr));
    bpf_probe_read_kernel(&daddr, sizeof(daddr), ip_header + offsetof(struct iphdr, daddr));

    evt->protocol = ip_protocol;
    evt->src_ip = saddr;
    evt->dst_ip = daddr;

    // Extract TCP/UDP ports
    if (ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP) {
        u8 ihl = (ihl_version & 0x0F) * 4;
        void *trans_header = ip_header + ihl;

        u16 sport = 0;
        u16 dport = 0;

        bpf_probe_read_kernel(&sport, sizeof(sport), trans_header);
        bpf_probe_read_kernel(&dport, sizeof(dport), trans_header + 2);

        evt->src_port = bpf_ntohs(sport);
        evt->dst_port = bpf_ntohs(dport);
    }

    // VALIDATION: Ensure we have meaningful packet data
    if (evt->protocol == 0 || (evt->src_ip == 0 && evt->dst_ip == 0)) {
        return 0;  // Failed extraction
    }

    // Cache packet info for enrichment
    if (evt->protocol != 0 && evt->skb_addr != 0) {
        struct packet_info pinfo = {};
        pinfo.protocol = evt->protocol;
        pinfo.src_ip = evt->src_ip;
        pinfo.dst_ip = evt->dst_ip;
        pinfo.src_port = evt->src_port;
        pinfo.dst_port = evt->dst_port;
        pinfo.length = evt->length;
        packet_info_map.update(&evt->skb_addr, &pinfo);
    }

    return 1;  // Success
}

// KERNEL-VERSION-INDEPENDENT PACKET EXTRACTION
// Uses proper kernel structs instead of hardcoded offsets
// Enhanced to handle early-layer packets (GRO, TC) where network_header may not be set
static __always_inline int extract_packet_info_from_skb(struct sk_buff *skb, struct trace_event *evt)
{
    if (!skb)
        return 0;

    evt->skb_addr = (u64)skb;

    // Read length using proper struct member
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    evt->length = len;

    // Read network protocol
    __be16 protocol_be = 0;
    bpf_probe_read_kernel(&protocol_be, sizeof(protocol_be), &skb->protocol);
    u16 eth_protocol = bpf_ntohs(protocol_be);

    // Only process IPv4 (0x0800)
    if (eth_protocol != 0x0800)
        return 0;

    // Get IP header pointer - handle multiple scenarios for early layers
    unsigned char *head = NULL;
    u16 network_header = 0;
    u16 mac_header = 0;
    unsigned char *data = NULL;

    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header);
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);

    if (!head)
        return 0;

    void *ip_header = NULL;

    // Strategy 1: Use network_header if it's set (most reliable)
    if (network_header != 0 && network_header != 0xFFFF) {
        ip_header = head + network_header;
    }
    // Strategy 2: If network_header not set but mac_header is, calculate from MAC + Ethernet header size (14 bytes)
    else if (mac_header != 0 && mac_header != 0xFFFF) {
        ip_header = head + mac_header + 14;  // 14 = sizeof(struct ethhdr)
    }
    // Strategy 3: Use data pointer directly (for very early layers)
    else if (data != NULL) {
        ip_header = data;
    }
    // Strategy 4: Fallback - assume standard ethernet header offset
    else {
        ip_header = head + 14;
    }

    if (!ip_header)
        return 0;

    // Read IP header using struct iphdr
    u8 ihl_version = 0;
    u8 ip_protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header);
    u8 version = (ihl_version >> 4) & 0x0F;

    // Verify IPv4
    if (version != 4)
        return 0;

    // Read protocol, source IP, dest IP using iphdr offsets
    bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), ip_header + offsetof(struct iphdr, protocol));
    bpf_probe_read_kernel(&saddr, sizeof(saddr), ip_header + offsetof(struct iphdr, saddr));
    bpf_probe_read_kernel(&daddr, sizeof(daddr), ip_header + offsetof(struct iphdr, daddr));

    evt->protocol = ip_protocol;
    evt->src_ip = saddr;
    evt->dst_ip = daddr;

    // Extract TCP/UDP ports
    if (ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP) {
        u8 ihl = (ihl_version & 0x0F) * 4;
        void *trans_header = ip_header + ihl;

        u16 sport = 0;
        u16 dport = 0;

        // TCP and UDP have ports at same offset (first 4 bytes)
        bpf_probe_read_kernel(&sport, sizeof(sport), trans_header);
        bpf_probe_read_kernel(&dport, sizeof(dport), trans_header + 2);

        evt->src_port = bpf_ntohs(sport);
        evt->dst_port = bpf_ntohs(dport);
    }

    // VALIDATION: Ensure we have meaningful packet data
    // If protocol is 0 or both IPs are 0.0.0.0, extraction likely failed
    if (evt->protocol == 0 || (evt->src_ip == 0 && evt->dst_ip == 0)) {
        return 0;  // Failed extraction
    }

    // Cache packet info for enrichment
    if (evt->protocol != 0 && evt->skb_addr != 0) {
        struct packet_info pinfo = {};
        pinfo.protocol = evt->protocol;
        pinfo.src_ip = evt->src_ip;
        pinfo.dst_ip = evt->dst_ip;
        pinfo.src_port = evt->src_port;
        pinfo.dst_port = evt->dst_port;
        pinfo.length = evt->length;
        packet_info_map.update(&evt->skb_addr, &pinfo);
    }

    return 1;  // Success
}

// KERNEL-VERSION-INDEPENDENT NFT PACKET INFO EXTRACTION
// Reads nft_pktinfo fields directly (BCC doesn't allow struct instance on stack)
static __always_inline int extract_packet_info_from_pkt(void *pkt, struct trace_event *evt)
{
    if (!pkt)
        return 0;

    // Read nft_pktinfo fields directly (skb at offset 0, state at offset 8)
    void *skb = NULL;
    void *state = NULL;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);           // offset 0: skb
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt + 8);  // offset 8: state

    // Extract packet info from skb
    int success = 0;
    if (skb) {
        success = extract_packet_info_from_skb((struct sk_buff *)skb, evt);
    }

    // Extract hook and pf from state (first 2 bytes)
    if (state) {
        u8 hook = 0;
        u8 pf = 0;
        bpf_probe_read_kernel(&hook, sizeof(hook), state);            // offset 0: hook
        bpf_probe_read_kernel(&pf, sizeof(pf), (char *)state + 1);    // offset 1: pf
        evt->hook = hook;
        evt->pf = pf;
    }

    return success;
}

// OUTBOUND: Extract packet info from socket (for TCP/UDP Output layers)
// At TCP/UDP output, SKB headers aren't built yet, so extract from socket instead
static __always_inline int extract_packet_info_from_sock(void *sk, struct trace_event *evt)
{
    if (!sk)
        return 0;

    // Read socket common fields (inet_sock structure)
    // struct inet_sock {
    //     struct sock sk;            // offset 0
    //     ...
    //     __be32 inet_saddr;         // offset varies by kernel
    //     __be32 inet_daddr;         // offset varies by kernel
    //     __be16 inet_sport;         // offset varies by kernel
    //     __be16 inet_dport;         // offset varies by kernel
    //     __u16  inet_num;           // offset varies by kernel
    // }

    // Try common offsets for inet_sock fields (kernel 4.x - 6.x)
    // These offsets work for most kernels
    u32 saddr = 0;
    u32 daddr = 0;
    u16 sport = 0;
    u16 dport = 0;
    u16 family = 0;
    u8 protocol = 0;

    // Read socket family (AF_INET = 2 for IPv4)
    bpf_probe_read_kernel(&family, sizeof(family), (char *)sk + 16);  // sk_family offset
    if (family != 2)  // AF_INET
        return 0;

    // Read protocol (IPPROTO_TCP=6 or IPPROTO_UDP=17)
    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)sk + 18);  // sk_protocol offset
    evt->protocol = protocol;

    // Try to read inet_sock fields - offsets vary by kernel version
    // Common offsets: saddr around 188-200, daddr around 192-204
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (char *)sk + 188);  // inet_saddr
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)sk + 192);  // inet_daddr
    bpf_probe_read_kernel(&sport, sizeof(sport), (char *)sk + 196);  // inet_sport
    bpf_probe_read_kernel(&dport, sizeof(dport), (char *)sk + 198);  // inet_dport

    evt->src_ip = saddr;
    evt->dst_ip = daddr;
    evt->src_port = bpf_ntohs(sport);
    evt->dst_port = bpf_ntohs(dport);

    // Validate extraction
    if (evt->protocol == 0 || (evt->src_ip == 0 && evt->dst_ip == 0)) {
        return 0;
    }

    return 1;  // Success
}

// Enrich event from packet_info_map cache
static __always_inline void enrich_from_packet_cache(struct trace_event *evt)
{
    if (evt->skb_addr == 0)
        return;

    struct packet_info *cached = packet_info_map.lookup(&evt->skb_addr);
    if (cached && evt->protocol == 0) {
        evt->protocol = cached->protocol;
        evt->src_ip = cached->src_ip;
        evt->dst_ip = cached->dst_ip;
        evt->src_port = cached->src_port;
        evt->dst_port = cached->dst_port;
        evt->length = cached->length;
    }
}

// GENERIC SKB FUNCTION TRACER
// Only emits events for successfully decoded IPv4 packets
int trace_skb_func(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 tid = bpf_get_current_pid_tgid();

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_FUNCTION_CALL;
    evt.func_ip = PT_REGS_IP(ctx);

    // Extract packet info using proper structs
    int success = extract_packet_info_from_skb(skb, &evt);

    // CRITICAL: Only emit if we successfully decoded packet info
    // This prevents noisy events with all zeros
    if (!success || evt.protocol == 0) {
        return 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));

    // Enrich with hook/pf from hook_map if available
    if (evt.skb_addr != 0) {
        struct hook_state *hs = hook_map.lookup(&evt.skb_addr);
        if (hs) {
            evt.hook = hs->hook;
            evt.pf = hs->pf;
        }
    }

    // Filter out backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Store for NFT correlation
    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// DEDICATED NFT_DO_CHAIN TRACING
// Separate from generic tracing to avoid double-counting
int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);

    if (!pkt)
        return 0;

    // Track nesting depth
    u8 depth = 0;
    u8 *cur_depth = depth_map.lookup(&tid);
    if (cur_depth) {
        depth = *cur_depth + 1;
    }
    depth_map.update(&tid, &depth);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_CHAIN;
    evt.chain_addr = (u64)priv;
    evt.chain_depth = depth;

    // Extract packet info using proper structs
    extract_packet_info_from_pkt(pkt, &evt);

    // Enrich from cache if direct extraction failed
    enrich_from_packet_cache(&evt);

    read_comm_safe(evt.comm, sizeof(evt.comm));

    // Filter out backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        if (cur_depth && *cur_depth > 0) {
            u8 new_depth = *cur_depth - 1;
            depth_map.update(&tid, &new_depth);
        } else {
            depth_map.delete(&tid);
        }
        return 0;
    }

    // Store for return probe
    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }

    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct trace_event *stored = skb_info_map.lookup(&tid);
    u8 *depth_ptr = depth_map.lookup(&tid);
    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_CHAIN;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;

    // Copy packet info from stored event
    if (stored) {
        evt.skb_addr = stored->skb_addr;
        evt.chain_addr = stored->chain_addr;
        evt.hook = stored->hook;
        evt.pf = stored->pf;
        evt.protocol = stored->protocol;
        evt.src_ip = stored->src_ip;
        evt.dst_ip = stored->dst_ip;
        evt.src_port = stored->src_port;
        evt.dst_port = stored->dst_port;
        evt.length = stored->length;
    }

    // CRITICAL: Skip events with no valid SKB address
    // These are noise events that can't be correlated with packets
    if (evt.skb_addr == 0) {
        // Clean up depth tracking before returning
        if (depth_ptr && *depth_ptr > 0) {
            u8 new_depth = *depth_ptr - 1;
            depth_map.update(&tid, &new_depth);
        } else {
            skb_info_map.delete(&tid);
            depth_map.delete(&tid);
        }
        return 0;
    }

    // Enrich from cache if stored event had no info
    if (evt.protocol == 0) {
        enrich_from_packet_cache(&evt);
    }

    // ADDITIONAL VALIDATION: Skip events with all-zero packet data
    if (evt.protocol == 0 && evt.src_ip == 0 && evt.dst_ip == 0) {
        // Clean up depth tracking before returning
        if (depth_ptr && *depth_ptr > 0) {
            u8 new_depth = *depth_ptr - 1;
            depth_map.update(&tid, &new_depth);
        } else {
            skb_info_map.delete(&tid);
            depth_map.delete(&tid);
        }
        return 0;
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    // Clean up depth tracking
    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    } else {
        skb_info_map.delete(&tid);
        depth_map.delete(&tid);
    }

    return 0;
}

// DEDICATED NFT_IMMEDIATE_EVAL TRACING
int kprobe__nft_immediate_eval(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *expr = (void *)PT_REGS_PARM1(ctx);

    if (!expr)
        return 0;

    struct trace_event *stored = skb_info_map.lookup(&tid);
    if (!stored)
        return 0;

    stored->rule_seq++;

    // Read verdict code from expr
    s32 verdict_code = 0;
    bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8);

    u64 rule_handle = extract_rule_handle(expr);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_RULE;

    // Copy packet and chain info from stored event
    evt.skb_addr = stored->skb_addr;
    evt.chain_addr = stored->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.hook = stored->hook;
    evt.pf = stored->pf;
    evt.chain_depth = stored->chain_depth;
    evt.rule_seq = stored->rule_seq;
    evt.rule_handle = rule_handle;

    evt.protocol = stored->protocol;
    evt.src_ip = stored->src_ip;
    evt.dst_ip = stored->dst_ip;
    evt.src_port = stored->src_port;
    evt.dst_port = stored->dst_port;
    evt.length = stored->length;

    // Enrich from cache if stored event had no info
    if (evt.protocol == 0) {
        enrich_from_packet_cache(&evt);
    }

    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);

    if (evt.verdict == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    }

    // CRITICAL: Set func_ip for Python backend to identify this as nft_immediate_eval
    evt.func_ip = PT_REGS_IP(ctx);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// GRO LAYER TRACING (03_GRO)
//=============================================================================

// Hook: kprobe__dev_gro_receive
// Function: dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
// Goal: Count packets entering GRO layer
int kprobe__dev_gro_receive(struct pt_regs *ctx)
{
    void *napi = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_GRO_IN;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info using early-layer extraction (GRO is very early)
    int success = extract_packet_info_from_skb_early(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_GRO;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// TC INGRESS LAYER TRACING (04_TC_Ingress)
//=============================================================================

// Hook: kprobe__tcf_classify
// Function: tcf_classify(struct sk_buff *skb, const struct tcf_proto *tp, ...)
// Goal: Count packets entering TC and track verdicts
int kprobe__tcf_classify(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TC_IN;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info using early-layer extraction (TC Ingress is early)
    int success = extract_packet_info_from_skb_early(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_TC_INGRESS;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for return probe
    tc_skb_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kretprobe__tcf_classify
// Goal: Track TC verdict (drop/pass) for ALL packets
int kretprobe__tcf_classify(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 rax = PT_REGS_RC(ctx);
    s32 retval = (s32)rax;

    u64 *skb_addr_ptr = tc_skb_map.lookup(&tid);
    if (!skb_addr_ptr) {
        return 0;
    }

    u64 skb_addr = *skb_addr_ptr;
    tc_skb_map.delete(&tid);

    // IMPORTANT: Emit verdict event for ALL packets (both accept and drop)
    // This allows backend to count both accepts and drops
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TC_VERDICT;
    evt.skb_addr = skb_addr;
    evt.verdict_raw = retval;
    evt.verdict = (retval == TC_ACT_SHOT) ? 0 : 1;  // 0=drop, 1=accept
    evt.func_ip = PT_REGS_IP(ctx);

    // Enrich from cache
    enrich_from_packet_cache(&evt);

    // Skip if enrichment failed
    if (evt.protocol == 0 && evt.src_ip == 0 && evt.dst_ip == 0) {
        return 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// NAT PREROUTING LAYER TRACING (06_NAT_PREROUTING)
//=============================================================================

// Hook: kprobe__nf_conntrack_in
// Function: nf_conntrack_in(struct net *net, u8 pf, unsigned int hooknum, struct sk_buff *skb)
// Goal: Count packets in PREROUTING hook only
int kprobe__nf_conntrack_in(struct pt_regs *ctx)
{
    void *net = (void *)PT_REGS_PARM1(ctx);
    u8 pf = (u8)PT_REGS_PARM2(ctx);
    u32 hooknum = (u32)PT_REGS_PARM3(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    // Store hooknum and skb_addr for verdict tracking (ALL hooks, not just PREROUTING)
    ct_hook_map.update(&tid, &hooknum);
    ct_skb_map.update(&tid, &skb_addr);

    // --------------------------
    // Conntrack layer chung (07_Conntrack) - FOR ALL HOOKS
    // --------------------------
    struct trace_event evt_ct = {};
    evt_ct.timestamp = bpf_ktime_get_ns();
    evt_ct.cpu_id = bpf_get_smp_processor_id();
    evt_ct.pid = (u32)(tid >> 32);
    evt_ct.event_type = EVENT_TYPE_CT_IN;
    evt_ct.skb_addr = skb_addr;
    evt_ct.hook = (u8)hooknum;
    evt_ct.pf = pf;
    evt_ct.func_ip = PT_REGS_IP(ctx);
    evt_ct.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt_ct);
    if (success && evt_ct.protocol != 0) {
        // Track layer: NAT_PREROUTING for hook 0, otherwise CONNTRACK
        u8 layer = (hooknum == NF_INET_PRE_ROUTING)
                     ? LAYER_NAT_PREROUTING
                     : LAYER_CONNTRACK;
        last_layer_map.update(&skb_addr, &layer);

        // Filter backend/frontend traffic
        if (!(evt_ct.src_port == 3000 || evt_ct.dst_port == 3000 ||
              evt_ct.src_port == 5000 || evt_ct.dst_port == 5000)) {
            read_comm_safe(evt_ct.comm, sizeof(evt_ct.comm));
            events.perf_submit(ctx, &evt_ct, sizeof(evt_ct));
        }
    }

    // REMOVED: NAT_PRE_IN emission (was duplicate of Conntrack)
    // --------------------------
    // NAT_PRE: Emit thêm NAT_PRE_IN chỉ cho PREROUTING
    // --------------------------
    // if (hooknum == NF_INET_PRE_ROUTING && evt_ct.protocol != 0) {
    //     struct trace_event evt_nat = {};
    //     evt_nat.timestamp = evt_ct.timestamp;
    //     evt_nat.cpu_id = evt_ct.cpu_id;
    //     evt_nat.pid = evt_ct.pid;
    //     evt_nat.event_type = EVENT_TYPE_NAT_PRE_IN;
    //     evt_nat.skb_addr = skb_addr;
    //     evt_nat.hook = (u8)hooknum;
    //     evt_nat.pf = pf;
    //     evt_nat.func_ip = PT_REGS_IP(ctx);
    //     evt_nat.verdict = 255;
    //
    //     // Copy packet info from CT event
    //     evt_nat.protocol = evt_ct.protocol;
    //     evt_nat.src_ip = evt_ct.src_ip;
    //     evt_nat.dst_ip = evt_ct.dst_ip;
    //     evt_nat.src_port = evt_ct.src_port;
    //     evt_nat.dst_port = evt_ct.dst_port;
    //     evt_nat.length = evt_ct.length;
    //
    //     if (!(evt_nat.src_port == 3000 || evt_nat.dst_port == 3000 ||
    //           evt_nat.src_port == 5000 || evt_nat.dst_port == 5000)) {
    //         read_comm_safe(evt_nat.comm, sizeof(evt_nat.comm));
    //         events.perf_submit(ctx, &evt_nat, sizeof(evt_nat));
    //     }
    // }

    return 0;
}

// Hook: kretprobe__nf_conntrack_in
// Goal: Track verdict (accept/drop) for ALL hooks
int kretprobe__nf_conntrack_in(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 rax = PT_REGS_RC(ctx);
    u32 retval = (u32)rax;

    u32 *hooknum_ptr = ct_hook_map.lookup(&tid);
    u64 *skb_addr_ptr = ct_skb_map.lookup(&tid);

    if (!hooknum_ptr || !skb_addr_ptr) {
        ct_hook_map.delete(&tid);
        ct_skb_map.delete(&tid);
        return 0;
    }

    u32 hooknum = *hooknum_ptr;
    u64 skb_addr = *skb_addr_ptr;

    ct_hook_map.delete(&tid);
    ct_skb_map.delete(&tid);

    // --------------------------
    // Conntrack verdict chung (CT_VERDICT) - FOR ALL HOOKS
    // --------------------------
    struct trace_event evt_ct = {};
    evt_ct.timestamp = bpf_ktime_get_ns();
    evt_ct.cpu_id = bpf_get_smp_processor_id();
    evt_ct.pid = (u32)(tid >> 32);
    evt_ct.event_type = EVENT_TYPE_CT_VERDICT;
    evt_ct.skb_addr = skb_addr;
    evt_ct.hook = (u8)hooknum;
    evt_ct.verdict_raw = (s32)retval;
    evt_ct.func_ip = PT_REGS_IP(ctx);

    // Map verdict: NF_ACCEPT (1) or NF_DROP (0)
    if (retval == NF_ACCEPT)
        evt_ct.verdict = NF_ACCEPT;
    else if (retval == NF_DROP)
        evt_ct.verdict = NF_DROP;
    else
        evt_ct.verdict = retval & 0xFF;

    // Enrich from cache
    enrich_from_packet_cache(&evt_ct);

    // Skip if enrichment failed
    if (evt_ct.protocol == 0 && evt_ct.src_ip == 0 && evt_ct.dst_ip == 0) {
        return 0;
    }

    read_comm_safe(evt_ct.comm, sizeof(evt_ct.comm));
    events.perf_submit(ctx, &evt_ct, sizeof(evt_ct));

    // REMOVED: NAT_PRE_VERDICT emission (was duplicate of Conntrack)
    // --------------------------
    // NAT_PRE verdict riêng (NAT_PRE_VERDICT) - CHỈ PREROUTING
    // --------------------------
    // if (hooknum == NF_INET_PRE_ROUTING) {
    //     struct trace_event evt_nat = evt_ct;  // Copy từ CT event
    //     evt_nat.event_type = EVENT_TYPE_NAT_PRE_VERDICT;
    //     // verdict đã được map ở trên, giữ nguyên
    //     events.perf_submit(ctx, &evt_nat, sizeof(evt_nat));
    // }

    return 0;
}

//=============================================================================
// CONNTRACK LAYER TRACING (07_Conntrack)
// FULLY IMPLEMENTED in kprobe/kretprobe__nf_conntrack_in above
//=============================================================================

// Conntrack events (EVENT_TYPE_CT_IN / EVENT_TYPE_CT_VERDICT) are now emitted
// for ALL hooks (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING).
//
// REMOVED: NAT_PREROUTING events (were duplicates of Conntrack)

//=============================================================================
// ROUTING DECISION LAYER TRACING (08_Routing_Decision)
//=============================================================================

// Hook: kprobe__ip_route_input_noref
// Function: ip_route_input_noref(struct sk_buff *skb, ...)
// Goal: Track routing decisions for inbound packets
int kprobe__ip_route_input_noref(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_IN;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_ROUTING;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for return probe
    route_skb_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kretprobe__ip_route_input_noref
// Goal: Track routing verdict (ok/drop) for ALL packets
int kretprobe__ip_route_input_noref(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 rax = PT_REGS_RC(ctx);
    s32 retval = (s32)rax;

    u64 *skb_addr_ptr = route_skb_map.lookup(&tid);
    if (!skb_addr_ptr) {
        return 0;
    }

    u64 skb_addr = *skb_addr_ptr;
    route_skb_map.delete(&tid);

    // IMPORTANT: Emit verdict event for ALL packets (both success and error)
    // This allows backend to count both accepts and drops
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_VERDICT;
    evt.skb_addr = skb_addr;
    evt.verdict_raw = retval;
    evt.verdict = (retval == 0) ? 1 : 0;  // 0=error/drop, 1=accept
    evt.func_ip = PT_REGS_IP(ctx);

    // Enrich from cache
    enrich_from_packet_cache(&evt);

    // Skip if enrichment failed
    if (evt.protocol == 0 && evt.src_ip == 0 && evt.dst_ip == 0) {
        return 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// TRANSPORT LAYER TRACING (10_Transport) - TCP
//=============================================================================

// Hook: kprobe__tcp_v4_rcv
// Function: tcp_v4_rcv(struct sk_buff *skb)
// Goal: Count TCP segments entering transport layer
int kprobe__tcp_v4_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TCP_IN;
    evt.protocol = 6;  // TCP
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_TRANSPORT_TCP;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kprobe__tcp_v4_send_reset
// Function: tcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
// Goal: Count TCP drops due to no port
int kprobe__tcp_v4_send_reset(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    // Only count when sk == NULL (no listening socket)
    if (sk != NULL || !skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TCP_DROP;
    evt.protocol = 6;  // TCP
    evt.verdict = 0;  // drop
    evt.verdict_raw = -1;  // no port
    evt.func_ip = PT_REGS_IP(ctx);

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// TRANSPORT LAYER TRACING (11_Transport) - UDP
//=============================================================================

// Hook: kprobe____udp4_lib_rcv
// Function: __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable, int proto)
// Goal: Count UDP datagrams entering transport layer
int kprobe____udp4_lib_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_UDP_IN;
    evt.protocol = 17;  // UDP
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_TRANSPORT_UDP;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// SOCKET LAYER TRACING (12_Socket)
//=============================================================================

// Hook: kprobe__tcp_queue_rcv
// Function: tcp_queue_rcv(struct sock *sk, struct sk_buff *skb)
// Goal: Count TCP packets queued to socket
int kprobe__tcp_queue_rcv(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_SOCK_TCP_IN;
    evt.protocol = 6;  // TCP
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_SOCKET;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kprobe__udp_queue_rcv_skb
// Function: udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb, ...)
// Goal: Count UDP packets queued to socket
int kprobe__udp_queue_rcv_skb(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    // Store for return probe
    udp_queue_skb_map.update(&tid, &skb_addr);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_SOCK_UDP_IN;
    evt.protocol = 17;  // UDP
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        udp_queue_skb_map.delete(&tid);
        return 0;
    }

    // Track layer
    u8 layer = LAYER_SOCKET;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// NF_HOOK_SLOW TRACKING
// Captures hook/pf for correlation with packet events
int kprobe__nf_hook_slow(struct pt_regs *ctx)
{
    void *skb = (void *)PT_REGS_PARM1(ctx);
    void *state = (void *)PT_REGS_PARM2(ctx);

    if (!skb || !state)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    // Read hook and pf directly from nf_hook_state (first 2 bytes)
    u8 hook = 0;
    u8 pf = 0;
    bpf_probe_read_kernel(&hook, sizeof(hook), state);            // offset 0: hook
    bpf_probe_read_kernel(&pf, sizeof(pf), (char *)state + 1);    // offset 1: pf

    struct hook_state hs = {};
    hs.hook = hook;
    hs.pf = pf;

    hook_map.update(&skb_addr, &hs);

    // MEMORY LEAK FIX: Store skb_addr for cleanup in kretprobe
    hook_skb_map.update(&tid, &skb_addr);

    return 0;
}

int kretprobe__nf_hook_slow(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    u32 verdict = decode_verdict(rax_s32, rax_u32);

    // Get skb_addr BEFORE emitting event
    u64 *skb_addr_ptr = hook_skb_map.lookup(&tid);
    if (!skb_addr_ptr) {
        return 0;  // No SKB tracked, skip
    }

    u64 skb_addr = *skb_addr_ptr;

    // CRITICAL: Skip events with no valid SKB address
    // These are noise events that can't be correlated with packets
    if (skb_addr == 0) {
        hook_skb_map.delete(&tid);
        return 0;
    }

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NF_VERDICT;
    evt.skb_addr = skb_addr;  // NOW we set the SKB address
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;

    // FIX: Read hook and pf from hook_map (saved by kprobe__nf_hook_slow)
    struct hook_state *hs = hook_map.lookup(&skb_addr);
    if (hs) {
        evt.hook = hs->hook;
        evt.pf = hs->pf;
    }

    // Enrich from packet cache
    enrich_from_packet_cache(&evt);

    // ADDITIONAL VALIDATION: Skip events with all-zero packet data
    if (evt.protocol == 0 && evt.src_ip == 0 && evt.dst_ip == 0) {
        hook_map.delete(&skb_addr);
        hook_skb_map.delete(&tid);
        packet_info_map.delete(&skb_addr);
        return 0;
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    // MEMORY LEAK FIX: Cleanup hook_map entry after processing
    hook_map.delete(&skb_addr);
    hook_skb_map.delete(&tid);
    // Also cleanup packet cache
    packet_info_map.delete(&skb_addr);

    return 0;
}

//=============================================================================
// OUTBOUND TRACING - APPLICATION LAYER (Optional)
//=============================================================================

// Hook: kprobe__tcp_sendmsg
// Function: tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// Goal: Count application TCP send calls
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);
    u64 size = (u64)PT_REGS_PARM3(ctx);

    if (!sk)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_APP_TCP_SEND;
    evt.protocol = 6;  // TCP
    evt.length = (u32)size;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // For app layer, we don't have skb yet, so we can't extract full packet info
    // We'll set basic info from socket
    evt.skb_addr = 0;  // No SKB yet at this layer

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kprobe__udp_sendmsg
// Function: udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// Goal: Count application UDP send calls
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    void *msg = (void *)PT_REGS_PARM2(ctx);
    u64 len = (u64)PT_REGS_PARM3(ctx);

    if (!sk)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_APP_UDP_SEND;
    evt.protocol = 17;  // UDP
    evt.length = (u32)len;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // For app layer, we don't have skb yet
    evt.skb_addr = 0;  // No SKB yet at this layer

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// OUTBOUND TRACING - TRANSPORT LAYER (TCP/UDP Output)
//=============================================================================

// Tracking map for __tcp_transmit_skb
BPF_HASH(tcp_transmit_skb_map, u64, u64, 2048);

// Hook: kprobe____tcp_transmit_skb
// Function: __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, ...)
// Goal: Count TCP packets going out through transport layer
int kprobe____tcp_transmit_skb(struct pt_regs *ctx)
{
    void *sk = (void *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    if (!skb || !sk)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TCP_OUT;
    evt.skb_addr = skb_addr;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // CRITICAL FIX: Extract from SOCKET instead of SKB
    // At TCP output, SKB headers aren't built yet, so extract from socket
    int success = extract_packet_info_from_sock(sk, &evt);
    if (!success || evt.protocol == 0) {
        // Fallback: try SKB extraction (may work for some packets)
        success = extract_packet_info_from_skb(skb, &evt);
        if (!success || evt.protocol == 0) {
            return 0;
        }
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Cache packet info for later layers
    if (evt.protocol != 0 && skb_addr != 0) {
        struct packet_info pinfo = {};
        pinfo.protocol = evt.protocol;
        pinfo.src_ip = evt.src_ip;
        pinfo.dst_ip = evt.dst_ip;
        pinfo.src_port = evt.src_port;
        pinfo.dst_port = evt.dst_port;
        pinfo.length = evt.length;
        packet_info_map.update(&skb_addr, &pinfo);
    }

    // Track layer
    u8 layer = LAYER_TCP_OUT;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for tracking
    tcp_transmit_skb_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Tracking map for udp_send_skb
BPF_HASH(udp_send_skb_map, u64, u64, 2048);

// Hook: kprobe__udp_send_skb
// Function: udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4, ...)
// Goal: Count UDP packets going out through transport layer
int kprobe__udp_send_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_UDP_OUT;
    evt.skb_addr = skb_addr;
    evt.protocol = 17;  // UDP (set default, may be overwritten by extraction)
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info from SKB (UDP layer may have headers ready)
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        // If extraction failed, set protocol explicitly and continue
        evt.protocol = 17;  // Force UDP
        // Try to enrich from cache (may have been set by earlier layer)
        enrich_from_packet_cache(&evt);

        // If still no packet info, skip this event
        if (evt.src_ip == 0 && evt.dst_ip == 0) {
            return 0;
        }
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Cache packet info for later layers
    if (evt.protocol != 0 && skb_addr != 0) {
        struct packet_info pinfo = {};
        pinfo.protocol = evt.protocol;
        pinfo.src_ip = evt.src_ip;
        pinfo.dst_ip = evt.dst_ip;
        pinfo.src_port = evt.src_port;
        pinfo.dst_port = evt.dst_port;
        pinfo.length = evt.length;
        packet_info_map.update(&skb_addr, &pinfo);
    }

    // Track layer
    u8 layer = LAYER_UDP_OUT;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for tracking
    udp_send_skb_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// OUTBOUND TRACING - ROUTING LAYER
//=============================================================================

// Tracking map for ip_route_output_flow
BPF_HASH(route_output_flow_map, u64, u64, 2048);

// Hook: kprobe__ip_route_output_flow
// Function: ip_route_output_flow(struct net *net, struct flowi4 *flp, struct sock *sk)
// Goal: Count routing lookups for outbound packets (no skb available here)
int kprobe__ip_route_output_flow(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_OUT_LOOKUP;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet
    evt.skb_addr = 0;  // No SKB available at routing lookup

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kretprobe__ip_route_output_flow
// Goal: Track routing lookup verdict (ok/fail)
int kretprobe__ip_route_output_flow(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 rax = PT_REGS_RC(ctx);
    void *rt = (void *)rax;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_OUT_LOOKUP_VERDICT;
    evt.skb_addr = 0;  // No SKB at this layer
    evt.func_ip = PT_REGS_IP(ctx);

    // Check if IS_ERR(rt) - error pointers are in range [0xfffffffffffff001, 0xffffffffffffffff]
    u64 rt_val = (u64)rt;
    if (rt_val >= 0xfffffffffffff001ULL) {
        evt.verdict = 0;  // FAIL/DROP
        evt.verdict_raw = -1;
    } else {
        evt.verdict = 1;  // OK/ACCEPT
        evt.verdict_raw = 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Tracking map for ip_local_out
BPF_HASH(ip_local_out_map, u64, u64, 2048);

// Hook: kprobe__ip_local_out
// Function: ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
// Goal: Count packets going through IP output (with skb)
int kprobe__ip_local_out(struct pt_regs *ctx)
{
    void *net = (void *)PT_REGS_PARM1(ctx);
    void *sk = (void *)PT_REGS_PARM2(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_OUT;
    evt.skb_addr = skb_addr;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info (IP headers should be ready at this layer)
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        // Enrich from cache (may have been set by TCP/UDP layer)
        enrich_from_packet_cache(&evt);

        // If still no packet info, skip
        if (evt.protocol == 0 || (evt.src_ip == 0 && evt.dst_ip == 0)) {
            return 0;
        }
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_ROUTING_OUT;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for tracking
    ip_local_out_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kprobe__dst_discard_out
// Function: dst_discard_out(struct sk_buff *skb)
// Goal: Count route discard (blackhole)
int kprobe__dst_discard_out(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_ROUTE_OUT_DISCARD;
    evt.skb_addr = skb_addr;
    evt.verdict = 0;  // DROP/DISCARD
    evt.verdict_raw = -1;
    evt.func_ip = PT_REGS_IP(ctx);

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        // Enrich from cache
        enrich_from_packet_cache(&evt);

        // If still no packet info, skip
        if (evt.protocol == 0 || (evt.src_ip == 0 && evt.dst_ip == 0)) {
            return 0;
        }
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_ROUTING_OUT;
    last_layer_map.update(&skb_addr, &layer);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// OUTBOUND TRACING - TC EGRESS LAYER
//=============================================================================

// Tracking map for __dev_queue_xmit
BPF_HASH(dev_queue_xmit_map, u64, u64, 2048);

// Hook: kprobe____dev_queue_xmit
// Function: __dev_queue_xmit(struct sk_buff *skb, struct net_device *dev, ...)
// Goal: Count packets entering TC/qdisc egress
int kprobe____dev_queue_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_TC_EGRESS_IN;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_TC_EGRESS;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for tracking
    dev_queue_xmit_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

//=============================================================================
// OUTBOUND TRACING - DRIVER TX LAYER
//=============================================================================

// Tracking map for dev_hard_start_xmit
BPF_HASH(dev_hard_start_xmit_map, u64, u64, 2048);

// Hook: kprobe__dev_hard_start_xmit
// Function: dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev, ...)
// Goal: Count TX packets going to driver
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_DRIVER_TX;
    evt.func_ip = PT_REGS_IP(ctx);
    evt.verdict = 255;  // UNKNOWN - entry events don't have verdicts yet

    // Extract packet info
    int success = extract_packet_info_from_skb(skb, &evt);
    if (!success || evt.protocol == 0) {
        return 0;
    }

    // Filter backend/frontend traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    // Track layer
    u8 layer = LAYER_DRIVER_TX;
    last_layer_map.update(&skb_addr, &layer);

    // Store skb_addr for return probe
    dev_hard_start_xmit_map.update(&tid, &skb_addr);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Hook: kretprobe__dev_hard_start_xmit
// Goal: Track TX verdict (ok/fail)
int kretprobe__dev_hard_start_xmit(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    u64 rax = PT_REGS_RC(ctx);
    s32 retval = (s32)rax;

    u64 *skb_addr_ptr = dev_hard_start_xmit_map.lookup(&tid);
    if (!skb_addr_ptr) {
        return 0;
    }

    u64 skb_addr = *skb_addr_ptr;
    dev_hard_start_xmit_map.delete(&tid);

    // Only emit event if TX failed (retval != NETDEV_TX_OK which is 0)
    if (retval != 0) {
        struct trace_event evt = {};
        evt.timestamp = bpf_ktime_get_ns();
        evt.cpu_id = bpf_get_smp_processor_id();
        evt.pid = (u32)(tid >> 32);
        evt.event_type = EVENT_TYPE_DRIVER_TX_FAIL;
        evt.skb_addr = skb_addr;
        evt.verdict = 0;  // FAIL/DROP
        evt.verdict_raw = retval;
        evt.func_ip = PT_REGS_IP(ctx);

        // Enrich from cache
        enrich_from_packet_cache(&evt);

        // Skip if enrichment failed
        if (!(evt.protocol == 0 && evt.src_ip == 0 && evt.dst_ip == 0)) {
            read_comm_safe(evt.comm, sizeof(evt.comm));
            events.perf_submit(ctx, &evt, sizeof(evt));
        }
    }

    return 0;
}
