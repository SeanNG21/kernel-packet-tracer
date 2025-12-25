#!/bin/bash
# Setup drop rules for testing layer-specific drop counting

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test ports
NFT_DROP_PORT=9004
TCP_RST_PORT=9999

# Interface
IFACE="${1:-lo}"

echo -e "${GREEN}=== Setting up Layer Drop Tests ===${NC}"
echo ""

echo -e "${GREEN}[1] Netfilter PREROUTING Drop (nf_conntrack_in)${NC}"
nft add table ip drop_test 2>/dev/null || true
nft add chain ip drop_test prerouting { type filter hook prerouting priority -150\; } 2>/dev/null || nft flush chain ip drop_test prerouting
nft add rule ip drop_test prerouting tcp dport $NFT_DROP_PORT counter drop
echo -e "  ${GREEN}✓ Netfilter PREROUTING will drop TCP port $NFT_DROP_PORT${NC}"
echo ""

echo -e "${GREEN}[2] Netfilter INPUT Drop${NC}"
nft add chain ip drop_test input { type filter hook input priority 0\; } 2>/dev/null || nft flush chain ip drop_test input
nft add rule ip drop_test input tcp dport $((NFT_DROP_PORT + 1)) counter drop
echo -e "  ${GREEN}✓ Netfilter INPUT will drop TCP port $((NFT_DROP_PORT + 1))${NC}"
echo ""

echo -e "${YELLOW}[3] TCP RST (No listening socket - triggers tcp_v4_send_reset)${NC}"
echo -e "  ${YELLOW}ℹ Port $TCP_RST_PORT is not listening${NC}"
echo ""

echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Test commands:"
echo ""
echo -e "${YELLOW}Netfilter PREROUTING Drop:${NC}"
echo "  curl -m 1 http://127.0.0.1:$NFT_DROP_PORT 2>&1 | head -1"
echo "  # Should see TC_IN, NAT_PRE_IN, NAT_PRE_VERDICT (DROP)"
echo ""
echo -e "${YELLOW}Netfilter INPUT Drop:${NC}"
echo "  curl -m 1 http://127.0.0.1:$((NFT_DROP_PORT + 1)) 2>&1 | head -1"
echo "  # Should see TC_IN, NAT_PRE_IN, ROUTE_IN, NFT_RULE (DROP)"
echo ""
echo -e "${YELLOW}TCP RST (No socket):${NC}"
echo "  curl -m 1 http://127.0.0.1:$TCP_RST_PORT 2>&1 | head -1"
echo "  # Should see TC_IN, NAT_PRE_IN, ROUTE_IN, TCP_IN, TCP_DROP"
echo ""
echo "Auto-run all tests:"
echo "  sudo bash $(dirname $0)/run_drop_tests.sh 5"
