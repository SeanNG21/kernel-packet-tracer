#!/bin/bash
# Cleanup test configuration

echo "=== Cleaning up test configuration ==="

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

IFACE="${1:-lo}"

echo "[1] Removing TC filters..."
tc qdisc del dev $IFACE clsact 2>/dev/null || true
echo -e "  ${GREEN}✓ TC filters removed${NC}"

echo "[2] Removing nftables test rules..."
nft delete table ip drop_test 2>/dev/null || true
echo -e "  ${GREEN}✓ nftables rules removed${NC}"

echo "[3] Removing blackhole route..."
ip route del blackhole 192.168.99.99/32 2>/dev/null || true
echo -e "  ${GREEN}✓ Blackhole route removed${NC}"

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
