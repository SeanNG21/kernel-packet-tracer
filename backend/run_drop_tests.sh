#!/bin/bash
# Run drop tests and generate traffic

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

NFT_DROP_PORT=9004
TCP_RST_PORT=9999
REPEAT=${1:-5}

echo -e "${GREEN}=== Running Drop Tests (${REPEAT} packets each) ===${NC}"
echo ""

echo -e "${YELLOW}[1] NAT PREROUTING Drop (port $NFT_DROP_PORT)${NC}"
for i in $(seq 1 $REPEAT); do
    timeout 0.5 curl -s http://127.0.0.1:$NFT_DROP_PORT 2>/dev/null &
    sleep 0.05
done
wait 2>/dev/null
echo -e "  ${GREEN}✓ Sent $REPEAT packets${NC}"
echo ""

echo -e "${YELLOW}[2] Netfilter INPUT Drop (port $((NFT_DROP_PORT + 1)))${NC}"
for i in $(seq 1 $REPEAT); do
    timeout 0.5 curl -s http://127.0.0.1:$((NFT_DROP_PORT + 1)) 2>/dev/null &
    sleep 0.05
done
wait 2>/dev/null
echo -e "  ${GREEN}✓ Sent $REPEAT packets${NC}"
echo ""

echo -e "${YELLOW}[3] TCP RST / No Socket (port $TCP_RST_PORT)${NC}"
for i in $(seq 1 $REPEAT); do
    timeout 0.5 curl -s http://127.0.0.1:$TCP_RST_PORT 2>/dev/null &
    sleep 0.05
done
wait 2>/dev/null
echo -e "  ${GREEN}✓ Sent $REPEAT packets${NC}"
echo ""

echo -e "${GREEN}=== Tests Complete! ===${NC}"
echo ""
echo "Check your logs for:"
echo "  - NAT_PRE_VERDICT with DROP"
echo "  - NFT_RULE with DROP"
echo "  - TCP_DROP events"
