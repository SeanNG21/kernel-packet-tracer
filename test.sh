#!/bin/bash

# NFT Tracer System Test Script
# Verifies installation and basic functionality

set -e

echo "=========================================="
echo "  NFT Tracer System Test"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓${NC} $1"
}

fail() {
    echo -e "${RED}✗${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# 1. Check if running as root
echo "1. Checking permissions..."
if [ "$EUID" -eq 0 ]; then
    pass "Running as root"
    ((TESTS_PASSED++))
else
    warn "Not running as root (required for BPF)"
    ((TESTS_WARNED++))
fi
echo ""

# 2. Check kernel version
echo "2. Checking kernel version..."
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -ge 4 ] && [ "$KERNEL_MINOR" -ge 14 ]; then
    pass "Kernel version: $KERNEL_VERSION (>= 4.14 required)"
    ((TESTS_PASSED++))
else
    fail "Kernel version: $KERNEL_VERSION (need >= 4.14)"
    ((TESTS_FAILED++))
fi
echo ""

# 3. Check kernel headers
echo "3. Checking kernel headers..."
if [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    pass "Kernel headers installed"
    ((TESTS_PASSED++))
else
    fail "Kernel headers not found"
    echo "   Install with: sudo apt-get install linux-headers-$(uname -r)"
    ((TESTS_FAILED++))
fi
echo ""

# 4. Check BCC installation
echo "4. Checking BCC installation..."
if python3 -c "from bcc import BPF" 2>/dev/null; then
    pass "BCC Python module available"
    ((TESTS_PASSED++))
else
    fail "BCC not found"
    echo "   Install with: sudo apt-get install bpfcc-tools python3-bpfcc"
    ((TESTS_FAILED++))
fi
echo ""

# 5. Check Python dependencies
echo "5. Checking Python dependencies..."
MISSING_DEPS=()
for dep in flask flask_cors psutil; do
    if ! python3 -c "import $dep" 2>/dev/null; then
        MISSING_DEPS+=($dep)
    fi
done

if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
    pass "All Python dependencies installed"
    ((TESTS_PASSED++))
else
    fail "Missing Python packages: ${MISSING_DEPS[*]}"
    echo "   Install with: pip3 install -r backend/requirements.txt"
    ((TESTS_FAILED++))
fi
echo ""

# 6. Check Node.js
echo "6. Checking Node.js installation..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    pass "Node.js installed: $NODE_VERSION"
    ((TESTS_PASSED++))
else
    warn "Node.js not found (optional for frontend)"
    ((TESTS_WARNED++))
fi
echo ""

# 7. Check nftables
echo "7. Checking nftables..."
if command -v nft &> /dev/null; then
    pass "nftables installed"
    
    # Check if nftables has rules
    if sudo nft list ruleset 2>/dev/null | grep -q "table"; then
        pass "nftables has rules configured"
    else
        warn "nftables installed but no rules found"
    fi
    ((TESTS_PASSED++))
else
    warn "nftables not found (target system may not have rules)"
    ((TESTS_WARNED++))
fi
echo ""

# 8. Check kernel symbols
echo "8. Checking kernel symbols..."
SYMBOLS_FOUND=0
for symbol in nft_do_chain nft_immediate_eval nf_hook_slow; do
    if sudo cat /proc/kallsyms 2>/dev/null | grep -q " ${symbol}$"; then
        pass "Symbol found: $symbol"
        ((SYMBOLS_FOUND++))
    else
        fail "Symbol not found: $symbol"
    fi
done

if [ $SYMBOLS_FOUND -eq 3 ]; then
    ((TESTS_PASSED++))
else
    ((TESTS_FAILED++))
    echo "   Note: Some symbols may not be available if nftables is not loaded"
fi
echo ""

# 9. Check filesystem structure
echo "9. Checking project files..."
FILES_OK=true
for file in backend/app.py backend/nft_tracer.bpf.c backend/requirements.txt; do
    if [ -f "$file" ]; then
        pass "File exists: $file"
    else
        fail "File missing: $file"
        FILES_OK=false
    fi
done

if $FILES_OK; then
    ((TESTS_PASSED++))
else
    ((TESTS_FAILED++))
fi
echo ""

# 10. Test backend health (if running)
echo "10. Testing backend health..."
if curl -s http://localhost:5000/api/health &> /dev/null; then
    HEALTH_DATA=$(curl -s http://localhost:5000/api/health)
    BCC_AVAILABLE=$(echo $HEALTH_DATA | grep -o '"bcc_available":[^,}]*' | cut -d: -f2)
    
    if [ "$BCC_AVAILABLE" = "true" ]; then
        pass "Backend is running and BCC is available"
        ((TESTS_PASSED++))
    else
        warn "Backend is running but BCC is not available"
        ((TESTS_WARNED++))
    fi
else
    warn "Backend not running (start with: sudo python3 backend/app.py)"
    ((TESTS_WARNED++))
fi
echo ""

# Summary
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo ""
echo -e "${GREEN}Passed:${NC}  $TESTS_PASSED"
echo -e "${YELLOW}Warned:${NC}  $TESTS_WARNED"
echo -e "${RED}Failed:${NC}  $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Start backend:  sudo python3 backend/app.py"
    echo "  2. Start frontend: cd frontend && npm start"
    echo "  3. Access UI:      http://localhost:3000"
    exit 0
else
    echo -e "${RED}Some tests failed. Please fix the issues above.${NC}"
    exit 1
fi
