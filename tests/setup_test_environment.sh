#!/bin/bash
################################################################################
# Test Environment Setup Script
################################################################################
#
# This script installs all necessary dependencies for running the NFT Tracer
# test scenarios.
#
# Author: NFT Tracer Development Team
# Date: 2025-11-24
#
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${GREEN}================================================================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}================================================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

print_header "NFT TRACER TEST ENVIRONMENT SETUP"

echo "This script will install the following components:"
echo "  • nftables - Linux kernel firewall"
echo "  • iperf3 - Network performance testing"
echo "  • hping3 - Packet generation tool"
echo "  • sockperf - Latency measurement tool (optional)"
echo "  • Python packages - requests, psutil, socketio, matplotlib, numpy"
echo ""
echo "Estimated time: 5-10 minutes"
echo ""

read -p "Press Enter to continue or Ctrl+C to cancel..."

################################################################################
# System Package Installation
################################################################################

print_header "INSTALLING SYSTEM PACKAGES"

# Update package list
echo "Updating package list..."
apt-get update -qq

# Install nftables
if command -v nft &> /dev/null; then
    print_success "nftables already installed"
else
    echo "Installing nftables..."
    apt-get install -y nftables
    print_success "nftables installed"
fi

# Install iperf3
if command -v iperf3 &> /dev/null; then
    print_success "iperf3 already installed"
else
    echo "Installing iperf3..."
    apt-get install -y iperf3
    print_success "iperf3 installed"
fi

# Install hping3
if command -v hping3 &> /dev/null; then
    print_success "hping3 already installed"
else
    echo "Installing hping3..."
    apt-get install -y hping3
    print_success "hping3 installed"
fi

# Install sockperf (optional, for advanced latency testing)
echo "Installing sockperf (optional)..."
if apt-get install -y sockperf 2>/dev/null; then
    print_success "sockperf installed"
else
    print_warning "sockperf not available in repositories (optional, skipping)"
fi

# Install scapy (for packet crafting)
if command -v pip3 &> /dev/null; then
    echo "Installing scapy..."
    pip3 install scapy 2>/dev/null || print_warning "scapy installation failed (optional)"
    print_success "scapy installed"
fi

################################################################################
# Python Package Installation
################################################################################

print_header "INSTALLING PYTHON PACKAGES"

# Ensure pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Installing pip3..."
    apt-get install -y python3-pip
fi

# Upgrade pip
echo "Upgrading pip..."
pip3 install --upgrade pip -qq

# Install required Python packages
PYTHON_PACKAGES=(
    "requests"
    "psutil"
    "python-socketio[client]"
    "matplotlib"
    "numpy"
    "pandas"
)

for package in "${PYTHON_PACKAGES[@]}"; do
    echo "Installing $package..."
    pip3 install "$package" -qq
    print_success "$package installed"
done

################################################################################
# Optional: Install pwru for comparison
################################################################################

print_header "OPTIONAL: INSTALLING PWRU (for comparison tests)"

echo "pwru is an eBPF-based packet tracer from Cilium project."
echo "It will be used for performance comparison."
echo ""

read -p "Install pwru? (y/n) [default: y]: " -n 1 -r INSTALL_PWRU
echo ""

if [[ $INSTALL_PWRU =~ ^[Yy]$ ]] || [[ -z $INSTALL_PWRU ]]; then
    if command -v pwru &> /dev/null; then
        print_success "pwru already installed"
    else
        echo "Downloading pwru..."

        # Detect architecture
        ARCH=$(uname -m)
        if [ "$ARCH" = "x86_64" ]; then
            PWRU_ARCH="amd64"
        elif [ "$ARCH" = "aarch64" ]; then
            PWRU_ARCH="arm64"
        else
            print_warning "Unsupported architecture: $ARCH"
            PWRU_ARCH="amd64"
        fi

        # Download latest release
        PWRU_VERSION="v1.0.6"  # Update to latest version
        PWRU_URL="https://github.com/cilium/pwru/releases/download/${PWRU_VERSION}/pwru-linux-${PWRU_ARCH}.tar.gz"

        cd /tmp
        wget -q "$PWRU_URL" -O pwru.tar.gz

        if [ $? -eq 0 ]; then
            tar xzf pwru.tar.gz
            mv pwru /usr/local/bin/
            chmod +x /usr/local/bin/pwru
            rm pwru.tar.gz
            print_success "pwru installed to /usr/local/bin/pwru"
        else
            print_error "Failed to download pwru"
            print_warning "You can install it manually from: https://github.com/cilium/pwru/releases"
        fi
    fi
else
    print_warning "pwru installation skipped"
fi

################################################################################
# Create Results Directory
################################################################################

print_header "SETTING UP DIRECTORIES"

TEST_DIR="/home/user/nft-tracer-app/tests"
RESULTS_DIR="$TEST_DIR/results"
CHARTS_DIR="$RESULTS_DIR/charts"

mkdir -p "$RESULTS_DIR"
mkdir -p "$CHARTS_DIR"

print_success "Results directory created: $RESULTS_DIR"

# Set proper permissions
chown -R $(logname):$(logname) "$RESULTS_DIR" 2>/dev/null || true

################################################################################
# Verify Installation
################################################################################

print_header "VERIFYING INSTALLATION"

# Check commands
REQUIRED_COMMANDS=("nft" "iperf3" "hping3" "python3" "pip3")

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if command -v $cmd &> /dev/null; then
        VERSION=$($cmd --version 2>&1 | head -n1 || echo "installed")
        print_success "$cmd: $VERSION"
    else
        print_error "$cmd not found"
    fi
done

# Check Python packages
echo ""
echo "Python packages:"
for package in "${PYTHON_PACKAGES[@]}"; do
    # Extract base package name (remove extras like [client])
    BASE_PACKAGE=$(echo "$package" | cut -d'[' -f1)

    if python3 -c "import ${BASE_PACKAGE//-/_}" 2>/dev/null; then
        print_success "$BASE_PACKAGE"
    else
        print_error "$BASE_PACKAGE"
    fi
done

# Check optional tools
echo ""
echo "Optional tools:"
if command -v pwru &> /dev/null; then
    print_success "pwru (available for comparison tests)"
else
    print_warning "pwru (not installed - comparison tests will be limited)"
fi

if command -v sockperf &> /dev/null; then
    print_success "sockperf (available for latency tests)"
else
    print_warning "sockperf (not installed - will use ping as fallback)"
fi

################################################################################
# Make Scripts Executable
################################################################################

print_header "SETTING PERMISSIONS"

chmod +x "$TEST_DIR/run_all_scenarios.py"
chmod +x "$TEST_DIR/scenarios/scenario_1_drop_detection.py"
chmod +x "$TEST_DIR/scenarios/scenario_2_performance_impact.py"
chmod +x "$TEST_DIR/scenarios/scenario_3_realtime_performance.py"

print_success "Test scripts marked as executable"

################################################################################
# Complete
################################################################################

print_header "SETUP COMPLETE"

echo "Environment is ready for testing!"
echo ""
echo "Next steps:"
echo "  1. Start NFT Tracer backend:"
echo "     cd /home/user/nft-tracer-app/backend"
echo "     sudo python3 app.py"
echo ""
echo "  2. Run all test scenarios:"
echo "     cd /home/user/nft-tracer-app/tests"
echo "     sudo python3 run_all_scenarios.py"
echo ""
echo "  3. Or run individual scenarios:"
echo "     sudo python3 scenarios/scenario_1_drop_detection.py"
echo "     sudo python3 scenarios/scenario_2_performance_impact.py"
echo "     sudo python3 scenarios/scenario_3_realtime_performance.py"
echo ""
echo "Results will be saved to: $RESULTS_DIR"
echo ""

exit 0
