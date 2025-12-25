#!/bin/bash
# Helper script to configure sysctl for IP spoofing and martian packet testing
# This script disables rp_filter and allows martian packets in network namespaces
#
# Usage:
#   sudo ./configure_sysctl_for_spoofing.sh <namespace_name>
#
# Example:
#   sudo ./configure_sysctl_for_spoofing.sh dbns

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Error: Namespace name required"
    echo "Usage: $0 <namespace_name>"
    exit 1
fi

NAMESPACE=$1

echo "[*] Configuring sysctl for IP spoofing in namespace: $NAMESPACE"

# Disable rp_filter for ALL interfaces (critical for spoofed packets)
echo "  ↳ Disabling rp_filter..."
for iface in all default lo veth-db veth-att; do
    ip netns exec $NAMESPACE sysctl -w net.ipv4.conf.${iface}.rp_filter=0 2>/dev/null || true
done

# Disable martian packet logging (reduces noise)
echo "  ↳ Disabling martian packet logging..."
for iface in all default lo veth-db veth-att; do
    ip netns exec $NAMESPACE sysctl -w net.ipv4.conf.${iface}.log_martians=0 2>/dev/null || true
done

# Accept local source addresses (needed for some loopback tests)
echo "  ↳ Enabling accept_local..."
for iface in all default lo veth-db veth-att; do
    ip netns exec $NAMESPACE sysctl -w net.ipv4.conf.${iface}.accept_local=1 2>/dev/null || true
done

# Disable source validation (allows packets with any source IP)
echo "  ↳ Disabling source validation..."
for iface in all default lo veth-db veth-att; do
    ip netns exec $NAMESPACE sysctl -w net.ipv4.conf.${iface}.arp_filter=0 2>/dev/null || true
done

echo "  ✓ Sysctl configuration complete for namespace: $NAMESPACE"
echo ""
echo "Current settings:"
ip netns exec $NAMESPACE sysctl net.ipv4.conf.all.rp_filter
ip netns exec $NAMESPACE sysctl net.ipv4.conf.all.log_martians
ip netns exec $NAMESPACE sysctl net.ipv4.conf.all.accept_local
