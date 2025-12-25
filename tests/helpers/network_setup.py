#!/usr/bin/env python3
"""
Network setup helpers for testing scenarios with IP spoofing and martian packets.

This module provides functions to configure network namespaces for testing
scenarios that require IP spoofing (hping3 --rand-source) and martian packets.
"""

import subprocess
from typing import List


def configure_sysctl_for_spoofing(namespace: str, interfaces: List[str] = None) -> bool:
    """
    Configure sysctl settings to allow IP spoofing and martian packets.

    This function disables reverse path filtering (rp_filter), enables acceptance
    of local addresses, and disables martian packet logging in the specified
    network namespace.

    Args:
        namespace: Name of the network namespace
        interfaces: List of interface names to configure. If None, configures
                   ['all', 'default', 'lo', 'veth-db', 'veth-att']

    Returns:
        True if configuration successful, False otherwise

    Example:
        >>> configure_sysctl_for_spoofing('dbns')
        True
        >>> configure_sysctl_for_spoofing('attns', interfaces=['all', 'veth-att'])
        True
    """
    if interfaces is None:
        interfaces = ['all', 'default', 'lo', 'veth-db', 'veth-att']

    print(f"  ↳ Configuring sysctl for IP spoofing in namespace: {namespace}")

    try:
        # Disable rp_filter (critical for spoofed packets)
        print("    - Disabling rp_filter...")
        for iface in interfaces:
            subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0"
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Disable martian packet logging
        print("    - Disabling martian packet logging...")
        for iface in interfaces:
            subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "sysctl", "-w", f"net.ipv4.conf.{iface}.log_martians=0"
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Enable accept_local (needed for loopback tests)
        print("    - Enabling accept_local...")
        for iface in interfaces:
            subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "sysctl", "-w", f"net.ipv4.conf.{iface}.accept_local=1"
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Disable ARP filter
        print("    - Disabling ARP filter...")
        for iface in interfaces:
            subprocess.run([
                "sudo", "ip", "netns", "exec", namespace,
                "sysctl", "-w", f"net.ipv4.conf.{iface}.arp_filter=0"
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"  ✓ Sysctl configuration complete for namespace: {namespace}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed to configure sysctl: {e}")
        return False


def verify_sysctl_configuration(namespace: str) -> bool:
    """
    Verify that sysctl settings are correctly configured for spoofing.

    Args:
        namespace: Name of the network namespace

    Returns:
        True if all settings are correct, False otherwise
    """
    print(f"  ↳ Verifying sysctl configuration in namespace: {namespace}")

    try:
        # Check rp_filter
        result = subprocess.run([
            "sudo", "ip", "netns", "exec", namespace,
            "sysctl", "net.ipv4.conf.all.rp_filter"
        ], capture_output=True, text=True, check=True)

        rp_filter = int(result.stdout.split('=')[1].strip())
        if rp_filter != 0:
            print(f"  ✗ rp_filter is {rp_filter}, expected 0")
            return False

        # Check accept_local
        result = subprocess.run([
            "sudo", "ip", "netns", "exec", namespace,
            "sysctl", "net.ipv4.conf.all.accept_local"
        ], capture_output=True, text=True, check=True)

        accept_local = int(result.stdout.split('=')[1].strip())
        if accept_local != 1:
            print(f"  ✗ accept_local is {accept_local}, expected 1")
            return False

        print(f"  ✓ Sysctl configuration verified:")
        print(f"    - rp_filter = 0 (disabled)")
        print(f"    - accept_local = 1 (enabled)")
        return True

    except Exception as e:
        print(f"  ✗ Verification failed: {e}")
        return False


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 network_setup.py <namespace_name>")
        print("Example: python3 network_setup.py dbns")
        sys.exit(1)

    namespace = sys.argv[1]

    # Configure sysctl
    if configure_sysctl_for_spoofing(namespace):
        # Verify configuration
        verify_sysctl_configuration(namespace)
    else:
        print("Failed to configure sysctl")
        sys.exit(1)
