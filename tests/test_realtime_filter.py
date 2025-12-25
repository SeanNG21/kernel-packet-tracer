#!/usr/bin/env python3
"""
Test script to demonstrate 5-tuple filtering in realtime sessions

This script creates a filtered realtime session and shows how
filtering works for monitoring specific traffic flows.
"""

import requests
import time
import json
from typing import Dict, Any

# Configuration
API_BASE = "http://localhost:5000/api"
USERNAME = "root"
PASSWORD = "123456"

def login() -> str:
    """Login and get access token"""
    response = requests.post(
        f"{API_BASE}/auth/login",
        json={"username": USERNAME, "password": PASSWORD}
    )

    if response.status_code == 200:
        data = response.json()
        print(f"✓ Login successful")
        return data['access_token']
    else:
        raise Exception(f"Login failed: {response.status_code}")

def create_filtered_session(token: str, session_id: str, trace_filter: Dict[str, str]) -> Dict[str, Any]:
    """Create a realtime session with 5-tuple filter"""
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "session_id": session_id,
        "mode": "full",
        "trace_filter": trace_filter
    }

    response = requests.post(
        f"{API_BASE}/sessions",
        json=payload,
        headers=headers
    )

    if response.status_code in [200, 201]:
        print(f"✓ Session created with filter: {trace_filter}")
        return response.json()
    else:
        raise Exception(f"Failed to create session: {response.status_code} - {response.text}")

def get_session_stats(token: str, session_id: str) -> Dict[str, Any]:
    """Get session statistics"""
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(
        f"{API_BASE}/sessions/{session_id}/stats",
        headers=headers
    )

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to get stats: {response.status_code}")

def stop_session(token: str, session_id: str):
    """Stop the session"""
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.delete(
        f"{API_BASE}/sessions/{session_id}",
        headers=headers
    )

    if response.status_code == 200:
        print(f"✓ Session stopped")
    else:
        print(f"⚠ Failed to stop session: {response.status_code}")

def main():
    print("\n" + "=" * 70)
    print("5-TUPLE FILTERING TEST - Realtime Session")
    print("=" * 70)

    # Login
    print("\n[1/4] Authenticating...")
    token = login()

    # Test Case 1: Filter by destination port (SSH traffic)
    print("\n[2/4] Creating filtered session - SSH traffic only (port 22)...")
    session_id_1 = f"filtered_ssh_{int(time.time())}"

    filter_ssh = {
        "dst_port": "22",  # Only SSH
        "src_ip": "",      # From any IP
        "dst_ip": "",
        "src_port": "",
        "comm": ""
    }

    try:
        create_filtered_session(token, session_id_1, filter_ssh)

        # Wait for some traffic
        print("\n  ↳ Monitoring for 10 seconds...")
        print("  ↳ Tip: Generate SSH traffic with: ssh user@host")
        time.sleep(10)

        # Get stats
        stats = get_session_stats(token, session_id_1)
        print(f"\n  📊 Session Stats:")
        print(f"     Total events processed: {stats.get('total_events', 0)}")
        print(f"     Events filtered out: {stats.get('filtered_events', 0)}")
        print(f"     Total packets traced: {stats.get('total_packets', 0)}")
        print(f"     Filter active: {stats.get('filter_enabled', False)}")

        if stats.get('trace_filter'):
            print(f"\n  🔍 Active Filter:")
            for key, value in stats['trace_filter'].items():
                if value:
                    print(f"     {key}: {value}")

        # Stop session
        stop_session(token, session_id_1)

    except Exception as e:
        print(f"\n  ✗ Error: {e}")

    # Test Case 2: Filter by source IP and destination port
    print("\n[3/4] Creating filtered session - Specific client to HTTP...")
    session_id_2 = f"filtered_http_{int(time.time())}"

    filter_http = {
        "src_ip": "10.20.0.2",  # From specific client
        "dst_port": "80",        # To HTTP
        "dst_ip": "",
        "src_port": "",
        "comm": ""
    }

    try:
        create_filtered_session(token, session_id_2, filter_http)

        print("\n  ↳ Monitoring for 10 seconds...")
        print("  ↳ Tip: Generate traffic from 10.20.0.2 to port 80")
        time.sleep(10)

        # Get stats
        stats = get_session_stats(token, session_id_2)
        print(f"\n  📊 Session Stats:")
        print(f"     Total events processed: {stats.get('total_events', 0)}")
        print(f"     Events filtered out: {stats.get('filtered_events', 0)}")
        print(f"     Total packets traced: {stats.get('total_packets', 0)}")

        # Calculate filter efficiency
        total = stats.get('total_events', 0) + stats.get('filtered_events', 0)
        if total > 0:
            efficiency = (stats.get('filtered_events', 0) / total) * 100
            print(f"     Filter efficiency: {efficiency:.1f}% events filtered")

        # Stop session
        stop_session(token, session_id_2)

    except Exception as e:
        print(f"\n  ✗ Error: {e}")

    print("\n[4/4] Test completed!")
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
The 5-tuple filter allows you to focus on specific traffic flows:

Filter Fields:
  • src_ip    - Source IP address
  • dst_ip    - Destination IP address
  • src_port  - Source port number
  • dst_port  - Destination port number
  • comm      - Process/command name

Benefits:
  ✓ Reduce noise in high-traffic environments
  ✓ Focus on specific client/server communication
  ✓ Monitor individual application traffic
  ✓ Debug specific network flows
  ✓ Save resources by filtering unnecessary events

Usage:
  - Leave fields empty to ignore them
  - Specify multiple fields for more precise filtering
  - All specified fields must match (AND logic)
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")
    except Exception as e:
        print(f"\n\n✗ Error: {e}")
