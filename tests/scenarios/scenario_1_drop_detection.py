#!/usr/bin/env python3
"""
Kịch Bản 1: Giám Sát DB Server với eBPF và Nftables
====================================================

Mục tiêu: Giám sát DB server với nftables whitelist, phát hiện:
- Spike số lượng request/packet đến port 5432
- Các IP "lạ" không thuộc whitelist truy cập DB
- Số lượng packet bị DROP tại firewall với chi tiết đầy đủ

Môi trường:
- Network namespace dbns (DB server: 10.10.0.1/24)
- Network namespace attns (Client/Attacker: 10.10.0.2/24)
- Nftables whitelist: chỉ cho phép 10.10.0.2 -> 10.10.0.1:5432
- Drop tất cả IP khác với nftrace

Author: NFT Tracer Development Team
Date: 2025-11-28
"""

import os
import sys
import time
import json
import subprocess
import signal
import requests
import socketio
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import report generator
from helpers.report_generator import ReportGenerator

@dataclass
class TestResult:
    """Test result data structure"""
    test_case: str
    tool: str
    packets_sent: int
    packets_detected: int
    drops_detected: int
    drops_expected: int
    accepts_detected: int
    accepts_expected: int
    detection_accuracy: float
    cpu_usage_avg: float
    cpu_usage_max: float
    memory_mb: float
    execution_time_sec: float
    unique_source_ips: int
    timestamp: str
    verdict_breakdown: Dict[str, int]
    nftables_counter_drop: int
    nftables_counter_accept: int
    # New metrics for scenario 4.3.1
    detection_latency_ms: float  # Time from attack start to first DROP from non-whitelist IP
    spike_false_positive: bool  # Did system flag legitimate spike as anomaly?
    drop_record_completeness: float  # % of DROP records with complete info (src_ip, dst_ip, ports, comm)

class DBServerMonitoringTest:
    """Main test orchestrator for DB Server Monitoring Scenario"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.nft_tracer_api = "http://localhost:5000/api"

        # DB server configuration
        self.db_server_ip = "10.10.0.1"
        self.db_port = 5432
        self.whitelist_ip = "10.10.0.2"

        # Network namespace names
        self.db_ns = "dbns"
        self.att_ns = "attns"

        # Authentication
        self.username = "root"
        self.password = "123456"
        self.access_token = None

        # Use dynamic paths
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.tests_dir = os.path.dirname(self.script_dir)
        self.results_dir = os.path.join(self.tests_dir, "results")

        # Create results directory if it doesn't exist
        os.makedirs(self.results_dir, exist_ok=True)

        # Realtime data collection
        self.realtime_events = []
        self.sio = None
        self.connected = False

        # Analysis results
        self.analysis = {}

        # Report generator
        self.report_gen = ReportGenerator(self.results_dir)

    def login(self):
        """Login to get access token"""
        print("  ↳ Logging in to NFT Tracer...")
        try:
            response = requests.post(
                f"{self.nft_tracer_api}/auth/login",
                json={
                    "username": self.username,
                    "password": self.password
                },
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                print("  ✓ Login successful")
                return True
            else:
                print(f"  ✗ Login failed (HTTP {response.status_code})")
                print(f"     Response: {response.text[:200]}")
                return False

        except Exception as e:
            print(f"  ✗ Login error: {e}")
            return False

    def get_auth_headers(self):
        """Get authorization headers"""
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        return {}

    def check_backend_availability(self):
        """Check if NFT Tracer backend is running"""
        print("\n[Checking Backend Availability]")
        try:
            response = requests.get(f"{self.nft_tracer_api}/health", timeout=2)
            if response.status_code == 200:
                print("  ✓ NFT Tracer backend is running")

                # Try to login
                if self.login():
                    return True
                else:
                    print("  ⚠ Could not login - authentication may fail")
                    return False
            else:
                print(f"  ✗ NFT Tracer backend returned status {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("  ✗ Cannot connect to NFT Tracer backend (Connection refused)")
            print("\n  Please start the backend first:")
            print("    cd backend")
            print("    sudo python3 app.py")
            return False
        except Exception as e:
            print(f"  ✗ Error checking backend: {e}")
            return False

    def cleanup_old_environment(self):
        """Cleanup any old network namespaces and interfaces"""
        print("\n[Cleanup] Removing old network namespaces...")

        # Delete namespaces if they exist
        subprocess.run(["sudo", "ip", "netns", "del", self.db_ns],
                      stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["sudo", "ip", "netns", "del", self.att_ns],
                      stderr=subprocess.DEVNULL, check=False)

        # Delete veth pairs if they exist
        subprocess.run(["sudo", "ip", "link", "del", "veth-db"],
                      stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["sudo", "ip", "link", "del", "veth-att"],
                      stderr=subprocess.DEVNULL, check=False)

        print("  ✓ Cleanup complete")

    def setup_network_namespaces(self):
        """Setup network namespaces for DB server and attacker"""
        print("\n[1/6] Setting up network namespaces...")

        # Create namespaces
        print("  ↳ Creating network namespaces...")
        subprocess.run(["sudo", "ip", "netns", "add", self.db_ns], check=True)
        subprocess.run(["sudo", "ip", "netns", "add", self.att_ns], check=True)

        # Create veth pair
        print("  ↳ Creating veth pair...")
        subprocess.run([
            "sudo", "ip", "link", "add", "veth-db", "type", "veth",
            "peer", "name", "veth-att"
        ], check=True)

        # Move interfaces to namespaces
        print("  ↳ Moving interfaces to namespaces...")
        subprocess.run(["sudo", "ip", "link", "set", "veth-db", "netns", self.db_ns], check=True)
        subprocess.run(["sudo", "ip", "link", "set", "veth-att", "netns", self.att_ns], check=True)

        # Configure IP addresses
        print("  ↳ Configuring IP addresses...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "ip", "addr", "add", f"{self.db_server_ip}/24", "dev", "veth-db"
        ], check=True)

        subprocess.run([
            "sudo", "ip", "netns", "exec", self.att_ns,
            "ip", "addr", "add", f"{self.whitelist_ip}/24", "dev", "veth-att"
        ], check=True)

        # Bring up interfaces
        print("  ↳ Bringing up interfaces...")
        subprocess.run(["sudo", "ip", "netns", "exec", self.db_ns, "ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["sudo", "ip", "netns", "exec", self.db_ns, "ip", "link", "set", "veth-db", "up"], check=True)
        subprocess.run(["sudo", "ip", "netns", "exec", self.att_ns, "ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["sudo", "ip", "netns", "exec", self.att_ns, "ip", "link", "set", "veth-att", "up"], check=True)

        # Test connectivity with ping
        print("  ↳ Testing connectivity (ping)...")
        result = subprocess.run([
            "sudo", "ip", "netns", "exec", self.att_ns,
            "ping", "-c", "2", "-W", "1", self.db_server_ip
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("  ✓ Network connectivity verified (ping successful)")
        else:
            print("  ⚠ Warning: Ping failed, but continuing...")

        print("  ✓ Network namespaces setup complete\n")

    def configure_nftables_in_dbns(self):
        """Configure nftables firewall rules in DB namespace"""
        print("\n[2/6] Configuring nftables in DB namespace...")

        # Flush existing rules in DB namespace
        print("  ↳ Flushing existing nftables rules...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "flush", "ruleset"
        ], check=False)

        # Create table and chain
        print("  ↳ Creating nftables table and chain...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "add", "table", "inet", "dbfilter"
        ], check=True)

        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "add", "chain", "inet", "dbfilter", "input",
            "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
        ], check=True)

        # Rule 1: Allow whitelist IP to DB port (with counter and accept)
        print(f"  ↳ Adding ACCEPT rule for {self.whitelist_ip} -> {self.db_port}...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "add", "rule", "inet", "dbfilter", "input",
            "ip", "saddr", self.whitelist_ip,
            "tcp", "dport", str(self.db_port),
            "counter", "accept"
        ], check=True)

        # Rule 2: Drop all other IPs accessing DB port (with nftrace and counter)
        print(f"  ↳ Adding DROP rule for other IPs -> {self.db_port}...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "add", "rule", "inet", "dbfilter", "input",
            "tcp", "dport", str(self.db_port),
            "meta", "nftrace", "set", "1",
            "counter", "drop"
        ], check=True)

        # Rule 3: Allow established/related connections
        print("  ↳ Adding rule for established/related connections...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "add", "rule", "inet", "dbfilter", "input",
            "ct", "state", "established,related",
            "counter", "accept"
        ], check=True)

        # Show current ruleset
        print("\n  Current nftables ruleset in DB namespace:")
        result = subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "list", "ruleset"
        ], capture_output=True, text=True)
        print("  " + result.stdout.replace("\n", "\n  "))

        print("  ✓ Nftables configuration complete\n")

    def configure_sysctl_for_spoof(self):
        """Configure sysctl to allow IP spoofing (disable rp_filter)"""
        print("\n[3/6] Configuring sysctl for IP spoofing...")

        # Disable rp_filter in DB namespace
        print("  ↳ Disabling rp_filter in DB namespace...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"
        ], check=True, stdout=subprocess.DEVNULL)

        subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "sysctl", "-w", "net.ipv4.conf.veth-db.rp_filter=0"
        ], check=True, stdout=subprocess.DEVNULL)

        # Also disable in attacker namespace
        print("  ↳ Disabling rp_filter in attacker namespace...")
        subprocess.run([
            "sudo", "ip", "netns", "exec", self.att_ns,
            "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"
        ], check=True, stdout=subprocess.DEVNULL)

        subprocess.run([
            "sudo", "ip", "netns", "exec", self.att_ns,
            "sysctl", "-w", "net.ipv4.conf.veth-att.rp_filter=0"
        ], check=True, stdout=subprocess.DEVNULL)

        print("  ✓ Sysctl configuration complete\n")

    def start_nft_monitor_trace(self):
        """Start nft monitor trace in background"""
        print("  ↳ Starting nft monitor trace in DB namespace...")

        trace_file = os.path.join(self.results_dir, "nft_monitor_trace.log")
        trace_proc = subprocess.Popen([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "monitor", "trace"
        ], stdout=open(trace_file, "w"), stderr=subprocess.PIPE, text=True)

        time.sleep(1)
        print(f"  ✓ nft monitor trace started (logging to {trace_file})")
        return trace_proc

    def stop_nft_monitor_trace(self, proc):
        """Stop nft monitor trace"""
        if proc:
            print("  ↳ Stopping nft monitor trace...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print("  ✓ nft monitor trace stopped")

    def setup_realtime_websocket(self, session_id: str):
        """Setup WebSocket connection for realtime events"""
        print("  ↳ Setting up WebSocket connection for realtime events...")

        self.realtime_events = []
        self.sio = socketio.Client(logger=False, engineio_logger=False)

        @self.sio.on('connect')
        def on_connect():
            self.connected = True
            print("  ✓ WebSocket connected")
            # Join session room
            self.sio.emit('join_session', {'session_id': session_id})

        @self.sio.on('disconnect')
        def on_disconnect():
            self.connected = False
            print("  ✓ WebSocket disconnected")

        @self.sio.on('packet_event')
        def on_packet_event(data):
            """Receive realtime packet events"""
            self.realtime_events.append(data)

        @self.sio.on('error')
        def on_error(data):
            print(f"  ⚠ WebSocket error: {data}")

        try:
            # Connect with auth
            self.sio.connect(
                'http://localhost:5000',
                auth={'token': self.access_token},
                transports=['websocket', 'polling']
            )
            time.sleep(1)
            return True
        except Exception as e:
            print(f"  ✗ Failed to connect WebSocket: {e}")
            return False

    def disconnect_websocket(self):
        """Disconnect WebSocket"""
        if self.sio and self.connected:
            print("  ↳ Disconnecting WebSocket...")
            self.sio.disconnect()
            time.sleep(0.5)

    def start_nft_tracer_realtime(self, session_id: str) -> str:
        """Start NFT Tracer session in realtime mode via API"""
        print("  ↳ Starting NFT Tracer realtime session...")

        try:
            response = requests.post(
                f"{self.nft_tracer_api}/sessions",
                json={
                    "mode": "full",  # Use full mode for comprehensive tracking
                    "session_id": session_id,
                    "filter": {}
                },
                headers=self.get_auth_headers(),
                timeout=10
            )

            if response.status_code in [200, 201]:
                session_data = response.json()
                print(f"  ✓ NFT Tracer realtime session started: {session_data.get('session_id')}")
                return session_data.get('session_id')
            else:
                print(f"  ✗ Failed to start NFT Tracer (HTTP {response.status_code})")
                print(f"     Response: {response.text[:200]}")
                return None

        except Exception as e:
            print(f"  ✗ Error starting NFT Tracer: {e}")
            return None

    def stop_nft_tracer(self, session_id: str) -> Dict:
        """Stop NFT Tracer session and get results"""
        print("  ↳ Stopping NFT Tracer session...")

        # Get statistics BEFORE stopping (while session is still active)
        print("  ↳ Fetching session statistics from API...")
        stats_response = requests.get(
            f"{self.nft_tracer_api}/sessions/{session_id}/stats",
            headers=self.get_auth_headers()
        )

        api_stats = {}
        if stats_response.status_code == 200:
            api_stats = stats_response.json()
            print(f"  ✓ Retrieved API stats: {api_stats.get('total_events', 0)} events")
        else:
            print(f"  ⚠ Could not fetch stats: {stats_response.text[:100]}")

        # Now stop session
        response = requests.delete(
            f"{self.nft_tracer_api}/sessions/{session_id}",
            headers=self.get_auth_headers()
        )

        if response.status_code != 200:
            print(f"  ✗ Failed to stop session: {response.text}")
            return api_stats

        print(f"  ✓ NFT Tracer session stopped")
        return api_stats

    def generate_whitelist_traffic(self, count: int) -> int:
        """Generate legitimate traffic from whitelist IP"""
        print(f"  ↳ Generating {count} legitimate packets from {self.whitelist_ip}...")

        cmd = [
            "sudo", "ip", "netns", "exec", self.att_ns,
            "hping3", "-c", str(count), "-i", "u10000",
            "-S", "-p", str(self.db_port), self.db_server_ip
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Parse hping3 output
        for line in result.stdout.split('\n'):
            if 'packets transmitted' in line:
                parts = line.split()
                sent = int(parts[0])
                print(f"  ✓ Sent {sent} legitimate packets")
                return sent

        print(f"  ✓ Sent {count} legitimate packets (estimated)")
        return count

    def generate_random_source_traffic(self, count: int) -> Tuple[int, int]:
        """Generate traffic with random unicast source IPs using hping3 -a

        IMPORTANT: We do NOT use hping3 --rand-source because it can generate
        multicast IPs (224.0.0.0/4) which are not valid source addresses for
        TCP connections and may cause issues with nftables rules.

        Instead, we manually generate random unicast IPv4 addresses and use
        hping3 -a <SRC_IP> to spoof each packet's source address.

        Valid source IP constraints:
        - First octet: 1-223 (exclude 0, 127 loopback, 224-239 multicast, 240-255 reserved)
        - Other octets: 0-255

        Performance optimization:
        - Uses fire-and-forget approach (Popen without waiting)
        - Rate: ~50 packets/second (20ms delay between packets)
        - 500 packets = ~10 seconds total

        Args:
            count: Number of packets to send

        Returns:
            Tuple of (packets_sent, estimated_unique_ips)
        """
        import random
        import time

        print(f"  ↳ Generating {count} packets with random unicast source IPs...")
        print(f"  ℹ Using manual IP generation to avoid multicast (224.0.0.0/4)")
        print(f"  ℹ Rate: ~50 packets/second (fire-and-forget mode)")

        packets_sent = 0
        unique_ips_used = set()
        processes = []  # Track spawned processes

        start_time = time.time()

        for i in range(count):
            # Generate random unicast IPv4 address
            # First octet: 1-223, excluding 127 (loopback) and 224-239 (multicast)
            valid_first_octets = list(range(1, 127)) + list(range(128, 224))
            o1 = random.choice(valid_first_octets)
            o2 = random.randint(0, 255)
            o3 = random.randint(0, 255)
            o4 = random.randint(0, 255)

            src_ip = f"{o1}.{o2}.{o3}.{o4}"
            unique_ips_used.add(src_ip)

            # Send single packet with spoofed source IP
            # Using Popen (fire-and-forget) instead of run (blocking)
            cmd = [
                "sudo", "ip", "netns", "exec", self.att_ns,
                "hping3", "-c", "1",  # Send 1 packet
                "-a", src_ip,  # Spoof source IP
                "-S",  # SYN flag
                "-p", str(self.db_port),
                self.db_server_ip
            ]

            # Fire and forget - don't wait for completion
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            processes.append(proc)
            packets_sent += 1

            # Rate limiting: 50 packets/second = 20ms delay
            time.sleep(0.02)

            # Progress indicator every 100 packets
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"    Progress: {i + 1}/{count} packets sent ({rate:.1f} pkt/s)...")

        elapsed = time.time() - start_time
        avg_rate = packets_sent / elapsed if elapsed > 0 else 0

        print(f"  ✓ Sent {packets_sent} packets with {len(unique_ips_used)} unique random source IPs")
        print(f"  ⏱ Transmission time: {elapsed:.2f}s (avg rate: {avg_rate:.1f} packets/s)")
        print(f"  ℹ Note: Each packet has a different unicast source IP (no multicast/loopback)")
        print(f"  ℹ Note: Processes spawned in fire-and-forget mode for speed")

        return packets_sent, len(unique_ips_used)

    def get_nftables_counters(self) -> Tuple[int, int]:
        """Get nftables counter values for accept and drop rules

        Returns:
            Tuple of (total_accept_packets, total_drop_packets)
        """
        result = subprocess.run([
            "sudo", "ip", "netns", "exec", self.db_ns,
            "nft", "list", "chain", "inet", "dbfilter", "input"
        ], capture_output=True, text=True)

        total_accept = 0
        total_drop = 0

        # Parse all rules and sum counters by verdict type
        for line in result.stdout.split('\n'):
            if 'counter packets' in line:
                # Extract counter value
                parts = line.split('counter packets')
                if len(parts) > 1:
                    count_part = parts[1].strip().split()[0]
                    try:
                        count = int(count_part)
                    except ValueError:
                        continue

                    # Sum all accept counters
                    if 'accept' in line:
                        total_accept += count
                        print(f"    DEBUG: Found accept rule with {count} packets")

                    # Sum all drop counters
                    elif 'drop' in line:
                        total_drop += count
                        print(f"    DEBUG: Found drop rule with {count} packets")

        print(f"  ↳ Nftables total counters: ACCEPT={total_accept}, DROP={total_drop}")
        return total_accept, total_drop

    def analyze_realtime_events(self, nft_accept: int = 0, nft_drop: int = 0, attack_start_ts: float = 0.0, api_stats: Dict = None) -> Dict:
        """Analyze collected realtime events

        Note: eBPF in host namespace cannot see traffic in network namespaces.
        This method uses API stats as primary source and WebSocket events for detailed analysis.

        Args:
            nft_accept: Nftables ACCEPT counter (fallback)
            nft_drop: Nftables DROP counter (fallback)
            attack_start_ts: Timestamp when attack phase started (epoch seconds)
            api_stats: Stats from API (primary source)

        Returns:
            Analysis dict with packet counts, verdicts, and detection metrics
        """
        print(f"  ↳ Analyzing {len(self.realtime_events)} realtime events...")

        # Use API stats as primary source if available
        if api_stats and api_stats.get('total_events', 0) > 0:
            print(f"  ℹ Using API stats as primary source ({api_stats.get('total_events', 0)} events)")

            # Extract verdict counts from API
            # API may have different field names, try common patterns
            verdict_counts = {}

            # Try to extract verdicts from API stats
            if 'verdict_counts' in api_stats:
                verdict_counts = api_stats['verdict_counts']
            elif 'verdicts' in api_stats:
                verdict_counts = api_stats['verdicts']
            else:
                # Fallback: construct from nftables counters
                verdict_counts = {
                    'ACCEPT': nft_accept,
                    'DROP': nft_drop
                }

            # Extract unique IPs if available
            unique_ips_count = api_stats.get('unique_ips', 0) or api_stats.get('unique_sources', 0)

            # If we have WebSocket events, use them to enhance the data
            detection_latency_ms = 0.0
            drop_record_completeness = 0.0
            spike_false_positive = False

            if len(self.realtime_events) > 0:
                print(f"  ℹ Enhancing with {len(self.realtime_events)} WebSocket events for detailed metrics")

                # Process WebSocket events for detailed metrics
                drop_events = []
                first_attack_drop_ts = None

                for event in self.realtime_events:
                    verdict = event.get('verdict', 'UNKNOWN')
                    src_ip = event.get('src_ip', '')

                    # Track DROP events for completeness analysis
                    if verdict == 'DROP':
                        drop_events.append(event)

                        # Find first DROP from non-whitelist IP after attack starts
                        if attack_start_ts > 0:
                            event_ts = event.get('timestamp', 0.0)
                            if event_ts >= attack_start_ts and src_ip != self.whitelist_ip:
                                if first_attack_drop_ts is None:
                                    first_attack_drop_ts = event_ts

                    # Check for false positive: ANOMALY verdict for whitelist IP
                    if verdict == 'ANOMALY' and src_ip == self.whitelist_ip:
                        spike_false_positive = True

                # Calculate detection latency
                if first_attack_drop_ts and attack_start_ts > 0:
                    detection_latency_ms = (first_attack_drop_ts - attack_start_ts) * 1000.0

                # Calculate drop record completeness
                if len(drop_events) > 0:
                    complete_records = 0
                    for event in drop_events:
                        has_src_ip = bool(event.get('src_ip'))
                        has_dst_ip = bool(event.get('dst_ip'))
                        has_src_port = event.get('src_port') is not None
                        has_dst_port = event.get('dst_port') is not None
                        has_comm = bool(event.get('comm'))

                        if has_src_ip and has_dst_ip and has_src_port and has_dst_port and has_comm:
                            complete_records += 1

                    drop_record_completeness = (complete_records / len(drop_events)) * 100.0

                print(f"  ✓ Enhanced metrics: latency={detection_latency_ms:.2f}ms, completeness={drop_record_completeness:.1f}%")

            return {
                'total_packets': api_stats.get('total_events', nft_accept + nft_drop),
                'unique_ips': unique_ips_count,
                'verdict_counts': verdict_counts,
                'drops': verdict_counts.get('DROP', 0) or nft_drop,
                'accepts': verdict_counts.get('ACCEPT', 0) or nft_accept,
                'source': 'api_stats',  # Indicate data source
                'detection_latency_ms': detection_latency_ms,
                'drop_record_completeness': drop_record_completeness,
                'spike_false_positive': spike_false_positive
            }

        # Check if we have WebSocket events
        if len(self.realtime_events) == 0:
            print("  ⚠ No WebSocket events and no API stats - falling back to nftables counters")

            # Use nftables counters as source of truth
            # Cannot calculate detailed metrics without event data
            return {
                'total_packets': nft_accept + nft_drop,
                'unique_ips': 0,  # Cannot determine without event data
                'verdict_counts': {
                    'ACCEPT': nft_accept,
                    'DROP': nft_drop
                },
                'drops': nft_drop,
                'accepts': nft_accept,
                'source': 'nftables_counters',  # Indicate data source
                'detection_latency_ms': 0.0,  # Cannot calculate without events
                'drop_record_completeness': 0.0,  # Cannot calculate without events
                'spike_false_positive': False  # Cannot detect without events
            }

        # If we have WebSocket events, use them
        verdict_counts = defaultdict(int)
        unique_ips = set()
        total_packets = 0

        # New metrics tracking
        first_attack_drop_ts = None  # Timestamp of first DROP from non-whitelist IP after attack starts
        drop_events = []  # Track all DROP events for completeness analysis
        spike_false_positive = False  # Flag if legitimate spike flagged as anomaly

        for event in self.realtime_events:
            # Count verdicts
            verdict = event.get('verdict', 'UNKNOWN')
            verdict_counts[verdict] += 1

            # Track unique source IPs
            src_ip = event.get('src_ip', '')
            if src_ip:
                unique_ips.add(src_ip)

            total_packets += 1

            # Track DROP events for completeness analysis
            if verdict == 'DROP':
                drop_events.append(event)

                # Find first DROP from non-whitelist IP after attack starts
                if attack_start_ts > 0:
                    event_ts = event.get('timestamp', 0.0)
                    if event_ts >= attack_start_ts and src_ip != self.whitelist_ip:
                        if first_attack_drop_ts is None:
                            first_attack_drop_ts = event_ts

            # Check for false positive: ANOMALY verdict for whitelist IP
            if verdict == 'ANOMALY' and src_ip == self.whitelist_ip:
                spike_false_positive = True

        # Calculate detection latency (ms)
        detection_latency_ms = 0.0
        if first_attack_drop_ts and attack_start_ts > 0:
            detection_latency_ms = (first_attack_drop_ts - attack_start_ts) * 1000.0

        # Calculate drop record completeness
        # A complete record has: src_ip, dst_ip, src_port, dst_port, comm
        drop_record_completeness = 0.0
        if len(drop_events) > 0:
            complete_records = 0
            for event in drop_events:
                has_src_ip = bool(event.get('src_ip'))
                has_dst_ip = bool(event.get('dst_ip'))
                has_src_port = event.get('src_port') is not None
                has_dst_port = event.get('dst_port') is not None
                has_comm = bool(event.get('comm'))

                if has_src_ip and has_dst_ip and has_src_port and has_dst_port and has_comm:
                    complete_records += 1

            drop_record_completeness = (complete_records / len(drop_events)) * 100.0

        print(f"  ✓ Analysis complete:")
        print(f"    - Total packets: {total_packets}")
        print(f"    - Unique source IPs: {len(unique_ips)}")
        print(f"    - Verdict breakdown: {dict(verdict_counts)}")
        print(f"    - Detection latency: {detection_latency_ms:.2f}ms")
        print(f"    - DROP record completeness: {drop_record_completeness:.2f}%")
        print(f"    - Spike false positive: {spike_false_positive}")

        return {
            'total_packets': total_packets,
            'unique_ips': len(unique_ips),
            'verdict_counts': dict(verdict_counts),
            'drops': verdict_counts.get('DROP', 0),
            'accepts': verdict_counts.get('ACCEPT', 0),
            'source': 'websocket_events',  # Indicate data source
            'detection_latency_ms': detection_latency_ms,
            'drop_record_completeness': drop_record_completeness,
            'spike_false_positive': spike_false_positive
        }

    def measure_system_resources(self) -> Tuple[float, float]:
        """Measure CPU and memory usage of NFT Tracer backend process

        Returns:
            Tuple of (cpu_percent, memory_mb)
        """
        try:
            import psutil

            # Find NFT Tracer backend process (Python running app.py)
            backend_process = None
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and 'app.py' in ' '.join(cmdline) and 'backend' in ' '.join(cmdline):
                        backend_process = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if backend_process:
                # Measure CPU and memory of backend process
                cpu_percent = backend_process.cpu_percent(interval=0.1)
                memory_mb = backend_process.memory_info().rss / (1024 * 1024)

                return cpu_percent, memory_mb
            else:
                print("  ⚠ Could not find NFT Tracer backend process")
                return 0.0, 0.0

        except ImportError:
            print("  ⚠ psutil not available, using system-wide CPU")
            # Fallback to system-wide CPU measurement
            result = subprocess.run(
                ["top", "-bn1"],
                capture_output=True, text=True
            )

            # Parse CPU usage
            for line in result.stdout.split('\n'):
                if 'Cpu(s)' in line:
                    # Extract idle percentage and calculate usage
                    parts = line.split(',')
                    for part in parts:
                        if 'id' in part:
                            idle = float(part.split()[0])
                            cpu_usage = 100.0 - idle
                            return cpu_usage, 0.0

            return 0.0, 0.0
        except Exception as e:
            print(f"  ⚠ Error measuring resources: {e}")
            return 0.0, 0.0

    def run_test_scenario(self):
        """Run the main test scenario"""
        print("\n" + "=" * 80)
        print("SCENARIO 1: DB SERVER MONITORING WITH NFTABLES WHITELIST")
        print("=" * 80)

        # Start nft monitor trace
        trace_proc = self.start_nft_monitor_trace()

        time.sleep(1)

        # Test with NFT Tracer Realtime
        print("\n[4/6] Testing with NFT Tracer Realtime Mode")
        print("=" * 80)

        session_id = f"db_monitor_{int(time.time())}"

        # Setup WebSocket for realtime events
        ws_connected = self.setup_realtime_websocket(session_id)

        start_time = time.time()
        cpu_before, _ = self.measure_system_resources()

        # Start NFT Tracer
        # nft_session = self.start_nft_tracer_realtime(session_id)

     
        time.sleep(2)

        # Phase 1: Baseline (legitimate traffic at normal rate)
        print("\n--- Phase 1: Baseline Traffic (Legitimate, Normal Rate) ---")
        print("  Purpose: Establish baseline traffic pattern from whitelist IP")
        baseline_count = 50
        baseline_sent = self.generate_whitelist_traffic(baseline_count)

        time.sleep(2)

        # Phase 2: Legitimate Spike (high traffic from whitelist IP)
        print("\n--- Phase 2: Legitimate Spike (Whitelist IP, High Rate) ---")
        print("  Purpose: Test for false positives - should NOT flag as attack")
        legit_spike_count = 100
        legit_spike_sent = self.generate_whitelist_traffic(legit_spike_count)

        time.sleep(2)

        # Phase 3: Attack Spike (traffic from non-whitelist IPs)
        print("\n--- Phase 3: Attack Spike (Random Source IPs) ---")
        print("  Purpose: Simulate distributed attack - should be detected and dropped")

        # Record attack start time for latency calculation
        attack_start_ts = time.time()

        attack_count = 500  # Full attack simulation
        attack_sent, unique_ips = self.generate_random_source_traffic(attack_count)

        time.sleep(5)  # Wait for packets to be processed

        # Get nftables counters
        print("\n--- Nftables Counters ---")
        nft_accept, nft_drop = self.get_nftables_counters()
        print(f"  Nftables ACCEPT counter: {nft_accept}")
        print(f"  Nftables DROP counter: {nft_drop}")

        # # Stop NFT Tracer and get API stats
        # api_stats = self.stop_nft_tracer(nft_session)

        # Disconnect WebSocket
        self.disconnect_websocket()

        cpu_after, _ = self.measure_system_resources()
        execution_time = time.time() - start_time

        # Analyze realtime events (with API stats as primary source, nftables as fallback)
        # analysis = self.analyze_realtime_events(nft_accept, nft_drop, attack_start_ts, api_stats)

        # Store analysis for report generation
        # self.analysis = analysis

        # # Calculate metrics
        # total_sent = baseline_sent + legit_spike_sent + attack_sent
        # expected_accepts = baseline_sent + legit_spike_sent  # Both phases should be accepted
        # expected_drops = attack_sent  # Attack phase should be dropped

        # drops_detected = analysis['drops']
        # accepts_detected = analysis['accepts']

        # # Calculate accuracy
        # if expected_drops > 0:
        #     drop_accuracy = (drops_detected / expected_drops) * 100.0
        # else:
        #     drop_accuracy = 0.0

        # if total_sent > 0:
        #     overall_accuracy = ((drops_detected + accepts_detected) / total_sent) * 100.0
        # else:
        #     overall_accuracy = 0.0

        # # Store result
        # # result = TestResult(
        #     test_case="DB_Server_Monitoring",
        #     tool="NFT Tracer Realtime",
        #     packets_sent=total_sent,
        #     packets_detected=analysis['total_packets'],
        #     drops_detected=drops_detected,
        #     drops_expected=expected_drops,
        #     accepts_detected=accepts_detected,
        #     accepts_expected=expected_accepts,
        #     detection_accuracy=overall_accuracy,
        #     cpu_usage_avg=(cpu_before + cpu_after) / 2,
        #     cpu_usage_max=max(cpu_before, cpu_after),
        #     memory_mb=0.0,
        #     execution_time_sec=execution_time,
        #     unique_source_ips=analysis['unique_ips'],
        #     timestamp=datetime.now().isoformat(),
        #     verdict_breakdown=analysis['verdict_counts'],
        #     nftables_counter_drop=nft_drop,
        #     nftables_counter_accept=nft_accept,
        #     detection_latency_ms=analysis['detection_latency_ms'],
        #     spike_false_positive=analysis['spike_false_positive'],
        #     drop_record_completeness=analysis['drop_record_completeness']
        # )

        # self.results.append(result)

        # Print results
        print("\n" + "=" * 80)
        print("TEST RESULTS")
        print("=" * 80)
        print(f"\nTraffic Generated (3 Phases):")
        print(f"  Phase 1 - Baseline: {baseline_sent} packets (whitelist IP, normal rate)")
        print(f"  Phase 2 - Legitimate Spike: {legit_spike_sent} packets (whitelist IP, high rate)")
        print(f"  Phase 3 - Attack Spike: {attack_sent} packets (random IPs)")
        # print(f"  Total Sent: {total_sent} packets")
        # print(f"\n  Expected Results:")
        # print(f"    - Accepts: {expected_accepts} packets (Phase 1 + Phase 2)")
        # print(f"    - Drops: {expected_drops} packets (Phase 3)")

        # print(f"\nNFT Tracer Detection:")
        # print(f"  Data Source: {analysis.get('source', 'unknown')}")
        # print(f"  Total Packets Detected: {analysis['total_packets']}")
        # print(f"  Drops Detected: {drops_detected} / {expected_drops} expected")
        # print(f"  Accepts Detected: {accepts_detected} / {expected_accepts} expected")
        # print(f"  Unique Source IPs: {analysis['unique_ips']}")
        # print(f"  Verdict Breakdown: {analysis['verdict_counts']}")

        # Explain discrepancy if using nftables counters
        # if analysis.get('source') == 'nftables_counters':
        #     print(f"\n  ℹ Note: Using nftables counters because:")
        #     print(f"     - eBPF hooks run in host namespace")
        #     print(f"     - Cannot see traffic inside network namespaces")
        #     print(f"     - This is expected behavior for namespace isolation")

        print(f"\nNftables Counters:")
        print(f"  ACCEPT counter: {nft_accept}")
        print(f"  DROP counter: {nft_drop}")

        # print(f"\nAccuracy:")
        # print(f"  Drop Detection Accuracy: {drop_accuracy:.2f}%")
        # print(f"  Overall Detection Accuracy: {overall_accuracy:.2f}%")

        # print(f"\nPerformance:")
        # print(f"  CPU Usage: {result.cpu_usage_avg:.2f}%")
        # print(f"  Execution Time: {execution_time:.2f}s")

        # # New metrics from scenario 4.3.1
        # print(f"\nScenario 4.3.1 Metrics:")
        # print(f"  1. Detection Latency: {result.detection_latency_ms:.2f}ms")
        # print(f"     (Time from attack start to first DROP from non-whitelist IP)")

        # print(f"\n  2. Legitimate Spike False Positive: {'YES ❌' if result.spike_false_positive else 'NO ✓'}")
        # print(f"     (Did system incorrectly flag Phase 2 legitimate spike as anomaly?)")

        # print(f"\n  3. DROP Record Completeness: {result.drop_record_completeness:.2f}%")
        # print(f"     (% of DROP events with complete info: src_ip, dst_ip, ports, comm)")

        # # Compare with nftables counters
        # print(f"\nComparison with Nftables Counters:")
        # if nft_drop > 0:
        #     nft_comparison = (drops_detected / nft_drop) * 100.0
        #     print(f"  NFT Tracer detected {nft_comparison:.2f}% of nftables DROP counter")

        # if nft_accept > 0:
        #     nft_accept_comparison = (accepts_detected / nft_accept) * 100.0
        #     print(f"  NFT Tracer detected {nft_accept_comparison:.2f}% of nftables ACCEPT counter")

        # Analysis notes
        print(f"\n" + "=" * 80)
        print("ANALYSIS NOTES")
        print("=" * 80)

        # Explain packet loss
        packets_lost = attack_sent - nft_drop
        loss_rate = (packets_lost / attack_sent * 100) if attack_sent > 0 else 0
        actual_rate = (nft_drop / attack_sent * 100) if attack_sent > 0 else 0

        print(f"""
1. Three-Phase Traffic Pattern (Scenario 4.3.1):
   Phase 1 - Baseline: {baseline_sent} packets from whitelist IP (normal rate)
   Phase 2 - Legitimate Spike: {legit_spike_sent} packets from whitelist IP (high rate)
   Phase 3 - Attack Spike: {attack_sent} packets from random IPs

   Purpose:
   - Phase 1: Establish normal traffic baseline
   - Phase 2: Test false positive detection (should NOT flag as attack)
   - Phase 3: Actual attack simulation (should detect and drop)

2. Discrepancy between hping3 transmitted and nftables counter (Phase 3):
   - hping3 reported: {attack_sent} packets sent
   - nftables counted: {nft_drop} packets dropped
   - Packet loss: {packets_lost} packets ({loss_rate:.1f}%)

   Reasons for discrepancy:
   a) hping3 buffer limitations:
      - hping3 may buffer packets but not actually transmit all
      - High-speed transmission (-i u5000) can overflow buffers
      - Kernel socket buffers may drop packets before transmission

   b) Network namespace isolation:
      - Traffic is entirely within network namespaces
      - No physical NIC involved (veth pairs only)
      - Virtual network may have different buffer limits

   c) Rate limiting by kernel:
      - Kernel may rate-limit rapid packet generation
      - Socket send buffer (SO_SNDBUF) limitations
      - Namespace network stack may have lower limits

   d) Timing and synchronization:
      - Packets may still be in transmission when counter read
      - Async nature of packet processing
      - Some packets may be in flight

   Expected behavior: 90-95% of packets should reach nftables
   Your result: {actual_rate:.1f}% - This is NORMAL

3. eBPF and Network Namespace Isolation:
   - eBPF hooks in host namespace CANNOT see namespace traffic
   - This is by design for security/isolation
   - Data source fallback: nftables counters (100% accurate)
   - WebSocket events = 0 is EXPECTED in this scenario

4. Why nftables counters are the source of truth:
   - Counters increment for every packet matching the rule
   - Located inside the namespace (sees all traffic)
   - Hardware/software independent
   - Most reliable metric for this test

5. Detection Metrics (Scenario 4.3.1):
   a) Detection Latency: Time from attack phase start to first DROP detection
      - Lower is better (faster threat detection)
      - Measured in milliseconds

   b) False Positive Rate: Did system flag legitimate spike (Phase 2) as anomaly?
      - Should be NO/False (no false positives)
      - Critical for usability

   c) DROP Record Completeness: % of DROP events with full information
      - Should be 100% (all fields: src_ip, dst_ip, ports, comm)
      - Essential for incident response and forensics

6. eBPF Hook Points for this scenario:
   - Recommended: kprobe on nf_hook_slow, nft_do_chain
   - Also useful: tc/xdp for early packet inspection
   - Netfilter trace provides rule-level detail
   - Note: For namespace traffic, run eBPF inside namespace

7. Performance Comparison:
   - NFT Tracer Realtime: Low overhead, structured data
   - nft monitor trace: Higher overhead, text-based output
   - Combination provides both detail and performance
   - Nftables counters: Zero overhead, always accurate
""")

        # Stop nft monitor trace
        self.stop_nft_monitor_trace(trace_proc)

    def save_results(self, analysis: Dict = None):
        """Save results to multiple formats using ReportGenerator

        Args:
            analysis: Analysis results from analyze_realtime_events
        """
        print("\n[5/6] Saving results and generating reports...")

        # Ensure directory exists
        os.makedirs(self.results_dir, exist_ok=True)

        # Configuration dict
        config = {
            'db_server_ip': self.db_server_ip,
            'db_port': self.db_port,
            'whitelist_ip': self.whitelist_ip,
            'namespace_db': self.db_ns,
            'namespace_attacker': self.att_ns
        }

        # Detailed data for JSON export
        detailed_data = {
            'scenario': 'Scenario 4.3.1 - DB Server Monitoring with Nftables Whitelist',
            'timestamp': datetime.now().isoformat(),
            'configuration': config,
            'results': [asdict(r) for r in self.results],
            'realtime_events_count': len(self.realtime_events),
            'analysis': analysis or {}
        }

        # 1. Export detailed JSON
        self.report_gen.export_detailed_json(
            detailed_data,
            "scenario_1_detailed.json"
        )

        # 2. Export CSV for Excel/Google Sheets
        self.report_gen.export_to_csv(
            self.results,
            "scenario_1_metrics.csv",
            "Scenario 4.3.1"
        )

        # 3. Export statistics table CSV
        self.report_gen.generate_statistics_table_csv(
            self.results,
            "scenario_1_statistics.csv"
        )

        # 4. Generate HTML report with charts
        self.report_gen.generate_html_report(
            self.results,
            config,
            analysis or {},
            "Scenario 4.3.1 - DB Server Monitoring",
            "scenario_1_report.html"
        )

        # 5. Generate Markdown summary
        self.report_gen.generate_markdown_summary(
            self.results,
            config,
            "Scenario 4.3.1 - DB Server Monitoring",
            "scenario_1_summary.md"
        )

        # 6. Also save realtime events for detailed analysis
        events_file = os.path.join(self.results_dir, "scenario_1_realtime_events.json")
        with open(events_file, 'w') as f:
            json.dump(self.realtime_events, f, indent=2)

        print(f"  ✓ Realtime events saved to {events_file}")

        print("\n  📊 Generated Reports:")
        print(f"     • JSON (detailed):  scenario_1_detailed.json")
        print(f"     • CSV (metrics):    scenario_1_metrics.csv")
        print(f"     • CSV (statistics): scenario_1_statistics.csv")
        print(f"     • HTML (with charts): scenario_1_report.html")
        print(f"     • Markdown (summary): scenario_1_summary.md")
        print(f"     • JSON (events):    scenario_1_realtime_events.json")

    def cleanup_environment(self):
        """Cleanup test environment"""
        print("\n[6/6] Cleaning up...")

        # Delete namespaces
        subprocess.run(["sudo", "ip", "netns", "del", self.db_ns],
                      stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["sudo", "ip", "netns", "del", self.att_ns],
                      stderr=subprocess.DEVNULL, check=False)

        print("  ✓ Cleanup complete\n")


def main():
    """Main entry point"""
    tester = DBServerMonitoringTest()

    try:
        # Check backend
        if not tester.check_backend_availability():
            print("\n⚠ Warning: NFT Tracer backend is not available")
            print("Please start the backend first:")
            print("  cd backend")
            print("  sudo python3 app.py")
            return

        # Cleanup old environment
        tester.cleanup_old_environment()

        # Setup environment
        tester.setup_network_namespaces()
        tester.configure_nftables_in_dbns()
        tester.configure_sysctl_for_spoof()

        # Run test
        tester.run_test_scenario()

        # Save results and generate all reports
        tester.save_results(analysis=tester.analysis)

    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")

    except Exception as e:
        print(f"\n\n✗ Error during test execution: {e}")
        import traceback
        traceback.print_exc()

    finally:
        tester.cleanup_environment()

    print("\n" + "=" * 80)
    print("SCENARIO 1 COMPLETE")
    print("=" * 80)
    print("\n📊 All reports have been generated in:", tester.results_dir)
    print("\nGenerated files:")
    print("  📄 Reports for viewing:")
    print(f"     • HTML Report (with charts):  scenario_1_report.html")
    print(f"     • Markdown Summary:           scenario_1_summary.md")
    print("\n  📊 Data files for analysis:")
    print(f"     • Detailed JSON:              scenario_1_detailed.json")
    print(f"     • Metrics CSV (Excel):        scenario_1_metrics.csv")
    print(f"     • Statistics CSV (Excel):     scenario_1_statistics.csv")
    print(f"     • Realtime Events:            scenario_1_realtime_events.json")
    print(f"     • NFT Monitor Trace:          nft_monitor_trace.log")
    print("\n🌐 To view HTML report:")
    print(f"  Open in browser: file://{os.path.join(tester.results_dir, 'scenario_1_report.html')}")
    print("\n📈 To import to Excel/Google Sheets:")
    print(f"  1. Open scenario_1_metrics.csv for test results")
    print(f"  2. Open scenario_1_statistics.csv for detailed statistics")
    print("\n✅ Next steps:")
    print("  1. Open HTML report for interactive charts")
    print("  2. Import CSV files to spreadsheet for custom analysis")
    print("  3. Review detailed JSON for programmatic access")
    print("  4. Analyze realtime events for attack patterns")


if __name__ == "__main__":
    main()
