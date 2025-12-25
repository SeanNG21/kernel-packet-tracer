#!/usr/bin/env python3
"""
Kịch bản rút gọn: 2 pha tấn công, đều DROP tại TCP (không có app lắng nghe)

Pha 2:
  - 200 packet từ attacker (10.20.0.3) -> edge (10.20.0.1) các port random (1000, 2000)
  - Không có rule đặc biệt cho các port này, policy accept
  - Không có ứng dụng lắng nghe -> DROP tại TCP/UDP (tcp_v4_send_reset)

Pha 3:
  - 100 packet từ attacker (10.20.0.3) -> edge (10.20.0.1) port 9000
  - Có thể có/không có rule netfilter; quan trọng là không có app lắng nghe
  - Cũng DROP tại TCP/UDP (tcp_v4_send_reset)

Cả hai pha đều dùng attacker namespace, inbound, giống nhau về pattern,
chỉ khác dst_port (random vs 9000).
"""

import subprocess


class EdgeFirewallTwoPhaseTCPDropTest:
    def __init__(self):
        self.edge_ip_client_side = "10.20.0.1"
        self.edge_ip_attacker_side = "10.20.0.254"
        self.client_ip = "10.20.0.2"
        self.attacker_ip = "10.20.0.3"

        self.edge_ns = "edge"
        self.client_ns = "client"
        self.attacker_ns = "attacker"

        self.phase2_packets = 200
        self.phase3_packets = 100
        # 2 port * 100 = 200 packet ở pha 2
        self.phase2_ports = [1000, 2000]

    def run_cmd(self, cmd, check=True, capture=False):
        kwargs = {"check": check}
        if capture:
            kwargs["capture_output"] = True
            kwargs["text"] = True
        return subprocess.run(cmd, **kwargs)

    # ---------- setup / cleanup ----------

    def cleanup_old_environment(self):
        print("[Cleanup] Xoá namespace/veth cũ (nếu có)...")
        for ns in [self.edge_ns, self.client_ns, self.attacker_ns]:
            self.run_cmd(["sudo", "ip", "netns", "del", ns], check=False)
        for v in ["veth-edge", "veth-client", "veth-edge-att", "veth-att"]:
            self.run_cmd(["sudo", "ip", "link", "del", v], check=False)
        print("  ✓ Done")

    def setup_network_namespaces(self):
        print("\n[1/3] Thiết lập namespaces...")

        # tạo ns
        for ns in [self.edge_ns, self.client_ns, self.attacker_ns]:
            self.run_cmd(["sudo", "ip", "netns", "add", ns])

        # veth client
        self.run_cmd([
            "sudo", "ip", "link", "add", "veth-edge", "type", "veth",
            "peer", "name", "veth-client"
        ])
        # veth attacker
        self.run_cmd([
            "sudo", "ip", "link", "add", "veth-edge-att", "type", "veth",
            "peer", "name", "veth-att"
        ])

        # gán ns
        self.run_cmd(["sudo", "ip", "link", "set", "veth-edge", "netns", self.edge_ns])
        self.run_cmd(["sudo", "ip", "link", "set", "veth-edge-att", "netns", self.edge_ns])
        self.run_cmd(["sudo", "ip", "link", "set", "veth-client", "netns", self.client_ns])
        self.run_cmd(["sudo", "ip", "link", "set", "veth-att", "netns", self.attacker_ns])

        # IP
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "ip", "addr", "add", f"{self.edge_ip_client_side}/24", "dev", "veth-edge"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "ip", "addr", "add", f"{self.edge_ip_attacker_side}/24", "dev", "veth-edge-att"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.client_ns,
            "ip", "addr", "add", f"{self.client_ip}/24", "dev", "veth-client"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.attacker_ns,
            "ip", "addr", "add", f"{self.attacker_ip}/24", "dev", "veth-att"
        ])

        # up interface
        for ns in [self.edge_ns, self.client_ns, self.attacker_ns]:
            self.run_cmd(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
        self.run_cmd(["sudo", "ip", "netns", "exec", self.edge_ns, "ip", "link", "set", "veth-edge", "up"])
        self.run_cmd(["sudo", "ip", "netns", "exec", self.edge_ns, "ip", "link", "set", "veth-edge-att", "up"])
        self.run_cmd(["sudo", "ip", "netns", "exec", self.client_ns, "ip", "link", "set", "veth-client", "up"])
        self.run_cmd(["sudo", "ip", "netns", "exec", self.attacker_ns, "ip", "link", "set", "veth-att", "up"])

        # route
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.client_ns,
            "ip", "route", "add", "default", "via", self.edge_ip_client_side
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.attacker_ns,
            "ip", "route", "add", "default", "via", self.edge_ip_attacker_side
        ])

        print("  ✓ Namespaces OK")

    def configure_nftables(self):
        print("\n[2/3] Cấu hình nftables...")

        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "flush", "ruleset"
        ], check=False)

        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "table", "inet", "edgefilter"
        ])

        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "chain", "inet", "edgefilter", "prerouting",
            "{", "type", "filter", "hook", "prerouting", "priority", "0", ";", "}"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "chain", "inet", "edgefilter", "input",
            "{", "type", "filter", "hook", "input", "priority", "0",
            ";", "policy", "accept", ";", "}"
        ])

        # bật trace
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "rule", "inet", "edgefilter", "prerouting",
            "meta", "nftrace", "set", "1", "counter"
        ])

        # một vài rule cơ bản
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "rule", "inet", "edgefilter", "input",
            "ct", "state", "established,related", "counter", "accept"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "rule", "inet", "edgefilter", "input",
            "iif", "lo", "counter", "accept"
        ])
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.edge_ns,
            "nft", "add", "rule", "inet", "edgefilter", "input",
            "ip", "protocol", "icmp", "counter", "accept"
        ])

        # KHÔNG thêm rule DROP cho attacker, KHÔNG cần rule riêng cho port 9000
        # để tất cả rơi xuống TCP (no listener).

        print("  ✓ nftables OK")

    # ---------- traffic phases ----------

    def generate_phase2_random_ports(self):
        """
        Pha 2:
          - 200 packet từ attacker -> các port 1000,2000
          - Không app lắng nghe -> DROP ở TCP/UDP
        """
        print("\n[3/3] Pha 2: attacker quét random port (1000, 2000)")
        per_port = self.phase2_packets // len(self.phase2_ports)  # 200/2 = 100
        total = 0
        for p in self.phase2_ports:
            print(f"  ↳ {per_port} SYN từ attacker -> port {p}")
            self.run_cmd([
                "sudo", "ip", "netns", "exec", self.attacker_ns,
                "hping3", "-c", str(per_port),
                "-S", "-i", "u1000",
                "-p", str(p), self.edge_ip_client_side
            ], check=False)
            total += per_port
        print(f"  ✓ Pha 2 xong (~{total} gói)")

    def generate_phase3_port9000(self):
        """
        Pha 3:
          - 100 packet từ attacker -> port 9000
          - Không app lắng nghe -> DROP ở TCP/UDP
          - Luồng inbound giống hệt pha 2, chỉ khác dst_port = 9000
        """
        print("\n[3/3] Pha 3: attacker tấn công port 9000")
        print(f"  ↳ {self.phase3_packets} SYN từ attacker -> port 9000")
        self.run_cmd([
            "sudo", "ip", "netns", "exec", self.attacker_ns,
            "hping3", "-c", str(self.phase3_packets),
            "-S", "-i", "u1000",
            "-p", "9000", self.edge_ip_client_side
        ], check=False)
        print("  ✓ Pha 3 xong")

    # ---------- summary (tuỳ bạn muốn thêm) ----------

    def cleanup_environment(self):
        print("\n[Cleanup] Dọn dẹp...")
        for ns in [self.edge_ns, self.client_ns, self.attacker_ns]:
            self.run_cmd(["sudo", "ip", "netns", "del", ns], check=False)
        print("  ✓ Done")

    def run(self):
        try:
            self.cleanup_old_environment()
            self.setup_network_namespaces()
            self.configure_nftables()

            # chỉ chạy 2 pha, đều từ attacker
            self.generate_phase2_random_ports()
            self.generate_phase3_port9000()

            print("\nHoàn thành: Pha 2 = 200 SYN attacker->random-port,"
                  " Pha 3 = 100 SYN attacker->9000.")
            print("Cả hai đều được firewall ACCEPT và DROP tại TCP (no listener).")
        finally:
            self.cleanup_environment()


def main():
    tester = EdgeFirewallTwoPhaseTCPDropTest()
    tester.run()


if __name__ == "__main__":
    main()
