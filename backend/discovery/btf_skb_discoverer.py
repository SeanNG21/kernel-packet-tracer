#!/usr/bin/env python3

import os
import re
import json
import subprocess
from typing import List, Dict, Set
from dataclasses import dataclass, asdict

@dataclass
class SKBFunction:
    name: str
    type: str
    category: str
    priority: int
    params: List[str]
    return_type: str = None

    def __hash__(self):
        return hash(self.name)

class BTFSKBDiscoverer:

    CATEGORIES = {
        'nft': ['nft_', 'nf_tables_'],
        'netfilter': ['nf_', 'xt_', 'ipt_', 'ip6t_'],
        'network': ['__netif_', 'netif_', 'dev_'],
        'tcp': ['tcp_', '__tcp_'],
        'ip': ['ip_', '__ip_', 'ipv4_', 'ipv6_'],
        'udp': ['udp_', '__udp_'],
        'routing': ['fib_', 'rt_', 'dst_'],
        'bridge': ['br_'],
        'packet': ['packet_', 'tpacket_'],
        'qdisc': ['qdisc_', 'sch_'],
    }

    PRIORITY_FUNCTIONS = {
        0: [
            'nft_do_chain',
            'nf_hook_slow',
            '__netif_receive_skb_core',
            'ip_rcv',
            'ip_output',
            'tcp_v4_rcv',
            'udp_rcv',
        ],
        1: [
            'nft_immediate_eval',
            'nf_conntrack_in',
            'ip_forward',
            'ip_local_deliver',
            'tcp_transmit_skb',
        ],
    }

    def __init__(self):
        self.functions: Set[SKBFunction] = set()
        self.btf_cache = None

    def discover_from_btf(self) -> List[SKBFunction]:
        print("[*] Discovering SKB functions from BTF...")

        self._discover_via_bpftool()

        if len(self.functions) < 10:
            print("[*] BTF discovery incomplete, using kallsyms...")
            self._discover_via_kallsyms()

        self._categorize_functions()

        sorted_funcs = sorted(self.functions, key=lambda x: (x.priority, x.name))

        print(f"[✓] Discovered {len(sorted_funcs)} SKB functions")
        print(f"    - Critical: {sum(1 for f in sorted_funcs if f.priority == 0)}")
        print(f"    - Important: {sum(1 for f in sorted_funcs if f.priority == 1)}")
        print(f"    - Optional: {sum(1 for f in sorted_funcs if f.priority == 2)}")

        return sorted_funcs

    def _discover_via_bpftool(self):
        try:
            result = subprocess.run(
                ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"[!] bpftool failed: {result.stderr}")
                return

            self._parse_btf_output(result.stdout)

        except FileNotFoundError:
            print("[!] bpftool not found, trying alternative method...")
        except Exception as e:
            print(f"[!] Error discovering via BTF: {e}")

    def _parse_btf_output(self, btf_output: str):
        pattern = r'^\s*(\w+)\s*\([^)]*struct\s+sk_buff\s*\*'

        for line in btf_output.split('\n'):
            match = re.search(pattern, line)
            if match:
                func_name = match.group(1)

                params_match = re.search(r'\((.*?)\)', line)
                params = []
                if params_match:
                    param_str = params_match.group(1)
                    params = [p.strip() for p in param_str.split(',')]

                ret_type = None
                ret_match = re.match(r'^\s*(\w+(?:\s*\*)?\s+)', line)
                if ret_match:
                    ret_type = ret_match.group(1).strip()

                func = SKBFunction(
                    name=func_name,
                    type='kprobe',
                    category='unknown',
                    priority=2,
                    params=params,
                    return_type=ret_type
                )
                self.functions.add(func)

    def _discover_via_kallsyms(self):
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue

                    func_name = parts[2]

                    if self._is_likely_skb_function(func_name):
                        func = SKBFunction(
                            name=func_name,
                            type='kprobe',
                            category='unknown',
                            priority=2,
                            params=['struct sk_buff *skb'],
                        )
                        self.functions.add(func)

        except Exception as e:
            print(f"[!] Error reading kallsyms: {e}")

    def _is_likely_skb_function(self, func_name: str) -> bool:
        skb_patterns = [
            '_skb_', 'skb_', '__skb',
            '_rcv', '_xmit', '_transmit',
            '_receive', '_forward',
            'nf_', 'nft_', 'netif_',
            'tcp_', 'udp_', 'ip_',
        ]

        return any(pattern in func_name for pattern in skb_patterns)

    def _categorize_functions(self):
        for func in self.functions:
            for category, prefixes in self.CATEGORIES.items():
                if any(func.name.startswith(prefix) for prefix in prefixes):
                    func.category = category
                    break

            if func.name in self.PRIORITY_FUNCTIONS.get(0, []):
                func.priority = 0
            elif func.name in self.PRIORITY_FUNCTIONS.get(1, []):
                func.priority = 1
            elif func.category in ['nft', 'netfilter']:
                func.priority = 1
            else:
                func.priority = 2

    def filter_by_category(self, categories: List[str]) -> List[SKBFunction]:
        return [f for f in self.functions if f.category in categories]

    def filter_by_priority(self, max_priority: int) -> List[SKBFunction]:
        return [f for f in self.functions if f.priority <= max_priority]

    def export_json(self, filepath: str):
        data = {
            'total': len(self.functions),
            'by_category': {},
            'by_priority': {},
            'functions': [asdict(f) for f in sorted(self.functions, key=lambda x: x.name)]
        }

        for func in self.functions:
            cat = func.category
            if cat not in data['by_category']:
                data['by_category'][cat] = []
            data['by_category'][cat].append(func.name)

        for func in self.functions:
            pri = func.priority
            if pri not in data['by_priority']:
                data['by_priority'][pri] = []
            data['by_priority'][pri].append(func.name)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[✓] Exported to {filepath}")

    def generate_bpf_attach_code(self, functions: List[SKBFunction]) -> str:
        code = "// Auto-generated attach code\n\n"

        for func in functions:
            code += f"// {func.category} - Priority {func.priority}\n"
            code += f"bpf.attach_kprobe(event=\"{func.name}\", fn_name=\"trace_skb_func\");\n"
            if func.type == 'kretprobe':
                code += f"bpf.attach_kretprobe(event=\"{func.name}\", fn_name=\"trace_skb_func_exit\");\n"
            code += "\n"

        return code

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Discover SKB functions from kernel BTF')
    parser.add_argument('--output', '-o', default='skb_functions.json',
                       help='Output JSON file')
    parser.add_argument('--category', '-c', action='append',
                       help='Filter by category (can specify multiple)')
    parser.add_argument('--priority', '-p', type=int, default=2,
                       help='Max priority (0=critical only, 1=important, 2=all)')
    parser.add_argument('--generate-code', '-g', action='store_true',
                       help='Generate BPF attach code')

    args = parser.parse_args()

    discoverer = BTFSKBDiscoverer()
    functions = discoverer.discover_from_btf()

    if args.category:
        functions = discoverer.filter_by_category(args.category)
        print(f"[*] Filtered to categories: {args.category}")

    functions = discoverer.filter_by_priority(args.priority)
    print(f"[*] Filtered to priority <= {args.priority}: {len(functions)} functions")

    discoverer.export_json(args.output)

    print("\n=== DISCOVERED FUNCTIONS ===")
    print(f"Total: {len(functions)}")
    print("\nTop 20 functions:")
    for i, func in enumerate(functions[:20]):
        print(f"  {i+1}. [{func.priority}] {func.name} ({func.category})")

    if args.generate_code:
        code = discoverer.generate_bpf_attach_code(functions)
        code_file = args.output.replace('.json', '_attach.txt')
        with open(code_file, 'w') as f:
            f.write(code)
        print(f"\n[✓] Generated attach code: {code_file}")

if __name__ == '__main__':
    main()
