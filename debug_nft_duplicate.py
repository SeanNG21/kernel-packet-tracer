#!/usr/bin/env python3
"""
Debug Script: Analyze nft_immediate_eval duplicate calls
Enhanced version with expr_addr analysis
"""

import json
import sys
from collections import defaultdict
from typing import Dict, List, Optional

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def colorize(text: str, color: str) -> str:
    """Colorize text for terminal"""
    return f"{color}{text}{Colors.ENDC}"

def analyze_trace_file(filepath: str, verbose: bool = False):
    """Analyze trace JSON file to detect duplicate nft_immediate_eval calls"""

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(colorize(f"[!] Error: File not found: {filepath}", Colors.FAIL))
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(colorize(f"[!] Error: Invalid JSON: {e}", Colors.FAIL))
        sys.exit(1)

    print("=" * 80)
    print(colorize("NFT_IMMEDIATE_EVAL DUPLICATE ANALYSIS", Colors.HEADER + Colors.BOLD))
    print("=" * 80)
    print(f"File: {filepath}\n")

    traces = data.get('traces', [])
    print(f"Total packet traces: {len(traces)}\n")

    total_true_duplicates = 0
    total_rule_evals = 0
    traces_with_duplicates = []

    for idx, trace in enumerate(traces):
        print(colorize(f"--- TRACE #{idx + 1} ---", Colors.OKBLUE + Colors.BOLD))
        print(f"SKB: {trace.get('skb_addr')}")

        protocol = trace.get('protocol_name', 'Unknown')
        protocol_num = trace.get('protocol', '?')
        print(f"Protocol: {protocol} ({protocol_num})")

        src = trace.get('src_ip', '0.0.0.0')
        sport = trace.get('src_port', 0)
        dst = trace.get('dst_ip', '0.0.0.0')
        dport = trace.get('dst_port', 0)
        print(f"Flow: {src}:{sport} → {dst}:{dport}")

        final_verdict = trace.get('final_verdict', 'UNKNOWN')
        print(f"Final verdict: {colorize(final_verdict, Colors.OKGREEN if final_verdict == 'ACCEPT' else Colors.FAIL)}")

        total_rules = trace.get('total_rules_evaluated', 0)
        print(f"Total rules evaluated: {total_rules}")
        print()

        # Extract rule_eval events
        all_events = trace.get('important_events', [])
        rule_evals = [e for e in all_events if e.get('trace_type') == 'rule_eval']

        if len(rule_evals) == 0:
            print(colorize("  [!] No rule_eval events found", Colors.WARNING))
            print()
            continue

        total_rule_evals += len(rule_evals)

        print(f"  Rule evaluation events: {len(rule_evals)}")
        print()

        # Group by expr_addr to detect TRUE duplicates
        by_expr = defaultdict(list)
        by_rule_handle = defaultdict(list)
        by_rule_seq = defaultdict(list)
        has_expr_addr = False

        for event in rule_evals:
            expr_addr = event.get('expr_addr')
            rule_handle = event.get('rule_handle')
            rule_seq = event.get('rule_seq')

            if expr_addr:
                has_expr_addr = True
                by_expr[expr_addr].append(event)

            if rule_handle is not None:
                by_rule_handle[rule_handle].append(event)

            if rule_seq is not None:
                by_rule_seq[rule_seq].append(event)

        # Print detailed table
        print("  " + colorize("Event Details:", Colors.BOLD))
        print("  " + "-" * 100)

        # Header
        header_parts = [
            "#".ljust(4),
            "rule_seq".ljust(10),
            "verdict".ljust(12),
            "verdict_raw".ljust(12),
        ]

        if has_expr_addr:
            header_parts.append("expr_addr".ljust(20))

        header_parts.extend([
            "rule_handle".ljust(12),
            "Δt(ns)".ljust(10)
        ])

        print("  " + " ".join(header_parts))
        print("  " + "-" * 100)

        # Events with timestamp delta
        first_ts = rule_evals[0]['timestamp'] if rule_evals else 0

        for i, event in enumerate(rule_evals):
            delta_ns = int(event['timestamp'] - first_ts) if i > 0 else 0

            verdict = event.get('verdict', 'N/A')
            verdict_raw = event.get('verdict_raw', 'N/A')

            # Colorize verdict
            if verdict == 'CONTINUE':
                verdict_colored = colorize(verdict, Colors.OKCYAN)
            elif verdict == 'DROP':
                verdict_colored = colorize(verdict, Colors.FAIL)
            elif verdict == 'ACCEPT':
                verdict_colored = colorize(verdict, Colors.OKGREEN)
            else:
                verdict_colored = verdict

            row_parts = [
                str(i+1).ljust(4),
                str(event.get('rule_seq', 'N/A')).ljust(10),
                verdict_colored.ljust(12 + len(Colors.FAIL) + len(Colors.ENDC)),  # Account for color codes
                str(verdict_raw).ljust(12),
            ]

            if has_expr_addr:
                expr_addr = event.get('expr_addr', 'N/A')
                row_parts.append(str(expr_addr).ljust(20))

            row_parts.extend([
                str(event.get('rule_handle', 'N/A')).ljust(12),
                (f"+{delta_ns}".ljust(10) if i > 0 else "-".ljust(10))
            ])

            print("  " + " ".join(row_parts))

        print()

        # Analysis section
        print("  " + colorize("Analysis:", Colors.BOLD))
        print("  " + "-" * 76)

        # Check for TRUE duplicates (same expr_addr)
        duplicates_found = False
        duplicate_count = 0

        if has_expr_addr:
            for expr_addr, events in by_expr.items():
                if len(events) > 1:
                    duplicates_found = True
                    duplicate_count += len(events) - 1

                    print(colorize(f"  [!!!] TRUE DUPLICATE DETECTED!", Colors.FAIL + Colors.BOLD))
                    print(f"        Same expr_addr {expr_addr} evaluated {len(events)} times")
                    print(f"        This is a BUG - same expression called multiple times!")
                    print(f"        Events:")

                    for e in events:
                        ts_delta = int(e['timestamp'] - events[0]['timestamp'])
                        print(f"          - rule_seq={e.get('rule_seq')}, "
                              f"verdict={e.get('verdict')}, "
                              f"Δt={ts_delta}ns")
                    print()
        else:
            print(colorize(f"  [!] WARNING: No expr_addr in events (old trace format)", Colors.WARNING))
            print(f"      Cannot verify TRUE duplicates without expr_addr")
            print(f"      Please re-run trace with updated code to get expr_addr")
            print()

        # Check for same rule_handle (might be same rule or chain-level handle)
        if not duplicates_found and has_expr_addr:
            # Check if all events have DIFFERENT expr_addr
            unique_expr = [e for e in by_expr.keys() if e != 'N/A' and e is not None]

            if len(unique_expr) == len(rule_evals):
                print(colorize(f"  [✓] All {len(rule_evals)} events have DIFFERENT expr_addr", Colors.OKGREEN))
                print(f"      This is NORMAL - packet evaluated by {len(rule_evals)} different expressions")
                print()
            elif len(unique_expr) > 0:
                print(colorize(f"  [?] Found {len(unique_expr)} unique expr_addr for {len(rule_evals)} events", Colors.WARNING))
                print(f"      Some events may share expressions or have missing expr_addr")
                print()

        # Analyze same rule_handle
        for rule_handle, events in by_rule_handle.items():
            if rule_handle is not None and rule_handle != 0 and len(events) > 1:
                print(f"  [i] Info: {len(events)} events share rule_handle={rule_handle}")

                if has_expr_addr:
                    # Check if they have different expr_addr
                    expr_addrs = set(e.get('expr_addr') for e in events if e.get('expr_addr'))
                    if len(expr_addrs) == len(events):
                        print(f"      → Different expr_addr - likely same rule with multiple expressions")
                    else:
                        print(f"      → Some share expr_addr - potential duplicate or chain-level handle")
                else:
                    print(f"      → Cannot verify without expr_addr")
                print()

        # Verdict progression analysis
        print("  " + colorize("Verdict Progression:", Colors.BOLD))

        for i, event in enumerate(rule_evals):
            verdict = event.get('verdict', 'UNKNOWN')
            verdict_raw = event.get('verdict_raw', 'N/A')
            rule_seq = event.get('rule_seq', '?')

            # Colorize verdict
            if verdict == 'CONTINUE':
                verdict_display = colorize(verdict, Colors.OKCYAN)
            elif verdict == 'DROP':
                verdict_display = colorize(verdict, Colors.FAIL)
            elif verdict == 'ACCEPT':
                verdict_display = colorize(verdict, Colors.OKGREEN)
            else:
                verdict_display = verdict

            print(f"    {i+1}. Rule seq={rule_seq}: {verdict_display} (raw={verdict_raw})")

        print()

        # Check for suspicious verdict flow
        terminal_verdicts = ['DROP', 'ACCEPT']
        for i, event in enumerate(rule_evals[:-1]):  # All except last
            verdict = event.get('verdict', 'UNKNOWN')
            if verdict in terminal_verdicts:
                remaining = len(rule_evals) - i - 1
                print(colorize(f"  [!] WARNING: Terminal verdict '{verdict}' at position {i+1}, "
                              f"but {remaining} more events followed!", Colors.WARNING))
                print(f"      Possible reasons:")
                print(f"      1. Verdict is actually CONTINUE (check verdict_raw={event.get('verdict_raw')})")
                print(f"      2. Jump/Goto to another chain")
                print(f"      3. Multiple expressions in same rule")
                print()
                break

        if duplicates_found:
            total_true_duplicates += duplicate_count
            traces_with_duplicates.append(idx + 1)

        if verbose:
            print("  " + colorize("Raw Events (JSON):", Colors.BOLD))
            for i, event in enumerate(rule_evals):
                print(f"    Event {i+1}:")
                for key, value in event.items():
                    print(f"      {key}: {value}")
            print()

        print("=" * 80)
        print()

    # Summary
    print(colorize("SUMMARY", Colors.HEADER + Colors.BOLD))
    print("-" * 80)
    print(f"Total packet traces analyzed: {len(traces)}")
    print(f"Total rule_eval events: {total_rule_evals}")
    print(f"Total TRUE duplicates (same expr_addr): {total_true_duplicates}")
    print()

    if total_true_duplicates == 0:
        print(colorize("[✓] NO TRUE DUPLICATES FOUND", Colors.OKGREEN + Colors.BOLD))
        print("    All nft_immediate_eval calls are for different expressions")
        print("    This is NORMAL behavior - packet evaluated by multiple expressions/rules")
    else:
        print(colorize(f"[!!!] {total_true_duplicates} TRUE DUPLICATES FOUND", Colors.FAIL + Colors.BOLD))
        print(f"      Same expression(s) evaluated multiple times")
        print(f"      This indicates a BUG in the tracer or nftables behavior")
        print(f"      Affected traces: {traces_with_duplicates}")
        print()
        print(colorize("      RECOMMENDATION:", Colors.WARNING + Colors.BOLD))
        print("      1. Verify deduplication logic is enabled in backend/app.py")
        print("      2. Check if expr_addr extraction is correct")
        print("      3. Report this as a bug with trace file attached")

    print("=" * 80)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Analyze NFT trace files for duplicate nft_immediate_eval calls',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python3 debug_nft_duplicate.py trace_file.json

  # Verbose mode (show all event details)
  python3 debug_nft_duplicate.py trace_file.json -v

  # Analyze latest trace
  python3 debug_nft_duplicate.py backend/output/trace_full_*.json

Expected Output:
  - If expr_addr all different → NORMAL (multiple rules/expressions)
  - If expr_addr duplicated → TRUE DUPLICATE (BUG!)
        """
    )

    parser.add_argument('trace_file',
                       help='Path to trace JSON file')
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Show detailed event information')

    args = parser.parse_args()

    if not args.trace_file:
        parser.print_help()
        sys.exit(1)

    analyze_trace_file(args.trace_file, args.verbose)


if __name__ == '__main__':
    main()
