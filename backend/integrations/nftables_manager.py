#!/usr/bin/env python3

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple


class NFTablesManager:

    @staticmethod
    def check_nft_available() -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                ['which', 'nft'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version_result = subprocess.run(
                    ['nft', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if version_result.returncode == 0:
                    return True, "nft available"
                else:
                    sudo_result = subprocess.run(
                        ['sudo', '-n', 'nft', '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if sudo_result.returncode == 0:
                        return True, "nft available (requires sudo)"
                    else:
                        return False, "nft requires sudo privileges"
            else:
                return False, "nft command not found"
        except Exception as e:
            return False, f"Error checking nft: {str(e)}"

    @staticmethod
    def get_ruleset() -> Tuple[bool, Optional[Dict], Optional[str]]:
        try:
            result = subprocess.run(
                ['nft', '--json', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                result = subprocess.run(
                    ['sudo', 'nft', '--json', 'list', 'ruleset'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result.returncode == 0:
                try:
                    ruleset = json.loads(result.stdout)
                    return True, ruleset, None
                except json.JSONDecodeError as e:
                    return False, None, f"Failed to parse JSON: {str(e)}"
            else:
                return False, None, result.stderr or "Failed to get ruleset"

        except subprocess.TimeoutExpired:
            return False, None, "Command timeout"
        except Exception as e:
            return False, None, f"Error: {str(e)}"

    @staticmethod
    def get_tables() -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        success, ruleset, error = NFTablesManager.get_ruleset()
        if not success:
            return False, None, error

        tables = []
        nftables = ruleset.get('nftables', [])

        for item in nftables:
            if 'table' in item:
                table_info = item['table']
                tables.append({
                    'family': table_info.get('family', 'unknown'),
                    'name': table_info.get('name', 'unknown'),
                    'handle': table_info.get('handle')
                })

        return True, tables, None

    @staticmethod
    def get_chains(family: str, table: str) -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        success, ruleset, error = NFTablesManager.get_ruleset()
        if not success:
            return False, None, error

        chains = []
        nftables = ruleset.get('nftables', [])

        for item in nftables:
            if 'chain' in item:
                chain_info = item['chain']
                if chain_info.get('family') == family and chain_info.get('table') == table:
                    chains.append({
                        'name': chain_info.get('name', 'unknown'),
                        'handle': chain_info.get('handle'),
                        'type': chain_info.get('type'),
                        'hook': chain_info.get('hook'),
                        'prio': chain_info.get('prio'),
                        'policy': chain_info.get('policy')
                    })

        return True, chains, None

    @staticmethod
    def add_rule(family: str, table: str, chain: str, rule_text: str) -> Tuple[bool, Optional[str]]:
        try:
            if not all([family, table, chain, rule_text]):
                return False, "Missing required parameters"

            cmd = [
                'sudo', 'nft', 'add', 'rule',
                family, table, chain, rule_text
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return True, None
            else:
                error_msg = result.stderr or "Failed to add rule"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"

    @staticmethod
    def delete_rule(family: str, table: str, chain: str, handle: int) -> Tuple[bool, Optional[str]]:
        try:
            if not all([family, table, chain]) or handle is None:
                return False, "Missing required parameters"

            cmd = [
                'sudo', 'nft', 'delete', 'rule',
                family, table, chain, 'handle', str(handle)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return True, None
            else:
                error_msg = result.stderr.strip() if result.stderr else "Failed to delete rule"
                # Provide more helpful error messages
                if "No such file or directory" in error_msg:
                    return False, f"Rule with handle {handle} not found in {family} {table} {chain}. The rule may have been already deleted or the handle is incorrect."
                elif "Could not process rule" in error_msg:
                    return False, f"Could not process rule deletion for handle {handle}. The table/chain may not exist or the handle is invalid."
                else:
                    return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"

    @staticmethod
    def update_rule(family: str, table: str, chain: str, handle: int, new_rule_text: str) -> Tuple[bool, Optional[str]]:
        success, error = NFTablesManager.delete_rule(family, table, chain, handle)
        if not success:
            return False, f"Failed to delete old rule: {error}"

        success, error = NFTablesManager.add_rule(family, table, chain, new_rule_text)
        if not success:
            return False, f"Failed to add new rule: {error}"

        return True, None

    @staticmethod
    def parse_ruleset_to_tree(ruleset: Dict) -> Dict:
        tree = {}
        nftables = ruleset.get('nftables', [])

        for item in nftables:
            if 'table' in item:
                table_info = item['table']
                family = table_info.get('family', 'unknown')
                table_name = table_info.get('name', 'unknown')

                if family not in tree:
                    tree[family] = {}

                if table_name not in tree[family]:
                    tree[family][table_name] = {
                        'handle': table_info.get('handle'),
                        'chains': {}
                    }

            elif 'chain' in item:
                chain_info = item['chain']
                family = chain_info.get('family', 'unknown')
                table_name = chain_info.get('table', 'unknown')
                chain_name = chain_info.get('name', 'unknown')

                if family not in tree:
                    tree[family] = {}
                if table_name not in tree[family]:
                    tree[family][table_name] = {'chains': {}}

                tree[family][table_name]['chains'][chain_name] = {
                    'handle': chain_info.get('handle'),
                    'type': chain_info.get('type'),
                    'hook': chain_info.get('hook'),
                    'prio': chain_info.get('prio'),
                    'policy': chain_info.get('policy'),
                    'rules': []
                }

        for item in nftables:
            if 'rule' in item:
                rule_info = item['rule']
                family = rule_info.get('family', 'unknown')
                table_name = rule_info.get('table', 'unknown')
                chain_name = rule_info.get('chain', 'unknown')

                if (family in tree and
                    table_name in tree[family] and
                    chain_name in tree[family][table_name]['chains']):

                    rule_text = NFTablesManager.parse_rule_expr(rule_info.get('expr', []))

                    rule_data = {
                        'handle': rule_info.get('handle'),
                        'expr': rule_info.get('expr', []),
                        'rule_text': rule_text,
                        'comment': rule_info.get('comment')
                    }

                    tree[family][table_name]['chains'][chain_name]['rules'].append(rule_data)

        return tree

    @staticmethod
    def parse_rule_expr(expr_list: List[Dict]) -> str:
        parts = []

        for expr in expr_list:
            if 'match' in expr:
                match = expr['match']
                left = match.get('left', {})
                right = match.get('right', {})
                op = match.get('op', '==')

                left_str = NFTablesManager.parse_expr_value(left)
                right_str = NFTablesManager.parse_expr_value(right)

                if op == '==':
                    parts.append(f"{left_str} {right_str}")
                else:
                    parts.append(f"{left_str} {op} {right_str}")

            elif 'counter' in expr:
                counter = expr['counter']
                packets = counter.get('packets', 0)
                bytes_val = counter.get('bytes', 0)
                parts.append(f"counter packets {packets} bytes {bytes_val}")

            elif 'accept' in expr:
                parts.append('accept')
            elif 'drop' in expr:
                parts.append('drop')
            elif 'reject' in expr:
                parts.append('reject')
            elif 'return' in expr:
                parts.append('return')
            elif 'jump' in expr:
                target = expr['jump'].get('target', '')
                parts.append(f"jump {target}")
            elif 'goto' in expr:
                target = expr['goto'].get('target', '')
                parts.append(f"goto {target}")
            elif 'log' in expr:
                log_info = expr['log']
                prefix = log_info.get('prefix', '')
                parts.append(f'log prefix "{prefix}"')

        return ' '.join(parts) if parts else '<empty rule>'

    @staticmethod
    def parse_expr_value(value_dict: Dict) -> str:
        if isinstance(value_dict, dict):
            if 'payload' in value_dict:
                payload = value_dict['payload']
                protocol = payload.get('protocol', '')
                field = payload.get('field', '')
                return f"{protocol} {field}" if protocol and field else str(value_dict)
            elif 'prefix' in value_dict:
                prefix = value_dict['prefix']
                addr = prefix.get('addr', '')
                length = prefix.get('len', '')
                return f"{addr}/{length}"
            elif 'set' in value_dict:
                return str(value_dict['set'])
            elif 'range' in value_dict:
                rng = value_dict['range']
                return f"{rng[0]}-{rng[1]}"
            else:
                for key, val in value_dict.items():
                    return str(val)

        return str(value_dict)
