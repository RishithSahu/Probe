"""Read-back verification of independent Windows firewall restrictions for nmap.

The capture auditor covers tagged raw probes. Kernel rules cover the untagged helper.
Neither a saved success flag nor an application-level target check substitutes for read-back.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import subprocess

from .authorisation import scope_digest


def denied_v4(cidrs) -> list[str]:
    remaining = [ipaddress.ip_network('0.0.0.0/0')]
    for net in ipaddress.collapse_addresses(ipaddress.ip_network(str(c)) for c in cidrs):
        if net.version != 4:
            raise ValueError('IPv6 active discovery is not supported')
        remaining = [part for old in remaining for part in
                     (old.address_exclude(net) if net.subnet_of(old) else ([] if old.subnet_of(net) else [old]))]
    return [str(n) for n in sorted(remaining)]


def create_policy(path: Path, program: str, cidrs) -> dict:
    data = {'scope_digest': scope_digest(cidrs), 'program': str(Path(program).resolve()),
            'scope': [str(c) for c in cidrs], 'denied_v4': denied_v4(cidrs)}
    Path(path).write_text(json.dumps(data, indent=2), encoding='utf-8')
    return data


def _intervals(value: str, version: int):
    nets = []
    for item in value.split(','):
        item = item.strip()
        if '-' in item:
            a, b = item.split('-', 1)
            nets.extend(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
        else:
            nets.append(ipaddress.ip_network(item, strict=False))
    if any(n.version != version for n in nets):
        raise ValueError('unexpected address family in firewall rule')
    return list(ipaddress.collapse_addresses(nets))


def validate_readback(policy: dict, result: dict) -> None:
    if not result.get('profiles_enabled') or result.get('scope_digest') != policy['scope_digest']:
        raise ValueError('firewall scope identity/profiles do not match')
    for family, version, expected in [('v4', 4, ','.join(policy['denied_v4'])), ('v6', 6, '::/0')]:
        rules = [r for r in result.get('rules', []) if r['name'] == f"ProbeScope.{policy['scope_digest']}.{family}"]
        if len(rules) != 1:
            raise ValueError(f'exactly one {family} firewall rule required')
        r = rules[0]
        if (not r['enabled'] or r['direction'] != 2 or r['action'] != 0 or r['protocol'] != 256
                or r['profiles'] != 7 or os.path.normcase(r['program']) != os.path.normcase(policy['program'])
                or r.get('service') or r.get('interfaces') != 'All'
                or r.get('local') != '*' or r.get('local_ports') not in (None, '', '*')
                or r.get('remote_ports') not in (None, '', '*') or r.get('interface_ids')):
            raise ValueError(f'{family} firewall rule is not an unconditional program egress block')
        if _intervals(r['remote'], version) != _intervals(expected, version):
            raise ValueError(f'{family} firewall destinations do not match the effective scope')


def check(policy_path: Path, *, expected=None) -> tuple[bool, str]:
    if os.name != 'nt':
        return False, 'independent helper egress verification is not implemented on this platform'
    try:
        policy = json.loads(Path(policy_path).read_text(encoding='utf-8'))
        if expected is not None and policy != expected:
            return False, 'egress policy changed after the auditor started'
        script = Path(__file__).resolve().parent.parent / 'enforce' / 'windows-program-scope.ps1'
        run = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script),
                              '-PolicyFile', str(Path(policy_path).resolve())], capture_output=True, text=True,
                             timeout=12, creationflags=subprocess.CREATE_NO_WINDOW)
        if run.returncode:
            return False, (run.stderr or run.stdout).strip()[:600]
        validate_readback(policy, json.loads(run.stdout))
        return True, ''
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
