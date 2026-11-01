#!/usr/bin/env python3
"""Replays the real 192.168.60.0/24 lab network (171 hosts, 263 services, discovered by the Network
Discovery Probe against the live lab this session) as a Mininet topology, so the orchestrator, Probe and
the new console session agent can all be developed and tested while disconnected from the real network.

What this is NOT: a claim that every host behaves identically to its real counterpart. Most hosts get a
generic stand-in service that answers with the SAME banner the real scan observed (so the same discovery
and fingerprinting code paths run), not a reimplementation of SSH/MySQL/SMB/etc. 192.168.60.139 is the one
host built to be behaviourally faithful end to end -- its real /vault/keykeeper binary, the real
trusted-proxy-header gating, and the real recovered passkey -- because that is the host this project's own
test cases and the console session agent are built against. See scripts/mininet/README.md.

Must run as root under Linux (WSL2 Kali, in this project's case) -- Mininet needs real network namespaces.

Usage:
    sudo python3 scripts/mininet/topology.py [--graph PATH] [--cli]

--cli drops into the Mininet CLI after setup (default); without it, the topology is built, services are
started, and the script blocks until Ctrl-C, then tears everything down.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_GRAPH = SCRIPT_DIR / "network_graph.json"
DEFAULT_KEYKEEPER = SCRIPT_DIR / "assets" / "keykeeper.elf"
ASSETS_DIR = "/opt/mininet_assets"
CONTROLLER_IP = "192.168.60.254"
SUBNET_PREFIX = "192.168.60.0/24"

# 139's two ports get dedicated, stateful scripts (vault_site.py, game_zone.py) instead of the generic
# banner stand-in -- see their own docstrings for exactly what is faithful vs reconstructed.
SPECIAL_HOST_IP = "192.168.60.139"
SPECIAL_PORTS = {80, 8833}


def _service_spec(port: int, service_name: str | None, protocol: str) -> dict:
    name = (service_name or "unknown").rstrip("?")
    is_http = "http" in name or port in (80, 8000, 8080, 8443)
    banner_by_name = {
        "ssh": "SSH-2.0-OpenSSH_9.6",
        "mysql": "\x00\x00\x00\x0a9.1.0-replica",
        "postgresql": "",
        "vnc": "RFB 003.008\n",
        "netbios-ssn": "",
        "msrpc": "",
        "microsoft-ds": "",
        "wsdapi": "",
        "upnp": "",
        "afs3-fileserver": "",
        "nessus": "",
        "realserver": "",
        "ppp": "",
    }
    if is_http:
        return {"kind": "http", "server": name, "banner": f"{name} replica (mininet)"}
    return {"kind": "raw", "banner": banner_by_name.get(name, f"{name} service (mininet replica)")}


def build_service_config(asset: dict) -> dict:
    config: dict[str, dict] = {}
    for service in asset["services"]:
        port = service["port"]
        if asset["ip"] == SPECIAL_HOST_IP and port in SPECIAL_PORTS:
            continue
        config[str(port)] = _service_spec(port, service.get("service_name"), service.get("protocol", "tcp"))
    return config


# This WSL2 + Open vSwitch combination stops forwarding once a single bridge passes roughly 57 ports --
# confirmed empirically (56 ports: works; 58 ports: silent 100% packet loss, no error from OVS, no
# Mininet exception, nothing in ovs-vswitchd's own log -- just dropped). Below that ceiling, linking two
# OVSBridge instances together trunks traffic between them exactly like a real pair of switches, verified
# with cross-shard host-to-host pings. So the 171-host network is split into shards of this size, all
# wired into one flat broadcast domain through shard 0 -- which is what the real /24 looked like to begin
# with, not a design choice this topology is making on its own.
_SHARD_SIZE = 45


def build_net(graph_path: Path, limit_hosts: int | None = None) -> Mininet:
    data = json.loads(graph_path.read_text())
    assets = data["assets"]
    if limit_hosts is not None:
        assets = assets[:limit_hosts]

    net = Mininet(switch=OVSBridge, controller=None)
    num_shards = max(1, (len(assets) + _SHARD_SIZE - 1) // _SHARD_SIZE)
    switches = [net.addSwitch(f"s{i}") for i in range(num_shards)]
    for i in range(1, len(switches)):
        net.addLink(switches[0], switches[i])

    for i, asset in enumerate(assets):
        ip = asset["ip"]
        shard = switches[i // _SHARD_SIZE]
        host = net.addHost(f"h{i}", ip=f"{ip}/24")
        net.addLink(host, shard)
        host._ape_asset = asset  # stash for start_services

    controller_host = net.addHost("ctrl", ip=f"{CONTROLLER_IP}/24")
    net.addLink(controller_host, switches[0])

    net.start()
    return net


def start_services(net: Mininet) -> None:
    for host in net.hosts:
        asset = getattr(host, "_ape_asset", None)
        if asset is None:
            continue  # the controller host runs nothing of its own
        if asset["ip"] == SPECIAL_HOST_IP:
            host.cmd(f"python3 {SCRIPT_DIR}/services/vault_site.py 80 > /tmp/vault_site.log 2>&1 &")
            host.cmd(f"python3 {SCRIPT_DIR}/services/game_zone.py 8833 > /tmp/game_zone.log 2>&1 &")
        config = build_service_config(asset)
        if config:
            config_json = json.dumps(config).replace("'", "'\\''")
            host.cmd(f"python3 {SCRIPT_DIR}/services/svc_runner.py '{config_json}' > /tmp/svc_runner.log 2>&1 &")


def stage_keykeeper_binary(src: Path = DEFAULT_KEYKEEPER) -> None:
    import shutil
    import subprocess

    if not src.exists():
        print(f"warning: {src} not found -- /vault/keykeeper on the replica will 500 until it's copied there")
        return
    subprocess.run(["mkdir", "-p", ASSETS_DIR], check=True)
    shutil.copy(src, f"{ASSETS_DIR}/keykeeper.elf")


def _run_self_test(net: Mininet) -> None:
    """Exercises the replica from the controller host's own namespace -- real L2/L3 connectivity to every
    other host, exactly how the orchestrator will reach them -- without needing an interactive CLI."""
    import time
    time.sleep(1.0)  # let the service listeners finish binding
    ctrl = net.get("ctrl")
    checks = [
        ("gateway host reachable", f"ping -c1 -W2 192.168.60.1"),
        ("generic service answers (192.168.60.111:3000)", "curl -s -m 3 -o /dev/null -w '%{http_code}' http://192.168.60.111:3000/ || true"),
        ("vault gated without header -> 404", "curl -s -m 3 -o /dev/null -w '%{http_code}' http://192.168.60.139/vault"),
        ("vault gated with header -> 308", "curl -s -m 3 -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.168.60.1' http://192.168.60.139/vault"),
        ("keykeeper binary downloadable", "curl -s -m 3 -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 192.168.60.1' http://192.168.60.139/vault/keykeeper"),
        ("game zone AUTH accepted", "printf 'AUTH R3v3rs3_Th3_Z0n3\\r\\n' | timeout 3 nc 192.168.60.139 8833"),
    ]
    for label, cmd in checks:
        result = ctrl.cmd(cmd).strip()
        print(f"[self-test] {label}: {result!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--cli", action="store_true", default=True)
    parser.add_argument("--self-test", action="store_true",
                       help="skip the interactive CLI: bring the topology up, probe a few known services, tear down")
    parser.add_argument("--limit-hosts", type=int, default=None, help="debug aid: only build the first N hosts")
    args = parser.parse_args()

    if not args.graph.exists():
        print(f"network graph not found: {args.graph}", file=sys.stderr)
        return 1

    setLogLevel("warning")
    repo_root = SCRIPT_DIR.parent.parent
    stage_keykeeper_binary()

    net = build_net(args.graph, limit_hosts=args.limit_hosts)
    try:
        start_services(net)
        print(f"topology up: {len(net.hosts) - 1} replica hosts + controller ({CONTROLLER_IP}) on {SUBNET_PREFIX}")
        print(f"from the controller host ('ctrl' in the CLI below), the real app is reachable at {repo_root}")
        print("example: mininet> ctrl python3 -m app.orchestrator run --assessment-id MININET-001 "
              f"--scope {SUBNET_PREFIX} --network-graph {args.graph} --max-minutes 20")
        if args.self_test:
            _run_self_test(net)
        else:
            CLI(net)
    finally:
        net.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
