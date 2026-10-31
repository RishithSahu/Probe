"""Builds the connection graph the web page draws:

  scanner -- local link -- on-link hosts
  local link -- router hop(s) from the measured path -- segment node -- its members
Silent hops appear as "?" nodes: we know a router is there (TTL distance), not its address.
"""
from __future__ import annotations

from .segments import Segment


def build_edges(my_ip: str, hosts: list[dict], segments: list[Segment]) -> list[tuple[str, str, str, str]]:
    edges: list[tuple[str, str, str, str]] = []
    local_nets = [s.cidr for s in segments if s.local]
    lan = f"lan:{local_nets[0] if local_nets else 'local'}"
    edges.append((my_ip, lan, "l2", "scanner interface"))
    member_of: dict[str, str] = {}
    for s in segments:
        if s.kind == "in-scope" and not s.local:
            for m in s.members:
                member_of[m] = f"seg:{s.cidr}"
    ips = {h["ip"] for h in hosts}
    for h in hosts:
        ip = h["ip"]
        if ip != my_ip and ip not in member_of:
            edges.append((lan, ip, "l2", ",".join(h["discovery_methods"][:3])))
    for ip, node in member_of.items():
        edges.append((node, ip, "member", "behind router"))
    for s in segments:
        if s.kind == "in-scope" and not s.local:
            node, prev = f"seg:{s.cidr}", lan
            depth = (s.distance - 1) if s.distance else len(s.path)
            for t in range(1, max(depth, len(s.path)) + 1):
                hop = s.path[t - 1] if t <= len(s.path) else None
                name = hop if hop and hop in ips else (hop or f"?{s.cidr}@{t}")
                edges.append((prev, name, "route", f"hop {t}"))
                prev = name
            edges.append((prev, node, "route", "; ".join(s.evidence)[:200]))
        elif s.kind == "outside-scope":
            edges.append((lan, f"seg:{s.cidr}", "route", "; ".join(s.evidence)[:200]))
    return edges
