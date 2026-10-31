"""Builds the connection graph the web page draws:

  scanner -- local link -- on-link hosts
  local link -- router hop(s) from the measured path -- segment node -- its members
Silent hops appear as "?" nodes: we know a router is there (TTL distance), not its address.
"""
from __future__ import annotations

from .segments import Segment


def build_edges(my_ip: str, hosts: list[dict], segments: list[Segment], *, link_subnet=None,
                classes=None) -> list[tuple[str, str, str, str]]:
    edges: list[tuple[str, str, str, str]] = []
    lan = f"lan:{link_subnet or 'scanner-link'}"
    edges.append((my_ip, lan, "l2", "scanner interface"))
    member_of: dict[str, str] = {}
    for s in segments:
        if s.kind == "in-scope" and not s.local:
            for m in s.members:
                member_of[m] = f"{'seg' if s.prefix_known else 'group'}:{s.cidr}"
    ips = {h["ip"] for h in hosts}
    for h in hosts:
        ip = h["ip"]
        if ip != my_ip and ip not in member_of:
            kind = "l2" if h.get("verdict") == "CONFIRMED_ONLINK" else "attachment-unknown"
            edges.append((lan, ip, kind, ",".join(h["discovery_methods"][:3])))
    for ip, c in (classes or {}).items():
        for port, why in c.behind_ports.items():
            endpoint = f"endpoint:{ip}:{port}/tcp"
            backend = f"unknown-backend:{ip}:{port}/tcp"
            edges.append((ip, endpoint, "publishes", "observed open TCP endpoint"))
            edges.append((endpoint, backend, "forwards" if c.behind_status.get(port) == "confirmed"
                          else "forwarding-hypothesis", why))
    for ip, node in member_of.items():
        edges.append((node, ip, "member", "behind router"))
    for s in segments:
        if s.kind == "in-scope" and not s.local:
            node, prev = f"{'seg' if s.prefix_known else 'group'}:{s.cidr}", lan
            depth = len(s.path)
            for t in range(1, max(depth, len(s.path)) + 1):
                hop = s.path[t - 1] if t <= len(s.path) else None
                name = hop if hop and hop in ips else (hop or f"?{s.cidr}@{t}")
                edges.append((prev, name, "route" if hop else "path-gap", f"observed hop {t}" if hop else f"unobserved position {t}; router identity unknown"))
                prev = name
            edges.append((prev, node, "route" if s.prefix_known else "attachment-evidence", "; ".join(s.evidence)[:200]))
        elif s.kind == "outside-scope":
            edges.append((my_ip, f"address:{s.members[0]}", "address-observed",
                          "; ".join(s.evidence)[:200]))
    return edges
