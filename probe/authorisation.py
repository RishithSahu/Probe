"""Explicit range grants, separate from observations and from the configured scope."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path


def scope_digest(cidrs) -> str:
    nets = [ipaddress.ip_network(str(n), strict=True) for n in cidrs]
    canonical = [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in nets if n.version == version)]
    return hashlib.sha256(json.dumps(canonical).encode()).hexdigest()


def verify(path: Path, cidrs) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    grants = []
    for g in data.get("grants", []):
        if not {"discovery", "inventory"} <= set(g.get("purposes", [])):
            continue
        if not all(g.get(k) for k in ("authority", "reference", "prefix_evidence")):
            continue
        grants.append(ipaddress.ip_network(g["cidr"], strict=True))
    requested = [ipaddress.ip_network(str(c), strict=True) for c in cidrs]
    allowed = [n for version in (4, 6) for n in ipaddress.collapse_addresses(
        n for n in grants if n.version == version)]
    for n in requested:
        if not any(n.version == g.version and n.subnet_of(g) for g in allowed):
            raise ValueError(f"{n} has no explicit discovery/inventory grant in {path}")
    return {"path": str(Path(path).resolve()), "scope_digest": scope_digest(requested),
            "scope": [str(n) for n in requested], "grants": data["grants"],
            "leads": data.get("leads", []), "pending": data.get("pending", []),
            "method_grants": data.get("method_grants", [])}


def header_test_grant(snapshot: dict, ip: str, port: int) -> dict | None:
    for g in snapshot.get("method_grants", []):
        if g.get("method") != "read-only-proxy-header-test" or g.get("target_ip") != ip or g.get("target_port") != port:
            continue
        if not g.get("authority") or not g.get("reference") or g.get("header_name") != "X-Forwarded-For":
            raise ValueError("proxy-header test lacks an explicit scoped grant")
        value = str(ipaddress.IPv4Address(g["header_value"]))
        if not (1 <= g.get("max_requests", 0) <= 12):
            raise ValueError("proxy-header test request bound is invalid")
        return {**g, "header_value": value}
    return None
