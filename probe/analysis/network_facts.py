"""Topology claims with provenance; address groups, routes and IP subnets are distinct."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re


def collect(hosts, ev, env, routes=()) -> list[dict]:
    facts = []
    scope = [ipaddress.ip_network(n) for n in env.get("scope", [])]

    def add(kind, source, evidence, *, prefix=None, address=None, **details):
        identity = f"{kind}:{source}:{prefix}:{address}"
        net = ipaddress.ip_network(prefix) if prefix else None
        relation = ("inside" if net and any(net.version == s.version and net.subnet_of(s) for s in scope)
                    else "overlaps" if net and any(net.version == s.version and net.overlaps(s) for s in scope)
                    else "outside" if net else "unknown")
        facts.append({"id": hashlib.sha256(identity.encode()).hexdigest()[:20], "kind": kind,
                      "source": source, "evidence": evidence, "prefix": prefix, "address": address,
                      "scope_relation": relation, **details})

    if env.get("link_subnet"):
        add("configured-interface-prefix", "scanner-os", "scanner interface address/mask", prefix=env["link_subnet"],
            state="configured", proves="interface configuration; not remote host liveness")
    for r in routes:
        n = ipaddress.ip_network(r.network, strict=False)
        if n.prefixlen == 0 or n.is_multicast or n.is_loopback or n.is_link_local:
            continue
        add("configured-route", f"scanner-os:interface-{r.if_index}", "local routing table", prefix=str(n),
            next_hop=r.gateway, state="configured", proves="route prefix; not a remote connected subnet")
    for prefix in ev.dhcp_nets:
        add("reported-dhcp-prefix", "captured-dhcp", "DHCP address and subnet-mask option", prefix=prefix,
            state="reported", proves="DHCP allocation statement; requires interface/context correlation")
    for h in hosts:
        for p in h.get("open_ports", []):
            source = f"{h['ip']}:{p['port']}/{p.get('proto','tcp')}"
            scripts = p.get("scripts") or {}
            if isinstance(scripts, str):
                scripts = json.loads(scripts)
            for script, output in scripts.items():
                for token in set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d)", output)):
                    try:
                        prefix = str(ipaddress.ip_network(token, strict=False))
                    except ValueError:
                        continue
                    add("reported-service-prefix", source + ":" + script, token, prefix=prefix, state="unverified",
                        proves="service referenced this prefix; not its location, reachability or authorisation")
        for reason in h.get("reasons", []):
            if reason.startswith("R8:"):
                add("forwarded-service", h["ip"], reason, state="observed", backend_prefix=None,
                    proves="forwarding behaviour for an endpoint; backend address/prefix and virtualisation type unknown")
    for address, reasons in ev.foreign.items():
        add("observed-or-referenced-address", "capture-or-service-metadata", sorted(reasons), address=address,
            state="unverified" if all("service output" in x for x in reasons) else "observed",
            proves="address only; no subnet prefix")
    return list({f['id']: f for f in facts}.values())
