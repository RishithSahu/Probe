"""The final, evidence-backed inventory and topology report -- produced by the probe itself at the end of every run.

Nothing in it is asserted without the observation that supports it: each device carries its verdict and the rules
that proved it, each segment its evidence, and the report lists what could NOT be established and why. It contains
discovery results only (no vulnerability assessment).
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def _confidence(verdicts: list[str]) -> str:
    if any(v.startswith("CONFIRMED") for v in verdicts):
        return "confirmed"
    if any(v.startswith("SUSPECTED") for v in verdicts):
        return "suspected"
    return "unverified"


def _status(verdict: str) -> str:
    return "confirmed" if verdict.startswith("CONFIRMED") else "suspected" if verdict.startswith("SUSPECTED") else "unverified"


def build(*, scope: list[str], env: dict, tuning: dict, hosts: list[dict], segments: list[dict], edges: list[dict],
          leads: list[dict], correlation: dict, limits: dict, decisions: list[dict], timings: dict, notes: list[str],
          safety: dict, crosscheck: dict | None = None, challenge: list[dict] | None = None,
          challenge_rules: dict | None = None, unanswered: dict | None = None) -> dict:
    import ipaddress
    by_ip = {h["ip"]: h for h in hosts}
    in_scope_segs = sorted((g for g in segments if g["kind"] == "in-scope"), key=lambda g: len(g["hosts"]))

    def segment_of(ip: str) -> str:
        for g in in_scope_segs:
            if ip in g["hosts"]:
                return g["cidr"] if (g.get("extra") or {}).get("prefix_known") else f"address group {g['cidr']} (prefix unknown)"
        for c in scope:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(c, strict=False):
                return f"{c} (authorised scope)"
        return "unknown"

    devices = []
    for d in correlation["devices"]:
        rows = [by_ip[a] for a in d["addresses"] if a in by_ip]
        devices.append({
            **d, "confidence": _confidence(d["verdicts"]), "segment": segment_of(d["addresses"][0]),
            "evidence": [{"address": r["ip"], "verdict": r["verdict"], "reasons": r.get("reasons") or [],
                          "seen_by": r.get("visible_to") or [], "methods": r.get("discovery_methods") or [],
                          "first_seen": r.get("first_seen")} for r in rows],
            "services": [{"address": r["ip"], "port": p["port"], "proto": p.get("proto", "tcp"), "service": p.get("service"),
                          "product": p.get("product"), "version": p.get("version"), "method": p.get("method"),
                          "identification": p.get("identification"), "ident_note": p.get("ident_note"),
                          "found_at": p.get("found_at"), "observations": json.loads(p["scripts"]) if isinstance(p.get("scripts"), str) else p.get("scripts", {})} for r in rows for p in (r.get("open_ports") or [])]})
    findings = [{"address": l["address"], "kind": l["source"], "evidence": l["evidence"], "status": "suspected, not proven"
                 if str(l["source"]).startswith(("anomaly", "unconfirmed")) else "recorded"}
                for l in leads]
    candidates = []
    for g in segments:
        ex = g.get("extra") or {}
        candidates.append({
            "proposed_cidr": g["cidr"], "status": _status(g["verdict"]), "verdict": g["verdict"],
            "scope_relation": "inside the authorised scope" if g["kind"] == "in-scope" else "OUTSIDE the authorised scope",
            "prefix_known": ex.get("prefix_known"), "basis": ex.get("basis"), "evidence": g["evidence"][:6], "via": g["via"],
            "members": g["hosts"],
            "probing": ("performed within the authorised scope" if g["kind"] == "in-scope" and g["state"] != "held" else
                        "none: recorded only until explicit authorisation is received")})
    outside = [c for c in candidates if c["scope_relation"].startswith("OUTSIDE")]
    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "authorised_scope": scope,
        "scope_immutable": True,
        "environment": env, "derived_settings": tuning,
        "summary": {"addresses_answering": len(hosts), "devices": correlation["device_count"],
                    "duplicate_addresses_merged": correlation["duplicates_removed"],
                    "conflicts": len(correlation["conflicts"]), "segments": len(segments),
                    "converged": limits["converged"],
                    "network_candidates": {k: sum(1 for c in outside if c["status"] == k)
                                           for k in ("confirmed", "suspected", "unverified")},
                    "challenge_artifact_candidates": len(challenge or [])},
        "devices": devices, "merged_devices": correlation["merged"], "conflicts": correlation["conflicts"],
        "segments": [{"cidr": s["cidr"], "prefix": s["cidr"] if (s.get("extra") or {}).get("prefix_known") else None,
                      "prefix_known": bool((s.get("extra") or {}).get("prefix_known")),
                      "representation": "prefix" if (s.get("extra") or {}).get("prefix_known") else "address-group-or-slice",
                      "kind": s["kind"], "state": s["state"], "verdict": s["verdict"], "via": s["via"],
                      "hosts": s["hosts"], "evidence": s["evidence"], "hidden": (s.get("extra") or {}).get("hidden")}
                     for s in segments],
        "network_candidates": candidates,
        "topology": [{"a": e["a"], "b": e["b"], "kind": e["kind"], "evidence": e["evidence"]} for e in edges],
        "findings": findings,
        "os_view_crosscheck": crosscheck or {}, "unanswered_addresses": unanswered or {},
        "challenge_rules": challenge_rules or {}, "challenge_artifact_candidates": challenge or [],
        "limits_of_visibility": limits,
        "decision_journal": decisions,
        "timings": timings, "notes": notes, "safety": safety,
    }


def to_markdown(r: dict) -> str:
    s = r["summary"]
    out = ["# Network discovery report", "",
           f"Generated {r['generated']}. Authorised scope (immutable during the run): `{', '.join(r['authorised_scope'])}`.", "",
           "## Summary", "",
           f"- {s['addresses_answering']} addresses answered, which correlate to **{s['devices']} devices** "
           f"({s['duplicate_addresses_merged']} duplicate address(es) merged, {s['conflicts']} conflict(s) reported)",
           f"- {s['segments']} segment(s) recorded; discovery {'converged' if s['converged'] else 'stopped on the time budget'}",
           f"- Safety: {r['safety']}", "", "## Segments", ""]
    for g in r["segments"]:
        out.append(f"- `{g['cidr']}` ({g['kind']}, {g['state']}, {g['verdict']}) via {g['via'] or '-'}")
        for e in g["evidence"][:3]:
            out.append(f"  - {e}")
    out += ["", "## Devices", "", "| Address(es) | MAC | Hostname | Vendor / OS | Confidence | Segment | Open ports | Methods |",
            "|---|---|---|---|---|---|---|---|"]
    for d in r["devices"]:
        osd = d.get("os_detail") or d.get("os_guess") or "-"
        out.append(f"| {', '.join(d['addresses'])} | {d['mac'] or '-'} | {d.get('hostname') or '-'} | {d['vendor'] or '-'} / {osd} | "
                   f"{d['confidence']} | {d['segment']} | {', '.join(map(str, d['open_ports'][:12])) or '-'} | "
                   f"{', '.join(d.get('discovery_methods') or [])} |")
    out += ["", "## Network candidates (candidates outside the scope are never probed)", "",
            "| Proposed CIDR | Status | Relation to scope | Basis | Probing |", "|---|---|---|---|---|"]
    for c in r["network_candidates"]:
        out.append(f"| {c['proposed_cidr']} | {c['status']} | {c['scope_relation']} | {c['basis'] or '-'} | {c['probing']} |")
    if r["challenge_artifact_candidates"]:
        out += ["", "## Challenge artifact candidates (locations only; values withheld)", ""]
        for c in r["challenge_artifact_candidates"]:
            out.append(f"- {c['address']}:{c['port']}/{c['proto']} [{c['field']}] {c['shape']} -- {c['needs']}")
    out += ["", "Challenge rules applied: " + str(r["challenge_rules"].get("applied_reading", "")), ""]
    if r["findings"]:
        out += ["", "## Findings (leads)", ""]
        for f in r["findings"]:
            out.append(f"- **{f['address']}** [{f['kind']}, {f['status']}]: {f['evidence']}")
    if r["conflicts"]:
        out += ["", "## Conflicting evidence", ""]
        for c in r["conflicts"]:
            out.append(f"- {c['address']}: MACs {', '.join(c['macs'])} -> {c['resolution']}")
    out += ["", "## Limits of visibility", "", r["limits_of_visibility"]["statement"], ""]
    for l in r["limits_of_visibility"]["limits"]:
        out.append(f"- **{l['kind']}**: {l['what']}. Why: {l['why']}. What would change it: {l['would_change']}.")
    comp = r.get("completeness")
    if comp:
        out += ["", "## Discovery completeness", "",
                f"**{comp['status']}** ({comp['stop_reason']}): {comp['rounds_used']}/{comp['max_rounds']} round(s), "
                f"{comp['elapsed_s']:.0f}/{comp['max_budget_s']:.0f}s of the completeness budget, "
                f"{comp['items_resolved']} item(s) resolved, {len(comp['items_unresolved'])} unresolved.", "",
                comp["note"], ""]
        if comp["items_unresolved"]:
            out += ["| Item | Kind | Open since round | Detail |", "|---|---|---|---|"]
            for it in comp["items_unresolved"]:
                out.append(f"| {it['key']} | {it['kind']} | {it['open_since_round']} | {it['detail'][:200]} |")
    out += ["", "## How the probe decided what to do", "", "| Round | Technique | Action | Reason | Gain |", "|---|---|---|---|---|"]
    for d in r["decision_journal"]:
        out.append(f"| {d['round']} | {d['technique']} | {d['action']} | {d['reason']} | {d['gain'] or ''} |")
    return "\n".join(out) + "\n"


def write(report: dict, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    j, m = directory / "report.json", directory / "report.md"
    j.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    m.write_text(to_markdown(report), encoding="utf-8")
    return j, m
