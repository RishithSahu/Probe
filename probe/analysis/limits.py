"""Limits of visibility: say what this vantage point CANNOT establish, and why, instead of implying completeness.

Discovery is finished when (a) the last adaptive round of follow-up techniques changed nothing and (b) every question
still open is one that no technique the probe is allowed to use could settle. This module produces that statement
from the evidence: each limit names the reason it is a limit and what would change it (a person's decision, a
different vantage point, a different tool), never "we found everything".
"""
from __future__ import annotations


def analyse(*, env: dict, questions: list[dict], converged: bool, rounds: int, last_gain: dict, segments: list[dict],
            leads: list[dict], decisions: list[dict], stopped: dict, catchall: list[str], held_blocked: int,
            ipv6_ignored: bool, coverage: dict | None = None) -> dict:
    limits: list[dict] = []

    def add(kind: str, what: str, why: str, would_change: str):
        limits.append({"kind": kind, "what": what, "why": why, "would_change": would_change})

    groups: dict[str, list[str]] = {}
    for q in questions:
        groups.setdefault(q["kind"], []).append(q["subject"])
    for kind, subjects in sorted(groups.items()):
        add("unresolved-after-all-techniques", f"{len(subjects)} open question(s) of kind '{kind}': {', '.join(subjects[:8])}"
            + (" ..." if len(subjects) > 8 else ""),
            "the configured observation methods did not settle this question; this is not proof of undiscoverability",
            "a vantage point on the other side of the device, or an operator-authorised technique not in the probe's whitelist")

    out_of_scope = [s for s in segments if s["kind"] == "outside-scope"]
    for s in out_of_scope:
        add("outside-authorised-scope", f"outside-scope observation {s['cidr']} (see its evidence and prefix status)",
            "it is outside the authorised scope; the scope is immutable during discovery and discovering a network never "
            "grants permission to probe it", "a new run started by a person with that range written into its scope")
    held = [s for s in segments if s["kind"] == "in-scope" and s["state"] == "held"]
    for s in held:
        add("held-segment", f"segment {s['cidr']} was located but is held",
            "separate segments are classified and then left alone", "an operator restart that lists the range explicitly")
    if stopped:
        n_out = sum(1 for v in stopped.values() if "leaves the scope" in v)
        n_silent = len(stopped) - n_out
        if n_out:
            add("leash", f"{n_out} address(es) could only be reached through a router outside the scope",
                "the probe will not send past a router it cannot prove is inside the scope", "the router's address in the scope")
        if n_silent:
            add("leash", f"{n_silent} address(es) lie behind a router that never answered",
                "an unidentifiable next hop is not proven in scope", "operator-set tolerance for silent hops")
    if catchall:
        add("decoys", f"catch-all responder(s) {', '.join(sorted(catchall))} answer for addresses that belong to other devices",
            "an address answered by a catch-all cannot be distinguished from a real host by those answers",
            "ARP/MAC ownership evidence, or a vantage point past the responder")
    if not env.get("gateway_in_scope"):
        add("vantage", "no in-scope gateway: routed subnets cannot be explored",
            "only hosts on the scanner's own link are reachable with in-scope next hops", "a scope that includes the gateway")
    if env.get("link_wider_than_scope"):
        add("vantage", "the scanner's link is wider than the authorised scope",
            "the extra addresses are recorded from the interface configuration and never probed", "explicit authorisation")
    if not env.get("nmap"):
        add("tooling", "service/version enrichment unavailable (nmap not found)",
            "ports are known as open/closed only", "installing the optional tool")
    if ipv6_ignored:
        add("protocol", "IPv6 scope entries ignored", "IPv6 discovery needs multicast, which is outside scope-safe bounds",
            "a unicast-only IPv6 technique")
    for name, c in sorted((coverage or {}).items()):
        if c.get("covered", 0) < c.get("total", 0):
            add("partial-coverage", f"{name.upper()} identification reached {c['covered']} of {c['total']} hosts",
                "the stage has its own time budget (UDP closed-port replies are rate-limited by many stacks)",
                "a longer budget for this stage")
    if held_blocked:
        add("held-segment", f"{held_blocked} deep probe(s) refused inside held segments", "by design", "operator restart with the range in scope")
    for d in decisions:
        if d["action"] == "skip" and d["reason"].startswith(("nmap", "needs", "no ")):
            add("technique-unavailable", f"{d['technique']} skipped", d["reason"], "different environment")

    reached = converged
    return {"converged": converged, "follow_up_rounds": rounds, "last_round_gain": last_gain, "limits": limits,
            "statement": (f"Adaptive discovery stopped after {rounds} follow-up round(s): the last round added no new "
                          "information using the available methods. Remaining questions are explicitly unresolved; "
                          "this does not establish completeness of the physical topology."
                          if converged else
                          "Adaptive discovery is NOT converged: budget, round limits, missing evidence or unavailable "
                          "observation methods left work incomplete."),
            "reached_limit": reached}
