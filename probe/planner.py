"""The planner: the part of the probe that decides WHAT to do, so no human has to.

It has four jobs, all driven by evidence and by the runtime configuration, never by anything site-specific:

  1. inspect   -> Environment: what the probe can see of its own situation (scope, interface, gateway, privileges,
                  available tools, size of the problem). Derives the tuning a person used to pick by hand (time budget,
                  port depth) from that.
  2. choose    -> every technique is registered with a PRECONDITION (when is it applicable?) and an expected benefit.
                  The planner evaluates each against the environment and the evidence so far and records a Decision:
                  run / skip / defer, with the reason. The decision journal is part of the final report.
  3. measure   -> after a technique runs, the planner compares what the probe knew before and after (information gain).
                  A technique that adds nothing is not repeated; one that adds something earns another round.
  4. question  -> open_questions() turns the current evidence into the list of things still unresolved (a host with no
                  MAC, an unresolved verdict, a silent address that something answered for...). Follow-up techniques
                  are chosen to address those specific questions; discovery ends when a full round of follow-ups
                  answers none of them (the limit of what is discoverable from this vantage point).

The planner NEVER touches the scope. Scope is frozen by ScopeGuard; the planner only chooses among techniques that
the guard then judges packet by packet.
"""
from __future__ import annotations

import ipaddress
import shutil
import time
from dataclasses import dataclass, field
from typing import Callable

# ---- environment ------------------------------------------------------------------------------------------


@dataclass
class Environment:
    scope: list[str]
    addresses: int
    scanner_ip: str | None
    link_subnet: str | None
    gateway_ip: str | None
    gateway_in_scope: bool
    gateway_mac: str | None = None
    scope_on_link: bool = False           # the whole scope lies inside the scanner's own interface subnet
    link_wider_than_scope: bool = False   # same link carries addresses the fence excludes (recorded, never probed)
    raw_send: bool = True                 # can we craft frames (privileges + capture library)?
    nmap: bool = False
    ipv6_scope: bool = False
    derived: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _nmap_available() -> bool:
    """Same lookup the tool itself uses (PATH, then the standard install folders): an elevated process often has a
    different PATH, and a false 'nmap missing' silently disables service identification, UDP and OS detection."""
    if shutil.which("nmap"):
        return True
    from .tools import nmap_tool
    return bool(nmap_tool.find_nmap())


def inspect(scope, transport, *, gateway_mac: str | None = None, raw_send: bool = True) -> Environment:
    nets = [n for n in scope.networks]
    v4 = [n for n in nets if n.version == 4]
    addrs = sum(max(0, n.num_addresses - 2) for n in v4)
    link = None
    try:
        link = ipaddress.ip_network(transport.my_network, strict=False) if transport.my_network else None
    except ValueError:
        link = None
    gw = transport.gateway_ip
    env = Environment(
        scope=[str(n) for n in nets], addresses=addrs, scanner_ip=transport.my_ip,
        link_subnet=str(link) if link else None, gateway_ip=gw,
        gateway_in_scope=bool(gw and scope.in_scope(gw)), gateway_mac=gateway_mac,
        scope_on_link=bool(link and v4 and all(n.subnet_of(link) for n in v4)),
        link_wider_than_scope=bool(link and v4 and link.version == 4 and not any(
            link.subnet_of(n) for n in ipaddress.collapse_addresses(v4))),
        raw_send=raw_send, nmap=_nmap_available(), ipv6_scope=any(n.version == 6 for n in nets))
    return env


def derive_tuning(env: Environment, *, budget_s: float | None, tcp_ports: int | None,
                  rate_pps: int | None) -> dict:
    """What a person used to set with --budget/--ports/--rate, derived from the size of the problem instead.
    Explicit operator values still win (an override is the operator's right); the default is autonomous."""
    a = max(1, env.addresses)
    budget = budget_s if budget_s else float(min(300, max(60, round(0.66 * a))))
    ports = tcp_ports if tcp_ports else (200 if a <= 1024 else 100 if a <= 4096 else 40)
    rate = rate_pps if rate_pps else (2500 if a <= 4096 else 3500)
    return {"budget_s": budget, "tcp_ports": ports, "rate_pps": rate,
            "basis": f"{a} addresses in scope: budget ~0.66 s/address clamped to 60-300 s; port depth shrinks as the scope grows"}


# ---- knowledge / information gain ------------------------------------------------------------------------


def knowledge(ev, ports_open: int, silent: int) -> dict:
    """A comparable snapshot of what is known. Information gain = any of these growing (silent shrinking)."""
    return {
        "hosts": len(ev.visible), "macs": len(ev.arp_mac), "open_ports": ports_open,
        "forwarders": len(ev.forwarders), "via": len(ev.via), "hosted_by": len(getattr(ev, "hosted_by", {}) or {}),
        "hops": sum(len(h) for h in ev.hops.values()), "foreign": len(ev.foreign), "silent": silent,
        "masks": len(ev.masks), "dhcp_prefixes": len(ev.dhcp_nets),
        "forwarded_port_checks": sum(n >= 2 for n in ev.ttl1_synack.values()) + sum(n >= 2 for n in ev.ttl1_exceeded.values()),
    }


def gain(before: dict, after: dict) -> dict:
    out = {k: after[k] - before[k] for k in after if k != "silent" and after[k] != before.get(k, 0)}
    if after["silent"] < before.get("silent", after["silent"]):
        out["silent"] = after["silent"] - before["silent"]
    return out


# ---- decisions ------------------------------------------------------------------------------------------------


@dataclass
class Decision:
    technique: str
    action: str                   # run | skip | defer
    reason: str
    round: int = 0
    gain: dict | None = None
    seconds: float | None = None
    at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {"technique": self.technique, "action": self.action, "reason": self.reason, "round": self.round,
                "gain": self.gain, "seconds": self.seconds}


@dataclass
class Technique:
    name: str
    purpose: str
    run: Callable[[], None]
    applicable: Callable[[Environment, "State"], tuple[bool, str]]
    answers: tuple[str, ...] = ()          # open-question kinds this technique can address
    repeatable: bool = False               # may run again in a follow-up round if the previous run gained something
    phase: str = "core"                    # core | followup | final


@dataclass
class State:
    """What the planner has seen so far; techniques' preconditions read this (never the network)."""
    env: Environment
    answered: int = 0
    silent: int = 0
    arp_known: int = 0
    forwarders: int = 0
    ports_open: int = 0
    unresolved: int = 0
    held_segments: int = 0
    catchall: int = 0
    hosted: int = 0
    remaining_s: float = 0.0


class Planner:
    def __init__(self, env: Environment):
        self.env = env
        self.techniques: dict[str, Technique] = {}
        self.journal: list[Decision] = []
        self.runs: dict[str, int] = {}
        self.last_gain: dict[str, dict] = {}
        self.round = 0

    def register(self, t: Technique) -> None:
        self.techniques[t.name] = t

    def decide(self, name: str, state: State, *, min_time_s: float = 0.0) -> bool:
        t = self.techniques[name]
        if min_time_s > 0 and state.remaining_s < min_time_s:
            self.journal.append(Decision(name, "skip", f"time budget: {state.remaining_s:.0f}s left, needs ~{min_time_s:.0f}s",
                                         self.round))
            return False
        ok, why = t.applicable(self.env, state)
        if not ok:
            self.journal.append(Decision(name, "skip", why, self.round))
            return False
        if self.runs.get(name) and not t.repeatable:
            self.journal.append(Decision(name, "skip", "already run and not repeatable", self.round))
            return False
        if self.runs.get(name) and not self.last_gain.get(name):
            self.journal.append(Decision(name, "skip", "previous run added no information", self.round))
            return False
        return True

    def execute(self, name: str, state: State, snapshot: Callable[[], dict], *, reason: str = "") -> dict:
        t = self.techniques[name]
        before, t0 = snapshot(), time.time()
        t.run()
        after = snapshot()
        g = gain(before, after)
        self.runs[name] = self.runs.get(name, 0) + 1
        self.last_gain[name] = g
        _ok, why = t.applicable(self.env, state)
        self.journal.append(Decision(name, "run", reason or why, self.round, g, round(time.time() - t0, 2)))
        return g

    def note(self, name: str, action: str, reason: str) -> None:
        self.journal.append(Decision(name, action, reason, self.round))

    def as_list(self) -> list[dict]:
        return [d.as_dict() for d in self.journal]


# ---- open questions ----------------------------------------------------------------------------------------------

Q_NO_MAC = "answers-l3-but-no-mac"
Q_UNRESOLVED = "verdict-unresolved"
Q_CONFLICT = "conflicting-evidence"
Q_SUSPECT = "suspected-not-proven"
Q_ARP_LOSS = "arp-responder-never-probed"
Q_SILENT_BEHIND = "silent-addresses-behind-forwarder"
Q_PREFIX = "backend-prefix-unknown"
Q_BACKEND = "forwarded-service-backend-unknown"


@dataclass
class Question:
    kind: str
    subject: str
    detail: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "subject": self.subject, "detail": self.detail}


def open_questions(classes: dict, ev, *, blitzed: set[str], silent: list[str]) -> list[Question]:
    """Everything the evidence says is still not settled. Empty list == nothing left that more probing could settle."""
    qs: list[Question] = []
    for ip, c in classes.items():
        v = c.verdict
        if v == "CONFLICT":
            qs.append(Question(Q_CONFLICT, ip, "; ".join(c.contradicts)[:200] or "contradictory evidence"))
        elif v == "UNRESOLVED":
            qs.append(Question(Q_UNRESOLVED, ip, "answered but its on-link/separate status is not proven"))
        elif v.startswith("SUSPECTED"):
            qs.append(Question(Q_SUSPECT, ip, "; ".join(c.proof + c.support)[:200]))
        if ip in ev.arp_failed:
            qs.append(Question(Q_NO_MAC, ip, "answers at layer 3 but never at ARP even after retries"))
        if (v == "CONFIRMED_SEPARATE" or "forwarder" in c.roles) and ip not in ev.masks:
            qs.append(Question(Q_PREFIX, ip, "separate attachment observed; no address/mask or connected-prefix evidence"))
        for port, status in c.behind_status.items():
            if status == "verified-local":
                continue        # settled: a TTL=1 SYN was answered locally -- not a forwarded service, nothing open
            qs.append(Question(Q_BACKEND, f"{ip}:{port}", f"{status} forwarding; backend address, prefix and mechanism unknown"))
    for ip in ev.arp_mac:
        if ip not in blitzed:
            qs.append(Question(Q_ARP_LOSS, ip, "ARP responder that has not had the full probe suite"))
    if silent and (ev.forwarders):
        qs.append(Question(Q_SILENT_BEHIND, f"{len(silent)} address(es)",
                           "silent addresses remain while forwarders exist: they may answer only through a forwarder"))
    return qs
