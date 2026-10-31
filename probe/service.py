"""The contract surface other agents (LangGraph nodes) use. Pure functions over the Store -- no packets here.

Everything returned is JSON-serialisable and stable (see docs/CONTRACT.md). The web app exposes these over HTTP
and probe.client wraps that HTTP API for Python callers, so a LangGraph process needs neither scapy nor admin rights.

The work ledger is what prevents re-runs: before doing a unit of work an agent claims its key; if the key is
already claimed or done, the agent skips it (and reuses the stored result when there is one).
"""
from __future__ import annotations

import time

from . import netutil
from .scope import ScopeGuard
from .store import Store

WEB_PORTS = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 3000, 5000, 7070, 9000, 9090, 49152}
WEB_SERVICE_HINTS = ("http", "ssl/http", "https", "www", "webcache")


class ProbeService:
    def __init__(self, store: Store, scope: ScopeGuard | None = None):
        self.store, self.scope = store, scope

    # ---- inventory --------------------------------------------------------------------
    def status(self) -> dict:
        return {**self.store.meta().get("status", {}), "last_scan": self.store.last_scan()}

    def hosts(self, *, held: bool | None = None, verdict: str | None = None, role: str | None = None,
              with_services: bool | None = None) -> list[dict]:
        out = []
        for h in self.store.hosts():
            if held is not None and h["held"] != held:
                continue
            if verdict and not h["verdict"].startswith(verdict):
                continue
            if role and role not in h["roles"]:
                continue
            if with_services is not None and bool(h["open_ports"]) != with_services:
                continue
            out.append(h)
        return out

    def host(self, ip: str) -> dict | None:
        target = netutil.norm_ip(ip)
        h = next((h for h in self.store.hosts() if netutil.norm_ip(h["ip"]) == target), None) if target else None
        if h is not None:
            h = {**h, "leads": self.store.leads_for_ip(target)}         # exact address join, never a prefix match
        return h

    def services(self, *, port: int | None = None, service: str | None = None, include_held: bool = False) -> list[dict]:
        out = []
        for h in self.store.hosts():
            if h["held"] and not include_held:
                continue
            for p in h["open_ports"]:
                if port is not None and p["port"] != port:
                    continue
                if service and (p["service"] or "").rstrip("?").lower() != service.rstrip("?").lower():
                    continue                                              # exact service name: 'http' is not 'https'/'http-proxy'
                out.append({"ip": h["ip"], "mac": h["mac"], "os_guess": h["os_guess"], **p})
        return out

    def web_targets(self) -> list[dict]:
        """Ready-made input for the web agent: every non-held host:port that looks like HTTP(S)."""
        out = []
        for s in self.services():
            svc = (s["service"] or "").lower()
            if s["port"] in WEB_PORTS or any(k in svc for k in WEB_SERVICE_HINTS):
                tls = s["port"] in (443, 8443) or "ssl" in svc or "https" in svc
                out.append({"ip": s["ip"], "port": s["port"], "url": f"{'https' if tls else 'http'}://{s['ip']}:{s['port']}/",
                            "service": s["service"], "product": s["product"], "version": s["version"],
                            "banner": s["banner"], "scripts": s["scripts"]})
        return out

    def segments(self) -> list[dict]:
        return self.store.segments()

    def leads(self) -> list[dict]:
        return self.store.leads()

    def pivots(self) -> list[dict]:
        """Hosts that forward IP / sit in front of another network: the interesting places to look next."""
        out = []
        for h in self.store.hosts():
            if "forwarder" in h["roles"] or any(r.startswith("R4") for r in h["reasons"]):
                out.append({"ip": h["ip"], "mac": h["mac"], "roles": h["roles"], "why": h["reasons"],
                            "services": [p["port"] for p in h["open_ports"]]})
        return out

    # ---- change feed ------------------------------------------------------------------------
    def events(self, since: int = 0, limit: int = 500) -> dict:
        ev = self.store.events_since(since, limit)
        return {"events": ev, "next": ev[-1]["id"] if ev else since}

    # ---- work ledger (prevents repeated work) -----------------------------------------------------
    def claim(self, key: str, agent: str, ttl_s: float = 600) -> dict:
        return self.store.claim(key, agent, ttl_s)

    def complete(self, key: str, agent: str, result: dict | None = None, ok: bool = True) -> dict:
        r = self.store.complete(key, agent, result, ok=ok)
        if r.get("ok"):
            self.store.add_event("work.done" if ok else "work.failed", {"key": key, "agent": agent})
        return r

    def claims(self, prefix: str = "") -> list[dict]:
        return self.store.claims(prefix)

    # ---- scope -----------------------------------------------------------------------------------------
    def check_scope(self, ip: str) -> dict:
        """May an agent send ANYTHING to this address? Other agents must ask (or import ScopeGuard) before acting."""
        if self.scope is None:
            return {"ip": ip, "in_scope": None, "held": None, "allowed": False, "reason": "scope unknown"}
        ins, held = self.scope.in_scope(ip), self.scope.is_held(ip)
        return {"ip": ip, "in_scope": ins, "held": held, "allowed": ins and not held,
                "reason": ("outside the authorised scope" if not ins else
                           "inside a held segment: no deeper probing until the network owner approves" if held else "ok"),
                "scope": [str(n) for n in self.scope.networks], "held_segments": self.scope.held}

    # ---- scan freshness ------------------------------------------------------------------------------------
    def scan_age(self) -> float | None:
        last = self.store.last_scan()
        return None if not last or not last["finished"] else time.time() - last["finished"]
