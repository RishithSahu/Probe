"""The orchestrator: turns the probe's findings into coordinated work for specialist agents.

It owns no network access at all. Its inputs are the probe's change feed (events) and inventory; its outputs are tasks.

  1. consume    reads every event since a persisted cursor, in order, and only advances the cursor after the event was
                handled (a crash or an error re-delivers; handlers are idempotent), so no discovery event is missed
  2. inventory  keeps ONE inventory: the probe's store is the source of truth, rebuilt from events and re-synchronised
                from the store, so a missed or reordered event cannot leave the inventory wrong
  3. dedupe     a task's key is derived from what it is about (kind:address:port), so the same finding reported twice,
                by two scans, or by two agents, is one task; a service that is identified later REPLACES the generic task
  4. assign     each finding is routed to the specialist kind that handles that service; an agent leases a task atomically
  5. track      leases expire and are re-offered, failures are retried up to MAX_ATTEMPTS then reported, nothing is
                silently dropped; status() accounts for every task
  6. enforce    a task is created only for an address the scope allows now, and is re-checked when leased. Tasks that need a
                human decision (examining a challenge artifact) are created BLOCKED and cannot be leased until approved.
                The scope is never touched.
"""
from __future__ import annotations

import json
import logging
import time

from . import netutil
from .scope import ScopeGuard
from .store import Store

logger = logging.getLogger("probe.orchestrator")

MAX_ATTEMPTS = 3
LEASE_S = 120

# service name -> specialist kind. Names are nmap's service names; anything unlisted goes to the generic service agent.
SPECIALISTS: dict[str, set[str]] = {
    "web": {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "http-mgmt", "sun-answerbook", "wsman", "wsmans"},
    "ssh": {"ssh"},
    "database": {"mysql", "postgresql", "ms-sql-s", "oracle", "mongod", "mongodb", "redis", "memcache", "cassandra", "couchdb"},
    "file-share": {"microsoft-ds", "netbios-ssn", "smb", "ftp", "nfs", "rpcbind", "tftp", "rsync"},
    "directory-and-name": {"domain", "ldap", "ldaps", "kerberos-sec", "kpasswd5", "msrpc", "snmp", "ntp"},
    "remote-access": {"ms-wbt-server", "vnc", "telnet", "rdp", "x11"},
}
EVENT_TYPES = ("host.discovered", "host.updated", "service.discovered", "service.updated", "segment.found", "network.candidate",
               "lead.recorded", "scan.finished")


def specialist_for(service: str | None, port: int | None = None) -> str:
    name = (service or "").lower().rstrip("?")
    for kind, names in SPECIALISTS.items():
        if name in names:
            return kind
    if not name and port in (80, 443, 8000, 8080, 8443):
        return "web"
    return "service-generic"


class Orchestrator:
    def __init__(self, store: Store, scope: ScopeGuard, *, name: str = "orchestrator"):
        self.store, self.scope, self.name = store, scope, name
        self.handled = 0

    # ---- 1. consume the change feed -------------------------------------------------------------------
    def _cursor(self) -> int:
        return int(self.store.meta().get("orchestrator.cursor") or 0)

    def consume(self, page: int = 500) -> int:
        """Handle every pending event in order. The cursor moves only past events that were handled."""
        n = 0
        while True:
            events = self.store.events_since(self._cursor(), page)
            if not events:
                break
            for ev in events:
                try:
                    self._handle(ev)
                except Exception:                       # do not skip it: stop here and re-deliver next time
                    logger.exception("event %s not handled; will be redelivered", ev["id"])
                    return n
                self.store.set_meta("orchestrator.cursor", ev["id"])
                n += 1
        self.handled += n
        return n

    def _handle(self, ev: dict) -> None:
        t, p = ev["type"], ev["payload"]
        if t in ("service.discovered", "service.updated"):
            self.offer_service(p["ip"], p["port"], p.get("proto", "tcp"), p.get("service"), p.get("product"), ev["id"])
        elif t in ("host.discovered", "host.updated"):
            if p.get("roles"):
                self.offer(f"network-structure:{p['ip']}", "network-structure", {"ip": p["ip"], "why": p["roles"]}, p["ip"])
        elif t == "segment.found" or t == "network.candidate":
            self.offer(f"network-structure:{p['cidr']}", "network-structure",
                       {"cidr": p["cidr"], "status": p.get("status"), "evidence": p.get("evidence")}, None,
                       probing_allowed=False)
        elif t == "lead.recorded" and p.get("source") == "challenge-artifact":
            self.offer(f"challenge-artifact:{p['address']}", "challenge-artifact", p, p["address"].split(":")[0], blocked=True)
        # scan.finished and anything else: nothing to assign, but it is still consumed (cursor advances)

    # ---- 2/3/4. inventory, dedupe, assign ---------------------------------------------------------------
    def sync(self) -> int:
        """Re-derive tasks from the store itself: guarantees the orchestrator's picture equals the probe's even if an
        event was emitted before the orchestrator started. Idempotent."""
        made = 0
        live: set[str] = set()
        for h in self.store.hosts():
            for pr in h.get("open_ports") or []:
                live.add(f"{h['ip']}:{pr['port']}/{pr.get('proto', 'tcp')}")
                made += self.offer_service(h["ip"], pr["port"], pr.get("proto", "tcp"), pr.get("service"), pr.get("product"))
        self._retire_stale(live)
        return made

    def _retire_stale(self, live: set[str]) -> int:
        """Tasks about an endpoint the latest inventory no longer contains (a host that left, a false sighting) are marked
        'stale', not deleted: still on record, but never offered to an agent."""
        report = self.store.meta().get("report") or {}
        flagged = {f"{c['address']}:{c['port']}" for c in report.get("challenge_artifact_candidates", [])}
        n = 0
        for row in self.store.query("SELECT key, type FROM tasks WHERE status IN ('pending','blocked')"):
            kind, _, rest = row["key"].partition(":")
            if kind == "challenge-artifact":
                gone = report and rest not in flagged
            elif kind in (*SPECIALISTS, "service-generic"):
                gone = bool(live) and rest not in live
            else:
                continue
            if gone:
                self.store.exec("UPDATE tasks SET status='stale' WHERE key=?", (row["key"],))
                n += 1
        return n

    def eligible(self, ip: str | None) -> tuple[bool, str]:
        if ip is None:
            return True, "no target address"
        if not self.scope.in_scope(ip):
            return False, "outside the authorised scope"
        if self.scope.is_held(ip):
            return False, "inside a held segment"
        return True, "ok"

    def offer_service(self, ip: str, port: int, proto: str, service: str | None, product: str | None,
                      event_id: int | None = None) -> int:
        kind = specialist_for(service, port)
        key = f"{kind}:{ip}:{port}/{proto}"
        made = self.offer(key, kind, {"ip": ip, "port": port, "proto": proto, "service": service, "product": product}, ip,
                          event_id=event_id)
        # a service identified later replaces the generic/other task for the same endpoint (no duplicate work)
        for row in self.store.query("SELECT key, payload FROM tasks WHERE key != ? AND status IN ('pending','blocked')", (key,)):
            if row["key"].split(":", 1)[0] not in (*SPECIALISTS, "service-generic"):
                continue
            p = json.loads(row["payload"])                    # identity is the parsed address and port, never a string suffix
            if netutil.same_ip(p.get("ip"), ip) and p.get("port") == port and p.get("proto", "tcp") == proto:
                self.store.exec("UPDATE tasks SET status='superseded' WHERE key=?", (row["key"],))
        return made

    def offer(self, key: str, kind: str, payload: dict, target_ip: str | None, *, blocked: bool = False,
              probing_allowed: bool = True, event_id: int | None = None) -> int:
        ok, why = self.eligible(target_ip)
        if not ok:
            self.store.add_event("task.refused", {"key": key, "reason": why})
            return 0
        if not probing_allowed:
            payload = {**payload, "note": "recorded only: nothing may be probed in this network without authorisation"}
            blocked = True
        status = "blocked" if blocked else "pending"
        cur = self.store.exec("INSERT OR IGNORE INTO tasks (key, scan_id, type, payload, status, attempts, created) VALUES (?,?,?,?,?,0,?)",
                              (key, None, kind, json.dumps({**payload, "event": event_id}), status, time.time()))
        return 1 if cur.rowcount else 0

    def approve(self, key: str, approved_by: str) -> dict:
        """A human releases a blocked task. Recorded; the orchestrator never does this itself."""
        cur = self.store.exec("UPDATE tasks SET status='pending' WHERE key=? AND status='blocked'", (key,))
        self.store.add_event("task.approved", {"key": key, "by": approved_by})
        return {"ok": bool(cur.rowcount)}

    # ---- 5. lease / complete / reap ---------------------------------------------------------------------
    def reap(self) -> int:
        now = time.time()
        cur = self.store.exec("UPDATE tasks SET status=CASE WHEN attempts>=? THEN 'failed' ELSE 'pending' END, agent=NULL "
                              "WHERE status='leased' AND lease_expires < ?", (MAX_ATTEMPTS, now))
        return cur.rowcount

    def lease(self, kind: str, agent: str, ttl_s: float = LEASE_S) -> dict | None:
        self.reap()
        now = time.time()
        with self.store._lock:                                       # atomic against other agents
            rows = self.store._conn.execute(
                "SELECT key, payload, attempts FROM tasks WHERE type=? AND status='pending' ORDER BY created LIMIT 20", (kind,)).fetchall()
            for r in rows:
                payload = json.loads(r["payload"])
                ok, why = self.eligible(payload.get("ip"))
                if not ok:                                           # scope re-checked at lease time
                    self.store._conn.execute("UPDATE tasks SET status='failed', result=? WHERE key=?",
                                             (json.dumps({"refused": why}), r["key"]))
                    continue
                self.store._conn.execute("UPDATE tasks SET status='leased', agent=?, lease_expires=?, attempts=attempts+1 WHERE key=?",
                                         (agent, now + ttl_s, r["key"]))
                self.store._conn.commit()
                return {"key": r["key"], "type": kind, "payload": payload, "attempt": r["attempts"] + 1, "lease_s": ttl_s}
            self.store._conn.commit()
        return None

    def complete(self, key: str, agent: str, result: dict | None = None, ok: bool = True) -> dict:
        row = self.store.query("SELECT agent, status, attempts FROM tasks WHERE key=?", (key,))
        if not row or row[0]["agent"] != agent or row[0]["status"] != "leased":
            return {"ok": False, "error": "task is not leased to this agent"}
        status = "done" if ok else ("failed" if row[0]["attempts"] >= MAX_ATTEMPTS else "pending")
        self.store.exec("UPDATE tasks SET status=?, finished=?, result=?, agent=CASE WHEN ?='pending' THEN NULL ELSE agent END WHERE key=?",
                        (status, time.time(), json.dumps(result or {}), status, key))
        self.store.add_event("task.done" if ok else "task.failed", {"key": key, "agent": agent, "final": status})
        return {"ok": True, "status": status}

    # ---- 6. accounting ----------------------------------------------------------------------------------
    def status(self) -> dict:
        rows = self.store.query("SELECT type, status, COUNT(*) AS n FROM tasks GROUP BY type, status")
        by: dict[str, dict[str, int]] = {}
        for r in rows:
            by.setdefault(r["type"], {})[r["status"]] = r["n"]
        total = sum(r["n"] for r in rows)
        failed = self.store.query("SELECT key, attempts, result FROM tasks WHERE status='failed'")
        return {"cursor": self._cursor(), "events_handled": self.handled, "tasks": total, "by_kind": by,
                "failed": failed, "blocked": [r["key"] for r in self.store.query("SELECT key FROM tasks WHERE status='blocked'")]}
