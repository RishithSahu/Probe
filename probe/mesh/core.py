"""The mesh: how many Probe agents (clones) share one job and one inventory.

Roles
  hub     owns the plan, the task queue, the merged inventory, the approvals. No packets, no scapy.
  worker  a Probe agent (container or process) with its OWN fence. It registers, leases a task, runs it under its own
          guard, submits the result, repeats. Workers are stateless clones: start as many as you want, stop any of them.

Rules that keep it safe and scalable
  * A worker's authorised scope is its OWN configuration. The hub can only hand it work inside that scope; it can never
    widen the fence. Tasks outside a worker's scope are simply never leased to it.
  * Work is leased with an expiry and renewed by heartbeat. A dead worker's tasks return to the queue (bounded retries),
    so nothing is lost and no worker is special.
  * Task keys are idempotent (`scan:<id>:<cidr>`); a result is accepted once, from the current lease holder.
  * Results are merged per vantage point: "on-link" is relative to who looked, so the hub keeps {agent: verdict} and
    derives the best global attachment instead of letting clones overwrite each other.
  * Chaining: a held (hidden) segment raises an approval request; once approved, a follow-up task is created that only
    a worker whose scope covers it can take. Heavy follow-ups (service enrichment) are split into chunks that any
    capable clone can take, which is where extra clones actually save time.

Everything here is pure Python over the Store, so it is unit-testable without HTTP or Docker.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
import time
import uuid
from typing import Callable

from ..store import Store

LEASE_TTL = 60.0          # seconds a lease lives without a heartbeat
MAX_ATTEMPTS = 3          # a task that keeps failing is parked as failed, not retried forever
ALIVE_AFTER = 45.0        # an agent that has not been heard from for this long is reported dead
ENRICH_CHUNK = 20         # hosts per enrichment task
VERDICT_ORDER = ("CONFIRMED_ONLINK", "CONFIRMED_SEPARATE", "CONFLICT", "SUSPECTED_ONLINK", "SUSPECTED_SEPARATE", "UNRESOLVED")


# --------------------------------------------------------------------------------------------- planning
def split_scope(cidrs: list[str], shard_size: int = 256) -> list[str]:
    """Cut the scope into disjoint aligned shards of at most `shard_size` addresses that cover it exactly."""
    size = 1 << max(2, (max(4, shard_size)).bit_length() - 1)          # round down to a power of two, at least /30
    new_prefix = 32 - (size.bit_length() - 1)
    out: list[str] = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if net.version != 4:
            continue                                                   # IPv6 needs multicast: out of scope-safe bounds
        out += [str(net)] if net.prefixlen >= new_prefix else [str(s) for s in net.subnets(new_prefix=new_prefix)]
    return out


def shard_size_for_workers(cidrs: list[str], worker_count: int, *, min_shard_size: int = 4) -> int:
    """Derive a shard address-count from the scope's own size and how many workers are available, instead
    of a fixed /24-style default -- so two workers get two disjoint shards from whatever the scope is
    (e.g. two /25s from a /24), four get four, and so on, computed from the input rather than hardcoded.
    `split_scope` itself already rounds whatever size it is given down to the nearest power of two and
    produces an EXACT, disjoint, covering decomposition (see its own docstring) -- nothing about that needs
    to change; this only decides WHAT size to ask it for.

    A worker pool much larger than a small scope must not explode it into one job per address: the result
    is never smaller than `min_shard_size` (the same floor split_scope itself already enforces), so a /30
    scope with 100 workers still yields one sensible shard, not a thousand single-address tasks."""
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    total = sum(n.num_addresses for n in nets if n.version == 4)
    if total <= 0 or worker_count <= 1:
        return max(min_shard_size, total or min_shard_size)
    return max(min_shard_size, total // worker_count)


def _nets(cidrs) -> list[ipaddress.IPv4Network]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def covered(cidr: str, scope: list[str]) -> bool:
    n = ipaddress.ip_network(cidr, strict=False)
    return any(n.version == s.version and n.subnet_of(s) for s in _nets(scope))


def ip_covered(ip: str, scope: list[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _nets(scope))


# ------------------------------------------------------------------------------------------------ merge
def best_verdict(vantages: dict[str, str]) -> str:
    """Attachment is relative to each vantage point. Confirmed on-link for ANY agent means that agent's segment is the
    host's home; otherwise take the strongest of what the others saw."""
    seen = set(vantages.values())
    for v in VERDICT_ORDER:
        if v in seen:
            return v
    return "UNRESOLVED"


def _union_list(a, b, limit: int = 40):
    out = list(dict.fromkeys([*a, *b]))
    return out[:limit]


def merge_host(store: Store, h: dict, agent: str) -> None:
    ip = h["ip"]
    row = (store.query("SELECT * FROM hosts WHERE ip=?", (ip,)) or [None])[0]
    vant = json.loads(row["vantages"]) if row else {}
    vant[agent] = h.get("verdict", "UNRESOLVED")
    agents = _union_list(json.loads(row["agents"]) if row else [], [agent])
    visible = _union_list(json.loads(row["visible_to"]) if row else [], h.get("visible_to", []), 80)
    reasons = _union_list(json.loads(row["reasons"]) if row else [], h.get("reasons", []))
    roles = _union_list(json.loads(row["roles"]) if row else [], h.get("roles", []))
    seen_macs = ",".join(_union_list((row["seen_macs"] if row else "").split(","), h.get("seen_macs", []) or []))
    methods = ",".join(_union_list((row["discovery_methods"] if row else "").split(","), h.get("discovery_methods", []) or []))
    now = h.get("last_seen") or ""
    fields = dict(mac=h.get("mac") or (row["mac"] if row else None), vendor=h.get("vendor") or (row["vendor"] if row else None),
                  os_guess=h.get("os_guess") or (row["os_guess"] if row else None), ttl=h.get("ttl") or (row["ttl"] if row else None),
                  mask=h.get("mask") or (row["mask"] if row else None), verdict=best_verdict(vant),
                  distance=h.get("distance") if h.get("distance") is not None else (row["distance"] if row else None),
                  visible_to=json.dumps(visible), reasons=json.dumps(reasons), roles=json.dumps(roles),
                  agents=json.dumps(agents), vantages=json.dumps(vant), seen_macs=seen_macs, discovery_methods=methods,
                  held=int(bool(h.get("held")) or bool(row and row["held"])))
    if row is None:
        cols = ["ip", *fields, "first_seen", "last_seen"]
        store.exec(f"INSERT INTO hosts ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                   (ip, *fields.values(), h.get("first_seen") or now, now or h.get("first_seen") or ""))
    else:
        sets = ", ".join(f"{k}=?" for k in fields)
        store.exec(f"UPDATE hosts SET {sets}, last_seen=? WHERE ip=?", (*fields.values(), now or row["last_seen"], ip))
    for p in h.get("open_ports", []):
        store.upsert_service(ip, p["port"], service=p.get("service"), product=p.get("product"), version=p.get("version"),
                             extrainfo=p.get("extrainfo"), banner=p.get("banner"),
                             scripts=json.loads(p["scripts"]) if isinstance(p.get("scripts"), str) else p.get("scripts"),
                             proto=p.get("proto", "tcp"))


def merge_segment(store: Store, seg: dict, agent: str) -> bool:
    """Returns True if this segment is a NEW held (hidden) in-scope segment that needs an approval decision."""
    extra = dict(seg.get("extra") or {})
    local = bool(extra.get("local"))
    key = f"{seg['cidr']}#{agent}" if local else seg["cidr"]          # every vantage point has its own local link
    existing = next((x for x in store.segments() if x["cidr"] == key), None)
    members = _union_list(existing["hosts"] if existing else [], seg.get("hosts", []), 4096)
    evidence = _union_list(existing["evidence"] if existing else [], seg.get("evidence", []), 12)
    state = "held" if (seg.get("state") == "held" or (existing and existing["state"] == "held")) else seg.get("state", "held")
    if existing and existing["state"] == "approved":
        state = "approved"
    extra["agents"] = _union_list((existing or {}).get("extra", {}).get("agents", []), [agent])
    store.upsert_segment(key, kind=seg["kind"], state=state, verdict=seg["verdict"], via=seg.get("via"),
                         evidence=evidence, hosts=members, extra=extra)
    return existing is None and state == "held" and seg["kind"] == "in-scope" and not local


def merge_scan_payload(store: Store, agent: str, scope: list[str], payload: dict) -> dict:
    """Validate against the submitter's registered scope, then merge. Anything outside it is dropped and counted."""
    kept = dropped = 0
    for h in payload.get("hosts", []):
        if ip_covered(h.get("ip", ""), scope):
            merge_host(store, h, agent)
            kept += 1
        else:
            dropped += 1
    new_held: list[str] = []
    for s in payload.get("segments", []):
        if s.get("kind") == "outside-scope" or covered(s["cidr"].split("#")[0], scope):
            if merge_segment(store, s, agent):
                new_held.append(s["cidr"])
    for l in payload.get("leads", []):
        store.add_lead(l["address"], l["evidence"], f"{l['source']}@{agent}" if l["source"].startswith("unconfirmed") else l["source"])
    return {"hosts": kept, "dropped_out_of_scope": dropped, "new_held_segments": new_held}


def merge_enrich_payload(store: Store, scope: list[str], payload: dict) -> dict:
    n = 0
    for r in payload.get("records", []):
        if ip_covered(r["ip"], scope):
            store.upsert_service(r["ip"], r["port"], service=r.get("service"), product=r.get("product"), version=r.get("version"),
                                 extrainfo=r.get("extrainfo"), banner=r.get("banner"), scripts=r.get("scripts"))
            n += 1
    for v in payload.get("vulnerable_apps", []):
        store.add_lead(f"{v['ip']}:{v['port']}", f"deliberately vulnerable application ({v['match']}): {v['title']}", "vulnerable-app")
    for addr, why in (payload.get("leaks") or {}).items():
        store.add_lead(addr, "; ".join(why), "outside-scope-address")
    return {"services": n}


# -------------------------------------------------------------------------------------------------- hub
class MeshError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Hub:
    def __init__(self, store: Store, *, token: str | None = None, scope: list[str] | None = None,
                 now: Callable[[], float] = time.time):
        self.store, self.token, self.scope, self.now = store, token, list(scope or []), now

    # ---- auth ----
    def authorised(self, presented: str | None) -> bool:
        if not self.token:
            return True
        return bool(presented) and secrets.compare_digest(presented, self.token)

    # ---- agents ----
    def register(self, body: dict) -> dict:
        scope = [str(ipaddress.ip_network(c, strict=False)) for c in body.get("scope", [])]
        if not scope:
            raise MeshError(400, "an agent must register its own authorised scope")
        aid = body.get("agent_id") or f"agent-{uuid.uuid4().hex[:8]}"
        now = self.now()
        self.store.exec(
            "INSERT INTO agents (id, name, scope, vantage, caps, version, registered, last_seen) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET name=excluded.name, scope=excluded.scope, vantage=excluded.vantage,"
            " caps=excluded.caps, version=excluded.version, last_seen=excluded.last_seen",
            (aid, body.get("name") or aid, json.dumps(scope), body.get("vantage"), json.dumps(body.get("caps") or ["scan"]),
             body.get("version"), now, now))
        self.store.add_event("mesh.agent.registered", {"agent": aid, "scope": scope, "caps": body.get("caps") or ["scan"]})
        return {"agent_id": aid, "lease_ttl": LEASE_TTL, "heartbeat_s": LEASE_TTL / 4}

    def _agent(self, aid: str) -> dict:
        rows = self.store.query("SELECT * FROM agents WHERE id=?", (aid,))
        if not rows:
            raise MeshError(404, "unknown agent: register first")
        a = rows[0]
        a["scope"], a["caps"] = json.loads(a["scope"]), json.loads(a["caps"])
        return a

    def heartbeat(self, aid: str) -> dict:
        self._agent(aid)
        now = self.now()
        self.store.exec("UPDATE agents SET last_seen=? WHERE id=?", (now, aid))
        self.store.exec("UPDATE tasks SET lease_expires=? WHERE agent=? AND status='leased'", (now + LEASE_TTL, aid))
        return {"ok": True, "approved": self.approvals()}

    def agents(self) -> list[dict]:
        now, out = self.now(), []
        for a in self.store.query("SELECT * FROM agents ORDER BY registered"):
            out.append({"id": a["id"], "name": a["name"], "scope": json.loads(a["scope"]), "vantage": a["vantage"],
                        "caps": json.loads(a["caps"]), "alive": now - a["last_seen"] < ALIVE_AFTER,
                        "seen_s_ago": round(now - a["last_seen"], 1),
                        "tasks": [t["key"] for t in self.store.query("SELECT key FROM tasks WHERE agent=? AND status='leased'", (a["id"],))]})
        return out

    # ---- planning ----
    def active(self) -> bool:
        return bool(self.store.query("SELECT 1 FROM tasks WHERE status IN ('pending','leased') LIMIT 1"))

    def plan(self, *, scope: list[str] | None = None, shard_size: int | None = None, worker_count: int | None = None,
            enrich: bool = True, force: bool = False) -> dict:
        if self.active() and not force:
            raise MeshError(409, "a plan is still running")
        scope = scope or self.scope
        if not scope:
            raise MeshError(400, "no scope to plan")
        # worker_count derives a shard size from the scope's own address count (see shard_size_for_workers);
        # an explicit shard_size always wins when given, and the historical default of 256 applies only
        # when NEITHER is given, so existing callers that pass neither keep their existing behaviour exactly.
        if shard_size is None:
            shard_size = shard_size_for_workers(scope, worker_count) if worker_count else 256
        shards = split_scope(scope, shard_size)
        self.store.exec("DELETE FROM tasks")
        self.store.reset()                                   # the merged inventory is rebuilt; ledger/events/agents survive
        scan_id = self.store.start_scan(scope)
        now = self.now()
        opts = {"enrich": enrich, "shard_size": shard_size}
        for c in shards:
            self.store.exec("INSERT INTO tasks (key, scan_id, type, payload, status, created) VALUES (?,?,?,?,?,?)",
                            (f"scan:{scan_id}:{c}", scan_id, "scan", json.dumps({"cidrs": [c], "approved": False, **opts}), "pending", now))
        self.store.set_meta("plan", {"scan_id": scan_id, "scope": scope, "shards": len(shards), **opts})
        self.store.add_event("scan.started", {"scan_id": scan_id, "scope": scope, "shards": len(shards)})
        return {"scan_id": scan_id, "shards": shards}

    # ---- leasing ----
    def _requeue_expired(self) -> None:
        now = self.now()
        for t in self.store.query("SELECT key, attempts FROM tasks WHERE status='leased' AND lease_expires < ?", (now,)):
            attempts = t["attempts"] + 1
            self.store.exec("UPDATE tasks SET status=?, agent=NULL, lease_expires=NULL, lease_token=NULL, attempts=? WHERE key=?",
                            ("failed" if attempts >= MAX_ATTEMPTS else "pending", attempts, t["key"]))
            self.store.add_event("mesh.lease.expired", {"key": t["key"], "attempts": attempts})

    @staticmethod
    def _eligible(task: dict, agent: dict) -> bool:
        if task["type"] not in agent["caps"]:
            return False
        p = json.loads(task["payload"])
        if task["type"] == "scan":
            return all(covered(c, agent["scope"]) for c in p["cidrs"])
        if task["type"] == "enrich":
            return all(ip_covered(ip, agent["scope"]) for ip in p["targets"])
        return False

    def lease(self, aid: str) -> dict:
        agent = self._agent(aid)
        self.heartbeat(aid)
        self._requeue_expired()
        now = self.now()
        t = self.store.claim_task(lambda task: self._eligible(task, agent), aid, LEASE_TTL, now)
        if t is not None:
            self.store.add_event("mesh.lease.granted", {"key": t["key"], "agent": aid, "attempt": t["attempts"]})
            return {
                "task": {"key": t["key"], "type": t["type"], "payload": json.loads(t["payload"]),
                         "lease_token": t["lease_token"], "attempt": t["attempts"]},
                "lease_ttl": LEASE_TTL, "approved": self.approvals(),
            }
        return {"task": None, "approved": self.approvals(), "active": self.active()}

    # ---- results ----
    def _held_task(self, aid: str, key: str, lease_token: str) -> dict:
        rows = self.store.query("SELECT * FROM tasks WHERE key=?", (key,))
        if not rows:
            raise MeshError(404, "unknown task")
        t = rows[0]
        if t["status"] != "leased" or t["agent"] != aid:
            raise MeshError(409, f"task is {t['status']}" + (f" and held by {t['agent']}" if t["agent"] else ""))
        if t.get("lease_token") != lease_token:
            # The lease this worker thinks it holds has already been reclaimed (expired and re-leased to
            # someone else, possibly even back to this same agent_id under a new token) -- a stale result
            # must never be accepted as if it came from the current lease holder. This is the fencing
            # token's entire purpose: agent_id + status alone cannot tell "my old lease" from "my new one."
            raise MeshError(409, "stale lease: this task was reclaimed under a different lease token")
        return t

    def submit(self, aid: str, key: str, payload: dict, lease_token: str) -> dict:
        agent, t = self._agent(aid), self._held_task(aid, key, lease_token)
        merged = (merge_scan_payload(self.store, aid, agent["scope"], payload) if t["type"] == "scan"
                  else merge_enrich_payload(self.store, agent["scope"], payload))
        self.store.exec("UPDATE tasks SET status='done', finished=?, result=? WHERE key=? AND lease_token=?",
                        (self.now(), json.dumps({"agent": aid, **merged, "summary": payload.get("summary")}), key, lease_token))
        self.store.add_event("mesh.task.done", {"key": key, "agent": aid, **merged})
        for cidr in merged.get("new_held_segments", []):
            self.store.add_event("mesh.approval-needed", {"cidr": cidr, "found_by": aid})
        self._after(t)
        return {"ok": True, **merged}

    def fail(self, aid: str, key: str, error: str, lease_token: str) -> dict:
        t = self._held_task(aid, key, lease_token)
        attempts = t["attempts"] + 1
        self.store.exec(
            "UPDATE tasks SET status=?, agent=NULL, lease_expires=NULL, lease_token=NULL, attempts=?, result=? "
            "WHERE key=? AND lease_token=?",
            ("failed" if attempts >= MAX_ATTEMPTS else "pending", attempts, json.dumps({"error": error[:300]}), key, lease_token))
        self.store.add_event("mesh.task.failed", {"key": key, "agent": aid, "error": error[:200], "attempts": attempts})
        return {"ok": True, "attempts": attempts}

    # ---- chaining ----
    def _after(self, done: dict) -> None:
        scan_id = done["scan_id"]
        opts = json.loads(done["payload"])
        left = self.store.query("SELECT 1 FROM tasks WHERE scan_id=? AND status IN ('pending','leased') LIMIT 1", (scan_id,))
        if left:
            return
        if opts.get("enrich") and not self.store.query("SELECT 1 FROM tasks WHERE scan_id=? AND type='enrich' LIMIT 1", (scan_id,)):
            if self._plan_enrich(scan_id):
                return                                         # follow-ups are now queued; finish when they are done
        self._finish(scan_id)

    def _plan_enrich(self, scan_id: int) -> int:
        from ..tools.nmap_tool import NOISE_PORTS
        work = {h["ip"]: [p["port"] for p in h["open_ports"] if p["port"] not in NOISE_PORTS]
                for h in self.store.hosts() if not h["held"] and h["open_ports"]}
        work = {ip: ports for ip, ports in work.items() if ports}
        ips = sorted(work)
        now, n = self.now(), 0
        for i in range(0, len(ips), ENRICH_CHUNK):
            chunk = {ip: work[ip] for ip in ips[i:i + ENRICH_CHUNK]}
            self.store.exec("INSERT INTO tasks (key, scan_id, type, payload, status, created) VALUES (?,?,?,?,?,?)",
                            (f"enrich:{scan_id}:{i // ENRICH_CHUNK}", scan_id, "enrich", json.dumps({"targets": chunk}), "pending", now))
            n += 1
        if n:
            self.store.add_event("mesh.enrich.planned", {"scan_id": scan_id, "tasks": n, "hosts": len(ips)})
        return n

    def _finish(self, scan_id: int) -> None:
        failed = [t["key"] for t in self.store.query("SELECT key FROM tasks WHERE scan_id=? AND status='failed'", (scan_id,))]
        hosts = self.store.hosts()
        summary = {"hosts": len(hosts), "open_ports": sum(len(h["open_ports"]) for h in hosts),
                   "segments": [{"cidr": s["cidr"], "kind": s["kind"], "state": s["state"]} for s in self.store.segments()],
                   "agents": sorted({a for h in hosts for a in h["agents"]}), "failed_tasks": failed}
        self.store.finish_scan(scan_id, "done" if not failed else "partial", summary)
        self.store.add_event("scan.finished", {"scan_id": scan_id, **summary})

    def approve(self, cidr: str) -> dict:
        net = str(ipaddress.ip_network(cidr, strict=False))
        approved = self.approvals()
        if net not in approved:
            approved.append(net)
            self.store.set_meta("approvals", approved)
        plan = self.store.meta().get("plan") or {}
        scan_id = plan.get("scan_id") or self.store.start_scan([net])
        key = f"scan:{scan_id}:{net}:approved"
        self.store.exec("INSERT OR REPLACE INTO tasks (key, scan_id, type, payload, status, created) VALUES (?,?,?,?,?,?)",
                        (key, scan_id, "scan", json.dumps({"cidrs": [net], "approved": True, "enrich": plan.get("enrich", True)}),
                         "pending", self.now()))
        self.store.add_event("mesh.approved", {"cidr": net, "task": key})
        return {"approved": approved, "task": key}

    def approvals(self) -> list[str]:
        return list(self.store.meta().get("approvals") or [])

    # ---- status ----
    def status(self) -> dict:
        by = {}
        for r in self.store.query("SELECT type, status, COUNT(*) AS n FROM tasks GROUP BY type, status"):
            by.setdefault(r["type"], {})[r["status"]] = r["n"]
        return {"plan": self.store.meta().get("plan"), "tasks": by, "agents": self.agents(), "active": self.active(),
                "last_scan": self.store.last_scan(), "approvals": self.approvals()}

    def tasks(self) -> list[dict]:
        return [{"key": t["key"], "type": t["type"], "status": t["status"], "agent": t["agent"], "attempts": t["attempts"]}
                for t in self.store.query("SELECT * FROM tasks ORDER BY created, key")]
