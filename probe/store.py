"""SQLite-backed inventory -- the single source of truth the web page reads.
One file, zero external services, so judges can run this with nothing but Python.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    vendor TEXT,
    status TEXT NOT NULL DEFAULT 'up',
    os_guess TEXT,
    ttl INTEGER,
    hops INTEGER,
    via TEXT,
    mask TEXT,
    verdict TEXT NOT NULL DEFAULT 'UNRESOLVED',
    distance INTEGER,
    visible_to TEXT NOT NULL DEFAULT '[]',
    reasons TEXT NOT NULL DEFAULT '[]',
    roles TEXT NOT NULL DEFAULT '[]',
    agents TEXT NOT NULL DEFAULT '[]',        -- mesh: which agents reported this host
    vantages TEXT NOT NULL DEFAULT '{}',      -- mesh: {agent: verdict}: attachment is relative to each vantage point
    seen_macs TEXT NOT NULL DEFAULT '',
    discovery_methods TEXT NOT NULL DEFAULT '',
    held INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    banner TEXT,
    scripts TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (host_ip, port, proto)
);
CREATE TABLE IF NOT EXISTS edges (
    a TEXT NOT NULL, b TEXT NOT NULL, kind TEXT NOT NULL, evidence TEXT,
    PRIMARY KEY (a, b, kind)
);
CREATE TABLE IF NOT EXISTS segments (
    cidr TEXT PRIMARY KEY,
    kind TEXT NOT NULL,          -- in-scope | outside-scope
    state TEXT NOT NULL,         -- local | held | approved
    verdict TEXT NOT NULL,       -- CONFIRMED | CONFIRMED_ADDRESS
    via TEXT,
    evidence TEXT NOT NULL,      -- json list: the observations that prove it
    hosts TEXT NOT NULL,         -- json list of member ips
    extra TEXT NOT NULL,         -- json: covering / max_extent / basis / hidden / path / distance
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leads (   -- uncorroborated sightings: NOT reported as segments
    address TEXT NOT NULL, evidence TEXT NOT NULL, source TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1, found_at TEXT NOT NULL,
    PRIMARY KEY (address, source)
);
CREATE TABLE IF NOT EXISTS stray_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, caller TEXT, at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- ---- shared with the other agents; survives a rescan (reset() leaves these alone) ----
CREATE TABLE IF NOT EXISTS events (          -- append-only change feed: poll with ?since=<id>
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (          -- work ledger: one row per unit of work, so nothing is done twice
    key TEXT PRIMARY KEY, agent TEXT NOT NULL, status TEXT NOT NULL,   -- claimed | done | failed
    claimed_at REAL NOT NULL, expires REAL NOT NULL, finished_at REAL, result TEXT
);
CREATE TABLE IF NOT EXISTS agents (          -- mesh: every clone that registered with a hub
    id TEXT PRIMARY KEY, name TEXT NOT NULL, scope TEXT NOT NULL, vantage TEXT, caps TEXT NOT NULL,
    version TEXT, registered REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (           -- mesh: units of work leased to agents
    key TEXT PRIMARY KEY, scan_id INTEGER, type TEXT NOT NULL, payload TEXT NOT NULL,
    status TEXT NOT NULL,                     -- pending | leased | done | failed
    agent TEXT, lease_expires REAL, attempts INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL,
    finished REAL, result TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL NOT NULL, finished REAL, status TEXT NOT NULL,
    scope TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '{}'
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _csv_add(existing: str | None, item: str | None) -> str:
    items = set(filter(None, (existing or "").split(",")))
    if item:
        items.add(item)
    return ",".join(sorted(items))


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")      # readers (web/API) never block the scan's writes
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        for col, ddl in (("agents", "TEXT NOT NULL DEFAULT '[]'"), ("vantages", "TEXT NOT NULL DEFAULT '{}'"),
                         ("roles", "TEXT NOT NULL DEFAULT '[]'")):   # upgrade an older database file in place
            try:
                self._conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError:
                pass
        self.exec, self.query = self._x, self._q         # public handles for the mesh layer
        self._conn.commit()

    def reset(self) -> None:
        with self._lock:
            for t in ("hosts", "ports", "edges", "segments", "leads", "stray_probes", "meta"):
                self._conn.execute(f"DELETE FROM {t}")
            self._conn.commit()

    def _x(self, sql: str, args: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur

    def _q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    # ---- hosts ------------------------------------------------------------
    def upsert_host(self, ip: str, *, mac: str | None = None, method: str | None = None,
                    ttl: int | None = None, seen_mac: str | None = None,
                    mask: str | None = None) -> None:
        now = _now()
        with self._lock:
            row = self._conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO hosts (ip, mac, ttl, mask, seen_macs, discovery_methods, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (ip, mac, ttl, mask, _csv_add("", seen_mac), _csv_add("", method), now, now))
            else:
                self._conn.execute(
                    "UPDATE hosts SET mac=COALESCE(?,mac), ttl=COALESCE(?,ttl), mask=COALESCE(?,mask),"
                    " seen_macs=?, discovery_methods=?, last_seen=? WHERE ip=?",
                    (mac, ttl, mask, _csv_add(row["seen_macs"], seen_mac),
                     _csv_add(row["discovery_methods"], method), now, ip))
            self._conn.commit()

    def update_host(self, ip: str, **fields) -> None:
        for k in ("visible_to", "reasons", "roles", "agents", "vantages"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k])
        allowed = {"vendor", "os_guess", "hops", "via", "held", "status", "mac", "verdict", "distance", "visible_to", "reasons", "roles", "agents", "vantages"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        cols = ", ".join(f"{k}=?" for k in sets)
        self._x(f"UPDATE hosts SET {cols} WHERE ip=?", (*sets.values(), ip))

    def add_port(self, ip: str, port: int, *, proto: str = "tcp", service: str | None = None) -> None:
        self._x("INSERT INTO ports (host_ip, port, proto, service) VALUES (?,?,?,?)"
                " ON CONFLICT(host_ip, port, proto) DO UPDATE SET service=COALESCE(excluded.service, service)",
                (ip, port, proto, service))

    def hosts(self) -> list[dict]:
        rows = self._q("SELECT * FROM hosts ORDER BY ip")
        ports: dict[str, list[dict]] = {}
        for p in self._q("SELECT host_ip, port, proto, service, product, version, extrainfo, banner, scripts FROM ports ORDER BY port"):
            ports.setdefault(p["host_ip"], []).append(p)
        for r in rows:
            r["open_ports"] = ports.get(r["ip"], [])
            r["discovery_methods"] = [m for m in r["discovery_methods"].split(",") if m]
            r["seen_macs"] = [m for m in r["seen_macs"].split(",") if m]
            r["held"] = bool(r["held"])
            r["visible_to"] = json.loads(r["visible_to"])
            r["reasons"] = json.loads(r["reasons"])
            r["roles"] = json.loads(r["roles"])
            r["agents"] = json.loads(r.get("agents") or "[]")
            r["vantages"] = json.loads(r.get("vantages") or "{}")
        return rows

    # ---- topology -----------------------------------------------------------
    def add_edge(self, a: str, b: str, kind: str, evidence: str = "") -> None:
        self._x("INSERT OR IGNORE INTO edges (a,b,kind,evidence) VALUES (?,?,?,?)", (a, b, kind, evidence))

    def clear_edges(self) -> None:
        self._x("DELETE FROM edges")

    def edges(self) -> list[dict]:
        return self._q("SELECT * FROM edges")

    def upsert_segment(self, cidr: str, *, kind: str, state: str, verdict: str, via: str | None,
                       evidence: list[str], hosts: list[str], extra: dict) -> None:
        self._x("INSERT INTO segments (cidr,kind,state,verdict,via,evidence,hosts,extra,first_seen)"
                " VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(cidr) DO UPDATE SET kind=excluded.kind,"
                " state=CASE WHEN segments.state='approved' THEN 'approved' ELSE excluded.state END,"
                " verdict=excluded.verdict, via=excluded.via, evidence=excluded.evidence,"
                " hosts=excluded.hosts, extra=excluded.extra",
                (cidr, kind, state, verdict, via, json.dumps(evidence), json.dumps(hosts), json.dumps(extra), _now()))

    def clear_segments(self) -> None:
        self._x("DELETE FROM segments WHERE state != 'approved'")

    def delete_segment(self, cidr: str) -> None:
        self._x("DELETE FROM segments WHERE cidr=?", (cidr,))

    def segments(self) -> list[dict]:
        rows = self._q("SELECT * FROM segments ORDER BY cidr")
        for r in rows:
            r["evidence"] = json.loads(r["evidence"])
            r["hosts"] = json.loads(r["hosts"])
            r["extra"] = json.loads(r["extra"])
        return rows

    # ---- leads / audit ----------------------------------------------------------
    def add_lead(self, address: str, evidence: str, source: str) -> None:
        self._x("INSERT INTO leads (address, evidence, source, found_at) VALUES (?,?,?,?)"
                " ON CONFLICT(address, source) DO UPDATE SET count=count+1", (address, evidence, source, _now()))

    def clear_leads(self, source_prefix: str) -> None:
        self._x("DELETE FROM leads WHERE source LIKE ?", (source_prefix + "%",))

    def leads(self) -> list[dict]:
        return self._q("SELECT * FROM leads ORDER BY count DESC, address")

    def add_stray_probe(self, target: str, caller: str) -> None:
        self._x("INSERT INTO stray_probes (target, caller, at) VALUES (?,?,?)", (target, caller, _now()))

    def stray_count(self) -> int:
        return self._q("SELECT COUNT(*) AS c FROM stray_probes")[0]["c"]

    def set_meta(self, key: str, value) -> None:
        self._x("INSERT INTO meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))

    def meta(self) -> dict:
        return {r["key"]: json.loads(r["value"]) for r in self._q("SELECT key, value FROM meta")}

    def delete_host(self, ip: str) -> None:
        self._x("DELETE FROM hosts WHERE ip=?", (ip,))
        self._x("DELETE FROM ports WHERE host_ip=?", (ip,))

    # ---- bulk paths used by the scan (one transaction instead of one commit per packet) ------------------
    def bulk_upsert_hosts(self, hosts: list[dict]) -> None:
        rows = [(h["ip"], h["mac"], h["ttl"], h["mask"], ",".join(sorted(h["seen_macs"])),
                 ",".join(sorted(h["methods"])), h["first"], h.get("last", h["first"])) for h in hosts]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO hosts (ip, mac, ttl, mask, seen_macs, discovery_methods, first_seen, last_seen)"
                " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET mac=COALESCE(excluded.mac, mac),"
                " ttl=COALESCE(excluded.ttl, ttl), mask=COALESCE(excluded.mask, mask), seen_macs=excluded.seen_macs,"
                " discovery_methods=excluded.discovery_methods, last_seen=excluded.last_seen", rows)
            self._conn.commit()

    def bulk_add_ports(self, pairs: list[tuple[str, int]]) -> None:
        with self._lock:
            self._conn.executemany("INSERT OR IGNORE INTO ports (host_ip, port, proto) VALUES (?,?, 'tcp')", pairs)
            self._conn.commit()

    def upsert_service(self, ip: str, port: int, *, service=None, product=None, version=None, extrainfo=None,
                       banner=None, scripts: dict | None = None, proto: str = "tcp") -> None:
        self._x("INSERT INTO ports (host_ip, port, proto, service, product, version, extrainfo, banner, scripts)"
                " VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(host_ip, port, proto) DO UPDATE SET"
                " service=COALESCE(excluded.service, service), product=COALESCE(excluded.product, product),"
                " version=COALESCE(excluded.version, version), extrainfo=COALESCE(excluded.extrainfo, extrainfo),"
                " banner=COALESCE(excluded.banner, banner), scripts=excluded.scripts",
                (ip, port, proto, service, product, version, extrainfo, banner, json.dumps(scripts or {})))

    # ---- shared ledger for the other agents ---------------------------------------------------------------------
    def add_event(self, type_: str, payload: dict) -> int:
        cur = self._x("INSERT INTO events (ts, type, payload) VALUES (?,?,?)", (_now(), type_, json.dumps(payload)))
        return cur.lastrowid

    def events_since(self, since: int = 0, limit: int = 500) -> list[dict]:
        rows = self._q("SELECT id, ts, type, payload FROM events WHERE id > ? ORDER BY id LIMIT ?", (since, limit))
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    def claim(self, key: str, agent: str, ttl_s: float = 600) -> dict:
        """Atomic claim of one unit of work. granted=False means somebody else owns it or it is already done:
        the caller must not redo it (and gets the stored result when there is one)."""
        import time as _t
        now = _t.time()
        with self._lock:
            row = self._conn.execute("SELECT * FROM claims WHERE key=?", (key,)).fetchone()
            if row is not None:
                st, owner = row["status"], row["agent"]
                if st == "done":
                    return {"granted": False, "status": "done", "owner": owner,
                            "result": json.loads(row["result"]) if row["result"] else None}
                if st == "claimed" and row["expires"] > now and owner != agent:
                    return {"granted": False, "status": "claimed", "owner": owner, "expires_in": round(row["expires"] - now, 1)}
            self._conn.execute(
                "INSERT INTO claims (key, agent, status, claimed_at, expires) VALUES (?,?, 'claimed', ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET agent=excluded.agent, status='claimed', claimed_at=excluded.claimed_at,"
                " expires=excluded.expires, finished_at=NULL, result=NULL", (key, agent, now, now + ttl_s))
            self._conn.commit()
        return {"granted": True, "status": "claimed", "owner": agent, "expires_in": ttl_s}

    def complete(self, key: str, agent: str, result: dict | None = None, *, ok: bool = True) -> dict:
        import time as _t
        with self._lock:
            row = self._conn.execute("SELECT agent, status FROM claims WHERE key=?", (key,)).fetchone()
            if row is None or row["agent"] != agent:
                return {"ok": False, "error": "claim not held by this agent"}
            self._conn.execute("UPDATE claims SET status=?, finished_at=?, result=? WHERE key=?",
                               ("done" if ok else "failed", _t.time(), json.dumps(result or {}), key))
            self._conn.commit()
        return {"ok": True, "status": "done" if ok else "failed"}

    def claims(self, prefix: str = "") -> list[dict]:
        rows = self._q("SELECT * FROM claims WHERE key LIKE ? ORDER BY claimed_at DESC", (prefix + "%",))
        for r in rows:
            r["result"] = json.loads(r["result"]) if r["result"] else None
        return rows

    def start_scan(self, scope: list[str]) -> int:
        import time as _t
        return self._x("INSERT INTO scans (started, status, scope) VALUES (?, 'running', ?)",
                       (_t.time(), json.dumps(scope))).lastrowid

    def finish_scan(self, scan_id: int, status: str, summary: dict) -> None:
        import time as _t
        self._x("UPDATE scans SET finished=?, status=?, summary=? WHERE id=?", (_t.time(), status, json.dumps(summary), scan_id))

    def last_scan(self) -> dict | None:
        rows = self._q("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        if not rows:
            return None
        r = rows[0]
        r["scope"], r["summary"] = json.loads(r["scope"]), json.loads(r["summary"])
        return r
