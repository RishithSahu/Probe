"""Dependency-free Python client for the Probe API -- what a LangGraph node imports.

No scapy, no admin rights, no extra packages (stdlib only). Every method returns plain JSON-able dicts/lists.

    from probe.client import ProbeClient
    probe = ProbeClient()                              # http://127.0.0.1:8080
    probe.ensure_scan(max_age_s=300)                   # reuse a fresh scan, or start one and wait for it
    for t in probe.web_targets(): ...                  # input for the web agent
    if probe.claim("web-crawl:10.20.30.13:80", "web-agent")["granted"]:
        ...do the work...
        probe.complete("web-crawl:10.20.30.13:80", "web-agent", {"findings": 3})
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request


class ProbeError(RuntimeError):
    pass


class ProbeClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout: float = 15.0):
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def _req(self, method: str, path: str, body: dict | None = None, **params):
        qs = {k: v for k, v in params.items() if v is not None}
        url = self.base + path + (("?" + urllib.parse.urlencode(qs)) if qs else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise ProbeError(f"{method} {path}: {e.code} {e.read().decode()[:200]}") from None
        except urllib.error.URLError as e:
            raise ProbeError(f"cannot reach Probe at {self.base}: {e.reason}") from None

    # ---- inventory ----
    def status(self): return self._req("GET", "/api/status")
    def hosts(self, **filters): return self._req("GET", "/api/hosts", **filters)
    def host(self, ip: str): return self._req("GET", f"/api/hosts/{ip}")
    def services(self, **filters): return self._req("GET", "/api/services", **filters)
    def web_targets(self): return self._req("GET", "/api/targets/web")
    def pivots(self): return self._req("GET", "/api/pivots")
    def segments(self): return self._req("GET", "/api/segments")
    def leads(self): return self._req("GET", "/api/leads")
    def check_scope(self, ip: str): return self._req("GET", "/api/scope/check", ip=ip)

    # ---- change feed ----
    def events(self, since: int = 0, limit: int = 500): return self._req("GET", "/api/events", since=since, limit=limit)

    # ---- work ledger ----
    def claim(self, key: str, agent: str, ttl_s: float = 600):
        return self._req("POST", "/api/claim", {"key": key, "agent": agent, "ttl_s": ttl_s})

    def complete(self, key: str, agent: str, result: dict | None = None, ok: bool = True):
        return self._req("POST", "/api/complete", {"key": key, "agent": agent, "result": result or {}, "ok": ok})

    def claims(self, prefix: str = ""): return self._req("GET", "/api/claims", prefix=prefix)

    # ---- scan freshness ----
    def request_scan(self, max_age_s: float = 300, force: bool = False):
        return self._req("POST", "/api/scan", {"max_age_s": max_age_s, "force": force})

    def ensure_scan(self, max_age_s: float = 300, wait: bool = True, poll_s: float = 2.0, timeout_s: float = 400):
        """Return the freshest scan summary, starting a scan only if the last one is older than max_age_s.
        Safe to call from many agents at once: the engine runs one scan and everybody gets the same result."""
        r = self.request_scan(max_age_s=max_age_s)
        if r["state"] == "fresh" or not wait:
            return r
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            time.sleep(poll_s)
            s = self.status().get("last_scan") or {}
            if s.get("status") == "done" and s.get("finished", 0) >= t0 - 1:
                return {"state": "fresh", "scan": s}
        raise ProbeError("scan did not finish in time")
