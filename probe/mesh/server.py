"""The hub's HTTP surface -- standard library only (no FastAPI/pydantic/uvicorn), so the hub container stays tiny.

  /mesh/*   register, heartbeat, lease, submit, fail, plan, approve, agents, status, tasks
  /api/*    the same inventory / events / ledger contract as the desktop app (docs/CONTRACT.md), so a LangGraph
            node can talk to a hub exactly as it talks to a single agent
  /health   unauthenticated liveness (for container healthchecks)

Every route except /health needs `Authorization: Bearer <token>` when a token is configured. A hub refuses to listen on
a non-loopback address without one.
"""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..scope import ScopeGuard
from ..service import ProbeService
from .core import Hub, MeshError

MAX_BODY = 32 * 1024 * 1024


def dispatch(hub: Hub, svc: ProbeService, method: str, path: str, q: dict, body: dict) -> tuple[int, object]:
    g = lambda k, d=None: (q.get(k) or [d])[0]
    try:
        if method == "POST":
            if path == "/mesh/register":
                return 200, hub.register(body)
            if path == "/mesh/heartbeat":
                return 200, hub.heartbeat(body["agent_id"])
            if path == "/mesh/lease":
                return 200, hub.lease(body["agent_id"])
            if path == "/mesh/submit":
                return 200, hub.submit(body["agent_id"], body["key"], body.get("payload") or {})
            if path == "/mesh/fail":
                return 200, hub.fail(body["agent_id"], body["key"], body.get("error", ""))
            if path == "/mesh/plan":
                return 200, hub.plan(scope=body.get("scope"), shard_size=int(body.get("shard_size", 256)),
                                     enrich=bool(body.get("enrich", True)), force=bool(body.get("force", False)))
            if path == "/mesh/approve":
                return 200, hub.approve(body["cidr"])
            if path == "/api/claim":
                return 200, svc.claim(body["key"], body["agent"], float(body.get("ttl_s", 600)))
            if path == "/api/complete":
                r = svc.complete(body["key"], body["agent"], body.get("result"), bool(body.get("ok", True)))
                return (200, r) if r.get("ok") else (409, r)
            if path == "/api/scan":
                return 200, request_scan(hub, bool(body.get("force", False)), float(body.get("max_age_s", 300)))
        else:
            if path == "/mesh/agents":
                return 200, hub.agents()
            if path == "/mesh/status":
                return 200, hub.status()
            if path == "/mesh/tasks":
                return 200, hub.tasks()
            if path == "/mesh/approvals":
                return 200, hub.approvals()
            if path == "/api/status":
                return 200, svc.status()
            if path == "/api/hosts":
                b = lambda k: None if g(k) is None else g(k).lower() in ("1", "true", "yes")
                return 200, svc.hosts(held=b("held"), verdict=g("verdict"), role=g("role"), with_services=b("with_services"))
            if path.startswith("/api/hosts/"):
                h = svc.host(path.rsplit("/", 1)[1])
                return (200, h) if h else (404, {"error": "unknown host"})
            if path == "/api/services":
                return 200, svc.services(port=int(g("port")) if g("port") else None, service=g("service"),
                                         include_held=(g("include_held") or "").lower() in ("1", "true"))
            if path == "/api/targets/web":
                return 200, svc.web_targets()
            if path == "/api/pivots":
                return 200, svc.pivots()
            if path == "/api/segments":
                return 200, svc.segments()
            if path == "/api/leads":
                return 200, svc.leads()
            if path == "/api/events":
                return 200, svc.events(int(g("since", 0)), int(g("limit", 500)))
            if path == "/api/scope/check":
                return 200, svc.check_scope(g("ip", ""))
            if path == "/api/claims":
                return 200, svc.claims(g("prefix", ""))
    except MeshError as e:
        return e.status, {"error": e.message}
    except KeyError as e:
        return 400, {"error": f"missing field {e}"}
    except (ValueError, TypeError) as e:
        return 400, {"error": str(e)}
    return 404, {"error": "not found"}


def request_scan(hub: Hub, force: bool, max_age_s: float) -> dict:
    last = hub.store.last_scan()
    if hub.active():
        return {"state": "running", "scan": last}
    if not force and last and last["status"] in ("done", "partial") and last["finished"] and time.time() - last["finished"] < max_age_s:
        return {"state": "fresh", "scan": last}
    plan = hub.plan(force=True)
    return {"state": "started", "scan": last, "plan": plan}


def make_server(hub: Hub, bind: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    if bind not in ("127.0.0.1", "localhost", "::1") and not hub.token:
        raise SystemExit("refusing to listen on a non-loopback address without a token (set PROBE_MESH_TOKEN)")
    svc = ProbeService(hub.store, ScopeGuard(hub.scope) if hub.scope else None)

    class Handler(BaseHTTPRequestHandler):
        server_version = "probe-hub"
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):      # quiet: a hub serving a busy mesh must not spam the console
            pass

        def _send(self, status: int, obj) -> None:
            data = json.dumps(obj, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            u = urlparse(self.path)
            if u.path == "/health":
                return self._send(200, {"ok": True})
            tok = self.headers.get("Authorization", "")
            if not hub.authorised(tok[7:] if tok.startswith("Bearer ") else None):
                return self._send(401, {"error": "bad or missing token"})
            body = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    return self._send(413, {"error": "payload too large"})
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "invalid JSON"})
            status, obj = dispatch(hub, svc, method, u.path, parse_qs(u.query), body)
            self._send(status, obj)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return ThreadingHTTPServer((bind, port), Handler)
