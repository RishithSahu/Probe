"""Local HTTP API + the minimal web view. Bound to 127.0.0.1 by the CLI.

Reads come straight from the SQLite store. The only writes are the shared work ledger (claim/complete) and a
scan *request*: a request never sends anything itself -- it asks the engine, which is bound by the same guard,
fence, leash and hold list as the first scan. See docs/CONTRACT.md for the full contract.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ..scope import ScopeGuard
from ..service import ProbeService
from ..store import Store

STATIC = Path(__file__).parent / "static"


class ClaimBody(BaseModel):
    key: str = Field(..., description="idempotency key of one unit of work, e.g. 'web-crawl:10.20.30.13:80'")
    agent: str
    ttl_s: float = 600


class CompleteBody(BaseModel):
    key: str
    agent: str
    result: dict | None = None
    ok: bool = True


class ScanBody(BaseModel):
    max_age_s: float = Field(300, description="reuse the last scan if it finished less than this many seconds ago")
    force: bool = False


def create_app(store: Store, scope: ScopeGuard | None = None,
               request_scan: Callable[[bool, float], dict] | None = None) -> FastAPI:
    app = FastAPI(title="Probe", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    svc = ProbeService(store, scope)

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/state")                 # the web view
    def state():
        return {"status": store.meta().get("status", {}), "hosts": store.hosts(), "edges": store.edges(),
                "segments": store.segments(), "leads": store.leads()}

    # ---- queries ----
    @app.get("/api/status")
    def status():
        return svc.status()

    @app.get("/api/hosts")
    def hosts(held: bool | None = None, verdict: str | None = None, role: str | None = None,
              with_services: bool | None = None):
        return svc.hosts(held=held, verdict=verdict, role=role, with_services=with_services)

    @app.get("/api/hosts/{ip}")
    def host(ip: str):
        h = svc.host(ip)
        if h is None:
            raise HTTPException(404, "unknown host")
        return h

    @app.get("/api/services")
    def services(port: int | None = None, service: str | None = None, include_held: bool = False):
        return svc.services(port=port, service=service, include_held=include_held)

    @app.get("/api/targets/web")
    def web_targets():
        return svc.web_targets()

    @app.get("/api/pivots")
    def pivots():
        return svc.pivots()

    @app.get("/api/segments")
    def segments():
        return svc.segments()

    @app.get("/api/leads")
    def leads():
        return svc.leads()

    @app.get("/api/events")
    def events(since: int = Query(0, ge=0), limit: int = Query(500, le=2000)):
        return svc.events(since, limit)

    @app.get("/api/scope/check")
    def scope_check(ip: str):
        return svc.check_scope(ip)

    # ---- the work ledger ----
    @app.get("/api/claims")
    def claims(prefix: str = ""):
        return svc.claims(prefix)

    @app.post("/api/claim")
    def claim(body: ClaimBody):
        return svc.claim(body.key, body.agent, body.ttl_s)

    @app.post("/api/complete")
    def complete(body: CompleteBody):
        r = svc.complete(body.key, body.agent, body.result, body.ok)
        if not r.get("ok"):
            raise HTTPException(409, r.get("error", "not the claim holder"))
        return r

    # ---- scan freshness: ask for a scan only if the last one is stale ----
    @app.post("/api/scan")
    def scan(body: ScanBody):
        if request_scan is None:
            raise HTTPException(503, "this instance cannot start scans")
        return request_scan(body.force, body.max_age_s)

    return app
