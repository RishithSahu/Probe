"""FastAPI application entry point.

Run with: `uvicorn app.main:app --host 0.0.0.0 --port 8000` (see
Dockerfile.orchestrator / docker-compose.yml for the containerised
equivalent).
"""
from __future__ import annotations

import logging

from fastapi import FastAPI

from app.api.routes import router
from app.core.config import settings
from app.database.session import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(
    title="Autonomous Pentest Engine — Orchestrator API",
    description="Coordinates the Web Security, Binary Analysis, and (externally-integrated) "
    "Network Vulnerability specialist agents, and serves consolidated assessment results.",
    version="0.1.0",
)
app.include_router(router)


@app.on_event("startup")
def on_startup() -> None:
    settings.ensure_directories()
    # Convenience for the synthetic demo / first run; real deployments should
    # rely on `alembic upgrade head` instead (see README.md).
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "environment": settings.environment}
