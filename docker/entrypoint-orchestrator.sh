#!/bin/sh
# Runs pending Alembic migrations against APE_DATABASE_URL, then starts the
# FastAPI/Orchestrator process. Migration failure is fatal (the container
# exits non-zero) rather than silently starting against a stale schema.
set -e

echo "[entrypoint] running alembic upgrade head..."
alembic upgrade head

echo "[entrypoint] starting uvicorn..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
