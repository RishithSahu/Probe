"""SQLAlchemy engine/session setup. Synchronous throughout (no async driver),
matching the rest of the codebase's synchronous style (agents/adapters are
all sync, called from LangGraph nodes that FastAPI runs via its threadpool
for sync path handlers).

Defaults to a local SQLite file (see app/core/config.py) — no external
database service required for a hackathon dev/demo deployment. The engine
is built generically from `settings.database_url`, so pointing it at a
PostgreSQL (or other SQLAlchemy-supported) URL instead needs no code change
here beyond the extra `connect_args` below, which only apply to SQLite.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database.models import Base

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}

if _is_sqlite:
    # A relative sqlite:///evidence/ape.db path needs its parent directory to
    # exist before SQLAlchemy opens the file — ensure_directories() also does
    # this on FastAPI startup, but engine creation can happen earlier (e.g.
    # module import in a standalone script or test) so it's repeated here.
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)

_engine = create_engine(
    settings.database_url, future=True, pool_pre_ping=not _is_sqlite, connect_args=_connect_args,
)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create all tables if they don't exist. For real deployments, Alembic
    migrations (see alembic/) are the source of truth — this is a convenience
    for tests and the synthetic demo, not a replacement for migrations."""
    Base.metadata.create_all(bind=_engine)


def get_engine():
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
