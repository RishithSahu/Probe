"""SQLAlchemy engine/session setup. Uses the sync psycopg2 driver (already a
project dependency) rather than an async driver, matching the rest of the
codebase's synchronous style (agents/adapters are all sync, called from
LangGraph nodes that FastAPI runs via its threadpool for sync path handlers).
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database.models import Base

_engine = create_engine(settings.database_url, future=True, pool_pre_ping=True)
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
