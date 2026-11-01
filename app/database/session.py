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

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database import vulnerability_lifecycle  # noqa: F401 -- register lifecycle tables
from app.database.models import Base


def _assert_safe_database_url(database_url: str) -> None:
    """Fail closed, at import time, rather than silently sharing (and risking) the production database.

    INCIDENT (2026-11-01): tests/conftest.py used to delete evidence/ape.db -- the real, live database --
    at the start of every pytest session. conftest.py now redirects every writable path via environment
    variables BEFORE this module is ever imported (see its own top-of-file comment), which is the actual
    fix; this is the second, independent layer -- it does not trust that redirection happened and checks
    the resolved path itself. `"pytest" in sys.modules` is used rather than `PYTEST_CURRENT_TEST` (which
    the project's own incident review confirmed is not necessarily set yet during test collection, only
    once a specific test is running) -- pytest itself is already imported by the time ANY test module,
    including this one's importer, runs, so this is reliable at the point this function is actually called
    (module import time, i.e. first `import app.database.session` anywhere in the process)."""
    from app.database.safety import validate_engine_url
    validate_engine_url(database_url)


_assert_safe_database_url(settings.database_url)

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
