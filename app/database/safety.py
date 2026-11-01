"""Database/workspace safety guards for the test suite.

INCIDENT (2026-11-01): tests used to delete `evidence/ape.db` -- the real, live database -- at the start
of every pytest session, via an autouse fixture that ran AFTER `app.database.session` had already built
its engine from that real path (imported before the fixture's own redirection could take effect).
`ASSESSMENT-CREDENTIAL-ACCESS-397A` and its history were lost this way.

This module is the shared, dependency-free safety layer both `tests/conftest.py` and
`app/database/session.py` call into, so a test run that is not correctly isolated into its own private
temp workspace fails loudly and immediately, rather than silently touching production data. Two
independent call sites (conftest's env-var redirection, and session.py's own import-time check) both have
to agree a URL is safe; either one failing closed is enough to prevent a repeat.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

# The one real production path this whole module exists to protect, in both path-separator styles.
_PRODUCTION_DB_MARKERS = ("evidence/ape.db", "evidence\\ape.db")

# Every test workspace this session creates lives under this one well-known segment (see
# tests/conftest.py's _TEST_ROOT) -- used both to recognise a URL/path as safely test-scoped and, in
# remove_test_workspace, to refuse to delete anything that doesn't carry it.
_TEST_ROOT_MARKER = "ape-pytest"


def _looks_like_production_sqlite_path(database_url: str) -> bool:
    if not database_url.startswith("sqlite"):
        return False  # a non-SQLite URL (e.g. Postgres) is never the file this incident was about
    return any(marker in database_url for marker in _PRODUCTION_DB_MARKERS)


def assert_test_database(database_url: str) -> None:
    """Raises if `database_url` looks like the real evidence/ape.db rather than an isolated test path."""
    if _looks_like_production_sqlite_path(database_url):
        raise RuntimeError(
            f"refusing to run tests against what looks like the production database: {database_url!r}"
        )


def validate_engine_url(database_url: str) -> None:
    """Called every time app.database.session builds its engine -- a second, independent check that does
    NOT trust conftest.py's env-var redirection actually ran first. Only enforced while pytest is the
    process running (`"pytest" in sys.modules`); a real deployment is free to point at whatever it likes."""
    if "pytest" not in sys.modules:
        return
    assert_test_database(database_url)


def assert_test_cleanup(db_path: Path, expected_database: str) -> None:
    """A path-based version of the same check, for a fixture that works with a concrete file path rather
    than a URL (tests/test_repository.py's db_session) -- the same refusal from the other direction, so a
    bug in one call site's path construction can't defeat the other's."""
    assert_test_database(expected_database)
    resolved = db_path.resolve()
    if resolved.name == "ape.db" and _TEST_ROOT_MARKER not in resolved.parts:
        raise RuntimeError(f"refusing to run tests against what looks like the production database: {resolved}")


def remove_test_workspace(test_root: Path) -> None:
    """Deletes the per-session temp workspace conftest.py created -- but only if the path is unmistakably
    a disposable test root, never anything that could be a real project or data directory."""
    resolved = test_root.resolve()
    if _TEST_ROOT_MARKER not in resolved.parts:
        raise RuntimeError(
            f"refusing to delete a directory that doesn't look like a disposable test root: {resolved}"
        )
    shutil.rmtree(resolved, ignore_errors=True)
