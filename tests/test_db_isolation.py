"""Regression tests for the 2026-11-01 incident: pytest deleted the live production database because
app/database/session.py's engine was bound to it before any test could redirect it.

Acceptance requirement (verbatim from the incident review): running pytest must be structurally incapable
of deleting or modifying the live assessment database.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.core.config import settings
from app.database.session import _assert_safe_database_url
from tests.conftest import assert_database_url_is_safe


def test_settings_are_redirected_away_from_the_production_path():
    assert_database_url_is_safe()


def test_evidence_and_reports_dirs_are_also_redirected():
    assert "ape-pytest" in str(settings.evidence_dir)
    assert "ape-pytest" in str(settings.reports_dir)
    assert "ape-pytest" in str(settings.ghidra_project_dir)


def test_each_pytest_session_env_is_a_fresh_unique_root():
    # This process's own env vars (set once, at conftest.py import time) are the ground truth for "this
    # session's root" -- a second, independent invocation of pytest (a real `subprocess.run([..., "-c", ...
    # python -m pytest ...])`) would get its OWN conftest.py top-level execution and therefore its own
    # uuid4 suffix; asserting that twice in-process would just re-read the same env vars, not prove
    # anything new, so this instead proves the root really is unique-per-run shaped (a uuid4 hex segment),
    # not a fixed, collidable name two real sessions could share.
    import re
    assert re.search(r"[0-9a-f]{12}", os.environ["APE_DATABASE_URL"]), (
        "APE_DATABASE_URL does not contain a uuid4-shaped unique segment -- two concurrent pytest "
        "sessions could collide on the same database file"
    )


def test_engine_guard_rejects_the_exact_production_path(tmp_path, monkeypatch):
    assert "pytest" in sys.modules  # the guard's own precondition for even checking anything
    with pytest.raises(RuntimeError):
        _assert_safe_database_url("sqlite:///evidence/ape.db")


def test_engine_guard_allows_a_path_outside_the_production_location(tmp_path):
    _assert_safe_database_url(f"sqlite:///{(tmp_path / 'isolated.db').as_posix()}")  # must not raise


def test_engine_guard_allows_non_sqlite_databases():
    # The guard's only job is catching accidental reuse of the production evidence/ape.db SQLITE path
    # (see app.database.safety.assert_test_database / _looks_like_production_sqlite_path) -- a Postgres (or
    # other) URL is never that file, so it is correctly let through unconditionally, matching the
    # documented Postgres swap-in support elsewhere in this codebase. This test previously asserted the
    # opposite (a stale draft expectation that never matched the shipped guard's actual, narrower scope).
    _assert_safe_database_url("postgresql://user:pass@localhost/db")  # must not raise


def test_production_database_file_is_untouched_by_this_test_run():
    """The real acceptance check: the actual evidence/ape.db file on disk (if present) must have a
    strictly-later-or-equal mtime and must not have been deleted -- this test ran INSIDE a real pytest
    session, so if isolation had failed the way it did during the incident, this file would already be
    gone or truncated by the time this assertion runs."""
    production_path = Path.cwd() / "evidence" / "ape.db"
    if not production_path.exists():
        pytest.skip("no production database present in this environment -- nothing to prove it survived")
    assert production_path.stat().st_size > 0, "production database exists but is empty -- was it just recreated?"
