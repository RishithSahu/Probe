"""Tests for app/api/routes.py.

First test coverage this module has had. Focused on the fix in
`_run_orchestrator_background`: an exception escaping the LangGraph run
used to be logged and silently dropped, leaving the assessment stuck at
`running` in the database forever with no way for an API caller to learn
it actually failed.
"""
from __future__ import annotations

import uuid

import pytest

from app.api.routes import _run_orchestrator_background
from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus
from app.database import repository
from app.database.session import SessionLocal, init_db


@pytest.fixture
def assessment_id():
    init_db()
    aid = f"ASSESSMENT-API-TEST-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    repository.create_assessment(
        db, Assessment(assessment_id=aid, scope_id="SCOPE-X", status=AssessmentStatus.RUNNING,
                        assessment_policy=AssessmentPolicy()),
    )
    db.commit()
    db.close()
    return aid


def test_uncaught_exception_marks_assessment_failed_not_stuck_running(assessment_id, monkeypatch):
    def _raise(_state):
        raise RuntimeError("simulated catastrophic orchestrator bug")

    monkeypatch.setattr("app.api.routes.run_assessment", _raise)

    _run_orchestrator_background({"assessment_id": assessment_id})

    db = SessionLocal()
    record = repository.get_assessment(db, assessment_id)
    db.close()
    assert record.status == "failed"
    assert record.completed_at is not None


def test_successful_run_is_left_to_the_graphs_own_final_status(assessment_id, monkeypatch):
    """A normal (non-crashing) run must not be touched by the background
    wrapper's error-handling path — the graph's own complete_assessment
    node is the only thing that should set the final status in that case."""
    calls = []

    def _ok(state):
        calls.append(state)
        return {"assessment_status": "completed"}

    monkeypatch.setattr("app.api.routes.run_assessment", _ok)
    _run_orchestrator_background({"assessment_id": assessment_id})

    assert len(calls) == 1
    db = SessionLocal()
    record = repository.get_assessment(db, assessment_id)
    db.close()
    # Status is whatever it was before (RUNNING, from the fixture) since the
    # background wrapper itself never touches it on success — only on crash.
    assert record.status == "running"
