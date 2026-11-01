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

from fastapi import BackgroundTasks, HTTPException

from app.api.routes import _run_orchestrator_background, create_assessment
from app.api.schemas import CreateAssessmentRequest
from app.core.config import settings
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


def test_create_assessment_rejects_live_assessment_with_fixtures_still_enabled(monkeypatch):
    """Spec item 3: the same live_assessment-vs-fixtures gate the CLI applies
    (app.core.execution_profile.preflight_check, called from
    app/orchestrator/__main__.py) must also apply to the FastAPI entry point --
    this used to be the only place in the whole app that called it, so an
    assessment created over the API could silently run fixture-backed under
    execution_profile=live_assessment with no warning at all."""
    init_db()
    monkeypatch.setattr(settings, "execution_profile", "live_assessment")
    monkeypatch.setattr(settings, "web_agent_use_fixtures", True)

    db = SessionLocal()
    try:
        with pytest.raises(HTTPException) as exc_info:
            create_assessment(
                CreateAssessmentRequest(scope_id="SCOPE-X", run_immediately=False),
                BackgroundTasks(),
                db=db,
            )
    finally:
        db.close()
    assert exc_info.value.status_code == 400
    assert "live_assessment" in exc_info.value.detail


def test_create_assessment_allows_synthetic_test_profile(monkeypatch):
    """The default profile (synthetic_test) must be unaffected -- this is what every other test in this
    file, and every test elsewhere that creates an assessment, relies on continuing to work unchanged."""
    init_db()
    monkeypatch.setattr(settings, "execution_profile", "synthetic_test")

    db = SessionLocal()
    try:
        response = create_assessment(
            CreateAssessmentRequest(scope_id="SCOPE-X", run_immediately=False),
            BackgroundTasks(),
            db=db,
        )
    finally:
        db.close()
    assert response.status == AssessmentStatus.CREATED
