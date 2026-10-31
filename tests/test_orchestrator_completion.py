"""Regression tests for `complete_assessment`'s final-status logic.

Bug found during review: the function used to derive AssessmentStatus
partly from `OrchestratorState.errors`, a list that also accumulates benign
diagnostic notes (e.g. validate_scope noting a permission is enabled with
nothing in the graph to use it on) alongside genuine task failures. A fully
successful run that merely logged such a note was incorrectly reported as
`partially_completed`. Fixed to use each task's actual persisted
TaskStatus instead.
"""
from __future__ import annotations

import uuid

import pytest

from app.core.schemas import AgentId, AgentTask, Assessment, AssessmentPolicy, AssessmentStatus, TaskStatus
from app.database import repository
from app.database.session import SessionLocal, init_db
from app.orchestrator.nodes import complete_assessment


@pytest.fixture
def assessment_id():
    # A fresh id per test — these are real rows in the shared SQLite file,
    # not an isolated in-memory fixture, so reusing one id across tests
    # would let one test's AgentTask rows leak into the next.
    init_db()
    aid = f"ASSESSMENT-COMPLETION-TEST-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    repository.create_assessment(
        db, Assessment(assessment_id=aid, scope_id="SCOPE-X", status=AssessmentStatus.CREATED,
                        assessment_policy=AssessmentPolicy()),
    )
    db.commit()
    db.close()
    return aid


def _set_task_statuses(assessment_id: str, statuses: dict[AgentId, TaskStatus]) -> None:
    db = SessionLocal()
    for agent, status in statuses.items():
        repository.upsert_agent_task(
            db, AgentTask(task_id=f"TASK-{agent.value}-{assessment_id}", assessment_id=assessment_id,
                          agent_id=agent, task_type="x", status=status),
        )
    db.commit()
    db.close()


def test_benign_warning_with_all_tasks_skipped_is_completed_not_partial(assessment_id):
    _set_task_statuses(assessment_id, {
        AgentId.WEB_SECURITY: TaskStatus.SKIPPED,
        AgentId.BINARY_ANALYSIS: TaskStatus.SKIPPED,
        AgentId.NETWORK_VULNERABILITY: TaskStatus.SKIPPED,
    })
    state = {
        "assessment_id": assessment_id,
        "errors": ["validate_scope: allow_passive_web_analysis is enabled but no HTTP/HTTPS services were found in the graph"],
    }
    result = complete_assessment(state)
    assert result["assessment_status"] == "completed"


def test_all_attempted_tasks_completed_is_completed(assessment_id):
    _set_task_statuses(assessment_id, {
        AgentId.WEB_SECURITY: TaskStatus.COMPLETED,
        AgentId.BINARY_ANALYSIS: TaskStatus.COMPLETED,
        AgentId.NETWORK_VULNERABILITY: TaskStatus.SKIPPED,
    })
    result = complete_assessment({"assessment_id": assessment_id, "errors": []})
    assert result["assessment_status"] == "completed"


def test_one_of_two_attempted_tasks_failed_is_partially_completed(assessment_id):
    _set_task_statuses(assessment_id, {
        AgentId.WEB_SECURITY: TaskStatus.COMPLETED,
        AgentId.BINARY_ANALYSIS: TaskStatus.FAILED,
    })
    result = complete_assessment({"assessment_id": assessment_id, "errors": []})
    assert result["assessment_status"] == "partially_completed"


def test_all_attempted_tasks_failed_is_failed(assessment_id):
    _set_task_statuses(assessment_id, {
        AgentId.WEB_SECURITY: TaskStatus.FAILED,
        AgentId.BINARY_ANALYSIS: TaskStatus.FAILED,
    })
    result = complete_assessment({"assessment_id": assessment_id, "errors": []})
    assert result["assessment_status"] == "failed"


def test_nothing_attempted_at_all_is_completed(assessment_id):
    # No tasks recorded (e.g. validate_assessment failed before create_agent_tasks ran) —
    # not the scenario this test targets, but complete_assessment must not crash on it.
    result = complete_assessment({"assessment_id": assessment_id, "errors": []})
    assert result["assessment_status"] == "completed"
