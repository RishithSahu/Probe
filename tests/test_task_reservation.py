"""Real concurrent exercise of repository.try_reserve_task -- the primitive the concurrent orchestrator
scheduler uses to claim a candidate exactly once among several simultaneous dispatch attempts. Uses real
threads racing the real (file-backed) SQLite database the rest of the suite uses, not a mock.
"""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.core.schemas import AgentId, AgentTask, TaskStatus
from app.database import repository
from app.database.session import init_db, session_scope


@pytest.fixture
def db_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    init_db()


def _task(task_id: str, assessment_id: str) -> AgentTask:
    return AgentTask(
        task_id=task_id, assessment_id=assessment_id, agent_id=AgentId.WEB_SECURITY,
        task_type="autonomous_next_objective", initiated_by="orchestrator",
        status=TaskStatus.RUNNING, started_at=datetime.now(timezone.utc),
    )


def test_many_threads_racing_one_task_id_only_one_reservation_wins(db_ready):
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"
    barrier = threading.Barrier(20)

    def go(_i):
        barrier.wait()
        with session_scope() as db:
            return repository.try_reserve_task(db, _task(task_id, assessment_id))

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(go, range(20)))

    tokens = [r for r in results if r is not None]
    assert len(tokens) == 1, "exactly one of twenty simultaneous reservations for the same task_id must win"
    assert results.count(None) == 19


def test_distinct_task_ids_all_reserve_independently(db_ready):
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_ids = [f"TASK-{i}-{uuid.uuid4().hex[:6]}" for i in range(10)]
    barrier = threading.Barrier(len(task_ids))

    def go(task_id):
        barrier.wait()
        with session_scope() as db:
            return task_id, repository.try_reserve_task(db, _task(task_id, assessment_id))

    with ThreadPoolExecutor(max_workers=len(task_ids)) as pool:
        results = dict(pool.map(go, task_ids))

    assert all(v is not None for v in results.values()), "distinct task_ids must never contend with each other"


def test_reservation_is_visible_to_list_agent_tasks(db_ready):
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"
    with session_scope() as db:
        won = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert won is not None

    with session_scope() as db:
        task_ids = [t.task_id for t in repository.list_agent_tasks(db, assessment_id)]
    assert task_ids == [task_id]

    # a second attempt at the SAME task_id while it is still RUNNING must lose -- "already in flight"
    with session_scope() as db:
        again = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert again is None


def test_a_finished_task_id_can_be_legitimately_reclaimed_for_a_new_attempt(db_ready):
    """task_id is NOT attempt-scoped -- the scheduler can legitimately pick the same candidate again once
    new evidence justifies it (item 6: new evidence restores eligibility). "Already exists" must not
    permanently block that, only "already RUNNING" may."""
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"

    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is not None

    # the first attempt finishes (a real run would call upsert_agent_task with a terminal status)
    with session_scope() as db:
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=AgentId.WEB_SECURITY,
            task_type="autonomous_next_objective", initiated_by="orchestrator",
            status=TaskStatus.COMPLETED, completed_at=datetime.now(timezone.utc),
        ))

    # a second, later attempt at the same task_id (new evidence) must now succeed...
    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is not None

    # ...and while THAT one is running, a third simultaneous attempt must lose
    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is None


def test_concurrent_reclaim_attempts_on_a_finished_task_id_only_one_wins(db_ready):
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"
    with session_scope() as db:
        repository.try_reserve_task(db, _task(task_id, assessment_id))
    with session_scope() as db:
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=AgentId.WEB_SECURITY,
            task_type="autonomous_next_objective", initiated_by="orchestrator",
            status=TaskStatus.FAILED, completed_at=datetime.now(timezone.utc),
        ))

    barrier = threading.Barrier(15)

    def go(_i):
        barrier.wait()
        with session_scope() as db:
            return repository.try_reserve_task(db, _task(task_id, assessment_id))

    with ThreadPoolExecutor(max_workers=15) as pool:
        results = list(pool.map(go, range(15)))

    tokens = [r for r in results if r is not None]
    assert len(tokens) == 1, "exactly one of fifteen simultaneous reclaim attempts must win"


def test_try_complete_task_rejects_a_stale_token_after_a_retry_reclaimed_the_task(db_ready):
    """The scenario item 7 of the concurrency spec describes: run_concurrently() cannot force-kill a
    running thread, only stop waiting on it. If that abandoned thread finishes LATER, after a retry has
    already reserved the same task_id under a NEW token, its write must be rejected, not silently accepted
    as if it came from the current attempt."""
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"

    with session_scope() as db:
        old_token = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert old_token is not None

    # the orchestrator gives up on this attempt (run_concurrently()'s timeout) and marks it failed,
    # WITHOUT going through try_complete_task (this models the abandoned thread simply never getting there
    # in time) -- then a retry reclaims the same task_id under a fresh token
    with session_scope() as db:
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=AgentId.WEB_SECURITY,
            task_type="autonomous_next_objective", initiated_by="orchestrator",
            status=TaskStatus.FAILED, completed_at=datetime.now(timezone.utc),
        ))
    with session_scope() as db:
        new_token = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert new_token is not None and new_token != old_token

    # the original, abandoned thread FINALLY finishes and tries to persist its (stale) result
    with session_scope() as db:
        accepted = repository.try_complete_task(
            db, task_id, old_token, status=TaskStatus.COMPLETED.value, output_data={"stale": True},
        )
    assert accepted is False, "a stale reservation_token must never be allowed to overwrite a newer attempt"

    # the retry's own, current result is still accepted under its own token
    with session_scope() as db:
        accepted2 = repository.try_complete_task(
            db, task_id, new_token, status=TaskStatus.COMPLETED.value, output_data={"stale": False},
        )
    assert accepted2 is True

    with session_scope() as db:
        tasks = repository.list_agent_tasks(db, assessment_id)
        output = tasks[0].output_data
    assert output == {"stale": False}, "the stale write must not have landed, even partially"
