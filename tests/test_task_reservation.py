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

    assert results.count(True) == 1, "exactly one of twenty simultaneous reservations for the same task_id must win"
    assert results.count(False) == 19


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

    assert all(results.values()), "distinct task_ids must never contend with each other"


def test_reservation_is_visible_to_list_agent_tasks(db_ready):
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"
    with session_scope() as db:
        won = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert won is True

    with session_scope() as db:
        task_ids = [t.task_id for t in repository.list_agent_tasks(db, assessment_id)]
    assert task_ids == [task_id]

    # a second attempt at the SAME task_id while it is still RUNNING must lose -- "already in flight"
    with session_scope() as db:
        again = repository.try_reserve_task(db, _task(task_id, assessment_id))
    assert again is False


def test_a_finished_task_id_can_be_legitimately_reclaimed_for_a_new_attempt(db_ready):
    """task_id is NOT attempt-scoped -- the scheduler can legitimately pick the same candidate again once
    new evidence justifies it (item 6: new evidence restores eligibility). "Already exists" must not
    permanently block that, only "already RUNNING" may."""
    assessment_id = f"ASSESSMENT-RESV-{uuid.uuid4().hex[:8]}"
    task_id = f"TASK-{uuid.uuid4().hex[:8]}"

    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is True

    # the first attempt finishes (a real run would call upsert_agent_task with a terminal status)
    with session_scope() as db:
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=AgentId.WEB_SECURITY,
            task_type="autonomous_next_objective", initiated_by="orchestrator",
            status=TaskStatus.COMPLETED, completed_at=datetime.now(timezone.utc),
        ))

    # a second, later attempt at the same task_id (new evidence) must now succeed...
    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is True

    # ...and while THAT one is running, a third simultaneous attempt must lose
    with session_scope() as db:
        assert repository.try_reserve_task(db, _task(task_id, assessment_id)) is False


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

    assert results.count(True) == 1, "exactly one of fifteen simultaneous reclaim attempts must win"
