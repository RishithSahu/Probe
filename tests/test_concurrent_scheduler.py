"""Proves app.orchestrator.autonomous_loop.run_concurrent_iteration actually dispatches multiple
independent candidates in parallel -- not just correctly, but concurrently. The agent calls themselves are
stubbed (a real one does real network I/O) with a function that sleeps, so wall-clock timing can tell real
parallel dispatch apart from a scheduler that is merely a for-loop with a reassuring name.
"""
from __future__ import annotations

import time
import uuid

import pytest

from app.core.config import settings
from app.core.schemas import (
    AgentId,
    AgentResult,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    NetworkGraphAssetRecord,
    NetworkGraphServiceRecord,
    TaskStatus,
)
from app.database import repository
from app.database.session import init_db, session_scope
from app.orchestrator import autonomous_loop
from app.orchestrator.task_ids import make_task_id

SLEEP_S = 0.3


@pytest.fixture
def assessment(tmp_path, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    init_db()

    assessment_id = f"ASSESSMENT-CONC-{uuid.uuid4().hex[:8]}"
    # Four independent network services (not HTTP, so the scheduler routes them to the Network
    # Vulnerability agent) on four separate assets -- genuinely independent work, nothing one depends on.
    assets = [
        NetworkGraphAssetRecord(
            asset_id=f"HOST-{i}", ip=f"10.20.30.{10 + i}",
            services=[NetworkGraphServiceRecord(service_id=f"HOST-{i}:22/tcp", asset_id=f"HOST-{i}",
                                                 port=22, protocol="tcp", service_name="ssh")],
        )
        for i in range(4)
    ]
    from app.core.schemas import NetworkGraph
    graph = NetworkGraph(scope_id="SCOPE-TEST", assets=assets)

    policy = AssessmentPolicy(
        allow_network_service_assessment=True, dry_run=False,
        approved_asset_ids=[a.asset_id for a in assets],
    )
    with session_scope() as db:
        repository.create_assessment(db, Assessment(
            assessment_id=assessment_id, scope_id=graph.scope_id, status=AssessmentStatus.RUNNING,
            assessment_policy=policy,
        ))
        repository.store_network_graph(db, assessment_id, graph)
    return assessment_id, policy


def _slow_stub(*_a, **kw):
    time.sleep(SLEEP_S)
    assessment_id = kw.get("assessment_id")
    return AgentResult(agent_id=AgentId.NETWORK_VULNERABILITY_DETECTIVE, assessment_id=assessment_id,
                       execution_status=TaskStatus.COMPLETED, findings=[], evidence=[])


def test_four_independent_candidates_run_concurrently_not_sequentially(assessment, monkeypatch, tmp_path):
    assessment_id, policy = assessment
    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent", _slow_stub)
    # this test is about proving real parallel dispatch, not the per-surface cap added alongside it --
    # raise the cap so all four of this test's candidates are eligible to run together (see
    # test_per_surface_cap_limits_how_many_of_one_surface_run_at_once for the cap itself).
    monkeypatch.setattr(settings, "max_concurrent_network_tasks", 4)

    start = time.monotonic()
    traces = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
    )
    elapsed = time.monotonic() - start

    assert len(traces) == 4
    assert {t.task_id for t in traces} == {
        make_task_id("autonomous", "network_vulnerability_detective", assessment_id, f"HOST-{i}:22/tcp")[0]
        for i in range(4)
    }
    # four independent candidates, each a SLEEP_S-long "agent call": sequential execution would take
    # ~4 * SLEEP_S; real concurrent dispatch takes ~1 * SLEEP_S. 2x is a generous margin over scheduling/
    # thread-pool/DB overhead while still failing hard if this silently degraded to one-at-a-time.
    assert elapsed < SLEEP_S * 2, f"took {elapsed:.2f}s for 4 candidates at {SLEEP_S}s each -- not run concurrently"

    with session_scope() as db:
        tasks = {t.task_id: t.status for t in repository.list_agent_tasks(db, assessment_id)}
    assert len(tasks) == 4
    assert all(status == TaskStatus.COMPLETED.value for status in tasks.values())


def test_per_surface_cap_limits_how_many_of_one_surface_run_at_once(assessment, monkeypatch, tmp_path):
    """Item 6: a per-surface concurrency limit, independent of max_inflight. All four candidates are
    Network Vulnerability Detective work (the fixture's four assets are all plain TCP services), so capping
    max_concurrent_network_tasks must limit the batch even though max_inflight itself would allow more."""
    assessment_id, policy = assessment
    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent", _slow_stub)
    monkeypatch.setattr(settings, "max_concurrent_network_tasks", 2)

    traces = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
    )
    assert len(traces) == 2, "the per-surface cap (2) must win over max_inflight (4) for this all-one-surface batch"

    # once those two finish (COMPLETED, no longer RUNNING), the surface's pool has room again
    traces2 = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
    )
    assert len(traces2) == 2
    assert {t.task_id for t in traces} & {t.task_id for t in traces2} == set()


def test_candidates_on_the_same_target_are_not_dispatched_together(tmp_path, monkeypatch):
    """Item 6: one task per target at a time within a single dispatch call -- two services on the SAME
    asset must not both be sent to agents simultaneously from one run_concurrent_iteration call."""
    from app.core.config import settings as cfg
    from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus, NetworkGraph

    monkeypatch.setattr(cfg, "evidence_dir", tmp_path / "evidence")
    init_db()
    assessment_id = f"ASSESSMENT-CONC-{uuid.uuid4().hex[:8]}"
    asset = NetworkGraphAssetRecord(
        asset_id="HOST-SHARED", ip="10.20.30.50",
        services=[
            NetworkGraphServiceRecord(service_id="HOST-SHARED:22/tcp", asset_id="HOST-SHARED", port=22, protocol="tcp", service_name="ssh"),
            NetworkGraphServiceRecord(service_id="HOST-SHARED:3306/tcp", asset_id="HOST-SHARED", port=3306, protocol="tcp", service_name="mysql"),
        ],
    )
    graph = NetworkGraph(scope_id="SCOPE-TEST", assets=[asset])
    policy = AssessmentPolicy(allow_network_service_assessment=True, dry_run=False, approved_asset_ids=["HOST-SHARED"])
    with session_scope() as db:
        repository.create_assessment(db, Assessment(
            assessment_id=assessment_id, scope_id=graph.scope_id, status=AssessmentStatus.RUNNING, assessment_policy=policy,
        ))
        repository.store_network_graph(db, assessment_id, graph)

    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent", _slow_stub)

    traces = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
    )
    assert len(traces) == 1, "two services on the same asset must not both be reserved in one dispatch call"

    traces2 = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
    )
    assert len(traces2) == 1
    assert {t.task_id for t in traces} & {t.task_id for t in traces2} == set()


def test_max_inflight_caps_how_many_run_at_once(assessment, monkeypatch, tmp_path):
    assessment_id, policy = assessment
    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent", _slow_stub)

    traces = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=2,
    )
    assert len(traces) == 2, "max_inflight=2 must reserve and run exactly two of the four eligible candidates"

    # the other two remain eligible (never reserved) -- a second call should pick up where the first left off
    traces2 = autonomous_loop.run_concurrent_iteration(
        assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=2,
    )
    assert len(traces2) == 2
    assert {t.task_id for t in traces} & {t.task_id for t in traces2} == set(), "the second call must not re-run what the first already completed"


def test_concurrent_dispatch_never_runs_the_same_candidate_twice(assessment, monkeypatch, tmp_path):
    """The actual item-3/item-4 acceptance test: call run_concurrent_iteration from several threads at
    once (simulating overlapping scheduler ticks) and confirm the total number of executions equals the
    number of distinct candidates, never more -- no duplicate equivalent work despite the race."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    assessment_id, policy = assessment
    call_count = {"n": 0}
    lock = threading.Lock()

    def counting_stub(*_a, **kw):
        with lock:
            call_count["n"] += 1
        time.sleep(0.05)
        return AgentResult(agent_id=AgentId.NETWORK_VULNERABILITY_DETECTIVE, assessment_id=kw.get("assessment_id"),
                           execution_status=TaskStatus.COMPLETED, findings=[], evidence=[])

    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent", counting_stub)

    barrier = threading.Barrier(3)

    def tick():
        barrier.wait()
        return autonomous_loop.run_concurrent_iteration(
            assessment_id, policy=policy, output_dir=tmp_path / "out", max_inflight=4,
        )

    with ThreadPoolExecutor(max_workers=3) as pool:
        all_traces = list(pool.map(lambda _: tick(), range(3)))

    executed_task_ids = [t.task_id for traces in all_traces for t in traces if t.task_id]
    assert len(executed_task_ids) == len(set(executed_task_ids)) == 4, \
        "three overlapping scheduler ticks must still execute each of the four candidates exactly once"
    assert call_count["n"] == 4, "the agent itself must only ever be invoked once per candidate"
