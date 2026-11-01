"""Item 5: --max-minutes must be a real wall-clock promise, not just a between-iterations check.

Bug found live: a single iteration's own agent dispatch (a real web assessment especially) has no
internal time budget and can run for minutes; the deadline used to be checked only between iterations, so
one slow iteration blew straight through the remaining budget -- --max-minutes 2 measurably overran to 4+
minutes in a real run.
"""
from __future__ import annotations

import time
import uuid

import pytest

from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus, NetworkGraph, NetworkGraphAssetRecord, NetworkGraphServiceRecord
from app.database import repository
from app.database.session import init_db, session_scope
from app.orchestrator import __main__ as cli
from app.orchestrator import autonomous_loop


@pytest.fixture
def assessment(tmp_path, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    init_db()
    assessment_id = f"ASSESSMENT-TIMEBUDGET-{uuid.uuid4().hex[:8]}"
    graph = NetworkGraph(scope_id="SCOPE-10.0.0.0-24", assets=[NetworkGraphAssetRecord(
        asset_id="HOST-1", ip="10.0.0.1",
        services=[NetworkGraphServiceRecord(service_id="HOST-1:22/tcp", asset_id="HOST-1", port=22, service_name="ssh")],
    )])
    policy = AssessmentPolicy(allow_network_service_assessment=True, dry_run=False, approved_asset_ids=["HOST-1"])
    with session_scope() as db:
        repository.create_assessment(db, Assessment(assessment_id=assessment_id, scope_id=graph.scope_id,
                                                     status=AssessmentStatus.RUNNING, assessment_policy=policy))
        repository.store_network_graph(db, assessment_id, graph)
    return assessment_id


def test_run_stops_at_the_budget_even_when_one_iteration_is_much_slower(assessment, monkeypatch):
    assessment_id = assessment
    SLOW_S = 2.0

    def _slow_run_next_iteration(*_a, **_k):
        time.sleep(SLOW_S)
        from app.orchestrator.autonomous_loop import IterationTrace
        return IterationTrace(task_id="", parent_task_id=None, agent_id=None, objective=None,
                              blocked_reason="slow stub finished")

    monkeypatch.setattr(cli, "run_next_iteration", _slow_run_next_iteration)

    start = time.monotonic()
    cli.run(assessment_id, "10.0.0.0/24", max_minutes=SLOW_S / 60 / 4)  # budget << one slow iteration
    elapsed = time.monotonic() - start

    # Before the fix: the loop would wait the FULL SLOW_S for the single iteration regardless of the tiny
    # budget (the deadline was never consulted while an iteration was in flight). After the fix: the CLI
    # stops waiting at (approximately) the budget, not at SLOW_S.
    assert elapsed < SLOW_S, f"took {elapsed:.2f}s against a budget of {SLOW_S/4:.2f}s and a {SLOW_S}s iteration -- the time budget was not actually enforced"
