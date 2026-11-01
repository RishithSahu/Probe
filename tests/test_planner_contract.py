"""Item 11: the planner interface is data-only and degrades safely."""
from __future__ import annotations

from app.core.schemas import NetworkGraph
from app.orchestrator.planner import (
    AssessmentSummary,
    DeterministicNullPlanner,
    ProposedInvestigation,
    RemoteHTTPPlanner,
)


def _summary(**overrides) -> AssessmentSummary:
    defaults = dict(
        assessment_id="ASSESSMENT-PLANNER-TEST", scope_cidrs=("10.0.0.0/24",),
        graph=NetworkGraph(scope_id="SCOPE-TEST"), findings=(), task_history=(),
        available_capabilities=("web_security_agent", "network_vulnerability_detective"),
        unresolved_objective_ids=(), execution_budget_seconds=600.0,
    )
    defaults.update(overrides)
    return AssessmentSummary(**defaults)


def test_deterministic_null_planner_always_proposes_nothing():
    planner = DeterministicNullPlanner()
    assert planner.propose(_summary()) == []
    assert planner.propose(_summary(unresolved_objective_ids=("OBJ-1",))) == []


def test_proposed_investigation_is_plain_data_not_a_callable():
    proposal = ProposedInvestigation(
        operation_type="web_assessment", asset_id="HOST-1", service_id="HOST-1:80/tcp",
        rationale="unvisited http service", confidence=0.4,
    )
    assert not callable(proposal)
    assert not hasattr(proposal, "execute") and not hasattr(proposal, "run")


def test_remote_planner_degrades_to_empty_list_when_unreachable():
    planner = RemoteHTTPPlanner("http://127.0.0.1:1", timeout_seconds=0.5)  # nothing listens here
    assert planner.propose(_summary()) == []


def test_remote_planner_drops_malformed_proposals_without_raising(monkeypatch):
    import httpx

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return [
                {"operation_type": "web_assessment", "asset_id": "HOST-1", "confidence": 0.5},
                {"operation_type": "network_assessment"},  # missing required asset_id -> dropped
                "not even a dict",  # dropped
            ]

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse())
    planner = RemoteHTTPPlanner("http://127.0.0.1:9")
    proposals = planner.propose(_summary())
    assert len(proposals) == 1
    assert proposals[0].asset_id == "HOST-1"
