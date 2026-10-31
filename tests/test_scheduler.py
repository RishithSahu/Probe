"""Unit tests for the deterministic evidence-based scheduler (app/orchestrator/scheduler.py).

Every test constructs a synthetic NetworkGraph/Finding set -- nothing here names any real challenge,
host, or service, matching the explicit "must generalise to previously unseen environments" requirement.
"""
from __future__ import annotations

import pytest

from app.core.schemas import (
    AgentId,
    AssessmentPolicy,
    Confidence,
    Finding,
    FindingStatus,
    NetworkGraph,
    NetworkGraphAssetRecord,
    NetworkGraphServiceRecord,
    PtesPhase,
    Severity,
    Surface,
)
from app.core.scope_guard import ScopeGuard
from app.orchestrator.scheduler import DEFAULT_WEIGHTS, generate_candidates, select_next


def _finding(service_id: str, *, confidence: Confidence = Confidence.HIGH, surface: Surface = Surface.BINARY) -> Finding:
    return Finding(
        finding_id=f"FINDING-{service_id}-{confidence.value}", assessment_id="A", agent_id=AgentId.BINARY_ANALYSIS,
        surface=surface, service_id=service_id, title="t", description="d", severity=Severity.MEDIUM,
        confidence=confidence, status=FindingStatus.SUSPECTED, ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
    )


def _graph(*services: tuple[str, int, str | None]) -> NetworkGraph:
    return NetworkGraph(
        scope_id="SCOPE-TEST",
        assets=[NetworkGraphAssetRecord(
            asset_id="HOST-A", ip="10.0.0.1",
            services=[NetworkGraphServiceRecord(service_id=sid, asset_id="HOST-A", port=port, service_name=name)
                     for sid, port, name in services],
        )],
    )


def _guard(graph: NetworkGraph, **policy_overrides) -> ScopeGuard:
    defaults = dict(allow_passive_web_analysis=True, allow_network_service_assessment=True, dry_run=False)
    defaults.update(policy_overrides)
    return ScopeGuard(AssessmentPolicy(**defaults), graph)


def test_evidence_backed_service_outranks_unrelated_unvisited_service():
    graph = _graph(("HOST-A:80/tcp", 80, "http"), ("HOST-A:81/tcp", 81, "http"))
    findings = [_finding("HOST-A:80/tcp", confidence=Confidence.HIGH)]
    candidates = generate_candidates(graph, [], findings, guard=_guard(graph))
    winner, explanation = select_next(candidates)
    assert winner.service_id == "HOST-A:80/tcp"
    assert winner.source == "finding_followup"
    assert explanation["selected"]["factors"]["objective_relevance"] == 1.0


def test_strong_evidence_outranks_routine_header_hygiene_style_candidate():
    """A binary/protocol-explaining lead (high-confidence finding) must outrank a same-type service with
    no backing evidence at all -- the 'missing header should not outrank a real lead' requirement."""
    graph = _graph(("HOST-A:443/tcp", 443, "https"), ("HOST-A:8080/tcp", 8080, "http"))
    findings = [_finding("HOST-A:443/tcp", confidence=Confidence.HIGH, surface=Surface.WEB)]
    candidates = generate_candidates(graph, [], findings, guard=_guard(graph))
    winner, _ = select_next(candidates)
    assert winner.service_id == "HOST-A:443/tcp"


def test_scopeguard_rejection_cannot_be_overridden_by_priority():
    graph = _graph(("HOST-A:80/tcp", 80, "http"))
    findings = [_finding("HOST-A:80/tcp", confidence=Confidence.HIGH)]  # would otherwise win easily
    guard = _guard(graph, allow_passive_web_analysis=False)  # policy forbids it outright
    candidates = generate_candidates(graph, [], findings, guard=guard)
    assert candidates == [], "a ScopeGuard-denied candidate must never be scored or selected, at any priority"


def test_held_asset_is_never_a_candidate_regardless_of_evidence():
    graph = NetworkGraph(scope_id="SCOPE-TEST", assets=[NetworkGraphAssetRecord(
        asset_id="HOST-HELD", ip="10.0.0.2", held=True,
        services=[NetworkGraphServiceRecord(service_id="HOST-HELD:80/tcp", asset_id="HOST-HELD", port=80,
                                            service_name="http")],
    )])
    candidates = generate_candidates(graph, [], [_finding("HOST-HELD:80/tcp")], guard=_guard(graph))
    assert candidates == []


def test_duplicate_investigation_is_deprioritised_not_rescored_from_scratch():
    graph = _graph(("HOST-A:22/tcp", 22, "ssh"))
    prior_attempt = [{"asset_id": "HOST-A", "service_id": "HOST-A:22/tcp"}]
    fresh = generate_candidates(graph, [], [], guard=_guard(graph))[0]
    repeated = generate_candidates(graph, prior_attempt, [], guard=_guard(graph))[0]
    assert repeated.factors["novelty"] < fresh.factors["novelty"]
    assert repeated.score(DEFAULT_WEIGHTS) < fresh.score(DEFAULT_WEIGHTS)


def test_previously_unproductive_task_becomes_eligible_again_with_new_evidence():
    graph = _graph(("HOST-A:22/tcp", 22, "ssh"))
    prior_attempt = [{"asset_id": "HOST-A", "service_id": "HOST-A:22/tcp"}]
    without_evidence = generate_candidates(graph, prior_attempt, [], guard=_guard(graph))[0]
    with_new_evidence = generate_candidates(
        graph, prior_attempt, [_finding("HOST-A:22/tcp", confidence=Confidence.HIGH)], guard=_guard(graph)
    )[0]
    assert with_new_evidence.factors["novelty"] > without_evidence.factors["novelty"]
    assert with_new_evidence.score(DEFAULT_WEIGHTS) > without_evidence.score(DEFAULT_WEIGHTS)


def test_a_completed_service_can_still_generate_a_finding_driven_candidate():
    """A finding tied to a service that already has a prior task must still be scoreable -- a completed
    service assessment must not permanently block investigating a NEW finding associated with it."""
    graph = _graph(("HOST-A:80/tcp", 80, "http"))
    prior_attempt = [{"asset_id": "HOST-A", "service_id": "HOST-A:80/tcp"}]
    candidates = generate_candidates(graph, prior_attempt, [_finding("HOST-A:80/tcp", confidence=Confidence.HIGH)],
                                     guard=_guard(graph))
    assert len(candidates) == 1
    assert candidates[0].source == "finding_followup"
    assert candidates[0].factors["novelty"] == 1.0


def test_an_unproductive_repeat_of_the_same_evidence_does_not_loop_forever():
    """A service already dispatched BECAUSE of a finding, whose attempt produced nothing new, must not
    stay at full novelty forever (it would otherwise always win and starve every other candidate)."""
    graph = _graph(("HOST-A:8833/tcp", 8833, "unknown"))
    finding = _finding("HOST-A:8833/tcp", confidence=Confidence.HIGH)
    prior_attempt = [{"asset_id": "HOST-A", "service_id": "HOST-A:8833/tcp", "finding_count_at_dispatch": 1}]
    candidates = generate_candidates(graph, prior_attempt, [finding], guard=_guard(graph))
    assert candidates[0].factors["novelty"] < 1.0, "repeating the same evidence with no new findings must decay"


def test_empty_queue_returns_a_meaningful_blocker():
    graph = NetworkGraph(scope_id="SCOPE-TEST", assets=[])
    winner, explanation = select_next(generate_candidates(graph, [], [], guard=_guard(graph)))
    assert winner is None
    assert "reason" in explanation and explanation["reason"]


def test_selection_explanation_includes_every_scored_candidate():
    graph = _graph(("HOST-A:80/tcp", 80, "http"), ("HOST-A:22/tcp", 22, "ssh"))
    candidates = generate_candidates(graph, [], [], guard=_guard(graph))
    winner, explanation = select_next(candidates)
    assert len(explanation["considered"]) == len(candidates)
    assert all("total_score" in c for c in explanation["considered"])
    assert explanation["selected"]["candidate_id"] == winner.candidate_id


def test_web_network_and_binary_style_candidates_use_the_same_scoring_formula():
    """Ranking consistency: the same four factors, the same weights, regardless of which agent a
    candidate would dispatch -- not a special-cased formula per agent type."""
    graph = _graph(("HOST-A:80/tcp", 80, "http"), ("HOST-A:21/tcp", 21, "ftp"))
    candidates = generate_candidates(graph, [], [_finding("HOST-A:80/tcp"), _finding("HOST-A:21/tcp")], guard=_guard(graph))
    assert len(candidates) == 2
    assert all(set(c.factors) == set(DEFAULT_WEIGHTS) for c in candidates)
