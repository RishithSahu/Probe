"""Integration test for the autonomous loop's web-to-binary handoff: a Web Agent result reporting a binary
reference must make `run_next_iteration` dispatch the SAME binary pipeline `handle_discovered_binaries` uses
(`process_discovered_binary_references`), as a child task of the web task that found it -- not a duplicate
pipeline, and not something a person has to notice and wire up by hand.
"""
from __future__ import annotations

import uuid

import pytest

from app.core.schemas import (
    AgentId,
    AgentResult,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    NetworkGraph,
    NetworkGraphAssetRecord,
    NetworkGraphServiceRecord,
    TaskStatus,
)
from app.database import repository
from app.database.session import SessionLocal, init_db
from app.orchestrator import autonomous_loop
from app.core.config import settings
from tests.test_discovered_artifact_pipeline import CORRELATION_PORT, HIDDEN_PATH, _Handler, fixture_server  # noqa: F401


@pytest.fixture
def db_assessment(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    init_db()
    return f"ASSESSMENT-AUTONOMOUS-{uuid.uuid4().hex[:10]}"


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(allow_content_discovery=True, allow_binary_analysis=True,
                            allow_passive_web_analysis=True, allow_network_service_assessment=True,
                            dry_run=False, max_content_discovery_requests=60)


def _graph(base_url: str) -> NetworkGraph:
    host = base_url.split("//", 1)[1].split(":")[0]
    port = int(base_url.rsplit(":", 1)[1])
    return NetworkGraph(
        scope_id="SCOPE-TEST",
        assets=[NetworkGraphAssetRecord(
            asset_id="HOST-TEST", ip=host,
            services=[NetworkGraphServiceRecord(service_id=f"HOST-TEST:{port}/tcp", asset_id="HOST-TEST",
                                                 port=port, service_name="http")],
        )],
    )


def _setup_assessment(assessment_id: str, graph: NetworkGraph, policy: AssessmentPolicy) -> None:
    with SessionLocal() as db:
        repository.create_assessment(
            db, Assessment(assessment_id=assessment_id, scope_id=graph.scope_id, status=AssessmentStatus.CREATED,
                           assessment_policy=policy),
        )
        repository.store_network_graph(db, assessment_id, graph)
        db.commit()


def test_web_finding_automatically_creates_a_child_binary_task(db_assessment, fixture_server, monkeypatch, tmp_path):
    assessment_id = db_assessment
    graph = _graph(fixture_server)
    policy = _policy()
    _setup_assessment(assessment_id, graph, policy)

    fake_web_result = AgentResult(
        agent_id=AgentId.WEB_SECURITY, assessment_id=assessment_id, execution_status=TaskStatus.COMPLETED,
        discovered_binary_references=[{
            "asset_id": "HOST-TEST", "url": f"{fixture_server}{HIDDEN_PATH}",
            "content_type": "application/octet-stream", "content_length": len(_Handler.body_with_correlation),
            "reason": "content-type 'application/octet-stream'",
        }],
    )
    monkeypatch.setattr(autonomous_loop, "run_web_security_agent", lambda *a, **k: fake_web_result)

    trace = autonomous_loop.run_next_iteration(assessment_id, policy=policy, output_dir=tmp_path / "out")

    assert trace.agent_id == AgentId.WEB_SECURITY
    assert trace.binary_findings_count > 0, "web-to-binary handoff produced no findings"

    with SessionLocal() as db:
        tasks = repository.list_agent_tasks(db, assessment_id)
    web_task = next(t for t in tasks if t.task_id == trace.task_id)
    binary_tasks = [t for t in tasks if t.task_type == "binary_analysis_triggered_by_web_discovery"]

    assert web_task.initiated_by == "orchestrator"
    assert binary_tasks, "no binary-analysis task was created from the web finding"
    assert binary_tasks[0].parent_task_id == web_task.task_id, (
        "the binary task must trace back to the web task that found the reference"
    )
    assert binary_tasks[0].initiated_by == "orchestrator"
    assert binary_tasks[0].status == "completed"

    with SessionLocal() as db:
        findings = repository.list_findings(db, assessment_id)
    assert any(f.detection_method == "hardcoded_credential" for f in findings)


def test_second_iteration_moves_to_a_different_unattempted_service(db_assessment, fixture_server, monkeypatch, tmp_path):
    """With two equally-unattempted services, the second iteration must not re-select the one the first
    iteration already investigated -- it moves to the other candidate instead of repeating."""
    assessment_id = db_assessment
    host = fixture_server.split("//", 1)[1].split(":")[0]
    port = int(fixture_server.rsplit(":", 1)[1])
    graph = NetworkGraph(
        scope_id="SCOPE-TEST",
        assets=[NetworkGraphAssetRecord(
            asset_id="HOST-TEST", ip=host,
            services=[
                NetworkGraphServiceRecord(service_id=f"HOST-TEST:{port}/tcp", asset_id="HOST-TEST", port=port,
                                          service_name="http"),
                NetworkGraphServiceRecord(service_id="HOST-TEST:22/tcp", asset_id="HOST-TEST", port=22,
                                          service_name="ssh"),
            ],
        )],
    )
    policy = _policy()
    _setup_assessment(assessment_id, graph, policy)

    monkeypatch.setattr(autonomous_loop, "run_web_security_agent",
                        lambda *a, **k: AgentResult(agent_id=AgentId.WEB_SECURITY, assessment_id=assessment_id,
                                                    execution_status=TaskStatus.COMPLETED))
    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent",
                        lambda *a, **k: AgentResult(agent_id=AgentId.NETWORK_VULNERABILITY_DETECTIVE,
                                                    assessment_id=assessment_id, execution_status=TaskStatus.COMPLETED))

    first = autonomous_loop.run_next_iteration(assessment_id, policy=policy, output_dir=tmp_path / "out")
    assert first.objective is not None

    second = autonomous_loop.run_next_iteration(assessment_id, policy=policy, output_dir=tmp_path / "out")
    assert second.objective is not None
    assert second.objective.service_id != first.objective.service_id, (
        "the scheduler re-selected an already-attempted service while an unattempted one remained eligible"
    )

    third = autonomous_loop.run_next_iteration(assessment_id, policy=policy, output_dir=tmp_path / "out")
    assert third.blocked_reason is None
    assert third.objective is not None, (
        "both services were investigated with no new evidence -- the lower-priority re-attempt should "
        "still be eligible (never a permanent blacklist), just last in line"
    )


def test_full_three_agent_dependency_chain(db_assessment, fixture_server, monkeypatch, tmp_path):
    """Web Agent finds a binary reference -> process_discovered_binary_references (the Binary Agent's own
    pipeline, invoked exactly as the web-to-binary handoff invokes it -- no second copy) recovers a
    credential-shaped weakness and links it, by the binary's OWN corroborating content, to a second,
    unrelated-looking network service on the same host -> the scheduler must then rank THAT service above a
    third, equally-unattempted but unevidenced service purely because real evidence now points at it."""
    assessment_id = db_assessment
    host = fixture_server.split("//", 1)[1].split(":")[0]
    web_port = int(fixture_server.rsplit(":", 1)[1])
    graph = NetworkGraph(
        scope_id="SCOPE-TEST",
        assets=[NetworkGraphAssetRecord(
            asset_id="HOST-TEST", ip=host,
            services=[
                NetworkGraphServiceRecord(service_id=f"HOST-TEST:{web_port}/tcp", asset_id="HOST-TEST",
                                          port=web_port, service_name="http"),
                NetworkGraphServiceRecord(service_id=f"HOST-TEST:{CORRELATION_PORT}/tcp", asset_id="HOST-TEST",
                                          port=CORRELATION_PORT, service_name="generic-test-service"),
                NetworkGraphServiceRecord(service_id="HOST-TEST:31337/tcp", asset_id="HOST-TEST", port=31337,
                                          service_name="generic-other-service"),
            ],
        )],
    )
    policy = _policy()
    _setup_assessment(assessment_id, graph, policy)

    # The web-to-binary handoff itself, exercised through the SAME function run_next_iteration calls --
    # proves the chain's middle link without depending on which unevidenced candidate the scheduler happens
    # to pick first (that tie-break is covered by test_second_iteration_moves_to_a_different_unattempted_service).
    from app.core.scope_guard import ScopeGuard
    from app.orchestrator.nodes import process_discovered_binary_references
    guard = ScopeGuard(policy, graph)
    binary_result = process_discovered_binary_references(
        assessment_id, policy, graph,
        [{"asset_id": "HOST-TEST", "url": f"{fixture_server}{HIDDEN_PATH}", "reason": "test"}],
        guard=guard, output_dir=tmp_path / "out" / "discovered_binaries",
        parent_task_id="TASK-web-parent", initiated_by="orchestrator",
    )
    assert binary_result.findings, "the binary pipeline produced no findings to link"
    with SessionLocal() as db:
        repository.store_findings(db, binary_result.findings, binary_result.evidence)
        db.commit()
        findings = repository.list_findings(db, assessment_id)
    linked = [f for f in findings if f.service_id == f"HOST-TEST:{CORRELATION_PORT}/tcp"]
    assert linked, "the binary finding was never linked to the service it corroborated"

    monkeypatch.setattr(autonomous_loop, "run_network_vulnerability_agent",
                        lambda *a, **k: AgentResult(agent_id=AgentId.NETWORK_VULNERABILITY_DETECTIVE,
                                                    assessment_id=assessment_id, execution_status=TaskStatus.COMPLETED))

    follow_up = autonomous_loop.run_next_iteration(assessment_id, policy=policy, output_dir=tmp_path / "out")
    assert follow_up.objective is not None
    assert follow_up.objective.service_id == f"HOST-TEST:{CORRELATION_PORT}/tcp", (
        "the scheduler should have prioritised the evidence-linked service over the unevidenced third one"
    )
    assert follow_up.objective.source == "finding_followup"
    assert follow_up.objective.agent_id == AgentId.NETWORK_VULNERABILITY_DETECTIVE
