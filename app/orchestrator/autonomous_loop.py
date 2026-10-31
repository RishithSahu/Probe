"""The orchestrator-controlled dispatch loop: generate every eligible investigation candidate from the
assessment's own evidence, score them deterministically (app.orchestrator.scheduler), dispatch the
highest-ranked one, verify what comes back, and persist the full trace -- so the next objective is chosen
and executed by the orchestrator, never by a person acting first and recording the result afterward.

Generic by construction: nothing here names a challenge, host, port, or flag. The only inputs are the
assessment's own `NetworkGraph`, its `AgentTask` history, and its `Finding` records.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.agents.network_vulnerability.agent import run_network_vulnerability_agent
from app.agents.web_security.agent import WebTarget, run_web_security_agent
from app.analysis.evidence_validator import run_evidence_validation
from app.core.schemas import AgentId, AgentTask, AssessmentPolicy, TaskStatus
from app.core.scope_guard import ScopeGuard
from app.database import repository
from app.database.session import session_scope
from app.orchestrator.scheduler import Candidate, generate_candidates, select_next

logger = logging.getLogger("ape.orchestrator.autonomous_loop")

EXECUTION_METHOD = "app.orchestrator.autonomous_loop.run_next_iteration"


@dataclass
class IterationTrace:
    task_id: str
    parent_task_id: str | None
    agent_id: AgentId | None
    objective: Candidate | None
    findings_count: int = 0
    verified_count: int = 0
    binary_findings_count: int = 0
    blocked_reason: str | None = None
    selection_explanation: dict = field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def run_next_iteration(
    assessment_id: str, *, policy: AssessmentPolicy, output_dir: Path, parent_task_id: str | None = None,
) -> IterationTrace:
    """One full Orchestrator -> candidate generation -> scoring -> selection -> task creation -> agent
    execution -> evidence returned -> verification cycle, run and persisted end to end by this function --
    not reconstructed afterward from a manual action."""
    with session_scope() as db:
        graph = repository.load_network_graph(db, assessment_id)
        existing_task_inputs = [dict(t.input_data or {}) for t in repository.list_agent_tasks(db, assessment_id)]
        findings = [repository.finding_to_schema(f) for f in repository.list_findings(db, assessment_id)]

    if graph is None:
        return IterationTrace(task_id="", parent_task_id=parent_task_id, agent_id=None, objective=None,
                              blocked_reason="no network graph loaded for this assessment")

    guard = ScopeGuard(policy, graph)
    candidates = generate_candidates(graph, existing_task_inputs, findings, guard=guard)
    objective, explanation = select_next(candidates)
    if objective is None:
        return IterationTrace(task_id="", parent_task_id=parent_task_id, agent_id=None, objective=None,
                              blocked_reason="no justified next action: " + explanation.get("reason", "queue empty"),
                              selection_explanation=explanation)

    task_id = f"TASK-autonomous-{objective.agent_id.value}-{assessment_id}-{objective.service_id}"

    with session_scope() as db:
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=objective.agent_id,
            task_type="autonomous_next_objective", parent_task_id=parent_task_id, initiated_by="orchestrator",
            execution_method=f"{EXECUTION_METHOD} -> (scheduler selection)",
            input_data={"asset_id": objective.asset_id, "service_id": objective.service_id, "finding_count_at_dispatch": objective.backing_findings_count, "attempt_count": objective.next_attempt_count},
            output_data={"selection": explanation},
            status=TaskStatus.RUNNING, started_at=_now(),
        ))
        repository.log_event(
            db, assessment_id, AgentId.ORCHESTRATOR.value,
            f"scheduler selected {objective.candidate_id} (score={explanation['selected']['total_score']:.2f}, "
            f"source={objective.source}) -> dispatching {objective.agent_id.value} as {task_id} "
            f"(parent={parent_task_id})",
        )

    method = EXECUTION_METHOD
    try:
        if objective.agent_id == AgentId.WEB_SECURITY:
            result = run_web_security_agent(
                [WebTarget(objective.asset_id, f"http://{objective.asset_id}:" + objective.service_id.split(":")[1].split("/")[0])],
                assessment_id=assessment_id, scope_guard=guard, policy=policy, output_dir=output_dir,
            )
            method = f"{EXECUTION_METHOD} -> run_web_security_agent"
        else:
            service_record = next(s for a in graph.assets for s in a.services if s.service_id == objective.service_id)
            asset_record = next(a for a in graph.assets if a.asset_id == objective.asset_id)
            result = run_network_vulnerability_agent(
                [(asset_record, service_record)], assessment_id=assessment_id, scope_guard=guard,
            )
            method = f"{EXECUTION_METHOD} -> run_network_vulnerability_agent"
    except Exception as exc:  # noqa: BLE001 - a dispatched agent failing is a FAILED task, not a crash of the loop
        with session_scope() as db:
            repository.upsert_agent_task(db, AgentTask(
                task_id=task_id, assessment_id=assessment_id, agent_id=objective.agent_id,
                task_type="autonomous_next_objective", parent_task_id=parent_task_id, initiated_by="orchestrator",
                execution_method=method, output_data={"selection": explanation},
                input_data={"asset_id": objective.asset_id, "service_id": objective.service_id, "finding_count_at_dispatch": objective.backing_findings_count, "attempt_count": objective.next_attempt_count},
                status=TaskStatus.FAILED, error_message=str(exc), completed_at=_now(),
            ))
        return IterationTrace(task_id=task_id, parent_task_id=parent_task_id, agent_id=objective.agent_id,
                              objective=objective, blocked_reason=f"agent execution failed: {exc}",
                              selection_explanation=explanation)

    # Web-to-binary handoff: a binary reference the Web Agent reported is handed to the SAME binary pipeline
    # `handle_discovered_binaries` uses (process_discovered_binary_references) -- never a second copy of it --
    # as a child of this web task, so a recovered-credential task further down still traces back to the page
    # that led to it.
    binary_result = None
    if objective.agent_id == AgentId.WEB_SECURITY and result.discovered_binary_references:
        from app.orchestrator.nodes import process_discovered_binary_references
        binary_output_dir = output_dir / "discovered_binaries"
        binary_result = process_discovered_binary_references(
            assessment_id, policy, graph, list(result.discovered_binary_references), guard=guard,
            output_dir=binary_output_dir, parent_task_id=task_id, initiated_by="orchestrator",
            execution_method=f"{EXECUTION_METHOD} -> process_discovered_binary_references",
        )

    # Execution outcome and finding outcome are tracked separately (item 4): a stage error must never
    # discard evidence another stage genuinely produced.
    verified_findings, report = run_evidence_validation(result.findings, result.evidence)
    verification_status = "verified" if report.auto_confirmed else ("unverified" if verified_findings else "no_findings")
    binary_findings_count = 0
    if binary_result is not None:
        verified_binary_findings, binary_report = run_evidence_validation(binary_result.findings, binary_result.evidence)
        binary_findings_count = len(verified_binary_findings)
        verified_findings = verified_findings + verified_binary_findings
        result.evidence.extend(binary_result.evidence)

    if result.errors and verified_findings:
        task_status = TaskStatus.PARTIAL
    elif result.errors:
        task_status = TaskStatus.FAILED
    else:
        task_status = TaskStatus.COMPLETED

    with session_scope() as db:
        if verified_findings:
            repository.store_findings(db, verified_findings, result.evidence)
        for record in guard.audit_log:
            repository.store_tool_invocation_log(db, assessment_id, "scope_guard", record)
        repository.upsert_agent_task(db, AgentTask(
            task_id=task_id, assessment_id=assessment_id, agent_id=objective.agent_id,
            task_type="autonomous_next_objective", parent_task_id=parent_task_id, initiated_by="orchestrator",
            execution_method=method,
            input_data={"asset_id": objective.asset_id, "service_id": objective.service_id, "finding_count_at_dispatch": objective.backing_findings_count, "attempt_count": objective.next_attempt_count},
            output_data={"findings_count": len(verified_findings), "selection": explanation},
            evidence_ids=[e.evidence_id for e in result.evidence],
            verification_status=verification_status,
            status=task_status,
            error_message="; ".join(result.errors) or None, completed_at=_now(),
        ))
        repository.log_event(
            db, assessment_id, AgentId.ORCHESTRATOR.value,
            f"{task_id} {task_status.value}: {len(verified_findings)} finding(s) "
            f"({binary_findings_count} via web-to-binary handoff), verification={verification_status}",
        )

    return IterationTrace(task_id=task_id, parent_task_id=parent_task_id, agent_id=objective.agent_id,
                          objective=objective, findings_count=len(verified_findings),
                          verified_count=sum(1 for f in verified_findings if f.status.value == "confirmed"),
                          binary_findings_count=binary_findings_count, selection_explanation=explanation)
