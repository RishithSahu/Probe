"""The orchestrator-controlled dispatch loop: generate every eligible investigation candidate from the
assessment's own evidence, score them deterministically (app.orchestrator.scheduler), dispatch the
highest-ranked one, verify what comes back, and persist the full trace -- so the next objective is chosen
and executed by the orchestrator, never by a person acting first and recording the result afterward.

Generic by construction: nothing here names a challenge, host, port, or flag. The only inputs are the
assessment's own `NetworkGraph`, its `AgentTask` history, and its `Finding` records.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.agents.network_vulnerability.agent import run_network_vulnerability_agent
from app.agents.web_security.agent import WebTarget, run_web_security_agent
from app.analysis.evidence_validator import run_evidence_validation
from app.core.schemas import AgentId, AgentTask, AssessmentPolicy, NetworkGraph, TaskStatus
from app.core.scope_guard import ScopeGuard
from app.database import repository
from app.database.session import session_scope
from app.orchestrator.scheduler import Candidate, generate_candidates, rank_candidates, select_next

logger = logging.getLogger("ape.orchestrator.autonomous_loop")

EXECUTION_METHOD = "app.orchestrator.autonomous_loop.run_next_iteration"
CONCURRENT_EXECUTION_METHOD = "app.orchestrator.autonomous_loop.run_concurrent_iteration"


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


def _task_id_for(assessment_id: str, objective: Candidate) -> str:
    """The candidate's deterministic fingerprint (item 3): assessment + agent/surface + target/service,
    exactly the fields that make two dispatches "the same unit of work" for this scheduler today. It is
    deliberately NOT attempt-scoped -- see try_reserve_task's own docstring for why that is correct, not
    an oversight: a fresh attempt justified by new evidence reclaims this same id rather than minting a new
    one, so the task's history stays one row per candidate instead of growing one per retry forever."""
    return f"TASK-autonomous-{objective.agent_id.value}-{assessment_id}-{objective.service_id}"


def _reserve(assessment_id: str, objective: Candidate, task_id: str, parent_task_id: str | None, explanation: dict) -> str | None:
    """Atomically claim `task_id` for this caller (see repository.try_reserve_task) and, iff that succeeds,
    log the dispatch -- so an unsuccessful reservation never produces a log line claiming a dispatch that
    didn't actually happen. Returns the fresh reservation_token on success (the caller must present it back
    to every later write for this task_id -- see _execute_objective), or None if the candidate is already
    running under someone else's reservation."""
    task = AgentTask(
        task_id=task_id, assessment_id=assessment_id, agent_id=objective.agent_id,
        task_type="autonomous_next_objective", parent_task_id=parent_task_id, initiated_by="orchestrator",
        execution_method=f"{EXECUTION_METHOD} -> (scheduler selection)",
        input_data={"asset_id": objective.asset_id, "service_id": objective.service_id,
                   "finding_count_at_dispatch": objective.backing_findings_count,
                   "attempt_count": objective.next_attempt_count},
        output_data={"selection": explanation},
        status=TaskStatus.RUNNING, started_at=_now(),
    )
    with session_scope() as db:
        token = repository.try_reserve_task(db, task)
        if token:
            repository.log_event(
                db, assessment_id, AgentId.ORCHESTRATOR.value,
                f"scheduler selected {objective.candidate_id} (score={explanation.get('selected', {}).get('total_score', 0.0):.2f}, "
                f"source={objective.source}) -> dispatching {objective.agent_id.value} as {task_id} "
                f"(parent={parent_task_id})",
            )
    return token


def _execute_objective(
    assessment_id: str, objective: Candidate, task_id: str, reservation_token: str, parent_task_id: str | None, *,
    policy: AssessmentPolicy, guard: ScopeGuard, graph: NetworkGraph, output_dir: Path, explanation: dict,
    method_prefix: str = EXECUTION_METHOD,
) -> IterationTrace:
    """Run the already-reserved `objective` to completion and persist the result. Safe to call from a
    worker thread: everything it touches is either a value passed in (its own `guard`, built fresh per
    objective -- see run_concurrent_iteration) or a brand-new `with session_scope() as db:` block (a new
    SQLAlchemy Session per call, never shared across threads).

    Every write to the task row below goes through `repository.try_complete_task(..., reservation_token)`,
    never the plain `upsert_agent_task` -- item 7 of the concurrency spec: `run_concurrently()`'s shared
    timeout cannot force-kill a thread that is still running an agent call. If this exact call is the
    straggler that timeout already gave up on and reported FAILED to the caller, and by the time it
    finally finishes a retry has reserved the same task_id under a NEW token, `try_complete_task` is a
    no-op here -- the stale write is dropped instead of silently clobbering the retry's real result."""
    method = method_prefix
    try:
        if objective.agent_id == AgentId.WEB_SECURITY:
            result = run_web_security_agent(
                [WebTarget(objective.asset_id, f"http://{objective.asset_id}:" + objective.service_id.split(":")[1].split("/")[0])],
                assessment_id=assessment_id, scope_guard=guard, policy=policy, output_dir=output_dir,
            )
            method = f"{method_prefix} -> run_web_security_agent"
        else:
            service_record = next(s for a in graph.assets for s in a.services if s.service_id == objective.service_id)
            asset_record = next(a for a in graph.assets if a.asset_id == objective.asset_id)
            result = run_network_vulnerability_agent(
                [(asset_record, service_record)], assessment_id=assessment_id, scope_guard=guard,
            )
            method = f"{method_prefix} -> run_network_vulnerability_agent"
    except Exception as exc:  # noqa: BLE001 - a dispatched agent failing is a FAILED task, not a crash of the loop
        with session_scope() as db:
            accepted = repository.try_complete_task(
                db, task_id, reservation_token,
                status=TaskStatus.FAILED.value, error_message=str(exc)[:2000], completed_at=_now(),
                execution_method=method, output_data={"selection": explanation},
            )
        if not accepted:
            logger.warning("task %s: stale reservation_token on failure write -- a retry already reclaimed it", task_id)
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
            execution_method=f"{method_prefix} -> process_discovered_binary_references",
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
        accepted = repository.try_complete_task(
            db, task_id, reservation_token,
            execution_method=method,
            output_data={"findings_count": len(verified_findings), "selection": explanation},
            evidence_ids=[e.evidence_id for e in result.evidence],
            verification_status=verification_status,
            status=task_status.value,
            error_message="; ".join(result.errors) or None, completed_at=_now(),
        )
        if accepted:
            repository.log_event(
                db, assessment_id, AgentId.ORCHESTRATOR.value,
                f"{task_id} {task_status.value}: {len(verified_findings)} finding(s) "
                f"({binary_findings_count} via web-to-binary handoff), verification={verification_status}",
            )
    if not accepted:
        logger.warning("task %s: stale reservation_token on completion write -- a retry already reclaimed it "
                       "(the findings above were still stored; only this task row's bookkeeping was skipped)",
                       task_id)

    return IterationTrace(task_id=task_id, parent_task_id=parent_task_id, agent_id=objective.agent_id,
                          objective=objective, findings_count=len(verified_findings),
                          verified_count=sum(1 for f in verified_findings if f.status.value == "confirmed"),
                          binary_findings_count=binary_findings_count, selection_explanation=explanation)


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

    task_id = _task_id_for(assessment_id, objective)
    reservation_token = _reserve(assessment_id, objective, task_id, parent_task_id, explanation)
    if not reservation_token:
        # Lost the reservation race (another dispatcher -- another thread of a concurrent run, or a
        # separate process against a shared database -- already has this exact candidate RUNNING right
        # now). This is not an error: the same deduplication that stops a concurrent scheduler from running
        # one candidate twice also applies here, in the single-candidate path, for free.
        return IterationTrace(task_id=task_id, parent_task_id=parent_task_id, agent_id=objective.agent_id,
                              objective=objective,
                              blocked_reason=f"candidate {objective.candidate_id} is already running under another reservation",
                              selection_explanation=explanation)

    return _execute_objective(assessment_id, objective, task_id, reservation_token, parent_task_id, policy=policy,
                              guard=guard, graph=graph, output_dir=output_dir, explanation=explanation)


def run_concurrent_iteration(
    assessment_id: str, *, policy: AssessmentPolicy, output_dir: Path, parent_task_id: str | None = None,
    max_inflight: int = 4,
) -> list[IterationTrace]:
    """Generate every eligible candidate, atomically reserve up to `max_inflight` of the highest-ranked
    ones (so two reservation attempts for the same candidate can never both win -- see
    repository.try_reserve_task), and run every successfully reserved one concurrently in its own thread.
    This is what replaces "select one candidate, run it, repeat" with real parallel dispatch (item 4): if
    three independent services are eligible right now, up to `max_inflight` of them are sent to their
    agents at once, not one iteration apart. Each reserved objective gets its OWN fresh `ScopeGuard`
    (cheap to construct, no I/O) rather than sharing one across threads, so concurrent tool-invocation
    logging from different objectives is never interleaved onto the same guard's audit_log."""
    with session_scope() as db:
        graph = repository.load_network_graph(db, assessment_id)
        existing_task_inputs = [dict(t.input_data or {}) for t in repository.list_agent_tasks(db, assessment_id)]
        findings = [repository.finding_to_schema(f) for f in repository.list_findings(db, assessment_id)]

    if graph is None:
        return [IterationTrace(task_id="", parent_task_id=parent_task_id, agent_id=None, objective=None,
                               blocked_reason="no network graph loaded for this assessment")]

    guard_for_candidates = ScopeGuard(policy, graph)
    candidates = generate_candidates(graph, existing_task_inputs, findings, guard=guard_for_candidates)
    ranked = rank_candidates(candidates)
    if not ranked:
        return [IterationTrace(task_id="", parent_task_id=parent_task_id, agent_id=None, objective=None,
                               blocked_reason="no justified next action: nothing in the current evidence/graph "
                                              "qualifies for investigation under the active policy and scope",
                               selection_explanation={"considered": []})]

    explanation_for = {c.candidate_id: {"selected": c.explanation(), "considered": [c.explanation() for c in ranked]}
                       for c in ranked}
    reserved: list[tuple[Candidate, str, str]] = []
    for c in ranked:
        if len(reserved) >= max(1, max_inflight):
            break
        task_id = _task_id_for(assessment_id, c)
        token = _reserve(assessment_id, c, task_id, parent_task_id, explanation_for[c.candidate_id])
        if token:
            reserved.append((c, task_id, token))

    if not reserved:
        return [IterationTrace(
            task_id="", parent_task_id=parent_task_id, agent_id=None, objective=None,
            blocked_reason="no justified next action: every eligible candidate is already running under "
                           "another reservation",
            selection_explanation={"considered": [c.explanation() for c in ranked]},
        )]

    def _run(objective: Candidate, task_id: str, token: str) -> IterationTrace:
        return _execute_objective(
            assessment_id, objective, task_id, token, parent_task_id, policy=policy, guard=ScopeGuard(policy, graph),
            graph=graph, output_dir=output_dir, explanation=explanation_for[objective.candidate_id],
            method_prefix=CONCURRENT_EXECUTION_METHOD,
        )

    traces: list[IterationTrace] = []
    with ThreadPoolExecutor(max_workers=len(reserved)) as pool:
        futures = [pool.submit(_run, objective, task_id, token) for objective, task_id, token in reserved]
        for future in as_completed(futures):
            traces.append(future.result())
    return traces
