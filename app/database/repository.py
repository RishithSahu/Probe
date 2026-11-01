"""Repository layer: translates between `app.core.schemas` Pydantic models
(the validation/wire contract) and `app.database.models` SQLAlchemy ORM rows
(the persistence contract). All functions take an open `Session` so callers
(the Orchestrator nodes, the FastAPI routes) control transaction boundaries
via `app.database.session.session_scope`.
"""
from __future__ import annotations

import secrets

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from app.core.exceptions import AppError, AssessmentNotFoundError
from app.core.schemas import (
    AgentTask,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    BinaryAsset,
    Evidence,
    Finding,
    NetworkGraph,
    TaskStatus,
)
from app.core.scope_guard import ToolInvocationRecord
from app.database.inventory import persist_network_graph
from app.database.models import (
    AgentTaskRecord,
    AssessmentRecord,
    AttackPathRecord,
    BinaryAssetRecord,
    EvidenceRecord,
    ExecutionLogRecord,
    FindingRecord,
    NetworkGraphRecord,
    ScopePolicyRecord,
)

# --- Assessments -------------------------------------------------------------


def create_assessment(db: Session, assessment: Assessment) -> AssessmentRecord:
    record = AssessmentRecord(
        assessment_id=assessment.assessment_id,
        scope_id=assessment.scope_id,
        status=assessment.status.value,
        assessment_policy=assessment.assessment_policy.model_dump(mode="json"),
        network_graph_ref=assessment.network_graph_ref,
        binaries_ref=assessment.binaries_ref,
        created_at=assessment.created_at,
    )
    db.add(record)
    db.add(ScopePolicyRecord(assessment_id=assessment.assessment_id, policy=assessment.assessment_policy.model_dump(mode="json")))
    db.flush()
    return record


def get_assessment(db: Session, assessment_id: str) -> AssessmentRecord:
    record = db.get(AssessmentRecord, assessment_id)
    if record is None:
        raise AssessmentNotFoundError(f"assessment {assessment_id!r} not found")
    return record


def update_assessment_status(db: Session, assessment_id: str, status: AssessmentStatus, *, completed_at=None) -> None:
    record = get_assessment(db, assessment_id)
    record.status = status.value
    if completed_at is not None:
        record.completed_at = completed_at
    db.flush()


def get_assessment_policy(db: Session, assessment_id: str) -> AssessmentPolicy:
    record = get_assessment(db, assessment_id)
    return AssessmentPolicy.model_validate(record.assessment_policy)


# --- Network graph -----------------------------------------------------------


def store_network_graph(db: Session, assessment_id: str, graph: NetworkGraph) -> None:
    persist_network_graph(db, assessment_id, graph)


def load_network_graph(db: Session, assessment_id: str) -> NetworkGraph | None:
    record = db.get(NetworkGraphRecord, assessment_id)
    if record is None:
        return None
    return NetworkGraph.model_validate(record.normalised_graph)


# --- Binaries -----------------------------------------------------------------


def store_binary_asset(db: Session, binary: BinaryAsset) -> None:
    db.add(
        BinaryAssetRecord(
            binary_id=binary.binary_id,
            assessment_id=binary.assessment_id,
            file_name=binary.file_name,
            file_path=binary.file_path,
            file_hash=binary.file_hash,
            format=binary.format,
            architecture=binary.architecture,
        )
    )
    db.flush()


# --- Agent tasks ----------------------------------------------------------------


def upsert_agent_task(db: Session, task: AgentTask) -> None:
    record = db.get(AgentTaskRecord, task.task_id)
    if record is None:
        record = AgentTaskRecord(task_id=task.task_id, assessment_id=task.assessment_id)
        db.add(record)
    record.agent_id = task.agent_id.value
    record.task_type = task.task_type
    record.input_data = task.input_data
    record.status = task.status.value
    record.output_data = task.output_data
    record.error_message = task.error_message
    record.started_at = task.started_at
    record.completed_at = task.completed_at
    record.parent_task_id = task.parent_task_id
    record.initiated_by = task.initiated_by
    record.execution_method = task.execution_method
    record.evidence_ids = task.evidence_ids
    record.verification_status = task.verification_status
    record.task_fingerprint = task.task_fingerprint
    db.flush()


def try_reserve_task(db: Session, task: AgentTask, *, allow_reclaim: bool = True) -> str | None:
    """Atomically claim `task.task_id` for THIS caller, so a concurrent scheduler dispatching several
    candidates at once can never run the same one twice. `task.task_id` is a deterministic fingerprint of
    the unit of work (assessment + agent/surface + target/service -- see
    app.orchestrator.scheduler.Candidate.candidate_id and autonomous_loop's task_id construction), but it is
    NOT attempt-scoped: the scheduler's own novelty/retry logic can legitimately select the SAME task_id
    again later once new evidence justifies a fresh attempt (item 6 of the concurrency spec: "new evidence
    may create a legitimate new follow-up task"). So "already exists" alone must not permanently block it --
    only "already RUNNING" may.

    `allow_reclaim` guards exactly that distinction, and callers must get it right: pass True only when
    the candidate's OWN freshly-read evidence (not a stale snapshot) positively justifies a new attempt
    (app.orchestrator.scheduler's `next_attempt_count > 1`, i.e. the generator itself already saw a prior,
    finished attempt and decided a retry is warranted). A caller reserving what IT believes is a brand-new,
    never-attempted candidate must pass False. Without this, a real race is possible: candidate generation
    takes a snapshot of task history at call-start; if a FAST concurrent call fully reserves, runs, and
    completes that same candidate before this call reaches its own reservation attempt, this call's stale
    snapshot still shows it as "unvisited" (next_attempt_count == 1) -- with allow_reclaim always true,
    that stale belief would let this call legitimately "reclaim" and re-execute a task that was correctly
    finished moments ago, under no new evidence at all. allow_reclaim=False for that case makes the
    INSERT's failure final: the row already existing, in ANY status, is enough to refuse.

    Two atomic paths, neither of them a SELECT-then-write:
      1. A brand-new task_id: a plain INSERT, which only one of several racing callers can ever have
         succeed (the primary key is what the database itself serialises on, across sessions/connections --
         see probe/store.py's claim_task for the same pattern against SQLite's own write lock).
      2. A task_id that already exists (from a prior, now-finished attempt, or from another caller
         currently racing this same reservation) AND `allow_reclaim` is True: an
         UPDATE ... WHERE status != 'running', whose rowcount is checked exactly like Probe's
         Hub.lease() does -- it reclaims a terminal task for a new attempt, but a task some other caller
         already has RUNNING matches no row and rowcount is 0.

    Every successful claim mints a fresh `reservation_token` (returned to the caller, who must present it
    back to `try_complete_task` -- see that function's docstring for why: `run_concurrently()`'s timeout
    cannot actually kill a running thread, so an abandoned one finishing late must not be able to overwrite
    whatever a retry, holding a NEWER token, already wrote for the same task_id).

    Returns the new reservation_token iff THIS call now owns the task (the caller must execute it and later
    present this token back); None means it already exists and either is currently RUNNING, or
    `allow_reclaim` was False (the caller must skip it, not retry)."""
    token = secrets.token_hex(12)
    record = AgentTaskRecord(
        task_id=task.task_id, assessment_id=task.assessment_id, agent_id=task.agent_id.value,
        task_type=task.task_type, input_data=task.input_data, status=task.status.value,
        output_data=task.output_data, parent_task_id=task.parent_task_id, initiated_by=task.initiated_by,
        execution_method=task.execution_method, started_at=task.started_at,
        verification_status=task.verification_status, task_fingerprint=task.task_fingerprint,
        reservation_token=token,
    )
    db.add(record)
    try:
        db.flush()
        return token
    except IntegrityError:
        db.rollback()
        if not allow_reclaim:
            return None
        result = db.execute(
            update(AgentTaskRecord)
            .where(AgentTaskRecord.task_id == task.task_id, AgentTaskRecord.status != TaskStatus.RUNNING.value)
            .values(
                assessment_id=task.assessment_id, agent_id=task.agent_id.value, task_type=task.task_type,
                input_data=task.input_data, status=task.status.value, output_data=None, error_message=None,
                started_at=task.started_at, completed_at=None, parent_task_id=task.parent_task_id,
                initiated_by=task.initiated_by, execution_method=task.execution_method,
                evidence_ids=None, verification_status=None, task_fingerprint=task.task_fingerprint,
                reservation_token=token,
            )
        )
        db.flush()
        return token if result.rowcount == 1 else None


def try_complete_task(db: Session, task_id: str, reservation_token: str, **fields) -> bool:
    """Persist a reserved task's final state -- but ONLY if `reservation_token` still matches what is
    currently on the row. This is the write-side half of the fencing `try_reserve_task` sets up (the same
    pattern as Probe's Hub.submit()/fail() checking lease_token against _held_task): if a thread
    run_concurrently() already gave up on and reported FAILED (because Python cannot force-kill a running
    thread, only stop waiting on it) finishes LATER, and by then a retry has reserved the same task_id
    under a NEW token, this call's UPDATE matches zero rows and returns False -- the stale result is
    rejected instead of silently clobbering whatever the retry already wrote. `fields` are plain column
    name/value pairs (already-serialised: enum .value, not the enum itself).
    Returns True iff this write was accepted."""
    result = db.execute(
        update(AgentTaskRecord)
        .where(AgentTaskRecord.task_id == task_id, AgentTaskRecord.reservation_token == reservation_token)
        .values(**fields)
    )
    db.flush()
    return result.rowcount == 1


def list_agent_tasks(db: Session, assessment_id: str) -> list[AgentTaskRecord]:
    return list(db.scalars(select(AgentTaskRecord).where(AgentTaskRecord.assessment_id == assessment_id)))


# --- Findings / evidence ---------------------------------------------------------


def store_findings(db: Session, findings: list[Finding], evidence: list[Evidence]) -> None:
    for f in findings:
        record = db.get(FindingRecord, f.finding_id)
        if record is None:
            record = FindingRecord(finding_id=f.finding_id)
            db.add(record)
        record.assessment_id = f.assessment_id
        record.agent_id = f.agent_id.value
        record.surface = f.surface.value
        record.asset_id = f.asset_id
        record.binary_id = f.binary_id
        record.service_id = f.service_id
        record.title = f.title
        record.description = f.description
        record.severity = f.severity.value
        record.confidence = f.confidence.value
        record.status = f.status.value
        record.evidence_refs = f.evidence_refs
        record.remediation = f.remediation
        record.ptes_phase = f.ptes_phase.value
        record.detection_method = f.detection_method
        record.affected_url = f.affected_url
        record.endpoint = f.endpoint
        record.parameter = f.parameter
        record.function_name = f.function_name
        record.function_address = f.function_address
        record.verification_required = f.verification_required
        record.created_at = f.created_at
        record.verification_state = f.verification_state
        record.verified_at = f.verified_at
        record.verifier = f.verifier
        record.verification_evidence_refs = f.verification_evidence_refs or None
        record.verification_explanation = f.verification_explanation
        record.evidence_integrity_hash = f.evidence_integrity_hash
    db.flush()

    for e in evidence:
        record = db.get(EvidenceRecord, e.evidence_id)
        if record is None:
            record = EvidenceRecord(evidence_id=e.evidence_id)
            db.add(record)
        record.finding_id = e.finding_id
        record.evidence_type = e.evidence_type
        record.source_tool = e.source_tool
        record.storage_path = e.storage_path
        record.description = e.description
        record.raw_data = e.raw_data
        record.timestamp = e.timestamp
    db.flush()


def update_finding_status(db: Session, finding_id: str, status: str, *, verification_required: bool) -> None:
    record = db.get(FindingRecord, finding_id)
    if record is not None:
        record.status = status
        record.verification_required = verification_required
        db.flush()


def list_findings(db: Session, assessment_id: str) -> list[FindingRecord]:
    return list(db.scalars(select(FindingRecord).where(FindingRecord.assessment_id == assessment_id)))


def finding_to_schema(record: FindingRecord) -> Finding:
    return Finding.model_validate(
        {
            "finding_id": record.finding_id,
            "assessment_id": record.assessment_id,
            "agent_id": record.agent_id,
            "surface": record.surface,
            "asset_id": record.asset_id,
            "binary_id": record.binary_id,
            "service_id": record.service_id,
            "title": record.title,
            "description": record.description,
            "severity": record.severity,
            "confidence": record.confidence,
            "status": record.status,
            "evidence_refs": record.evidence_refs,
            "remediation": record.remediation,
            "ptes_phase": record.ptes_phase,
            "detection_method": record.detection_method,
            "affected_url": record.affected_url,
            "endpoint": record.endpoint,
            "parameter": record.parameter,
            "function_name": record.function_name,
            "function_address": record.function_address,
            "verification_required": record.verification_required,
            "created_at": record.created_at,
            "verification_state": record.verification_state,
            "verified_at": record.verified_at,
            "verifier": record.verifier,
            "verification_evidence_refs": record.verification_evidence_refs or [],
            "verification_explanation": record.verification_explanation,
            "evidence_integrity_hash": record.evidence_integrity_hash,
        }
    )


def update_finding_verification(
    db: Session, finding_id: str, *, verification_state: str, verifier: str,
    verification_evidence_refs: list[str] | None = None, verification_explanation: str | None = None,
    evidence_integrity_hash: str | None = None, verified_at=None,
) -> None:
    """Sets the per-finding verification outcome (item 7) -- deliberately separate from
    `update_finding_status`, which changes `status` (suspected/confirmed/rejected). A finding can be
    `verification_state='inconclusive'` while `status` stays `suspected`, or vice versa; these are two
    different questions ("is this evidence sound?" vs "do we believe the weakness is real?") and neither
    implies the other."""
    record = db.get(FindingRecord, finding_id)
    if record is None:
        raise AppError(f"finding {finding_id!r} not found")
    record.verification_state = verification_state
    record.verifier = verifier
    record.verification_evidence_refs = verification_evidence_refs or None
    record.verification_explanation = verification_explanation
    record.evidence_integrity_hash = evidence_integrity_hash
    record.verified_at = verified_at or datetime.now(timezone.utc)
    db.flush()


# --- Attack paths ---------------------------------------------------------------


def store_attack_path_edges(db: Session, assessment_id: str, edges: list[dict]) -> None:
    db.query(AttackPathRecord).filter(AttackPathRecord.assessment_id == assessment_id).delete()
    for edge in edges:
        db.add(
            AttackPathRecord(
                assessment_id=assessment_id,
                source_node=edge["source"],
                target_node=edge["target"],
                relation=edge["relation"],
                evidence_backed=edge.get("evidence_backed", False),
                finding_id=edge.get("finding_id"),
            )
        )
    db.flush()


# --- Execution logs ---------------------------------------------------------------


def store_tool_invocation_log(db: Session, assessment_id: str, agent_id: str, record: ToolInvocationRecord) -> None:
    db.add(
        ExecutionLogRecord(
            assessment_id=assessment_id,
            agent_id=agent_id,
            tool=record.tool,
            operation=record.operation,
            target=record.target,
            allowed=record.allowed,
            message=record.reason,
            level="info" if record.allowed else "warning",
        )
    )
    db.flush()


def log_event(db: Session, assessment_id: str, agent_id: str, message: str, *, level: str = "info") -> None:
    db.add(ExecutionLogRecord(assessment_id=assessment_id, agent_id=agent_id, message=message, level=level))
    db.flush()
