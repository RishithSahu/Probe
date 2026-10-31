"""Repository layer: translates between `app.core.schemas` Pydantic models
(the validation/wire contract) and `app.database.models` SQLAlchemy ORM rows
(the persistence contract). All functions take an open `Session` so callers
(the Orchestrator nodes, the FastAPI routes) control transaction boundaries
via `app.database.session.session_scope`.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AssessmentNotFoundError
from app.core.schemas import (
    AgentTask,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    BinaryAsset,
    Evidence,
    Finding,
    NetworkGraph,
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
    db.flush()


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
        }
    )


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
