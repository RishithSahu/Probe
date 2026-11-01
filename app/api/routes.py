"""FastAPI routes (PRD Part 14).

No route here ever executes an arbitrary command or directly shells out —
every assessment-affecting action goes through the Orchestrator/Scope Guard.
Assessment creation only records policy + references to already-completed
inputs (a network graph export, organiser-supplied binaries); it never
triggers a new discovery scan.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.external_network_agent import ExternalFindingValidationError, to_findings, validate_external_findings
from app.agents.binary_analysis.metadata import identify_binary
from app.api.dependencies import get_db
from app.core.execution_profile import ExecutionProfileError, preflight_check
from app.api.schemas import (
    AgentTaskStatusResponse,
    AssessmentResponse,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    ExternalFindingsRequest,
    ExternalFindingsResponse,
    FindingsResponse,
    ReportResponse,
)
from app.core.config import settings
from app.core.exceptions import AssessmentNotFoundError, ToolExecutionError
from app.core.schemas import Assessment, AssessmentStatus, BinaryAsset, NetworkGraph
from app.database import repository
from app.database.models import AssessmentRecord, BinaryAssetRecord
from app.orchestrator.graph import run_assessment
from app.orchestrator.state import OrchestratorState
from app.reporting.safety import public_output, report_directory, report_path

logger = logging.getLogger("ape.api")
router = APIRouter()


@router.get("/assessments/{assessment_id}/vulnerability-lifecycle")
def get_vulnerability_lifecycle(assessment_id: str, db: Session = Depends(get_db)) -> dict:
    from app.database.vulnerability_lifecycle import assessment_lifecycles

    repository.get_assessment(db, assessment_id)
    return public_output({"assessment_id": assessment_id,
                          "findings": assessment_lifecycles(db, assessment_id)})


def _input_file(value: str, root: Path, label: str) -> Path:
    """API inputs are files in configured input roots, never arbitrary server files."""
    try:
        candidate = Path(value).absolute()
        base = Path(root).resolve()
        if not candidate.is_relative_to(base):
            raise ValueError("Outside input root")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(base) or not resolved.is_file():
            raise ValueError("Not an input file")
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(400, f"{label} must be an existing file inside its configured input folder") from exc
    return resolved


def _run_orchestrator_background(initial_state: OrchestratorState) -> None:
    """BUG FIX: this used to only log an uncaught exception from
    `run_assessment` and return. Every individual orchestrator node already
    catches its own tool/validation errors and reports them through state,
    but an exception escaping the graph itself (e.g. a bug in a node, a DB
    outage mid-run) left the assessment's DB row exactly where
    `validate_assessment` had set it — `running` — forever. Nothing ever
    moved it to `failed`, so `GET /assessments/{id}` kept reporting "running"
    indefinitely with no indication anything had gone wrong: actively
    misleading for an "autonomous" system nobody may be watching the logs
    of. Now explicitly marks the assessment `failed` with the error logged
    against it, so the API surface reflects reality even in this case."""
    assessment_id = initial_state.get("assessment_id")
    try:
        run_assessment(initial_state)
    except Exception as exc:  # noqa: BLE001 - background task; must not crash the worker
        logger.exception("orchestrator run failed for assessment %s", assessment_id)
        if assessment_id:
            try:
                from datetime import datetime, timezone

                from app.database.session import session_scope

                with session_scope() as db:
                    repository.update_assessment_status(
                        db, assessment_id, AssessmentStatus.FAILED, completed_at=datetime.now(timezone.utc),
                    )
                    repository.log_event(
                        db, assessment_id, "orchestrator",
                        f"orchestrator run crashed: {type(exc).__name__}: {exc}", level="error",
                    )
            except Exception:  # noqa: BLE001 - best-effort status update; the crash itself is already logged
                logger.exception("additionally failed to mark assessment %s as failed in the database", assessment_id)


@router.post("/assessments", response_model=CreateAssessmentResponse, status_code=201)
def create_assessment(
    request: CreateAssessmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> CreateAssessmentResponse:
    # Spec item 3 / app.core.execution_profile's own stated requirement: the same live_assessment-vs-
    # fixtures gate the CLI applies (app/orchestrator/__main__.py) must apply here too -- a FastAPI-created
    # assessment must not be able to quietly run fixture-backed when execution_profile=live_assessment,
    # just because this entry point forgot to call the one function that checks.
    try:
        preflight_check()
    except ExecutionProfileError as exc:
        raise HTTPException(400, str(exc)) from exc

    assessment_id = request.assessment_id or f"ASSESSMENT-{uuid.uuid4().hex[:10].upper()}"
    try:
        report_path(settings.reports_dir, assessment_id, "json")
    except ValueError as exc:
        raise HTTPException(422, "Assessment ID must be a safe filename identifier of at most 128 characters") from exc
    if db.get(AssessmentRecord, assessment_id) is not None:
        raise HTTPException(409, "An assessment with this ID already exists")

    graph_path = str(_input_file(request.network_graph_path, settings.network_graph_dir, "Network graph")) if request.network_graph_path else None
    binary_entries: list[tuple[str, str]] = []
    binary_assets = []
    binary_ids = set()
    for item in request.binaries:
        binary_id = item.binary_id or f"BINARY-{uuid.uuid4().hex[:8].upper()}"
        if binary_id in binary_ids or db.get(BinaryAssetRecord, binary_id) is not None:
            raise HTTPException(409, "Binary ID already exists; use a fresh identifier")
        binary_ids.add(binary_id)
        path = _input_file(item.file_path, settings.binaries_dir, "Binary")
        try:
            meta = identify_binary(path)
        except ToolExecutionError as exc:
            raise HTTPException(400, str(exc)) from exc
        binary_assets.append(
            BinaryAsset(
                binary_id=binary_id, assessment_id=assessment_id, file_name=meta.file_name,
                file_path=str(path), file_hash=meta.file_hash_sha256, format=meta.format, architecture=meta.architecture,
            ),
        )
        binary_entries.append((binary_id, str(path)))

    assessment = Assessment(
        assessment_id=assessment_id,
        scope_id=request.scope_id,
        status=AssessmentStatus.CREATED,
        assessment_policy=request.assessment_policy,
        network_graph_ref=graph_path,
        binaries_ref=str(settings.binaries_dir) if binary_entries else None,
    )
    try:
        repository.create_assessment(db, assessment)
        for binary in binary_assets:
            repository.store_binary_asset(db, binary)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Assessment or binary identifiers conflict with existing records") from exc

    if request.run_immediately:
        initial_state: OrchestratorState = {
            "assessment_id": assessment_id,
            "scope_id": request.scope_id,
            "policy": request.assessment_policy,
            "network_graph_source_path": graph_path,
            "binary_paths": binary_entries,
            "external_network_findings_raw": [],
            "errors": [],
        }
        background_tasks.add_task(_run_orchestrator_background, initial_state)
        message = "assessment created; orchestrator pipeline started in the background"
    else:
        message = "assessment created; call not configured to run immediately"

    return CreateAssessmentResponse(
        assessment_id=assessment_id, scope_id=request.scope_id, status=AssessmentStatus.CREATED, message=message,
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)) -> AssessmentResponse:
    try:
        record = repository.get_assessment(db, assessment_id)
    except AssessmentNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    return AssessmentResponse(
        assessment_id=record.assessment_id, scope_id=record.scope_id, status=record.status,
        network_graph_ref=record.network_graph_ref, binaries_ref=record.binaries_ref,
        created_at=record.created_at, completed_at=record.completed_at,
    )


@router.get("/assessments/{assessment_id}/network-graph", response_model=NetworkGraph)
def get_network_graph(assessment_id: str, db: Session = Depends(get_db)) -> NetworkGraph:
    graph = repository.load_network_graph(db, assessment_id)
    if graph is None:
        raise HTTPException(404, f"no network graph loaded yet for assessment {assessment_id!r}")
    return graph


@router.get("/assessments/{assessment_id}/findings", response_model=FindingsResponse)
def get_findings(
    assessment_id: str,
    surface: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
) -> FindingsResponse:
    records = repository.list_findings(db, assessment_id)
    findings = [repository.finding_to_schema(r) for r in records]
    if surface:
        findings = [f for f in findings if f.surface.value == surface]
    if status_filter:
        findings = [f for f in findings if f.status.value == status_filter]
    return FindingsResponse(assessment_id=assessment_id, count=len(findings), findings=findings)


@router.get("/assessments/{assessment_id}/agents", response_model=list[AgentTaskStatusResponse])
def get_agents(assessment_id: str, db: Session = Depends(get_db)) -> list[AgentTaskStatusResponse]:
    tasks = repository.list_agent_tasks(db, assessment_id)
    return [
        AgentTaskStatusResponse(
            task_id=t.task_id, agent_id=t.agent_id, task_type=t.task_type, status=t.status,
            error_message=t.error_message, started_at=t.started_at, completed_at=t.completed_at,
        )
        for t in tasks
    ]


@router.get("/assessments/{assessment_id}/report", response_model=None)
def get_report(
    assessment_id: str,
    format: str = Query(default="json", pattern="^(json|pdf)$"),
    download: bool = Query(default=False),
    source: str = Query(default="latest", pattern="^(latest|execution|snapshot)$"),
) -> ReportResponse | FileResponse:
    try:
        directory = report_directory(settings.reports_dir, assessment_id, source)
        json_path = report_path(directory, assessment_id, "json")
        pdf_path = report_path(directory, assessment_id, "pdf")
    except ValueError as exc:
        raise HTTPException(400, "Invalid report identifier") from exc

    if format == "pdf":
        if not pdf_path.is_file():
            raise HTTPException(404, "PDF report not yet generated for this assessment")
        return FileResponse(str(pdf_path), media_type="application/pdf", filename=pdf_path.name)

    if not json_path.is_file():
        raise HTTPException(404, "report not yet generated for this assessment")
    import json as _json

    try:
        data = _json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("assessment_id") != assessment_id:
            raise ValueError("Report assessment does not match")
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Saved report is unreadable or does not match this assessment") from exc
    data = public_output(data)
    if download:
        from fastapi.responses import Response

        return Response(_json.dumps(data, indent=2), media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="{json_path.name}"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        })
    return ReportResponse(assessment_id=assessment_id, json_report=data)


@router.post("/assessments/{assessment_id}/external-findings", response_model=ExternalFindingsResponse)
def submit_external_findings(
    assessment_id: str,
    request: ExternalFindingsRequest,
    db: Session = Depends(get_db),
) -> ExternalFindingsResponse:
    """Ingestion endpoint for the teammate's independently-developed Network
    Vulnerability Assessment Agent (PRD Part 6 / Part 14). Validates against
    the external contract and the assessment's own scope before persisting
    anything — his component is trusted to scan, not to expand the
    assessment's asset inventory."""
    try:
        record = repository.get_assessment(db, assessment_id)
    except AssessmentNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc

    graph = repository.load_network_graph(db, assessment_id)
    known_asset_ids = {a.asset_id for a in graph.assets} if graph else None

    payload = [f.model_dump(mode="json") for f in request.findings]
    try:
        validated = validate_external_findings(assessment_id, record.scope_id, payload, known_asset_ids=known_asset_ids)
    except ExternalFindingValidationError as exc:
        raise HTTPException(422, str(exc)) from exc

    findings = to_findings(validated)
    # Stub Evidence rows for any evidence_refs his findings cite, so
    # downstream evidence validation doesn't flag them as dangling — the
    # actual evidence artifact is retained by his own component, not
    # duplicated here.
    from app.core.schemas import Evidence

    stub_evidence = [
        Evidence(
            evidence_id=ref, finding_id=f.finding_id, evidence_type="external_network_evidence",
            source_tool="network_vulnerability_agent",
            description="Evidence reference supplied by the external Network Vulnerability Agent; "
            "raw artifact retained by that component.",
        )
        for f in findings
        for ref in f.evidence_refs
    ]
    repository.store_findings(db, findings, stub_evidence)
    db.commit()

    return ExternalFindingsResponse(accepted=len(findings), finding_ids=[f.finding_id for f in findings])
