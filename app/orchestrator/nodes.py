"""LangGraph workflow nodes (PRD Part 9.2).

Each function takes the current `OrchestratorState` and returns a partial
dict of the keys it updates — the signature LangGraph expects for a node.
Security-analysis logic itself never lives here (per the PRD's explicit
requirement that the Orchestrator coordinates, it does not analyse) — nodes
call into `app.agents.*`, `app.adapters.*`, and `app.analysis.*` and persist
via `app.database.repository`; this file is wiring, not logic.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from app.adapters.external_network_agent import to_findings, validate_external_findings
from app.adapters.network_graph_adapter import (
    JSONFileNetworkGraphSource,
    ProbeAPISource,
    extract_http_services,
    load_network_graph as adapter_load_network_graph,
    normalise_probe_graph,
)
from app.adapters.probe_leads import findings_from_probe_leads
from app.agents.binary_analysis.agent import run_binary_analysis_agent
from app.agents.network_vulnerability.agent import run_network_vulnerability_agent
from app.agents.web_security.agent import WebTarget, run_web_security_agent
from app.analysis.attack_paths import build_attack_path_graph
from app.analysis.evidence_validator import run_evidence_validation
from app.analysis.ptes_mapper import summarise_activities
from app.core.config import settings
from app.core.exceptions import AppError, GraphValidationError
from app.core.schemas import (
    AgentId,
    AgentResult,
    AssessmentStatus,
    TaskStatus,
)
from app.core.scope_guard import ScopeGuard
from app.database import repository
from app.database.session import session_scope
from app.orchestrator.dispatcher import run_concurrently
from app.orchestrator.state import OrchestratorState

logger = logging.getLogger("ape.orchestrator")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 1. validate_assessment
# ---------------------------------------------------------------------------


def validate_assessment(state: OrchestratorState) -> dict:
    assessment_id = state["assessment_id"]
    logger.info("validate_assessment: %s", assessment_id)
    with session_scope() as db:
        try:
            repository.get_assessment(db, assessment_id)
        except AppError as exc:
            return {"errors": [f"validate_assessment: {exc}"], "assessment_status": AssessmentStatus.FAILED.value}
        repository.update_assessment_status(db, assessment_id, AssessmentStatus.RUNNING)
    return {"assessment_status": AssessmentStatus.RUNNING.value, "errors": []}


# ---------------------------------------------------------------------------
# 2. load_network_graph
# ---------------------------------------------------------------------------


def load_network_graph(state: OrchestratorState) -> dict:
    """Loads the already-completed inventory. Two sources, both read-only —
    neither this node nor anything downstream of it performs discovery:

    1. A static JSON file (`network_graph_source_path`), when the request
       supplied one — the original provisional contract, still useful for
       offline work, synthetic fixtures, and an exported snapshot.
    2. The live Network Discovery Probe API (`settings.probe_api_url`),
       otherwise — the real integration, per docs/CONTRACT.md. Falls back
       here automatically so an assessment created without an explicit file
       path still gets an inventory when Probe is reachable.
    """
    assessment_id = state["assessment_id"]
    source_path = state.get("network_graph_source_path")

    try:
        if source_path:
            graph = adapter_load_network_graph(JSONFileNetworkGraphSource(source_path), raw_source_ref=source_path)
            source_desc = f"file {source_path}"
        elif settings.probe_api_url:
            graph = adapter_load_network_graph(
                ProbeAPISource(ensure_scan=settings.probe_ensure_scan_on_load),
                raw_source_ref=settings.probe_api_url,
                normaliser=normalise_probe_graph,
                scope_id=state["scope_id"],
            )
            source_desc = f"Probe API at {settings.probe_api_url}"
        else:
            return {
                "errors": state.get("errors", [])
                + ["load_network_graph: no network_graph_source_path supplied and APE_PROBE_API_URL is unset"]
            }
    except GraphValidationError as exc:
        return {"errors": state.get("errors", []) + [f"load_network_graph: {exc}"]}

    with session_scope() as db:
        repository.store_network_graph(db, assessment_id, graph)
        repository.log_event(db, assessment_id, AgentId.ORCHESTRATOR.value, f"loaded network graph from {source_desc}")

    return {"network_graph": graph}


# ---------------------------------------------------------------------------
# 3. normalise_network_graph
# ---------------------------------------------------------------------------


def normalise_network_graph(state: OrchestratorState) -> dict:
    """The adapter already normalises shape on load; this node's job is to
    derive the Web Agent's input (graph-listed HTTP/HTTPS services) — the
    *only* sanctioned way web targets enter the assessment."""
    graph = state.get("network_graph")
    if graph is None:
        return {"http_targets": []}

    http_services = extract_http_services(graph)
    targets: list[tuple[str, str]] = []
    for asset, service in http_services:
        scheme = "https" if service.service_name and "https" in service.service_name.lower() else "http"
        host = asset.ip or asset.hostname
        if not host:
            continue
        port_suffix = "" if (scheme == "https" and service.port == 443) or (scheme == "http" and service.port == 80) else f":{service.port}"
        targets.append((asset.asset_id, f"{scheme}://{host}{port_suffix}/"))

    return {"http_targets": targets}


# ---------------------------------------------------------------------------
# 4. validate_scope
# ---------------------------------------------------------------------------


def validate_scope(state: OrchestratorState) -> dict:
    """Builds the single ScopeGuard instance shared by both agents for this
    assessment run, and does an early sanity check: if web/binary analysis
    is authorised but there's nothing in scope to run it against, that's
    recorded (not fatal — e.g. a binary-only assessment with no web
    services is entirely valid)."""
    policy = state["policy"]
    graph = state.get("network_graph")
    warnings = []
    try:
        # Constructed here purely to fail fast on a malformed policy/graph
        # combination before any agent is dispatched. ScopeGuard itself isn't
        # threaded through state (it isn't cleanly serialisable across
        # LangGraph checkpoints) — downstream nodes reconstruct their own
        # instance from (policy, network_graph).
        ScopeGuard(policy, graph)
    except Exception as exc:  # noqa: BLE001 - surfaced as a warning, not fatal here
        warnings.append(f"validate_scope: failed to construct ScopeGuard: {exc}")

    if policy.allow_passive_web_analysis and not state.get("http_targets"):
        warnings.append("allow_passive_web_analysis is enabled but no HTTP/HTTPS services were found in the graph")
    if policy.allow_binary_analysis and not state.get("binary_paths"):
        warnings.append("allow_binary_analysis is enabled but no binaries were supplied")

    return {"errors": state.get("errors", []) + warnings}


# ---------------------------------------------------------------------------
# 5. create_agent_tasks
# ---------------------------------------------------------------------------


def create_agent_tasks(state: OrchestratorState) -> dict:
    from app.core.schemas import AgentTask

    assessment_id = state["assessment_id"]
    task_status: dict[str, dict] = {}

    with session_scope() as db:
        for agent_id, task_type, input_data in (
            (AgentId.WEB_SECURITY, "web_security_assessment", {"targets": state.get("http_targets", [])}),
            (AgentId.BINARY_ANALYSIS, "binary_analysis", {"binaries": state.get("binary_paths", [])}),
            (AgentId.NETWORK_VULNERABILITY, "external_ingestion", {}),
            (AgentId.NETWORK_VULNERABILITY_DETECTIVE, "network_service_assessment", {}),
        ):
            task_id = f"TASK-{agent_id.value}-{assessment_id}"
            repository.upsert_agent_task(
                db,
                AgentTask(task_id=task_id, assessment_id=assessment_id, agent_id=agent_id, task_type=task_type,
                          input_data=input_data, status=TaskStatus.PENDING),
            )
            task_status[agent_id.value] = {"status": TaskStatus.PENDING.value, "error": None}

    return {"task_status": task_status}


def _call_web_agent_remote(assessment_id: str, http_targets: list[tuple[str, str]], policy, graph) -> AgentResult:
    import httpx as _httpx

    body = {
        "assessment_id": assessment_id, "targets": http_targets,
        "policy": policy.model_dump(mode="json"),
        "network_graph": graph.model_dump(mode="json") if graph else None,
    }
    resp = _httpx.post(f"{settings.web_agent_service_url}/run", json=body, timeout=settings.agent_service_timeout_seconds)
    resp.raise_for_status()
    return AgentResult.model_validate(resp.json())


def _call_binary_agent_remote(assessment_id: str, binary_paths: list[tuple[str, str]], policy, graph) -> AgentResult:
    import httpx as _httpx

    body = {
        "assessment_id": assessment_id, "binaries": binary_paths,
        "policy": policy.model_dump(mode="json"),
        "network_graph": graph.model_dump(mode="json") if graph else None,
    }
    resp = _httpx.post(f"{settings.binary_agent_service_url}/run", json=body, timeout=settings.agent_service_timeout_seconds)
    resp.raise_for_status()
    return AgentResult.model_validate(resp.json())


def _mark_task(assessment_id: str, agent_id: AgentId, status: TaskStatus, *, error: str | None = None) -> None:
    from app.core.schemas import AgentTask

    with session_scope() as db:
        task_id = f"TASK-{agent_id.value}-{assessment_id}"
        repository.upsert_agent_task(
            db,
            AgentTask(
                task_id=task_id, assessment_id=assessment_id, agent_id=agent_id, task_type="",
                status=status, error_message=error,
                started_at=_now() if status == TaskStatus.RUNNING else None,
                completed_at=_now() if status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED) else None,
            ),
        )


# ---------------------------------------------------------------------------
# 6 & 7. dispatch_web_agent / dispatch_binary_agent (run concurrently)
# ---------------------------------------------------------------------------


def dispatch_specialist_agents(state: OrchestratorState) -> dict:
    """Combines the Web, Binary, and Network Vulnerability Detective
    dispatch into one LangGraph node so all three execute concurrently via
    `run_concurrently` — LangGraph models true node-level parallelism via
    separate graph branches, but since all three tasks here are short-lived
    and independent, running them inside one node with a thread pool keeps
    the graph topology simple while still satisfying "agents execute
    concurrently".

    The Network Vulnerability Detective (app/agents/network_vulnerability/)
    only assesses services already present in the authorised NetworkGraph —
    it never performs discovery itself; that remains Probe's job
    exclusively (see docs/IMPLEMENTATION_STATUS.md, "The Probe conflict")."""
    assessment_id = state["assessment_id"]
    policy = state["policy"]
    graph = state.get("network_graph")
    guard = ScopeGuard(policy, graph)
    output_dir = Path(settings.evidence_dir) / assessment_id
    output_dir.mkdir(parents=True, exist_ok=True)

    jobs = {}

    http_targets = state.get("http_targets", [])
    if policy.allow_passive_web_analysis and http_targets:
        _mark_task(assessment_id, AgentId.WEB_SECURITY, TaskStatus.RUNNING)
        if settings.web_agent_service_url:
            jobs[AgentId.WEB_SECURITY.value] = lambda: _call_web_agent_remote(assessment_id, http_targets, policy, graph)
        else:
            web_targets = [WebTarget(asset_id=aid, url=url) for aid, url in http_targets]
            jobs[AgentId.WEB_SECURITY.value] = lambda: run_web_security_agent(
                web_targets, assessment_id=assessment_id, scope_guard=guard, policy=policy, output_dir=output_dir,
            )
    else:
        _mark_task(assessment_id, AgentId.WEB_SECURITY, TaskStatus.SKIPPED, error="not authorised or no HTTP targets")

    binary_paths = state.get("binary_paths", [])
    if policy.allow_binary_analysis and binary_paths:
        _mark_task(assessment_id, AgentId.BINARY_ANALYSIS, TaskStatus.RUNNING)
        if settings.binary_agent_service_url:
            jobs[AgentId.BINARY_ANALYSIS.value] = lambda: _call_binary_agent_remote(assessment_id, binary_paths, policy, graph)
        else:
            binaries = [(bid, Path(p)) for bid, p in binary_paths]
            jobs[AgentId.BINARY_ANALYSIS.value] = lambda: run_binary_analysis_agent(
                binaries, assessment_id=assessment_id, scope_guard=guard, output_dir=output_dir,
            )
    else:
        _mark_task(assessment_id, AgentId.BINARY_ANALYSIS, TaskStatus.SKIPPED, error="not authorised or no binaries supplied")

    # Network Vulnerability Detective: every (asset, service) pair in the
    # already-loaded graph — it decides itself which services it has a
    # check for (see _CHECKED_SERVICE_NAMES) and silently skips the rest;
    # this is not a second discovery pass, only a filter over what Probe
    # already reported.
    netvuln_targets: list[tuple] = []
    if graph is not None:
        for asset in graph.assets:
            for service in asset.services:
                netvuln_targets.append((asset, service))

    if policy.allow_network_service_assessment and netvuln_targets:
        _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY_DETECTIVE, TaskStatus.RUNNING)
        jobs[AgentId.NETWORK_VULNERABILITY_DETECTIVE.value] = lambda: run_network_vulnerability_agent(
            netvuln_targets, assessment_id=assessment_id, scope_guard=guard,
            allow_ftp_anonymous_check=policy.allow_ftp_anonymous_check,
        )
    else:
        _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY_DETECTIVE, TaskStatus.SKIPPED,
                    error="not authorised or no services in the graph")

    results = run_concurrently(jobs) if jobs else {}

    web_result = results.get(AgentId.WEB_SECURITY.value)
    binary_result = results.get(AgentId.BINARY_ANALYSIS.value)
    netvuln_result = results.get(AgentId.NETWORK_VULNERABILITY_DETECTIVE.value)

    if web_result is not None:
        _mark_task(assessment_id, AgentId.WEB_SECURITY, web_result.execution_status,
                    error="; ".join(web_result.errors) if web_result.errors else None)
    if binary_result is not None:
        _mark_task(assessment_id, AgentId.BINARY_ANALYSIS, binary_result.execution_status,
                    error="; ".join(binary_result.errors) if binary_result.errors else None)
    if netvuln_result is not None:
        _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY_DETECTIVE, netvuln_result.execution_status,
                    error="; ".join(netvuln_result.errors) if netvuln_result.errors else None)

    # Persist the scope guard's audit trail regardless of outcome — tool
    # invocations (allowed AND denied) must be recorded even for a failed task.
    with session_scope() as db:
        for record in guard.audit_log:
            repository.store_tool_invocation_log(db, assessment_id, "scope_guard", record)

    return {
        "web_agent_result": web_result, "binary_agent_result": binary_result,
        "network_vulnerability_result": netvuln_result,
    }


# ---------------------------------------------------------------------------
# 8. ingest_network_agent_results (external interface)
# ---------------------------------------------------------------------------


def ingest_network_agent_results(state: OrchestratorState) -> dict:
    """Pulls network-surface findings from two independent sources, neither
    of which this node dispatches or scans with itself:

    1. Whatever was POSTed to `/assessments/{id}/external-findings` and
       queued for this run via `external_network_findings_raw` — the
       contract for a separate, deeper Network Vulnerability Assessment
       Agent, should one be built later (app.adapters.external_network_agent).
    2. The Network Discovery Probe's own `leads()` feed, pulled fresh on
       every run when `settings.probe_auto_ingest_leads` and
       `settings.probe_api_url` are set (app.adapters.probe_leads) — the
       real signal this application has today.

    One source failing (e.g. Probe unreachable) does not discard the other;
    the task is only `failed` if every configured/supplied source failed,
    and `skipped` only if nothing was configured or supplied at all.
    """
    assessment_id = state["assessment_id"]
    scope_id = state["scope_id"]
    graph = state.get("network_graph")
    raw_payload = state.get("external_network_findings_raw", [])
    known_asset_ids = {a.asset_id for a in graph.assets} if graph else None

    all_findings: list = []
    all_evidence: list = []
    source_errors: list[str] = []
    any_source_attempted = False

    if raw_payload:
        any_source_attempted = True
        try:
            validated = validate_external_findings(assessment_id, scope_id, raw_payload, known_asset_ids=known_asset_ids)
            all_findings.extend(to_findings(validated))
        except Exception as exc:  # noqa: BLE001 - one bad submission must not abort the assessment
            source_errors.append(f"external_findings_payload: {exc}")

    if settings.probe_auto_ingest_leads and settings.probe_api_url:
        any_source_attempted = True
        try:
            from probe.client import ProbeClient, ProbeError

            leads = ProbeClient(base_url=settings.probe_api_url).leads()
            lead_findings, lead_evidence = findings_from_probe_leads(leads, assessment_id=assessment_id)
            all_findings.extend(lead_findings)
            all_evidence.extend(lead_evidence)
        except ImportError:
            source_errors.append("probe_leads: 'probe' package not importable")
        except ProbeError as exc:
            source_errors.append(f"probe_leads: could not reach Probe at {settings.probe_api_url}: {exc}")

    if not any_source_attempted:
        _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY, TaskStatus.SKIPPED,
                    error="no external findings submitted and Probe lead auto-ingest is disabled/unconfigured")
        return {"network_agent_findings": [], "network_agent_evidence": []}

    if source_errors and not all_findings:
        _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY, TaskStatus.FAILED, error="; ".join(source_errors))
        return {
            "network_agent_findings": [], "network_agent_evidence": [],
            "errors": state.get("errors", []) + [f"ingest_network_agent_results: {e}" for e in source_errors],
        }

    _mark_task(assessment_id, AgentId.NETWORK_VULNERABILITY, TaskStatus.COMPLETED,
                error="; ".join(source_errors) if source_errors else None)
    return {
        "network_agent_findings": all_findings, "network_agent_evidence": all_evidence,
        "errors": state.get("errors", []) + [f"ingest_network_agent_results: {e}" for e in source_errors],
    }


# ---------------------------------------------------------------------------
# 9. aggregate_findings
# ---------------------------------------------------------------------------


def aggregate_findings(state: OrchestratorState) -> dict:
    all_findings = []
    all_evidence = []

    web_result = state.get("web_agent_result")
    if web_result is not None:
        all_findings.extend(web_result.findings)
        all_evidence.extend(web_result.evidence)

    binary_result = state.get("binary_agent_result")
    if binary_result is not None:
        all_findings.extend(binary_result.findings)
        all_evidence.extend(binary_result.evidence)

    netvuln_result = state.get("network_vulnerability_result")
    if netvuln_result is not None:
        all_findings.extend(netvuln_result.findings)
        all_evidence.extend(netvuln_result.evidence)

    all_findings.extend(state.get("network_agent_findings", []))
    all_evidence.extend(state.get("network_agent_evidence", []))

    with session_scope() as db:
        repository.store_findings(db, all_findings, all_evidence)
        repository.log_event(db, state["assessment_id"], AgentId.ORCHESTRATOR.value,
                              f"aggregated {len(all_findings)} findings / {len(all_evidence)} evidence items")

    return {"all_findings": all_findings, "all_evidence": all_evidence}


# ---------------------------------------------------------------------------
# 10. validate_evidence
# ---------------------------------------------------------------------------


def validate_evidence(state: OrchestratorState) -> dict:
    findings = state.get("all_findings", [])
    evidence = state.get("all_evidence", [])
    promoted, report = run_evidence_validation(findings, evidence)

    with session_scope() as db:
        for finding in promoted:
            repository.update_finding_status(db, finding.finding_id, finding.status.value,
                                              verification_required=finding.verification_required)

    return {
        "validated_findings": promoted,
        "validation_report": {
            "total_findings": report.total_findings,
            "valid_count": len(report.valid),
            "invalid_count": len(report.invalid),
            "invalid_reasons": [reason for _, reason in report.invalid],
            "auto_confirmed": report.auto_confirmed,
            "incomplete_evidence": report.incomplete_evidence,
        },
    }


# ---------------------------------------------------------------------------
# 11. build_attack_paths
# ---------------------------------------------------------------------------


def build_attack_paths(state: OrchestratorState) -> dict:
    graph = state.get("network_graph")
    findings = state.get("validated_findings", [])
    if graph is None:
        return {"attack_path_edges": []}

    attack_graph = build_attack_path_graph(graph, findings)
    edges = attack_graph.to_edge_dicts()

    with session_scope() as db:
        repository.store_attack_path_edges(db, state["assessment_id"], edges)

    return {"attack_path_edges": edges}


# ---------------------------------------------------------------------------
# 12. map_ptes_phases
# ---------------------------------------------------------------------------


def map_ptes_phases(state: OrchestratorState) -> dict:
    tool_executions: list[dict] = []
    for result in (state.get("web_agent_result"), state.get("binary_agent_result"), state.get("network_vulnerability_result")):
        if result is not None:
            tool_executions.extend(result.tool_executions)

    summary = summarise_activities(tool_executions, state.get("validated_findings", []))
    return {"ptes_summary": summary.to_dict()}


# ---------------------------------------------------------------------------
# 13. generate_report
# ---------------------------------------------------------------------------


def generate_report(state: OrchestratorState) -> dict:
    from app.reporting.generator import generate_reports

    output_dir = Path(settings.reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path, pdf_path = generate_reports(state, output_dir=output_dir)
    return {"report_json_path": str(json_path), "report_pdf_path": str(pdf_path)}


# ---------------------------------------------------------------------------
# 14. complete_assessment
# ---------------------------------------------------------------------------


def complete_assessment(state: OrchestratorState) -> dict:
    """Determines the final AssessmentStatus from each specialist task's
    actual recorded TaskStatus (persisted by `_mark_task` throughout this
    run) — NOT from `OrchestratorState.errors`.

    `errors` previously drove this decision directly, which was a bug: that
    list also accumulates benign diagnostic notes (e.g. validate_scope's
    "a permission is enabled but there's nothing in the graph to use it
    on") that are not failures. A run where every attempted task actually
    completed, but validate_scope merely noted a configuration mismatch,
    was incorrectly reported as `partially_completed`. SKIPPED tasks
    (not authorised, or nothing to do) don't count as failures either —
    only COMPLETED vs FAILED among tasks that were actually attempted.
    """
    assessment_id = state["assessment_id"]

    with session_scope() as db:
        tasks = repository.list_agent_tasks(db, assessment_id)
        attempted = [t for t in tasks if t.status in (TaskStatus.COMPLETED.value, TaskStatus.FAILED.value)]
        failed = [t for t in attempted if t.status == TaskStatus.FAILED.value]

        if attempted and len(failed) == len(attempted):
            final_status = AssessmentStatus.FAILED
        elif failed:
            final_status = AssessmentStatus.PARTIALLY_COMPLETED
        else:
            final_status = AssessmentStatus.COMPLETED

        repository.update_assessment_status(db, assessment_id, final_status, completed_at=_now())
        repository.log_event(db, assessment_id, AgentId.ORCHESTRATOR.value,
                              f"assessment complete: status={final_status.value}")

    return {"assessment_status": final_status.value}
