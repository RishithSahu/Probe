"""Report generation for a CLI-driven autonomous assessment, straight from the database.

app.reporting.generator.generate_reports requires an in-memory OrchestratorState carrying each agent's own
AgentResult envelope (tool_executions, per-call used_fixture, errors) -- that is what the LangGraph/FastAPI
path (app/orchestrator/graph.py) produces and retains. app.orchestrator.autonomous_loop's CLI-driven loop
runs one candidate (or, concurrently, several) per iteration and never retains a consolidated state across
the whole run -- only each task's own AgentTaskRecord row and the Finding/Evidence rows it produced. This
is a real, separate reporting path for that case: it never invents per-call tool detail the database does
not have (no tool_executions, no per-call used_fixture), and says so explicitly rather than guessing.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.database import repository
from app.database.session import session_scope


def build_db_backed_report(assessment_id: str) -> dict[str, Any]:
    """Everything below is read directly from already-persisted rows -- nothing here is computed from a
    live tool call or invented to fill a gap. `known_limitations` names exactly what this report cannot
    show (per-call tool_executions/used_fixture detail), which `app.reporting.generator`'s
    AgentResult-backed path can show for a LangGraph/FastAPI-driven assessment."""
    with session_scope() as db:
        assessment = repository.get_assessment(db, assessment_id)
        tasks = repository.list_agent_tasks(db, assessment_id)
        findings = repository.list_findings(db, assessment_id)
        graph = repository.load_network_graph(db, assessment_id)

        task_rows = [
            {"task_id": t.task_id, "agent_id": t.agent_id, "status": t.status,
             "error_message": t.error_message, "started_at": t.started_at, "completed_at": t.completed_at}
            for t in tasks
        ]
        finding_rows = [
            {"finding_id": f.finding_id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
             "status": f.status, "surface": f.surface, "asset_id": f.asset_id, "service_id": f.service_id,
             "affected_url": f.affected_url, "description": f.description, "detection_method": f.detection_method,
             "remediation": f.remediation, "verification_state": f.verification_state}
            for f in findings
        ]
        assessment_info = {
            "assessment_id": assessment_id, "scope_id": assessment.scope_id if assessment else None,
            "status": assessment.status if assessment else None,
        }

    by_status: Counter = Counter(t["status"] for t in task_rows)
    by_agent: Counter = Counter(t["agent_id"] for t in task_rows)
    by_agent_status: dict[str, Counter] = {}
    for t in task_rows:
        by_agent_status.setdefault(t["agent_id"], Counter())[t["status"]] += 1

    findings_by_severity = Counter(f["severity"] for f in finding_rows)
    findings_by_status = Counter(f["status"] for f in finding_rows)
    findings_by_surface: dict[str, list[dict]] = {}
    for f in finding_rows:
        findings_by_surface.setdefault(f["surface"], []).append(f)

    hosts_with_findings = {f["asset_id"] for f in finding_rows if f["asset_id"]}
    incomplete_tasks = [
        {"task_id": t["task_id"], "agent_id": t["agent_id"], "status": t["status"], "error": t["error_message"]}
        for t in task_rows if t["status"] in ("failed", "partial")
    ]

    return {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "report_source": "db_backed (CLI-driven autonomous assessment; see app/reporting/db_report.py)",
        "assessment": assessment_info,
        "discovery": {
            "assets_in_network_graph": len(graph.assets) if graph else 0,
        },
        "task_execution": {
            "total_tasks": len(task_rows),
            "by_status": dict(by_status),
            "by_agent": dict(by_agent),
            "by_agent_and_status": {agent: dict(counts) for agent, counts in by_agent_status.items()},
            "incomplete_tasks": incomplete_tasks,
        },
        "findings": {
            "total": len(finding_rows),
            "by_severity": dict(findings_by_severity),
            "by_status": dict(findings_by_status),
            "by_surface": {surface: len(items) for surface, items in findings_by_surface.items()},
            "distinct_affected_assets": len(hosts_with_findings),
            "detail": finding_rows,
        },
        "known_limitations": [
            "This report is built directly from persisted AgentTaskRecord/Finding rows, not from each "
            "agent's own AgentResult envelope -- the CLI-driven autonomous loop (app.orchestrator."
            "autonomous_loop) does not retain that envelope across the whole run, only "
            "app.orchestrator.graph's LangGraph/FastAPI path does.",
            "Per-call tool_executions detail (which specific external tool ran for a given task, and "
            "whether that specific call fell back to a synthetic fixture) is therefore not available here "
            "at the per-task level. Any finding whose detection_method implies a fixture-backed tool "
            "(e.g. zap_passive_scan/zap_active_scan, when ZAP itself was unreachable and "
            "APE_WEB_AGENT_USE_FIXTURES is still enabled) should be treated as possibly fixture-derived "
            "unless independently confirmed -- check APE_WEB_AGENT_USE_FIXTURES/APE_BINARY_AGENT_USE_FIXTURES "
            "for the run that produced it.",
            "A task's own status (completed/partial/failed) is authoritative; 'incomplete_tasks' above "
            "lists every partial/failed task with its recorded error, so a zero-finding result for a host "
            "can be told apart from a host whose assessment never actually completed.",
        ],
    }


def write_db_backed_report(assessment_id: str, output_dir: Path) -> Path:
    report = build_db_backed_report(assessment_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{assessment_id}_db_report.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path
