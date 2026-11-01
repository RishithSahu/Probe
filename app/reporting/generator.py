"""Consolidated report generation: JSON (machine-readable, full fidelity) and
PDF (human-readable, via ReportLab) from the same underlying data. Activity
mapping is derived from every recorded agent result, including handoffs;
no discovery or analysis is repeated to produce either artifact.

Narrative text sections (executive summary, methodology) are rendered via
Jinja2 templates in `templates/` so their wording can be edited without
touching the PDF layout code.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

from app.adapters.discovery_snapshot import read_snapshot
from app.analysis.great_readiness import evaluate_great
from app.analysis.ptes_mapper import summarise_activities
from app.core.exceptions import GraphValidationError
from app.core.schemas import AgentResult, PtesPhase, TaskStatus
from app.reporting.completeness import assessment_coverage
from app.reporting.pdf_sections import (
    attack_paths_section,
    coverage_section,
    evidence_section,
    inventory_section,
    measurement_section,
    table,
    text,
)
from app.reporting.safety import public_output, report_path

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(disabled_extensions=("txt.j2",)),
    trim_blocks=True,
)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_AGENT_RESULT_LABELS = (
    ("web_agent_result", "Web Security Agent"),
    ("binary_agent_result", "Binary Analysis Agent"),
    ("network_vulnerability_result", "Network Vulnerability Detective"),
    ("triggered_binary_agent_result", "Discovered Binary Analysis Agent"),
)
_SEVERITY_COLORS = {
    "critical": colors.HexColor("#7a0d0d"),
    "high": colors.HexColor("#c0392b"),
    "medium": colors.HexColor("#d68910"),
    "low": colors.HexColor("#2874a6"),
    "info": colors.HexColor("#5d6d7e"),
}


def _finding_dict(f) -> dict[str, Any]:
    return f.model_dump(mode="json")


def _build_report_data(state: dict) -> dict[str, Any]:
    """Pure data-assembly step, shared by the JSON and PDF writers. Produces
    exactly the sections required by PRD Part 13.4 / the PRD's reporting
    requirements, each one traceable to actual pipeline output rather than
    invented narrative."""
    assessment_id = state["assessment_id"]
    graph = state.get("network_graph")
    findings = state.get("validated_findings", state.get("all_findings", []))
    evidence = state.get("all_evidence", [])
    validation_report = state.get("validation_report", {})
    attack_path_edges = state.get("attack_path_edges", [])
    ptes_summary = state.get("ptes_summary", {})
    agent_results = [result for result in state.values() if isinstance(result, AgentResult)]
    if agent_results:
        # Derive report mapping from all recorded branches, including handoffs.
        # The orchestration state is not mutated and no activities are invented.
        ptes_summary = summarise_activities(
            [event for result in agent_results for event in result.tool_executions], findings,
        ).to_dict()
    coverage_state = dict(state)
    discovery_provenance = {}
    if graph and graph.raw_source_ref and Path(graph.raw_source_ref).parent.name == "discovery_snapshots":
        try:
            snapshot = read_snapshot(graph.raw_source_ref)
            if snapshot.get("scope_id") != state.get("scope_id"):
                raise GraphValidationError("Retained snapshot scope does not match the report")
            raw = snapshot["payload"]
            probe_report = raw.get("_probe_metadata", {}).get("report", {})
            converged = probe_report.get("summary", {}).get("converged")
            if isinstance(converged, bool) and "discovery_report" not in coverage_state:
                coverage_state["discovery_report"] = {"converged": converged}
            discovery_provenance = {
                "snapshot_ref": graph.raw_source_ref, "snapshot_sha256": Path(graph.raw_source_ref).stem,
                "integrity_verified": True, "observation_only": True,
                "recorded_scope": probe_report.get("authorised_scope"),
                "import_limitations": raw.get("_import_limitations", []),
                "network_observation_count": len(probe_report.get("network_observations", [])),
                "meaning": "Preserved discovery evidence; not a permission grant or instruction to replay a method.",
            }
        except (GraphValidationError, OSError, ValueError, KeyError, TypeError, AttributeError):
            discovery_provenance = {"integrity_verified": False, "import_limitations": ["Retained discovery evidence could not be verified"]}
    coverage = assessment_coverage(coverage_state)
    if discovery_provenance and not discovery_provenance.get("integrity_verified"):
        coverage["overall"] = "incomplete"
        coverage["evidence_incomplete"] = True

    findings_by_status = Counter(f.status.value for f in findings)
    findings_by_severity = Counter(f.severity.value for f in findings)
    findings_by_surface: dict[str, list[dict]] = {"network": [], "web": [], "binary": []}
    for f in findings:
        findings_by_surface.setdefault(f.surface.value, []).append(_finding_dict(f))

    incomplete_tasks = []
    agent_execution_summary = {}
    labels = dict(_AGENT_RESULT_LABELS)
    for result_key, result in state.items():
        if not isinstance(result, AgentResult):
            continue
        label = labels.get(result_key, result_key)
        agent_execution_summary[result_key] = {
            "status": result.execution_status.value,
            "errors": list(result.errors),
            "tool_execution_count": len(result.tool_executions),
        }
        if result.errors:
            incomplete_tasks.append(f"{label}: {'; '.join(result.errors)}")
        if result.execution_status != TaskStatus.COMPLETED:
            incomplete_tasks.append(f"{label}: execution status {result.execution_status.value}")
    if validation_report.get("invalid_count"):
        incomplete_tasks.append(f"Evidence validation rejected {validation_report['invalid_count']} finding(s); see evidence_validation")
    if validation_report.get("incomplete_evidence"):
        incomplete_tasks.append(
            f"Evidence is incomplete for {len(validation_report['incomplete_evidence'])} finding(s); see evidence_validation"
        )
    if coverage["missing_or_incomplete_surfaces"]:
        incomplete_tasks.append("Required surfaces incomplete: " + ", ".join(coverage["missing_or_incomplete_surfaces"]))
    if coverage["discovery_status"] != "complete":
        incomplete_tasks.append("Discovery completeness is " + coverage["discovery_status"])
    if ptes_summary.get("unmapped_activities"):
        incomplete_tasks.append(f"PTES phase is unresolved for {len(ptes_summary['unmapped_activities'])} activity record(s)")
    incomplete_tasks.extend(discovery_provenance.get("import_limitations", []))
    incomplete_tasks.extend(state.get("report_limitations", []))
    if not state.get("network_agent_findings"):
        incomplete_tasks.append("External Network Vulnerability Agent: no results ingested for this run")

    # FIX (fundamental report-integrity gap): when a real tool (Katana, ZAP,
    # Ghidra) is unavailable, its agent silently substitutes documented
    # synthetic fixture data (see each agent's `_synthetic_*` fallback) so
    # development/demos keep working. That substitution was previously
    # invisible in the final report — a reader had no way to tell a
    # fixture-generated finding from a real one. Every tool_executions entry
    # already carries `used_fixture`; this surfaces it as an explicit,
    # unmissable report section instead of silently losing that signal.
    fixture_tools_used: set[str] = set()
    for result in agent_results:
        for te in result.tool_executions:
            if te.get("used_fixture"):
                fixture_tools_used.add(te.get("tool", "unknown"))
    for item in evidence:
        if (item.raw_data or {}).get("used_fixture") is True:
            fixture_tools_used.add(item.source_tool)
    fixture_tools_used = sorted(fixture_tools_used)
    tool_history_available = state.get("report_source", {}).get("tool_execution_history_available", True)

    policy = state.get("policy")
    policy_dict = policy.model_dump(mode="json") if policy else {}

    exec_summary = _jinja_env.get_template("executive_summary.txt.j2").render(
        assessment_id=assessment_id,
        scope_id=state.get("scope_id", ""),
        asset_count=len(graph.assets) if graph else 0,
        binary_count=len(state.get("binary_paths", [])),
        confirmed_count=findings_by_status.get("confirmed", 0),
        suspected_count=findings_by_status.get("suspected", 0),
        rejected_count=findings_by_status.get("rejected", 0),
        severity_counts={s: findings_by_severity.get(s, 0) for s in _SEVERITY_ORDER if findings_by_severity.get(s, 0)},
        incomplete_tasks=incomplete_tasks,
        fixture_tools_used=fixture_tools_used,
        coverage=coverage,
    )
    methodology = _jinja_env.get_template("methodology.txt.j2").render(
        crawling_enabled=policy_dict.get("allow_web_crawling", False),
        active_scan_enabled=policy_dict.get("allow_active_web_verification", False),
    )

    report_data = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "assessment_id": assessment_id,
        "scope_id": state.get("scope_id", ""),
        "executive_summary": exec_summary.strip(),
        "authorised_scope": policy_dict,
        "methodology": methodology.strip(),
        "network_graph_overview": graph.model_dump(mode="json") if graph else None,
        "findings_by_surface": findings_by_surface,
        "findings_summary": {
            "total": len(findings),
            "by_status": dict(findings_by_status),
            "by_severity": dict(findings_by_severity),
        },
        "evidence": [e.model_dump(mode="json") for e in evidence],
        "evidence_validation": validation_report,
        "vulnerability_lifecycles": state.get("vulnerability_lifecycles", []),
        "attack_paths": attack_path_edges,
        "ptes_mapping": ptes_summary,
        "incomplete_tasks_and_limitations": incomplete_tasks,
        "agent_execution_summary": agent_execution_summary,
        "assessment_coverage": coverage,
        "discovery_provenance": discovery_provenance,
        "execution_metrics": state.get("execution_metrics", {}),
        "scope_audit": state.get("scope_audit", {}),
        "task_ledger": state.get("task_ledger", []),
        "report_source": state.get("report_source", {"kind": "execution_state"}),
        # See the fixture_tools_used comment above `exec_summary` — this is
        # the authoritative, machine-readable form of that warning. A
        # non-empty list means at least one tool's findings in this report
        # are synthetic fixture data, not real scan results.
        "data_integrity": {
            "fixture_tools_used": fixture_tools_used,
            "contains_synthetic_data": True if fixture_tools_used else (False if tool_history_available else None),
            "tool_execution_history_available": tool_history_available,
        },
    }
    try:
        report_data["great_readiness"] = evaluate_great(report_data, state.get("benchmark_comparison"))
    except ValueError:
        report_data["great_readiness"] = evaluate_great(report_data)
        report_data["great_readiness"]["comparison_error"] = "Optional comparison does not match this assessment/scope"
        incomplete_tasks.append("Optional scoring comparison rejected; assessment/scope binding did not match")
    return public_output(report_data)


def write_json_report(report_data: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_path.parent,
                                     prefix=".report-", suffix=".json", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(public_output(report_data), stream, indent=2, default=str)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path


def _severity_badge_style(severity: str) -> ParagraphStyle:
    styles = getSampleStyleSheet()
    return ParagraphStyle(
        f"severity_{severity}", parent=styles["Normal"], textColor=colors.white,
        backColor=_SEVERITY_COLORS.get(severity, colors.grey), alignment=1,
    )


def write_pdf_report(report_data: dict[str, Any], output_path: Path) -> Path:
    report_data = public_output(report_data)
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.splitLongWords = True
    styles["Normal"].fontSize = 9
    styles["Normal"].leading = 13
    styles["BodyText"].fontSize = 8
    styles["BodyText"].leading = 11
    for name in ("Heading1", "Heading2", "Heading3"):
        styles[name].keepWithNext = True
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    story = []

    story.append(Paragraph("Autonomous Security Assessment Report", styles["Title"]))
    story.append(Paragraph(f"Assessment {text(report_data['assessment_id'])} &middot; Scope {text(report_data['scope_id'])}", styles["Normal"]))
    story.append(Paragraph(f"Generated {text(report_data['generated_at'])}", styles["Normal"]))
    coverage = report_data.get("assessment_coverage", {})
    story.append(Paragraph(
        f"<b>Coverage: {text(coverage.get('overall', 'unknown'))}</b> &middot; "
        f"Discovery: {text(coverage.get('discovery_status', 'unknown'))}", styles["Normal"],
    ))
    story.append(Spacer(1, 0.5 * cm))

    fixture_tools = report_data.get("data_integrity", {}).get("fixture_tools_used", [])
    if fixture_tools:
        warning_style = ParagraphStyle(
            "data_integrity_warning", parent=styles["Normal"], textColor=colors.white,
            backColor=colors.HexColor("#b91c1c"), borderPadding=8, leading=14,
        )
        story.append(Paragraph(
            f"<b>DATA INTEGRITY WARNING</b> &mdash; this report contains SYNTHETIC/FIXTURE data from: "
            f"<b>{text(', '.join(fixture_tools))}</b>. These tool(s) were unavailable during this run; their "
            "findings are documented placeholders, not real scan results, and must not be acted on as such.",
            warning_style,
        ))
        story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    executive_summary = report_data["executive_summary"]
    if fixture_tools and executive_summary.startswith("*** DATA INTEGRITY WARNING ***"):
        executive_summary = executive_summary.split("\n\n", 1)[-1]
    for para in executive_summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(text(para.strip()), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))

    story.append(Paragraph("Assessment Scope", styles["Heading1"]))
    policy = report_data["authorised_scope"]
    scope_rows = [["Permission", "Enabled"]] + [
        [k.replace("_", " ").capitalize(), "Yes" if v else "No"] for k, v in policy.items() if isinstance(v, bool)
    ]
    story.append(table(scope_rows[0], scope_rows[1:], styles, doc.width))
    for field, label in (("approved_asset_ids", "Approved asset IDs"), ("approved_web_origins", "Approved web origins")):
        story.append(Paragraph(f"{label}: {text(', '.join(policy.get(field, [])) or 'None explicitly listed')}", styles["Normal"]))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Methodology", styles["Heading1"]))
    for para in report_data["methodology"].split("\n\n"):
        if para.strip():
            story.append(Paragraph(text(para.strip()), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))

    story.extend(coverage_section(report_data, styles))
    story.extend(measurement_section(report_data, styles, doc.width))
    story.extend(inventory_section(report_data, styles, doc.width))
    story.append(PageBreak())
    story.append(Paragraph("Findings Summary", styles["Heading1"]))
    summary = report_data["findings_summary"]
    story.append(Paragraph(f"Total findings: {summary['total']}", styles["Normal"]))
    status_rows = [["Status", "Count"]] + [[k, str(v)] for k, v in summary["by_status"].items()]
    story.append(table(status_rows[0], status_rows[1:], styles, doc.width))
    story.append(Spacer(1, 0.3 * cm))
    severity_rows = [["Severity", "Count"]] + [
        [sev, str(summary["by_severity"].get(sev, 0))] for sev in _SEVERITY_ORDER if summary["by_severity"].get(sev, 0)
    ]
    story.append(table(severity_rows[0], severity_rows[1:], styles, doc.width))
    for label, key in (("Network Findings", "network"), ("Web Security Findings", "web"), ("Binary Analysis Findings", "binary")):
        if not report_data["findings_by_surface"].get(key):
            story.append(Paragraph(f"{label}: no findings recorded.", styles["Normal"]))

    for surface_label, surface_key in (("Network Findings", "network"), ("Web Security Findings", "web"), ("Binary Analysis Findings", "binary")):
        findings = report_data["findings_by_surface"].get(surface_key, [])
        if not findings:
            continue
        story.append(Paragraph(surface_label, styles["Heading1"]))
        for f in findings:
            group = [Paragraph(text(f"{f['title']}  [{f['severity'].upper()} / {f['status'].upper()}]"), styles["Heading3"]),
                     Paragraph(f"Agent: {text(f['agent_id'])} &middot; Detection: {text(f.get('detection_method') or 'n/a')}", styles["Normal"]),
                     Paragraph(text(f.get("description", "")), styles["Normal"])]
            if f.get("remediation"):
                group.append(Paragraph(f"Remediation: {text(f['remediation'])}", styles["Normal"]))
            target = f.get("asset_id") or f.get("binary_id") or "not recorded"
            group.append(Paragraph(
                f"Finding: {text(f.get('finding_id'))} &middot; Target: {text(target)}<br/>"
                f"Service: {text(f.get('service_id') or 'not recorded')} &middot; "
                f"Confidence: {text(f.get('confidence', 'unknown'))}<br/>"
                f"Location: {text(f.get('affected_url') or f.get('function_name') or f.get('function_address') or 'not recorded')}",
                styles["Normal"],
            ))
            group.append(Paragraph(f"PTES phase: {text(f.get('ptes_phase', 'n/a'))} &middot; Evidence: {text(', '.join(f.get('evidence_refs', [])) or 'none')}", styles["Normal"]))
            story.extend(group)
            story.append(Spacer(1, 10))

    story.extend(attack_paths_section(report_data, styles))
    story.extend(evidence_section(report_data, styles))
    story.append(Paragraph("PTES Mapping", styles["Heading1"]))
    ptes = report_data.get("ptes_mapping", {})
    ptes_rows = []
    for phase in (item.value for item in PtesPhase):
        if not any(phase in ptes.get(key, {}) for key in ("phase_activity_counts", "phase_finding_counts", "failed_activity_counts")):
            continue
        ptes_rows.append([
            phase,
            str(ptes.get("phase_activity_counts", {}).get(phase, 0)),
            str(ptes.get("phase_finding_counts", {}).get(phase, 0)),
            str(ptes.get("failed_activity_counts", {}).get(phase, 0)),
        ])
    story.append(table(["Phase", "Activities", "Findings", "Failed attempts"], ptes_rows, styles, doc.width))
    for key, label in (("inferred_operations", "Legacy operations inferred"), ("unmapped_activities", "Unmapped activities"), ("skipped_activities", "Activities not executed")):
        for activity in ptes.get(key, []):
            story.append(Paragraph(f"{label}: {text(activity)}", styles["Normal"]))

    story.append(Paragraph("Incomplete Tasks and Limitations", styles["Heading1"]))
    limitations = report_data.get("incomplete_tasks_and_limitations", [])
    if limitations:
        for item in limitations:
            story.append(Paragraph(f"&bull; {text(item)}", styles["Normal"]))
    else:
        story.append(Paragraph("No incomplete tasks were recorded for this assessment.", styles["Normal"]))

    def page_footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(document.leftMargin, 20, str(report_data["assessment_id"])[:65])
        canvas.drawRightString(document.pagesize[0] - document.rightMargin, 20, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return output_path


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f7")]),
    ])


def generate_reports(state: dict, *, output_dir: Path) -> tuple[Path, Path]:
    assessment_id = state["assessment_id"]
    json_path = report_path(output_dir, assessment_id, "json")
    pdf_path = report_path(output_dir, assessment_id, "pdf")
    report_data = _build_report_data(state)
    output_dir = json_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    # Finish both artifacts before publishing either. Each replacement is atomic;
    # no partial PDF/JSON is served if rendering fails. This is not a two-file DB transaction.
    with tempfile.TemporaryDirectory(prefix=".report-build-", dir=output_dir) as temporary:
        staged_json = Path(temporary) / json_path.name
        staged_pdf = Path(temporary) / pdf_path.name
        write_json_report(report_data, staged_json)
        write_pdf_report(report_data, staged_pdf)
        os.replace(staged_pdf, pdf_path)
        os.replace(staged_json, json_path)

    return json_path, pdf_path
