"""Consolidated report generation: JSON (machine-readable, full fidelity) and
PDF (human-readable, via ReportLab) from the same underlying data — built
from the Orchestrator's final `OrchestratorState`, never recomputed from
scratch, so both artifacts describe exactly what this run actually did.

Narrative text sections (executive summary, methodology) are rendered via
Jinja2 templates in `templates/` so their wording can be edited without
touching the PDF layout code.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
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
    Table,
    TableStyle,
)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(disabled_extensions=("txt.j2",)),
    trim_blocks=True,
)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
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

    findings_by_status = Counter(f.status.value for f in findings)
    findings_by_severity = Counter(f.severity.value for f in findings)
    findings_by_surface: dict[str, list[dict]] = {"network": [], "web": [], "binary": []}
    for f in findings:
        findings_by_surface.setdefault(f.surface.value, []).append(_finding_dict(f))

    incomplete_tasks = []
    for result_key, label in (
        ("web_agent_result", "Web Security Agent"),
        ("binary_agent_result", "Binary Analysis Agent"),
        ("network_vulnerability_result", "Network Vulnerability Detective"),
    ):
        result = state.get(result_key)
        if result is not None and result.errors:
            incomplete_tasks.append(f"{label}: {'; '.join(result.errors)}")
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
    for result_key in ("web_agent_result", "binary_agent_result", "network_vulnerability_result"):
        result = state.get(result_key)
        if result is None:
            continue
        for te in result.tool_executions:
            if te.get("used_fixture"):
                fixture_tools_used.add(te.get("tool", "unknown"))
    fixture_tools_used = sorted(fixture_tools_used)

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
    )
    methodology = _jinja_env.get_template("methodology.txt.j2").render(
        crawling_enabled=policy_dict.get("allow_web_crawling", False),
        active_scan_enabled=policy_dict.get("allow_active_web_verification", False),
    )

    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
        "attack_paths": attack_path_edges,
        "ptes_mapping": ptes_summary,
        "incomplete_tasks_and_limitations": incomplete_tasks,
        # See the fixture_tools_used comment above `exec_summary` — this is
        # the authoritative, machine-readable form of that warning. A
        # non-empty list means at least one tool's findings in this report
        # are synthetic fixture data, not real scan results.
        "data_integrity": {
            "fixture_tools_used": fixture_tools_used,
            "contains_synthetic_data": bool(fixture_tools_used),
        },
    }


def write_json_report(report_data: dict[str, Any], output_path: Path) -> Path:
    output_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    return output_path


def _severity_badge_style(severity: str) -> ParagraphStyle:
    styles = getSampleStyleSheet()
    return ParagraphStyle(
        f"severity_{severity}", parent=styles["Normal"], textColor=colors.white,
        backColor=_SEVERITY_COLORS.get(severity, colors.grey), alignment=1,
    )


def write_pdf_report(report_data: dict[str, Any], output_path: Path) -> Path:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    story = []

    story.append(Paragraph("Autonomous Security Assessment Report", styles["Title"]))
    story.append(Paragraph(f"Assessment {report_data['assessment_id']} &middot; Scope {report_data['scope_id']}", styles["Normal"]))
    story.append(Paragraph(f"Generated {report_data['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    fixture_tools = report_data.get("data_integrity", {}).get("fixture_tools_used", [])
    if fixture_tools:
        warning_style = ParagraphStyle(
            "data_integrity_warning", parent=styles["Normal"], textColor=colors.white,
            backColor=colors.HexColor("#b91c1c"), borderPadding=8, leading=14,
        )
        story.append(Paragraph(
            f"<b>DATA INTEGRITY WARNING</b> &mdash; this report contains SYNTHETIC/FIXTURE data from: "
            f"<b>{', '.join(fixture_tools)}</b>. These tool(s) were unavailable during this run; their "
            "findings are documented placeholders, not real scan results, and must not be acted on as such.",
            warning_style,
        ))
        story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    for para in report_data["executive_summary"].split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))

    story.append(Paragraph("Assessment Scope", styles["Heading1"]))
    policy = report_data["authorised_scope"]
    scope_rows = [["Permission", "Enabled"]] + [
        [k, "Yes" if v else "No"] for k, v in policy.items() if isinstance(v, bool)
    ]
    story.append(Table(scope_rows, style=_table_style()))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Methodology", styles["Heading1"]))
    for para in report_data["methodology"].split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))

    story.append(PageBreak())
    story.append(Paragraph("Findings Summary", styles["Heading1"]))
    summary = report_data["findings_summary"]
    story.append(Paragraph(f"Total findings: {summary['total']}", styles["Normal"]))
    status_rows = [["Status", "Count"]] + [[k, str(v)] for k, v in summary["by_status"].items()]
    story.append(Table(status_rows, style=_table_style()))
    story.append(Spacer(1, 0.3 * cm))
    severity_rows = [["Severity", "Count"]] + [
        [sev, str(summary["by_severity"].get(sev, 0))] for sev in _SEVERITY_ORDER if summary["by_severity"].get(sev, 0)
    ]
    story.append(Table(severity_rows, style=_table_style()))

    for surface_label, surface_key in (("Network Findings", "network"), ("Web Security Findings", "web"), ("Binary Analysis Findings", "binary")):
        findings = report_data["findings_by_surface"].get(surface_key, [])
        story.append(PageBreak())
        story.append(Paragraph(surface_label, styles["Heading1"]))
        if not findings:
            story.append(Paragraph("No findings for this surface.", styles["Normal"]))
            continue
        for f in findings:
            story.append(Paragraph(f"{f['title']}  [{f['severity'].upper()} / {f['status'].upper()}]", styles["Heading3"]))
            story.append(Paragraph(f"Agent: {f['agent_id']} &middot; Detection: {f.get('detection_method') or 'n/a'}", styles["Normal"]))
            story.append(Paragraph(f.get("description", ""), styles["Normal"]))
            if f.get("remediation"):
                story.append(Paragraph(f"Remediation: {f['remediation']}", styles["Normal"]))
            story.append(Paragraph(f"PTES phase: {f.get('ptes_phase', 'n/a')} &middot; Evidence: {', '.join(f.get('evidence_refs', [])) or 'none'}", styles["Normal"]))
            story.append(Spacer(1, 0.3 * cm))

    story.append(PageBreak())
    story.append(Paragraph("PTES Mapping", styles["Heading1"]))
    ptes = report_data.get("ptes_mapping", {})
    ptes_rows = [["Phase", "Activities", "Findings"]]
    for phase in set(list(ptes.get("phase_activity_counts", {}).keys()) + list(ptes.get("phase_finding_counts", {}).keys())):
        ptes_rows.append([
            phase,
            str(ptes.get("phase_activity_counts", {}).get(phase, 0)),
            str(ptes.get("phase_finding_counts", {}).get(phase, 0)),
        ])
    story.append(Table(ptes_rows, style=_table_style()))

    story.append(PageBreak())
    story.append(Paragraph("Incomplete Tasks and Limitations", styles["Heading1"]))
    limitations = report_data.get("incomplete_tasks_and_limitations", [])
    if limitations:
        for item in limitations:
            story.append(Paragraph(f"&bull; {item}", styles["Normal"]))
    else:
        story.append(Paragraph("No incomplete tasks were recorded for this assessment.", styles["Normal"]))

    doc.build(story)
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
    report_data = _build_report_data(state)

    json_path = output_dir / f"{assessment_id}_report.json"
    pdf_path = output_dir / f"{assessment_id}_report.pdf"

    write_json_report(report_data, json_path)
    write_pdf_report(report_data, pdf_path)

    return json_path, pdf_path
