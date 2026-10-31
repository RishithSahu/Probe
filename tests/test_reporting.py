"""Tests for app/reporting/generator.py.

Primary focus: the data-integrity warning (fixture vs real tool output).
Fundamental gap found during review — when a real tool (Katana/ZAP/Ghidra)
is unavailable, its agent silently substitutes documented synthetic fixture
data so demos/dev keep working, but that substitution was never surfaced in
the final report. A reader had no way to tell a fixture-generated finding
from a real one. Fixed by computing `fixture_tools_used` from
`AgentResult.tool_executions` and surfacing it as an explicit, unmissable
section in both the JSON report and the PDF (a red warning banner).
"""
from __future__ import annotations

import json

from app.core.schemas import AgentId, AgentResult, AssessmentPolicy, TaskStatus
from app.reporting.generator import _build_report_data, generate_reports


def _minimal_state(**overrides) -> dict:
    state = {
        "assessment_id": "ASSESSMENT-REPORT-TEST",
        "scope_id": "SCOPE-TEST",
        "policy": AssessmentPolicy(),
        "network_graph": None,
        "validated_findings": [],
        "all_evidence": [],
        "validation_report": {},
        "attack_path_edges": [],
        "ptes_summary": {},
        "web_agent_result": None,
        "binary_agent_result": None,
        "network_agent_findings": [],
        "binary_paths": [],
    }
    state.update(overrides)
    return state


def test_no_warning_when_no_tool_used_a_fixture():
    web_result = AgentResult(
        agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED,
        tool_executions=[{"tool": "httpx", "target": "http://x", "error": None}],
    )
    report = _build_report_data(_minimal_state(web_agent_result=web_result))
    assert report["data_integrity"]["contains_synthetic_data"] is False
    assert report["data_integrity"]["fixture_tools_used"] == []
    assert "DATA INTEGRITY WARNING" not in report["executive_summary"]


def test_warning_present_when_katana_used_fixture():
    web_result = AgentResult(
        agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED,
        tool_executions=[
            {"tool": "httpx", "target": "http://x", "error": None},
            {"tool": "katana", "target": "http://x", "used_fixture": True, "endpoint_count": 4},
        ],
    )
    report = _build_report_data(_minimal_state(web_agent_result=web_result))
    assert report["data_integrity"]["contains_synthetic_data"] is True
    assert report["data_integrity"]["fixture_tools_used"] == ["katana"]
    assert "DATA INTEGRITY WARNING" in report["executive_summary"]
    assert "katana" in report["executive_summary"]


def test_warning_lists_multiple_fixture_tools_from_both_agents():
    web_result = AgentResult(
        agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED,
        tool_executions=[{"tool": "zap_passive", "target": "http://x", "used_fixture": True}],
    )
    binary_result = AgentResult(
        agent_id=AgentId.BINARY_ANALYSIS, assessment_id="X", execution_status=TaskStatus.COMPLETED,
        tool_executions=[{"tool": "ghidra", "target": "bin", "used_fixture": True, "function_count": 3}],
    )
    report = _build_report_data(_minimal_state(web_agent_result=web_result, binary_agent_result=binary_result))
    assert report["data_integrity"]["fixture_tools_used"] == ["ghidra", "zap_passive"]


def test_pdf_and_json_both_generated_with_warning(tmp_path):
    web_result = AgentResult(
        agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED,
        tool_executions=[{"tool": "zap_passive", "target": "http://x", "used_fixture": True}],
    )
    state = _minimal_state(web_agent_result=web_result)
    json_path, pdf_path = generate_reports(state, output_dir=tmp_path)

    assert json_path.exists()
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["data_integrity"]["contains_synthetic_data"] is True
    assert data["data_integrity"]["fixture_tools_used"] == ["zap_passive"]


def test_discovered_binary_branch_errors_and_fixture_use_are_visible():
    result = AgentResult(
        agent_id=AgentId.BINARY_ANALYSIS, assessment_id="X", execution_status=TaskStatus.FAILED,
        errors=["Static analysis tool unavailable"],
        tool_executions=[{"tool": "ghidra", "used_fixture": True}],
    )
    report = _build_report_data(_minimal_state(triggered_binary_agent_result=result))
    assert report["data_integrity"]["fixture_tools_used"] == ["ghidra"]
    assert any("Static analysis tool unavailable" in item for item in report["incomplete_tasks_and_limitations"])
    assert report["agent_execution_summary"]["triggered_binary_agent_result"]["status"] == "failed"


def test_skipped_agent_cannot_disappear_from_report_when_errors_are_empty():
    result = AgentResult(
        agent_id=AgentId.BINARY_ANALYSIS, assessment_id="X", execution_status=TaskStatus.SKIPPED,
    )
    report = _build_report_data(_minimal_state(triggered_binary_agent_result=result))
    assert any("execution status skipped" in item for item in report["incomplete_tasks_and_limitations"])


def test_report_surfaces_rejected_and_incomplete_evidence_counts():
    report = _build_report_data(_minimal_state(
        validation_report={"invalid_count": 2, "incomplete_evidence": ["F-1"]},
    ))
    limitations = report["incomplete_tasks_and_limitations"]
    assert any("rejected 2 finding(s)" in item for item in limitations)
    assert any("incomplete for 1 finding(s)" in item for item in limitations)
