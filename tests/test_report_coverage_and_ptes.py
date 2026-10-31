"""Offline checks for truthful coverage and all-branch activity reporting."""
from __future__ import annotations

import json

import pytest
from pypdf import PdfReader

from app.analysis.ptes_mapper import summarise_activities
from app.core.schemas import AgentId, AgentResult, PtesPhase, TaskStatus
from app.reporting.completeness import assessment_coverage
from app.reporting.generator import _build_report_data, generate_reports
from tests.test_reporting import _minimal_state


def result(agent=AgentId.BINARY_ANALYSIS, status=TaskStatus.COMPLETED, **kwargs):
    return AgentResult(agent_id=agent, assessment_id="A-1", execution_status=status, **kwargs)


def completed_state():
    return _minimal_state(
        web_agent_result=result(AgentId.WEB_SECURITY),
        binary_agent_result=result(),
        network_vulnerability_result=result(AgentId.NETWORK_VULNERABILITY_DETECTIVE),
        discovery_report={"converged": True},
    )


def test_all_skipped_is_incomplete_even_when_process_says_completed():
    state = completed_state()
    state["assessment_status"] = "completed"
    for key in ("web_agent_result", "binary_agent_result", "network_vulnerability_result"):
        state[key].execution_status = TaskStatus.SKIPPED
    coverage = assessment_coverage(state)
    assert coverage["execution_status"] == "completed"
    assert coverage["overall"] == "incomplete"
    assert set(coverage["missing_or_incomplete_surfaces"]) == {"web", "binary", "network"}


def test_no_findings_can_still_mean_complete_surface_execution():
    assert assessment_coverage(completed_state())["overall"] == "complete"


def test_discovery_completeness_cannot_be_inferred_from_a_finished_task():
    state = completed_state()
    state.pop("discovery_report")
    assert assessment_coverage(state)["overall"] == "unknown"


def test_discovered_binary_can_satisfy_binary_surface_when_supplied_path_skipped():
    state = completed_state()
    state["binary_agent_result"] = result(status=TaskStatus.SKIPPED)
    state["triggered_binary_agent_result"] = result()
    assert assessment_coverage(state)["surfaces"]["binary"]["status"] == "completed"


@pytest.mark.parametrize("flag", ["truncated", "incomplete", "timed_out"])
def test_limited_tool_results_are_not_complete(flag):
    state = completed_state()
    state["triggered_binary_agent_result"] = result(tool_executions=[{"tool": "binary_analysis_agent", flag: True}])
    assert assessment_coverage(state)["overall"] == "incomplete"


def test_fixture_results_do_not_establish_real_coverage():
    state = completed_state()
    state["binary_agent_result"] = result(tool_executions=[{"tool": "ghidra", "used_fixture": True}])
    assert assessment_coverage(state)["surfaces"]["binary"]["status"] == "synthetic"
    assert assessment_coverage(state)["overall"] == "incomplete"


def test_legacy_operations_are_explicitly_marked_and_unknown_ones_remain_unknown():
    summary = summarise_activities([
        {"tool": "httpx"}, {"tool": "katana"}, {"tool": "unrecognised"},
        {"tool": "httpx", "operation": "unknown-operation"},
    ], []).to_dict()
    assert summary["phase_activity_counts"][PtesPhase.INTELLIGENCE_GATHERING.value] == 2
    assert summary["inferred_operations"] == [("httpx", "fingerprint"), ("katana", "crawl")]
    assert summary["unmapped_activities"] == [("unrecognised", ""), ("httpx", "unknown-operation")]


def test_failed_or_denied_actions_do_not_count_as_successful_exploitation():
    summary = summarise_activities([
        {"tool": "zap_active", "ran": False},
        {"tool": "zap_active", "allowed": False},
        {"tool": "zap_active", "error": "local test failure"},
    ], []).to_dict()
    assert PtesPhase.EXPLOITATION.value not in summary["phase_activity_counts"]
    assert summary["failed_activity_counts"][PtesPhase.EXPLOITATION.value] == 1
    assert len(summary["skipped_activities"]) == 2


def test_report_collects_handoff_activities_even_if_state_summary_is_stale():
    state = _minimal_state(
        ptes_summary={"phase_activity_counts": {}},
        triggered_binary_agent_result=result(tool_executions=[
            {"tool": "binary_analysis_agent", "op": "acquire"},
            {"tool": "binary_analysis_agent", "op": "static_analysis"},
        ]),
    )
    report = _build_report_data(state)
    assert report["ptes_mapping"]["phase_activity_counts"]["intelligence_gathering"] == 1
    assert report["ptes_mapping"]["phase_activity_counts"]["vulnerability_analysis"] == 1
    assert state["ptes_summary"]["phase_activity_counts"] == {}


def test_future_agent_branch_cannot_hide_fixture_or_execution_failures():
    state = _minimal_state(additional_agent_result=result(
        status=TaskStatus.FAILED, errors=["Unavailable tool"],
        tool_executions=[{"tool": "future-tool", "used_fixture": True}],
    ))
    report = _build_report_data(state)
    assert report["data_integrity"]["contains_synthetic_data"]
    assert report["agent_execution_summary"]["additional_agent_result"]["status"] == "failed"
    assert ("future-tool", "") in report["ptes_mapping"]["unmapped_activities"]


def test_pdf_includes_inventory_path_evidence_and_literal_untrusted_text(tmp_path):
    from app.core.schemas import NetworkGraph, NetworkGraphAssetRecord, NetworkGraphServiceRecord

    graph = NetworkGraph(scope_id="SCOPE-TEST", assets=[NetworkGraphAssetRecord(
        asset_id="HOST-<untrusted>&literal", ip="10.20.30.10", services=[NetworkGraphServiceRecord(
            service_id="SERVICE-TEST", asset_id="HOST-<untrusted>&literal", port=8080, service_name="http",
        )],
    )])
    state = _minimal_state(network_graph=graph, attack_path_edges=[{
        "source": "HOST-<untrusted>&literal", "target": "SERVICE-TEST", "relation": "HOSTS",
        "evidence_backed": False, "finding_id": None,
    }])
    json_path, pdf_path = generate_reports(state, output_dir=tmp_path)
    body = "\n".join(page.extract_text() for page in PdfReader(pdf_path).pages)
    for expected in ("Device and Service Inventory", "Attack Paths and Observed Relationships", "Evidence Index", "Coverage and Completion", "SERVICE-TEST", "HOST-<untrusted>&literal"):
        assert expected in body
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["assessment_coverage"]["overall"] == "incomplete"
    assert data["attack_paths"][0]["evidence_backed"] is False
