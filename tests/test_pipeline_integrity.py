"""Offline regressions for evidence ownership and unsupported attack paths."""
from __future__ import annotations

import pytest

from app.analysis.attack_paths import build_attack_path_graph
from app.analysis.evidence_validator import (
    auto_confirm_eligible,
    run_evidence_validation,
    validate_schema_and_evidence_refs,
)
from app.core.schemas import (
    AgentId, Confidence, Evidence, Finding, FindingStatus, NetworkGraph,
    NetworkGraphAssetRecord, NetworkGraphEdgeRecord, Severity, Surface,
)


def finding(**overrides):
    fields = dict(
        finding_id="F-1", assessment_id="A-1", agent_id=AgentId.WEB_SECURITY,
        surface=Surface.WEB, asset_id="HOST-A", title="Missing header",
        description="Observed response", severity=Severity.LOW,
        confidence=Confidence.HIGH, evidence_refs=["E-1"],
        detection_method="httpx_header_analysis",
        # Required by evidence_validator._supports_deterministic_check's own replay check (recheck the
        # observation instead of trusting a method label alone) -- data.get("url") must equal this, and
        # a bare "no affected_url at all" is unconditionally rejected. Added when these fixtures predated
        # that tightening; kept here instead of weakening the validator for the test's convenience.
        affected_url="http://host-a/",
    )
    fields.update(overrides)
    return Finding(**fields)


def observation(**overrides):
    fields = dict(
        evidence_id="E-1", finding_id="F-1", evidence_type="http_response",
        source_tool="httpx", description="Observed headers",
        raw_data={"headers": {}, "missing": ["x-frame-options"], "url": "http://host-a/", "status_code": 200},
    )
    fields.update(overrides)
    return Evidence(**fields)


def topology():
    return NetworkGraph(
        scope_id="S-1",
        assets=[NetworkGraphAssetRecord(asset_id=name) for name in ("HOST-A", "HOST-B")],
        edges=[NetworkGraphEdgeRecord(source="HOST-A", target="HOST-B")],
    )


@pytest.mark.parametrize("status", [FindingStatus.SUSPECTED, FindingStatus.CONFIRMED])
def test_foreign_evidence_cannot_support_a_finding(status):
    report = validate_schema_and_evidence_refs(
        [finding(status=status)], [observation(finding_id="OTHER-FINDING")],
    )
    assert not report.valid
    assert "another finding" in report.invalid[0][1]


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_evidence_ids_fail_closed_independent_of_order(reverse):
    records = [observation(), observation(finding_id="OTHER-FINDING")]
    report = validate_schema_and_evidence_refs([finding()], records[::-1] if reverse else records)
    assert not report.valid
    assert "conflicting evidence" in report.invalid[0][1]


def test_repeated_identical_evidence_is_safe_to_replay():
    item = observation()
    promoted, report = run_evidence_validation([finding()], [item, item.model_copy()])
    assert promoted[0].status == FindingStatus.CONFIRMED
    assert report.auto_confirmed == ["F-1"]


def test_description_only_placeholder_remains_incomplete_and_unconfirmed():
    promoted, report = run_evidence_validation([finding()], [observation(raw_data=None)])
    assert promoted[0].status == FindingStatus.SUSPECTED
    assert report.incomplete_evidence == ["F-1"]
    assert report.auto_confirmed == []


def test_description_only_evidence_cannot_arrive_already_confirmed():
    report = validate_schema_and_evidence_refs(
        [finding(status=FindingStatus.CONFIRMED)], [observation(raw_data={})],
    )
    assert not report.valid
    assert "no observation" in report.invalid[0][1]


def test_direct_promotion_without_supplied_evidence_does_not_confirm():
    assert auto_confirm_eligible([finding()])[0].status == FindingStatus.SUSPECTED


@pytest.mark.parametrize("overrides", [
    {"raw_data": {"unrelated": "some data"}},
    {"raw_data": {"headers": {"X-Frame-Options": "DENY"}, "missing": ["x-frame-options"]}},
    {"raw_data": {"headers": {}, "missing": ["x-frame-options"], "used_fixture": True}},
    {"source_tool": "unknown_scanner"},
])
def test_method_label_cannot_auto_confirm_unrelated_or_contradictory_data(overrides):
    validated, report = run_evidence_validation([finding()], [observation(**overrides)])
    assert validated[0].status == FindingStatus.SUSPECTED
    assert report.auto_confirmed == []


@pytest.mark.parametrize("data, expected", [
    ({"name": "session", "secure": False, "httponly": True}, FindingStatus.CONFIRMED),
    ({"name": "session", "secure": True, "httponly": True}, FindingStatus.SUSPECTED),
    ({"name": "session"}, FindingStatus.SUSPECTED),
])
def test_cookie_promotion_requires_observed_insecure_flags(data, expected):
    # The common replay check (url/status_code matching the finding) applies before any method-specific
    # branch -- these need it too, same as the header test's observation() default.
    validated, _ = run_evidence_validation(
        [finding(detection_method="httpx_cookie_analysis")],
        [observation(raw_data={**data, "url": "http://host-a/", "status_code": 200})],
    )
    assert validated[0].status == expected


def test_one_bad_finding_does_not_discard_other_owned_observations():
    valid, report = run_evidence_validation(
        [finding(), finding(finding_id="F-2")], [observation()],
    )
    assert [f.finding_id for f in valid] == ["F-1"]
    assert report.invalid[0][0].finding_id == "F-2"


def test_confirmed_header_and_connectivity_do_not_prove_access():
    validated, _ = run_evidence_validation([finding()], [observation()])
    result = build_attack_path_graph(topology(), validated)
    records = result.to_edge_dicts()
    assert any(e["relation"] == "AFFECTED_BY" and e["evidence_backed"] for e in records)
    assert any(e["relation"] == "CONNECTS_TO" and not e["evidence_backed"] for e in records)
    assert not any(e["relation"] == "VERIFIED_TRANSITION" for e in records)
    assert not result.graph.has_edge("finding:F-1", "HOST-B")
    assert not result.verified_transition_subgraph().has_edge("HOST-A", "HOST-B")


def test_rejected_findings_cannot_form_potential_attack_steps():
    result = build_attack_path_graph(topology(), [finding(status=FindingStatus.REJECTED)])
    assert "finding:F-1" not in result.graph
    assert result.potential_paths_to("HOST-B") == [["HOST-A", "HOST-B"]]


def test_confirmed_without_refs_is_not_an_evidence_backed_graph_edge():
    result = build_attack_path_graph(
        topology(), [finding(status=FindingStatus.CONFIRMED, evidence_refs=[])],
    )
    assert not any(edge.evidence_backed for edge in result.edges)


def test_binary_candidate_does_not_prove_network_access():
    candidate = finding(
        agent_id=AgentId.BINARY_ANALYSIS, surface=Surface.BINARY,
        asset_id=None, binary_id="BIN-1", detection_method="static_analysis",
        status=FindingStatus.CONFIRMED,
    )
    result = build_attack_path_graph(topology(), [candidate])
    assert result.graph.has_edge("BIN-1", "finding:F-1")
    assert not result.graph.has_edge("finding:F-1", "HOST-A")
    assert not any(edge.relation == "VERIFIED_TRANSITION" for edge in result.edges)


def test_actual_web_findings_pass_validation_and_reporting_without_access_claims():
    from app.agents.web_security.findings import findings_from_fingerprint
    from app.agents.web_security.fingerprint import FingerprintResult
    from app.core.schemas import AssessmentPolicy
    from app.reporting.generator import _build_report_data

    # Recorded observation only: this test makes no HTTP request.
    raw = FingerprintResult(
        url="http://example.invalid/", final_url="http://example.invalid/",
        status_code=200, headers={"server": "test-server"},
        cookies=[{"name": "session", "secure": False, "httponly": True}],
    )
    findings, evidence = findings_from_fingerprint(raw, assessment_id="A-1", asset_id="HOST-A")
    validated, validation = run_evidence_validation(findings, evidence)
    assert len(validated) == 2
    assert all(item.status == FindingStatus.CONFIRMED for item in validated)
    assert not validation.invalid
    paths = build_attack_path_graph(topology(), validated)
    report = _build_report_data({
        "assessment_id": "A-1", "scope_id": "S-1", "policy": AssessmentPolicy(),
        "network_graph": topology(), "validated_findings": validated,
        "all_evidence": evidence, "attack_path_edges": paths.to_edge_dicts(),
    })
    assert report["findings_summary"]["by_status"] == {"confirmed": 2}
    assert not any(edge["relation"] == "VERIFIED_TRANSITION" for edge in report["attack_paths"])
