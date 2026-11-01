"""Tests for app/analysis/evidence_validator.py — the single place that is
allowed to promote a finding's status. No prior test file covered this
module despite it enforcing the system's core "a scanner alert is never
automatically confirmed" guarantee.
"""
from __future__ import annotations

import pytest

from app.analysis.evidence_validator import (
    auto_confirm_eligible,
    run_evidence_validation,
    validate_schema_and_evidence_refs,
)
from app.core.exceptions import EvidenceValidationError
from app.core.schemas import (
    AgentId,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    PtesPhase,
    Severity,
    Surface,
)


def _finding(**overrides) -> Finding:
    defaults = dict(
        finding_id="WEB-001",
        assessment_id="ASSESSMENT-001",
        agent_id=AgentId.WEB_SECURITY,
        surface=Surface.WEB,
        asset_id="HOST-001",
        title="Test finding",
        description="Test",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        status=FindingStatus.SUSPECTED,
        evidence_refs=[],
        ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
        affected_url="http://example.test/",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _evidence(evidence_id: str, finding_id: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id, finding_id=finding_id, evidence_type="http_response",
        source_tool="httpx", description="test evidence",
        raw_data={"headers": {}, "missing": ["x-frame-options"], "url": "http://example.test/", "status_code": 200},
    )


def test_dangling_evidence_ref_is_rejected():
    f = _finding(evidence_refs=["EVIDENCE-MISSING"])
    report = validate_schema_and_evidence_refs([f], [])
    assert report.valid == []
    assert len(report.invalid) == 1
    assert "missing evidence" in report.invalid[0][1]


def test_confirmed_with_no_evidence_is_rejected():
    f = _finding(status=FindingStatus.CONFIRMED, evidence_refs=[])
    report = validate_schema_and_evidence_refs([f], [])
    assert report.valid == []
    assert "no evidence_refs" in report.invalid[0][1]


def test_valid_finding_with_resolved_evidence_passes():
    f = _finding(evidence_refs=["EVIDENCE-001"])
    e = _evidence("EVIDENCE-001", "WEB-001")
    report = validate_schema_and_evidence_refs([f], [e])
    assert report.valid == [f]
    assert report.invalid == []


def test_finding_with_no_evidence_refs_flagged_incomplete_but_still_valid():
    f = _finding(evidence_refs=[])
    report = validate_schema_and_evidence_refs([f], [])
    assert report.valid == [f]
    assert report.incomplete_evidence == ["WEB-001"]


def test_auto_confirm_requires_all_three_conditions():
    # Promotion also requires a supplied observation owned by the finding.

    # Right detection_method + HIGH confidence + has evidence -> promoted.
    eligible = _finding(detection_method="httpx_header_analysis", confidence=Confidence.HIGH, evidence_refs=["EVIDENCE-001"])
    # Right detection_method but only MEDIUM confidence -> stays suspected.
    low_confidence = _finding(finding_id="WEB-002", detection_method="httpx_header_analysis", confidence=Confidence.MEDIUM, evidence_refs=["EVIDENCE-001"])
    # HIGH confidence but a scanner-derived (not deterministic) detection method -> stays suspected.
    scanner_derived = _finding(finding_id="WEB-003", detection_method="zap_passive_scan", confidence=Confidence.HIGH, evidence_refs=["EVIDENCE-001"])
    # Eligible detection method + HIGH confidence but no evidence -> stays suspected.
    no_evidence = _finding(finding_id="WEB-004", detection_method="httpx_header_analysis", confidence=Confidence.HIGH, evidence_refs=[])

    result = auto_confirm_eligible(
        [eligible, low_confidence, scanner_derived, no_evidence],
        evidence=[_evidence("EVIDENCE-001", "WEB-001")],
    )
    statuses = {f.finding_id: f.status for f in result}
    assert statuses["WEB-001"] == FindingStatus.CONFIRMED
    assert statuses["WEB-002"] == FindingStatus.SUSPECTED
    assert statuses["WEB-003"] == FindingStatus.SUSPECTED
    assert statuses["WEB-004"] == FindingStatus.SUSPECTED


def test_run_evidence_validation_raises_when_everything_is_invalid():
    f = _finding(evidence_refs=["EVIDENCE-MISSING"])
    with pytest.raises(EvidenceValidationError):
        run_evidence_validation([f], [])


def test_run_evidence_validation_does_not_raise_on_empty_input():
    promoted, report = run_evidence_validation([], [])
    assert promoted == []
    assert report.total_findings == 0


def test_three_findings_from_one_batch_can_land_in_three_different_verification_states():
    """Item 7's core acceptance criterion: one task's findings must be able to carry three different
    verification outcomes -- a task-level status must never stand in for per-finding verification."""
    verified = _finding(
        finding_id="WEB-VERIFIED", detection_method="httpx_cookie_analysis",
        confidence=Confidence.HIGH, evidence_refs=["EVIDENCE-VERIFIED"],
    )
    ev_verified = _evidence("EVIDENCE-VERIFIED", "WEB-VERIFIED")
    ev_verified.raw_data = {"name": "session", "secure": False, "httponly": True, "url": "http://example.test/", "status_code": 200}

    unverified = _finding(finding_id="WEB-UNVERIFIED", confidence=Confidence.LOW, evidence_refs=["EVIDENCE-UNVERIFIED"])
    ev_unverified = _evidence("EVIDENCE-UNVERIFIED", "WEB-UNVERIFIED")

    inconclusive = _finding(finding_id="WEB-INCONCLUSIVE", evidence_refs=[])

    promoted, report = run_evidence_validation(
        [verified, unverified, inconclusive], [ev_verified, ev_unverified],
    )

    by_id = {f.finding_id: f for f in [verified, unverified, inconclusive]}
    assert by_id["WEB-VERIFIED"].verification_state == "verified"
    assert by_id["WEB-UNVERIFIED"].verification_state == "unverified"
    assert by_id["WEB-INCONCLUSIVE"].verification_state == "inconclusive"
    assert all(f.verifier == "evidence_validator@auto_confirm" for f in by_id.values())
    assert all(f.verified_at is not None for f in by_id.values())


def test_auto_confirmed_report_only_lists_findings_actually_promoted_this_pass():
    """Regression: `auto_confirmed` used to be derived from post-pass status
    alone (`status == CONFIRMED`), which would also count a finding that
    entered the pipeline ALREADY confirmed — mislabelling it as having been
    auto-confirmed by this run. Fixed to compare before/after status."""
    e1 = _evidence("EVIDENCE-001", "WEB-001")
    e1.raw_data = {"name": "session", "secure": False, "httponly": True, "url": "http://example.test/", "status_code": 200}
    e2 = _evidence("EVIDENCE-002", "WEB-002")

    newly_promoted = _finding(
        finding_id="WEB-001", detection_method="httpx_cookie_analysis",
        confidence=Confidence.HIGH, evidence_refs=["EVIDENCE-001"],
    )
    already_confirmed = _finding(
        finding_id="WEB-002", status=FindingStatus.CONFIRMED,
        detection_method="zap_passive_scan", evidence_refs=["EVIDENCE-002"],
    )

    promoted, report = run_evidence_validation([newly_promoted, already_confirmed], [e1, e2])
    assert report.auto_confirmed == ["WEB-001"]
    assert "WEB-002" not in report.auto_confirmed
