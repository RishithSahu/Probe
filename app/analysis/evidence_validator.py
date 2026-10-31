"""Evidence validation and finding-status promotion.

Runs centrally in the Orchestrator (`aggregate_findings` / `validate_evidence`
nodes) over the combined output of all three agents, so the same promotion
policy applies regardless of which agent produced a finding. This module
never invents evidence and never promotes a finding to `confirmed` on
anything less than the explicit rules below — the PRD's core requirement
("a scanner alert must not automatically be considered confirmed") is
enforced here, once, for the whole system.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.exceptions import EvidenceValidationError
from app.core.schemas import Confidence, Evidence, Finding, FindingStatus

# Detection methods that are considered reliable enough, on their own
# evidence, to promote `suspected` -> `confirmed` without a separate human
# verification step. Deliberately short: these are deterministic,
# low-false-positive checks (e.g. "the header is absent" is a verifiable
# fact, not a scanner heuristic). Everything else — ZAP alerts (active or
# passive), Ghidra-derived weakness heuristics, and all external Network
# Vulnerability Agent findings — stays `suspected` until a human explicitly
# confirms/rejects it via `promote_finding` below.
_AUTO_CONFIRM_DETECTION_METHODS = {
    "httpx_header_analysis",
    "httpx_cookie_analysis",
}


@dataclass
class ValidationReport:
    total_findings: int = 0
    valid: list[Finding] = field(default_factory=list)
    invalid: list[tuple[Finding, str]] = field(default_factory=list)
    auto_confirmed: list[str] = field(default_factory=list)  # finding_ids
    incomplete_evidence: list[str] = field(default_factory=list)  # finding_ids


def validate_schema_and_evidence_refs(
    findings: list[Finding], evidence: list[Evidence]
) -> ValidationReport:
    """Checks that:
    1. Every finding's `evidence_refs` actually resolve to a supplied Evidence
       object (never a dangling reference).
    2. A finding claiming `status=confirmed` already has at least one
       evidence reference (can't be confirmed with zero evidence).
    3. A finding with incomplete evidence (fewer refs than its
       detection_method would be expected to produce) is flagged, not
       silently passed.
    """
    evidence_ids = {e.evidence_id for e in evidence}
    report = ValidationReport(total_findings=len(findings))

    for finding in findings:
        missing_refs = [ref for ref in finding.evidence_refs if ref not in evidence_ids]
        if missing_refs:
            report.invalid.append((finding, f"evidence_refs reference missing evidence: {missing_refs}"))
            continue
        if finding.status == FindingStatus.CONFIRMED and not finding.evidence_refs:
            report.invalid.append((finding, "status=confirmed but no evidence_refs present"))
            continue
        if not finding.evidence_refs:
            report.incomplete_evidence.append(finding.finding_id)
        report.valid.append(finding)

    return report


def promote_finding(
    finding: Finding, *, new_status: FindingStatus, reviewer_note: str | None = None
) -> Finding:
    """The only sanctioned way to move a finding between suspected/confirmed/
    rejected once it has left the agent that produced it. Takes an explicit
    `new_status` rather than inferring one, so promotion is always a
    deliberate decision (by a human reviewer, or by `auto_confirm_eligible`
    below for the narrow, deterministic cases that qualify) and is
    traceable via `reviewer_note`.
    """
    updated = finding.model_copy(
        update={
            "status": new_status,
            "verification_required": new_status == FindingStatus.SUSPECTED,
        }
    )
    if reviewer_note:
        updated.description = f"{updated.description}\n\n[Verification note] {reviewer_note}"
    return updated


def auto_confirm_eligible(findings: list[Finding]) -> list[Finding]:
    """Applies the narrow, deterministic auto-confirmation policy and returns
    the (possibly) updated list. Only findings whose `detection_method` is in
    `_AUTO_CONFIRM_DETECTION_METHODS` AND carry high confidence are promoted;
    everything else is returned unchanged (still `suspected`)."""
    result = []
    for f in findings:
        if (
            f.status == FindingStatus.SUSPECTED
            and f.detection_method in _AUTO_CONFIRM_DETECTION_METHODS
            and f.confidence == Confidence.HIGH
            and f.evidence_refs
        ):
            result.append(promote_finding(f, new_status=FindingStatus.CONFIRMED, reviewer_note="auto-confirmed: deterministic header/cookie check"))
        else:
            result.append(f)
    return result


def run_evidence_validation(findings: list[Finding], evidence: list[Evidence]) -> tuple[list[Finding], ValidationReport]:
    """Full pipeline: schema/reference validation, then the conservative
    auto-confirmation pass. Raises `EvidenceValidationError` only if ALL
    findings are invalid (a sign of a systemic upstream bug) — a partial
    batch of invalid findings is reported, not fatal, so one bad finding
    doesn't block the whole assessment's report."""
    report = validate_schema_and_evidence_refs(findings, evidence)
    if findings and not report.valid:
        raise EvidenceValidationError("all findings failed evidence validation")

    promoted = auto_confirm_eligible(report.valid)
    # auto_confirmed must mean "this pass promoted it" — not merely "its
    # status happens to be CONFIRMED now". Every producer starts a finding
    # `suspected`, so this distinction has no effect today, but comparing
    # before/after status (rather than just checking the after-state) keeps
    # this report field honest if that assumption ever stops holding (e.g. a
    # future caller re-running validation over already-reviewed findings).
    before_by_id = {f.finding_id: f.status for f in report.valid}
    report.auto_confirmed = [
        f.finding_id for f in promoted
        if f.status == FindingStatus.CONFIRMED and before_by_id.get(f.finding_id) != FindingStatus.CONFIRMED
    ]
    return promoted, report
