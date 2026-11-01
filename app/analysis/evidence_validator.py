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
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.analysis.protocol_verification import supports_protocol_observation
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
    "network_vulnerability:ssh_protocol_version",
    "network_vulnerability:redis_auth_check",
    "network_vulnerability:postgresql_auth_check",
    "network_vulnerability:ftp_anonymous_login",
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
    2. Referenced evidence belongs to the finding and has an unambiguous ID.
    3. A confirmed finding has recorded observation data or an artifact
       reference. Description-only records remain incomplete, not proof.

    This checks evidence integrity, not the truth of arbitrary raw data or
    the contents of a referenced artifact.
    """
    evidence_by_id: dict[str, Evidence] = {}
    conflicting_ids: set[str] = set()
    for item in evidence:
        previous = evidence_by_id.get(item.evidence_id)
        if previous is not None and previous != item:
            conflicting_ids.add(item.evidence_id)
        evidence_by_id[item.evidence_id] = item
    report = ValidationReport(total_findings=len(findings))

    for finding in findings:
        missing_refs = [ref for ref in finding.evidence_refs if ref not in evidence_by_id]
        if missing_refs:
            report.invalid.append((finding, f"evidence_refs reference missing evidence: {missing_refs}"))
            continue
        ambiguous_refs = [ref for ref in finding.evidence_refs if ref in conflicting_ids]
        if ambiguous_refs:
            report.invalid.append((finding, f"conflicting evidence records for IDs: {ambiguous_refs}"))
            continue
        foreign_refs = [
            ref for ref in finding.evidence_refs
            if evidence_by_id[ref].finding_id != finding.finding_id
        ]
        if foreign_refs:
            report.invalid.append((finding, f"evidence belongs to another finding: {foreign_refs}"))
            continue
        if finding.status == FindingStatus.CONFIRMED and not finding.evidence_refs:
            report.invalid.append((finding, "status=confirmed but no evidence_refs present"))
            continue
        has_observation = any(
            evidence_by_id[ref].raw_data or evidence_by_id[ref].storage_path
            for ref in finding.evidence_refs
        )
        if not has_observation and finding.status == FindingStatus.CONFIRMED:
            report.invalid.append((finding, "status=confirmed but evidence has no observation or artifact reference"))
            continue
        if not has_observation:
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


def auto_confirm_eligible(
    findings: list[Finding], *, evidence: list[Evidence] | None = None
) -> list[Finding]:
    """Applies the narrow, deterministic auto-confirmation policy and returns
    the (possibly) updated list. Only findings whose `detection_method` is in
    `_AUTO_CONFIRM_DETECTION_METHODS` AND carry high confidence are promoted.
    Evidence must also pass ownership/reference checks and contain an
    observation. Omitting evidence never promotes a finding. Invalid inputs
    are left unchanged here; the full pipeline filters them out."""
    validation = validate_schema_and_evidence_refs(findings, evidence or [])
    eligible_objects = {
        id(f) for f in validation.valid
        if f.finding_id not in validation.incomplete_evidence
    }
    observations = {item.evidence_id: item for item in evidence or []}
    result = []
    for f in findings:
        if (
            f.status == FindingStatus.SUSPECTED
            and f.detection_method in _AUTO_CONFIRM_DETECTION_METHODS
            and f.confidence == Confidence.HIGH
            and f.evidence_refs
            and id(f) in eligible_objects
            and any(_supports_deterministic_check(f, observations[ref]) for ref in f.evidence_refs)
        ):
            verified = promote_finding(f, new_status=FindingStatus.CONFIRMED, reviewer_note="auto-confirmed: deterministic observation replay")
            result.append(verified.model_copy(update={"verification_status": "verified"}))
        else:
            result.append(f)
    return result


def _supports_deterministic_check(finding: Finding, evidence: Evidence) -> bool:
    """Recheck the observation instead of trusting a method label alone."""
    data = evidence.raw_data or {}
    if (finding.detection_method or "").startswith("network_vulnerability:"):
        return supports_protocol_observation(finding, evidence)
    if evidence.source_tool != "httpx" or evidence.evidence_type != "http_response" or data.get("used_fixture"):
        return False
    if (not finding.affected_url or data.get("url") != finding.affected_url
            or type(data.get("status_code")) is not int or not 100 <= data["status_code"] <= 599):
        return False
    if finding.detection_method == "httpx_header_analysis":
        headers = data.get("headers")
        missing = data.get("missing")
        if not isinstance(headers, dict) or not isinstance(missing, list) or not missing:
            return False
        present = {str(name).lower() for name in headers}
        security_headers = {"content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options"}
        return all(isinstance(name, str) and name in security_headers and name not in present
                   and (name != "strict-transport-security" or urlsplit(finding.affected_url or "").scheme == "https") for name in missing)
    if finding.detection_method == "httpx_cookie_analysis":
        return (
            isinstance(data.get("name"), str) and bool(data["name"].strip())
            and isinstance(data.get("secure"), bool)
            and isinstance(data.get("httponly"), bool)
            and (not data["secure"] or not data["httponly"])
        )
    return False


_VERIFIER_IDENTITY = "evidence_validator@auto_confirm"


def _stamp_verification(findings: list[Finding], report: ValidationReport, auto_confirmed_ids: set[str]) -> None:
    """Per-finding verification (item 7): a task-level status must never stand in for this -- three
    findings from one task can land here with three different outcomes. Mutates each Finding in place
    (verification_state/verified_at/verifier/explanation) so the SAME object `store_findings` later
    persists already carries it; nothing here changes `status` (confirmed/suspected/rejected), which is a
    different question answered elsewhere (auto_confirm_eligible)."""
    now = datetime.now(timezone.utc)
    invalid_ids = {f.finding_id for f, _ in report.invalid}
    for f in findings:
        if f.finding_id in invalid_ids:
            reason = next((r for item, r in report.invalid if item.finding_id == f.finding_id), "invalid")
            f.verification_state, f.verification_explanation = "inconclusive", f"evidence validation failed: {reason}"
        elif f.finding_id in report.incomplete_evidence:
            f.verification_state, f.verification_explanation = "inconclusive", "evidence present but incomplete (no observation/artifact reference)"
        elif f.finding_id in auto_confirmed_ids:
            f.verification_state, f.verification_explanation = "verified", "auto-confirmed: high-confidence detection method with a complete, owned observation"
        else:
            f.verification_state, f.verification_explanation = "unverified", "evidence references check out but did not meet the auto-confirmation bar"
        f.verified_at, f.verifier = now, _VERIFIER_IDENTITY
        f.verification_evidence_refs = list(f.evidence_refs)


def run_evidence_validation(findings: list[Finding], evidence: list[Evidence]) -> tuple[list[Finding], ValidationReport]:
    """Full pipeline: schema/reference validation, then the conservative
    auto-confirmation pass. Raises `EvidenceValidationError` only if ALL
    findings are invalid (a sign of a systemic upstream bug) — a partial
    batch of invalid findings is reported, not fatal, so one bad finding
    doesn't block the whole assessment's report."""
    report = validate_schema_and_evidence_refs(findings, evidence)
    if findings and not report.valid:
        raise EvidenceValidationError("all findings failed evidence validation")

    promoted = auto_confirm_eligible(report.valid, evidence=evidence)
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
    _stamp_verification(findings, report, set(report.auto_confirmed))
    return promoted, report
