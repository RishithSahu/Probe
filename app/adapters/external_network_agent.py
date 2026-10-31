"""Integration interface for the teammate's independently-developed Network
Vulnerability Assessment Agent.

This module does NOT implement network vulnerability scanning. It only
validates and translates whatever his component submits into our shared
`Finding` schema, so the Orchestrator can aggregate it with Web/Binary
findings. See `app.api.routes` for the HTTP endpoint
(`POST /assessments/{assessment_id}/external-findings`) that uses this.

Until his agent is ready, `synthetic_network_findings()` below produces
fixture data conforming to the exact same contract, so the Orchestrator's
aggregation/attack-path/report pipeline can be developed and tested end to
end today.
"""
from __future__ import annotations

from app.core.schemas import (
    Confidence,
    ExternalNetworkFinding,
    Finding,
    Severity,
    TaskStatus,
)


class ExternalFindingValidationError(ValueError):
    """Raised when a submitted external finding fails schema or scope checks."""


def validate_external_findings(
    assessment_id: str,
    scope_id: str,
    payload: list[dict],
    *,
    known_asset_ids: set[str] | None = None,
) -> list[ExternalNetworkFinding]:
    """Validate a batch of raw finding dicts against the external contract.

    `known_asset_ids`, when supplied (normally from the loaded NetworkGraph),
    is used to reject findings about assets that are not part of this
    assessment's authorised graph — the Network Vulnerability Agent is
    trusted to do its own scanning, but it is not trusted to silently expand
    the inventory this application reports on.
    """
    validated: list[ExternalNetworkFinding] = []
    for i, item in enumerate(payload):
        try:
            finding = ExternalNetworkFinding.model_validate(item)
        except Exception as exc:  # noqa: BLE001 - re-raised with context
            raise ExternalFindingValidationError(f"external finding[{i}] failed schema validation: {exc}") from exc

        if finding.assessment_id != assessment_id:
            raise ExternalFindingValidationError(
                f"external finding[{i}] assessment_id {finding.assessment_id!r} does not match {assessment_id!r}"
            )
        if finding.scope_id != scope_id:
            raise ExternalFindingValidationError(
                f"external finding[{i}] scope_id {finding.scope_id!r} does not match assessment scope {scope_id!r}"
            )
        if known_asset_ids is not None and finding.asset_id not in known_asset_ids:
            raise ExternalFindingValidationError(
                f"external finding[{i}] references asset_id {finding.asset_id!r} which is not in the "
                "assessment's authorised network graph"
            )
        validated.append(finding)
    return validated


def to_findings(validated: list[ExternalNetworkFinding]) -> list[Finding]:
    return [f.to_finding() for f in validated]


def synthetic_network_findings(assessment_id: str, scope_id: str, asset_id: str, service_id: str) -> list[Finding]:
    """Fixture findings matching the external contract exactly, so integration
    (ingestion endpoint -> validation -> aggregation -> attack paths -> report)
    can be exercised before the teammate's agent exists. Clearly NOT a stand-in
    for his scanning logic — just contract-shaped test data."""
    sample = ExternalNetworkFinding(
        assessment_id=assessment_id,
        scope_id=scope_id,
        asset_id=asset_id,
        service_id=service_id,
        finding_id=f"NET-SYNTH-{asset_id}",
        title="Outdated service banner (synthetic fixture)",
        description="Synthetic placeholder finding standing in for the teammate's "
        "Network Vulnerability Agent output until it is integrated.",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        execution_status=TaskStatus.COMPLETED,
    )
    return [sample.to_finding()]
