"""Translates the Network Discovery Probe's `leads()` into the shared
Finding/Evidence schema.

Field names here are taken from `probe/store.py`'s `leads` table (ground
truth), not just docs/CONTRACT.md's prose description: a lead row is
`{address, evidence, source, count, found_at}` — note `address`, not `ip`,
and `evidence` is the (string) observation text, not a `description` field.

This is the network-surface signal this application actually has today —
Probe performs lightweight banner/title-based flagging (`vulnerable-app`),
proof-backed hidden-host detection (`hidden-host`), and structural anomaly
flags (`anomaly:*`); it does not run a deep vulnerability scanner. Every
translated finding is therefore `suspected`, never `confirmed` — Probe's own
contract is explicit that these are "not facts, follow-up candidates"
(`unconfirmed:*`) or, at best, proof-backed observations that still warrant
independent verification before being treated as an exploitable finding.

Distinct from `app.adapters.external_network_agent`, which defines the
contract for a SEPARATE, deeper Network Vulnerability Assessment Agent
should one be built later — that interface is unaffected by this module and
remains available via `POST /assessments/{id}/external-findings`.
"""
from __future__ import annotations

import uuid

from app.core.schemas import AgentId, Confidence, Evidence, Finding, PtesPhase, Severity, Surface

# Lead `source` values Probe is documented to emit (docs/CONTRACT.md §2).
# Anything else encountered is still translated (as a low-severity,
# low-confidence finding) rather than silently dropped — an unrecognised
# source is a signal to update this table, not a reason to lose the lead.
_SOURCE_SEVERITY = {
    "hidden-host": Severity.MEDIUM,
    "vulnerable-app": Severity.HIGH,
    "anomaly:forwarder": Severity.LOW,
    "anomaly:ttl-cluster": Severity.LOW,
    "outside-scope-address": Severity.INFO,
}
_SOURCE_CONFIDENCE = {
    "hidden-host": Confidence.MEDIUM,  # proof-backed (an actual observation), but still needs independent review
    "vulnerable-app": Confidence.LOW,  # banner/title heuristic only
}
_UNCONFIRMED_PREFIX = "unconfirmed:"


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _title_for(lead: dict) -> str:
    source = lead.get("source", "unknown")
    address = lead.get("address") or "unknown target"
    if source == "hidden-host":
        return f"Hidden host detected: {address}"
    if source == "vulnerable-app":
        return f"Possible vulnerable application at {address}"
    if source.startswith("anomaly:"):
        return f"Network anomaly ({source.split(':', 1)[1]}) involving {address}"
    if source == "outside-scope-address":
        return f"Reachable address outside authorised scope: {address}"
    if source.startswith(_UNCONFIRMED_PREFIX):
        return f"Unconfirmed lead ({source.split(':', 1)[1]}): {address}"
    return f"Probe lead ({source}): {address}"


def findings_from_probe_leads(
    leads: list[dict], *, assessment_id: str
) -> tuple[list[Finding], list[Evidence]]:
    findings: list[Finding] = []
    evidence: list[Evidence] = []

    for lead in leads:
        source = str(lead.get("source", "unknown"))
        finding_id = _new_id("NET")
        evidence_id = _new_id("EVIDENCE")
        address = lead.get("address")
        evidence_text = lead.get("evidence") or f"Probe lead: {source}"
        count = lead.get("count")

        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                evidence_type=f"probe_lead:{source}",
                source_tool="network_discovery_probe",
                description=evidence_text,
                raw_data=lead,
            )
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                assessment_id=assessment_id,
                agent_id=AgentId.NETWORK_VULNERABILITY,
                surface=Surface.NETWORK,
                asset_id=str(address) if address else None,
                title=_title_for(lead),
                description=(
                    f"{evidence_text} (observed {count}x)" if count and count > 1 else evidence_text
                ),
                severity=_SOURCE_SEVERITY.get(source, Severity.LOW),
                confidence=_SOURCE_CONFIDENCE.get(source, Confidence.LOW),
                evidence_refs=[evidence_id],
                remediation="Review manually; Probe leads are discovery-time signal, not a confirmed assessment.",
                ptes_phase=PtesPhase.INTELLIGENCE_GATHERING if source != "vulnerable-app" else PtesPhase.VULNERABILITY_ANALYSIS,
                detection_method=f"probe_lead:{source}",
            )
        )

    return findings, evidence
