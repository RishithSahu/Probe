"""Stage D: translate static-analysis Weaknesses into the shared Finding/
Evidence schema. As with the Web Agent, nothing here marks a finding
`confirmed` — all start `suspected`, pending `app.analysis.evidence_validator`.
"""
from __future__ import annotations

import uuid

from app.agents.binary_analysis.static_analysis import Weakness
from app.core.schemas import AgentId, Confidence, Evidence, Finding, PtesPhase, Severity, Surface

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_CONFIDENCE_MAP = {"low": Confidence.LOW, "medium": Confidence.MEDIUM, "high": Confidence.HIGH}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def findings_from_weaknesses(
    weaknesses: list[Weakness],
    *,
    assessment_id: str,
    binary_id: str,
    source_tool: str = "ghidra_static_analysis",
) -> tuple[list[Finding], list[Evidence]]:
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for w in weaknesses:
        finding_id = _new_id("BIN")
        evidence_id = _new_id("EVIDENCE")
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                evidence_type=f"ghidra_{w.category}",
                source_tool=source_tool,
                description=f"{w.title} (matched: {w.matched_value!r})" if w.matched_value else w.title,
                raw_data={
                    "function_name": w.function_name,
                    "function_address": w.function_address,
                    "matched_value": w.matched_value,
                    **w.context,
                },
            )
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                assessment_id=assessment_id,
                agent_id=AgentId.BINARY_ANALYSIS,
                surface=Surface.BINARY,
                binary_id=binary_id,
                title=w.title,
                description=w.description,
                severity=_SEVERITY_MAP.get(w.severity, Severity.INFO),
                confidence=_CONFIDENCE_MAP.get(w.confidence, Confidence.LOW),
                evidence_refs=[evidence_id],
                remediation=_remediation_for_category(w.category),
                ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                detection_method=w.category,
                function_name=w.function_name,
                function_address=w.function_address,
            )
        )
    return findings, evidence


def _remediation_for_category(category: str) -> str | None:
    return {
        "unsafe_function_usage": "Replace with a bounds-checked equivalent (e.g. strncpy/snprintf) "
        "and validate/sanitise any input reaching command-execution sinks.",
        "hardcoded_credential": "Remove embedded credentials/secrets; load them from a secret manager "
        "or environment configuration at runtime, and rotate the value if it was ever shipped.",
        "weak_binary_hardening": "Rebuild with the relevant compiler/linker hardening flags enabled "
        "(e.g. -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -pie, -Wl,-z,relro,-z,now).",
        "suspicious_input_handling": "Review the referenced function for missing input-length validation "
        "before it reaches an unsafe sink.",
    }.get(category)
