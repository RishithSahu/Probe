"""PTES phase mapping.

Deterministic classification of assessment activities (not generic
"findings") into the seven PTES phases. The Orchestrator's `map_ptes_phases`
node calls `summarise_activities` once, over the audit trail (tool
executions + findings), rather than every component guessing its own phase —
keeping this single-sourced is what prevents activities from being forced
into an inappropriate phase.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.core.schemas import AgentId, Finding, PtesPhase

# Maps a recorded activity (tool + operation, as logged by the Scope Guard /
# agents' tool_executions) to its PTES phase. Deliberately explicit rather
# than inferred, so a new tool/operation pair that isn't in this table is
# surfaced as "unmapped" instead of silently defaulting somewhere wrong.
_ACTIVITY_PHASE_MAP: dict[tuple[str, str], PtesPhase] = {
    ("httpx", "fingerprint"): PtesPhase.INTELLIGENCE_GATHERING,
    ("http_client", "redirect"): PtesPhase.INTELLIGENCE_GATHERING,
    ("katana", "crawl"): PtesPhase.INTELLIGENCE_GATHERING,
    ("file+readelf+checksec", "identify"): PtesPhase.INTELLIGENCE_GATHERING,
    ("scope_guard", "asset_check"): PtesPhase.PRE_ENGAGEMENT,
    ("scope_guard", "target_check"): PtesPhase.PRE_ENGAGEMENT,
    ("zap_passive", "scan"): PtesPhase.VULNERABILITY_ANALYSIS,
    ("ghidra", "static_analysis"): PtesPhase.VULNERABILITY_ANALYSIS,
    ("network_vulnerability_agent", "service_assessment"): PtesPhase.VULNERABILITY_ANALYSIS,
    ("network_vulnerability_detective", "service_check"): PtesPhase.VULNERABILITY_ANALYSIS,
    ("zap_active", "scan"): PtesPhase.EXPLOITATION,
    ("zap", "active_scan"): PtesPhase.EXPLOITATION,
    ("content_discovery", "discover"): PtesPhase.INTELLIGENCE_GATHERING,
    ("binary_analysis_agent", "acquire"): PtesPhase.INTELLIGENCE_GATHERING,
    ("binary_analysis_agent", "static_analysis"): PtesPhase.VULNERABILITY_ANALYSIS,
}

# Compatibility with the specific legacy producers that omit an operation.
# An explicit unknown operation is never replaced by a guess. Every use of
# these defaults is recorded in the summary until producers are standardised.
_LEGACY_OPERATIONS = {
    "httpx": "fingerprint", "katana": "crawl", "zap_passive": "scan",
    "zap_active": "scan", "ghidra": "static_analysis",
    "file+readelf+checksec": "identify", "content_discovery": "discover",
}

_AGENT_DEFAULT_PHASE: dict[AgentId, PtesPhase] = {
    AgentId.WEB_SECURITY: PtesPhase.VULNERABILITY_ANALYSIS,
    AgentId.BINARY_ANALYSIS: PtesPhase.VULNERABILITY_ANALYSIS,
    AgentId.NETWORK_VULNERABILITY: PtesPhase.VULNERABILITY_ANALYSIS,
    AgentId.ORCHESTRATOR: PtesPhase.THREAT_MODELING,
}


@dataclass
class PtesSummary:
    phase_activity_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    phase_finding_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    unmapped_activities: list[tuple[str, str]] = field(default_factory=list)
    inferred_operations: list[tuple[str, str]] = field(default_factory=list)
    skipped_activities: list[tuple[str, str]] = field(default_factory=list)
    failed_activity_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self) -> dict:
        return {
            "phase_activity_counts": dict(self.phase_activity_counts),
            "phase_finding_counts": dict(self.phase_finding_counts),
            "unmapped_activities": self.unmapped_activities,
            "inferred_operations": self.inferred_operations,
            "skipped_activities": self.skipped_activities,
            "failed_activity_counts": dict(self.failed_activity_counts),
        }


def classify_activity(tool: str, operation: str) -> PtesPhase | None:
    return _ACTIVITY_PHASE_MAP.get((tool, operation))


def classify_finding(finding: Finding) -> PtesPhase:
    """A finding's own `ptes_phase` (set by the producing agent at
    finding-generation time, per the shared schema) is authoritative — this
    is only a fallback for findings that somehow lack one."""
    return finding.ptes_phase or _AGENT_DEFAULT_PHASE.get(finding.agent_id, PtesPhase.VULNERABILITY_ANALYSIS)


def summarise_activities(tool_executions: list[dict], findings: list[Finding]) -> PtesSummary:
    summary = PtesSummary()
    for execution in tool_executions:
        tool = str(execution.get("tool") or "")
        operation = str(execution.get("operation") or execution.get("op") or "")
        if not operation and tool in _LEGACY_OPERATIONS:
            operation = _LEGACY_OPERATIONS[tool]
            summary.inferred_operations.append((tool, operation))
        phase = classify_activity(tool, operation)
        if phase is None:
            summary.unmapped_activities.append((tool, operation))
            continue
        if execution.get("ran") is False or execution.get("allowed") is False:
            summary.skipped_activities.append((tool, operation))
            continue
        if execution.get("error"):
            summary.failed_activity_counts[phase.value] += 1
            continue
        summary.phase_activity_counts[phase.value] += 1

    for finding in findings:
        phase = classify_finding(finding)
        summary.phase_finding_counts[phase.value] += 1

    # Reporting itself (generating the consolidated report) is always part
    # of the final phase — recorded unconditionally so every assessment's
    # PTES summary includes it, independent of what tools ran.
    summary.phase_activity_counts[PtesPhase.REPORTING.value] += 1

    return summary
