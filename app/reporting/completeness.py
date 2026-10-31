"""Report coverage separately from whether the orchestration process ended.

No work is dispatched here and no permission is inferred from observations.
Unknown discovery completeness stays unknown unless a discovery report supplies
an explicit status. A zero-finding result can still be a completed assessment.
"""
from __future__ import annotations

from app.core.schemas import AgentResult, TaskStatus


def assessment_coverage(state: dict) -> dict:
    requirements = state.get("required_surfaces", ["network", "web", "binary"])
    if not isinstance(requirements, (list, tuple, set)) or not set(requirements) <= {"network", "web", "binary"}:
        raise ValueError("required_surfaces must contain only network, web, binary")
    requirements = [name for name in ("network", "web", "binary") if name in requirements]
    results = {
        "network": [state.get("network_vulnerability_result")],
        "web": [state.get("web_agent_result")],
        "binary": [state.get("binary_agent_result"), state.get("triggered_binary_agent_result")],
    }
    surfaces = {}
    for surface, candidates in results.items():
        candidates = [r for r in candidates if isinstance(r, AgentResult)]
        if not candidates:
            status = "not_observed"
        elif any(r.execution_status == TaskStatus.COMPLETED and not r.errors for r in candidates):
            status = "completed"
        else:
            status = "incomplete"
        if any(r.errors or r.execution_status == TaskStatus.FAILED for r in candidates):
            status = "incomplete"
        if any(te.get("truncated") or te.get("incomplete") or te.get("timed_out") for r in candidates for te in r.tool_executions):
            status = "incomplete"
        if any(te.get("used_fixture") for r in candidates for te in r.tool_executions):
            status = "synthetic"
        surfaces[surface] = {"status": status, "required": surface in requirements}

    discovery = state.get("discovery_report")
    discovery_status = "unknown"
    if isinstance(discovery, dict):
        if discovery.get("converged") is True:
            discovery_status = "complete"
        elif discovery.get("converged") is False:
            discovery_status = "incomplete"
    missing = [name for name, data in surfaces.items() if data["required"] and data["status"] != "completed"]
    validation = state.get("validation_report") or {}
    evidence_incomplete = bool(validation.get("invalid_count") or validation.get("incomplete_evidence"))
    return {
        "execution_status": str(getattr(state.get("assessment_status", "unknown"), "value", state.get("assessment_status", "unknown"))),
        "required_surfaces": list(requirements),
        "surfaces": surfaces,
        "missing_or_incomplete_surfaces": missing,
        "discovery_status": discovery_status,
        "evidence_incomplete": evidence_incomplete,
        "overall": "incomplete" if missing or evidence_incomplete or discovery_status == "incomplete" else (
            "unknown" if discovery_status == "unknown" else "complete"
        ),
    }
