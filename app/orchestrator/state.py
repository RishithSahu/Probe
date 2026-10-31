"""LangGraph workflow state.

A single TypedDict threaded through every node (PRD Part 9.2's 14 nodes).
Each node returns only the keys it changes; LangGraph merges them into the
running state (default "last write wins" reducer, which is sufficient here
because the two nodes that can run concurrently — dispatch_web_agent and
dispatch_binary_agent — write to disjoint keys, `web_agent_result` and
`binary_agent_result`).
"""
from __future__ import annotations

from typing import Any, TypedDict

from app.core.schemas import (
    AgentResult,
    AssessmentPolicy,
    Evidence,
    Finding,
    NetworkGraph,
)


class TaskExecutionState(TypedDict, total=False):
    status: str  # pending|running|completed|failed|skipped
    error: str | None


class OrchestratorState(TypedDict, total=False):
    # --- Input -----------------------------------------------------------
    assessment_id: str
    scope_id: str
    policy: AssessmentPolicy
    network_graph_source_path: str | None
    binary_paths: list[tuple[str, str]]  # (binary_id, path)
    external_network_findings_raw: list[dict]  # payload already POSTed, if any

    # --- Derived / intermediate -------------------------------------------
    network_graph: NetworkGraph | None
    http_targets: list[tuple[str, str]]  # (asset_id, url)
    task_status: dict[str, TaskExecutionState]  # keyed by agent_id value

    # --- Agent outputs -----------------------------------------------------
    web_agent_result: AgentResult | None
    binary_agent_result: AgentResult | None
    # This app's own Network Vulnerability Detective (app/agents/network_vulnerability/)
    # — safe, read-only protocol probes against already-discovered services.
    # Kept separate from network_agent_findings/evidence below (which cover
    # the EXTERNAL-agent contract + Probe's own leads) so each source's
    # provenance/tool_executions stay distinguishable in the report.
    network_vulnerability_result: AgentResult | None
    network_agent_findings: list[Finding]
    network_agent_evidence: list[Evidence]

    # --- Aggregation / post-processing --------------------------------------
    all_findings: list[Finding]
    all_evidence: list[Evidence]
    validated_findings: list[Finding]
    validation_report: dict[str, Any]
    attack_path_edges: list[dict]
    ptes_summary: dict[str, Any]

    # --- Output --------------------------------------------------------------
    report_json_path: str | None
    report_pdf_path: str | None
    assessment_status: str  # AssessmentStatus value
    errors: list[str]
