"""AI planner integration contract (item 11).

The planner being built on the other laptop proposes WHAT to investigate next; it never executes
anything itself. This module defines that boundary precisely:

  InvestigationPlanner.propose(context) -> list[ProposedInvestigation]

A proposal names entities and an operation type -- it is data, not code, and it cannot invoke a tool,
run a command, or bypass ScopeGuard. The orchestrator (app.orchestrator.autonomous_loop, extended by
`run_planner_iteration` below) is the only thing that ever turns a proposal into a running task, and it
does so through the EXACT SAME validation every other candidate goes through:

    1. Validate every referenced entity actually exists in the current graph/finding set.
    2. Check task dependencies (parent/prerequisite findings are present and resolved).
    3. Check the proposed operation type is one this orchestrator recognises.
    4. Check ScopeGuard -- independently of the planner, and it fails closed (app.core.scope_guard).
    5. Deduplicate against the existing task ledger (repository.try_reserve_task's own fingerprinting).
    6. Compute resource requirements / respect concurrency limits (_surface_caps in autonomous_loop).
    7. Reserve and dispatch the appropriate worker.
    8. Validate the evidence that comes back (app.analysis.evidence_validator), same as every other task.

A proposal that fails any of 1-4 is dropped with a logged reason; it is never a runtime error that aborts
the loop, and it never silently expands what the proposal itself could not justify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.core.schemas import AgentId, Finding, NetworkGraph


@dataclass(frozen=True)
class AssessmentSummary:
    """Everything the planner is handed about the assessment's current state -- a read-only snapshot, not
    a handle it can act through."""
    assessment_id: str
    scope_cidrs: tuple[str, ...]
    graph: NetworkGraph
    findings: tuple[Finding, ...]
    task_history: tuple[dict, ...]  # [{task_id, task_type, agent_id, status, service_id, asset_id}, ...]
    available_capabilities: tuple[str, ...]  # e.g. ("web_security_agent", "network_vulnerability_detective", "binary_analysis_agent")
    unresolved_objective_ids: tuple[str, ...]
    execution_budget_seconds: float


@dataclass(frozen=True)
class ProposedInvestigation:
    """A candidate investigation, named by entity, not by instruction. `operation_type` must be one of a
    small, fixed vocabulary the orchestrator already knows how to dispatch (e.g. "web_assessment",
    "network_assessment", "binary_analysis") -- never a free-form command, tool name, or shell string."""
    operation_type: str
    asset_id: str
    service_id: str | None
    rationale: str
    confidence: float  # 0..1 -- the planner's own stated confidence, informational only; never a bypass of scoring
    references_finding_ids: tuple[str, ...] = field(default_factory=tuple)
    requested_capability: AgentId | None = None


class InvestigationPlanner(Protocol):
    def propose(self, context: AssessmentSummary) -> list[ProposedInvestigation]:
        """Returns proposed candidates, highest-priority first. Must not raise for an empty/uncertain
        context -- an empty list is the correct response when nothing is justified, not an exception."""
        ...


class DeterministicNullPlanner:
    """The non-AI reference implementation (item 11's explicit requirement): always proposes nothing. Lets
    every test and local run exercise the full validate/dedupe/dispatch pipeline without depending on any
    actual planning logic, AI or otherwise -- the orchestrator's OWN scheduler (app.orchestrator.scheduler)
    remains the default source of candidates when no external planner is configured."""

    def propose(self, context: AssessmentSummary) -> list[ProposedInvestigation]:
        return []


class RemoteHTTPPlanner:
    """Talks to a planner running as its own process/service (e.g. the other laptop), so the execution
    engine here never has to change to add a planner backend -- only this one adapter does. POSTs the
    `AssessmentSummary` as JSON and expects back a JSON list of proposals in the same shape; a
    malformed/unreachable response degrades to an empty proposal list (a planner failure must never halt
    or corrupt the orchestrator's own loop), with the error logged for the operator."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def propose(self, context: AssessmentSummary) -> list[ProposedInvestigation]:
        import logging

        import httpx

        logger = logging.getLogger("ape.orchestrator.planner")
        body = {
            "assessment_id": context.assessment_id, "scope_cidrs": list(context.scope_cidrs),
            "graph": context.graph.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in context.findings],
            "task_history": list(context.task_history),
            "available_capabilities": list(context.available_capabilities),
            "unresolved_objective_ids": list(context.unresolved_objective_ids),
            "execution_budget_seconds": context.execution_budget_seconds,
        }
        try:
            resp = httpx.post(f"{self.base_url}/propose", json=body, timeout=self.timeout_seconds)
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:  # noqa: BLE001 - a remote planner being down must degrade, not crash the loop
            logger.warning("remote planner at %s unavailable or returned an invalid response: %s", self.base_url, exc)
            return []
        proposals = []
        for item in raw if isinstance(raw, list) else []:
            try:
                proposals.append(ProposedInvestigation(
                    operation_type=str(item["operation_type"]), asset_id=str(item["asset_id"]),
                    service_id=item.get("service_id"), rationale=str(item.get("rationale", "")),
                    confidence=float(item.get("confidence", 0.0)),
                    references_finding_ids=tuple(item.get("references_finding_ids", [])),
                    requested_capability=AgentId(item["requested_capability"]) if item.get("requested_capability") else None,
                ))
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("dropping malformed proposal from remote planner: %r (%s)", item, exc)
        return proposals
