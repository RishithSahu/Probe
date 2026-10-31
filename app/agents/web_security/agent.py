"""Web Security Assessment Agent — entry point.

Receives graph-listed HTTP/HTTPS services from the Orchestrator (never
discovers targets itself), runs Stages A-D, and returns a single
`AgentResult`. One agent failure (a single target erroring out) does not
abort the whole task — it's recorded in `errors` and the agent moves on, so a
partial result is still useful to the Orchestrator's aggregation step.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from app.agents.web_security.crawler import crawl
from app.agents.web_security.findings import findings_from_fingerprint, findings_from_zap_alerts
from app.agents.web_security.fingerprint import fingerprint_url
from app.agents.web_security.zap_integration import run_active_scan_if_authorised, run_passive_scan
from app.core.exceptions import ScopeViolationError, ToolExecutionError
from app.core.schemas import (
    AgentId,
    AgentResult,
    AssessmentPolicy,
    Evidence,
    Finding,
    TaskStatus,
)
from app.core.scope_guard import ScopeGuard

logger = logging.getLogger("ape.web_agent")


class WebTarget:
    """One graph-listed web service to assess, as handed to this agent by the
    Orchestrator (see app/orchestrator/nodes.py::dispatch_web_agent)."""

    def __init__(self, asset_id: str, url: str):
        self.asset_id = asset_id
        self.url = url


def assess_target(
    target: WebTarget,
    *,
    assessment_id: str,
    scope_guard: ScopeGuard,
    policy: AssessmentPolicy,
    output_dir: Path,
) -> tuple[list[Finding], list[Evidence], list[str], list[dict], list[str]]:
    """Run Stages A-C for one target. Returns (findings, evidence, endpoint
    urls, tool_execution_records, errors) — never raises for an individual
    target's tool failure; scope violations and tool errors both become
    entries in the returned `errors` list instead."""
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    endpoints: list[str] = []
    tool_executions: list[dict] = []
    errors: list[str] = []

    # Stage A: fingerprinting
    try:
        fp = fingerprint_url(target.url, asset_id=target.asset_id, scope_guard=scope_guard)
        tool_executions.append({"tool": "httpx", "target": target.url, "error": fp.error})
        fp_findings, fp_evidence = findings_from_fingerprint(fp, assessment_id=assessment_id, asset_id=target.asset_id)
        findings.extend(fp_findings)
        evidence.extend(fp_evidence)
        if fp.error:
            errors.append(f"fingerprint({target.url}): {fp.error}")
    except ScopeViolationError as exc:
        errors.append(f"fingerprint({target.url}) rejected by scope guard: {exc}")
        return findings, evidence, endpoints, tool_executions, errors

    # Stage B: crawling (only if authorised)
    if policy.allow_web_crawling:
        try:
            crawl_result = crawl(
                target.url,
                asset_id=target.asset_id,
                scope_guard=scope_guard,
                depth=policy.max_crawl_depth,
                rate_per_second=policy.max_crawl_requests_per_second,
                output_dir=output_dir,
            )
            tool_executions.append({
                "tool": "katana", "target": target.url,
                "used_fixture": crawl_result.used_fixture, "endpoint_count": len(crawl_result.endpoints),
            })
            endpoints = [ep.url for ep in crawl_result.endpoints]
        except (ScopeViolationError, ToolExecutionError) as exc:
            errors.append(f"crawl({target.url}): {exc}")

    # Stage C: ZAP passive (+ active if authorised)
    try:
        passive = run_passive_scan(target.url, asset_id=target.asset_id, scope_guard=scope_guard)
        tool_executions.append({"tool": "zap_passive", "target": target.url, "used_fixture": passive.used_fixture})
        if passive.error:
            errors.append(f"zap_passive({target.url}): {passive.error}")
        zap_findings, zap_evidence = findings_from_zap_alerts(passive.alerts, assessment_id=assessment_id, asset_id=target.asset_id)
        findings.extend(zap_findings)
        evidence.extend(zap_evidence)
    except (ScopeViolationError, ToolExecutionError) as exc:
        errors.append(f"zap_passive({target.url}): {exc}")

    if policy.allow_active_web_verification:
        try:
            active = run_active_scan_if_authorised(target.url, asset_id=target.asset_id, scope_guard=scope_guard)
            tool_executions.append({
                "tool": "zap_active", "target": target.url,
                "ran": active.active_scan_run, "used_fixture": active.used_fixture,
            })
            if active.error:
                errors.append(f"zap_active({target.url}): {active.error}")
            active_findings, active_evidence = findings_from_zap_alerts(active.alerts, assessment_id=assessment_id, asset_id=target.asset_id)
            findings.extend(active_findings)
            evidence.extend(active_evidence)
        except (ScopeViolationError, ToolExecutionError) as exc:
            errors.append(f"zap_active({target.url}): {exc}")

    return findings, evidence, endpoints, tool_executions, errors


def run_web_security_agent(
    targets: list[WebTarget],
    *,
    assessment_id: str,
    scope_guard: ScopeGuard,
    policy: AssessmentPolicy,
    output_dir: Path,
) -> AgentResult:
    start = time.monotonic()
    all_findings: list[Finding] = []
    all_evidence: list[Evidence] = []
    all_endpoints: list[str] = []
    all_tool_executions: list[dict] = []
    all_errors: list[str] = []

    for target in targets:
        findings, evidence, endpoints, tool_executions, errors = assess_target(
            target, assessment_id=assessment_id, scope_guard=scope_guard, policy=policy, output_dir=output_dir,
        )
        all_findings.extend(findings)
        all_evidence.extend(evidence)
        all_endpoints.extend(endpoints)
        all_tool_executions.extend(tool_executions)
        all_errors.extend(errors)

    duration = time.monotonic() - start
    # The agent as a whole only "fails" if every target failed with zero
    # findings/endpoints produced; a mix of successes and per-target errors
    # is still a completed task with partial results.
    execution_status = TaskStatus.COMPLETED
    if targets and len(all_errors) >= len(targets) and not all_findings and not all_endpoints:
        execution_status = TaskStatus.FAILED

    return AgentResult(
        agent_id=AgentId.WEB_SECURITY,
        assessment_id=assessment_id,
        execution_status=execution_status,
        findings=all_findings,
        evidence=all_evidence,
        discovered_endpoints=all_endpoints,
        tool_executions=all_tool_executions,
        errors=all_errors,
        duration_seconds=duration,
    )
