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

from app.adapters.authorisation_grants import headers_for_url
from app.agents.web_security.content_discovery import discover_hidden_paths
from app.agents.web_security.crawler import crawl
from app.agents.web_security.findings import (
    findings_from_discovered_endpoints,
    findings_from_fingerprint,
    findings_from_zap_alerts,
)
from app.agents.web_security.fingerprint import fingerprint_url
from app.agents.web_security.zap_integration import run_active_scan_if_authorised, run_passive_scan
from app.core.config import settings
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

# A cap, not a policy knob: bounds how many of Katana's discovered endpoints additionally get a ZAP
# passive/active scan (beyond the root URL, which is always scanned), so a large crawl can't turn into an
# unbounded number of ZAP scans per target.
_MAX_ZAP_ENDPOINT_TARGETS = 10


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
) -> tuple[list[Finding], list[Evidence], list[str], list[dict], list[str], list[dict]]:
    """Run Stages A-C (+ content discovery) for one target. Returns (findings, evidence, endpoint urls,
    tool_execution_records, errors, binary_references) — never raises for an individual target's tool
    failure; scope violations and tool errors both become entries in the returned `errors` list instead."""
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    endpoints: list[str] = []
    tool_executions: list[dict] = []
    errors: list[str] = []
    binary_references: list[dict] = []

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
        # BUG FIX: this used to abort the WHOLE target here, so disabling Stage A (allow_passive_web_analysis)
        # silently skipped every later stage too, including content discovery (Stage E) -- which has its own,
        # independent policy flag and scope-guard check and must not depend on Stage A's permission at all.
        errors.append(f"fingerprint({target.url}) rejected by scope guard: {exc}")

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
            # Katana's discoveries previously fed only report metadata and never became a Finding, unlike
            # Ghidra's analysis -- see findings_from_discovered_endpoints's own docstring.
            ep_findings, ep_evidence = findings_from_discovered_endpoints(
                crawl_result.endpoints, assessment_id=assessment_id, asset_id=target.asset_id,
                used_fixture=crawl_result.used_fixture,
            )
            findings.extend(ep_findings)
            evidence.extend(ep_evidence)
        except (ScopeViolationError, ToolExecutionError) as exc:
            errors.append(f"crawl({target.url}): {exc}")

    # Stage C: ZAP passive (+ active if authorised) -- against the root URL AND every endpoint Katana
    # discovered. Previously ZAP only ever saw target.url: a page Katana crawled to (e.g. an admin panel or
    # a parametrised endpoint reachable only via a link, never the site root) was fully invisible to ZAP's
    # own header/cookie/active-rule checks, even though Katana had already proven it exists and is in scope.
    # Each endpoint still goes through its own scope_guard check inside run_passive_scan/
    # run_active_scan_if_authorised -- this loop does not widen what ZAP is allowed to touch, only how many
    # of the already-in-scope, already-discovered URLs get the same checks the root URL always got.
    zap_targets = [target.url]
    seen_zap_targets = {target.url}
    for ep_url in endpoints:
        base = ep_url.split("?", 1)[0]
        if base in seen_zap_targets or len(zap_targets) >= _MAX_ZAP_ENDPOINT_TARGETS:
            continue
        seen_zap_targets.add(base)
        zap_targets.append(base)

    for zap_url in zap_targets:
        try:
            passive = run_passive_scan(zap_url, asset_id=target.asset_id, scope_guard=scope_guard)
            tool_executions.append({"tool": "zap_passive", "target": zap_url, "used_fixture": passive.used_fixture})
            if passive.error:
                errors.append(f"zap_passive({zap_url}): {passive.error}")
            zap_findings, zap_evidence = findings_from_zap_alerts(
                passive.alerts, assessment_id=assessment_id, asset_id=target.asset_id, used_fixture=passive.used_fixture,
            )
            findings.extend(zap_findings)
            evidence.extend(zap_evidence)
        except (ScopeViolationError, ToolExecutionError) as exc:
            errors.append(f"zap_passive({zap_url}): {exc}")

        if policy.allow_active_web_verification:
            try:
                active = run_active_scan_if_authorised(zap_url, asset_id=target.asset_id, scope_guard=scope_guard)
                tool_executions.append({
                    "tool": "zap_active", "target": zap_url,
                    "ran": active.active_scan_run, "used_fixture": active.used_fixture,
                })
                if active.error:
                    errors.append(f"zap_active({zap_url}): {active.error}")
                active_findings, active_evidence = findings_from_zap_alerts(
                    active.alerts, assessment_id=assessment_id, asset_id=target.asset_id, used_fixture=active.used_fixture,
                )
                findings.extend(active_findings)
                evidence.extend(active_evidence)
            except (ScopeViolationError, ToolExecutionError) as exc:
                errors.append(f"zap_active({zap_url}): {exc}")

    # Stage E: generic hidden-path content discovery -- resource discovery only; see content_discovery.py's
    # own docstring for why this never extracts a credential itself.
    if policy.allow_content_discovery:
        try:
            discovery = discover_hidden_paths(
                target.url, asset_id=target.asset_id, scope_guard=scope_guard,
                max_requests=policy.max_content_discovery_requests,
                rate_per_second=policy.content_discovery_rate_per_second,
                extra_headers=headers_for_url(target.url, settings.authorisations_path),
            )
            tool_executions.append({
                "tool": "content_discovery", "target": target.url, "requests_made": discovery.requests_made,
                "hits": len(discovery.hits), "binary_references": len(discovery.binary_references),
            })
            errors.extend(f"content_discovery({target.url}): {e}" for e in discovery.errors)
            binary_references.extend({
                "asset_id": ref.asset_id, "url": ref.url, "content_type": ref.content_type,
                "content_length": ref.content_length, "reason": ref.reason,
            } for ref in discovery.binary_references)
        except (ScopeViolationError, ToolExecutionError) as exc:
            errors.append(f"content_discovery({target.url}): {exc}")

    return findings, evidence, endpoints, tool_executions, errors, binary_references


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
    all_binary_references: list[dict] = []

    for target in targets:
        findings, evidence, endpoints, tool_executions, errors, binary_references = assess_target(
            target, assessment_id=assessment_id, scope_guard=scope_guard, policy=policy, output_dir=output_dir,
        )
        all_findings.extend(findings)
        all_evidence.extend(evidence)
        all_endpoints.extend(endpoints)
        all_tool_executions.extend(tool_executions)
        all_errors.extend(errors)
        all_binary_references.extend(binary_references)

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
        discovered_binary_references=all_binary_references,
        tool_executions=all_tool_executions,
        errors=all_errors,
        duration_seconds=duration,
    )
