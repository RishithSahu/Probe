"""Scope Guard.

Deterministic, dependency-free authorisation checks. Every tool invocation
anywhere in this codebase (httpx request, Katana crawl, ZAP scan, Ghidra run)
must pass through here *immediately before execution* — not just once at
assessment startup. No LLM-generated command, URL, or argument list reaches a
subprocess or network call without going through one of these checks first.

The checks are intentionally boring: string/URL comparisons and set
membership, nothing clever. That is a feature — this is the one place in the
system that must be trivially auditable.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.exceptions import ScopeViolationError
from app.core.schemas import AssessmentPolicy, NetworkGraph

logger = logging.getLogger("ape.scope_guard")


@dataclass(frozen=True)
class ToolInvocationRecord:
    """Audit record for every attempted tool call, allowed or not. The
    Orchestrator/agents persist these via AgentResult.tool_executions."""

    tool: str
    operation: str
    target: str
    allowed: bool
    reason: str
    dry_run: bool


class ScopeGuard:
    """Constructed once per assessment from its `AssessmentPolicy` and
    `NetworkGraph`. Agents hold a reference to this and must call the
    relevant `check_*` method before every tool invocation.
    """

    def __init__(self, policy: AssessmentPolicy, graph: NetworkGraph | None = None):
        self.policy = policy
        self.graph = graph
        self._known_asset_ids: set[str] = {a.asset_id for a in graph.assets} if graph else set()
        self._known_service_ids: set[str] = (
            {s.service_id for a in graph.assets for s in a.services} if graph else set()
        )
        self._approved_asset_ids: set[str] = set(policy.approved_asset_ids) or self._known_asset_ids
        self._approved_origins = {self._normalise_origin(o) for o in policy.approved_web_origins}
        self.audit_log: list[ToolInvocationRecord] = []

    # -- internal -----------------------------------------------------------

    @staticmethod
    def _normalise_origin(origin: str) -> str:
        parsed = urlparse(origin if "//" in origin else f"//{origin}")
        host = (parsed.hostname or "").lower()
        port = parsed.port
        scheme = parsed.scheme or "https"
        if port is None:
            port = 443 if scheme == "https" else 80
        return f"{scheme}://{host}:{port}"

    def _record(self, tool: str, operation: str, target: str, allowed: bool, reason: str) -> ToolInvocationRecord:
        rec = ToolInvocationRecord(
            tool=tool, operation=operation, target=target, allowed=allowed, reason=reason, dry_run=self.policy.dry_run
        )
        self.audit_log.append(rec)
        log_fn = logger.info if allowed else logger.warning
        log_fn("scope_guard tool=%s op=%s target=%s allowed=%s dry_run=%s reason=%s",
               tool, operation, target, allowed, rec.dry_run, reason)
        return rec

    def _deny(self, tool: str, operation: str, target: str, reason: str) -> None:
        self._record(tool, operation, target, allowed=False, reason=reason)
        raise ScopeViolationError(reason)

    def _allow(self, tool: str, operation: str, target: str, reason: str = "authorised") -> ToolInvocationRecord:
        return self._record(tool, operation, target, allowed=True, reason=reason)

    # -- network / service checks --------------------------------------------

    def check_asset_in_scope(self, asset_id: str) -> None:
        if asset_id not in self._approved_asset_ids:
            self._deny("scope_guard", "asset_check", asset_id, f"asset {asset_id!r} is not in the approved assessment scope")

    def check_service_assessment_allowed(self, asset_id: str, service_id: str) -> ToolInvocationRecord:
        if not self.policy.allow_network_service_assessment:
            self._deny("network_vulnerability_agent", "service_assessment", service_id,
                        "allow_network_service_assessment is disabled by the assessment policy")
        self.check_asset_in_scope(asset_id)
        if service_id not in self._known_service_ids:
            self._deny("network_vulnerability_agent", "service_assessment", service_id,
                        f"service {service_id!r} is not present in the authorised network graph")
        return self._allow("network_vulnerability_agent", "service_assessment", service_id)

    # -- web checks -----------------------------------------------------------

    def check_web_target_in_scope(self, asset_id: str, url: str) -> ToolInvocationRecord:
        self.check_asset_in_scope(asset_id)
        origin = self._normalise_origin(url)
        if self._approved_origins and origin not in self._approved_origins:
            self._deny("web_security_agent", "target_check", url,
                        f"origin {origin!r} is not in approved_web_origins")
        return self._allow("web_security_agent", "target_check", url)

    def check_passive_web_analysis_allowed(self, asset_id: str, url: str) -> ToolInvocationRecord:
        if not self.policy.allow_passive_web_analysis:
            self._deny("httpx", "fingerprint", url, "allow_passive_web_analysis is disabled by the assessment policy")
        return self.check_web_target_in_scope(asset_id, url)

    def check_crawl_allowed(self, asset_id: str, url: str) -> ToolInvocationRecord:
        if not self.policy.allow_web_crawling:
            self._deny("katana", "crawl", url, "allow_web_crawling is disabled by the assessment policy")
        return self.check_web_target_in_scope(asset_id, url)

    def check_redirect_allowed(self, origin_url: str, redirect_target: str) -> ToolInvocationRecord:
        """Called on every redirect hop encountered by httpx/Katana. A
        redirect leaving the approved origin set must never be followed —
        this is how we prevent an out-of-scope link from silently expanding
        the target inventory."""
        origin = self._normalise_origin(redirect_target)
        if self._approved_origins and origin not in self._approved_origins:
            self._deny("http_client", "redirect", redirect_target,
                        f"redirect from {origin_url!r} to {redirect_target!r} leaves approved origins")
        return self._allow("http_client", "redirect", redirect_target)

    def check_active_web_verification_allowed(self, asset_id: str, url: str) -> ToolInvocationRecord:
        if not self.policy.allow_active_web_verification:
            self._deny("zap", "active_scan", url,
                        "allow_active_web_verification is disabled by the assessment policy (safe default)")
        return self.check_web_target_in_scope(asset_id, url)

    # -- binary checks --------------------------------------------------------

    def check_binary_analysis_allowed(self, binary_path: str) -> ToolInvocationRecord:
        if not self.policy.allow_binary_analysis:
            self._deny("ghidra", "static_analysis", binary_path,
                        "allow_binary_analysis is disabled by the assessment policy")
        return self._allow("ghidra", "static_analysis", binary_path)

    # -- crawl budget -----------------------------------------------------------

    def check_crawl_depth(self, depth: int) -> None:
        if depth > self.policy.max_crawl_depth:
            raise ScopeViolationError(f"crawl depth {depth} exceeds policy max_crawl_depth={self.policy.max_crawl_depth}")


def is_private_or_lab_address(ip: str) -> bool:
    """Best-effort helper: true for RFC1918/loopback/link-local addresses.
    Used only for defensive sanity-checks/logging (e.g. warning if an
    assessment target doesn't look like a lab address) — NOT as an
    authorisation mechanism. Authorisation is solely the approved_* lists in
    AssessmentPolicy, enforced above."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local
