"""Stage D: translate raw tool output into the shared Finding/Evidence schema.

Nothing here decides a finding is `confirmed` — everything produced by this
agent starts life as `suspected` with `verification_required=True`.
Promotion to `confirmed`/`rejected` is the job of
`app.analysis.evidence_validator`, run centrally by the Orchestrator so the
same policy applies across all three surfaces.
"""
from __future__ import annotations

import uuid
from typing import Iterable
from urllib.parse import parse_qs, urlsplit

from app.agents.web_security.crawler import DiscoveredEndpoint
from app.agents.web_security.fingerprint import FingerprintResult
from app.agents.web_security.zap_integration import ZapAlert
from app.core.schemas import (
    AgentId,
    Confidence,
    Evidence,
    Finding,
    PtesPhase,
    Severity,
    Surface,
)

# Query-parameter names generically associated with a server reading a file named
# by the request (local file inclusion / path traversal), independent of any one
# application -- the same class of signal static_analysis.py's _UNSAFE_FUNCTIONS
# heuristic uses for binaries, applied here to endpoints Katana discovers that a
# plain fingerprint of the root page would never see.
_FILE_READ_PARAM_NAMES = ("file", "page", "view", "template", "document", "doc", "path", "include", "filename", "load")

_ZAP_RISK_TO_SEVERITY = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}
_ZAP_CONFIDENCE_TO_OURS = {
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
}

MISSING_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def findings_from_fingerprint(
    result: FingerprintResult, *, assessment_id: str, asset_id: str
) -> tuple[list[Finding], list[Evidence]]:
    """Deterministic, non-scanner-dependent checks derived purely from the
    httpx fingerprint: missing security headers and insecure cookies. These
    are flagged `suspected` the same as any other finding here — header
    *absence* is good signal but still goes through the same validation
    gate as everything else, for consistency rather than because it's
    inherently uncertain."""
    findings: list[Finding] = []
    evidence: list[Evidence] = []

    if result.error:
        return findings, evidence

    present_lower = {h.lower() for h in result.headers}
    missing = [h for h in MISSING_SECURITY_HEADERS if h not in present_lower]
    if missing:
        finding_id = _new_id("WEB")
        evidence_id = _new_id("EVIDENCE")
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                evidence_type="http_response",
                source_tool="httpx",
                description=f"Response headers observed for {result.final_url}",
                raw_data={"headers": result.headers, "missing": missing},
            )
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                assessment_id=assessment_id,
                agent_id=AgentId.WEB_SECURITY,
                surface=Surface.WEB,
                asset_id=asset_id,
                affected_url=result.final_url,
                title=f"Missing security headers: {', '.join(missing)}",
                description=(
                    "The response did not include the following recommended security "
                    f"headers: {', '.join(missing)}."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence_refs=[evidence_id],
                remediation="Configure the web server/application to emit the missing headers.",
                ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                detection_method="httpx_header_analysis",
            )
        )

    for cookie in result.cookies:
        if not cookie.get("secure") or not cookie.get("httponly"):
            finding_id = _new_id("WEB")
            evidence_id = _new_id("EVIDENCE")
            problems = []
            if not cookie.get("secure"):
                problems.append("missing Secure flag")
            if not cookie.get("httponly"):
                problems.append("missing HttpOnly flag")
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    finding_id=finding_id,
                    evidence_type="http_response",
                    source_tool="httpx",
                    description=f"Cookie {cookie.get('name')!r} observed on {result.final_url}",
                    raw_data=cookie,
                )
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    agent_id=AgentId.WEB_SECURITY,
                    surface=Surface.WEB,
                    asset_id=asset_id,
                    affected_url=result.final_url,
                    title=f"Insecure cookie attributes on '{cookie.get('name')}'",
                    description=f"Cookie '{cookie.get('name')}' is {', '.join(problems)}.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_refs=[evidence_id],
                    remediation="Set Secure and HttpOnly on session/auth cookies.",
                    ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                    detection_method="httpx_cookie_analysis",
                )
            )

    return findings, evidence


def findings_from_zap_alerts(
    alerts: Iterable[ZapAlert], *, assessment_id: str, asset_id: str
) -> tuple[list[Finding], list[Evidence]]:
    """Every ZAP alert is suspected until independently validated — a scanner
    alert is signal, not proof. Active-rule alerts are still `suspected`:
    ZAP's own confidence rating informs `confidence`, not `status`."""
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for alert in alerts:
        finding_id = _new_id("WEB")
        evidence_id = _new_id("EVIDENCE")
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                finding_id=finding_id,
                evidence_type="zap_alert",
                source_tool="owasp_zap",
                description=f"ZAP alert {alert.plugin_id} ({alert.name}) on {alert.url}",
                raw_data={
                    "plugin_id": alert.plugin_id,
                    "evidence": alert.evidence,
                    "cwe_id": alert.cwe_id,
                    "is_active_rule": alert.is_active_rule,
                },
            )
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                assessment_id=assessment_id,
                agent_id=AgentId.WEB_SECURITY,
                surface=Surface.WEB,
                asset_id=asset_id,
                affected_url=alert.url,
                parameter=alert.param,
                title=alert.name,
                description=alert.description or alert.name,
                severity=_ZAP_RISK_TO_SEVERITY.get(alert.risk, Severity.INFO),
                confidence=_ZAP_CONFIDENCE_TO_OURS.get(alert.confidence, Confidence.LOW),
                evidence_refs=[evidence_id],
                remediation=alert.solution or None,
                ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                detection_method="zap_active_scan" if alert.is_active_rule else "zap_passive_scan",
            )
        )
    return findings, evidence


def findings_from_discovered_endpoints(
    endpoints: Iterable[DiscoveredEndpoint], *, assessment_id: str, asset_id: str
) -> tuple[list[Finding], list[Evidence]]:
    """Katana finds real endpoints a plain fingerprint of the root page never sees -- until now, that
    discovery fed only report metadata (`discovered_endpoints`) and never became a Finding, unlike Ghidra's
    static_analysis.py, which flags its own signal. This is the Web Agent's equivalent: a generic,
    site-independent heuristic over each endpoint's own query-parameter NAMES (never their values, never page
    content), flagging one `suspected`, low-confidence finding per matching parameter per endpoint -- a
    starting point for manual review, exactly like the binary agent's unsafe-function flags, never a claim
    that the parameter is actually exploitable."""
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()  # (url-without-query, param) -- one finding per distinct (endpoint, param)

    for ep in endpoints:
        query = parse_qs(urlsplit(ep.url).query)
        for param in query:
            if param.lower() not in _FILE_READ_PARAM_NAMES:
                continue
            base_url = ep.url.split("?", 1)[0]
            key = (base_url, param.lower())
            if key in seen:
                continue
            seen.add(key)

            finding_id = _new_id("WEB")
            evidence_id = _new_id("EVIDENCE")
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    finding_id=finding_id,
                    evidence_type="discovered_endpoint",
                    source_tool="katana",
                    description=f"Endpoint discovered by Katana with a file-read-shaped parameter: {ep.url}",
                    raw_data={"url": ep.url, "method": ep.method, "parameter": param},
                )
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    agent_id=AgentId.WEB_SECURITY,
                    surface=Surface.WEB,
                    asset_id=asset_id,
                    affected_url=ep.url,
                    parameter=param,
                    title=f"Potential local file inclusion / path traversal parameter '{param}'",
                    description=(
                        f"The endpoint {base_url!r} was discovered with a query parameter named {param!r}, a "
                        "name generically associated with a server reading a file named by the request "
                        "(local file inclusion / path traversal). This does not by itself prove the parameter "
                        "is exploitable -- it is flagged for manual review of whether its value controls a "
                        "file path and whether that path is validated."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    evidence_refs=[evidence_id],
                    remediation="Review whether this parameter's value reaches a filesystem read, and if so, "
                    "validate it against an allow-list rather than passing it through unchecked.",
                    ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
                    detection_method="katana_endpoint_param_heuristic",
                )
            )
    return findings, evidence
