"""Deterministic re-verification of network_vulnerability protocol-check findings.

Mirrors app.analysis.evidence_validator's own httpx_header_analysis/httpx_cookie_analysis replay checks
(_supports_deterministic_check): a finding's detection_method label is never trusted on its own for
auto-confirmation -- the raw protocol observation recorded as evidence is re-derived against the exact
condition app.agents.network_vulnerability.checks.py used to flag it in the first place, so a finding can
only auto-confirm if its own evidence still proves the claim on replay, not merely because of what it
says it is.
"""
from __future__ import annotations

from app.core.schemas import Evidence, Finding

_CHECK_FOR_METHOD = {
    "network_vulnerability:ssh_protocol_version": "ssh_protocol_version",
    "network_vulnerability:ftp_anonymous_login": "ftp_anonymous_login",
    "network_vulnerability:redis_auth_check": "redis_auth_check",
    "network_vulnerability:postgresql_auth_check": "postgresql_auth_check",
}


def supports_protocol_observation(finding: Finding, evidence: Evidence) -> bool:
    """Recheck the observation instead of trusting a method label alone. See
    app/agents/network_vulnerability/checks.py for exactly what each of these conditions guards -- the
    same live check that originally produced this evidence's raw_data."""
    check_name = _CHECK_FOR_METHOD.get(finding.detection_method or "")
    if check_name is None or evidence.evidence_type != f"network_vulnerability:{check_name}":
        return False
    data = evidence.raw_data or {}
    if check_name == "ssh_protocol_version":
        return isinstance(data.get("banner"), str) and data["banner"].startswith("SSH-1.")
    if check_name == "ftp_anonymous_login":
        return isinstance(data.get("pass_response"), str) and data["pass_response"].startswith("230")
    if check_name == "redis_auth_check":
        return isinstance(data.get("response"), str) and data["response"].startswith("+PONG")
    if check_name == "postgresql_auth_check":
        return data.get("auth_code") == 0
    return False
