"""Stage C: security assessment via OWASP ZAP.

Talks to a running ZAP instance over its REST API (the `zap` Docker Compose
service). Passive scanning (header/cookie/info-disclosure analysis of traffic
ZAP observes as it's proxied through, or of pages it's told to open) runs
whenever `allow_passive_web_analysis` is set. Active scan rules — the ones
that actually send attack payloads — only run when
`allow_active_web_verification` is explicitly set, and even then only against
URLs the Scope Guard has already approved; this function re-checks that
immediately before triggering the active scan, not just at task setup.

When ZAP is unreachable and `settings.web_agent_use_fixtures` is set, a
documented synthetic alert set is returned so finding-generation and
reporting can be developed/tested without a live ZAP instance.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.config import settings
from app.core.exceptions import ToolExecutionError
from app.core.scope_guard import ScopeGuard

logger = logging.getLogger("ape.web_agent.zap")

# ZAP passive scanner "riskcode": 0=Informational 1=Low 2=Medium 3=High
_RISK_TO_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}
_CONFIDENCE_TO_OURS = {0: "low", 1: "low", 2: "medium", 3: "high"}  # ZAP confidence 0-3


@dataclass
class ZapAlert:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    param: str | None
    description: str
    solution: str
    evidence: str | None
    cwe_id: str | None = None
    is_active_rule: bool = False


@dataclass
class ZapScanResult:
    alerts: list[ZapAlert] = field(default_factory=list)
    used_fixture: bool = False
    active_scan_run: bool = False
    error: str | None = None


class ZapClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 30.0):
        self.base_url = (base_url or settings.zap_api_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.zap_api_key
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}{path}", params=params)
            resp.raise_for_status()
            return resp.json()

    def is_available(self) -> bool:
        """Short, fixed timeout regardless of the client's configured
        operation timeout — this is just a liveness probe, so a slow/absent
        ZAP shouldn't stall task startup waiting on the full timeout."""
        try:
            params = {"apikey": self.api_key} if self.api_key else {}
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"{self.base_url}/JSON/core/view/version/", params=params)
                resp.raise_for_status()
            return True
        except Exception:  # noqa: BLE001
            return False

    def open_url(self, url: str) -> None:
        """Passive: have ZAP's spider-less 'access URL' fetch and passively
        analyse one page, populating its alert store without active attacks."""
        self._get("/JSON/core/action/accessUrl/", {"url": url})

    def wait_for_passive_scan(self, poll_interval: float = 1.0, max_wait: float = 30.0) -> None:
        waited = 0.0
        while waited < max_wait:
            status = self._get("/JSON/pscan/view/recordsToScan/")
            if int(status.get("recordsToScan", 0)) == 0:
                return
            time.sleep(poll_interval)
            waited += poll_interval

    def alerts_for_url(self, url: str) -> list[dict[str, Any]]:
        data = self._get("/JSON/core/view/alerts/", {"baseurl": url})
        return data.get("alerts", [])

    def start_active_scan(self, url: str) -> str:
        # `scanPolicyName` restricts active scanning to a pre-defined,
        # non-destructive rule set (see settings.zap_active_scan_policy_name
        # and README.md) rather than ZAP's full default rule set, which
        # includes some noisier/DoS-adjacent rules we never want to run here.
        data = self._get(
            "/JSON/ascan/action/scan/",
            {
                "url": url, "recurse": "false", "inScopeOnly": "true",
                "scanPolicyName": settings.zap_active_scan_policy_name,
            },
        )
        return str(data.get("scan"))

    def active_scan_status(self, scan_id: str) -> int:
        data = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(data.get("status", 0))

    def wait_for_active_scan(self, scan_id: str, poll_interval: float = 2.0, max_wait: float = 300.0) -> None:
        waited = 0.0
        while waited < max_wait:
            if self.active_scan_status(scan_id) >= 100:
                return
            time.sleep(poll_interval)
            waited += poll_interval
        raise ToolExecutionError(f"ZAP active scan {scan_id} did not complete within {max_wait}s")


def _to_zap_alert(raw: dict[str, Any], *, is_active_rule: bool = False) -> ZapAlert:
    risk = str(raw.get("risk", "Informational")).lower()
    confidence = str(raw.get("confidence", "Low")).lower()
    return ZapAlert(
        plugin_id=str(raw.get("pluginId", raw.get("alertRef", "0"))),
        name=raw.get("alert") or raw.get("name", "Unknown ZAP alert"),
        risk=risk,
        confidence=confidence,
        url=raw.get("url", ""),
        param=raw.get("param") or None,
        description=raw.get("description", ""),
        solution=raw.get("solution", ""),
        evidence=raw.get("evidence") or None,
        cwe_id=str(raw.get("cweid")) if raw.get("cweid") else None,
        is_active_rule=is_active_rule,
    )


def _synthetic_alerts(base_url: str) -> list[ZapAlert]:
    """Documented fixture standing in for a live ZAP passive scan — a small
    set of plausible passive findings (missing security headers, a
    permissive cookie) seen against a typical demo app."""
    return [
        ZapAlert(
            plugin_id="10038",
            name="Content Security Policy (CSP) Header Not Set",
            risk="medium",
            confidence="high",
            url=base_url,
            param=None,
            description="No Content-Security-Policy header was found in the response.",
            solution="Configure a restrictive Content-Security-Policy header.",
            evidence=None,
            cwe_id="693",
        ),
        ZapAlert(
            plugin_id="10020",
            name="X-Frame-Options Header Not Set",
            risk="low",
            confidence="medium",
            url=base_url,
            param=None,
            description="X-Frame-Options header is not set, risking clickjacking.",
            solution="Set X-Frame-Options: DENY or SAMEORIGIN.",
            evidence=None,
            cwe_id="1021",
        ),
        ZapAlert(
            plugin_id="10054",
            name="Cookie Without SameSite Attribute",
            risk="low",
            confidence="medium",
            url=f"{base_url.rstrip('/')}/login",
            param="session",
            description="A cookie was set without the SameSite attribute.",
            solution="Set SameSite=Strict or Lax on session cookies.",
            evidence="Set-Cookie: session=...",
            cwe_id="1275",
        ),
    ]


def run_passive_scan(
    url: str,
    *,
    asset_id: str,
    scope_guard: ScopeGuard,
    client: ZapClient | None = None,
) -> ZapScanResult:
    scope_guard.check_passive_web_analysis_allowed(asset_id, url)
    client = client or ZapClient()

    if not client.is_available():
        if settings.web_agent_use_fixtures:
            logger.info("ZAP unreachable at %s; using synthetic passive-alert fixture", client.base_url)
            return ZapScanResult(alerts=_synthetic_alerts(url), used_fixture=True)
        return ZapScanResult(error=f"ZAP unavailable at {client.base_url} and fixtures disabled")

    try:
        client.open_url(url)
        client.wait_for_passive_scan()
        raw_alerts = client.alerts_for_url(url)
        alerts = [_to_zap_alert(a) for a in raw_alerts]
        return ZapScanResult(alerts=alerts, used_fixture=False)
    except httpx.HTTPError as exc:
        raise ToolExecutionError(f"ZAP passive scan failed for {url}: {exc}") from exc


def run_active_scan_if_authorised(
    url: str,
    *,
    asset_id: str,
    scope_guard: ScopeGuard,
    client: ZapClient | None = None,
) -> ZapScanResult:
    """No-op unless `allow_active_web_verification` is explicitly enabled.
    Active scan rules send real payloads (non-destructive by ZAP policy
    configuration) — never brute force, never DoS, never data exfiltration
    rules; `settings.zap_active_scan_policy_name` selects a ZAP scan policy
    (created in advance via the ZAP UI/API — see README.md) that excludes
    those rule categories from the enabled set."""
    scope_guard.check_active_web_verification_allowed(asset_id, url)  # raises if disabled
    client = client or ZapClient()

    if not client.is_available():
        if settings.web_agent_use_fixtures:
            logger.info("ZAP unreachable; active scan skipped, returning empty fixture result")
            return ZapScanResult(alerts=[], used_fixture=True, active_scan_run=False)
        return ZapScanResult(error=f"ZAP unavailable at {client.base_url}", active_scan_run=False)

    scan_id = client.start_active_scan(url)
    client.wait_for_active_scan(scan_id)
    raw_alerts = client.alerts_for_url(url)
    alerts = [_to_zap_alert(a, is_active_rule=True) for a in raw_alerts]
    return ZapScanResult(alerts=alerts, used_fixture=False, active_scan_run=True)
