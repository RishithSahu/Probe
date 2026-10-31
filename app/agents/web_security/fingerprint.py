"""Stage A: application fingerprinting via httpx.

Every request made here goes through the ScopeGuard first. This module never
follows a redirect without checking it, never retries past the configured
timeout, and never touches an origin outside the policy's approved list.
"""
from __future__ import annotations

import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.scope_guard import ScopeGuard

SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie"}


@dataclass
class FingerprintResult:
    url: str
    final_url: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    server_header: str | None = None
    powered_by_header: str | None = None
    tls_version: str | None = None
    tls_cert_subject: str | None = None
    response_time_ms: float | None = None
    error: str | None = None


def _redact_headers(headers: httpx.Headers) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        out[k] = "[redacted]" if k.lower() in SENSITIVE_HEADER_NAMES else v
    return out


def _inspect_cookies(response: httpx.Response) -> list[dict[str, Any]]:
    cookies = []
    for name, value in response.cookies.items():
        set_cookie_headers = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]
        raw = set_cookie_headers[0] if set_cookie_headers else ""
        cookies.append(
            {
                "name": name,
                "secure": "secure" in raw.lower(),
                "httponly": "httponly" in raw.lower(),
                "samesite": next(
                    (p.split("=", 1)[1].strip() for p in raw.split(";") if p.strip().lower().startswith("samesite=")),
                    None,
                ),
            }
        )
    return cookies


def _tls_metadata(response: httpx.Response) -> tuple[str | None, str | None]:
    try:
        network_stream = response.extensions.get("network_stream")
        ssl_object = network_stream.get_extra_info("ssl_object") if network_stream else None
        if ssl_object is None:
            return None, None
        version = ssl_object.version()
        cert = ssl_object.getpeercert()
        subject = None
        if cert:
            subject_parts = cert.get("subject", ())
            subject = ", ".join(f"{k}={v}" for part in subject_parts for k, v in part)
        return version, subject
    except Exception:  # noqa: BLE001 - TLS introspection is best-effort only
        return None, None


def fingerprint_url(
    url: str,
    *,
    asset_id: str,
    scope_guard: ScopeGuard,
    timeout_seconds: float = 10.0,
) -> FingerprintResult:
    """Perform a single, read-only GET against `url` and collect metadata.
    Never submits forms, never authenticates, never bypasses TLS verification
    (cert errors surface as `error`, they are not silently ignored)."""
    scope_guard.check_passive_web_analysis_allowed(asset_id, url)

    redirect_chain: list[str] = []
    start = time.monotonic()
    try:
        with httpx.Client(timeout=timeout_seconds, verify=True, follow_redirects=False) as client:
            current_url = url
            response: httpx.Response | None = None
            for _ in range(10):  # hard cap independent of policy, avoids infinite loops
                response = client.get(current_url)
                if response.is_redirect:
                    next_url = str(response.headers.get("location", ""))
                    if not next_url:
                        break
                    next_url = str(httpx.URL(current_url).join(next_url))
                    scope_guard.check_redirect_allowed(current_url, next_url)
                    redirect_chain.append(current_url)
                    current_url = next_url
                    continue
                break
            assert response is not None
            elapsed_ms = (time.monotonic() - start) * 1000
            tls_version, tls_subject = _tls_metadata(response)
            return FingerprintResult(
                url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                headers=_redact_headers(response.headers),
                redirect_chain=redirect_chain,
                cookies=_inspect_cookies(response),
                server_header=response.headers.get("server"),
                powered_by_header=response.headers.get("x-powered-by"),
                tls_version=tls_version,
                tls_cert_subject=tls_subject,
                response_time_ms=elapsed_ms,
            )
    except ssl.SSLError as exc:
        return FingerprintResult(url=url, final_url=url, error=f"TLS error: {exc}")
    except httpx.HTTPError as exc:
        return FingerprintResult(url=url, final_url=url, error=f"HTTP error: {exc}")
