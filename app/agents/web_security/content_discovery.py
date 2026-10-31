"""Generic, bounded hidden-path content discovery -- RESOURCE DISCOVERY ONLY.

A plain crawler (Stage B) only follows links it can already see. Some content is deliberately not linked
anywhere -- the only way to find it is to ask for candidate paths directly and see which ones diverge from how
the application answers a path it has never heard of. This module does exactly that, nothing more:

  * builds one baseline response (a path that is certainly meaningless) per target, once
  * asks a small, generic recon wordlist -- not tied to any one application, challenge, or target
  * a candidate only "hits" if its (status, redirect-or-not, content length) DIFFERS from the baseline --
    never merely "not 404", since many frameworks never return a 404 for an unmatched path at all
  * every candidate goes through the same ScopeGuard check as any other web request, and the whole sweep is
    hard-capped and rate-limited by policy

This module never extracts a credential from anything it sees -- no page text, no header, no banner. When a
hit's response looks like it might be a binary file (content-type or magic bytes), it is reported as a
*reference* (URL + why it looks binary) for the Orchestrator to hand to the Binary Analysis Agent, which owns
acquisition and is the only place a credential-shaped finding may legitimately come from. This module never
downloads or retains the file's bytes itself.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

from app.core.exceptions import ScopeViolationError
from app.core.scope_guard import ScopeGuard

# Generic recon wordlist: common content-discovery terms seen across unrelated applications, not written for
# (or derived from) any one target.
GENERIC_WORDLIST: tuple[str, ...] = (
    "vault", "artifacts", "artifact", "build", "builds", "release", "releases", "dist", "bin", "binaries",
    "files", "downloads", "download", "backup", "backups", "old", "archive", "archives", "storage",
    "admin", "config", "configs", "secret", "secrets", "private", "internal", "hidden", "staging", "dev",
    "test", "tmp", "data", "assets", "static", "uploads", "src", ".git", ".env", "api", "docs",
)

_BINARY_CONTENT_TYPES = (
    "application/octet-stream", "application/x-executable", "application/x-elf",
    "application/x-msdownload", "application/vnd.microsoft.portable-executable",
)
_BINARY_MAGIC = (b"\x7fELF", b"MZ")
# Only enough of the body is ever inspected to decide "does this look binary" -- never retained, never scanned
# for content, and never the source of a credential.
_SNIFF_BYTES = 8


@dataclass
class DiscoveredPath:
    path: str
    url: str
    status_code: int
    content_length: int
    is_binary_reference: bool = False


@dataclass
class BinaryReference:
    """A URL this sweep believes serves a binary file, for the Orchestrator to hand to the Binary Analysis
    Agent. No bytes travel with this -- acquisition is that agent's own responsibility."""
    asset_id: str
    url: str
    content_type: str | None
    content_length: int
    reason: str


@dataclass
class ContentDiscoveryResult:
    base_url: str
    baseline_status: int | None = None
    requests_made: int = 0
    hits: list[DiscoveredPath] = field(default_factory=list)
    binary_references: list[BinaryReference] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _looks_binary(headers: httpx.Headers, body_prefix: bytes) -> bool:
    ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype in _BINARY_CONTENT_TYPES:
        return True
    return any(body_prefix.startswith(magic) for magic in _BINARY_MAGIC)


def _signature(resp: httpx.Response) -> tuple:
    """What makes two responses "the same" for baseline-diff purposes: same status, same redirect-or-not (the
    exact echoed path inside a catch-all redirect target always legitimately differs and must not itself count
    as a difference), and same content length."""
    has_redirect = resp.headers.get("location") is not None
    return (resp.status_code, has_redirect, len(resp.content))


def discover_hidden_paths(
    base_url: str,
    *,
    asset_id: str,
    scope_guard: ScopeGuard,
    max_requests: int,
    rate_per_second: float,
    wordlist: tuple[str, ...] = GENERIC_WORDLIST,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: float = 6.0,
) -> ContentDiscoveryResult:
    """`extra_headers`, if given, is applied to every request made here -- it is the CALLER's job to source any
    such header from an already-recorded, explicit authorisation (e.g. a method_grant), never invented here."""
    base = base_url.rstrip("/")
    result = ContentDiscoveryResult(base_url=base_url)
    gap = 1.0 / rate_per_second if rate_per_second > 0 else 0.0

    try:
        scope_guard.check_content_discovery_allowed(asset_id, base_url)
    except ScopeViolationError as exc:
        result.errors.append(str(exc))
        return result

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False, headers=extra_headers or {}) as client:
        baseline_path = f"__ape_content_discovery_baseline__{int(time.time())}"
        try:
            baseline_resp = client.get(f"{base}/{baseline_path}")
            baseline_sig = _signature(baseline_resp)
            result.baseline_status = baseline_resp.status_code
        except httpx.HTTPError as exc:
            result.errors.append(f"baseline request failed: {exc}")
            return result
        result.requests_made += 1

        for term in wordlist:
            if result.requests_made >= max_requests:
                result.errors.append(f"stopped at max_requests={max_requests}: wordlist not exhausted")
                break
            url = f"{base}/{term}"
            try:
                scope_guard.check_content_discovery_allowed(asset_id, url)
            except ScopeViolationError as exc:
                result.errors.append(f"{url}: {exc}")
                continue
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                result.errors.append(f"{url}: {exc}")
                time.sleep(gap)
                continue
            result.requests_made += 1
            if _signature(resp) != baseline_sig:
                hit = DiscoveredPath(path=term, url=url, status_code=resp.status_code, content_length=len(resp.content))
                if _looks_binary(resp.headers, resp.content[:_SNIFF_BYTES]):
                    hit.is_binary_reference = True
                    ctype = resp.headers.get("content-type")
                    reason = f"content-type {ctype!r}" if ctype in _BINARY_CONTENT_TYPES else "binary magic bytes at start of body"
                    result.binary_references.append(
                        BinaryReference(asset_id=asset_id, url=url, content_type=ctype,
                                        content_length=len(resp.content), reason=reason)
                    )
                result.hits.append(hit)
            time.sleep(gap)

    return result
