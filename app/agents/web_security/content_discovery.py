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

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

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


# Generic access-control-bypass probe: well-known headers a reverse proxy commonly uses to convey the
# ORIGINAL client address, and well-known candidate values for "an address this origin might treat as
# trusted" -- this is OWASP's own documented technique for testing whether access control is actually
# enforced server-side or merely trusts a client-controllable header, not anything written for one target.
TRUSTED_PROXY_HEADERS: tuple[str, ...] = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "Client-IP", "True-Client-IP")
_GENERIC_TRUSTED_IP_CANDIDATES: tuple[str, ...] = ("127.0.0.1", "localhost", "0.0.0.0")


def _likely_gateway(ip: str) -> str | None:
    """"<network>.1" is a near-universal default-gateway convention for an IPv4 /24 -- a GENERIC candidate
    for "an address this origin might treat as trusted" (the same reasoning a human tester would apply),
    not anything specific to one target's actual topology."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    return ".".join([*parts[:3], "1"])


@dataclass
class AccessControlBypassHit:
    header: str
    value: str
    status_code: int
    content_length: int


@dataclass
class AccessControlBypassResult:
    base_url: str
    hits: list[AccessControlBypassHit] = field(default_factory=list)
    requests_made: int = 0
    errors: list[str] = field(default_factory=list)


def discover_via_trusted_proxy_headers(
    base_url: str, *, asset_id: str, asset_ip: str | None, scope_guard: ScopeGuard,
    rate_per_second: float, timeout_seconds: float = 6.0,
) -> AccessControlBypassResult:
    """Tries each (header, value) pair from TRUSTED_PROXY_HEADERS x the generic IP candidates against the
    SAME base_url, comparing each response's signature to the plain baseline (no extra header at all). A
    DIFFERENT signature is evidence the origin's own access control is driven by a spoofable header --
    reported here as hits; this function never acts on a hit itself (e.g. by re-crawling under the
    winning header) -- that decision belongs to the caller, same separation as this module's own
    binary-reference reporting never acquiring the binary itself."""
    result = AccessControlBypassResult(base_url=base_url)
    gap = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
    try:
        scope_guard.check_content_discovery_allowed(asset_id, base_url)
    except ScopeViolationError as exc:
        result.errors.append(str(exc))
        return result

    candidates = list(_GENERIC_TRUSTED_IP_CANDIDATES)
    gateway = _likely_gateway(asset_ip) if asset_ip else None
    if gateway:
        candidates.append(gateway)

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        try:
            baseline_resp = client.get(base_url)
            baseline_sig = _signature(baseline_resp)
        except httpx.HTTPError as exc:
            result.errors.append(f"baseline request failed: {exc}")
            return result
        result.requests_made += 1

        for header in TRUSTED_PROXY_HEADERS:
            for value in candidates:
                try:
                    resp = client.get(base_url, headers={header: value})
                except httpx.HTTPError as exc:
                    result.errors.append(f"{header}={value}: {exc}")
                    time.sleep(gap)
                    continue
                result.requests_made += 1
                if _signature(resp) != baseline_sig:
                    result.hits.append(AccessControlBypassHit(
                        header=header, value=value, status_code=resp.status_code, content_length=len(resp.content),
                    ))
                time.sleep(gap)
    return result


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


_HREF_PATTERN = re.compile(r'''href=["']([^"'#?]+)''', re.IGNORECASE)
_MAX_LISTING_FOLLOW_UPS = 20


def _follow_listing_and_check_children(
    client: httpx.Client, *, hit_url: str, location: str, scope_guard: ScopeGuard, asset_id: str,
    result: "ContentDiscoveryResult", max_requests: int, gap: float,
) -> None:
    """A wordlist hit that turns out to be a directory (a 3xx redirect, almost always to the same path
    with a trailing slash -- e.g. "/vault" -> "/vault/") is a dead end on its own: this function never
    knows the directory's own listing contains anything until it actually reads it. Follows that ONE
    redirect, reads the listing page, and checks every link it finds that stays under the same directory
    (never an unrelated nav link elsewhere on the site) with the exact same binary-looking test the plain
    wordlist sweep already applies -- generalised "found a directory -> read its listing -> check what's
    in it," not specific to any one application's listing format."""
    if result.requests_made >= max_requests:
        return
    listing_url = urljoin(hit_url if hit_url.endswith("/") else hit_url + "/", location)
    try:
        scope_guard.check_content_discovery_allowed(asset_id, listing_url)
        listing_resp = client.get(listing_url)
    except (ScopeViolationError, httpx.HTTPError) as exc:
        result.errors.append(f"{listing_url}: could not follow directory listing: {exc}")
        return
    result.requests_made += 1
    if listing_resp.status_code >= 400:
        return

    listing_dir = listing_url if listing_url.endswith("/") else listing_url + "/"
    listing_path = urlsplit(listing_dir).path
    seen_children: set[str] = set()
    checked = 0
    for href in _HREF_PATTERN.findall(listing_resp.text):
        if checked >= _MAX_LISTING_FOLLOW_UPS or result.requests_made >= max_requests:
            break
        child_url = urljoin(listing_dir, href)
        child_path = urlsplit(child_url).path
        # Only a direct child of the listing's own directory -- never a parent/sibling nav link ("..",
        # "/", a totally different section of the site) that a real directory-listing page always has too.
        if not child_path.startswith(listing_path) or child_path == listing_path or child_url in seen_children:
            continue
        seen_children.add(child_url)
        try:
            scope_guard.check_content_discovery_allowed(asset_id, child_url)
            child_resp = client.get(child_url)
        except (ScopeViolationError, httpx.HTTPError) as exc:
            result.errors.append(f"{child_url}: {exc}")
            continue
        result.requests_made += 1
        checked += 1
        if _looks_binary(child_resp.headers, child_resp.content[:_SNIFF_BYTES]):
            ctype = child_resp.headers.get("content-type")
            reason = f"content-type {ctype!r}" if ctype in _BINARY_CONTENT_TYPES else "binary magic bytes at start of body"
            result.binary_references.append(BinaryReference(
                asset_id=asset_id, url=child_url, content_type=ctype,
                content_length=len(child_resp.content), reason=reason,
            ))
            result.hits.append(DiscoveredPath(path=child_path, url=child_url, status_code=child_resp.status_code,
                                              content_length=len(child_resp.content), is_binary_reference=True))
        time.sleep(gap)


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
                location = resp.headers.get("location")
                if location and 300 <= resp.status_code < 400:
                    # A redirect hit is almost always "this is a real directory" -- see
                    # _follow_listing_and_check_children's own docstring for why this sweep would otherwise
                    # stop at "found a directory" and never learn what's actually in it.
                    _follow_listing_and_check_children(
                        client, hit_url=url, location=location, scope_guard=scope_guard, asset_id=asset_id,
                        result=result, max_requests=max_requests, gap=gap,
                    )
            time.sleep(gap)

    return result
