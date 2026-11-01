"""Stage B: endpoint discovery via Katana.

Katana is invoked as a subprocess with a fixed, validated argument list (never
a shell string built from untrusted input) and with explicit host/origin
restrictions passed to the tool itself as a second line of defence behind the
Scope Guard. If the `katana` binary is not present on PATH (true for most dev
machines and this hackathon sandbox), and
`settings.web_agent_use_fixtures` is enabled, a documented synthetic endpoint
set is returned instead so the rest of the pipeline can be built and tested.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import settings
from app.core.exceptions import ToolExecutionError
from app.core.scope_guard import ScopeGuard

logger = logging.getLogger("ape.web_agent.crawler")


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    source: str = "katana"
    forms: list[dict] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    is_api_like: bool = False


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    used_fixture: bool = False
    raw_output_path: str | None = None
    error: str | None = None


def _katana_available() -> bool:
    return shutil.which(settings.katana_binary) is not None


def _origin_scope_regex(base_url: str) -> str:
    """Restrict this crawl to its one authorised origin, including port.

    Only RE2-compatible constructs are used, since Katana uses Go regexps.
    Host suffixes, userinfo, alternate schemes and ports cannot match.
    """
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ToolExecutionError("Crawler requires an HTTP(S) origin without URL credentials")
    host = parsed.hostname.encode("idna").decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port if parsed.port is not None else default_port
    if port == 0:
        raise ToolExecutionError("Crawler requires a non-zero TCP port")
    port_pattern = f"(:{port})?" if port == default_port else f":{port}"
    return rf"(?i)^{re.escape(parsed.scheme)}://{re.escape(host)}{port_pattern}(/|\?|#|$)"


def _check_scope_capabilities() -> None:
    """Fail before crawling if the installed tool cannot enforce these flags."""
    try:
        result = subprocess.run(
            [settings.katana_binary, "-h"], capture_output=True, text=True, timeout=5, check=False,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolExecutionError("Could not verify Katana scope and redirect controls") from exc
    help_text = result.stdout + result.stderr
    if result.returncode != 0 or not all(flag in help_text for flag in ("-crawl-scope", "-disable-redirects")):
        raise ToolExecutionError("Installed Katana does not advertise required scope and redirect controls; crawl not started")


def _parse_katana_jsonl(output: str) -> list[DiscoveredEndpoint]:
    """Katana's `-jsonl` output is one JSON object per line. Real output (verified
    against katana v1.8.0) nests the URL under `request.endpoint`/`request.url`,
    not at the top level — a top-level `endpoint`/`url` key is also accepted for
    forward/backward compatibility with other Katana versions, but checked second
    so it never silently shadows the real field. BUG FIX: this previously only
    checked the top-level keys, which don't exist in real katana output at all —
    every real crawl silently parsed to zero endpoints, with no error anywhere,
    while a fixture-fallback crawl (whose synthetic records DO use a top-level
    `url` key) parsed fine, making the bug invisible without a real katana binary
    to test against."""
    endpoints: list[DiscoveredEndpoint] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("skipping unparseable katana output line")
            continue
        request = record.get("request", {}) or {}
        url = request.get("endpoint") or request.get("url") or record.get("endpoint") or record.get("url")
        if not url:
            continue
        method = request.get("method", "GET")
        query_params = []
        if "?" in url:
            query_string = url.split("?", 1)[1]
            query_params = [p.split("=", 1)[0] for p in query_string.split("&") if p]
        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                method=method,
                query_params=query_params,
                is_api_like="/api/" in url or url.rstrip("/").endswith((".json", "/api")),
            )
        )
    return endpoints


def _synthetic_endpoints(base_url: str) -> list[DiscoveredEndpoint]:
    """Documented fixture: a representative small site map used whenever
    Katana is unavailable. See tests/fixtures/katana/sample_output.jsonl for
    the equivalent raw form."""
    base = base_url.rstrip("/")
    return [
        DiscoveredEndpoint(url=f"{base}/", method="GET", source="fixture"),
        DiscoveredEndpoint(url=f"{base}/login", method="GET", source="fixture",
                            forms=[{"action": "/login", "method": "POST", "fields": ["username", "password"]}]),
        DiscoveredEndpoint(url=f"{base}/search?q=test", method="GET", source="fixture", query_params=["q"]),
        DiscoveredEndpoint(url=f"{base}/api/v1/users", method="GET", source="fixture", is_api_like=True),
    ]


def crawl(
    base_url: str,
    *,
    asset_id: str,
    scope_guard: ScopeGuard,
    depth: int,
    rate_per_second: float,
    output_dir: Path,
) -> CrawlResult:
    scope_guard.check_crawl_allowed(asset_id, base_url)
    scope_guard.check_crawl_depth(depth)

    if not _katana_available():
        if settings.web_agent_use_fixtures:
            logger.info("katana binary not found; using synthetic fixture endpoints for %s", base_url)
            return CrawlResult(endpoints=_synthetic_endpoints(base_url), used_fixture=True)
        raise ToolExecutionError(f"katana binary {settings.katana_binary!r} not found on PATH and fixtures disabled")

    origin_scope = _origin_scope_regex(base_url)
    _check_scope_capabilities()

    output_dir.mkdir(parents=True, exist_ok=True)
    asset_key = sha256(asset_id.encode("utf-8")).hexdigest()[:16]
    out_file = output_dir / f"katana_{asset_key}_{uuid.uuid4().hex[:8]}.jsonl"

    # Fixed, validated argument list — never a shell string. `-d` bounds crawl
    # depth, `-rl` bounds request rate, `-silent`/`-jsonl` give us structured,
    # parseable output. No flag here allows following out-of-scope hosts;
    # scope is enforced redundantly by the Scope Guard on every discovered
    # URL below, not just trusted to Katana's own host-matching.
    #
    # BUG FIX: `-dr`/`-disable-redirects` previously sat alongside `-cs` here,
    # with the comment "redirects must not escape the origin before output
    # filtering" — but `-dr` disables following ANY redirect, in-scope or not,
    # not just out-of-scope ones; `-cs` (crawl-scope regex) already bounds
    # exactly that, on its own. The practical effect was that katana could
    # never crawl past a redirecting entry page (a common, unremarkable
    # pattern — this exact real lab target's own homepage 302s to
    # /index.php?p=), silently truncating every real crawl to one page. `-dr`
    # is removed; `-cs` alone keeps redirects from leaving the authorised
    # origin, and the Scope Guard re-checks every resulting URL regardless.
    args = [
        settings.katana_binary,
        "-u", base_url,
        "-d", str(depth),
        "-rl", str(max(1, int(rate_per_second))),
        "-cs", origin_scope,
        "-c", "1",
        "-p", "1",
        "-jc",  # include form/query-param-bearing endpoints
        "-silent",
        "-jsonl",
    ]
    # BUG FIX: the old formula (max(30, depth*30), ignoring rate_per_second) gave
    # 60s at depth=2 — a real crawl of a real, modestly-sized site at the default
    # rate (5 req/s) was independently measured at ~84s to complete, so this
    # silently timed out (raising ToolExecutionError, zero endpoints returned, no
    # crash) on realistic targets while passing every test against the fixture
    # fallback or a tiny fixture-shaped local server. Scaled by depth AND
    # inversely by rate (a slower, more polite crawl legitimately needs more
    # wall-clock time for the same page count); the depth=2/rate=5 baseline
    # keeps comfortable headroom over the measured 84s.
    timeout_seconds = max(120.0, depth * 90.0) * (5.0 / max(rate_per_second, 1.0))
    try:
        # BUG FIX: found against a real live target, invisible with any fixture/synthetic test data --
        # text=True without an explicit encoding uses the platform's default codec (cp1252 on Windows),
        # which raises UnicodeDecodeError the moment a real crawled page's JSONL output contains a
        # non-cp1252 byte (ordinary UTF-8 content from an actual website, not something a fixture would
        # ever contain). The error surfaced in subprocess's own internal reader thread, not here, so it
        # printed a traceback and silently produced truncated/empty stdout instead of raising
        # ToolExecutionError -- every subprocess.run() in this module needs an explicit encoding.
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_seconds, check=False,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolExecutionError(f"katana timed out crawling {base_url} after {timeout_seconds:.0f}s") from exc

    # Defensive guard for the same root cause the encoding= fix above addresses: before that fix,
    # proc.stdout could come back None (not "") if subprocess's own internal reader thread crashed with
    # UnicodeDecodeError before ever populating it -- write_text(None) then raised its own unrelated-
    # looking TypeError ("data must be str, not NoneType"), masking the real cause. Treated the same as
    # empty output now, which is itself still an honest ToolExecutionError below if returncode != 0.
    out_file.write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0:
        raise ToolExecutionError(f"katana exited {proc.returncode}; partial output retained at {out_file}")
    endpoints = _parse_katana_jsonl(proc.stdout or "")

    # Second line of defence: drop (and log) any endpoint Katana returned that
    # the Scope Guard would reject — handles the case where Katana's own host
    # filtering is misconfigured or bypassed by a redirect.
    in_scope: list[DiscoveredEndpoint] = []
    for ep in endpoints:
        try:
            scope_guard.check_web_target_in_scope(asset_id, ep.url)
            in_scope.append(ep)
        except Exception:  # noqa: BLE001
            logger.warning("dropping out-of-scope endpoint returned by katana: %s", ep.url)

    return CrawlResult(endpoints=in_scope, used_fixture=False, raw_output_path=str(out_file))
