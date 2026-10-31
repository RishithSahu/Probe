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
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

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


def _parse_katana_jsonl(output: str) -> list[DiscoveredEndpoint]:
    """Katana's `-jsonl` output is one JSON object per line, each with at
    least an `endpoint`/`url` field and optionally a `request`/`response`
    block describing method/params/forms. Parsed defensively since output
    shape can vary slightly across Katana versions."""
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
        url = record.get("endpoint") or record.get("url")
        if not url:
            continue
        request = record.get("request", {}) or {}
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

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"katana_{asset_id}.jsonl"

    # Fixed, validated argument list — never a shell string. `-d` bounds crawl
    # depth, `-rl` bounds request rate, `-silent`/`-jsonl` give us structured,
    # parseable output. No flag here allows following out-of-scope hosts;
    # scope is enforced redundantly by the Scope Guard on every discovered
    # URL below, not just trusted to Katana's own host-matching.
    args = [
        settings.katana_binary,
        "-u", base_url,
        "-d", str(depth),
        "-rl", str(max(1, int(rate_per_second))),
        "-jc",  # include form/query-param-bearing endpoints
        "-silent",
        "-jsonl",
    ]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=max(30.0, depth * 30.0), check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"katana timed out crawling {base_url}") from exc

    if proc.returncode != 0 and not proc.stdout:
        raise ToolExecutionError(f"katana exited {proc.returncode} crawling {base_url}: {proc.stderr[:500]}")

    out_file.write_text(proc.stdout, encoding="utf-8")
    endpoints = _parse_katana_jsonl(proc.stdout)

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
