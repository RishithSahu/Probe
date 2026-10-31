"""Binary acquisition -- the Binary Analysis Agent's own responsibility.

Per the project's explicit design: a Web Agent may discover and REPORT a reference to a binary resource, but
locating and fetching the actual bytes belongs to this agent, through an explicitly authorised source, so the
chain of custody for a finding's provenance (SHA-256, source URL) always traces back to this agent's own
fetch -- never to another agent's cached/opportunistic bytes.

One bounded, read-only GET per acquisition. The file is never executed, at any point.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.core.exceptions import ToolExecutionError
from app.core.scope_guard import ScopeGuard

MAX_BINARY_BYTES = 16 * 1024 * 1024  # 16 MiB: bounded regardless of what the server claims to be sending


@dataclass
class AcquiredBinary:
    source_url: str
    saved_path: Path
    sha256: str
    byte_count: int
    truncated: bool


def acquire_binary(
    url: str, *, asset_id: str, scope_guard: ScopeGuard, output_dir: Path, timeout_seconds: float = 10.0,
    extra_headers: dict[str, str] | None = None,
) -> AcquiredBinary:
    """`extra_headers`, if given, is the caller's job to source from an already-recorded authorisation --
    never invented here (see app/adapters/authorisation_grants.py)."""
    scope_guard.check_binary_acquisition_allowed(asset_id, url)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=False, headers=extra_headers or {}) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.content
    except httpx.HTTPError as exc:
        raise ToolExecutionError(f"could not acquire binary from {url}: {exc}") from exc

    truncated = len(data) > MAX_BINARY_BYTES
    data = data[:MAX_BINARY_BYTES]
    digest = hashlib.sha256(data).hexdigest()
    saved = output_dir / f"acquired_{digest[:16]}"
    saved.write_bytes(data)
    return AcquiredBinary(source_url=url, saved_path=saved, sha256=digest, byte_count=len(data), truncated=truncated)
