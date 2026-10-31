"""Generic bridge to explicit, already-recorded method grants.

`probe/authorisation.py` (the discovery side) writes/reads a small JSON record of explicit, operator-approved
exceptions to default request behaviour -- e.g. "send this one header on requests to this one origin". This
reads that same file and turns any grant matching a target URL's host:port into HTTP headers, so this
application's own requests can honour an authorisation that was already given, without inventing one or
hardcoding any target-specific value in code. A URL with no matching grant gets no extra headers at all.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

_SUPPORTED_METHODS = {"read-only-proxy-header-test"}


def headers_for_url(url: str, authorisations_path: str | Path | None) -> dict[str, str]:
    if not authorisations_path:
        return {}
    try:
        data = json.loads(Path(authorisations_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    headers: dict[str, str] = {}
    for grant in data.get("method_grants", []):
        if grant.get("method") not in _SUPPORTED_METHODS:
            continue
        if grant.get("target_ip") == host and grant.get("target_port") == port:
            name, value = grant.get("header_name"), grant.get("header_value")
            if name and value:
                headers[name] = value
    return headers
