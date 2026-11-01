"""Shared, dependency-free safety helpers for anything that builds a report path from an assessment_id
supplied over the API, or returns report data to an API caller.

`report_path`/`report_directory` exist so an assessment_id coming straight from a URL path parameter can
never walk a report write/read outside its own reports directory -- the identifier is validated BEFORE it
ever touches a filesystem path, not sanitised after the fact. `public_output` exists so anything this
project's own protected-storage layer (app/core/protected_storage.py) or a credential-bearing Evidence
record ever put into report data cannot leave the process through the API by accident.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Mirrors the identifiers this project actually generates (f"ASSESSMENT-{uuid4().hex[:10].upper()}", or
# whatever an operator passes to the CLI's --assessment-id) -- safe filename characters only, no "..",
# no path separators, so joining it onto a base directory can never leave that directory.
_SAFE_ASSESSMENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

_VALID_SOURCES = ("latest", "execution", "snapshot")

# Keys this redacts wherever they appear, however deeply nested, case-insensitively. Matches this
# project's own vocabulary for anything protected_storage.retrieve_secret or a credential-bearing Evidence
# record would use: never return the value itself over the public API, only that one existed.
_SENSITIVE_KEY_SUBSTRINGS = (
    "credential", "secret", "passkey", "password", "api_key", "apikey", "token", "private_key",
)


def _validate_assessment_id(assessment_id: str) -> None:
    if not _SAFE_ASSESSMENT_ID.match(assessment_id):
        raise ValueError(f"not a safe assessment identifier: {assessment_id!r}")


def report_path(base_dir: Path, assessment_id: str, fmt: str) -> Path:
    """The file a report of format `fmt` ("json" or "pdf") for `assessment_id` lives at, under `base_dir`.
    Raises ValueError for anything that isn't a safe, bounded identifier -- never attempts to sanitise one."""
    _validate_assessment_id(assessment_id)
    if fmt not in ("json", "pdf"):
        raise ValueError(f"unsupported report format: {fmt!r}")
    return Path(base_dir) / f"{assessment_id}.{fmt}"


def report_directory(reports_dir: Path, assessment_id: str, source: str) -> Path:
    """Where a given `source` view of an assessment's reports lives: "latest" is the single, most
    recently (re)generated copy at the top level (what report_path's other callers write to directly);
    "execution" and "snapshot" are this assessment's own namespaced subdirectories for the other report
    sources get_report's `source` query parameter can ask for."""
    _validate_assessment_id(assessment_id)
    if source not in _VALID_SOURCES:
        raise ValueError(f"unsupported report source: {source!r}")
    base = Path(reports_dir)
    if source == "latest":
        return base
    return base / assessment_id / source


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(substring in lowered for substring in _SENSITIVE_KEY_SUBSTRINGS)


def public_output(data: Any) -> Any:
    """Recursively strips any sensitive-looking key from a report structure before it leaves the process
    through the API -- never mutates the input, so a caller that still needs the unredacted version (e.g.
    writing the full report to disk before redacting what it serves) can reuse the same source dict."""
    if isinstance(data, dict):
        return {
            key: ("[redacted]" if _is_sensitive_key(key) else public_output(value))
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [public_output(item) for item in data]
    return data
