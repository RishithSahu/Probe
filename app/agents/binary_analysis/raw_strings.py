"""Real (never-fixture) printable-string extraction, for when Ghidra is not installed.

`ghidra_adapter.run_ghidra_analysis` falls back to a documented SYNTHETIC fixture when Ghidra isn't
configured, specifically so the rest of the pipeline can be built/tested without it -- that fixture is
canned data and must never be mistaken for a real finding about a real file (see its own docstring).

This module is the opposite: a genuine, dependency-free scan of the REAL bytes on disk (equivalent to the
Unix `strings` utility; works on an ELF, a PE, or anything else), used only by the discovered-artifact
pipeline so that a credential-shaped string fed into a verification step always comes from the actual file,
never from a canned example -- at the cost of function/import data, which this does not attempt to recover.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.agents.binary_analysis.ghidra_adapter import GhidraString

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % 6)


def extract_printable_strings(path: str | Path, *, min_length: int = 6, max_strings: int = 4000) -> list[GhidraString]:
    """ASCII runs of at least `min_length` printable characters, with their byte offset -- the same shape
    `static_analysis._check_hardcoded_secrets` already consumes, so no downstream heuristic needs to change."""
    data = Path(path).read_bytes()
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    out: list[GhidraString] = []
    for m in pattern.finditer(data):
        out.append(GhidraString(address=hex(m.start()), value=m.group().decode("ascii")))
        if len(out) >= max_strings:
            break
    return out
