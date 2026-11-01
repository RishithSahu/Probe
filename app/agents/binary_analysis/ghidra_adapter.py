"""Stage B: Ghidra Headless Analyzer integration.

Invokes `analyzeHeadless` as a subprocess with a fixed argument list against
a per-binary, disposable Ghidra project (`-deleteProject`), running
`scripts/ghidra/extract_analysis.py` to dump functions/strings/imports to
JSON. The supplied binary is imported for static analysis only — Ghidra
headless never executes target code.

When Ghidra is not installed (true for most dev machines, including this
one) and `settings.binary_agent_use_fixtures` is enabled, a documented
synthetic analysis result is returned instead, so static-weakness
identification and finding-generation can be built/tested without a Ghidra
install. The fixture is clearly flagged (`used_fixture=True`) end to end so
it is never confused with a real analysis in a report.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import ToolExecutionError

logger = logging.getLogger("ape.binary_agent.ghidra")

_SCRIPT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "ghidra"
_SCRIPT_NAME = "extract_analysis.py"


@dataclass
class GhidraFunction:
    name: str
    address: str
    signature: str = ""
    is_thunk: bool = False
    is_external: bool = False
    called_by: list[str] = field(default_factory=list)


@dataclass
class GhidraString:
    address: str
    value: str


@dataclass
class GhidraImport:
    name: str
    namespace: str = ""


@dataclass
class GhidraAnalysisResult:
    program_name: str
    language_id: str | None = None
    image_base: str | None = None
    functions: list[GhidraFunction] = field(default_factory=list)
    strings: list[GhidraString] = field(default_factory=list)
    imports: list[GhidraImport] = field(default_factory=list)
    used_fixture: bool = False
    raw_output_path: str | None = None
    error: str | None = None
    decompiled_by_function: dict[str, str] = field(default_factory=dict)  # populated only by the real
    # PyGhidra path (discovered_artifact.py) -- empty for the organiser-supplied subprocess/fixture path.


def _analyzeheadless_path() -> str | None:
    """BUG FIX: this used to return the extension-less `analyzeHeadless` shell script whenever it existed,
    even on Windows, where Ghidra ALSO ships `analyzeHeadless.bat` specifically because the shell script
    cannot be executed there (CreateProcess fails with WinError 193, "not a valid Win32 application"). The
    platform-appropriate launcher must be tried first, not merely "whichever file happens to exist first"."""
    if not settings.ghidra_install_dir:
        return None
    candidate = Path(settings.ghidra_install_dir) / "support" / "analyzeHeadless"
    ordered = [candidate.with_suffix(".bat"), candidate] if sys.platform == "win32" else [candidate, candidate.with_suffix(".bat")]
    for c in ordered:
        if c.exists():
            return str(c)
    return None


def _synthetic_result(binary_path: Path) -> GhidraAnalysisResult:
    """Documented fixture standing in for a real Ghidra run. Shaped like a
    small, somewhat-careless C program with a hardcoded credential, an
    unsafe `strcpy`, and a couple of harmless strings — representative
    enough to exercise static_analysis.py's weakness checks end to end."""
    return GhidraAnalysisResult(
        program_name=binary_path.name,
        language_id="x86:LE:64:default",
        image_base="0x00100000",
        functions=[
            GhidraFunction(name="main", address="0x00101000", signature="int main(int argc, char **argv)"),
            GhidraFunction(name="authenticate_user", address="0x00101200",
                            signature="int authenticate_user(char *username, char *password)",
                            called_by=["0x00101050"]),
            GhidraFunction(name="copy_input", address="0x00101400", signature="void copy_input(char *buf)",
                            called_by=["0x00101080"]),
        ],
        strings=[
            GhidraString(address="0x00102000", value="admin"),
            GhidraString(address="0x00102010", value="S3cr3tP@ssw0rd!"),
            GhidraString(address="0x00102020", value="Usage: %s <input>\\n"),
            GhidraString(address="0x00102030", value="/bin/sh"),
        ],
        imports=[
            GhidraImport(name="strcpy", namespace="libc"),
            GhidraImport(name="system", namespace="libc"),
            GhidraImport(name="strcmp", namespace="libc"),
        ],
        used_fixture=True,
    )


def _parse_result_json(raw: dict, *, used_fixture: bool, raw_output_path: str | None) -> GhidraAnalysisResult:
    return GhidraAnalysisResult(
        program_name=raw.get("program_name", "unknown"),
        language_id=raw.get("language_id"),
        image_base=raw.get("image_base"),
        functions=[GhidraFunction(**f) for f in raw.get("functions", [])],
        strings=[GhidraString(**s) for s in raw.get("strings", [])],
        imports=[GhidraImport(**i) for i in raw.get("imports", [])],
        used_fixture=used_fixture,
        raw_output_path=raw_output_path,
    )


def run_ghidra_analysis(binary_path: str | Path, *, output_dir: Path) -> GhidraAnalysisResult:
    binary_path = Path(binary_path)
    analyze_headless = _analyzeheadless_path()

    if analyze_headless is None:
        if settings.binary_agent_use_fixtures:
            logger.info("Ghidra not installed (APE_GHIDRA_INSTALL_DIR unset); using synthetic analysis fixture for %s", binary_path)
            return _synthetic_result(binary_path)
        raise ToolExecutionError("Ghidra Headless Analyzer not configured and fixtures disabled")

    output_dir.mkdir(parents=True, exist_ok=True)
    settings.ghidra_project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"ape_{uuid.uuid4().hex[:8]}"
    result_json_path = output_dir / f"ghidra_{binary_path.stem}.json"

    # Fixed argument list; -deleteProject guarantees no persisted project
    # artifact lingers beyond this one-shot analysis run.
    args = [
        analyze_headless,
        str(settings.ghidra_project_dir),
        project_name,
        "-import", str(binary_path),
        "-postScript", _SCRIPT_NAME, str(result_json_path),
        "-scriptPath", str(_SCRIPT_DIR),
        "-deleteProject",
    ]
    try:
        # text=True without an explicit encoding uses the platform default codec (cp1252 on Windows),
        # which can raise UnicodeDecodeError on real decompiler output -- see crawler.py's own fix for
        # the same bug, found against a live target.
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=settings.binary_analysis_timeout_seconds, check=False,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolExecutionError(f"Ghidra headless analysis timed out for {binary_path}") from exc

    if not result_json_path.exists():
        raise ToolExecutionError(
            f"Ghidra headless analysis did not produce output for {binary_path} "
            f"(exit={proc.returncode}): {proc.stderr[-1000:]}"
        )

    with result_json_path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return _parse_result_json(raw, used_fixture=False, raw_output_path=str(result_json_path))
