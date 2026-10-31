"""Real Ghidra analysis via PyGhidra (in-process, CPython -- not the old Jython scripting bridge, which
Ghidra 12.x no longer ships for a plain `-postScript`). This is the FULL-fidelity analysis tier: real
disassembly, real decompilation, a real call graph, real defined strings -- used only when
`settings.ghidra_install_dir` points at a working install. When it does not, or the import/analysis genuinely
fails (unsupported architecture, timeout, crash), this raises `ToolExecutionError` / returns an explicit
`error` -- it never falls back to canned data; that fallback (a raw byte-level string scan of the REAL file)
lives one level up, in discovered_artifact.py.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import ToolExecutionError

logger = logging.getLogger("ape.binary_agent.pyghidra")

_STRING_LITERAL_RE = re.compile(r'^(?:u8|u|U|L)?"(.*)"$', re.DOTALL)

_start_lock = threading.Lock()
_started = False


@dataclass
class PyGhidraFunction:
    name: str
    address: str
    signature: str = ""
    decompiled_c: str | None = None
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    is_thunk: bool = False
    is_external: bool = False


@dataclass
class PyGhidraResult:
    program_name: str
    executable_format: str
    language_id: str
    functions: list[PyGhidraFunction] = field(default_factory=list)
    strings: list[tuple[str, str]] = field(default_factory=list)  # (address, value)
    imports: list[str] = field(default_factory=list)


def _ensure_started() -> None:
    global _started
    with _start_lock:
        if _started:
            return
        if not settings.ghidra_install_dir:
            raise ToolExecutionError("Ghidra Headless Analyzer not configured (APE_GHIDRA_INSTALL_DIR unset)")
        if not Path(settings.ghidra_install_dir).exists():
            raise ToolExecutionError(f"configured Ghidra install dir does not exist: {settings.ghidra_install_dir}")
        os.environ.setdefault("GHIDRA_INSTALL_DIR", str(settings.ghidra_install_dir))
        try:
            import pyghidra
        except ImportError as exc:
            raise ToolExecutionError(f"pyghidra package not installed: {exc}") from exc
        try:
            pyghidra.start()
        except Exception as exc:  # noqa: BLE001 - any JVM/Ghidra startup failure is a tool failure, not a crash
            raise ToolExecutionError(f"pyghidra.start() failed: {exc}") from exc
        _started = True


def analyse(binary_path: str | Path, *, timeout_seconds: float | None = None,
           project_dir: str | Path | None = None) -> PyGhidraResult:
    """Imports and auto-analyses `binary_path` for real, decompiles every non-thunk/non-external function,
    and builds its call graph from Ghidra's own reference manager. Raises `ToolExecutionError` for anything
    that stops this from being a genuine result: missing/broken Ghidra, an architecture Ghidra's own loader
    rejects, or a hang past `timeout_seconds`."""
    _ensure_started()
    import pyghidra
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    project_dir = Path(project_dir or settings.ghidra_project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    project_location = project_dir / f"pyghidra_{uuid.uuid4().hex[:12]}"

    result_box: dict = {}
    error_box: dict = {}

    def work() -> None:
        try:
            with pyghidra.open_program(str(binary_path), project_location=str(project_location)) as flat_api:
                program = flat_api.getCurrentProgram()
                fmt = str(program.getExecutableFormat())
                if fmt is None or "unknown" in fmt.lower() or fmt == "":
                    error_box["exc"] = ToolExecutionError(f"Ghidra could not identify an executable format for {binary_path}")
                    return
                fm = program.getFunctionManager()
                ref_mgr = program.getReferenceManager()
                dec = DecompInterface()
                dec.openProgram(program)
                monitor = ConsoleTaskMonitor()

                functions: list[PyGhidraFunction] = []
                for func in fm.getFunctions(True):
                    entry = func.getEntryPoint()
                    pf = PyGhidraFunction(name=func.getName(), address=str(entry),
                                          signature=str(func.getSignature()),
                                          is_thunk=bool(func.isThunk()), is_external=bool(func.isExternal()))
                    if not func.isThunk() and not func.isExternal():
                        try:
                            res = dec.decompileFunction(func, 25, monitor)
                            if res.decompileCompleted():
                                pf.decompiled_c = res.getDecompiledFunction().getC()
                        except Exception:  # noqa: BLE001 - one function's decompile failing must not abort the run
                            logger.warning("decompile failed for %s @ %s", pf.name, pf.address)
                        callers, callees = set(), set()
                        for ref in ref_mgr.getReferencesTo(entry):
                            if ref.getReferenceType().isCall():
                                caller_func = fm.getFunctionContaining(ref.getFromAddress())
                                if caller_func is not None:
                                    callers.add(caller_func.getName())
                        for instr_addr in func.getBody().getAddresses(True):
                            for ref in ref_mgr.getReferencesFrom(instr_addr):
                                if ref.getReferenceType().isCall():
                                    callee_func = fm.getFunctionAt(ref.getToAddress())
                                    if callee_func is not None:
                                        callees.add(callee_func.getName())
                        pf.callers, pf.callees = sorted(callers), sorted(callees)
                    functions.append(pf)

                strings: list[tuple[str, str]] = []
                listing = program.getListing()
                for data in listing.getDefinedData(True):
                    dt_name = data.getDataType().getName().lower()
                    if "string" not in dt_name and "char" not in dt_name:
                        continue
                    addr_text = str(data.getAddress())
                    if "::" in addr_text:
                        # BUG FIX: an address like '.shstrtab::0000001' is Ghidra's own representation of raw
                        # section-header/string-table METADATA (ELF section names etc.), not content a human
                        # put in the program -- it was being reported as a "string" and then false-positive
                        # flagged as a credential-shaped value. A real, loaded-memory string always has a
                        # plain address; this generic check (not specific to any one binary) excludes
                        # anything that isn't one.
                        continue
                    val = data.getDefaultValueRepresentation()
                    if val:
                        # Ghidra renders a UTF-8 string literal with a C-style encoding prefix
                        # (u8"text", u"text", L"text"); strip that prefix along with the quotes so the
                        # recovered value is the literal content, not 'u8"text' with the prefix still on.
                        quoted = _STRING_LITERAL_RE.match(val)
                        strings.append((addr_text, quoted.group(1) if quoted else val.strip('"')))

                imports = sorted({f.name for f in functions if f.is_external})

                result_box["result"] = PyGhidraResult(
                    program_name=Path(str(binary_path)).name, executable_format=fmt,
                    language_id=str(program.getLanguage().getLanguageID()),
                    functions=functions, strings=strings, imports=imports,
                )
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a ToolExecutionError, never silently fixtured
            error_box["exc"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    if thread.is_alive():
        raise ToolExecutionError(f"Ghidra analysis of {binary_path} did not finish within {timeout_seconds}s (timeout)")
    if "exc" in error_box:
        raise ToolExecutionError(f"Ghidra analysis of {binary_path} failed: {error_box['exc']}") from error_box["exc"]
    if "result" not in result_box:
        raise ToolExecutionError(f"Ghidra analysis of {binary_path} produced no result")
    return result_box["result"]


def read_memory(binary_path: str | Path, address: int, length: int, *,
                timeout_seconds: float | None = None, project_dir: str | Path | None = None) -> bytes:
    """Reads `length` bytes starting at `address` from the SAME binary, via Ghidra's own memory model (so the
    file-offset-to-virtual-address mapping is exactly what the decompiler itself used) -- used only to
    retrieve the fixed input bytes a `credential_recovery.XorKeySchedule` needs; never to read anything a
    schedule did not name."""
    _ensure_started()
    import pyghidra

    project_dir = Path(project_dir or settings.ghidra_project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    project_location = project_dir / f"pyghidra_mem_{uuid.uuid4().hex[:12]}"

    result_box: dict = {}
    error_box: dict = {}

    def work() -> None:
        try:
            with pyghidra.open_program(str(binary_path), project_location=str(project_location)) as flat_api:
                program = flat_api.getCurrentProgram()
                mem = program.getMemory()
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
                result_box["data"] = bytes(mem.getByte(addr.add(i)) & 0xFF for i in range(length))
        except Exception as exc:  # noqa: BLE001
            error_box["exc"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    if thread.is_alive():
        raise ToolExecutionError(f"Ghidra memory read for {binary_path} timed out after {timeout_seconds}s")
    if "exc" in error_box:
        raise ToolExecutionError(f"Ghidra memory read for {binary_path} failed: {error_box['exc']}") from error_box["exc"]
    return result_box["data"]
