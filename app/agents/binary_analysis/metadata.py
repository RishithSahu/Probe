"""Stage A: binary identification.

Uses `file`, `readelf`, and `checksec` (all invoked with fixed argument lists,
never a shell string) to identify format/architecture/security properties.
The supplied binary is NEVER executed — these are static-inspection tools
only. Falls back to Python-native parsing (via `pefile`/manual ELF header
read) when a given CLI tool isn't installed, so this still works on a
Windows dev box without `readelf`/`checksec` on PATH.
"""
from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.core.exceptions import ToolExecutionError

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"


@dataclass
class ChecksecProperties:
    """Binary security hardening properties. `None` means "could not be
    determined" — never guessed."""

    relro: str | None = None  # none | partial | full
    stack_canary: bool | None = None
    nx: bool | None = None
    pie: bool | None = None
    fortify_source: bool | None = None
    rpath: str | None = None
    runpath: str | None = None


@dataclass
class BinaryMetadata:
    file_path: str
    file_name: str
    file_hash_sha256: str
    file_size_bytes: int
    format: str = "unknown"  # ELF | PE | unknown
    architecture: str | None = None
    bits: int | None = None  # 32 | 64
    endianness: str | None = None
    is_stripped: bool | None = None
    imported_libraries: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    checksec: ChecksecProperties = field(default_factory=ChecksecProperties)
    file_tool_output: str | None = None
    warnings: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_tool(args: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
    try:
        # text=True without an explicit encoding uses the platform default codec (cp1252 on Windows),
        # which can raise UnicodeDecodeError on a real tool's real output -- see crawler.py's own fix for
        # the same bug, found against a live target.
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                              encoding="utf-8", errors="replace")
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{args[0]} not found on PATH"
    except subprocess.TimeoutExpired:
        return -1, "", f"{args[0]} timed out"


def _identify_elf_native(data: bytes) -> dict:
    """Minimal ELF header parse (no external tool needed) — just enough to
    report architecture/bits/endianness when `readelf` is unavailable."""
    ei_class = data[4]
    ei_data = data[5]
    bits = 64 if ei_class == 2 else 32
    endianness = "little" if ei_data == 1 else "big"
    fmt = "<" if ei_data == 1 else ">"
    e_machine = struct.unpack_from(fmt + "H", data, 18)[0]
    machine_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS", 0x14: "PowerPC"}
    arch = machine_map.get(e_machine, f"unknown(0x{e_machine:x})")
    return {"bits": bits, "endianness": endianness, "architecture": arch}


def _identify_pe_native(path: Path) -> dict:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {}
    pe = pefile.PE(str(path), fast_load=True)
    machine = pe.FILE_HEADER.Machine
    machine_map = {0x014C: "x86", 0x8664: "x86_64", 0x01C4: "ARM", 0xAA64: "AArch64"}
    arch = machine_map.get(machine, f"unknown(0x{machine:x})")
    bits = 64 if "64" in arch else 32
    imports = []
    try:
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="replace"))
    except Exception:  # noqa: BLE001 - best effort
        pass
    return {"architecture": arch, "bits": bits, "imported_libraries": imports}


def _parse_checksec_output(output: str) -> ChecksecProperties:
    """`checksec --file=<path>` emits a single-line human-readable summary
    (or `--output=json` for structured output, preferred when available)."""
    props = ChecksecProperties()
    lower = output.lower()
    if "full relro" in lower:
        props.relro = "full"
    elif "partial relro" in lower:
        props.relro = "partial"
    elif "no relro" in lower or "relro" in lower:
        props.relro = "none"
    if "canary found" in lower:
        props.stack_canary = True
    elif "no canary" in lower:
        props.stack_canary = False
    if "nx enabled" in lower:
        props.nx = True
    elif "nx disabled" in lower:
        props.nx = False
    if "pie enabled" in lower:
        props.pie = True
    elif "no pie" in lower:
        props.pie = False
    return props


def identify_binary(path: str | Path) -> BinaryMetadata:
    path = Path(path)
    if not path.exists():
        raise ToolExecutionError(f"binary not found: {path}")

    data = path.read_bytes()[:64]  # header only is enough for identification
    meta = BinaryMetadata(
        file_path=str(path),
        file_name=path.name,
        file_hash_sha256=_sha256(path),
        file_size_bytes=path.stat().st_size,
    )

    # `file` command, if available, gives a good human-readable cross-check.
    rc, out, err = _run_tool(["file", "--brief", str(path)])
    if rc == 0:
        meta.file_tool_output = out.strip()
    else:
        meta.warnings.append(f"'file' unavailable or failed: {err.strip()}")

    if data[:4] == _ELF_MAGIC:
        meta.format = "ELF"
        meta.__dict__.update(_identify_elf_native(data))

        rc, out, err = _run_tool(["readelf", "-h", str(path)])
        if rc == 0:
            meta.__dict__["readelf_header"] = out
            # BUG FIX: this used to also set `meta.is_stripped` from this
            # same `-h` (ELF *header*) output by checking for the text "no
            # symbols" — which readelf's header dump never contains, so the
            # check was vacuously almost-always True. It was overwritten
            # below by the real `-sW` (symbol table) check in the common
            # case, but left a wrong `is_stripped=True` behind on the rare
            # path where `readelf -sW` itself failed. Stripped-ness is only
            # ever set from the actual symbol-table output now.
        else:
            meta.warnings.append(f"'readelf' unavailable or failed: {err.strip()}")

        rc, out, err = _run_tool(["readelf", "-d", str(path)])
        if rc == 0:
            for line in out.splitlines():
                if "NEEDED" in line and "[" in line:
                    lib = line.split("[", 1)[1].split("]", 1)[0]
                    meta.imported_libraries.append(lib)
        rc, out, err = _run_tool(["readelf", "-sW", str(path)])
        if rc == 0:
            meta.is_stripped = out.strip().count("\n") < 3
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[3] in ("FUNC", "OBJECT"):
                    meta.symbols.append(parts[-1])

        checksec_bin = shutil.which("checksec")
        if checksec_bin:
            rc, out, err = _run_tool([checksec_bin, f"--file={path}"])
            if rc == 0:
                meta.checksec = _parse_checksec_output(out)
            else:
                meta.warnings.append(f"'checksec' failed: {err.strip()}")
        else:
            meta.warnings.append("'checksec' not found on PATH; hardening properties unknown")

    elif data[:2] == _PE_MAGIC:
        meta.format = "PE"
        pe_info = _identify_pe_native(path)
        if pe_info:
            meta.architecture = pe_info.get("architecture")
            meta.bits = pe_info.get("bits")
            meta.imported_libraries = pe_info.get("imported_libraries", [])
        else:
            meta.warnings.append("'pefile' not available; PE architecture/imports not extracted")
    else:
        meta.format = "unknown"
        meta.warnings.append("unrecognised file magic; not ELF or PE")

    return meta
