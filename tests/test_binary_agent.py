from pathlib import Path

import pytest

from app.agents.binary_analysis.agent import run_binary_analysis_agent
from app.agents.binary_analysis.ghidra_adapter import run_ghidra_analysis
from app.agents.binary_analysis.metadata import identify_binary
from app.agents.binary_analysis.static_analysis import analyse
from app.core.exceptions import ToolExecutionError
from app.core.schemas import AssessmentPolicy, TaskStatus
from app.core.scope_guard import ScopeGuard

FIXTURES = Path(__file__).parent / "fixtures" / "binaries"


def test_identify_elf_binary():
    meta = identify_binary(FIXTURES / "minimal_elf64.bin")
    assert meta.format == "ELF"
    assert meta.architecture == "x86_64"
    assert meta.bits == 64
    assert meta.file_hash_sha256


def test_identify_unrecognised_format():
    meta = identify_binary(FIXTURES / "sample.txt")
    assert meta.format == "unknown"
    assert meta.warnings


def test_identify_missing_file_raises():
    with pytest.raises(ToolExecutionError):
        identify_binary(FIXTURES / "does_not_exist.bin")


def test_ghidra_analysis_uses_fixture_when_not_installed(tmp_path):
    result = run_ghidra_analysis(FIXTURES / "minimal_elf64.bin", output_dir=tmp_path)
    assert result.used_fixture is True
    assert len(result.functions) > 0
    assert len(result.strings) > 0


def test_static_analysis_detects_fixture_weaknesses(tmp_path):
    meta = identify_binary(FIXTURES / "minimal_elf64.bin")
    ghidra = run_ghidra_analysis(FIXTURES / "minimal_elf64.bin", output_dir=tmp_path)
    weaknesses = analyse(meta, ghidra)
    categories = {w.category for w in weaknesses}
    assert "unsafe_function_usage" in categories  # strcpy/system in fixture imports
    assert "hardcoded_credential" in categories  # "password"-ish / high-entropy strings in fixture


def test_full_binary_agent_run_produces_findings(tmp_path):
    policy = AssessmentPolicy(allow_binary_analysis=True, dry_run=False)
    guard = ScopeGuard(policy)
    result = run_binary_analysis_agent(
        [("BINARY-001", FIXTURES / "minimal_elf64.bin")],
        assessment_id="ASSESSMENT-001", scope_guard=guard, output_dir=tmp_path,
    )
    assert result.execution_status == TaskStatus.COMPLETED
    assert len(result.findings) > 0
    assert all(f.status.value == "suspected" for f in result.findings)
    assert all(f.binary_id == "BINARY-001" for f in result.findings)


def test_binary_agent_denies_without_permission(tmp_path):
    policy = AssessmentPolicy(allow_binary_analysis=False)
    guard = ScopeGuard(policy)
    result = run_binary_analysis_agent(
        [("BINARY-001", FIXTURES / "minimal_elf64.bin")],
        assessment_id="ASSESSMENT-001", scope_guard=guard, output_dir=tmp_path,
    )
    assert result.execution_status == TaskStatus.FAILED
    assert len(result.findings) == 0
    assert any("not" in e.lower() or "disabled" in e.lower() for e in result.errors)
