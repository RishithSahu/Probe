"""Binary Analysis Agent — entry point.

Receives organiser-supplied binaries from the Orchestrator (a directory or
explicit file list under `inputs/binaries/`) — never retrieves executables
from discovered network devices. Each binary is treated as untrusted: it is
identified and statically analysed, and NEVER executed on the host, at any
stage of this pipeline.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from app.agents.binary_analysis.findings import findings_from_weaknesses
from app.agents.binary_analysis.ghidra_adapter import run_ghidra_analysis
from app.agents.binary_analysis.metadata import identify_binary
from app.agents.binary_analysis.static_analysis import analyse
from app.core.exceptions import ScopeViolationError, ToolExecutionError
from app.core.schemas import AgentId, AgentResult, Evidence, Finding, TaskStatus
from app.core.scope_guard import ScopeGuard

logger = logging.getLogger("ape.binary_agent")


def assess_binary(
    binary_id: str,
    binary_path: str | Path,
    *,
    assessment_id: str,
    scope_guard: ScopeGuard,
    output_dir: Path,
) -> tuple[list[Finding], list[Evidence], list[dict], list[str]]:
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    tool_executions: list[dict] = []
    errors: list[str] = []

    try:
        scope_guard.check_binary_analysis_allowed(str(binary_path))
    except ScopeViolationError as exc:
        errors.append(f"binary {binary_path}: {exc}")
        return findings, evidence, tool_executions, errors

    try:
        metadata = identify_binary(binary_path)
        tool_executions.append({
            "tool": "file+readelf+checksec", "target": str(binary_path),
            "format": metadata.format, "warnings": metadata.warnings,
        })
    except ToolExecutionError as exc:
        errors.append(f"identify_binary({binary_path}): {exc}")
        return findings, evidence, tool_executions, errors

    try:
        ghidra_result = run_ghidra_analysis(binary_path, output_dir=output_dir)
        tool_executions.append({
            "tool": "ghidra", "target": str(binary_path),
            "used_fixture": ghidra_result.used_fixture,
            "function_count": len(ghidra_result.functions),
        })
    except ToolExecutionError as exc:
        errors.append(f"ghidra({binary_path}): {exc}")
        return findings, evidence, tool_executions, errors

    weaknesses = analyse(metadata, ghidra_result)
    binary_findings, binary_evidence = findings_from_weaknesses(
        weaknesses, assessment_id=assessment_id, binary_id=binary_id,
    )
    findings.extend(binary_findings)
    evidence.extend(binary_evidence)

    return findings, evidence, tool_executions, errors


def run_binary_analysis_agent(
    binaries: list[tuple[str, Path]],  # (binary_id, path)
    *,
    assessment_id: str,
    scope_guard: ScopeGuard,
    output_dir: Path,
) -> AgentResult:
    start = time.monotonic()
    all_findings: list[Finding] = []
    all_evidence: list[Evidence] = []
    all_tool_executions: list[dict] = []
    all_errors: list[str] = []

    for binary_id, path in binaries:
        findings, evidence, tool_executions, errors = assess_binary(
            binary_id, path, assessment_id=assessment_id, scope_guard=scope_guard, output_dir=output_dir,
        )
        all_findings.extend(findings)
        all_evidence.extend(evidence)
        all_tool_executions.extend(tool_executions)
        all_errors.extend(errors)

    duration = time.monotonic() - start
    execution_status = TaskStatus.COMPLETED
    if binaries and len(all_errors) >= len(binaries) and not all_findings:
        execution_status = TaskStatus.FAILED

    return AgentResult(
        agent_id=AgentId.BINARY_ANALYSIS,
        assessment_id=assessment_id,
        execution_status=execution_status,
        findings=all_findings,
        evidence=all_evidence,
        tool_executions=all_tool_executions,
        errors=all_errors,
        duration_seconds=duration,
    )
