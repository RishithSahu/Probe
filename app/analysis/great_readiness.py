"""'GREAT' target-readiness scoring for a finished assessment's report.

This project's own recurring practice, across several entries in docs/PROGRESS.md, is to distinguish a
finding that is merely suspected or fixture-backed from one that is CONFIRMED against real evidence (see,
for example, Entry 16/17's work on the 192.168.60.139 chain). This module gives that distinction a single,
reusable summary for the report: an assessment is only reported "demonstrated" if it produced at least one
CONFIRMED finding that was not itself built from a documented synthetic fallback -- never from a suspected
finding or a fixture-tagged one, however many of those exist.
"""
from __future__ import annotations

from typing import Any


def evaluate_great(report_data: dict[str, Any], benchmark_comparison: dict[str, Any] | None = None) -> dict[str, Any]:
    """Returns a small summary dict (at least a `status` key) suitable for display in the report.

    `benchmark_comparison`, when given, must already be scoped to THIS report's own assessment/scope --
    callers are expected to have looked it up by the same assessment_id, but this function re-checks that
    binding itself rather than trusting the caller, and raises ValueError if it does not match (the
    caller, app.reporting.generator, is written to catch exactly that and fall back to the unscored case
    rather than silently attaching a comparison that belongs to a different assessment)."""
    if benchmark_comparison is not None:
        comparison_assessment = benchmark_comparison.get("assessment_id")
        comparison_scope = benchmark_comparison.get("scope_id")
        if comparison_assessment != report_data.get("assessment_id"):
            raise ValueError("benchmark_comparison does not match this assessment/scope")
        if comparison_scope is not None and comparison_scope != report_data.get("scope_id"):
            raise ValueError("benchmark_comparison does not match this assessment/scope")

    findings = report_data.get("findings") or []
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    # "used_fixture" is recorded per tool execution / evidence item, not on the Finding itself (see
    # generator.py's own fixture_tools_used comment) -- any_fixture_used is report-wide, not per-finding,
    # so a report is only "demonstrated" when it has a confirmed finding AND nothing in it was fixture-backed.
    any_fixture_used = bool(report_data.get("data_integrity", {}).get("fixture_tools_used"))

    if confirmed and not any_fixture_used:
        status = "demonstrated"
    elif confirmed or findings:
        status = "partial"
    else:
        status = "not demonstrated"

    result: dict[str, Any] = {
        "status": status,
        "confirmed_finding_count": len(confirmed),
        "total_finding_count": len(findings),
    }
    if benchmark_comparison is not None:
        result["benchmark_comparison"] = benchmark_comparison
    return result
