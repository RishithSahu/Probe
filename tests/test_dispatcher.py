"""Tests for app/orchestrator/dispatcher.py.

Primary focus: the timeout bug. `run_concurrently` is documented as
bounding how long it blocks for by `timeout_seconds`, but previously used
`with ThreadPoolExecutor(...) as executor:`, whose implicit
`shutdown(wait=True)` on exit blocked until every submitted thread
*actually* finished — including ones `wait()` had already declared timed
out (`Future.cancel()` is a no-op on an already-running thread; Python
cannot force-kill one). The declared timeout was therefore cosmetic: a
hung job could block the calling thread (a FastAPI background task, i.e.
the whole assessment pipeline) for as long as that job actually took,
regardless of `timeout_seconds`. Fixed with `shutdown(wait=False)`.
"""
from __future__ import annotations

import threading
import time

from app.core.schemas import AgentId, AgentResult, TaskStatus
from app.orchestrator.dispatcher import run_concurrently


def test_timeout_actually_bounds_wall_clock_time():
    """The function must return close to `timeout_seconds`, not close to
    how long the slow job actually takes to finish."""
    def slow_job():
        time.sleep(2.0)
        return AgentResult(agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED)

    start = time.monotonic()
    results = run_concurrently({AgentId.WEB_SECURITY.value: slow_job}, timeout_seconds=0.3)
    elapsed = time.monotonic() - start

    # Generous upper bound (not 0.3s sharp) to absorb scheduling jitter in
    # CI/dev environments, but nowhere near the job's real 2.0s duration —
    # before the fix this reliably took >= 2.0s.
    assert elapsed < 1.0, f"run_concurrently blocked for {elapsed:.2f}s despite a 0.3s timeout"
    assert results[AgentId.WEB_SECURITY.value].execution_status == TaskStatus.FAILED
    assert "timed out" in results[AgentId.WEB_SECURITY.value].errors[0]


def test_fast_job_still_returns_its_real_result():
    def fast_job():
        return AgentResult(
            agent_id=AgentId.BINARY_ANALYSIS, assessment_id="X", execution_status=TaskStatus.COMPLETED,
            tool_executions=[{"tool": "ghidra"}],
        )

    results = run_concurrently({AgentId.BINARY_ANALYSIS.value: fast_job}, timeout_seconds=5.0)
    result = results[AgentId.BINARY_ANALYSIS.value]
    assert result.execution_status == TaskStatus.COMPLETED
    assert result.tool_executions == [{"tool": "ghidra"}]


def test_one_job_failing_does_not_affect_the_other():
    def failing_job():
        raise RuntimeError("boom")

    def ok_job():
        return AgentResult(agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED)

    results = run_concurrently(
        {AgentId.BINARY_ANALYSIS.value: failing_job, AgentId.WEB_SECURITY.value: ok_job}, timeout_seconds=5.0,
    )
    assert results[AgentId.BINARY_ANALYSIS.value].execution_status == TaskStatus.FAILED
    assert "RuntimeError" in results[AgentId.BINARY_ANALYSIS.value].errors[0]
    assert results[AgentId.WEB_SECURITY.value].execution_status == TaskStatus.COMPLETED


def test_jobs_actually_run_concurrently_not_sequentially():
    barrier = threading.Barrier(2, timeout=5)

    def waits_for_both():
        barrier.wait()  # only returns once BOTH jobs have reached this line
        return AgentResult(agent_id=AgentId.WEB_SECURITY, assessment_id="X", execution_status=TaskStatus.COMPLETED)

    results = run_concurrently(
        {"a": waits_for_both, "b": waits_for_both}, timeout_seconds=5.0,
    )
    assert results["a"].execution_status == TaskStatus.COMPLETED
    assert results["b"].execution_status == TaskStatus.COMPLETED
