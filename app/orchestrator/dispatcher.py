"""Concurrent task dispatch helper.

The Web and Binary agents are independent of each other (per PRD Part 9.3)
and are run concurrently here via a thread pool — both are I/O-bound
(subprocess calls, HTTP requests) so threads are sufficient; no need for a
separate process pool. Each callable is wrapped so that one agent's
exception never prevents the other's result from being collected — a
failure becomes a `TaskStatus.FAILED` AgentResult-shaped error entry instead
of propagating and aborting the whole assessment.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Callable, TypeVar

from app.core.config import settings
from app.core.schemas import AgentId, AgentResult, TaskStatus

logger = logging.getLogger("ape.orchestrator.dispatcher")

T = TypeVar("T")


def run_concurrently(
    jobs: dict[str, Callable[[], AgentResult]],
    *,
    timeout_seconds: float | None = None,
) -> dict[str, AgentResult]:
    """Runs each zero-arg callable in `jobs` (keyed by agent_id string) in its
    own thread, with a shared timeout. A job that raises or times out is
    turned into a `TaskStatus.FAILED` AgentResult rather than raising —
    callers always get a result for every job they submitted, so the rest of
    the Orchestrator's aggregation step has something to work with.

    BUG FIX: this used to be `with ThreadPoolExecutor(...) as executor:`.
    `wait(..., timeout=timeout_seconds)` correctly returned on time and a
    straggler future's `.cancel()` was called, but `Future.cancel()` is a
    no-op once a thread has actually started running (Python cannot force-
    kill a thread) — and `with`'s implicit `executor.shutdown(wait=True)`
    on exit then blocked until every submitted thread *actually* finished,
    regardless of the timeout. The declared `timeout_seconds` was therefore
    cosmetic: a hung Katana/Ghidra subprocess could block this function (and
    the whole assessment pipeline, since this runs inside a FastAPI
    background task) for as long as that subprocess's own, separate timeout
    took to fire — verified with a minimal repro before changing this.
    `shutdown(wait=False)` makes the function actually return within
    `timeout_seconds` as documented; any straggler thread keeps running
    detached (Python has no way to force-kill it) until its own inner
    tool-call timeout fires, but this function no longer waits on it.
    """
    timeout_seconds = timeout_seconds or settings.agent_task_timeout_seconds
    results: dict[str, AgentResult] = {}

    executor = ThreadPoolExecutor(max_workers=max(1, settings.max_concurrent_agent_tasks))
    try:
        future_to_name: dict[Future, str] = {executor.submit(fn): name for name, fn in jobs.items()}
        start = time.monotonic()
        done, not_done = wait(future_to_name.keys(), timeout=timeout_seconds)

        for future in done:
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001 - must not abort sibling tasks
                logger.exception("agent task %s raised an exception", name)
                results[name] = AgentResult(
                    agent_id=AgentId(name) if name in AgentId._value2member_map_ else AgentId.ORCHESTRATOR,
                    assessment_id="",
                    execution_status=TaskStatus.FAILED,
                    errors=[f"{type(exc).__name__}: {exc}"],
                )

        for future in not_done:
            name = future_to_name[future]
            future.cancel()  # no-op for an already-running thread; still correct for a queued-but-not-started one
            logger.warning("agent task %s did not complete within %.1fs; abandoning it (thread may keep running in the background)", name, timeout_seconds)
            results[name] = AgentResult(
                agent_id=AgentId(name) if name in AgentId._value2member_map_ else AgentId.ORCHESTRATOR,
                assessment_id="",
                execution_status=TaskStatus.FAILED,
                errors=[f"task timed out after {timeout_seconds}s"],
            )

        elapsed = time.monotonic() - start
        logger.info("run_concurrently: %d jobs finished in %.2fs (%d timed out)", len(jobs), elapsed, len(not_done))
    finally:
        # wait=False: do NOT block here waiting for any straggler thread
        # that `not_done` already gave up on — that defeats the timeout
        # entirely (see docstring). Still releases the executor's own
        # bookkeeping; the worker threads simply aren't joined.
        executor.shutdown(wait=False)

    return results
