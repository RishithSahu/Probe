"""One-command entry point for the autonomous assessment loop.

    python -m app.orchestrator run --assessment-id ASSESSMENT-CREDENTIAL-ACCESS-397A \\
        --scope 192.168.60.0/24 --max-minutes 20

Initialises a NEW assessment (needs --network-graph the first time) or RESUMES an existing one by
assessment_id -- resumption needs nothing but the id: policy, network graph, task history and findings are
all read back from the database, so interrupting this command and re-running it later continues from
exactly where it left off, never from scratch. Every iteration is one full
`app.orchestrator.autonomous_loop.run_next_iteration()` call: candidate generation, scoring, agent dispatch,
verification, and persistence, with nothing selected by hand.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import AppError
from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus, NetworkGraph
from app.database import repository
from app.database.session import init_db, session_scope
from app.orchestrator.autonomous_loop import run_concurrent_iteration, run_next_iteration

logger = logging.getLogger("ape.orchestrator.cli")

REPO_ROOT = Path(__file__).resolve().parents[2]


def _start_probe_and_discover(scope: str, assessment_id: str, *, port: int, probe_minutes: float) -> NetworkGraph:
    """Import one supervised scan's atomic snapshot; reuse a matching snapshot.

    The managed parent must already have the required privileges. No API polling,
    second scan request, detached elevation or imported historical task state.
    """
    from app.adapters.network_graph_adapter import normalise_probe_graph
    from app.orchestrator.probe_supervisor import discover

    directory = Path(settings.evidence_dir) / assessment_id / "probe-data"
    snapshot = discover(root=REPO_ROOT, data_dir=directory, scope=scope, assessment_id=assessment_id,
                        port=port, minutes=probe_minutes)
    return normalise_probe_graph(snapshot["payload"], scope_id=f"SCOPE-{scope.replace('/', '-')}",
                                 raw_source_ref=str(directory / "inventory-snapshot.json"))


def _load_or_create(
    assessment_id: str, scope: str, network_graph_path: str | None, *, probe_port: int, probe_minutes: float,
) -> AssessmentPolicy:
    import re
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", assessment_id):
        raise ValueError("Unsafe assessment identity")
    with session_scope() as db:
        try:
            policy = repository.get_assessment_policy(db, assessment_id)
            existing = repository.get_assessment(db, assessment_id)
            if existing.scope_id != f"SCOPE-{scope.replace('/', '-')}":
                raise ValueError("Resume scope does not match the original assessment")
            if repository.load_network_graph(db, assessment_id) is None:
                target = Path(settings.evidence_dir) / assessment_id / "probe-data" / "inventory-snapshot.json"
                if not target.exists():
                    raise RuntimeError("Assessment identity retained but inventory missing; recover existing artifacts before resume")
                from probe.snapshot import read_snapshot
                from app.adapters.network_graph_adapter import normalise_probe_graph
                snapshot = read_snapshot(target, assessment_id=assessment_id, scope=[scope])
                repository.store_network_graph(db, assessment_id, normalise_probe_graph(
                    snapshot["payload"], scope_id=existing.scope_id, raw_source_ref=str(target)))
            return policy
        except AppError:
            pass  # does not exist yet -- fall through to initialise it

    policy = AssessmentPolicy(
        allow_network_discovery=True, allow_network_service_assessment=True, allow_passive_web_analysis=True,
        allow_web_crawling=True, allow_content_discovery=True, allow_binary_analysis=True,
        allow_single_credential_verification=False, dry_run=False,
    )
    # Commit the identity before any discovery process can start. A failed import
    # leaves a CREATED assessment and the complete Probe evidence for recovery.
    with session_scope() as db:
        repository.create_assessment(db, Assessment(
            assessment_id=assessment_id, scope_id=f"SCOPE-{scope.replace('/', '-')}",
            status=AssessmentStatus.CREATED, assessment_policy=policy,
        ))
    if network_graph_path:
        graph = NetworkGraph.model_validate(json.loads(Path(network_graph_path).read_text()))
        logger.info("initialised %s (scope=%s) from supplied graph file %s", assessment_id, scope, network_graph_path)
    else:
        graph = _start_probe_and_discover(scope, assessment_id, port=probe_port, probe_minutes=probe_minutes)
        logger.info("initialised %s (scope=%s) from Probe's own real discovery -- %d asset(s)",
                   assessment_id, scope, len(graph.assets))

    with session_scope() as db:
        repository.store_network_graph(db, assessment_id, graph)
    return policy


def run(assessment_id: str, scope: str, max_minutes: float, network_graph_path: str | None = None, *,
       probe_port: int = 8080, probe_minutes: float = 5.0, max_inflight: int = 1) -> int:
    from app.core.execution_profile import preflight_check
    preflight_check()  # item 9: refuses to start a live_assessment run with fixture fallbacks still enabled

    # Unlike app.main's FastAPI service, this standalone CLI never otherwise calls init_db(): a brand-new
    # environment with no evidence/ape.db yet (a genuinely clean run, not a resume) would hit a bare
    # "no such table" OperationalError the moment _load_or_create below reads the database. Base.metadata.
    # create_all is a no-op against an already-current schema, so this is always safe to call, every run.
    init_db()
    policy = _load_or_create(assessment_id, scope, network_graph_path, probe_port=probe_port, probe_minutes=probe_minutes)
    output_dir = Path(settings.evidence_dir) / assessment_id / "autonomous"
    deadline = time.monotonic() + max_minutes * 60

    with session_scope() as db:
        repository.update_assessment_status(db, assessment_id, AssessmentStatus.RUNNING)

    iteration = 0
    parent_task_id: str | None = None
    final_status = AssessmentStatus.RUNNING
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.info("time budget (%.1f min) exhausted after %d iteration(s)", max_minutes, iteration)
                final_status = AssessmentStatus.RUNNING  # genuinely incomplete, not blocked -- more time helps
                break

            iteration += 1
            # BUG FIX: the deadline above is only checked BETWEEN iterations, but one iteration's own
            # agent dispatch (a web assessment's crawl + ZAP + content discovery, especially) has no
            # internal time budget of its own and can legitimately run for minutes -- --max-minutes 2
            # measurably overran to 4+ minutes this way, confirmed live. Python cannot force-kill a
            # running thread (the same limitation run_concurrently's own docstring already documents), so
            # this bounds how long the CLI WAITS for it, not the thread's own lifetime: once `remaining`
            # elapses the loop stops and exits with final_status=RUNNING (genuinely incomplete, resumable)
            # instead of silently blowing through the promised wall-clock budget. A straggler thread that
            # finishes after this process has moved on is already fenced by reservation_token/
            # try_complete_task (app.database.repository), so it cannot corrupt a later run's state.
            # max_inflight=1 (the default) keeps the original one-candidate-per-iteration behaviour exactly;
            # >1 dispatches up to that many independent, atomically-reserved candidates concurrently each
            # iteration (app.orchestrator.autonomous_loop.run_concurrent_iteration -- item 4/5/6 of the
            # concurrency spec), still one `while` tick per batch so the time-budget check above still applies.
            # NOT a `with ThreadPoolExecutor() as _pool:` block on purpose: that calls shutdown(wait=True)
            # on exit, which would block on exactly the straggler thread this is trying to stop waiting
            # for. shutdown(wait=False) below is the same pattern already used (and already documented as
            # imperfect -- Python cannot force-kill a thread) elsewhere in this codebase's own dispatcher.
            _pool = ThreadPoolExecutor(max_workers=1)
            future = (_pool.submit(run_next_iteration, assessment_id, policy=policy, output_dir=output_dir,
                                   parent_task_id=parent_task_id)
                     if max_inflight <= 1 else
                     _pool.submit(run_concurrent_iteration, assessment_id, policy=policy, output_dir=output_dir,
                                 parent_task_id=parent_task_id, max_inflight=max_inflight))
            try:
                result = future.result(timeout=max(remaining, 0.0))
            except FuturesTimeoutError:
                logger.warning(
                    "iteration %d exceeded the remaining time budget (%.1fs left when dispatched) and is "
                    "still running in the background; the CLI is stopping here rather than waiting "
                    "further -- re-run with the same --assessment-id to resume once it finishes",
                    iteration, remaining,
                )
                _pool.shutdown(wait=False)
                final_status = AssessmentStatus.RUNNING
                break
            _pool.shutdown(wait=False)
            traces = [result] if max_inflight <= 1 else result

            if all(trace.objective is None for trace in traces):
                # A real distinction (point E): "nothing is eligible right now" is not automatically the
                # same as "the assessment is done" -- but with no agent-capability signal to tell them
                # apart beyond the scheduler's own reason text, this is reported honestly as incomplete,
                # not silently marked complete.
                logger.info("iteration %d: no justified next action -- %s", iteration, traces[0].blocked_reason)
                final_status = AssessmentStatus.FAILED  # "blocked", in this schema's vocabulary
                break

            for trace in traces:
                if trace.objective is None:
                    continue
                logger.info(
                    "iteration %d: task=%s agent=%s score=%.2f findings=%d (+%d via binary handoff) "
                    "verification=%s parent=%s",
                    iteration, trace.task_id, trace.agent_id.value if trace.agent_id else None,
                    trace.selection_explanation.get("selected", {}).get("total_score", 0.0),
                    trace.findings_count, trace.binary_findings_count,
                    None, parent_task_id,
                )
            # Each batch becomes the parent of the next -- a plain, honest provenance chain of "the loop
            # kept going from here", not a claim about which specific finding justified it (the scheduler's
            # persisted explanation on each task already says that precisely). With several traces in one
            # batch, the first one with a real task_id anchors the next batch's parent link.
            parent_task_id = next((t.task_id for t in traces if t.task_id), parent_task_id)
    except KeyboardInterrupt:
        logger.info("interrupted by user after %d iteration(s) -- state is persisted; re-run the same "
                   "command with the same --assessment-id to resume", iteration)
        final_status = AssessmentStatus.RUNNING
        with session_scope() as db:
            repository.update_assessment_status(db, assessment_id, final_status)
        return 130

    with session_scope() as db:
        repository.update_assessment_status(
            db, assessment_id, final_status,
            completed_at=datetime.now(timezone.utc) if final_status != AssessmentStatus.RUNNING else None,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.orchestrator")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="start or resume the autonomous assessment loop")
    run_parser.add_argument("--assessment-id", required=True)
    run_parser.add_argument("--scope", required=True, help="CIDR this assessment is authorised against (recorded, not re-derived)")
    run_parser.add_argument("--max-minutes", type=float, default=20.0)
    run_parser.add_argument("--network-graph", default=None,
                            help="path to a NetworkGraph JSON file, for offline/test use. Omit it (the "
                                 "normal case) and a brand-new assessment_id starts Probe itself, for "
                                 "real, against --scope; an existing assessment_id just resumes")
    run_parser.add_argument("--probe-port", type=int, default=8080)
    run_parser.add_argument("--probe-minutes", type=float, default=5.0,
                            help="wall-clock budget for Probe's own discovery pass, when it is started by this command")
    run_parser.add_argument("--max-inflight", type=int, default=1,
                            help="how many independent, eligible candidates to dispatch concurrently per "
                                 "iteration (default 1: the original one-at-a-time behaviour). >1 uses "
                                 "app.orchestrator.autonomous_loop.run_concurrent_iteration, still subject "
                                 "to the per-surface caps in app.core.config (max_concurrent_web_tasks etc.)")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "run":
        return run(args.assessment_id, args.scope, args.max_minutes, args.network_graph,
                  probe_port=args.probe_port, probe_minutes=args.probe_minutes, max_inflight=args.max_inflight)
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
