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
    """Starts Probe itself (python -m probe run), under this orchestrator's control, against exactly the
    authorised scope, and reads back its real discovery as this assessment's initial NetworkGraph --
    nothing here is a canned graph. Probe's own code (probe/cli.py::_ensure_privileges) asks Windows for
    admin rights itself via a UAC prompt if this process is not already elevated; this function only
    starts the process and waits for its API to come up, it never tries to grant itself privileges."""
    from app.adapters.network_graph_adapter import ProbeAPISource, normalise_probe_graph
    from probe.client import ProbeClient, ProbeError

    data_dir = Path(settings.evidence_dir) / assessment_id / "probe-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    # NOT --no-ui: Probe's own cli.py only starts uvicorn (its web view AND its API) when --no-ui is
    # absent (probe/cli.py:345) -- passing --no-ui here left no API for ProbeClient.status() to ever poll,
    # so this always timed out after 180s even though the scan itself completed normally underneath it.
    cmd = [sys.executable, "-m", "probe", "run", "--scope", scope, "--port", str(port),
          "--data-dir", str(data_dir), "--max-minutes", str(probe_minutes),
          "--authorisations", str(REPO_ROOT / "authorisations.json")]
    logger.info("starting Probe under orchestrator control: %s", " ".join(cmd))
    subprocess.Popen(cmd, cwd=str(REPO_ROOT))

    base_url = f"http://127.0.0.1:{port}"
    client = ProbeClient(base_url=base_url)
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            client.status()
            break
        except ProbeError:
            time.sleep(2.0)
    else:
        raise SystemExit(
            f"Probe's API never came up at {base_url} within 180s. If a Windows UAC elevation prompt "
            "appeared, it must be approved for raw packet discovery to run; if it was declined or this "
            "ran in a non-interactive context where no one could approve it, Probe could not start."
        )
    logger.info("Probe API is up at %s -- requesting a scan of %s", base_url, scope)
    raw = ProbeAPISource(base_url=base_url, ensure_scan=True).load_raw()
    return normalise_probe_graph(raw, scope_id=f"SCOPE-{scope.replace('/', '-')}", raw_source_ref=base_url)


def _load_or_create(
    assessment_id: str, scope: str, network_graph_path: str | None, *, probe_port: int, probe_minutes: float,
) -> AssessmentPolicy:
    with session_scope() as db:
        try:
            return repository.get_assessment_policy(db, assessment_id)
        except AppError:
            pass  # does not exist yet -- fall through to initialise it

    if network_graph_path:
        graph = NetworkGraph.model_validate(json.loads(Path(network_graph_path).read_text()))
        logger.info("initialised %s (scope=%s) from supplied graph file %s", assessment_id, scope, network_graph_path)
    else:
        graph = _start_probe_and_discover(scope, assessment_id, port=probe_port, probe_minutes=probe_minutes)
        logger.info("initialised %s (scope=%s) from Probe's own real discovery -- %d asset(s)",
                   assessment_id, scope, len(graph.assets))

    policy = AssessmentPolicy(
        allow_network_discovery=True, allow_network_service_assessment=True, allow_passive_web_analysis=True,
        allow_web_crawling=True, allow_content_discovery=True, allow_binary_analysis=True,
        allow_single_credential_verification=True, dry_run=False,
    )
    with session_scope() as db:
        repository.create_assessment(db, Assessment(
            assessment_id=assessment_id, scope_id=graph.scope_id, status=AssessmentStatus.RUNNING,
            assessment_policy=policy,
        ))
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
            # max_inflight=1 (the default) keeps the original one-candidate-per-iteration behaviour exactly;
            # >1 dispatches up to that many independent, atomically-reserved candidates concurrently each
            # iteration (app.orchestrator.autonomous_loop.run_concurrent_iteration -- item 4/5/6 of the
            # concurrency spec), still one `while` tick per batch so the time-budget check above still applies.
            traces = ([run_next_iteration(assessment_id, policy=policy, output_dir=output_dir, parent_task_id=parent_task_id)]
                     if max_inflight <= 1 else
                     run_concurrent_iteration(assessment_id, policy=policy, output_dir=output_dir,
                                              parent_task_id=parent_task_id, max_inflight=max_inflight))

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
