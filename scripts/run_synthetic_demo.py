#!/usr/bin/env python
"""Synthetic end-to-end demo — NOT run during development per project
convention; run this yourself once the venv has `requirements.txt`
installed. Uses the default SQLite database (no external service needed) —
set APE_DATABASE_URL first if you want to point it at something else.

Exercises the full pipeline against the bundled sample network graph
(tests/fixtures/network_graphs/sample_graph.json) and the synthetic
Ghidra/Katana/ZAP fixtures (no external network access, no organiser
targets). Prints the final assessment status and where the JSON/PDF reports
were written.

Usage:
    python scripts/run_synthetic_demo.py
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402
from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus  # noqa: E402
from app.database import repository  # noqa: E402
from app.database.session import init_db, session_scope  # noqa: E402
from app.orchestrator.graph import run_assessment  # noqa: E402
from app.orchestrator.state import OrchestratorState  # noqa: E402

FIXTURE_GRAPH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "network_graphs" / "sample_graph.json"


def main() -> None:
    settings.ensure_directories()
    init_db()

    assessment_id = f"ASSESSMENT-DEMO-{uuid.uuid4().hex[:8]}"
    scope_id = "SCOPE-HACKATHON-01"
    policy = AssessmentPolicy(
        allow_passive_web_analysis=True,
        allow_web_crawling=True,
        allow_active_web_verification=False,  # safe default — demo stays passive-only
        allow_binary_analysis=False,  # no fixture binary wired into this demo; see tests/test_binary_agent.py
        allow_network_service_assessment=True,
        approved_web_origins=["https://web01.lab.local:443", "http://api01.lab.local"],
        approved_asset_ids=["HOST-001", "HOST-002", "HOST-003"],
        dry_run=False,
    )

    with session_scope() as db:
        repository.create_assessment(
            db, Assessment(assessment_id=assessment_id, scope_id=scope_id, status=AssessmentStatus.CREATED, assessment_policy=policy),
        )

    # Build the external-contract-shaped payload directly (ExternalNetworkFinding,
    # not Finding) — this is what the orchestrator's ingestion node, and the
    # real /external-findings endpoint, both expect to receive.
    from app.core.schemas import ExternalNetworkFinding, Severity

    external_payload = [
        ExternalNetworkFinding(
            assessment_id=assessment_id, scope_id=scope_id, asset_id="HOST-003", service_id="HOST-003:SVC-004",
            finding_id="NET-DEMO-001", title="Outdated PostgreSQL version (synthetic)",
            description="Synthetic fixture standing in for the teammate's Network Vulnerability Agent.",
            severity=Severity.MEDIUM,
        ).model_dump(mode="json")
    ]

    initial_state: OrchestratorState = {
        "assessment_id": assessment_id,
        "scope_id": scope_id,
        "policy": policy,
        "network_graph_source_path": str(FIXTURE_GRAPH),
        "binary_paths": [],
        "external_network_findings_raw": external_payload,
        "errors": [],
    }

    print(f"Running synthetic demo assessment {assessment_id} ...")
    final_state = run_assessment(initial_state)

    print(f"\nFinal status: {final_state.get('assessment_status')}")
    print(f"Findings: {len(final_state.get('validated_findings', []))}")
    print(f"Report (JSON): {final_state.get('report_json_path')}")
    print(f"Report (PDF):  {final_state.get('report_pdf_path')}")
    if final_state.get("errors"):
        print("\nErrors/warnings recorded:")
        for e in final_state["errors"]:
            print(f"  - {e}")


if __name__ == "__main__":
    main()
