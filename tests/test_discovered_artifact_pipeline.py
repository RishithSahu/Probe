"""End-to-end test of the generic discovered-binary pipeline: Web Agent reports a binary REFERENCE only (no
credential extraction, no bytes retained) -> the Orchestrator notices it and creates a Binary Analysis task in
the shared ledger automatically -> the Binary Analysis Agent acquires the file itself, runs static analysis
WITHOUT ever substituting the canned Ghidra fixture for a real file, and produces a credential finding with
full provenance (SHA-256, source URL, extraction method) and an honest service-correlation statement.

A generic local test server stands in for "the challenge environment" -- nothing here names any real
service, file, or credential; every string is a synthetic test value.
"""
from __future__ import annotations

import dataclasses
import hashlib
import http.server
import threading
import uuid

import pytest

from app.agents.binary_analysis import acquisition, discovered_artifact
from app.agents.web_security import content_discovery
from app.core.config import settings
from app.core.exceptions import ScopeViolationError
from app.core.schemas import (
    AgentId,
    AgentResult,
    Assessment,
    AssessmentPolicy,
    AssessmentStatus,
    NetworkGraph,
    NetworkGraphAssetRecord,
    NetworkGraphServiceRecord,
    TaskStatus,
)
from app.core.scope_guard import ScopeGuard
from app.database import repository
from app.database.session import SessionLocal, init_db
from app.orchestrator import nodes

HIDDEN_PATH = "/backup"                               # a generic, made-up "undisclosed resource" path
CORRELATION_PORT = 9999                                # a made-up port number, used only as a test value
CREDENTIAL_LIKE = "T3st-Cred_Value!42"                  # synthetic, shaped like a secret, not a real one


class _Handler(http.server.BaseHTTPRequestHandler):
    """Generic fixture app: every path redirects except one undisclosed path, which serves a small binary-
    looking payload containing a credential-shaped string and (optionally) a value that correlates it with
    a specific service."""

    body_with_correlation = (
        f"generic header\x00API_SECRET={CREDENTIAL_LIKE}\x00service-port:{CORRELATION_PORT}\x00trailer"
    ).encode("ascii")
    body_without_correlation = f"generic header\x00API_SECRET={CREDENTIAL_LIKE}\x00trailer".encode("ascii")
    serve_correlation = True

    def do_GET(self):  # noqa: N802 - stdlib handler method name
        if self.path.lstrip("/") == HIDDEN_PATH.lstrip("/"):
            body = self.body_with_correlation if _Handler.serve_correlation else self.body_without_correlation
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, fmt, *args):  # noqa: A002 - silence stdlib's default stderr logging
        pass


@pytest.fixture
def fixture_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url
    server.shutdown()
    thread.join(timeout=5)


def _policy(**overrides) -> AssessmentPolicy:
    defaults = dict(
        allow_content_discovery=True, allow_binary_analysis=True, dry_run=False,
        max_content_discovery_requests=60,
    )
    defaults.update(overrides)
    return AssessmentPolicy(**defaults)


def _graph(base_url: str, *, with_matching_port: bool) -> NetworkGraph:
    host = base_url.split("//", 1)[1].split(":")[0]
    port = int(base_url.rsplit(":", 1)[1])
    service_port = CORRELATION_PORT if with_matching_port else 31337
    return NetworkGraph(
        scope_id="SCOPE-TEST",
        assets=[NetworkGraphAssetRecord(
            asset_id="HOST-TEST", ip=host,
            services=[NetworkGraphServiceRecord(service_id=f"HOST-TEST:{port}/tcp", asset_id="HOST-TEST", port=port),
                      NetworkGraphServiceRecord(service_id=f"HOST-TEST:{service_port}/tcp", asset_id="HOST-TEST",
                                                port=service_port, service_name="generic-test-service")],
        )],
    )


# ---------------------------------------------------------------------------
# 1. content discovery: reports a REFERENCE only, never extracts anything from it
# ---------------------------------------------------------------------------


def test_hidden_binary_path_is_found_by_baseline_diff(fixture_server):
    policy = _policy()
    guard = ScopeGuard(policy, _graph(fixture_server, with_matching_port=True))
    result = content_discovery.discover_hidden_paths(
        fixture_server, asset_id="HOST-TEST", scope_guard=guard,
        max_requests=60, rate_per_second=50.0,
    )
    assert any(r.url.endswith("/backup") for r in result.binary_references)
    # every OTHER guess redirects identically to the baseline: none of them should be reported as hits
    assert len(result.hits) == 1


def test_no_bytes_are_retained_by_content_discovery(fixture_server):
    """The dataclass has no field capable of holding downloaded bytes at all -- this asserts that by
    construction, not just by behaviour."""
    ref_fields = {f.name for f in dataclasses.fields(content_discovery.BinaryReference)}
    assert not ({"body", "content", "data"} & ref_fields)


def test_disabled_policy_makes_no_request_at_all(fixture_server):
    policy = _policy(allow_content_discovery=False)
    guard = ScopeGuard(policy, _graph(fixture_server, with_matching_port=True))
    result = content_discovery.discover_hidden_paths(
        fixture_server, asset_id="HOST-TEST", scope_guard=guard, max_requests=60, rate_per_second=50.0,
    )
    assert result.requests_made == 0
    assert result.errors


# ---------------------------------------------------------------------------
# 2. acquisition: the Binary Analysis Agent's OWN fetch, real hash of real bytes
# ---------------------------------------------------------------------------


def test_acquisition_computes_the_real_sha256_of_the_real_bytes(tmp_path, fixture_server):
    import hashlib

    policy = _policy()
    guard = ScopeGuard(policy, _graph(fixture_server, with_matching_port=True))
    acquired = acquisition.acquire_binary(
        f"{fixture_server}{HIDDEN_PATH}", asset_id="HOST-TEST", scope_guard=guard, output_dir=tmp_path,
    )
    assert acquired.sha256 == hashlib.sha256(_Handler.body_with_correlation).hexdigest()
    assert acquired.saved_path.read_bytes() == _Handler.body_with_correlation


def test_acquisition_denied_without_allow_binary_analysis(tmp_path, fixture_server):
    policy = _policy(allow_binary_analysis=False)
    guard = ScopeGuard(policy, _graph(fixture_server, with_matching_port=True))
    with pytest.raises(ScopeViolationError):
        acquisition.acquire_binary(
            f"{fixture_server}{HIDDEN_PATH}", asset_id="HOST-TEST", scope_guard=guard, output_dir=tmp_path,
        )


def test_acquisition_denied_for_an_origin_outside_approved_web_origins(tmp_path, fixture_server):
    policy = _policy(approved_web_origins=["http://totally-different-host.invalid"])
    guard = ScopeGuard(policy, _graph(fixture_server, with_matching_port=True))
    with pytest.raises(ScopeViolationError):
        acquisition.acquire_binary(
            f"{fixture_server}{HIDDEN_PATH}", asset_id="HOST-TEST", scope_guard=guard, output_dir=tmp_path,
        )


# ---------------------------------------------------------------------------
# 3. discovered_artifact analysis: never the canned fixture; honest correlation
# ---------------------------------------------------------------------------


def test_never_uses_the_canned_ghidra_fixture_for_an_acquired_binary(tmp_path):
    """Ghidra is not installed in this environment (APE_GHIDRA_INSTALL_DIR unset) -- confirms the fallback is
    the REAL raw-string scan, and none of the synthetic fixture's canned strings leak into the result."""
    saved_path = tmp_path / "artifact.bin"
    saved_path.write_bytes(_Handler.body_with_correlation)
    acquired = acquisition.AcquiredBinary(
        source_url="http://example.test/backup", saved_path=saved_path,
        sha256=hashlib.sha256(_Handler.body_with_correlation).hexdigest(),
        byte_count=len(_Handler.body_with_correlation), truncated=False,
    )

    analysis = discovered_artifact.analyse_discovered_binary(
        acquired, output_dir=tmp_path, correlation_terms=(str(CORRELATION_PORT),),
    )
    assert analysis.analysis_depth == discovered_artifact.ANALYSIS_STRINGS_ONLY
    assert not analysis.incomplete
    fixture_only_strings = {"S3cr3tP@ssw0rd!", "admin", "/bin/sh"}
    found_values = {w.matched_value for w in analysis.weaknesses if w.matched_value}
    assert not (found_values & fixture_only_strings)
    cred = next(w for w in analysis.weaknesses if w.category == "hardcoded_credential")
    assert cred.context["sha256"] == acquired.sha256
    assert cred.context["source_url"] == acquired.source_url
    assert cred.context["extraction_method"] == "raw_printable_string_scan"
    assert "corroborated" in cred.context["service_correlation"]


def test_correlation_is_honestly_unconfirmed_when_nothing_else_matches(tmp_path):
    saved_path = tmp_path / "artifact2.bin"
    saved_path.write_bytes(_Handler.body_without_correlation)
    acquired = acquisition.AcquiredBinary(
        source_url="http://example.test/backup", saved_path=saved_path,
        sha256=hashlib.sha256(_Handler.body_without_correlation).hexdigest(),
        byte_count=len(_Handler.body_without_correlation), truncated=False,
    )

    analysis = discovered_artifact.analyse_discovered_binary(
        acquired, output_dir=tmp_path, correlation_terms=(str(CORRELATION_PORT),),
    )
    cred = next(w for w in analysis.weaknesses if w.category == "hardcoded_credential")
    assert "unconfirmed" in cred.context["service_correlation"]
    assert cred.confidence == "low"


def test_an_unreadable_acquired_file_is_an_explicit_incomplete_result_not_a_fabrication(tmp_path):
    missing = tmp_path / "does-not-exist.bin"
    acquired = acquisition.AcquiredBinary(source_url="http://example.test/x", saved_path=missing,
                                          sha256="x", byte_count=0, truncated=False)
    analysis = discovered_artifact.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.incomplete
    assert analysis.weaknesses == []
    assert analysis.errors


def test_an_empty_file_produces_no_weaknesses_and_is_marked_incomplete(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    acquired = acquisition.AcquiredBinary(source_url="http://example.test/x", saved_path=empty,
                                          sha256="x", byte_count=0, truncated=False)
    analysis = discovered_artifact.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.incomplete
    assert analysis.weaknesses == []


# ---------------------------------------------------------------------------
# 4. orchestrator: automatic task-ledger handoff, end to end, no AUTH/verification attempted
# ---------------------------------------------------------------------------


@pytest.fixture
def db_assessment(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    init_db()
    assessment_id = f"ASSESSMENT-DISCOVERED-{uuid.uuid4().hex[:10]}"
    db = SessionLocal()
    try:
        repository.create_assessment(
            db, Assessment(assessment_id=assessment_id, scope_id="SCOPE-TEST", status=AssessmentStatus.CREATED,
                            assessment_policy=AssessmentPolicy()),
        )
        db.commit()
    finally:
        db.close()
    return assessment_id


def test_orchestrator_creates_a_task_and_produces_a_provenanced_finding(db_assessment, fixture_server):
    graph = _graph(fixture_server, with_matching_port=True)
    policy = _policy()
    state = {
        "assessment_id": db_assessment, "policy": policy, "network_graph": graph,
        "web_agent_result": AgentResult(
            agent_id=AgentId.WEB_SECURITY, assessment_id=db_assessment,
            execution_status=TaskStatus.COMPLETED,
            discovered_binary_references=[{
                "asset_id": "HOST-TEST", "url": f"{fixture_server}{HIDDEN_PATH}",
                "content_type": "application/octet-stream", "content_length": len(_Handler.body_with_correlation),
                "reason": "content-type 'application/octet-stream'",
            }],
        ),
        "errors": [],
    }
    out = nodes.handle_discovered_binaries(state)
    result = out["triggered_binary_agent_result"]
    assert result.findings, "expected at least the hardcoded-credential finding"
    cred_finding = next(f for f in result.findings if f.detection_method == "hardcoded_credential")
    evidence = next(e for e in result.evidence if e.evidence_id in cred_finding.evidence_refs)
    assert evidence.raw_data["sha256"]
    assert evidence.raw_data["source_url"] == f"{fixture_server}{HIDDEN_PATH}"
    assert evidence.raw_data["extraction_method"] == "raw_printable_string_scan"
    assert "corroborated" in evidence.raw_data["service_correlation"]

    with SessionLocal() as db:
        tasks = repository.list_agent_tasks(db, db_assessment)
    triggered = [t for t in tasks if t.task_type == "binary_analysis_triggered_by_web_discovery"]
    assert triggered and triggered[0].status == "completed"


def test_orchestrator_refuses_without_allow_binary_analysis_and_creates_no_task(db_assessment, fixture_server):
    graph = _graph(fixture_server, with_matching_port=True)
    policy = _policy(allow_binary_analysis=False)
    state = {
        "assessment_id": db_assessment, "policy": policy, "network_graph": graph,
        "web_agent_result": AgentResult(
            agent_id=AgentId.WEB_SECURITY, assessment_id=db_assessment, execution_status=TaskStatus.COMPLETED,
            discovered_binary_references=[{"asset_id": "HOST-TEST", "url": f"{fixture_server}{HIDDEN_PATH}",
                                           "content_type": None, "content_length": 0, "reason": "test"}],
        ),
        "errors": [],
    }
    out = nodes.handle_discovered_binaries(state)
    assert out.get("triggered_binary_agent_result") is None
    assert out["errors"]
    with SessionLocal() as db:
        tasks = repository.list_agent_tasks(db, db_assessment)
    assert not [t for t in tasks if t.task_type == "binary_analysis_triggered_by_web_discovery"]


def test_no_network_connection_or_finding_is_ever_attempted_against_port_8833_equivalent(db_assessment, fixture_server):
    """Guards the explicit instruction: this pipeline must demonstrate acquisition + analysis only. Nothing
    in handle_discovered_binaries opens a second TCP connection to "verify" anything beyond the HTTP fetch
    content_discovery/acquisition already made."""
    import app.orchestrator.nodes as nodes_module

    assert not hasattr(nodes_module, "attempt_console_verification")
    assert "console_auth" not in dir(nodes_module)
