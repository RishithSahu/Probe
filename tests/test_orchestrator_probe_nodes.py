"""Orchestrator node tests for the Probe integration specifically:
`load_network_graph` falling back to the live Probe API when no static
file path is supplied, and `ingest_network_agent_results` auto-pulling
Probe's leads. Uses the same real-probe-server fixture pattern as
tests/test_probe_integration.py.
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.schemas import Assessment, AssessmentPolicy, AssessmentStatus
from app.database import repository
from app.database.session import SessionLocal, init_db
from app.orchestrator import nodes
from probe.store import Store
from probe.web.app import create_app
from tests.conftest import start_probe_test_server, stop_probe_test_server


@pytest.fixture(scope="module")
def probe_server():
    store = Store(":memory:")
    store.upsert_host("10.40.50.5")
    store.update_host("10.40.50.5", verdict="CONFIRMED_ONLINK")
    store.upsert_service("10.40.50.5", 80, service="http")
    store.add_lead("10.40.50.5", "banner matched a known-vulnerable product string", "vulnerable-app")

    app = create_app(store, scope=None, request_scan=None)
    server, thread, base_url = start_probe_test_server(app)
    yield base_url
    stop_probe_test_server(server, thread)


@pytest.fixture
def db_assessment():
    init_db()
    assessment_id = "ASSESSMENT-NODE-TEST"
    db = SessionLocal()
    try:
        existing = repository.get_assessment(db, assessment_id)
    except Exception:
        existing = None
    if existing is None:
        repository.create_assessment(
            db, Assessment(assessment_id=assessment_id, scope_id="SCOPE-NODE-TEST", status=AssessmentStatus.CREATED,
                            assessment_policy=AssessmentPolicy()),
        )
        db.commit()
    db.close()
    return assessment_id


def test_load_network_graph_falls_back_to_probe_api(probe_server, db_assessment, monkeypatch):
    monkeypatch.setattr(settings, "probe_api_url", probe_server)
    state = {
        "assessment_id": db_assessment,
        "scope_id": "SCOPE-NODE-TEST",
        "network_graph_source_path": None,
        "errors": [],
    }
    result = nodes.load_network_graph(state)
    assert "network_graph" in result
    graph = result["network_graph"]
    assert {a.asset_id for a in graph.assets} == {"10.40.50.5"}


def test_load_network_graph_errors_cleanly_with_no_source_at_all(db_assessment, monkeypatch):
    monkeypatch.setattr(settings, "probe_api_url", None)
    state = {
        "assessment_id": db_assessment,
        "scope_id": "SCOPE-NODE-TEST",
        "network_graph_source_path": None,
        "errors": [],
    }
    result = nodes.load_network_graph(state)
    assert "network_graph" not in result
    assert any("no network_graph_source_path" in e for e in result["errors"])


def test_ingest_network_agent_results_auto_pulls_probe_leads(probe_server, db_assessment, monkeypatch):
    monkeypatch.setattr(settings, "probe_api_url", probe_server)
    monkeypatch.setattr(settings, "probe_auto_ingest_leads", True)
    state = {
        "assessment_id": db_assessment,
        "scope_id": "SCOPE-NODE-TEST",
        "network_graph": None,
        "external_network_findings_raw": [],
        "errors": [],
    }
    result = nodes.ingest_network_agent_results(state)
    findings = result["network_agent_findings"]
    assert len(findings) == 1
    assert findings[0].detection_method == "probe_lead:vulnerable-app"
    assert len(result["network_agent_evidence"]) == 1


def test_ingest_network_agent_results_skipped_when_nothing_configured(db_assessment, monkeypatch):
    monkeypatch.setattr(settings, "probe_api_url", None)
    state = {
        "assessment_id": db_assessment,
        "scope_id": "SCOPE-NODE-TEST",
        "network_graph": None,
        "external_network_findings_raw": [],
        "errors": [],
    }
    result = nodes.ingest_network_agent_results(state)
    assert result["network_agent_findings"] == []
    assert result["network_agent_evidence"] == []


def test_ingest_network_agent_results_probe_unreachable_is_recorded_not_fatal(db_assessment, monkeypatch):
    monkeypatch.setattr(settings, "probe_api_url", "http://127.0.0.1:1")
    monkeypatch.setattr(settings, "probe_auto_ingest_leads", True)
    state = {
        "assessment_id": db_assessment,
        "scope_id": "SCOPE-NODE-TEST",
        "network_graph": None,
        "external_network_findings_raw": [],
        "errors": [],
    }
    result = nodes.ingest_network_agent_results(state)
    assert result["network_agent_findings"] == []
    assert any("probe_leads" in e for e in result["errors"])
