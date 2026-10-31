"""Source fidelity and freshness checks without contacting a running Probe."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from app.adapters.discovery_snapshot import read_snapshot, save_snapshot
from app.adapters.network_graph_adapter import ProbeAPISource, load_network_graph, normalise_probe_graph
from app.core.config import settings
from app.core.exceptions import GraphValidationError
from app.reporting.generator import _build_report_data
from tests.test_reporting import _minimal_state


@pytest.fixture(autouse=True)
def isolated_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_dir", tmp_path)


def payload():
    return {
        "_probe_hosts": [{"ip": "10.20.30.10", "open_ports": [{"port": 8080, "service": "http", "banner": "Observed app"}]}],
        "_probe_segments": [],
        "_probe_metadata": {"report": {"summary": {"converged": False}, "authorised_scope": ["10.20.30.0/24"],
            "network_observations": [{"kind": "http-application-view", "resource": "/public-resource", "source_port": 8080}]}},
        "_import_limitations": [],
    }


def test_content_addressed_archive_replays_without_duplicate_files(tmp_path):
    first = save_snapshot(payload(), source="http://127.0.0.1:8080", scope_id="SCOPE-TEST")
    second = save_snapshot(payload(), source="http://127.0.0.1:8080", scope_id="SCOPE-TEST")
    assert first == second
    assert len(list((tmp_path / "discovery_snapshots").iterdir())) == 1
    assert read_snapshot(first)["payload"] == payload()


def test_simultaneous_archive_writers_publish_complete_content():
    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(lambda _: save_snapshot(payload(), source="offline", scope_id="SCOPE-TEST"), range(2)))
    assert paths[0] == paths[1]
    assert read_snapshot(paths[0])["payload"] == payload()


def test_tampered_archive_cannot_be_read_or_reused():
    path = save_snapshot(payload(), source="offline", scope_id="SCOPE-TEST")
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(GraphValidationError, match="hash"):
        read_snapshot(path)
    with pytest.raises(GraphValidationError, match="hash"):
        save_snapshot(payload(), source="offline", scope_id="SCOPE-TEST")


def test_snapshot_records_app_metadata_and_scope_without_granting_permission(monkeypatch):
    from probe.client import ProbeClient

    raw = payload()
    monkeypatch.setattr(ProbeClient, "status", lambda self: {"last_scan": {"id": 4, "status": "done"}})
    monkeypatch.setattr(ProbeClient, "hosts", lambda self: raw["_probe_hosts"])
    monkeypatch.setattr(ProbeClient, "segments", lambda self: [])
    monkeypatch.setattr(ProbeClient, "state", lambda self: {"edges": [{"relation": "http-application-view"}]})
    monkeypatch.setattr(ProbeClient, "report", lambda self: raw["_probe_metadata"]["report"])
    graph = load_network_graph(ProbeAPISource(base_url="http://127.0.0.1:8080"), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST")
    retained = read_snapshot(graph.raw_source_ref)
    assert retained["observation_only"] is True
    assert retained["payload"]["_probe_metadata"]["state"]["edges"][0]["relation"] == "http-application-view"
    state = _minimal_state(network_graph=graph)
    report = _build_report_data(state)
    assert report["discovery_provenance"]["integrity_verified"]
    assert report["discovery_provenance"]["network_observation_count"] == 1
    assert report["assessment_coverage"]["discovery_status"] == "incomplete"
    assert not state["policy"].allow_binary_analysis
    assert state["policy"].approved_web_origins == []


def test_import_rejects_inventory_that_changes_scan_identity_mid_read(monkeypatch):
    from probe.client import ProbeClient

    ids = iter([1, 2])
    monkeypatch.setattr(ProbeClient, "status", lambda self: {"last_scan": {"id": next(ids), "status": "done"}})
    monkeypatch.setattr(ProbeClient, "hosts", lambda self: payload()["_probe_hosts"])
    monkeypatch.setattr(ProbeClient, "segments", lambda self: [])
    monkeypatch.setattr(ProbeClient, "state", lambda self: {})
    monkeypatch.setattr(ProbeClient, "report", lambda self: {})
    with pytest.raises(GraphValidationError, match="changed during"):
        ProbeAPISource(base_url="http://127.0.0.1:8080").load_raw()


def test_report_surfaces_snapshot_integrity_failure():
    path = save_snapshot(payload(), source="offline", scope_id="SCOPE-TEST")
    graph = normalise_probe_graph(payload(), scope_id="SCOPE-TEST", raw_source_ref=str(path))
    path.write_text("{}", encoding="utf-8")
    report = _build_report_data(_minimal_state(network_graph=graph))
    assert report["discovery_provenance"]["integrity_verified"] is False
    assert report["assessment_coverage"]["overall"] == "incomplete"
    assert any("could not be verified" in message for message in report["incomplete_tasks_and_limitations"])
