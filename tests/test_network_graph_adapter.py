import json
from pathlib import Path

import pytest

from app.adapters.network_graph_adapter import (
    JSONFileNetworkGraphSource,
    extract_http_services,
    load_network_graph,
    normalise,
)
from app.core.exceptions import GraphValidationError

FIXTURE = Path(__file__).parent / "fixtures" / "network_graphs" / "sample_graph.json"


def test_loads_sample_graph_and_preserves_ids():
    graph = load_network_graph(JSONFileNetworkGraphSource(FIXTURE), raw_source_ref=str(FIXTURE))
    assert graph.scope_id == "SCOPE-HACKATHON-01"
    asset_ids = {a.asset_id for a in graph.assets}
    assert asset_ids == {"HOST-001", "HOST-002", "HOST-003"}
    host1 = next(a for a in graph.assets if a.asset_id == "HOST-001")
    service_ids = {s.service_id for s in host1.services}
    # original service ids preserved, namespaced by asset id
    assert "HOST-001:SVC-001" in service_ids


def test_edges_preserved_and_reference_known_assets():
    graph = load_network_graph(JSONFileNetworkGraphSource(FIXTURE))
    assert len(graph.edges) == 2
    assert all(e.source in {a.asset_id for a in graph.assets} for e in graph.edges)


def test_extract_http_services_only_returns_http_https():
    graph = load_network_graph(JSONFileNetworkGraphSource(FIXTURE))
    http_services = extract_http_services(graph)
    names = {s.service_name for _, s in http_services}
    assert names == {"https", "http"}
    assert len(http_services) == 2


def test_missing_scope_id_rejected():
    with pytest.raises(GraphValidationError):
        normalise({"hosts": []})


def test_missing_host_list_rejected():
    with pytest.raises(GraphValidationError):
        normalise({"scope_id": "X"})


def test_host_missing_asset_id_rejected():
    with pytest.raises(GraphValidationError):
        normalise({"scope_id": "X", "hosts": [{"ip": "10.0.0.1"}]})


def test_edge_referencing_unknown_asset_rejected():
    raw = json.loads(FIXTURE.read_text())
    raw["edges"].append({"source": "HOST-001", "target": "HOST-999"})
    with pytest.raises(GraphValidationError):
        normalise(raw)


def test_tolerant_synonyms_for_host_and_port_list():
    raw = {
        "scope_id": "X",
        "nodes": [
            {"node_id": "H1", "ip": "10.0.0.5", "open_ports": [80, 443]},
        ],
    }
    graph = normalise(raw)
    assert graph.assets[0].asset_id == "H1"
    assert {s.port for s in graph.assets[0].services} == {80, 443}


def test_file_not_found_raises():
    with pytest.raises(GraphValidationError):
        load_network_graph(JSONFileNetworkGraphSource("does/not/exist.json"))
