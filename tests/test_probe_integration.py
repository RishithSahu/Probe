"""Integration tests for the Network Graph Adapter's Probe API path and the
Probe-leads-to-Finding translator.

Runs the teammate's real `probe.web.app` FastAPI app (not a mock) against an
in-memory `probe.store.Store` pre-seeded with synthetic hosts/segments/leads
— a real HTTP round trip through `probe.client.ProbeClient`, exactly the
path `app.adapters.network_graph_adapter.ProbeAPISource` uses, with no
network discovery and no real scanning involved.
"""
from __future__ import annotations

import pytest

from app.adapters.network_graph_adapter import (
    ProbeAPISource,
    extract_http_services,
    load_network_graph,
    non_held_asset_ids,
    normalise_probe_graph,
)
from app.adapters.probe_leads import findings_from_probe_leads
from app.core.exceptions import GraphValidationError
from app.core.schemas import AssessmentPolicy
from app.core.scope_guard import ScopeGuard
from probe.store import Store
from probe.web.app import create_app
from tests.conftest import start_probe_test_server, stop_probe_test_server


def _seed_store(store: Store) -> None:
    # HOST-A: visible, confirmed, one HTTP service -> should become a web
    # target.
    store.upsert_host("10.20.30.10", mac="aa:bb:cc:dd:ee:01")
    store.update_host("10.20.30.10", verdict="CONFIRMED_ONLINK", roles=["forwarder"])
    store.upsert_service("10.20.30.10", 8080, service="http", product="Apache httpd", version="2.4.68",
                         scripts={"probe-http-metadata": {"resources": [{"path": "/"}]}})
    store.upsert_service("10.20.30.10", 22, service="ssh")

    # HOST-B: held (inside a hidden segment pending approval) — must never
    # become a web target or be in scope by default, even though it also has
    # an HTTP service.
    store.upsert_host("10.20.30.200", mac="aa:bb:cc:dd:ee:02")
    store.update_host("10.20.30.200", verdict="CONFIRMED_SEPARATE", held=True)
    store.upsert_service("10.20.30.200", 443, service="https")

    # A segment reached via HOST-A, containing HOST-B.
    store.upsert_segment(
        "10.20.30.192/26", kind="in-scope", state="held", verdict="CONFIRMED",
        via="10.20.30.10", evidence=["TTL delta"], hosts=["10.20.30.200"], extra={},
    )

    # Leads: one proof-backed, one heuristic.
    store.add_lead("10.20.30.200", "hidden behind 10.20.30.10 (TTL delta of 1)", "hidden-host")
    store.add_lead("10.20.30.10:8080", "title matched 'Login :: Damn Vulnerable Web Application'", "vulnerable-app")


@pytest.fixture(scope="module")
def probe_server():
    store = Store(":memory:")
    _seed_store(store)
    app = create_app(store, scope=None, request_scan=None)

    server, thread, base_url = start_probe_test_server(app)
    yield base_url
    stop_probe_test_server(server, thread)


def test_probe_api_source_loads_real_endpoints(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server),
        raw_source_ref=probe_server,
        normaliser=normalise_probe_graph,
        scope_id="SCOPE-TEST",
    )
    asset_ids = {a.asset_id for a in graph.assets}
    assert asset_ids == {"10.20.30.10", "10.20.30.200"}

    host_a = next(a for a in graph.assets if a.asset_id == "10.20.30.10")
    host_b = next(a for a in graph.assets if a.asset_id == "10.20.30.200")
    assert host_a.held is False
    assert host_b.held is True
    assert host_a.verdict == "CONFIRMED_ONLINK"

    service_names = {s.service_name for s in host_a.services}
    assert service_names == {"http", "ssh"}
    http_service = next(s for s in host_a.services if s.service_name == "http")
    assert http_service.product == "Apache httpd"
    assert http_service.version == "2.4.68"
    assert http_service.probe_observations["probe-http-metadata"]["resources"][0]["path"] == "/"
    assert host_a.probe_roles == ["forwarder"]


def test_probe_api_source_derives_edges_from_via(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
    )
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source == "10.20.30.10"
    assert edge.target == "10.20.30.200"
    assert edge.relation == "CONNECTS_TO"


def test_held_host_excluded_from_web_targets(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
    )
    http_targets = extract_http_services(graph)
    # HOST-B has an https service but is held — must not appear.
    assert {a.asset_id for a, _ in http_targets} == {"10.20.30.10"}


def test_non_held_asset_ids_excludes_held(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
    )
    assert non_held_asset_ids(graph) == {"10.20.30.10"}


def test_scope_guard_refuses_held_asset_even_if_explicitly_approved(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
    )
    # Operator mistake: explicitly lists the held host. ScopeGuard must still refuse it.
    policy = AssessmentPolicy(approved_asset_ids=["10.20.30.10", "10.20.30.200"])
    guard = ScopeGuard(policy, graph)
    guard.check_asset_in_scope("10.20.30.10")  # fine
    with pytest.raises(Exception):
        guard.check_asset_in_scope("10.20.30.200")


def test_scope_guard_default_scope_excludes_held_without_explicit_list(probe_server):
    graph = load_network_graph(
        ProbeAPISource(base_url=probe_server), normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
    )
    policy = AssessmentPolicy()  # no approved_asset_ids given at all
    guard = ScopeGuard(policy, graph)
    guard.check_asset_in_scope("10.20.30.10")  # falls back to "all non-held"
    with pytest.raises(Exception):
        guard.check_asset_in_scope("10.20.30.200")


def test_probe_api_source_unreachable_raises_graph_validation_error():
    with pytest.raises(GraphValidationError):
        load_network_graph(
            ProbeAPISource(base_url="http://127.0.0.1:1"),  # nothing listens on port 1
            normaliser=normalise_probe_graph, scope_id="SCOPE-TEST",
        )


def test_findings_from_probe_leads_translates_both_sources(probe_server):
    from probe.client import ProbeClient

    leads = ProbeClient(base_url=probe_server).leads()
    assert len(leads) == 2

    findings, evidence = findings_from_probe_leads(leads, assessment_id="ASSESSMENT-TEST")
    assert len(findings) == 2
    assert len(evidence) == 2
    assert all(f.status.value == "suspected" for f in findings)
    assert all(f.agent_id.value == "network_vulnerability_agent" for f in findings)

    by_source = {f.detection_method: f for f in findings}
    hidden = by_source["probe_lead:hidden-host"]
    assert hidden.asset_id == "10.20.30.200"
    assert hidden.severity.value == "medium"

    vuln = by_source["probe_lead:vulnerable-app"]
    assert vuln.asset_id == "10.20.30.10:8080"
    assert vuln.severity.value == "high"
    assert vuln.confidence.value == "low"


def test_findings_from_probe_leads_handles_unknown_source_gracefully():
    findings, evidence = findings_from_probe_leads(
        [{"address": "10.0.0.5", "evidence": "something odd", "source": "a-brand-new-lead-type", "count": 1}],
        assessment_id="ASSESSMENT-TEST",
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert findings[0].status.value == "suspected"
