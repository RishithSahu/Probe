"""Attack-path correlation using NetworkX.

Builds a directed graph of hosts, services, web applications, binaries, and
findings, then classifies edges into two tiers so the report can distinguish
what's actually been shown to be true from what's merely structurally
possible:

  - Structural / potential edges (HOSTS, EXPOSES, CONNECTS_TO,
    POTENTIAL_ACCESS_RELATION): derived purely from the network graph's own
    topology and from a finding's existence. These represent *possible*
    relationships, not demonstrated ones.
  - Evidence-backed edges (AFFECTED_BY, VERIFIED_TRANSITION): only added when
    a finding's status is `confirmed` with supporting evidence. Network
    connectivity alone is never treated as proof of compromise — a
    CONNECTS_TO edge never becomes a VERIFIED_TRANSITION without a matching
    confirmed finding.

Nothing here performs lateral movement or any live validation; it is a pure
graph-construction/analysis pass over already-collected data.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from app.core.schemas import Finding, FindingStatus, NetworkGraph, Surface

RELATION_HOSTS = "HOSTS"
RELATION_EXPOSES = "EXPOSES"
RELATION_CONNECTS_TO = "CONNECTS_TO"
RELATION_AFFECTED_BY = "AFFECTED_BY"
RELATION_POTENTIAL_ACCESS = "POTENTIAL_ACCESS_RELATION"
RELATION_VERIFIED_TRANSITION = "VERIFIED_TRANSITION"

_EVIDENCE_BACKED_RELATIONS = {RELATION_AFFECTED_BY, RELATION_VERIFIED_TRANSITION}


@dataclass
class AttackPathEdge:
    source: str
    target: str
    relation: str
    evidence_backed: bool
    finding_id: str | None = None


@dataclass
class AttackPathGraph:
    graph: nx.DiGraph
    edges: list[AttackPathEdge] = field(default_factory=list)

    def to_edge_dicts(self) -> list[dict]:
        return [
            {
                "source": e.source,
                "target": e.target,
                "relation": e.relation,
                "evidence_backed": e.evidence_backed,
                "finding_id": e.finding_id,
            }
            for e in self.edges
        ]

    def potential_paths_to(self, target_node: str) -> list[list[str]]:
        """All simple paths in the full graph (structural + evidence-backed)
        reaching `target_node` — i.e. "could an attacker plausibly reach X",
        not "has reaching X been demonstrated"."""
        paths: list[list[str]] = []
        for node in self.graph.nodes:
            if node == target_node:
                continue
            try:
                for path in nx.all_simple_paths(self.graph, node, target_node, cutoff=6):
                    paths.append(path)
            except nx.NodeNotFound:
                continue
        return paths

    def verified_transition_subgraph(self) -> nx.DiGraph:
        """Subgraph containing ONLY evidence-backed edges — i.e. what has
        actually been demonstrated, for a report section that must not
        overstate confidence."""
        evidence_edges = [
            (e.source, e.target) for e in self.edges if e.relation in _EVIDENCE_BACKED_RELATIONS
        ]
        return self.graph.edge_subgraph(evidence_edges).copy() if evidence_edges else nx.DiGraph()


def build_attack_path_graph(
    network_graph: NetworkGraph,
    findings: list[Finding],
    *,
    critical_asset_ids: set[str] | None = None,
) -> AttackPathGraph:
    g = nx.DiGraph()
    edges: list[AttackPathEdge] = []
    critical_asset_ids = critical_asset_ids or set()

    def add_edge(source: str, target: str, relation: str, *, finding_id: str | None = None):
        evidence_backed = relation in _EVIDENCE_BACKED_RELATIONS
        g.add_edge(source, target, relation=relation, evidence_backed=evidence_backed, finding_id=finding_id)
        edges.append(AttackPathEdge(source=source, target=target, relation=relation, evidence_backed=evidence_backed, finding_id=finding_id))

    # --- Structural layer: preserve the original graph's own topology ------
    for asset in network_graph.assets:
        g.add_node(asset.asset_id, kind="host", critical=asset.asset_id in critical_asset_ids)
        for service in asset.services:
            service_node = service.service_id
            g.add_node(service_node, kind="service", port=service.port, service_name=service.service_name)
            add_edge(asset.asset_id, service_node, RELATION_HOSTS)
            add_edge(service_node, asset.asset_id, RELATION_EXPOSES)

    for edge in network_graph.edges:
        add_edge(edge.source, edge.target, RELATION_CONNECTS_TO)

    # --- Findings layer: a finding is always a potential/structural edge
    # from its target asset/binary to itself (modelled as AFFECTED_BY only
    # when confirmed; otherwise POTENTIAL_ACCESS_RELATION to a synthetic
    # finding node so unconfirmed findings are still visible in the graph
    # without implying anything was actually demonstrated). --------------
    for finding in findings:
        finding_node = f"finding:{finding.finding_id}"
        g.add_node(
            finding_node,
            kind="finding",
            severity=finding.severity.value,
            status=finding.status.value,
            surface=finding.surface.value,
        )
        target_node = finding.asset_id if finding.surface != Surface.BINARY else finding.binary_id
        if target_node is None:
            continue
        if target_node not in g:
            g.add_node(target_node, kind="binary" if finding.surface == Surface.BINARY else "host")

        if finding.status == FindingStatus.CONFIRMED:
            add_edge(target_node, finding_node, RELATION_AFFECTED_BY, finding_id=finding.finding_id)
            # A confirmed finding on a service/host that itself connects
            # onward becomes a verified transition ONLY to nodes already
            # reachable via CONNECTS_TO from this target — we never invent a
            # new reachability relationship from a finding alone.
            for _, neighbour, data in g.out_edges(target_node, data=True):
                if data.get("relation") == RELATION_CONNECTS_TO:
                    add_edge(finding_node, neighbour, RELATION_VERIFIED_TRANSITION, finding_id=finding.finding_id)
        else:
            add_edge(target_node, finding_node, RELATION_POTENTIAL_ACCESS, finding_id=finding.finding_id)

    return AttackPathGraph(graph=g, edges=edges)
