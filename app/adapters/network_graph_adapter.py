"""Network Graph Adapter.

The boundary between the teammate's independently-developed network probe and
this application. See docs/network_graph_contract.md for the full rationale
and the provisional wire format this module parses.

Design intent: this is the ONLY module in the codebase that knows the shape of
the externally-supplied graph. It performs a tolerant parse of several
plausible wire shapes (the real probe hasn't been pushed to the repo yet) and
always emits the same normalised `app.core.schemas.NetworkGraph`. When the
real probe lands, only `_coerce_wire_record` / `NetworkGraphSource` need to
change — nothing downstream does.

No network discovery is performed here. This module only reads an
already-completed graph (from disk today; from whatever the teammate's
component exposes later) and normalises its shape.
"""
from __future__ import annotations

import abc
import json
from pathlib import Path
from typing import Any

from app.core.exceptions import GraphValidationError
from app.core.schemas import (
    NetworkGraph,
    NetworkGraphAssetRecord,
    NetworkGraphEdgeRecord,
    NetworkGraphServiceRecord,
)

_HOST_LIST_KEYS = ("hosts", "assets", "nodes")
_ASSET_ID_KEYS = ("asset_id", "host_id", "node_id", "id")
_SERVICE_LIST_KEYS = ("services", "ports", "open_ports")
_SERVICE_ID_KEYS = ("service_id", "id")
_SERVICE_NAME_KEYS = ("service_name", "name", "banner_service")
_EDGE_LIST_KEYS = ("edges", "relationships", "links")
_HTTP_SERVICE_NAMES = {"http", "https", "http-alt", "https-alt", "http-proxy"}


class NetworkGraphSource(abc.ABC):
    """Strategy interface for *where* the raw graph comes from. Today only a
    JSON file source exists (the teammate's probe exports to disk, or we use
    a synthetic fixture). If/when his component instead exposes a live API or
    importable function, add a sibling implementation here — the rest of the
    adapter (and everything downstream of it) is unaffected.
    """

    @abc.abstractmethod
    def load_raw(self) -> dict[str, Any]:
        """Return the raw, un-normalised graph as a dict."""


class JSONFileNetworkGraphSource(NetworkGraphSource):
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load_raw(self) -> dict[str, Any]:
        if not self.path.exists():
            raise GraphValidationError(f"Network graph file not found: {self.path}")
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            raise GraphValidationError(f"Network graph file is not valid JSON: {self.path}: {exc}") from exc


class InMemoryNetworkGraphSource(NetworkGraphSource):
    """Used by tests / the orchestrator when the raw graph is already a dict
    in memory (e.g. synthetic fixtures loaded by a test, or a future live-API
    source that fetched JSON itself)."""

    def __init__(self, raw: dict[str, Any]):
        self._raw = raw

    def load_raw(self) -> dict[str, Any]:
        return self._raw


def _first_present(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


def _coerce_service(host_asset_id: str, raw_service: dict[str, Any] | int) -> NetworkGraphServiceRecord:
    """Coerce one service entry. Tolerates the service being a bare port
    integer (some probes emit `open_ports: [80, 443]`) as well as a full
    record."""
    if isinstance(raw_service, int):
        raw_service = {"port": raw_service}
    if not isinstance(raw_service, dict):
        raise GraphValidationError(f"Service entry for asset {host_asset_id!r} is not an object or port number: {raw_service!r}")

    port = raw_service.get("port")
    if port is None:
        raise GraphValidationError(f"Service entry for asset {host_asset_id!r} is missing 'port'")
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise GraphValidationError(f"Service port for asset {host_asset_id!r} is not an integer: {port!r}") from exc

    raw_service_id = _first_present(raw_service, _SERVICE_ID_KEYS)
    # Many real-world probes only guarantee uniqueness of service ids *within*
    # a host. Namespace under the asset id so cross-host collisions can never
    # silently merge two distinct services.
    service_id = f"{host_asset_id}:{raw_service_id}" if raw_service_id is not None else f"{host_asset_id}:{port}/{raw_service.get('protocol', 'tcp')}"

    service_name = _first_present(raw_service, _SERVICE_NAME_KEYS)

    return NetworkGraphServiceRecord(
        service_id=service_id,
        asset_id=host_asset_id,
        port=port,
        protocol=str(raw_service.get("protocol", "tcp")),
        service_name=str(service_name) if service_name is not None else None,
        version=raw_service.get("version"),
    )


def _coerce_host(raw_host: dict[str, Any]) -> NetworkGraphAssetRecord:
    asset_id = _first_present(raw_host, _ASSET_ID_KEYS)
    if asset_id is None:
        raise GraphValidationError(f"Host record is missing an asset identifier: {raw_host!r}")
    asset_id = str(asset_id)

    raw_services = _first_present(raw_host, _SERVICE_LIST_KEYS) or []
    if not isinstance(raw_services, list):
        raise GraphValidationError(f"Host {asset_id!r}: services/ports field is not a list")

    services = [_coerce_service(asset_id, s) for s in raw_services]

    return NetworkGraphAssetRecord(
        asset_id=asset_id,
        ip=raw_host.get("ip"),
        hostname=raw_host.get("hostname"),
        asset_type=str(raw_host.get("asset_type", "host")),
        services=services,
    )


def _coerce_edge(raw_edge: dict[str, Any]) -> NetworkGraphEdgeRecord:
    source = raw_edge.get("source") or raw_edge.get("from")
    target = raw_edge.get("target") or raw_edge.get("to")
    if source is None or target is None:
        raise GraphValidationError(f"Edge record missing source/target: {raw_edge!r}")
    return NetworkGraphEdgeRecord(
        source=str(source),
        target=str(target),
        relation=str(raw_edge.get("relation", raw_edge.get("type", "CONNECTS_TO"))),
    )


def normalise(raw: dict[str, Any], *, raw_source_ref: str | None = None) -> NetworkGraph:
    """Pure function: raw wire dict -> normalised NetworkGraph. Never performs
    I/O, never invents assets/services/edges beyond what's present in `raw`."""
    if not isinstance(raw, dict):
        raise GraphValidationError("Network graph root must be a JSON object")

    scope_id = raw.get("scope_id")
    if not scope_id:
        raise GraphValidationError("Network graph is missing required field 'scope_id'")

    raw_hosts = _first_present(raw, _HOST_LIST_KEYS)
    if raw_hosts is None:
        raise GraphValidationError(
            f"Network graph is missing a host list (expected one of {_HOST_LIST_KEYS})"
        )
    if not isinstance(raw_hosts, list):
        raise GraphValidationError("Network graph host list must be an array")

    assets = [_coerce_host(h) for h in raw_hosts]

    known_ids = {a.asset_id for a in assets}
    raw_edges = _first_present(raw, _EDGE_LIST_KEYS) or []
    if not isinstance(raw_edges, list):
        raise GraphValidationError("Network graph edge list must be an array")
    edges = [_coerce_edge(e) for e in raw_edges]
    for edge in edges:
        if edge.source not in known_ids or edge.target not in known_ids:
            raise GraphValidationError(
                f"Edge references an asset not present in the host list: {edge.source} -> {edge.target}"
            )

    return NetworkGraph(
        scope_id=str(scope_id),
        generated_by=str(raw.get("generated_by", "network_probe")),
        assets=assets,
        edges=edges,
        raw_source_ref=raw_source_ref,
    )


def load_network_graph(source: NetworkGraphSource, *, raw_source_ref: str | None = None) -> NetworkGraph:
    """Load + normalise in one step. `raw_source_ref` is recorded for
    traceability (e.g. the file path or API reference) but never used to
    re-fetch or re-interpret data beyond the initial load."""
    raw = source.load_raw()
    return normalise(raw, raw_source_ref=raw_source_ref)


def extract_http_services(graph: NetworkGraph) -> list[tuple[NetworkGraphAssetRecord, NetworkGraphServiceRecord]]:
    """Returns (asset, service) pairs for every service whose name indicates
    HTTP/HTTPS. Used by the Orchestrator to build the Web Agent's task input —
    this is the *only* sanctioned way web targets enter the assessment; the
    Web Agent itself never discovers new hosts."""
    results: list[tuple[NetworkGraphAssetRecord, NetworkGraphServiceRecord]] = []
    for asset in graph.assets:
        for service in asset.services:
            if service.service_name and service.service_name.lower() in _HTTP_SERVICE_NAMES:
                results.append((asset, service))
    return results
