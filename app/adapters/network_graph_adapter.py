"""Network Graph Adapter.

The boundary between the teammate's Network Discovery Probe (`probe/`, in
this same repo as of the merge documented in docs/CONTRACT.md) and this
application. Two independent paths both produce the same normalised
`app.core.schemas.NetworkGraph`:

- `ProbeAPISource` + `normalise_probe_graph` — the **real** integration.
  Talks to a running Probe instance (`python -m probe`) through
  `probe.client.ProbeClient`, exactly per docs/CONTRACT.md's data model.
- `JSONFileNetworkGraphSource` / `InMemoryNetworkGraphSource` +
  `normalise` — the original provisional, tolerant file-based contract.
  Kept for offline development, tests, and synthetic fixtures; also usable
  for an exported snapshot of a live Probe inventory.

No network discovery is performed here, in either path. This module only
reads an already-completed inventory and normalises its shape — the one
`probe`-specific detail every downstream module (Scope Guard, Web/Binary
agents, Orchestrator, attack-path correlation) is shielded from.
"""
from __future__ import annotations

import abc
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.config import settings
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
    """Strategy interface for *where* the raw graph comes from. See the
    module docstring for the two implementations below."""

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
    """Used by tests when the raw graph is already a dict in memory (e.g.
    synthetic fixtures loaded by a test)."""

    def __init__(self, raw: dict[str, Any]):
        self._raw = raw

    def load_raw(self) -> dict[str, Any]:
        return self._raw


class ProbeAPISource(NetworkGraphSource):
    """Pulls the live inventory from the Network Discovery Probe
    (`probe/web/app.py`) via `probe.client.ProbeClient`, per
    docs/CONTRACT.md. This is the real integration path.

    `probe.client` is stdlib-only (json/time/urllib — no scapy, no admin
    rights), so importing it here never pulls in Probe's heavier runtime
    dependencies; the import is deferred into `load_raw` purely so that code
    paths which never use this source don't require the `probe` package to
    be importable at all (e.g. a minimal deployment that only ever reads a
    static graph file).

    `load_raw()` returns `{"_probe_hosts": [...], "_probe_segments": [...]}`
    — a container, not the provisional wire shape — which is why this source
    must be paired with `normalise_probe_graph`, not the generic `normalise`.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        ensure_scan: bool = False,
        max_age_s: float | None = None,
    ):
        self.base_url = base_url or settings.probe_api_url
        if not self.base_url:
            raise GraphValidationError(
                "ProbeAPISource requires a base_url (or APE_PROBE_API_URL to be configured)"
            )
        self.ensure_scan = ensure_scan
        self.max_age_s = max_age_s if max_age_s is not None else settings.probe_scan_max_age_seconds

    def load_raw(self) -> dict[str, Any]:
        try:
            from probe.client import ProbeClient, ProbeError
        except ImportError as exc:  # pragma: no cover - only hit if `probe` isn't on the path at all
            raise GraphValidationError(
                "the 'probe' package is not importable; is it present in the repository root "
                "(probe/client.py) and is the orchestrator's working directory/PYTHONPATH correct?"
            ) from exc

        client = ProbeClient(base_url=self.base_url)
        try:
            if self.ensure_scan:
                # Safe to call even if other agents call it concurrently —
                # Probe runs at most one scan and everyone gets the same
                # result (docs/CONTRACT.md §5). Off by default here because
                # a fresh scan can take minutes; an assessment shouldn't
                # silently block on one unless explicitly asked to.
                client.ensure_scan(max_age_s=self.max_age_s)
            before = client.status()
            hosts = client.hosts()
            segments = client.segments()
            metadata = {}
            limitations = []
            for name in ("state", "report"):
                try:
                    metadata[name] = getattr(client, name)()
                except ProbeError:
                    limitations.append(f"Probe {name} metadata unavailable")
            after = client.status()
            before_scan = before.get("last_scan")
            after_scan = after.get("last_scan")
            if before_scan != after_scan or (
                isinstance(after_scan, dict) and after_scan.get("status") in {"running", "queued", "starting"}
            ):
                raise GraphValidationError("Probe scan changed during inventory import; obtain a stable snapshot before proceeding")
            if not after_scan:
                limitations.append("No completed scan identity or freshness was supplied by Probe")
        except ProbeError as exc:
            raise GraphValidationError(f"could not read the network inventory from Probe at {self.base_url}: {exc}") from exc

        return {"_probe_hosts": hosts, "_probe_segments": segments,
                "_probe_metadata": metadata, "_probe_status": after, "_import_limitations": limitations}


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


def _coerce_probe_port(ip: str, raw_port: dict[str, Any]) -> NetworkGraphServiceRecord:
    port = raw_port.get("port")
    if port is None:
        raise GraphValidationError(f"Probe host {ip!r} has an open_ports entry with no 'port': {raw_port!r}")
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise GraphValidationError(f"Probe host {ip!r} port is not an integer: {port!r}") from exc
    proto = str(raw_port.get("proto", "tcp"))
    raw_observations = raw_port.get("observations") or raw_port.get("scripts") or {}
    if isinstance(raw_observations, str):
        try:
            raw_observations = json.loads(raw_observations)
        except json.JSONDecodeError:
            # Preserve neither an unstructured blob nor an invented interpretation.  The
            # specialist can still work from the service/banner fields.
            raw_observations = {}
    if not isinstance(raw_observations, dict):
        raw_observations = {}
    return NetworkGraphServiceRecord(
        service_id=f"{ip}:{port}/{proto}",
        asset_id=ip,
        port=port,
        protocol=proto,
        service_name=raw_port.get("service"),
        version=raw_port.get("version"),
        product=raw_port.get("product"),
        banner=raw_port.get("banner"),
        probe_observations=raw_observations,
    )


def _coerce_probe_host(raw_host: dict[str, Any]) -> NetworkGraphAssetRecord:
    ip = raw_host.get("ip")
    if not ip:
        raise GraphValidationError(f"Probe host record is missing 'ip': {raw_host!r}")
    ip = str(ip)

    raw_ports = raw_host.get("open_ports") or []
    if not isinstance(raw_ports, list):
        raise GraphValidationError(f"Probe host {ip!r}: open_ports is not a list")
    services = [_coerce_probe_port(ip, p) for p in raw_ports]

    raw_roles = raw_host.get("roles") or []
    if not isinstance(raw_roles, list):
        raw_roles = []
    return NetworkGraphAssetRecord(
        asset_id=ip,
        ip=ip,
        hostname=None,  # Probe's host record carries no resolved hostname field (ip is the identity)
        asset_type="host",
        services=services,
        held=bool(raw_host.get("held", False)),
        verdict=raw_host.get("verdict"),
        probe_roles=[role for role in raw_roles if isinstance(role, str)],
    )


def normalise_probe_graph(raw: dict[str, Any], *, scope_id: str, raw_source_ref: str | None = None) -> NetworkGraph:
    """Converts a `ProbeAPISource.load_raw()` payload
    (`{"_probe_hosts": [...], "_probe_segments": [...]}`) into a
    `NetworkGraph`. Unlike `normalise()`, Probe's own JSON carries no
    `scope_id` of its own (that's the assessment's concern, not Probe's —
    Probe only knows `probe-scope.txt`), so the caller supplies it.

    Edges are derived only from a segment's explicit `via` pivot field
    (CONTRACT.md §2) — a real, Probe-observed relationship — never invented
    from co-location or address proximity. A Probe deployment that doesn't
    populate `via` simply yields fewer edges; that's honest, not a bug.
    """
    probe_hosts = raw.get("_probe_hosts")
    probe_segments = raw.get("_probe_segments")
    if not isinstance(probe_hosts, list):
        raise GraphValidationError("Probe graph payload is missing a '_probe_hosts' list")
    if not isinstance(probe_segments, list):
        raise GraphValidationError("Probe graph payload is missing a '_probe_segments' list")

    assets = [_coerce_probe_host(h) for h in probe_hosts]
    known_ids = {a.asset_id for a in assets}

    edges: list[NetworkGraphEdgeRecord] = []
    seen_edges: set[tuple[str, str]] = set()
    for segment in probe_segments:
        via = segment.get("via")
        if not via or via not in known_ids:
            continue
        for host_ip in segment.get("hosts", []) or []:
            if host_ip not in known_ids or host_ip == via:
                continue
            key = (via, host_ip)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(NetworkGraphEdgeRecord(source=via, target=host_ip, relation="CONNECTS_TO"))

    return NetworkGraph(
        scope_id=scope_id,
        generated_by="network_probe",
        assets=assets,
        edges=edges,
        raw_source_ref=raw_source_ref,
    )


def load_network_graph(
    source: NetworkGraphSource,
    *,
    raw_source_ref: str | None = None,
    normaliser: Callable[..., NetworkGraph] | None = None,
    **normaliser_kwargs: Any,
) -> NetworkGraph:
    """Load + normalise in one step. `raw_source_ref` is recorded for
    traceability (e.g. the file path or API reference) but never used to
    re-fetch or re-interpret data beyond the initial load.

    `normaliser` defaults to the provisional file-contract `normalise()`;
    pass `normalise_probe_graph` (with its required `scope_id=` kwarg
    forwarded via `**normaliser_kwargs`) when `source` is a `ProbeAPISource`.
    """
    raw = source.load_raw()
    normaliser = normaliser or normalise
    graph = normaliser(raw, raw_source_ref=raw_source_ref, **normaliser_kwargs)
    if isinstance(source, ProbeAPISource):
        from app.adapters.discovery_snapshot import save_snapshot

        reference = save_snapshot(raw, source=source.base_url, scope_id=graph.scope_id)
        graph = graph.model_copy(update={"raw_source_ref": str(reference)})
    return graph


def extract_http_services(graph: NetworkGraph) -> list[tuple[NetworkGraphAssetRecord, NetworkGraphServiceRecord]]:
    """Returns (asset, service) pairs for every service whose name indicates
    HTTP/HTTPS. Used by the Orchestrator to build the Web Agent's task input —
    this is the *only* sanctioned way web targets enter the assessment; the
    Web Agent itself never discovers new hosts.

    Assets Probe has marked `held` (inside a hidden segment pending
    network-owner approval) are excluded unconditionally — this is a hard
    safety rule, not something an AssessmentPolicy permission can override.
    """
    results: list[tuple[NetworkGraphAssetRecord, NetworkGraphServiceRecord]] = []
    for asset in graph.assets:
        if asset.held:
            continue
        for service in asset.services:
            if service.service_name and service.service_name.lower() in _HTTP_SERVICE_NAMES:
                results.append((asset, service))
    return results


def non_held_asset_ids(graph: NetworkGraph) -> set[str]:
    """Asset IDs Probe has NOT flagged as held — the safe default scope when
    an AssessmentPolicy doesn't enumerate `approved_asset_ids` explicitly.
    See app.core.scope_guard.ScopeGuard, which uses this instead of "every
    known asset" so a held/hidden segment is never silently in scope by
    omission."""
    return {a.asset_id for a in graph.assets if not a.held}
