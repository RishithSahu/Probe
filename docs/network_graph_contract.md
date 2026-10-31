# Network Graph Integration Contract

Status: **integrated**. The Network Discovery Probe (`probe/`) is now part of
this repository, and `app/adapters/network_graph_adapter.py` consumes its
real API per [`docs/CONTRACT.md`](CONTRACT.md) (the probe-side contract —
read that first; this document covers only the app-side adapter mechanics).
The provisional static-file contract described below still exists and is
still used — for offline development, synthetic fixtures, tests, and an
exported snapshot of a live inventory — but it is no longer the primary
path.

## Why this exists

`app/adapters/network_graph_adapter.py` is the *only* place in this codebase
allowed to know about Probe's output shape. Nothing downstream (Scope Guard,
Web/Binary Agents, Orchestrator, attack-path correlation, reporting) talks to
raw Probe JSON — everything consumes `app.core.schemas.NetworkGraph`, the
normalised internal representation, regardless of which source produced it.

## Two sources, one normalised shape

| Source | Class | Normaliser | When used |
|---|---|---|---|
| Live Probe API | `ProbeAPISource` | `normalise_probe_graph` | Default — `app/orchestrator/nodes.py::load_network_graph` falls back to this whenever an assessment doesn't supply a static file path and `APE_PROBE_API_URL` is set. |
| Static JSON file | `JSONFileNetworkGraphSource` | `normalise` | When the request supplies `network_graph_path`; also what `tests/fixtures/network_graphs/sample_graph.json` and the synthetic demo use. |

`ProbeAPISource` talks to `probe.client.ProbeClient` (stdlib-only — no
scapy, no admin rights needed by the orchestrator process) and pulls
`GET /api/hosts` + `GET /api/segments`, exactly as documented in
[`docs/CONTRACT.md`](CONTRACT.md) §2. `normalise_probe_graph` maps Probe's
real field names (verified against `probe/store.py`, not just the contract
prose — e.g. Probe's own `held`/`verdict`/`open_ports` fields, not a
provisional guess) onto `NetworkGraph`:

- `asset_id` = the host's `ip` (Probe's own identity for a host).
- `held` and `verdict` are carried through onto `NetworkGraphAssetRecord` —
  see "Held-segment safety" below.
- Each `open_ports` entry becomes a `NetworkGraphServiceRecord`, including
  `product`/`banner` when Probe captured them.
- Edges are derived **only** from a segment's explicit `via` pivot field — a
  real, Probe-observed relationship, never invented from address proximity
  or co-location. A Probe deployment that never populates `via` simply
  yields fewer edges; that is honest, not a bug.

Probe's `leads()` feed (hidden hosts, banner-flagged apps, anomalies) is
translated separately, by `app/adapters/probe_leads.py`, into network-surface
`Finding`s — see that module's docstring for why these stay `suspected`
rather than `confirmed`.

## Held-segment safety

A segment Probe has not yet had approved by the network owner (`python -m
probe approve <cidr>`) is "held", and any host inside it carries
`held: true`. This is enforced as a **hard rule**, not something an
`AssessmentPolicy` permission can relax:

- `extract_http_services()` excludes held assets unconditionally — a held
  host's HTTP service is never offered to the Web Agent.
- `ScopeGuard.check_asset_in_scope()` refuses a held asset even if an
  operator explicitly lists its `asset_id` in `approved_asset_ids` — that is
  treated as a mistake to refuse, not an override to honour.
- When `approved_asset_ids` is left empty (the common case), the Scope
  Guard's default scope is every known asset **except** held ones — see
  `non_held_asset_ids()`.

## Provisional static-file format (still used for fixtures/tests)

```json
{
  "scope_id": "SCOPE-001",
  "generated_by": "network_probe",
  "generated_at": "2026-10-30T12:00:00Z",
  "hosts": [
    {
      "asset_id": "HOST-001",
      "ip": "10.20.30.10",
      "hostname": "web01.lab.local",
      "asset_type": "host",
      "services": [
        {
          "service_id": "SVC-001",
          "port": 443,
          "protocol": "tcp",
          "service_name": "https",
          "version": "nginx/1.24.0"
        }
      ]
    }
  ],
  "edges": [
    {"source": "HOST-001", "target": "HOST-002", "relation": "CONNECTS_TO"}
  ]
}
```

Tolerated synonyms (handled defensively):

| Canonical field      | Accepted synonyms                          |
|-----------------------|---------------------------------------------|
| `hosts`               | `assets`, `nodes`                           |
| `asset_id`            | `host_id`, `node_id`, `id`                  |
| `services`            | `ports`, `open_ports`                       |
| `service_id`          | `id` (host-local; namespaced on import)     |
| `service_name`        | `name`, `banner_service`                    |
| `edges`               | `relationships`, `links`                    |

Any record missing a required identifier (`asset_id`/synonym) is rejected
with `GraphValidationError` rather than silently dropped or invented — a
partial/corrupt graph must fail loudly, not produce a quietly-incomplete
assessment. This same rule applies to the Probe-sourced path: a malformed
response raises `GraphValidationError` rather than producing a partial
inventory.

## What the adapter guarantees downstream, regardless of source

- Original asset identity (Probe's `ip`, or a file's `asset_id`) is
  preserved verbatim — never regenerated — so findings that reference an
  asset line up with the inventory without a translation table.
- No new hosts, services, or edges are invented. The adapter normalises
  shape; it does not enrich content.
- No network discovery is performed by this adapter, or by anything that
  consumes its output — it is a pure, read-only transform of an
  already-completed (or live-queried) inventory.
