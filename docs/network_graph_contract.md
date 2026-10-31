# Network Graph Integration Contract

Status: **provisional**. The network probe is being developed independently by
a teammate and has not yet been pushed to this repository. This document
defines the interface our application depends on, so his implementation and
ours can be built in parallel and integrated without either side waiting on
the other.

## Why this exists

`app/adapters/network_graph_adapter.py` is the *only* place in this codebase
allowed to know about the network probe's output format. Nothing downstream
(Scope Guard, Web Agent, Orchestrator, Attack Path analysis, reporting) talks
to the raw graph — everything consumes `app.core.schemas.NetworkGraph`, the
normalised internal representation. That boundary means:

- When the real probe is pushed, only the adapter's parsing logic needs to
  change (or, if his export already matches the provisional shape below,
  nothing needs to change at all).
- Until then, development and tests proceed against synthetic fixtures in
  `tests/fixtures/network_graphs/` that conform to the same provisional shape.

## How to swap in the real probe once it is pushed

1. Inspect what his code actually produces: a JSON file export, a database
   table, or a live API/module call.
2. If it's a JSON export: compare its shape against
   `tests/fixtures/network_graphs/sample_graph.json`. If the field names
   differ, extend `_coerce_wire_record` in `network_graph_adapter.py` — it is
   written as a tolerant, defensive parser specifically so differing key names
   (`host_id` vs `asset_id`, `services` vs `ports`, etc.) can be mapped in one
   place.
3. If it's a live call (function import or HTTP API) instead of a file: add a
   new `NetworkGraphSource` implementation (see the `JSONFileNetworkGraphSource`
   class for the pattern) that fetches the raw graph, then feed it through the
   same `_coerce_wire_record` / `normalise()` pipeline. Nothing else in the
   adapter, and nothing outside it, needs to change.
4. Update `assessment.network_graph_ref` handling in
   `app/orchestrator/nodes.py::load_network_graph` only if the *location*
   mechanism changes (e.g. from "path on disk" to "assessment_id to query his
   API with"). The normalisation step itself is unaffected.

## Provisional wire format (used by fixtures today)

```json
{
  "scope_id": "SCOPE-001",
  "generated_by": "network_probe",
  "generated_at": "2026-10-30T12:00:00Z",
  "hosts": [
    {
      "asset_id": "HOST-001",
      "ip": "192.168.60.10",
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

Tolerated synonyms (handled defensively, not assumed to be the final format):

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
assessment.

## What the adapter guarantees downstream

- Original `asset_id` / `service_id` values from the source graph are
  preserved verbatim — never regenerated — so the teammate's Network
  Vulnerability Agent's findings (which reference those same IDs) line up
  with ours without a translation table.
- No new hosts, services, or edges are invented. The adapter normalises
  shape, it does not enrich content.
- No network discovery is performed by this adapter or by anything that
  consumes its output — it is a pure, read-only transform of an
  already-completed graph.

## Open questions for integration (ask the teammate)

- Exact export mechanism: file path convention, or an API endpoint we should
  poll/call?
- Are `service_id`s globally unique already, or only unique per-host (in
  which case the adapter namespaces them as `{asset_id}:{service_id}` — see
  `normalise()`)?
- Does his graph ever represent services without a resolved `service_name`
  (e.g. raw port-only results), and if so should those be treated as
  non-HTTP by default (current adapter behaviour: yes)?
