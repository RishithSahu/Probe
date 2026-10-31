# Autonomous Pentest Engine

An autonomous, multi-agent security assessment platform for an explicitly
authorised engagement. A LangGraph Orchestrator coordinates specialist
assessment agents against a network inventory the Network Discovery Probe
owns, and produces a consolidated, evidence-based PDF/JSON report.

> **Who built what.** `probe/` — network discovery, the scope fence, the
> kill switch, and lightweight lead flagging — is a teammate's independently
> developed component; it is not modified here. Everything under `app/` —
> the LangGraph Orchestrator, the Web Security Agent, the Binary Analysis
> Agent, and all shared infrastructure (schemas, authorisation enforcement,
> database, API, analysis, reporting, deployment) — is this side of the
> project. The two integrate through [`docs/CONTRACT.md`](docs/CONTRACT.md)
> (Probe's own contract) and
> [`docs/network_graph_contract.md`](docs/network_graph_contract.md) (how
> the app-side adapter consumes it) — see "Network Discovery Probe
> integration" below for what that actually means in this codebase.

## Architecture

```
                  python -m probe (teammate, this repo: probe/)
                             |
              scans once, keeps serving its own API
                             |
                             v
                  PROBE API  http://host:8080
            (hosts, segments, leads, scope check,
             work ledger, change feed)
                             |
                             v
              NETWORK GRAPH ADAPTER  (app/adapters/)
                             |
                             v
                 LANGGRAPH ORCHESTRATOR  (app/orchestrator/)
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
  Probe leads          Web Security          Binary Analysis
  (auto-ingested          Agent                  Agent
   as findings)             |                      |
                          Katana                 Ghidra
                          OWASP ZAP               file/readelf/checksec
                          httpx
        |                    |                    |
        +--------------------+--------------------+
                             |
                             v
                   SQLite (shared assessment state)
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
    Evidence              Attack-Path            PTES
    Validation             Correlation            Mapping
                           (NetworkX)
        |                    |                    |
        +--------------------+--------------------+
                             |
                             v
               Report Generator (Jinja2 + ReportLab)
                             |
                             v
                   Final PDF / JSON report
```

## Repository layout

```
app/
  main.py                      FastAPI app entry point
  api/                         HTTP routes + request/response schemas
  orchestrator/                LangGraph workflow (state, nodes, graph, dispatcher)
  agents/web_security/         httpx fingerprint, Katana crawl, ZAP scan, findings, agent, service
  agents/binary_analysis/      file/readelf/checksec identify, Ghidra adapter, static analysis, findings, agent, service
  adapters/                    Network Graph Adapter (incl. the live Probe API source), Probe-leads translator,
                                external Network Vulnerability Agent interface
  core/                        config, exceptions, shared Pydantic schemas, Scope Guard
  database/                    SQLAlchemy models, session, repository
  analysis/                    evidence validation, NetworkX attack-path correlation, PTES mapping
  reporting/                   Jinja2 + ReportLab report generator and templates
probe/                         Network Discovery Probe (teammate's component — see docs/CONTRACT.md)
scripts/ghidra/                Ghidra Headless post-analysis script
alembic/                       Database migrations (initial schema: 52b26ccce240)
tests/                         pytest suite + synthetic fixtures (network graph, binaries, web server, live Probe)
docs/                          Integration contracts (CONTRACT.md is Probe's; network_graph_contract.md is the adapter's)
inputs/                        Mount point for a static network-graph export + supplied binaries
evidence/                      Mount point for evidence artifacts + generated reports
Dockerfile.orchestrator        FastAPI + LangGraph (+ in-process Web/Binary agent code by default)
Dockerfile.web                 Standalone Web Security Agent service (Katana)
Dockerfile.binary              Standalone Binary Analysis Agent service (Ghidra + JDK)
docker-compose.yml             orchestrator, web-agent, binary-agent, zap (no database service — SQLite is a file)
```

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

This starts OWASP ZAP and the orchestrator (applying Alembic migrations
against its SQLite database on startup — no separate database service to
wait on). The Web/Binary agent code runs **in-process inside the
orchestrator container by default** — the standalone `web-agent` /
`binary-agent` containers also start (so Katana/Ghidra are available) but
are only *used* if you set `APE_WEB_AGENT_SERVICE_URL` /
`APE_BINARY_AGENT_SERVICE_URL` on the orchestrator service (commented out in
`docker-compose.yml`) to dispatch to them over HTTP instead.

The API is then available at `http://localhost:8000` (`/docs` for the
interactive OpenAPI UI). The SQLite database file lives at
`evidence/ape.db` on the host (bind-mounted), so it survives
`docker compose down`/`up` and is directly inspectable with any SQLite
client. Verified end to end: `docker build`, container start, Alembic
migration, `POST /assessments`, and host-side file persistence all checked
against a real container.

### Network Discovery Probe integration

Probe normally runs directly on a host with raw-socket/admin access, not in
a container — it is not one of the `docker-compose.yml` services. Run it
separately:

```bash
pip install -r requirements.txt -r requirements-probe.txt   # adds scapy; needs Npcap (Windows) or libpcap (Linux/macOS)
cp probe-scope.example.txt probe-scope.txt   # edit to your authorised range(s)
python -m probe
```

**Live discovery additionally requires `authorisations.json`** with explicit
discovery/inventory grants matching the configured scope — a discovered
address, service reference, or interface supernet cannot extend that scope.
`probe approve` releases holds only within that explicit scope. On Windows,
a live run also requires independently verified Nmap program firewall rules:
Probe writes an exact policy to its data directory and refuses to send any
traffic if those rules are missing — install them (administrator rights
required) with
`enforce/windows-program-scope.ps1 -PolicyFile <data-directory>/egress-policy.json -Install`,
then rerun. Other platforms currently refuse live execution until an
independent enforcement adapter is provided. Use `--data-dir <directory>` to
isolate reports/audit records per run. See
[the Network Roamer review](docs/reviews/2026-10-31-roamer.md) for the
current validation status of this enforcement.

Point the orchestrator at it with `APE_PROBE_API_URL`. If the orchestrator
runs in Docker, `127.0.0.1` inside the container is the container itself,
not the host — use `http://host.docker.internal:8080` (Docker Desktop on
Windows/Mac) or the host's bridge/LAN IP (Linux). Outside Docker, the
default `http://127.0.0.1:8080` just works. With no `network_graph_path`
supplied, `POST /assessments` automatically pulls the live inventory from
Probe; see "Held-segment safety" below for what it will and won't offer as
an assessment target.

### Running the synthetic end-to-end demo

Not run automatically — this was deliberately left for you to run
yourselves:

```bash
pip install -r requirements.txt
python scripts/run_synthetic_demo.py
```

No database service to start first — it uses the default SQLite file. It
runs the full pipeline against the bundled sample network graph
(`tests/fixtures/network_graphs/sample_graph.json`) and the synthetic
Katana/ZAP/Ghidra fixtures (used automatically whenever those tools aren't
installed) — no external network access, no Probe instance required.

### Running the test suite

```bash
pip install -r requirements.txt -r requirements-probe.txt   # the second file is needed to collect probe/'s own tests
python -m pytest tests/ -q
```

The repository-layer tests use a throwaway SQLite file by default (no setup
needed). Point `APE_DATABASE_URL` at a different database first if you want
to run them against something else (e.g. PostgreSQL) — the module probes it
and skips itself if unreachable rather than failing the suite. The Probe
integration tests (`tests/test_probe_integration.py`,
`tests/test_orchestrator_probe_nodes.py`) run Probe's real FastAPI app
in-process against an in-memory store — no live scan, no admin rights, no
network traffic. `probe/`'s own test files (`tests/test_fence_leash.py`,
`tests/test_territory.py`, etc.) import `scapy` directly, so without
`requirements-probe.txt` installed those specific files fail to *collect*
(not a test failure — `pytest` reports a collection error for just those
files; everything else still runs).

### Database migrations

```bash
# Apply migrations (also done automatically by the orchestrator container's
# entrypoint — docker/entrypoint-orchestrator.sh):
alembic upgrade head

# After changing app/database/models.py, generate a new migration:
alembic revision --autogenerate -m "describe the change"
```

## Using the API

```bash
# 1. Create an assessment. With no network_graph_path, this pulls the live
#    inventory from Probe (APE_PROBE_API_URL) automatically; this call does
#    NOT trigger any discovery itself — it only records policy and starts
#    the Orchestrator pipeline against an already-completed inventory.
curl -X POST http://localhost:8000/assessments \
  -H 'Content-Type: application/json' \
  -d '{
        "scope_id": "SCOPE-001",
        "binaries": [{"file_path": "/data/inputs/binaries/sample.bin"}],
        "assessment_policy": {
          "allow_passive_web_analysis": true,
          "allow_web_crawling": true,
          "allow_active_web_verification": false,
          "allow_binary_analysis": true,
          "allow_network_service_assessment": true,
          "approved_web_origins": ["https://web01.lab.local"],
          "dry_run": false
        }
      }'
# (approved_asset_ids left empty here on purpose — the Scope Guard then
# defaults to every Probe-known asset EXCEPT held ones; see below.)

# 2. Poll status
curl http://localhost:8000/assessments/ASSESSMENT-XXXX

# 3. Inspect per-agent task status
curl http://localhost:8000/assessments/ASSESSMENT-XXXX/agents

# 4. Inspect findings (optionally filter by surface/status)
curl "http://localhost:8000/assessments/ASSESSMENT-XXXX/findings?surface=web&status=confirmed"

# 5. Fetch the consolidated report
curl http://localhost:8000/assessments/ASSESSMENT-XXXX/report            # JSON
curl http://localhost:8000/assessments/ASSESSMENT-XXXX/report?format=pdf -o report.pdf

# 6. A separate, deeper Network Vulnerability Assessment Agent (if one is
#    built later) submits its results here, any time (findings are
#    validated against the assessment's scope and stored immediately).
#    Probe's own leads are ingested automatically — this endpoint is for a
#    genuinely separate scanner, not required for Probe's signal to appear.
curl -X POST http://localhost:8000/assessments/ASSESSMENT-XXXX/external-findings \
  -H 'Content-Type: application/json' \
  -d '{"findings": [{...ExternalNetworkFinding...}]}'
```

## Safety / authorisation model

Every tool invocation (httpx request, Katana crawl, ZAP scan, Ghidra run)
passes through `app/core/scope_guard.py` **immediately before execution**,
not just once at assessment startup. `AssessmentPolicy`
(`app/core/schemas.py`) distinguishes six independent permissions, all
**disabled by default**:

| Permission | Governs |
|---|---|
| `allow_network_discovery` | Probe's own authorisation (its scope comes from `probe-scope.txt`, not from this app; recorded here for completeness) |
| `allow_network_service_assessment` | A separate, deeper Network Vulnerability Assessment Agent's checks, if one is built |
| `allow_web_crawling` | Katana endpoint discovery |
| `allow_passive_web_analysis` | httpx fingerprinting + ZAP passive scanning |
| `allow_active_web_verification` | ZAP active-scan rules — **never implied** by crawling/passive permission |
| `allow_binary_analysis` | Ghidra + file/readelf/checksec static analysis |

A discovery-only authorisation is never interpreted as permission for
active vulnerability testing — `allow_active_web_verification` must be set
explicitly and independently. Supplied binaries are **never executed**
anywhere in this codebase — only static identification
(`file`/`readelf`/`checksec`) and static analysis (Ghidra Headless) are
performed. `AssessmentPolicy.dry_run` (default `true`) makes the Scope
Guard log intended tool invocations without executing them, for safely
trialling a new policy.

### Held-segment safety

Probe marks a host `held` when it sits inside a hidden segment the network
owner has not yet approved (`python -m probe approve <cidr>`). This
application treats that as a **hard rule**, not a policy permission:

- `extract_http_services()` excludes held assets unconditionally — a held
  host is never offered to the Web Agent, whatever `AssessmentPolicy` says.
- `ScopeGuard.check_asset_in_scope()` refuses a held asset even if an
  operator explicitly lists its `asset_id` in `approved_asset_ids` — that
  is treated as a mistake to refuse, not an override to honour.
- When `approved_asset_ids` is left empty, the Scope Guard's default scope
  is every Probe-known asset **except** held ones.

## Evidence and finding status

Every finding starts `suspected`. A scanner alert — ZAP (passive or
active), a Ghidra-derived static-analysis heuristic, or a Probe lead — is
never automatically `confirmed`. `app/analysis/evidence_validator.py` is
the single place that promotes findings, and only promotes a narrow,
deterministic class (missing-security-header / insecure-cookie checks
derived directly from an observed HTTP response) automatically; everything
else remains `suspected` pending a human reviewer calling
`promote_finding(...)`.

## Attack-path correlation

`app/analysis/attack_paths.py` builds a NetworkX graph distinguishing:
- **Structural edges** (`HOSTS`, `EXPOSES`, `CONNECTS_TO`,
  `POTENTIAL_ACCESS_RELATION`) — derived from the network graph's own
  topology (including Probe-observed `via` pivot relationships) and from
  findings that exist but aren't yet confirmed. These represent what's
  *possible*, not what's been shown.
- **Evidence-backed edges** (`AFFECTED_BY`, `VERIFIED_TRANSITION`) — only
  added for `confirmed` findings. Network connectivity alone is never
  treated as proof that compromise would propagate.

## OWASP ZAP active-scan policy

When `allow_active_web_verification` is enabled, active scans run under the
ZAP scan policy named by `APE_ZAP_ACTIVE_SCAN_POLICY_NAME` (default `Default
Policy`). For a controlled engagement, define a stricter named policy in ZAP
first (UI: *Analyse → Scan Policy Manager → New*, or via
`/JSON/ascan/action/addScanPolicy/`) that disables brute-force- and
DoS-capable rule categories, then set `APE_ZAP_ACTIVE_SCAN_POLICY_NAME` to
its name. This application never performs brute-force authentication,
destructive payloads, or denial-of-service testing regardless of ZAP policy
— see `app/agents/web_security/zap_integration.py`.

## What's still a fixture / synthetic, and why

| Component | Real integration | Fixture fallback (used automatically when real tool is absent) |
|---|---|---|
| Network Discovery Probe | Live API, `ProbeAPISource` — see "Network Discovery Probe integration" above | `JSONFileNetworkGraphSource` + `tests/fixtures/network_graphs/sample_graph.json` when no Probe instance is configured |
| Katana crawl | `katana` binary on `PATH` | Synthetic endpoint list — see `app/agents/web_security/crawler.py::_synthetic_endpoints` |
| OWASP ZAP | Live ZAP instance at `APE_ZAP_API_URL` | Synthetic passive-alert set — see `app/agents/web_security/zap_integration.py::_synthetic_alerts` |
| Ghidra Headless | `APE_GHIDRA_INSTALL_DIR` pointing at a real install | Synthetic function/string/import analysis — see `app/agents/binary_analysis/ghidra_adapter.py::_synthetic_result` |
| Deeper Network Vulnerability Assessment Agent | Not yet built; contract (`app/adapters/external_network_agent.py`) is ready for one | `synthetic_network_findings()`; in the meantime Probe's own `leads()` is real signal, auto-ingested |

Set `APE_WEB_AGENT_USE_FIXTURES=false` / `APE_BINARY_AGENT_USE_FIXTURES=false`
once the real tools are confirmed working in the assessment environment —
with fixtures disabled, a missing tool raises `ToolExecutionError` (the task
is recorded `failed`) rather than silently substituting fixture data.

## Remaining implementation gaps (honest list)

- **Live tool validation.** Katana, ZAP, and Ghidra Headless have not been
  exercised against a live instance in this environment — the integrations
  are implemented against each tool's documented CLI/API contract, with
  fixture fallbacks, but have only been exercised via those fixtures and
  (for Probe specifically) against Probe's real code running in-process.
  Validate Katana/ZAP/Ghidra against live instances before a real
  assessment.
- **The Probe work ledger (claim/complete) is not yet used by the Web/Binary
  agents.** Probe's contract (`docs/CONTRACT.md` §4) defines an idempotency
  mechanism — claim a unit of work before doing it, so concurrent or
  re-run agents don't repeat it — that this application does not call yet.
  Safe today because the Orchestrator itself is the only dispatcher, but
  worth adding before multiple independent agent processes share one Probe
  instance.
- **`aggregate_findings`** only picks up a separate Network Vulnerability
  Agent's results that were supplied via
  `OrchestratorState.external_network_findings_raw` at the time a given
  orchestrator run was invoked, OR already persisted via the
  `/external-findings` endpoint *before* that run started. A submission
  arriving *during* a run is stored immediately (queryable via
  `GET /findings`) but won't appear in that run's attack-path/report output
  until the next run. Probe's own leads, by contrast, are pulled fresh on
  every run (no such staleness).
- **Evidence for externally-submitted findings**: the `/external-findings`
  endpoint creates stub `Evidence` rows for any `evidence_refs` the external
  finding cites (so evidence validation doesn't flag them as dangling), but
  the actual evidence artifact is understood to remain with that agent's
  own component, not duplicated here.
- **Report PDF layout** is functional (ReportLab Platypus flowables) but not
  visually polished.
- **No authentication/authorisation on the FastAPI endpoints themselves** —
  the Scope Guard governs what the *assessment* may target, not who may call
  this API. Fine for an isolated lab network; add auth before exposing this
  more broadly.

## What we need from the network owner, for a live assessment

1. Confirmation of the authorised scope and any sub-segment restrictions
   (`probe-scope.txt`), including the approval process for a hidden segment
   Probe finds — `python -m probe approve <cidr>` and how/when that happens.
2. The specific permissions to enable in `AssessmentPolicy` for the live
   window (crawling, active web verification, binary analysis) — all are
   disabled by default and must be explicitly turned on.
3. The binaries to assess, if any (file paths to mount into
   `inputs/binaries/`).
4. Network reachability from wherever this stack runs to the in-scope web
   services (for the Web Agent) — this application makes no outbound
   connections beyond the authorised scope, enforced independently by the
   Scope Guard; Probe additionally enforces its own fence
   (`probe/fence.py`, `enforce/nftables.nft`) at the network layer.
