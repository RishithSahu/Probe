# Autonomous Pentest Engine (`app/`) — architecture and tech stack

Companion to [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md) / [`TECHNICAL_OVERVIEW.md`](TECHNICAL_OVERVIEW.md),
which document the Network Discovery Probe (`probe/`). This document covers
**everything downstream of discovery**: the orchestrator, the specialist
agents, scope enforcement, and reporting — the `app/` package — and how it
was verified against a real, live lab network rather than synthetic data
alone.

## 1. One-sentence summary

Probe discovers *what exists* on an authorised network; `app/` decides *what
to check* on what Probe found, runs a small set of read-only/passive
specialist checks against it under hard scope enforcement, and turns the
result into a report — with every synthetic/fixture value honestly labelled
as such, never silently blended with real findings.

## 2. End-to-end data flow

```
 probe/ (separate component, own repo area)
   discovers hosts/segments/services on an authorised CIDR
   serves them over a local HTTP API (probe.client.ProbeClient)
          │
          ▼
 app/adapters/network_graph_adapter.py
   ProbeAPISource + normalise_probe_graph()         (live integration)
   JSONFileNetworkGraphSource + normalise()         (file/offline/testing)
          │  -> app.core.schemas.NetworkGraph (assets, services, edges, held-flags)
          ▼
 app/core/scope_guard.py — ScopeGuard
   every tool call from every agent passes through this FIRST.
   - held/hidden-segment assets: hard refuse, not policy-overridable
   - everything else: checked against AssessmentPolicy's explicit allow-lists
   - dry_run=True: every check still runs, but is downgraded to "would have
     executed" and no real tool call fires (DryRunSkipped)
          │
          ▼
 app/orchestrator/graph.py — LangGraph StateGraph (13 nodes, see §4)
   validate_assessment -> load/normalise network graph -> validate_scope
   -> create_agent_tasks -> [dispatch_specialist_agents | ingest_network_agent_results] (parallel)
   -> aggregate_findings -> validate_evidence -> build_attack_paths
   -> map_ptes_phases -> generate_report -> complete_assessment
          │
          ├─ app/agents/web_security/        (HTTP/HTTPS services from the graph)
          ├─ app/agents/network_vulnerability/ (TCP services: ssh/ftp/redis/mysql/postgresql/smb)
          ├─ app/agents/binary_analysis/      (binaries supplied out-of-band, not graph-discovered)
          └─ external network-vulnerability findings ingested via /external-findings
             (the teammate's separate CTF-chain work plugs in here, not into this pipeline)
          │
          ▼
 app/analysis/{evidence_validator,attack_paths,ptes_mapper}.py
   auto-confirms deterministic findings, builds attack-path graph (networkx),
   maps every tool execution to a PTES phase
          │
          ▼
 app/reporting/generator.py
   -> evidence/reports/<id>_report.json  (machine-readable, data_integrity block)
   -> evidence/reports/<id>_report.pdf   (reportlab; red banner if any fixture data used)
```

## 3. Core design rules (apply everywhere, not just one module)

- **No agent discovers targets.** The Web, Binary, and Network Vulnerability
  agents only ever act on what the Orchestrator hands them from the already-
  normalised `NetworkGraph`. This is the boundary that keeps `app/` from
  re-implementing Probe's job (see `docs/CONTRACT.md`).
- **Scope is enforced once, centrally, before every tool call** —
  `ScopeGuard`, never re-implemented per-agent. A held/hidden Probe segment
  is refused unconditionally, even if an `AssessmentPolicy` lists it.
- **One target failing never aborts the run.** Every agent function returns
  `(findings, evidence, ..., errors)` instead of raising; a bad target becomes
  an entry in `errors`/`incomplete_tasks_and_limitations`, not a crash.
- **Fixture/synthetic output is never silently indistinguishable from a real
  finding.** Every tool execution carries `used_fixture`; the report computes
  `data_integrity.fixture_tools_used` and prints a warning banner (both JSON
  and PDF, plus the executive summary text) whenever any is non-empty.
- **`dry_run` is a real, enforced safety switch**, not just a policy field —
  `ScopeGuard._allow()` raises `DryRunSkipped` before any tool actually runs.

## 4. The Orchestrator (`app/orchestrator/`)

| File | Responsibility |
|---|---|
| `graph.py` | Wires the 13-node LangGraph `StateGraph`. Two branches — `dispatch_specialist_agents` (Web + Network-Vuln + Binary, run concurrently via a thread pool) and `ingest_network_agent_results` (externally-submitted findings) — fan out from `create_agent_tasks` and converge at `aggregate_findings`. |
| `nodes.py` | One function per graph node: validation, graph loading/normalising, scope validation, task-row creation, dispatch, ingestion, aggregation, PTES mapping, report generation, completion. |
| `dispatcher.py` | `run_concurrently()` — `ThreadPoolExecutor`-based fan-out with a real, enforced per-task timeout (`shutdown(wait=False)`, not the default blocking shutdown). |
| `state.py` | `OrchestratorState` TypedDict — the single object threaded through every node. |

`complete_assessment` derives the final status from actual `TaskStatus` rows
(`COMPLETED`/`FAILED` among attempted tasks), not from the presence of
warning strings — so a run with recorded-but-non-fatal errors (e.g. an
unreachable external agent) still reports `partially_completed` rather than
`failed`, and only tasks that genuinely errored count against it.

## 5. Specialist agents

All three agents share the same shape: `run_<agent>_agent(targets, *,
assessment_id, scope_guard, policy) -> AgentResult`, and the same contract —
no discovery, no raising on a single target's failure, `used_fixture` on
every tool execution that can fall back to synthetic data.

### 5.1 Web Security Agent (`app/agents/web_security/`)

Runs Stages A–C against every HTTP/HTTPS service the graph lists (never
discovers its own):

| Stage | Tool | Real dependency | Fixture fallback |
|---|---|---|---|
| A — fingerprint | `httpx` (Python library, not the CLI) | none — pure Python, always real | n/a |
| B — crawl (if `allow_web_crawling`) | `katana` (ProjectDiscovery CLI, subprocess) | `katana` binary on PATH | synthetic endpoint list, `used_fixture=True` |
| C — passive/active scan | OWASP ZAP (HTTP API) | a reachable ZAP instance (`APE_ZAP_API_URL`) | synthetic alerts, `used_fixture=True` |

Findings include deterministic, auto-confirmed checks (missing security
headers, parsed directly from the real HTTP response — no tool dependency)
and ZAP-sourced checks (`suspected`, pending verification).

### 5.2 Network Vulnerability Detective (`app/agents/network_vulnerability/`)

Distinct from Probe's own "Network Vulnerability Agent" ingestion path
(`AgentId.NETWORK_VULNERABILITY`, external) — this one (`AgentId
.NETWORK_VULNERABILITY_DETECTIVE`) runs **in-process**, read-only protocol
probes against graph-listed TCP services:

| Service | Check | What it looks for |
|---|---|---|
| SSH | banner read | SSH-1.x (flagged, high) |
| FTP | banner + optional gated anonymous-login | cleartext transport; anonymous access (only if `allow_ftp_anonymous_check`) |
| Redis | `PING`/RESP parse | unauthenticated access (`+PONG` with no auth = critical) |
| MySQL | handshake packet parse | version string (observed-only) |
| PostgreSQL | minimal `StartupMessage` | `AuthenticationOk` with no auth challenge = critical ("trust auth") |
| SMB | TCP reachability only | documented limitation — no dialect negotiation (would need a dedicated library) |

No credential guessing, no data modification, ever. Dispatch is by the
graph's reported `service_name`, **with a fallback to the IANA-registered
name for the port** when Probe reported none at all (fixed during this
verification pass — see §7). Only a `flagged` check result becomes a
`Finding`; `observed`/`not_applicable` results don't clutter the report but
are still counted in `tool_executions` for traceability.

### 5.3 Binary Analysis Agent (`app/agents/binary_analysis/`)

Takes binaries supplied out-of-band (`binary_paths` on the initial state —
**not** anything from the network graph), runs static analysis
(`static_analysis.py`, `metadata.py` — PE header parsing via `pefile`,
stripped-symbol detection via `readelf`) and an optional Ghidra headless pass
(`ghidra_adapter.py`) for disassembly-derived findings.

This is the module the teammate's content-discovery/secret-extraction chain
extends — see `docs/PROGRESS.md` Entry 4's note on the scope split; this
session's work here was limited to the agent's existing static-analysis
plumbing, not that chain.

## 6. Analysis & reporting (`app/analysis/`, `app/reporting/`)

- `evidence_validator.py` — deterministic re-checks that can auto-confirm a
  `suspected` finding without a human (e.g. a header-based check is either
  present or not); `auto_confirmed` is computed from a real before/after
  status comparison, not just the post-pass state.
- `attack_paths.py` — builds a `networkx` graph connecting findings/assets
  into plausible attack chains.
- `ptes_mapper.py` — maps every recorded tool execution to a PTES
  (Penetration Testing Execution Standard) phase for the report's
  methodology section.
- `generator.py` — builds the JSON report (Jinja2 templates for text
  sections) and the PDF report (`reportlab`), including the mandatory
  `data_integrity` block and red warning banner whenever fixture data was
  used anywhere in the run.

## 7. Tech stack

| Layer | Technology | Notes |
|---|---|---|
| Orchestration | **LangGraph** (`langgraph`) | `StateGraph` with 13 nodes, explicit fan-out/fan-in for concurrent agent dispatch |
| API | **FastAPI** + **uvicorn** | `app/api/routes.py`; also the optional standalone Web/Binary agent services |
| Data validation | **Pydantic v2** (+ `pydantic-settings`) | every cross-module payload (`AssessmentPolicy`, `NetworkGraph`, `Finding`, …) is a Pydantic model |
| Database | **SQLite** (stdlib `sqlite3`) by default via **SQLAlchemy** + **Alembic** | `APE_DATABASE_URL` swaps to PostgreSQL with zero code change; `psycopg2-binary` listed but commented out unless needed |
| Web agent tools | **httpx** (library, real), **katana** (CLI, optional), **OWASP ZAP** (HTTP API, optional) | graceful fixture fallback + `used_fixture` flag when a tool is absent |
| Network vulnerability checks | raw **stdlib sockets** | no external dependency — SSH/FTP/Redis/MySQL/PostgreSQL/SMB probes are hand-rolled protocol parsers |
| Binary analysis | **pefile** (PE headers), **readelf** (ELF symbols, via subprocess), optional **Ghidra** headless | |
| Attack-path analysis | **networkx** | |
| Reporting | **Jinja2** (text templates) + **reportlab** (PDF) | |
| Network discovery (separate component) | **scapy** + raw sockets + **nmap** (service enrichment) | `probe/`; only `probe.client.ProbeClient` (stdlib-only) is imported by `app/` — Probe's own heavier deps (`requirements-probe.txt`) never ship in the orchestrator/web-agent/binary-agent containers |
| Deployment | **Docker Compose** | orchestrator + web-agent + binary-agent + zap containers; Probe runs separately on a host with raw-socket access, reached via `APE_PROBE_API_URL` |
| Testing | **pytest**, **ruff** | 343+ tests as of this document; real (non-mocked) integration tests for Probe, the orchestrator, and a real `docker build && run` round trip |

## 8. Verified against a real lab network, not just fixtures

**Correction**: an earlier version of this document reported the pipeline
as verified after a run that only exercised the Web Agent and Network
Vulnerability Detective (Binary Analysis was explicitly disabled in that
test). That was an overstatement, caught and corrected below. The current
state, re-verified with all three agents actually running, in-process, with
no Docker/containers involved (by explicit instruction — see §11):

The full pipeline (scope guard → Web Agent → Network Vulnerability
Detective → Binary Analysis Agent → orchestrator aggregation/evidence
validation/attack-path/PTES mapping → JSON+PDF reporting) was run
**end-to-end against a real, already-completed Probe scan of the actual
`10.20.30.0/24` lab network** (166 real hosts, 233 real TCP services) and a
**real, locally-compiled binary** (not the bundled synthetic demo graph,
and not a stub). Results:

- **Scope enforcement verified for real**: with only `http://10.20.30.139`
  approved as a web origin, the `ScopeGuard` correctly refused dozens of
  other genuinely-discovered HTTP services on the same network (ports 8000,
  8080, 5000, 8081, etc. across many hosts) — each refusal recorded in
  `incomplete_tasks_and_limitations`, not silently dropped.
- **Real findings produced from real traffic**: `httpx` fingerprinted the
  live `.139` wiki host for real (missing security headers — auto-confirmed,
  deterministic, no tool dependency) with `used_fixture=False`.
- **Fixture fallback worked and was honestly labelled**: `katana` and ZAP
  aren't installed/running on this dev machine, so both fell back to
  synthetic output — correctly flagged via `data_integrity.fixture_tools_used`
  in the JSON report, the executive summary text, *and* a red banner on page
  1 of the generated PDF.
- **Network Vulnerability Detective verified against real services**: after
  the fix in §9 below, it ran 91 real protocol checks (ssh/mysql/postgresql/
  smb) against the real lab hosts and correctly reported zero flagged
  findings — an honest negative result, not a skipped/silent one.
- **Binary Analysis Agent verified for real, with one honestly-flagged gap**:
  a real test binary was compiled locally (`gcc`, a deliberately weak C
  program with real `strcpy`/`gets`/`system` calls and a real embedded
  secret-shaped string). Stage A (`file`/`readelf`/`checksec` — binary
  identification, format detection, hardening properties) ran for real
  against it using tools genuinely present on this machine (MinGW
  `readelf`/`objdump`, `file`) and correctly identified it as a `PE`
  binary. Stage B (Ghidra function/string/import extraction) fell back to
  its synthetic fixture because **Ghidra is not installed on this
  machine** — correctly flagged via `used_fixture=True` and
  `data_integrity.fixture_tools_used` including `"ghidra"`. The resulting
  binary findings therefore describe the fixture's canned program, not an
  independently-verified read of the real test binary, even though they
  happen to resemble it (both involve `strcpy`/`system`/a secret string) —
  that resemblance is coincidence, not evidence, and the report does not
  claim otherwise.
- **Both report formats generate correctly** from real data: an 8-page PDF
  and a structured JSON report, each internally consistent with the other.

## 9. Bug found and fixed during this verification

**Network Vulnerability Detective silently skipped unmistakable services
when Probe reported no `service_name`.** Dispatch in both
`agent.py::run_network_vulnerability_agent` (the pre-filter gate) and
`checks.py::run_checks_for_service` (the actual dispatch) keyed purely off
the graph's `service_name` string. On the real lab network, ports 22 (ssh),
445/139 (smb), and 5432 (postgresql) frequently carried no `service_name`
at all (Probe's passive discovery saw the port but hadn't run banner
enrichment on it) — so these universally-registered, unambiguous services
were never assessed, with no error or warning surfaced anywhere.

**Fix**: added `_PORT_NAME_FALLBACK` — a small, local, IANA-registered
port→name map covering only the handful of protocols this agent actually
checks — consulted *only* when the graph supplies no name at all; a name
the graph *does* report is never overridden. The fallback is also recorded
transparently in each `tool_execution`'s `assumed_service_name` field, so a
report reviewer can see when a check ran on a port-based guess rather than
a graph-confirmed identification. Verified via the same real-lab run:
`vulnerability_analysis` tool-execution count went from 2 to 91 after the
fix, with all 14 of the agent's existing unit tests still passing.

## 10a. Correction: Katana was never actually exercised until Entry 8

Every "Katana fell back to its fixture" statement in §8 above was accurate
for what was tested, but misleading about why: Katana had simply never been
installed on this machine, and its JSONL output parser turned out to have a
real schema bug that a fixture-only test run could never have caught (see
`docs/PROGRESS.md` Entry 8 for the full diagnosis). Once installed and
fixed, a real crawl of the real `10.20.30.139` lab host returned **24
genuinely new endpoints**, including an `index.php?p=&view=...`
file-read-shaped parameter and several real hidden files — and those
discoveries now actually become `Finding`s
(`findings_from_discovered_endpoints`), closing the gap with how Ghidra's
analysis already fed `static_analysis.py`. Two more real bugs (an
over-broad `-disable-redirects` flag capping every real crawl at one page,
and a crawl timeout shorter than a real crawl actually takes) were found
and fixed alongside the parser bug — see Entry 8 for the full detail on
each. **Closed in Entry 9**: ZAP's Stage C now also scans up to 10
deduplicated endpoints Katana discovered, not just the root URL — see
`docs/PROGRESS.md` Entry 9 and
`test_zap_scans_discovered_endpoints_not_just_the_root_url`.

## 10. Known gaps (not covered by this pass)

- SSE event stream, task ledger/idempotent claims, and binary sandbox
  isolation (Container 2) from the earlier Master-Spec audit
  (`docs/IMPLEMENTATION_STATUS.md`) remain unbuilt.
- The content-discovery → binary-harvesting → secret-extraction →
  console-auth chain for the CTF flag behind `10.20.30.139:8833` is the
  teammate's scope (see `docs/PROGRESS.md` Entry 4), not covered here.
- ZAP, `katana`, and Ghidra were not installed/running during this
  verification — everything about their real behavior (as opposed to the
  fixture fallback path) is therefore still unverified in this environment;
  the fixture fallback itself, and its honest labelling, is fully verified.
  Installing a local Ghidra would close the one remaining gap in the Binary
  Analysis Agent's verification (Stage A is fully real; Stage B/C are not).

## 11. Deployment: in-process vs. containers

Two deployment modes exist in the code (§7's compose file), but as of this
document **only the in-process mode has been run and verified**, by
explicit instruction ("don't even use Docker for anything, run everything
on my laptop"):

- **In-process (verified)**: the Orchestrator imports and calls each
  agent's Python code directly — no `APE_WEB_AGENT_SERVICE_URL`/
  `APE_BINARY_AGENT_SERVICE_URL` set. This is what every real-lab run in §8
  used.
- **Containerised (built, not run)**: `docker-compose.yml`'s optional
  `web-agent`/`binary-agent`/`zap` services, for when the Orchestrator is
  configured to dispatch to them over HTTP instead. Attempting a real build
  of this path surfaced a genuine, previously-undiscovered bug —
  `Dockerfile.binary`'s final stage pinned `FROM python:3.12-slim`, whose
  Debian base recently moved from `bookworm` to `trixie`; `trixie` dropped
  the `openjdk-17-jre-headless` package Ghidra 11.1.2 needs (only
  `openjdk-21-*` remains), so the image failed to build at all, every time,
  on a clean `docker compose build`. **Fixed** by pinning
  `python:3.12-slim-bookworm` explicitly. The fix is committed to the repo
  even though the containerised path hasn't been run end-to-end since —
  that verification is still outstanding.
