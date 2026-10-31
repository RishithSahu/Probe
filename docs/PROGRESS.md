# Project Progress Log

Living document — updated every time something material changes (a feature
lands, a bug is found/fixed, an integration point shifts). Read top-down for
current status; the "History" section at the bottom is append-only and
never edited after the fact, so it stays a true record of what happened and
when.

## Current status (as of this entry)

- **Architecture**: LangGraph Orchestrator + Web Security Agent + Binary
  Analysis Agent (`app/`), integrated with the teammate's Network Discovery
  Probe (`probe/`) via a live HTTP API. All merged into one repository.
- **Database**: SQLite by default (`evidence/ape.db`), no external service
  required. PostgreSQL remains a documented drop-in swap.
- **Tests**: 170 passing (`python -m pytest tests/ -q`), including real
  integration tests that run Probe's actual FastAPI app in-process and a
  real `docker build && docker run` round trip for the orchestrator image.
  One of the teammate's own tests (`test_fence_leash.py::test_cannot_escape_once_installed`)
  is unreliable on this Windows dev machine — see "Known environment
  limitations" below; it is not one of ours and not deselected in CI, only
  in local runs here.
- **Deployment**: `docker-compose.yml` runs orchestrator + web-agent +
  binary-agent + zap. Probe runs separately on a host with raw-socket
  access (not containerised) and is reached via `APE_PROBE_API_URL`.
- **`AssessmentPolicy.dry_run` is now actually enforced** (see bug #8 below)
  — any policy that doesn't explicitly set `dry_run=false` will not execute
  real tool calls, even with other permissions enabled. Every example in
  this repo (README, synthetic demo) already sets it explicitly.
- **Not yet committed to git** as of this entry — see `git status`.

## Known environment limitations (not application bugs)

- `probe/fence.py`'s process-level network fence appears to rely on
  mechanisms that don't fully translate to Windows (it is built for a
  Linux deployment target). On this Windows dev machine,
  `tests/test_fence_leash.py::FenceInstalled::test_cannot_escape_once_installed`
  can hang for its full 60s subprocess timeout and occasionally destabilises
  whatever test runs immediately after it in the same `pytest` invocation
  (observed as spurious timeouts in otherwise-passing, unrelated tests).
  Running the suite with `--deselect` on that one test, or running it in its
  own process, avoids this. Not something to "fix" here — it's the
  teammate's component and a platform-support question, not a logic bug.

## Fundamental issues raised but not yet acted on

These are architecture/process-level gaps, not single-file bugs — each
needs a decision (and in some cases a conversation with the teammate or a
deployment-configuration change), not just an edit:

1. **The PRD's "Network Vulnerability Assessment Agent" (Nmap-based
   service-level vulnerability checks) doesn't exist in a meaningful sense
   yet.** `probe/` is the *discovery* half of the teammate's two described
   components; it does lightweight banner/title-based lead flagging, not
   deep vulnerability scanning. Per the PRD this is explicitly the
   teammate's deliverable, not ours — but it means the "three-agent"
   architecture currently has one agent contributing far less than the PRD
   describes. Needs a conversation with the teammate about whether a
   deeper scanner is still coming, or whether Probe's leads are the
   intended final signal (in which case the report wording and the PRD
   itself should be reconciled to say so honestly).
2. **No real tool integration (Katana, ZAP, Ghidra) has ever been
   exercised against a live instance.** Everything is built against each
   tool's documented CLI/API and exercised only via the synthetic fixtures
   (now at least clearly labelled in the report — see bug #13). This is
   the single biggest execution-day risk: install all three for real and
   run one full live assessment against a disposable target before relying
   on this for an actual engagement.
3. **Untrusted-input processing isn't isolated from the Orchestrator by
   default.** Binary Analysis (Ghidra, on supplied binaries explicitly
   described as untrusted) and Web Security (fetching content
   from potentially hostile targets) run **in-process**, inside the same
   container as the Orchestrator's own state/DB logic, unless
   `APE_WEB_AGENT_SERVICE_URL`/`APE_BINARY_AGENT_SERVICE_URL` are set to
   use the separate `web-agent`/`binary-agent` containers that already
   exist in `docker-compose.yml`. A compromised Ghidra/httpx/Katana process
   (these are complex tools with real historical CVEs) could in principle
   pivot into the orchestrator's own state. Recommendation: make the
   isolated multi-container mode the default before processing real
   untrusted binaries or crawling untrusted sites, not an opt-in.
4. **No authentication on the FastAPI endpoints.** Already noted in
   README's "Remaining implementation gaps" — anyone who can reach the
   orchestrator's port can trigger binary analysis, web crawling, and read
   all findings. Fine for a fully isolated lab network; add auth (even a
   static bearer token) before this is reachable from anywhere less
   trusted.
5. **SQLite's single-writer model is a scaling ceiling**, not a problem
   for one assessment at a time but worth flagging if concurrent
   assessments become a requirement — PostgreSQL remains a documented
   drop-in swap (`APE_DATABASE_URL`) for that case.
6. **Probe's own work-ledger (claim/complete, docs/CONTRACT.md §4) isn't
   used by the Web/Binary agents.** Safe today because the Orchestrator is
   the only dispatcher, but if multiple orchestrator runs or independent
   agent processes ever share one Probe instance, work could be repeated.

## Components and who owns them

| Component | Owner | Status |
|---|---|---|
| `probe/` — network discovery, scope fence, kill switch, leads | Teammate | Complete, not modified here |
| `app/adapters/` — Network Graph Adapter, Probe-leads translator, external-agent contract | This side | Complete |
| `app/agents/web_security/` — httpx, Katana, ZAP | This side | Complete; Katana/ZAP have synthetic fixture fallbacks, not yet validated against live tool instances |
| `app/agents/binary_analysis/` — file/readelf/checksec, Ghidra | This side | Complete; Ghidra has a synthetic fixture fallback, not yet validated against a live Ghidra install |
| `app/orchestrator/` — LangGraph workflow (14 nodes) | This side | Complete |
| `app/core/` — schemas, Scope Guard, config | This side | Complete |
| `app/database/` — SQLAlchemy models, repository | This side | Complete |
| `app/analysis/` — evidence validation, attack paths (NetworkX), PTES mapping | This side | Complete |
| `app/reporting/` — Jinja2 + ReportLab | This side | Complete, PDF layout functional but not polished |
| `app/api/` — FastAPI routes | This side | Complete |

## Known bugs found and fixed

Each entry: what was wrong, how it was found, the fix, and the commit/date.

### 1. `repository.store_network_graph` referenced a non-existent field
- **Symptom**: `AttributeError: 'NetworkGraphAssetRecord' object has no attribute 'discovery_source'` the first time any code path actually called `store_network_graph` (no test had ever exercised it before).
- **Root cause**: `NetworkGraphAssetRecord` (the normalised adapter model) never had a `discovery_source` field; the repository code assumed it did.
- **Fix**: derive `discovery_source` once per graph from `NetworkGraph.generated_by` (every asset in one graph shares the same origin) instead of reading it off each asset.
- **Found via**: writing `tests/test_orchestrator_probe_nodes.py::test_load_network_graph_falls_back_to_probe_api`, the first test to call this path end-to-end.
- **File**: `app/database/repository.py`

### 2. CRLF line endings broke the orchestrator's Docker entrypoint
- **Symptom**: container exits immediately with `exec /usr/local/bin/entrypoint-orchestrator.sh: no such file or directory` — a misleading error that looks like a missing file, not a shebang problem.
- **Root cause**: `docker/entrypoint-orchestrator.sh` was edited on Windows; Git's `core.autocrlf=true` keeps it CRLF in the working tree, and a CRLF shebang line (`#!/bin/sh\r`) doesn't resolve inside the Linux container.
- **Fix**: stripped CRLF from the file; added `.gitattributes` (`*.sh text eol=lf`) so this can't silently regress on a future Windows checkout.
- **Found via**: an actual `docker build` + `docker run` of the orchestrator image.
- **Files**: `docker/entrypoint-orchestrator.sh`, `.gitattributes`

### 3. `probe/` package missing from the orchestrator's Docker image
- **Symptom**: would have raised `ImportError` (caught, surfaced as a clear `GraphValidationError`) the first time `ProbeAPISource` ran inside a container — the live Probe integration would silently never work in the deployed container, only when run locally from the repo root.
- **Root cause**: `Dockerfile.orchestrator`'s `COPY` list never included `probe/`.
- **Fix**: added `COPY probe ./probe`. Verified it doesn't drag in `scapy` or any of Probe's heavier runtime — `probe.client` (the only submodule the orchestrator imports) is stdlib-only, confirmed by importing it inside the rebuilt container and checking size/behaviour.
- **Found via**: manual review while auditing container compatibility, then confirmed by rebuilding and importing `probe.client` inside the actual container.
- **File**: `Dockerfile.orchestrator`

### 4. `probe_leads.py` used wrong field names for Probe's `leads()` output
- **Symptom**: would have silently produced findings with `asset_id=None` and a generic description, instead of real data — no exception, just quietly wrong output.
- **Root cause**: written against `docs/CONTRACT.md`'s prose description (which implied an `ip`/`description` shape) without checking `probe/store.py`'s actual `leads` table schema (`address`/`evidence`/`source`/`count`).
- **Fix**: rewrote the translator against the real `Store.leads()` columns, verified with a live round trip through Probe's actual FastAPI app in `tests/test_probe_integration.py::test_findings_from_probe_leads_translates_both_sources`.
- **Found via**: reading `probe/store.py` directly instead of trusting the contract doc's prose.
- **File**: `app/adapters/probe_leads.py`

### 5. `requirements.txt` forced `scapy` into every container, and the orchestrator image never imported it anyway
- **Symptom**: not a crash, but unnecessary bloat/fragility — all three app containers (orchestrator, web-agent, binary-agent) installed `scapy` even though the only Probe code they ever touch (`probe.client`) is stdlib-only.
- **Fix**: moved `scapy` into a separate `requirements-probe.txt`, installed only on the machine that actually runs `python -m probe`.
- **File**: `requirements.txt`, new `requirements-probe.txt`

### 6. Held-segment safety was policy-overridable, not a hard rule
- **Symptom**: before the fix, an operator who explicitly listed a Probe-held (hidden, not-yet-approved) asset in `approved_asset_ids` would have had it treated as in-scope — a policy mistake would silently defeat Probe's own hold mechanism.
- **Fix**: `ScopeGuard.check_asset_in_scope` now refuses a held asset unconditionally, before checking the approved list at all; the default scope (when `approved_asset_ids` is empty) is "every known asset except held ones", not "every known asset".
- **Found via**: design review while wiring the real `held` field through from Probe, not a test failure — this was a safety gap, not a crash.
- **File**: `app/core/scope_guard.py`

### 7. The genericness test (`tests/test_generic.py`, teammate's) was failing on our docs
- **Symptom**: `python -m unittest` / `pytest` failed on site-specific strings (a hardcoded lab IP range and two event/role-specific words — see `tests/test_generic.py`'s `FORBIDDEN` table for the exact patterns) in `README.md` and `docs/network_graph_contract.md` — this repo's own policy (enforced by a teammate-written test) is that nothing in product docs/code names a specific event or network.
- **Fix**: rewrote both documents in neutral language, using the same example range (`10.20.30.0/24`) Probe's own docs/fixtures already use.
- **Files**: `README.md`, `docs/network_graph_contract.md`

### 8. `AssessmentPolicy.dry_run` was documented but completely unenforced
- **Severity**: high — this is a documented safety control that silently did nothing.
- **Symptom**: the schema's own docstring and the README both state that `dry_run` (default `true`) makes the Scope Guard "log intended tool invocations without executing them" — but no code anywhere ever read `policy.dry_run` to actually stop a call. Every `check_*_allowed()` method either denied (permission off / out of scope) or returned normally, and the caller always went on to make the real httpx request / subprocess call / ZAP API call regardless of `dry_run`'s value. An operator relying on the documented behaviour (e.g. enabling `allow_web_crawling` to validate a policy with `dry_run=true` before really running it) would have had Katana actually run for real.
- **Fix**: `ScopeGuard._allow()` — the single choke point every `check_*_allowed()` call funnels through on success — now raises a new `DryRunSkipped` exception (a `ScopeViolationError` subclass, so every existing `except ScopeViolationError` call site already handles it correctly with no further changes) instead of returning, whenever `dry_run` is set. The attempt is still recorded `allowed=True` in the audit log (the policy *would* have permitted it), just not executed.
- **Consequence for other code**: since `dry_run` defaults to `True`, every existing test/script that constructs an `AssessmentPolicy` and expects a real (or fixture-backed) tool call to actually run had to be updated to pass `dry_run=False` explicitly — `tests/test_scope_guard.py`, `tests/test_web_agent.py`, `tests/test_binary_agent.py`. `scripts/run_synthetic_demo.py` and the README's example `POST /assessments` body already did this correctly.
- **Found via**: manual line-by-line review of `app/core/scope_guard.py` plus a repo-wide `grep -rn dry_run app/`, which turned up zero reads of the field outside the dataclass/schema definitions.
- **Files**: `app/core/exceptions.py` (new `DryRunSkipped`), `app/core/scope_guard.py`, plus the three test files above. New test: `tests/test_scope_guard.py::test_dry_run_blocks_an_otherwise_authorised_call`.

### 9. `complete_assessment` derived final status from a list that mixes warnings with failures
- **Symptom**: a fully successful assessment (every attempted task actually completed) could be reported `partially_completed` purely because an earlier node (`validate_scope`) had logged a benign configuration note — e.g. "a permission is enabled but there's nothing in the graph to use it on" — into the shared `OrchestratorState.errors` list. `complete_assessment` treated *any* non-empty `errors` list as proof something had gone wrong.
- **Fix**: `complete_assessment` now queries each specialist task's actual persisted `TaskStatus` (`repository.list_agent_tasks`) and bases the verdict only on COMPLETED vs FAILED among tasks that were actually attempted (SKIPPED tasks — not authorised, or nothing to do — don't count as failures either). `OrchestratorState.errors` is no longer consulted for this decision at all.
- **Found via**: reproduced directly — constructed a state with only a benign warning string and confirmed it returned `partially_completed`, confirming the bug before changing anything.
- **File**: `app/orchestrator/nodes.py`. New test file: `tests/test_orchestrator_completion.py` (5 cases covering all-skipped, all-completed, one-failed, all-failed, and nothing-attempted-at-all).

### 10. `evidence_validator`'s `auto_confirmed` report field was computed from post-pass status alone
- **Severity**: low — no current producer triggers it, but the field's meaning was wrong.
- **Symptom**: `report.auto_confirmed` was built as "every finding whose status is now CONFIRMED", which would also catch a finding that entered `run_evidence_validation` *already* confirmed (from some future/other caller), mislabelling it as "confirmed by this auto-confirmation pass" when it wasn't touched at all.
- **Fix**: compare each finding's status *before* and *after* `auto_confirm_eligible`; only list a finding if this pass actually changed it from `suspected` to `confirmed`.
- **Found via**: manual review of the module while writing `tests/test_evidence_validator.py` — a file that didn't exist before, despite this module enforcing the system's core "a scanner alert is never automatically confirmed" guarantee.
- **File**: `app/analysis/evidence_validator.py`. New test: `tests/test_evidence_validator.py::test_auto_confirmed_report_only_lists_findings_actually_promoted_this_pass` (plus 7 other cases covering the rest of the module, which had zero prior test coverage).

### 11. `Finding`'s `_at_most_one_target` validator was a no-op
- **Severity**: low-moderate — a modelling invariant was silently unenforced; no current producer actually violates it.
- **Symptom**: the validator's name and position (applied to both `asset_id` and `binary_id`) strongly imply it enforces "a finding targets at most one of a network asset or a binary" — but its body was `return v` with no check at all. A `Finding` with both `asset_id` and `binary_id` set (or a future bug that sets both) would have passed validation silently.
- **Fix**: replaced with a real `@model_validator(mode="after")` that raises `ValueError` if both are set. Verified no existing producer (`app/agents/web_security/findings.py`, `app/agents/binary_analysis/findings.py`, `app/adapters/probe_leads.py`, `app/adapters/external_network_agent.py`) sets both, so this is a pure tightening with no behaviour change for valid input.
- **Found via**: `ruff --select ARG003` flagged the validator's unused `info` parameter, which prompted reading the function body.
- **File**: `app/core/schemas.py`.

### 12. Flaky Probe-integration tests under load (test infrastructure, not application code)
- **Symptom**: `tests/test_probe_integration.py` and `tests/test_orchestrator_probe_nodes.py` passed reliably alone, but intermittently failed/errored when run as part of the full suite (empty responses, connection errors) — not a consistent reproduction, which is itself the signature of a race condition.
- **Root cause**: both files' `probe_server` fixture polled `uvicorn.Server.started` to decide the server was ready, then immediately started sending real HTTP requests. `started` becomes `True` right after uvicorn's own startup sequence finishes, which is a moment *before* the OS-level listen socket reliably accepts every connection — usually fine, but prone to losing the race under system load (e.g. running right after a large, CPU-heavy test file).
- **Fix**: added `start_probe_test_server()`/`stop_probe_test_server()` to `tests/conftest.py`, which additionally retries a real `GET /api/status` request (up to 15s) before declaring the server ready. Both test files now share this one implementation instead of each having their own copy of the polling loop. Verified by running the two files together 3x back-to-back with zero failures (previously flaky roughly every other run).
- **Files**: `tests/conftest.py`, `tests/test_probe_integration.py`, `tests/test_orchestrator_probe_nodes.py`.

### 13. Report integrity: synthetic fixture data was indistinguishable from real findings
- **Severity**: critical — a trust/integrity gap in the deliverable itself, found during an architecture-level review, not routine testing.
- **Symptom**: when a real tool (Katana, ZAP, Ghidra) is unavailable, its agent silently substitutes documented synthetic fixture data so development/demos keep working. That substitution was never surfaced anywhere in the final PDF/JSON report. A reader had no way to tell a fixture-generated finding from a real scan result — a report produced during a real engagement where, say, ZAP happened to be down would read identically to one from a fully live run.
- **Fix**: `_build_report_data` now computes `fixture_tools_used` from each agent's `tool_executions` (which already carried `used_fixture` per call, just never read downstream) and surfaces it as an unmissable, explicit section: a `data_integrity` block in the JSON report, a bold warning paragraph at the top of the executive summary, and a red banner at the top of the PDF.
- **Found via**: architecture-level review requested explicitly, not a test failure — grepped for `used_fixture` reaching the reporting module and found it stopped at `map_ptes_phases`, never reaching `generate_report`.
- **Files**: `app/reporting/generator.py`, `app/reporting/templates/executive_summary.txt.j2`. New test file: `tests/test_reporting.py` (first test coverage this module has ever had).

### 14. `run_concurrently`'s declared timeout was cosmetic — it didn't actually bound blocking time
- **Severity**: high — this is the mechanism meant to stop a hung Katana/Ghidra subprocess from blocking the whole assessment pipeline, and it didn't work.
- **Symptom**: `app.orchestrator.dispatcher.run_concurrently` runs the Web and Binary agents concurrently with a shared `timeout_seconds`. It used `with ThreadPoolExecutor(...) as executor:`. `wait(..., timeout=timeout_seconds)` correctly identified a straggler future and the code called `.cancel()` on it — but `Future.cancel()` is a no-op once a thread has actually started running (Python has no way to force-kill a running thread), and the `with` block's implicit `executor.shutdown(wait=True)` on exit then blocked until that straggler thread *actually* finished, regardless of the declared timeout. A hung tool call (e.g. a Katana crawl against an unresponsive target) could therefore block this function — and the FastAPI background task running the whole assessment — for as long as the straggler actually took, not the configured `agent_task_timeout_seconds` (default 600s, potentially much longer for a truly hung process).
- **Reproduced first**: a minimal 10-line script confirmed the exact mechanism — `wait()` returned at 0.5s as expected, but the `with`-block exit still blocked for the job's full 3s duration — before touching any code.
- **Fix**: replaced the `with` statement with a manual `executor.shutdown(wait=False)`, so the function returns at the declared timeout as documented. A timed-out job's thread may continue running in the background (unavoidable in Python), but this function and its caller no longer wait on it; the underlying tool call's own inner timeout (Katana/Ghidra/httpx each already have one) eventually cleans it up.
- **Files**: `app/orchestrator/dispatcher.py`. New test file: `tests/test_dispatcher.py`, including `test_timeout_actually_bounds_wall_clock_time` (a 2s job with a 0.3s timeout must return in well under 1s — reliably took >=2s before the fix) and a concurrency sanity check using a `threading.Barrier` to prove the two jobs actually overlap rather than running sequentially.

### 15. A crashed orchestrator run left the assessment stuck at "running" forever
- **Severity**: high — an "autonomous" system whose failures are invisible is worse than one with no status at all.
- **Symptom**: `_run_orchestrator_background` (the FastAPI background task that drives a whole assessment) caught any exception escaping the LangGraph run, logged it, and returned — but never updated the assessment's database row. Since `validate_assessment` (the graph's first node) already sets the row to `running` before anything else happens, any later uncaught exception (a bug in a node, a DB outage mid-run, anything not already handled by that node's own try/except) left the assessment permanently reporting `running` via `GET /assessments/{id}`, with the actual crash visible only in server logs nobody may be watching.
- **Fix**: the exception handler now explicitly marks the assessment `failed` (with `completed_at` set) and logs the crash against it via `repository.log_event`, wrapped in its own best-effort try/except so a *second* failure (e.g. DB also down) doesn't change the outcome — it just logs twice instead of updating status.
- **Files**: `app/api/routes.py`. New test file: `tests/test_api_routes.py` (first test coverage this module has had), including a test that a successful run is left untouched by this error-handling path (only a crash triggers it).

### 16. `BinaryMetadata.is_stripped` was briefly set from the wrong tool output
- **Severity**: low — overwritten by the correct check in the common case; wrong only when `readelf -sW` itself fails.
- **Symptom**: `is_stripped` was first set by checking whether the string `"no symbols"` appeared in `readelf -h`'s output — the ELF *header* dump, which never contains that phrase in any `readelf` implementation, so the check was vacuously almost-always `True`. A later line correctly overwrites this from the real symbol-table output (`readelf -sW`), masking the bug in the common case — but if that second call itself failed for any reason, the binary was left incorrectly reported as stripped based on a check that could never meaningfully be `False`.
- **Fix**: removed the vacuous assignment; `is_stripped` is now only ever set from the actual symbol-table check, and stays `None` (honestly "unknown") if that check fails, instead of guessing wrong.
- **File**: `app/agents/binary_analysis/metadata.py`.

---

## New capability: Network Vulnerability Detective (app/agents/network_vulnerability/)

Following a new, more detailed specification that explicitly named this as
the biggest gap (`docs/IMPLEMENTATION_STATUS.md` has the full audit),
implemented a real (not a stub) agent that answers "are the identified
network services affected by known security weaknesses or insecure
configurations?" — distinct from Probe, which only identifies that a
service exists. **Probe/discovery was explicitly not touched or
re-implemented** — this agent only operates on services already present in
the authorised `NetworkGraph`.

- **Checks implemented**, each a single short-lived, read-only TCP
  connection with no credential guessing and no data modification:
  SSH (banner + deprecated-protocol-1 detection), Redis (PING-based
  auth-required check — flags an unauthenticated instance as `critical`),
  MySQL (handshake-packet version parsing), PostgreSQL (StartupMessage +
  auth-method parsing — flags `trust` auth, i.e. no password at all, as
  `critical`), FTP (banner + gated, explicitly-authorised-only anonymous-
  login check), SMB (reachability only — full dialect negotiation would
  need a dedicated library, documented as a known limitation rather than
  faked).
- **Scope-gated**: reuses the existing `ScopeGuard.check_service_assessment_allowed`
  (already present, previously unused by anything in `app/`) — no scope
  guard changes needed.
- **Bugs this specific work caught**: the agent's `AgentId` was initially
  reused from the existing `NETWORK_VULNERABILITY` value (used by the
  external-agent ingestion contract and Probe's leads), which would have
  made two independent orchestrator branches race to update the same
  database task row — fixed by giving it a distinct `AgentId.NETWORK_VULNERABILITY_DETECTIVE`.
  Separately, `ruff` caught a missing import in `app/orchestrator/nodes.py`
  (`run_network_vulnerability_agent` was referenced but never imported) that
  no test had caught, because every initial test called the agent function
  directly rather than through the actual orchestrator dispatch node — a
  new test (`test_dispatched_through_the_real_orchestrator_node`) now
  exercises that exact path.
- **Tested against real protocol wire formats**, not mocks: each check's
  hand-written binary/text parser is exercised against a small real TCP
  server emitting the actual protocol bytes (a real Redis `+PONG`/`-NOAUTH`
  reply, a real MySQL handshake packet, a real PostgreSQL
  `AuthenticationOk`/`AuthenticationMD5Password` response, etc.) — this
  caught a real test-fixture bug (Windows RST-on-close race) during
  development, fixed by draining the client's request before responding,
  not by weakening the check logic itself.
- **Files**: `app/agents/network_vulnerability/{checks,findings,agent}.py`
  (new), `app/orchestrator/nodes.py`, `app/orchestrator/state.py`,
  `app/core/schemas.py` (new `AgentId.NETWORK_VULNERABILITY_DETECTIVE`,
  new `AssessmentPolicy.allow_ftp_anonymous_check`), `app/analysis/ptes_mapper.py`,
  `app/reporting/generator.py`. New test file:
  `tests/test_network_vulnerability_agent.py` (14 tests).

---

## History

<!-- Append new entries above this line, most recent first is NOT required —
     just keep each entry intact once written. -->

- **Entry 1** — Documentation created. Captured the state of the merged
  codebase (app/ + probe/) after the Probe integration work: live
  `ProbeAPISource`, auto-ingested leads, held-segment safety, SQLite
  default, and the 7 bugs listed above found and fixed during that work.
  Starting a fresh bug-hunting pass from here per explicit request.

- **Entry 2** — Dedicated bug-hunting pass. Found and fixed 5 more real
  issues (#8-#12 above), the most significant being #8: `dry_run` was
  documented and defaulted on, but had zero actual effect anywhere — every
  tool call ran for real regardless. Also fixed a no-op Pydantic validator
  on `Finding` (`_at_most_one_target` took a value and returned it
  unchanged, enforcing nothing — now a real `model_validator` that rejects
  a finding citing both `asset_id` and `binary_id`), an assessment-status
  bug that conflated benign warnings with real task failures, a mislabelled
  `auto_confirmed` report field, and flaky test fixtures that raced a
  background uvicorn server's readiness. Added test coverage for two
  modules that had none (`evidence_validator`, the `complete_assessment`
  status logic) and a dedicated dry-run regression test. Test count:
  157 → 170, and the Probe-integration tests are now reliable under
  repeated back-to-back runs (previously flaky). Also diagnosed (not fixed
  — not our component) `test_fence_leash.py`'s platform-specific flakiness
  on Windows, documented under "Known environment limitations" above.

- **Entry 3** — Architecture-level review (explicitly requested: "find
  fundamental issues... our job depends on it"), followed by fixing the
  four concrete, fixable issues it turned up (#13-#16 above). The
  standout: #13, a report-integrity gap — synthetic fixture data was
  completely indistinguishable from real findings in the delivered report,
  found by tracing `used_fixture` and discovering it never reached
  `generate_report`. Also fixed #14 (a concurrency timeout that didn't
  actually bound wall-clock blocking time — reproduced with a standalone
  script before changing any code), #15 (a crashed assessment run left
  stuck reporting "running" forever instead of surfacing the failure), and
  #16 (a minor wrong-tool-output bug in binary stripped-ness detection).
  Added first-ever test coverage for three more modules that had none
  (`dispatcher`, `api/routes`, `reporting/generator`). Test count: 170 → 180.
  Architecture-level findings that are NOT yet fixed (deliberately —
  they're design/process decisions, not drop-in code changes) are listed
  separately below under "Fundamental issues raised but not yet acted on".
