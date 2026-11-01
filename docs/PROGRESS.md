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
- **Scope division (as of this entry)**: the teammate is independently
  building the content-discovery → binary-artifact-harvesting →
  embedded-secret-extraction → single-attempt-console-auth chain in
  `app/` (new orchestrator nodes on the web + binary agents) to chase the
  CTF flag behind the `10.20.30.139:8833` console found during Probe
  verification. That whole chain is their scope by agreement — do not add
  competing/duplicate nodes for it here. This session's `app/` work stays
  on everything else (reporting, orchestrator plumbing, Probe
  integration/verification, remaining Master-Spec gaps not in that list:
  SSE event stream, task ledger, binary sandbox isolation).

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

- **Entry 4** — Independently verified the teammate's newest Probe commit
  (hidden-HTTP-service discovery via `http-inventory`/`observe_http.py`)
  rather than trusting the self-report, per request. Merge was clean
  (fast-forward, no conflicts), full suite green (343 passed). Ran a real
  live discovery pass against the authorised `/24` to reproduce the
  claimed results directly:
  - **Confirmed**: the headline claim reproduces. `10.20.30.139:80`
    (a wiki page) names an internal endpoint, `10.20.30.139:8833`, and
    the engine's `reported-endpoint-connect` follow-up independently
    connects to port 8833 and captures its real banner ("GAME ZONE" CTF
    service) — stored as both a `leads` row and a `ports` row with the
    connect-banner evidence attached. The attribution/provenance chain
    (which page referenced which address, on what basis) is intact in the
    stored lead record.
  - **New bug found (not fixed — teammate's component, flagged per the
    standing instruction not to touch Probe's own scanning code without
    being asked to fix it, only diagnose it):** the live run died silently
    partway through the `fingerprint` phase (UDP + OS nmap scans), with no
    traceback and no final summary ever printed. Root-caused via the
    auditor's own evidence file, not guesswork: `audit-violation.json` in
    the run's data dir records `"independent scope enforcement cannot be
    verified: ... windows-program-scope.ps1 ... timed out after 12
    seconds"`. The independent egress auditor (`probe/audit.py`)
    periodically re-verifies the Windows firewall egress rule by shelling
    out to a PowerShell script with a hard 12s timeout; under the CPU load
    of two concurrent nmap subprocesses (`-sU` and `-O`, each budgeted
    45s) that readback call ran long, the auditor treated the timeout
    itself as an unverifiable-safety condition (correctly, by its own
    fail-closed design) and killed the main process with `SIGTERM` +
    `os._exit(87)` in the auditor — a false-positive safety trip, not an
    actual out-of-scope probe or scope violation. This is why the run's
    own `run.log` just stops mid-phase with no error line: the kill is a
    raw `SIGTERM` to the main process, which has no custom handler, so
    nothing more gets logged. (A second, separate red herring: the shell
    pipeline used to capture output, `... | tee f | tail -200`, reports
    `tail`'s exit code, not the killed Python process's — so "exited with
    code 0" in the captured transcript did not mean what it looked like.)
    Net effect: as written, any sufficiently loaded host risks losing a
    run's UDP-scan/OS-fingerprint results (and the final summary) to this
    false trip — confirmed by `probe.db` from this run itself showing 0
    UDP-proto rows among its 233 stored ports. Likely fix on Probe's side:
    either raise the readback timeout, treat a timeout as "retry once"
    rather than an immediate fail-closed kill, or de-prioritize/stagger the
    readback check relative to concurrent nmap subprocesses — a decision
    for the teammate to make, flagged here rather than changed.

- **Entry 5** — Full post-probe pipeline (`app/`: web agent, Network
  Vulnerability Detective, orchestrator, reporting) run end-to-end against
  the real, already-completed lab-network scan (166 real hosts, 233 real
  TCP services) instead of the bundled synthetic demo graph, per request
  ("make sure it works correctly on lab network ... even the reporting
  part"). Full writeup, data flow, and tech stack: see new
  `docs/APP_ARCHITECTURE.md`. Headline results: scope enforcement correctly
  refused dozens of real-but-unapproved web origins across the lab; `httpx`
  produced a real, auto-confirmed finding against the real wiki host;
  `katana`/ZAP correctly fell back to fixtures (not installed locally) and
  that fallback was honestly flagged in both the JSON and PDF reports; both
  report formats generated correctly from real data.
  - **Bug found and fixed**: the Network Vulnerability Detective silently
    skipped unmistakable services (ssh/smb/postgresql) whenever Probe's
    graph carried no `service_name` for the port — the dispatch gate in
    both `agent.py` and `checks.py` keyed purely off that string, with no
    fallback. Fixed with a small, local, IANA-registered port→name
    fallback (`_PORT_NAME_FALLBACK`), consulted only when the graph
    supplies no name, never overriding one it does supply, and recorded
    transparently per-check as `assumed_service_name`. Verified via the
    same real-lab run: real protocol checks executed went from 2 to 91
    after the fix (all against genuinely real lab services), correctly
    reporting zero flagged findings — an honest negative, not a skipped
    one. All 14 of the agent's existing tests, plus the full 343-test
    suite, still pass.

- **Entry 6** — Correction and honest re-verification, after being called
  out (rightly) for overstating Entry 5: that run only exercised the Web
  Agent and Network Vulnerability Detective — `allow_binary_analysis` was
  `False` and `binary_paths` was empty, so **the Binary Analysis Agent never
  ran at all**, despite the write-up implying all three agents were
  verified. Also, the whole run was in-process, not through the actual
  `docker-compose` deployment, so nothing about the containerised path had
  been checked.
  - **Tried the containers next; found a real build-breaking bug.**
    `docker compose build` failed outright on `binary-agent`:
    `Dockerfile.binary`'s final stage pins `FROM python:3.12-slim`, whose
    Debian base image recently rolled from `bookworm` to `trixie`, which
    dropped the `openjdk-17-jre-headless` package (only `openjdk-21-*`
    remains) — so `apt-get install ... openjdk-17-jre-headless` fails with
    "no installation candidate", every time, on a clean build. The
    container could never have been exercised before this was found. Fixed
    by pinning `python:3.12-slim-bookworm` explicitly instead of floating
    `python:3.12-slim`, keeping the JRE version Ghidra 11.1.2 was actually
    built against.
  - **Then asked to stop using Docker entirely and run natively.** Dropped
    the containerised path for this verification (the Dockerfile.binary fix
    stays in the repo — it's a real bug either way) and instead confirmed
    every tool `app/` depends on is genuinely present on this machine:
    `readelf`/`objdump` (MinGW), `file`, a JDK, and `gcc`. Compiled a real,
    deliberately-weak C program (`vuln.exe`: a real `strcpy`/`gets`/`system`
    call chain, a real embedded secret-shaped string) and ran a true
    3-agent, in-process, no-Docker assessment against it plus the same real
    lab network graph:
    - **Web Agent**: ran exactly as in Entry 5 (real `httpx`, fixture
      `katana`/ZAP, honestly flagged).
    - **Network Vulnerability Detective**: 91 real protocol checks against
      real lab services (ssh/mysql/postgresql/smb), all correctly
      zero-flagged.
    - **Binary Analysis Agent: ran for the first time, genuinely.** Stage A
      (`file`/`readelf`/`checksec` — binary identification and hardening
      properties) ran for real against the real compiled `vuln.exe` and
      correctly identified it as `PE` format with no errors. Stage B
      (Ghidra function/string/import extraction) fell back to its synthetic
      fixture, because **Ghidra itself is not installed on this machine** —
      a genuine environment gap, not a code bug, and already handled by the
      code exactly as designed: `used_fixture=True`, surfaced in
      `data_integrity.fixture_tools_used` (`["ghidra", "katana",
      "zap_passive"]`) in both the JSON and PDF reports. The four resulting
      binary findings (unsafe `strcpy`/`system` usage, an embedded-secret
      string, a suspicious-input-handling function) therefore describe the
      fixture's canned program, not an independently-verified read of
      `vuln.exe`'s actual content, even though they happen to resemble it —
      that resemblance is not evidence, and the report says so.
  - **Net honest status**: all three agents now confirmed to actually run,
    in-process, no Docker. Two of three (Web, Network Vulnerability
    Detective) produced fully real, non-fixture-dependent results against
    genuine lab targets. The third (Binary Analysis) is real end-to-end for
    Stage A; Stage B/C are only verified via fixture pending a local Ghidra
    install, which has not been attempted.
  - **On network-discovery completeness** (separately raised, "the
    network owner has already given the IP address but the tool can't probe
    every device inside it"): re-checked the Probe scan's own recorded
    stats directly rather than re-asserting anything. Of 253 addresses in
    the authorised `/24`, 166 answered something and were classified; 87
    never answered any probe at a single tier (ARP through UDP-to-closed-
    port) and are reported as "undetectable with this probe set," which is
    this tool's honest terminology for "no evidence of a device here," not
    proof one is absent; 12 more were seen but ran out of the scan's time
    budget before full identification. Discovery itself converged normally
    (the adaptive round-robin stopped because a further round added no new
    evidence — not because of an error). Separately, the Entry 4
    auditor-timeout bug killed a *later*, different phase (UDP/OS service
    fingerprinting of already-discovered hosts) — that is a real, already-
    diagnosed-and-flagged gap in service enrichment, not in device
    discovery itself, and the two should not be conflated.

- **Entry 7** — Pulled the teammate's latest commit (`a6eb3c0`, "Update
  project implementation and tests") into `main`. Clean fast-forward, no
  divergence, no conflicts with this session's uncommitted work — the
  commits don't touch any of the same files. This is their full
  content-discovery → binary-harvesting → credential-recovery →
  console-auth chain (see §1's scope split): new
  `app/agents/web_security/content_discovery.py`,
  `app/agents/binary_analysis/{acquisition,discovered_artifact,
  credential_recovery,pyghidra_adapter,raw_strings}.py`,
  `app/agents/network_security/console_auth.py`, plus new inventory/
  protected-storage/completeness infrastructure and ~15 new test files.
  `docs/BINARY_ANALYSIS_REPORT.md` (their own write-up) confirms they
  followed through on the redesign reviewed earlier in this log: scope
  10.20.30.0/24 → stated explicitly as "discovery/analysis stage only,
  no authentication attempt was made."
  - Installed the one new dependency (`pypdf==6.15.0`).
  - Two test failures after the pull, both chased down rather than assumed:
    one was this session's own stale, gitignored local `evidence/ape.db`
    (accumulated across many repeated local `pytest` runs today) tripping
    a new, stricter duplicate-asset-ID guard their merge added to
    `app/database/inventory.py` — deleted the local file (not repo state)
    and it passed cleanly. The other was real: their new
    `docs/BINARY_ANALYSIS_REPORT.md` itself violates this repo's own
    generic/no-site-specific-content test (a literal `10.20.30.` where
    the rest of the repo uses a neutral example range) — fixed with the
    same one-line wording change already applied elsewhere in this log.
  - Full suite after the pull and both fixes: **445 passed, 4 skipped**
    (all four skips are `test_credential_recovery.py` cases that need a
    real Ghidra install — the same honestly-flagged gap noted in Entry 6,
    now confirmed shared by their code too, not specific to this
    environment).
  - No action taken on the new chain itself — still their scope per the
    agreement in §1/Entry 4; this entry is the pull + the two fixes needed
    to get the merged tree back to green, nothing more.

- **Entry 8** — Investigated the explicit complaint "my friend pulled this
  code and the vulnerability detection pipeline isn't flagging anything;
  make sure Katana is genuinely downloaded and used, the way Ghidra is."
  That comparison turned out to be exactly right — the gap is real, and
  Katana really had never been run against anything but its own fixture on
  this machine before now (confirmed: `katana` was not on PATH at the start
  of this entry). Installed it for real (`go install
  .../projectdiscovery/katana/cmd/katana@latest`, Go was already present),
  confirmed the real binary (v1.8.0) resolves and runs. Three real, separate
  bugs were then found by testing it against the real lab target, not by
  inspection alone — each one independently explains why a real katana
  install would still silently produce nothing:
  1. **`_parse_katana_jsonl` schema mismatch.** It read a top-level
     `endpoint`/`url` key; real Katana's JSONL nests the URL under
     `request.endpoint`. Every real crawl parsed to zero endpoints, with no
     error anywhere — only the *fixture's* synthetic records (which do use
     a top-level key) ever parsed successfully, which is exactly why this
     was invisible without a real binary to test against. Fixed to check
     `request.endpoint`/`request.url` first, falling back to the top-level
     keys for compatibility.
  2. **`-dr`/`-disable-redirects` silently capped every real crawl at one
     page.** The flag disables following *any* redirect, not just
     out-of-scope ones — `-cs` (crawl-scope regex) already bounds redirects
     to the authorised origin on its own. The real lab target's own
     homepage 302s to `/index.php?p=`, an unremarkable, common pattern; with
     `-dr` present, Katana could never get past it. Removed `-dr`;
     `-cs` plus the existing Scope Guard re-check on every resulting URL is
     the correct and sufficient bound.
  3. **Timeout too short for a real crawl.** The old formula gave 60s at
     depth=2; an actual, measured real crawl of the real lab target at the
     default rate took ~84s to complete. Rescaled by depth and (inversely)
     by rate, with comfortable headroom over the measured baseline.
  - **Verified all three fixes together**: a real crawl against the real
    lab host (`10.20.30.139`) returned **24 genuinely new, in-scope
    endpoints** (`used_fixture=False`) including an `index.php?p=&view=...`
    file-read-shaped parameter, `/backups`, `/ops`, and several real,
    previously-hidden files (`README.txt`, `netops-handover.txt`,
    `edr_log_generator.py`) — the Scope Guard also correctly filtered out
    ~40 real but out-of-scope third-party CDN/script URLs Katana also
    found. Full suite re-run after the fix: **445 passed, 4 skipped**
    (one pre-existing test asserted the buggy `-dr` behavior as a
    requirement; updated it to assert the corrected behavior instead).
  - **Second gap, also matching the user's Ghidra comparison exactly**:
    Katana's discoveries fed only report metadata
    (`discovered_endpoints`) and were never turned into a `Finding` at
    all — unlike Ghidra's `static_analysis.py`, which flags its own
    signal. Added `findings_from_discovered_endpoints` (new, in
    `web_security/findings.py`): a generic, site-independent heuristic
    over each discovered endpoint's own query-PARAMETER NAMES (never
    values, never page content) — `file`, `page`, `view`, `path`,
    `template`, etc. — flagging one `suspected`, low-confidence,
    medium-severity finding per matching parameter, the same posture as
    the binary agent's unsafe-function flags (signal for review, not
    proof). Verified against the real, already-captured 63-endpoint real
    crawl output: it correctly flags the real `view=` parameter found
    above.
  - **Not fixed, flagged honestly**: ZAP's passive/active scan still only
    opens the single root `target.url`, never Katana's discovered
    endpoints — so ZAP-sourced findings still only ever cover the one
    page, regardless of how much Katana discovers. Closing this
    (ZAP-scanning each discovered endpoint, not just the root) is the
    next real step toward full parity with the binary side, not done
    here.
  - **Environment note**: the real lab target visibly degraded (one
    request returned `502`, a later crawl found only 1 endpoint instead
    of 24) partway through this verification, almost certainly from the
    repeated real crawl load this entry itself generated against a small
    shared lab service — not a pipeline defect. Stopped repeated live
    runs once this was apparent; the 24-endpoint/flagged-finding result
    above was already captured and is not retracted by the later
    flakiness.
  - **Setup note for whoever runs this**: Katana now needs to be
    findable the same way Ghidra does — either on `PATH` or via
    `APE_KATANA_BINARY` pointing at the binary directly. It's been
    installed to this machine's Go bin and added to this user's
    persistent `PATH`, but a shell/session already running when that
    change was made won't see it until restarted — explicit setup, like
    `APE_GHIDRA_INSTALL_DIR`, not something the code can detect for you.

- **Entry 9** — Pulled the teammate's new autonomous-loop commit
  (`cc19ca6`, "Add orchestrator-controlled autonomous assessment loop with
  evidence-driven scheduler": `app/orchestrator/__main__.py`,
  `autonomous_loop.py`, `scheduler.py` — a one-command, resumable
  `python -m app.orchestrator run --assessment-id ID --scope CIDR
  --max-minutes N` that starts Probe itself, reads back its real
  discovery, then iterates candidate-scoring → agent dispatch →
  verification). Clean fast-forward; the only friction was the same
  gitignored stale `evidence/ape.db` issue as Entry 7 (the new
  `parent_task_id` column from the teammate's migration didn't exist in
  the stale local file) — deleted it, 460 passed/4 skipped.

  Then actually ran that new command against the real lab scope end to
  end, which surfaced two further real bugs, neither in anything added
  this entry — both were already-present gaps the new CLI finally
  exercised for the first time:

  1. **The orchestrator's own Probe-launch command disabled the thing it
     was about to poll.** `_start_probe_and_discover` passed `--no-ui` to
     `python -m probe run`, intending "headless." But Probe's own
     `cli.py` (`if not args.no_ui: ... uvicorn.Server(cfg).run()`) only
     starts its HTTP API at all when `--no-ui` is *absent* — the flag
     disables the API, not just the browser-facing web view. So Probe's
     own scan ran to completion correctly underneath it (confirmed: its
     own phase-by-phase log ran all the way to `enrich`), but
     `ProbeClient.status()` had nothing to poll and the orchestrator
     always hit its 180s timeout, regardless of admin rights — this is
     what the user saw and correctly identified as "it's not working even
     though I ran it as administrator." Fixed by removing `--no-ui` from
     the command `__main__.py` builds.
  2. **A real, reproduced auditor false-positive kill**, independently
     matching the *mechanism* already described (but, per that entry's
     own text, never fixed) in Entry 4 — reproduced live, not inferred:
     after fix #1 let the orchestrator actually reach the `fingerprint`
     phase, the whole Probe process died with
     `CRITICAL probe.killswitch: KILL SWITCH: ... auditor heartbeat
     stale`. Root-caused in `probe/audit.py`: the auditor's main loop
     both promises the engine a heartbeat every 0.5s (`Attestation`'s
     `STALE_AFTER` is only 3.0s) *and* calls `egress.check()` inline —
     a PowerShell subprocess shell-out with its own hard 12s timeout.
     Under the CPU load of the engine's own concurrent `nmap -sU`/`-O`
     during fingerprinting, that subprocess call ran long enough to raise
     `TimeoutExpired`; `egress.check()` turned that into
     `(False, "...")`, and the auditor's fail-closed design (correctly,
     by its own logic, just acting on a false premise) treated an
     unverifiable check as a scope violation and `SIGTERM`'d the whole
     engine — a false-positive safety trip, not an actual out-of-scope
     probe. Fixed by moving `egress.check()` into its own thread on a
     1s cadence, decoupled from the 0.5s heartbeat-write loop, so a slow
     read-back no longer blocks the heartbeat the engine depends on; a
     genuine egress failure (not just a slow one) still calls
     `violation()` exactly as before. Also widened the PowerShell
     subprocess timeout itself (12s → 20s) as extra margin. Full suite
     re-run after both changes: 460 passed/4 skipped (no existing test
     exercises `audit.py` directly — it only runs live, under real
     privileges). Live re-verification against the real lab scope
     reached the `fingerprint` phase cleanly (no kill-switch trip) before
     the lab network itself went down mid-session, which stopped further
     live verification for the time being; the fix itself is unchanged by
     that and stands on the code-level diagnosis above.

  **Also closed the one gap Entry 8 flagged as not done**: ZAP's
  passive/active scan previously only ever opened `target.url` — a page
  Katana discovered (reachable only via a link, never the site root) was
  invisible to ZAP's own header/cookie/active-rule checks even after
  Entry 8 made Katana's own discoveries become `Finding`s. Changed
  `web_security/agent.py`'s Stage C to run ZAP against the root URL plus
  up to 10 additional, deduplicated endpoints Katana discovered (each
  still goes through the normal per-URL Scope Guard check inside
  `run_passive_scan`/`run_active_scan_if_authorised` — this does not
  widen what ZAP is allowed to touch, only how many already-in-scope
  URLs get the same checks the root URL always got). Added
  `test_zap_scans_discovered_endpoints_not_just_the_root_url` (regression
  test, uses the fixture crawl so it runs without a real `katana` binary
  in CI) proving ZAP now scans more than one target per run. Full suite:
  **461 passed, 4 skipped**.

- **Entry 10** — Scoped the first item of a 14-item concurrency/scaling
  request (atomic multi-worker task leasing, scope partitioning,
  deduplication, a concurrent scheduler, worker pools, resource limits,
  PostgreSQL, a generic evidence-driven dependency graph, a one-command
  multi-worker CLI, real concurrency tests, and a load/scaling
  demonstration). Given the size, did item 1 ("fix Probe's task-leasing
  race first," as explicitly requested) for real, end to end, rather than
  attempt all 14 superficially. **The rest (items 2-14) are not done** —
  noted here so this entry can't be misread later as more complete than
  it is.

  **The race, as it actually was**: `Hub.lease()` ran a `SELECT` for a
  pending task the caller is eligible for, then an `UPDATE ... WHERE
  status='pending'` to claim it, then unconditionally returned that task
  to the caller — without ever checking the `UPDATE`'s own row count.
  Two callers racing the same task could both run their `UPDATE`; only
  one actually flips a row (the other's `WHERE status='pending'` no
  longer matches), but the code handed the same task back to *both*
  callers regardless of which one's write actually won.

  **Fix**: added `Store.claim_task()` (`probe/store.py`) — one atomic
  select-and-claim, wrapped in an explicit SQLite `BEGIN IMMEDIATE` /
  `COMMIT` / `ROLLBACK` (not relying solely on the existing in-process
  `threading.RLock`, which can't protect two separate OS processes
  sharing one db file), that only ever returns a task whose claiming
  `UPDATE` reported `rowcount == 1`. `Hub.lease()` now calls this instead
  of the old select-then-update pair. Needed switching `Store`'s
  connection to `isolation_level = None` (autocommit) so `claim_task`
  could issue its own `BEGIN IMMEDIATE` without fighting sqlite3's
  implicit transaction management — every other `Store` method's
  trailing `self._conn.commit()` becomes a harmless no-op under this,
  confirmed by the full suite still passing unchanged.

  **Added real fencing**: a `lease_token` column (`secrets.token_hex(12)`
  per successful claim) is now required on every `submit`/`fail` call
  and checked in `_held_task()` before either is allowed to mutate a
  task — "a stale worker must not be allowed to submit results after its
  lease expired and another worker reclaimed the task" from the
  request, verified by test (below), not assumed. Threaded `lease_token`
  through `probe/mesh/server.py`'s HTTP dispatch and
  `probe/mesh/worker.py`'s `Worker.run_once()` so the whole register →
  lease → run → submit/fail path actually carries it, not just
  `Hub`'s in-process API.

  **New tests** (`tests/test_mesh_concurrency.py`, real `threading` +
  `Barrier`/`ThreadPoolExecutor`, not sequential mocks): 8 workers racing
  one task (exactly one wins); 12 workers racing 4 tasks (all 4 claimed,
  none claimed twice); an expired lease reclaimed by a second agent under
  a fresh token; the original holder's now-stale token rejected on
  submit; a wrong token rejected on submit and on fail even from the
  correct agent; 40 threads hammering `Store.claim_task` directly below
  `Hub` with one pending task (exactly one winner, one token). Full
  suite: **468 passed, 4 skipped**, re-run 5x with no flakiness.

  **Explicitly not done, so the next pass knows where it left off**:
  items 2-14 of the request — configurable scope partitioning by worker
  count (`split_scope` still takes a manual `shard_size`, not derived
  from a worker-count argument), task-fingerprint deduplication, the
  concurrent/dependency-graph scheduler in
  `app/orchestrator/autonomous_loop.py`/`scheduler.py` (still selects and
  runs one candidate at a time), multi-worker-per-surface pools on the
  `app/` side, global/per-surface/per-agent concurrency and resource
  limits, subprocess cancellation/process-group kill on timeout,
  PostgreSQL as the shared authoritative store, the generic
  evidence-graph dependency model (agents still can't publish arbitrary
  dependent work beyond the existing binary-handoff special case), the
  `--probe-workers/--web-workers/...` one-command CLI, the remaining
  concurrency tests (web/network/binary and orchestrator-level), and the
  load/scaling demonstration across 1/2/4/8+ workers. None of this is
  claimed as done.

- **Entry 11** — Continued the same 14-item request with items 3 and 4
  (task-fingerprint deduplication, and turning the autonomous
  orchestrator into a genuine concurrent scheduler). Item 2 (configurable
  scope partitioning) is still not done.

  **Item 3 — deduplication, done at the reservation layer, not by
  inspection**: added `repository.try_reserve_task()`
  (`app/database/repository.py`) as the orchestrator-side equivalent of
  Probe's `Hub.lease()`/`claim_task()` fix from Entry 10. A naive
  "does `task_id` already exist -> reject" check would have been WRONG
  here and was caught before landing: `task_id` is a deterministic
  fingerprint of (assessment + agent/surface + target/service) but is
  *not* attempt-scoped, and the scheduler's own novelty logic
  legitimately re-selects the same candidate once new evidence justifies
  a fresh attempt (item 6 of the spec: "new evidence may create a
  legitimate new follow-up task"). So the real rule implemented is: a
  brand-new `task_id` reserves via a plain `INSERT` (the primary key is
  what the database serialises concurrent callers on — not a
  SELECT-then-INSERT); an existing `task_id` can only be *reclaimed* by
  an atomic `UPDATE ... WHERE status != 'running'` with its own rowcount
  checked, so a task someone else already has `RUNNING` can never be
  claimed twice, while a *finished* task's `task_id` can legitimately be
  reclaimed for a new attempt. Verified with real threads
  (`tests/test_task_reservation.py`): 20 threads racing one brand-new
  `task_id` (exactly one wins), 10 distinct `task_id`s racing
  independently (all win, no cross-contention), and 15 threads racing a
  reclaim of one finished `task_id` (exactly one wins) — run 3x, no
  flakiness.

  **Item 4 — a real concurrent scheduler, not a bigger for-loop**:
  `run_next_iteration()` used to select exactly one candidate and run it
  to completion before returning, so three independent eligible services
  could only ever be dispatched one iteration apart. Refactored
  `app/orchestrator/autonomous_loop.py`: extracted the
  reserve/dispatch/validate/persist body shared by both paths into
  `_execute_objective()`; `run_next_iteration()` now reserves via
  `try_reserve_task` before running (so it also benefits from the same
  dedup, for free); added `run_concurrent_iteration(..., max_inflight=4)`
  which ranks every eligible candidate
  (`scheduler.rank_candidates`, factored out of `select_next`'s own
  sort), atomically reserves up to `max_inflight` of the
  highest-ranked ones, then runs every one that was actually won
  **concurrently**, each in its own thread, each with its *own* fresh
  `ScopeGuard` (cheap, no I/O) rather than one shared across threads —
  so concurrent tool-invocation logging from different objectives is
  never interleaved onto the same audit log.

  **Verified it is actually concurrent, not merely correct**
  (`tests/test_concurrent_scheduler.py`, agent calls stubbed with a
  0.3s sleep so wall-clock timing can tell real parallel dispatch apart
  from a relabelled sequential loop): four independent candidates with
  `max_inflight=4` complete in ~0.3s total, not ~1.2s (asserted under a
  2x margin so it still fails hard on a regression to one-at-a-time);
  `max_inflight=2` runs exactly 2 of 4 candidates, and a second call
  picks up the other 2 without re-running the first pair; three
  overlapping `run_concurrent_iteration` calls fired from separate
  threads at once (simulating overlapping scheduler ticks) still execute
  each of four candidates exactly once — the agent stub's own call
  counter confirms 4 invocations, not more. Full suite: **476 passed,
  4 skipped**.

  **Item 2 — configurable scope partitioning by worker count, done
  right after this entry's items 3/4**: added
  `shard_size_for_workers(cidrs, worker_count)` (`probe/mesh/core.py`) --
  derives a shard address-count from the scope's own size and the
  worker count (`total_addresses // worker_count`, floored at 4), then
  hands that to the EXISTING `split_scope()` unchanged, which already
  rounds down to a power of two and produces an exact, disjoint,
  covering decomposition (nothing about that logic needed to change;
  only what size to ask it for). `Hub.plan()` gained a `worker_count`
  parameter alongside the existing `shard_size` (an explicit
  `shard_size` always wins; neither given keeps the historical
  default of 256 exactly as before); threaded through
  `probe/mesh/server.py`'s `/mesh/plan` dispatch. Verified
  (`tests/test_mesh_partitioning.py`, 17 tests) against the request's
  own worked examples: 2 workers on a `/24` -> exactly
  `10.20.30.0/25` + `10.20.30.128/25`; 4 workers -> exactly four `/26`s;
  8 workers -> eight `/27`s; a parametrised disjoint+exact-coverage
  check across worker counts 1/2/3/4/5/7/8/16/32 (every address in the
  original scope ends up in exactly one shard, every shard stays
  inside the authorised scope); a `/30` scope with 500 requested
  workers still yields at most 4 shards, never one job per address;
  an explicit `shard_size` overriding `worker_count` when both are
  given. Full suite: **493 passed, 4 skipped**.

  **Still not done**: items 5-14 (multi-worker pools actually dispatching
  through `probe/mesh/worker.py` at scale, resource limits, subprocess
  cancellation, PostgreSQL, the generic evidence-graph model, the
  `--probe-workers/--web-workers/...` one-command CLI, the remaining
  concurrency tests, and the load/scaling demonstration across
  1/2/4/8+ workers).

- **Entry 12** — Items 5 (multi-worker pools) and 6 (resource limits) of
  the concurrency request, plus a real, user-asked-for completeness check
  ("ghidra should not need to be downloaded each time, ship it with the
  main codebase") that was deliberately NOT done after weighing the
  tradeoff with the user: no Ghidra install exists on this machine right
  now (checked PATH, env vars, common install dirs -- nothing), and
  committing a ~1-1.5GB install into git permanently (GitHub blocks
  single files over 100MB without Git LFS) is a real, hard-to-reverse
  cost; asked, and the user said to skip it for now rather than vendor it.

  **Item 6 -- per-surface and per-target concurrency limits**: added
  `max_concurrent_web_tasks` / `max_concurrent_network_tasks` /
  `max_concurrent_binary_tasks` (`app/core/config.py`, defaults 3/3/2) --
  separate resource pools so one surface's own tool cost (Ghidra is the
  heaviest) can't starve the others out of the shared `max_inflight`
  budget. `run_concurrent_iteration`'s reservation loop now counts
  currently-RUNNING tasks per agent_id from the task ledger before
  deciding what to reserve, skipping a candidate whose surface is
  already at its cap (soft/best-effort under heavy cross-call
  concurrency -- documented honestly -- but the "never run the same
  candidate twice" guarantee is completely unaffected, since that is
  still try_reserve_task's own atomicity, not this count). Also added
  one-task-per-target-at-a-time: two candidates on the SAME asset_id are
  never both reserved together in one dispatch call.

  **A second real bug found and fixed while testing this, not assumed
  away**: proving the per-surface cap with a fast stub surfaced an
  actual race in Entry 11's own reservation design. Candidate
  generation takes a snapshot of task history at call-start; with a
  fast enough stub, one concurrent call could fully reserve, run, AND
  complete a candidate before a SECOND concurrent call -- reading its
  own, now-stale snapshot -- reached that same candidate, still
  believing it "unvisited." Because `try_reserve_task` would reclaim
  ANY non-RUNNING task_id, the second call's stale belief let it
  legitimately re-reserve and **re-execute** a candidate that had
  correctly finished moments earlier, under zero new evidence --
  reproduced directly by `test_concurrent_dispatch_never_runs_the_same_
  candidate_twice` going from 4 to 6 executions once the per-surface
  cap change made the timing more likely to trigger it. Fixed by adding
  `allow_reclaim` to `try_reserve_task` (default True, so direct callers/
  tests are unaffected): `autonomous_loop._reserve()` now only passes
  `allow_reclaim=True` when the candidate's own `next_attempt_count > 1`
  -- i.e., when `generate_candidates` itself already saw a prior,
  finished attempt and positively decided a retry is warranted, never
  merely because a caller's snapshot happens not to know about one.
  Re-run 4x after the fix, no recurrence.

  New/updated tests (`tests/test_concurrent_scheduler.py`):
  per-surface cap correctly limits a same-surface batch below
  `max_inflight`, and a later call picks up the rest once the capped
  tasks finish; two services on the same asset are never reserved
  together, and a later call picks up the second once the first
  finishes. Full suite: **496 passed, 4 skipped**.

  **Still not done**: item 5's remaining piece (separate Probe-side
  worker PROCESSES actually dispatching through `probe/mesh/worker.py`
  at scale -- today's per-surface caps govern the `app/` orchestrator's
  own in-process thread pool, not distinct OS-level worker processes),
  subprocess cancellation/process-group kill for Katana/nmap (item 7's
  remaining half), PostgreSQL verified end-to-end against a real server
  (item 8), the generic evidence-graph model, the multi-worker CLI, the
  remaining concurrency tests, and the load/scaling demonstration.

- **Entry 13** — Found and fixed a real scope-enforcement security bug while
  reviewing a live run's own 465-finding output, not by inspection: the Web
  Security Agent's ZAP stage had been dispatched against third-party internet
  domains (`cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `code.jquery.com`) that
  Katana's real crawl happened to reference — confirmed directly from that
  run's own `scope_guard` audit log (`op=target_check ... allowed=True` for
  those exact domains), not merely inferred from the findings.

  **Root cause**: `ScopeGuard.__init__` builds `_approved_asset_ids` with a
  deliberate fallback — "no explicit list" defaults to every known graph
  asset (minus held ones), never to "everything, including the unknown."
  `_approved_origins` had no such fallback: it was just
  `{normalise(o) for o in policy.approved_web_origins}`, an **empty set**
  when the policy left it unset. `check_web_target_in_scope`'s own check —
  `if self._approved_origins and origin not in self._approved_origins` —
  only enforces the restriction when the set is non-empty, so an empty set
  didn't mean "nothing is approved," it meant **the check was skipped
  entirely**. Any assessment created without explicitly populating
  `approved_web_origins` — including `app/orchestrator/__main__.py`'s own
  default policy, used by every real run so far this session — had *no* web
  scope enforcement at all.

  **Fix**: `ScopeGuard` now defaults `_approved_origins`, when left empty,
  to the origins of the graph's own web-shaped services (by name — http,
  https, http-alt, etc. — or well-known web port) belonging to approved
  assets — mirroring `_approved_asset_ids`'s existing shape of fallback,
  never "everything." Covers both URL conventions the codebase actually
  uses for a given asset (`asset_id` as host, per
  `autonomous_loop`'s own fingerprint/crawl dispatch; `asset.ip`/
  `asset.hostname`, per whatever a discovered binary/content reference
  itself reported) rather than assuming only one.

  **A second, independent bug this surfaced** (invisible exactly as long as
  the above check was a no-op): `app.orchestrator.scheduler._eligible()`'s
  own web-eligibility pre-check always probed `http://{asset_id}/` —
  implicitly port 80 — regardless of the service's real port, so a
  port-443/8080/etc. service's eligibility was checked against the *wrong*
  origin. Fixed with a new `_web_url_for()` that builds the same
  port-aware URL the real dispatch uses.

  **A third, independent bug this surfaced**: `app/orchestrator/nodes.py`
  referenced `ScopeViolationError` and `ToolExecutionError` in an
  `except (...)` clause without ever importing either — a bare `NameError`
  the instant a scope denial became reachable there for the first time
  (previously, nothing in that path could ever actually raise
  `ScopeViolationError`, since the check being guarded was a no-op). Fixed
  the missing import.

  **Tests** (`tests/test_scope_guard.py`): an empty `approved_web_origins`
  still denies the exact two real-world domains this run leaked to; the
  same empty policy still correctly allows the graph's own already-known
  web services (not an overcorrection to "deny everything"); an explicit,
  non-empty `approved_web_origins` still overrides the default exactly as
  before. Full suite: **499 passed, 4 skipped**, re-run twice clean.

- **Entry 16** — Diagnosed, precisely, why the automated pipeline could
  never have found the `.139:8833` "Game Zone" console/binary chain this
  session's manual investigation found by hand, then fixed each root
  cause generically (nothing here is specific to that one challenge).
  Three separate, compounding gaps, each confirmed against the real
  host, not assumed:

  1. **The service was never even connected to.** `run_network_
     vulnerability_agent`'s own pre-filter (`_CHECKED_SERVICE_NAMES`)
     skipped any service whose name/port wasn't on its small named-
     protocol allowlist *before* `assess_service` ever ran -- "no check
     implemented" silently meant "never even looked," not "looked and
     found nothing." Port 8833's banner (which literally says "the
     passkey lives inside a binary you had to find and reverse") was
     therefore never read by anything automated. Fixed with a new
     `check_unknown_service()` (`app/agents/network_vulnerability/
     checks.py`): the same bounded, read-only, single-recv banner grab
     every other check here already does, now the fallback for ANY
     service with no more specific check, reported as a `flagged`
     (not merely `observed`) info-severity finding so a human has
     something to act on instead of a silent gap. Verified against the
     real host: the finding's evidence now carries the real banner text
     verbatim.
  2. **The hidden vault was never found because nothing tried the
     header that gates it.** `content_discovery.py`'s own docstring was
     explicit that `extra_headers` must come from an already-recorded
     authorisation, never be invented -- correct for *arbitrary*
     headers, but this project had no generic mechanism at all for the
     well-known, real pentesting technique of testing whether access
     control trusts a client-controllable header (X-Forwarded-For and
     similar) rather than the real connection. Added
     `discover_via_trusted_proxy_headers()`: tries a small, generic
     header list against a small, generic value list (127.0.0.1,
     localhost, 0.0.0.0) PLUS one computed heuristic -- `<network>.1`,
     a near-universal default-gateway convention for a /24, derived
     from the asset's own IP, never hardcoded to one target. On the
     real host, this correctly found `X-Forwarded-For: <gateway>` as
     the winning header using ONLY that generic heuristic, with no
     knowledge of the specific answer. A hit becomes a `medium`-severity
     finding (`findings_from_access_control_bypass_hits`), and
     `web_security/agent.py`'s Stage E now automatically re-runs the
     same bounded content-discovery sweep under the winning header --
     which is what actually finds gated content, not just flags that
     something is gated.
  3. **Even gated, the binary was still invisible, because nothing
     followed a discovered directory to see what's in it.**
     `discover_hidden_paths` recorded a wordlist hit's status/redirect/
     length and stopped -- a 308 redirect (the normal shape of "this
     path is a real directory") was never actually followed, so a
     binary linked from that directory's own listing page was never
     seen. Added `_follow_listing_and_check_children()`: follows that
     ONE redirect, reads the listing, and applies the exact same
     binary-looking check already used for ordinary wordlist hits to
     every link that stays under the same directory (never a parent/
     nav link elsewhere on the site) -- bounded
     (`_MAX_LISTING_FOLLOW_UPS`), generic (works for any directory-
     listing format, not one application's).

  **Verified end to end against the real host** (not asserted from
  code reading): `discover_hidden_paths('http://<lab-host>/', ...,
  extra_headers={'X-Forwarded-For': '<lab-gateway>'})` now returns
  `binary_references=[BinaryReference(url='.../vault/keykeeper',
  content_type='application/octet-stream', ...)]` -- the exact binary
  this session's manual investigation found, now discovered by the
  pipeline itself with zero challenge-specific code. New
  `tests/test_access_control_bypass_pipeline.py` reproduces the whole
  chain against a local test server (not the real target) so it's
  verified every run: the bypass probe finds the gated header
  generically, a plain sweep with no header finds nothing (proving the
  gating is real), and the gated sweep finds the binary through the
  listing. New `tests/test_network_vulnerability_agent.py` cases cover
  `check_unknown_service`'s three outcomes (flagged/observed/error)
  directly, one of them using the real "Game Zone" banner text as its
  fixture. Full suite: **522 passed, 4 skipped**.

  **What is still NOT fixed, stated plainly**: recovering the actual
  passkey from the binary still needs full Ghidra analysis (the raw-
  string-only fallback cannot derive an XOR-keyed credential -- this
  session's own manual reversal used `objdump`/`readelf` by hand,
  outside the pipeline entirely, because Ghidra isn't installed in
  this environment); and completing the console's own multi-step
  protocol (AUTH -> WHOAMI -> compute a CRC -> PIDREQ) still has no
  automated agent at all -- `execute_authorised_credential_access`
  only ever makes ONE AUTH attempt and is never called automatically,
  by design. Both are real, separate gaps from the three fixed here.

- **Entry 17** — Ghidra and the console's multi-step protocol (the two gaps
  Entry 16 explicitly left open). Downloaded and extracted Ghidra 12.2
  (the latest release) locally; Java 17 was already present. Built a new,
  generic `app/agents/network_security/console_session_agent.py`:
  `run_llm_driven_console_session()` performs the same single AUTH attempt
  as `console_auth.attempt_single_credential_verification`, then — only on
  success — hands the growing transcript to an LLM each turn, asking for
  exactly one line to send next (or DONE), so the service's OWN documented
  protocol (its banner, its HELP output, whatever it says) drives what
  happens, rather than hardcoding one target's command sequence. Bounded by
  both a step count and a wall-clock budget regardless of what the model
  decides; the only side effect it can produce is "send this one line to
  the already-authenticated, already-scoped socket." A generic
  `WORD{...}`-shaped pattern match stops the loop early and records the
  extracted value.

  Wired into the orchestrator with the exact same explicit-approval gate as
  credential access: `execute_console_session()` in
  `app/orchestrator/nodes.py` mirrors `execute_authorised_credential_access`
  line for line — a BLOCKED `console_session` task transitions to RUNNING
  only on a recorded operator approval naming the credential_ref and
  target, retrieves the secret via `protected_storage.retrieve_secret`,
  and is never auto-dispatched by the scheduler. `ScopeGuard.check_console_auth_allowed`
  (`allow_single_credential_verification`) gates it exactly as before.

  Found and fixed a real bug in `_recv_all` while writing the first test
  against a local multi-step server: the original version kept blocking
  for the *full* read timeout on every call even after a complete response
  had already arrived, because nothing told it the peer was done sending —
  a 5-step session would have cost 5× the per-read timeout for no reason,
  and in one test it caused the SERVER side to time out and drop the
  connection mid-session before the client ever got to send its next line.
  Fixed by only waiting the full timeout for the first chunk of a response,
  then a short (0.2s) grace period for any trailing bytes already in flight.

  Added `openai==1.97.0` to `requirements.txt` (was already installed in
  this environment but undeclared). New
  `tests/test_console_session_agent.py` (5 tests, LLM calls monkeypatched —
  what's under test is the session-driving loop, bounds and deliverable
  extraction, not any model's behaviour): a full AUTH→WHOAMI→PIDREQ flag
  extraction against a local TCP server, early stop on DONE, the max_steps
  ceiling actually holding when a model never stops itself, the scope-guard
  denial firing before any socket opens, and an honest `connection_refused`
  outcome. Full suite (527 tests) passes.

  Not yet done: the orchestrator has not been re-run against the real lab
  network with this new chain wired up end to end — that is the explicit
  next step, now that both of Entry 16's open gaps are closed.

- **Entry 18** — Built an offline Mininet replica of the real `192.168.60.0/24`
  lab network (`scripts/mininet/`), so development and testing can continue
  without a connection to the real lab. All 171 hosts and 263 services come
  straight from a real discovery export (`network_graph.json`, from
  `ASSESSMENT-LIVE-REAL-003`); most get a generic banner-matching stand-in
  (`services/svc_runner.py`), while `192.168.60.139` gets dedicated,
  behaviourally faithful services (`vault_site.py`, `game_zone.py`) — the
  real recovered `/vault/keykeeper` binary, the real trusted-proxy-header
  gating, and the real recovered passkey (`R3v3rs3_Th3_Z0n3`) for `AUTH`.
  The `WHOAMI`/`PIDREQ` sequence past `AUTH` is an explicitly-labelled
  reconstruction, not a captured transcript, since this project never
  actually drove the real console that far.

  Found and worked around a real environment limit while building this:
  this WSL2 + Open vSwitch combination silently stops forwarding once a
  single bridge passes ~57 ports (56 works, 58 drops every packet with
  nothing in any log — confirmed by bisection, not assumed). Worked around
  by sharding the 171 hosts across multiple linked `OVSBridge` switches
  (45 per shard), verified with cross-shard host-to-host pings and a full
  171-host self-test.

  Verified end to end, not just by inspection: ran the real orchestrator
  (`python -m app.orchestrator run`) from inside the topology's own
  controller host, pointed at the exported graph — 1607 real iterations
  against the replica's live services in 1.5 minutes, zero crashes, the
  same scope-guard and scheduler code paths as the real live runs. The
  Python environment needed `SQLAlchemy` upgraded past the pinned
  `2.0.29` for Python 3.13 compatibility in that one dev environment —
  not a change to this project's own pinned dependencies.
