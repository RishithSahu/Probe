# Implementation Audit

Baseline problems identified before the current implementation pass (spec: "Make Probe a Real, Functional
Vulnerability Assessment and Detection Platform"), recorded per that spec's own Section 2.7 requirement.
This is a snapshot at the time it was written — see `docs/PROGRESS.md` for the full, continuously-updated
history of what has since been fixed.

## 1. Repository did not import from a clean checkout (fixed this pass)

`app/database/repository.py` imported `app.database.vulnerability_lifecycle.ingest_verifier_result`, and
`app/analysis/protocol_verification.py` imported `app.agents.network_vulnerability.wire.verify_transcript`
— neither module had actually been committed to `origin/main`, breaking collection for every test file that
touched `repository.py` or `evidence_validator.py` (9-11 files, depending on which push). This happened
twice in quick succession from two different pushes. Both restored; see `docs/PROGRESS.md` Entries 14-15 for
the exact fix and what each module's real contract turned out to be from its call sites.

## 2. Synthetic fixtures are real and well-labelled, but reachable without an explicit opt-out

`web_agent_use_fixtures` / `binary_agent_use_fixtures` default to `True`. When a real tool (Katana, ZAP,
Ghidra) is unavailable, the agent code does fall back to a documented, clearly-labelled synthetic fixture
(`used_fixture=True` on every such result) rather than fabricating something unlabelled — this part of the
design was already sound. What was missing: nothing stopped a "live" run from silently being fixture-backed
the whole way through if nobody noticed the flags were still on. `app/core/execution_profile.py`
(`ExecutionProfile` / `preflight_check()`) already existed to close this (an explicit `live_assessment`
profile that refuses to start if fixtures are still enabled), but was only wired into the CLI entry point
(`app/orchestrator/__main__.py`), not the FastAPI entry point (`POST /assessments`) — fixed this pass (see
`docs/PROGRESS.md`).

## 3. approved_web_origins had no safe default (fixed this pass, see PROGRESS.md Entry 13)

`ScopeGuard._approved_origins` was an empty set, with no restriction enforced, whenever a policy didn't
explicitly populate `approved_web_origins` — including the CLI's own default policy, used by every real run
this session. Confirmed directly from a live run's own `scope_guard` audit log: the Web Security
Agent/ZAP were dispatched against third-party domains (`cdn.jsdelivr.net`, `cdnjs.cloudflare.com`,
`code.jquery.com`) that Katana's crawl happened to reference. Fixed by defaulting to the graph's own
web-shaped services instead of to "everything" — the same shape of fallback `_approved_asset_ids` already
had.

## 4. Network Vulnerability Detective: real, but narrow, read-only checks

`app/agents/network_vulnerability/checks.py` covers SSH (banner + protocol-1 detection), FTP (banner,
cleartext note, optional anonymous-login), Redis (unauthenticated PING), MySQL (handshake/version), and
PostgreSQL (startup/auth-method). Each is a single, short, real TCP exchange — not simulated. What it does
not yet do: SMB beyond raw reachability, TLS/cipher inspection, SSH algorithm negotiation, or any
version-to-CVE correlation. Services outside this explicit list are silently skipped by
`run_network_vulnerability_agent`'s own pre-filter rather than recorded with an explicit "unsupported"
outcome.

## 5. Web Security Agent: real tools, with a now-closed coverage gap

Katana crawling and ZAP passive/active scanning are both real (not fixture, when the tools are present and
configured) — verified directly against this session's real lab target. ZAP previously only ever scanned
the root URL, never Katana's own discovered endpoints (fixed in `docs/PROGRESS.md` Entry 9). Active scanning
is correctly gated behind an explicit policy flag. What remains missing relative to the new spec: no SQLi/
XSS/path-traversal/SSRF-specific active checks beyond ZAP's own active-scan policy, no CORS-misconfiguration
check, and no authenticated-testing support.

## 6. Binary Analysis Agent: real static analysis, Ghidra-dependent for anything beyond raw strings

`identify_binary`/`checksec`-style metadata and the raw printable-string fallback
(`app/agents/binary_analysis/raw_strings.py`) are real and dependency-free. Full decompiler-backed analysis
(unsafe-call-path tracing, the XOR-key-schedule credential-recovery logic in `credential_recovery.py`) needs
a real local Ghidra install, which is not present in this environment. Verified directly this session: a
real binary (`/vault/keykeeper` from the real lab target) was acquired and analysed; the raw-string fallback
correctly found no plaintext credential (because the real passkey is XOR-derived, not a plain string) and
reported the result honestly as `analysis_depth=strings_only` rather than fabricating a finding.

## 7. Orchestration: three execution paths, not fully unified

`app/orchestrator/graph.py` (LangGraph, FastAPI-triggered), `app/orchestrator/autonomous_loop.py`
(CLI-triggered, now with real atomic task reservation/fencing and a concurrent scheduler — see
`docs/PROGRESS.md` Entries 10-12), and the new `app/orchestrator/vulnerability_planner.py` /
`app/orchestrator/planner.py` contract (a pluggable `InvestigationPlanner`, not yet wired into
`autonomous_loop`'s own candidate generation, per the teammate's own commit notes) are three genuinely
separate code paths today, not one coherent process with three entry points into the same logic.

## 8. Reporting: findings exist, but coverage/limitations are not yet surfaced as a first-class section

`app/reporting/generator.py` already carries a used-fixture warning banner and an executive-summary caveat
when any fixture-backed tool contributed to a result (a real, working, existing control — not a gap). What
is missing relative to the new spec: an explicit per-asset/per-service "assessed / unsupported / blocked by
scope / tool unavailable" breakdown, separate from the finding list itself.
