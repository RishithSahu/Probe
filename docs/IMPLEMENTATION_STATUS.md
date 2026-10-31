# Implementation Status — Audit Against the Master Engineering Specification

This audit compares the **existing, working, tested codebase** (built against
an earlier PRD, documented in `docs/PROGRESS.md`) against the newer Master
Engineering Specification (four-agent "Detective" naming, Container 1 /
Container 2 split, Shared Clue Board, Task Ledger, SSE dashboard, angr,
rabin2). Per that spec's own Part 2 instruction, this audit comes before any
rewrite. Classifications are honest, not optimistic — "a Python file exists"
does not count as COMPLETE.

## Summary classification

| Component (new spec naming) | Existing implementation | Classification | Required action |
|---|---|---|---|
| A. Network Probe | `probe/` (teammate's component, real, tested) — discovery, fence, kill switch, scope hold/approve, lightweight lead flagging | **COMPLETE** (as discovery) | Preserve as-is; see "Probe conflict" below for the naming/scope question |
| B. Web Detective | `app/agents/web_security/` — httpx fingerprint, Katana crawl, ZAP passive/active, findings | **PARTIALLY IMPLEMENTED** | Checks framework exists but lacks the new spec's explicit observation/potential/confirmed tiering as a first-class field per-check; no hidden-path wordlist module; no CORS/access-control check modules |
| C. Network Vulnerability Detective | `app/agents/network_vulnerability/` (SSH/Redis/MySQL/PostgreSQL/FTP real protocol checks + SMB reachability) + `app/adapters/external_network_agent.py` (ingestion contract for a deeper external scanner) + `app/adapters/probe_leads.py` | **PARTIALLY IMPLEMENTED** (updated — see `docs/PROGRESS.md`'s "New capability" section) | Core safe checks done and tested against real protocol wire formats; SMB is reachability-only (full dialect negotiation needs a dedicated library); no FTP/SMB/Redis/MySQL/PostgreSQL *credentialed* configuration checks (out of scope by design — no credential guessing) |
| D. Binary Detective | `app/agents/binary_analysis/` — file/readelf/checksec, Ghidra Headless, static weakness heuristics | **PARTIALLY IMPLEMENTED** | No `rabin2`, no angr, no isolated sandbox container (binary analysis runs in-process by default — this is my own prior review's finding #3, independently confirmed by this spec's Container 2 requirement) |
| LangGraph Manager | `app/orchestrator/` — 14-node graph, state, dispatcher | **PARTIALLY IMPLEMENTED** | Linear DAG with one fan-out/fan-in, not the spec's cyclic "check for eligible new tasks" routing; no checkpointing; no idempotent task claiming |
| Shared Clue Board | `app/database/` (SQLAlchemy models + repository) | **PARTIALLY IMPLEMENTED** | Covers assessments/assets/services/findings/evidence/agent_tasks/attack_paths/execution_logs; missing `web_endpoints`, `binaries` as a first-class queryable table with `binary_service_matches`, `loot_endpoints`, `safety_events` as distinct from `agent_execution_logs`, `reports` metadata table |
| Scope Guard | `app/core/scope_guard.py` | **COMPLETE** for what it covers | Already enforces per-operation permission + held-segment safety (see `docs/PROGRESS.md` bugs #6, #8); does not yet implement the spec's explicit container-firewall / egress-restriction layer (Part 4.3) — that lives in `probe/fence.py` + `enforce/nftables.nft` for Probe's own traffic only, not for the Web/Binary agents' traffic |
| Verification Gate | `app/analysis/evidence_validator.py` | **PARTIALLY IMPLEMENTED** | Has `suspected`/`confirmed`/`rejected` (3 states); spec wants `OBSERVED`/`POTENTIAL`/`REQUIRES_VERIFICATION`/`VERIFIED`/`REJECTED`/`INCONCLUSIVE` (6 states) — functionally the same *idea* (don't auto-confirm a scanner alert), coarser granularity |
| Attack-Path Correlation | `app/analysis/attack_paths.py` (NetworkX) | **COMPLETE** for the relationships it models | Has `HOSTS`/`EXPOSES`/`CONNECTS_TO`/`AFFECTED_BY`/`POTENTIAL_ACCESS_RELATION`/`VERIFIED_TRANSITION` — close to spec's `RUNS_SERVICE`/`EXPOSES_ENDPOINT`/`ASSOCIATED_WITH_BINARY`/`AFFECTED_BY`/`SUPPORTED_BY`/`CONNECTED_TO`; missing explicit `ASSOCIATED_WITH_BINARY`/web-endpoint nodes |
| PTES Mapping | `app/analysis/ptes_mapper.py` | **COMPLETE** | Already maps activities + findings to the 7 PTES phases from real tool-execution data, not guessed |
| Reporting (PDF + JSON) | `app/reporting/generator.py` (Jinja2 + ReportLab) | **PARTIALLY IMPLEMENTED** | Has executive summary, scope, methodology, findings, evidence, attack paths, PTES, limitations, and (new) a data-integrity warning section; missing a dedicated "asset inventory" section, a "tool execution summary" section, and a "potential findings appendix" separated from verified findings |
| FastAPI backend | `app/api/routes.py` | **PARTIALLY IMPLEMENTED** | Has create/get assessment, findings, agents, report, external-findings; missing `/start`, `/stop`, `/hosts`, `/services`, `/endpoints`, `/binaries`, `/attack-paths`, `/events`, pagination, auth |
| SSE dashboard | — | **NOT IMPLEMENTED** | Nothing exists; this is a genuinely new capability, not a rename |
| Docker deployment | `docker-compose.yml`, `Dockerfile.{orchestrator,web,binary}` | **PARTIALLY IMPLEMENTED** | Orchestrator + web-agent + binary-agent + zap exist and are verified (real `docker build && run`); no isolated, no-network, resource-limited binary sandbox container; no Postgres service (SQLite by default, documented trade-off) |
| Database: PostgreSQL authoritative | SQLite by default (`app/core/config.py`) | **INCORRECTLY IMPLEMENTED relative to this spec** | This spec explicitly wants PostgreSQL as "the authoritative shared assessment store." A deliberate earlier decision (this same project) made SQLite the default for a zero-external-service dev/demo deployment. PostgreSQL remains a one-line `APE_DATABASE_URL` swap — the code is DB-agnostic — but the *default* conflicts with this spec's explicit requirement |
| Task Ledger (idempotent claims) | Not implemented in `app/` (Probe has its own, for its own leads — see `docs/CONTRACT.md` §4) | **NOT IMPLEMENTED** | Already flagged as a gap in `docs/PROGRESS.md`'s "fundamental issues" #6 |

## The Probe conflict — read before changing anything here

The spec asks: *"If the existing Probe implementation conflicts with the new
Network Probe design, explain the conflict and propose a migration path
before removing or replacing working functionality."*

**There is no functional conflict.** `probe/` already *is* a working,
real, independently-tested "Network Probe" in this spec's sense: it
discovers hosts/ports/services, maintains a held/approved segment model,
and exposes that inventory over a documented HTTP API
(`docs/CONTRACT.md`). The only mismatch is **scope of responsibility**: the
spec's Network Probe (Part 7) explicitly does *not* decide whether a
service is vulnerable, while Probe's `leads()` feed does a small amount of
banner/title-based heuristic flagging (`vulnerable-app` leads) that blurs
slightly into "Network Vulnerability Detective" territory. This is minor —
those leads are already treated as `suspected`-only, low-confidence
signal in `app/adapters/probe_leads.py`, never auto-confirmed — but worth
naming precisely:

- **Keep Probe exactly as-is.** It is a teammate's working component with
  its own safety guarantees (fence, kill switch, audit process) that this
  side of the project must not modify.
- **Do not rename it** to "Network Probe" in code — it already fulfils that
  role; renaming would touch a component this project does not own, for a
  purely cosmetic reason.
- **The real gap is Network Vulnerability Detective (Part 9)**, which does
  not exist as a dedicated agent anywhere in this codebase. `probe_leads.py`
  is a thin translator for Probe's own lightweight signal, not a
  implementation of the spec's SSH/FTP/SMB/Redis/MySQL/PostgreSQL
  service-assessment modules. **This is the single largest implementation
  gap relative to this specification** and the first thing to build.

## Reconciliation decision (stated explicitly, not left implicit)

Given the scale of this specification (27 parts, a full container-split
re-architecture, new terminology for already-working components), a
line-by-line rename of working, tested code to match this spec's naming
("Clue Board", "Detective") would consume significant effort for zero
functional gain and risks introducing regressions into code that is
currently fully tested (180 passing tests, verified against real
containers and the teammate's real Probe code). The approach taken here:

1. **Keep existing naming and module layout** (`app/agents/web_security/`,
   not `app/agents/web_detective/`) — rename is cosmetic risk for no
   functional benefit, and the existing structure already satisfies this
   spec's actual architectural *principles* (separate modules, documented
   contracts, no agent touching another's internal state).
2. **Build the components that are genuinely missing**, in the priority
   order below, because they are not cosmetic — they are the items this
   audit classified NOT IMPLEMENTED or where a real security/functionality
   gap exists:
   - ~~Network Vulnerability Detective (new agent — the biggest gap)~~ **DONE** — see `docs/PROGRESS.md`
   - Binary sandbox isolation (Container 2) — independently confirmed by
     both this spec (Part 11) and this project's own prior architecture
     review (`docs/PROGRESS.md`, "fundamental issues" #3)
   - SSE event stream (Part 20) — genuinely new, not previously requested
   - Task ledger / idempotent claims (Part 6.5, 22.4)
3. **Treat the PostgreSQL-vs-SQLite default as a decision to confirm with
   you, not override unilaterally** — the code is already DB-agnostic
   (`APE_DATABASE_URL`), so this is a one-line config change whenever you
   want it, not a code change.

## Priority implementation order (adapted from this spec's Part 26, reflecting what already exists)

1. ~~Phase 1: Audit~~ — this document.
2. Phase 2 (partial — already have schemas/DB/repository): add the missing
   tables/fields the Network Vulnerability Detective and sandbox need.
3. **Network Vulnerability Detective** (new agent) — biggest gap, build next.
4. **Binary sandbox isolation** (Container 2) — security-critical, build next.
5. **SSE event stream** — new capability, moderate effort.
6. Task ledger / idempotent claims.
7. Remaining FastAPI routes (`/hosts`, `/services`, `/attack-paths`, `/events`, `/start`, `/stop`).
8. Report sections not yet present (asset inventory, tool execution summary, potential-findings appendix).

This document will be updated as each phase lands, alongside `docs/PROGRESS.md`.
