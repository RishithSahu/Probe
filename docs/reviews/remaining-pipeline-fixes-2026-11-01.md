# Independent pipeline fixes and integration handoff — 2026-11-01

## What changed

These changes leave the binary-analysis modules, protected credential storage,
shared schemas/configuration/scope guard, and orchestrator graph/nodes/state
under concurrent development untouched. No challenge authentication, credential
verification, target crawl, or additional discovery was initiated.

| Gap | Implemented result | Boundary |
| --- | --- | --- |
| Dropped Probe evidence | Live API imports retain a content-addressed source envelope containing original hosts, segments, application-view state, report metadata, scope context and import limitations. The existing graph `raw_source_ref` survives persistence and points to the verified archive. | Metadata is evidence only. It grants no permission and schedules no replay. Typed application-view scheduling still needs shared-contract integration. |
| Mixed/stale imports | Compare scan identity/status before and after reads; reject a changing or running scan. Preserve a warning when scan identity/freshness is absent. | Separate API reads are not a server-side atomic snapshot. Hash verification establishes retained-byte integrity, not issuing-authority authenticity. |
| PTES branch omissions | Build the report mapping from every `AgentResult`, including discovered-binary handoffs and future result branches. Map acquisition, static analysis and content discovery. Mark legacy inferred operations explicitly. | Unknown operations remain visible. The older orchestrator state collector has not been edited. |
| Fictional phase completion | Keep failed attempts and actions explicitly denied/not run separate from successful activity counts. | Producer operation/result fields still need standardisation in the shared orchestration work. |
| Completion ambiguity | Report execution status, required-surface coverage, discovery convergence and evidence incompleteness separately. Missing/skipped/synthetic/truncated required work cannot establish complete coverage. | The existing database assessment-status policy is unchanged. A completed process can still have an incomplete report. |
| Missing PDF sections | Include device/service inventory, attack-path relationships, evidence index, coverage, PTES details and limitations. Escape untrusted text and retain literal text. Keep finding/relationship groups readable across pages and add page numbers. | Evidence index links to findings; full structured excerpts remain in JSON/artifacts. The layout sample is synthetic. |
| Overstated narrative | Remove boilerplate asserting every tool or PTES phase ran. Describe recorded policy separately from execution evidence. | A report does not prove independent egress enforcement for every worker. |
| Crawler scope after execution | Verify installed Katana advertises required controls, pass an anchored scheme/host/port scope and disable redirects before crawling. Unsupported controls stop the crawl. Bound concurrency and reject port zero. | Unit tests inspect subprocess arguments without launching Katana. Independent egress, DNS pinning and redirect boundary validation remain separate requirements. |
| Partial crawler failure | Retain partial output as an artifact and report a tool failure rather than successful crawling. Use unique, safe artifact filenames instead of raw asset IDs. | Task cancellation and subprocess-tree lifetime remain orchestration work. |
| Unjustified scores | Add an optional offline comparison command using supplied denominators and independent finding labels. Reject fixture/unspecified-integrity live scores; unknown labels/measurements remain null. | **No manifest is required for autonomous discovery or orchestration.** Without one, observed coverage, unresolved work and convergence remain the operational measures; total recall/false-positive rates are unknown. |

The Katana controls follow the [official CLI documentation](https://github.com/projectdiscovery/katana).
The installed tool's help is checked before use; advertised controls alone do
not establish independent packet-level enforcement.

## Files and contracts

- `app/adapters/discovery_snapshot.py`: immutable-content archive publication
  with SHA-256 checks and bounded reads. Atomic no-replace hard-link publication
  fixes concurrent Windows replacement failures; the temporary file and archive
  reside on the same filesystem.
- `app/adapters/network_graph_adapter.py` and `probe/client.py`: read-only
  source retention and freshness checks. Optional metadata endpoints can be
  unavailable; that limitation is retained rather than invented data.
- `app/analysis/ptes_mapper.py`: explicit phase mappings, inferred-operation
  audit, failed attempts and skipped activities.
- `app/reporting/completeness.py`, `pdf_sections.py`, `generator.py`, and
  templates: one consolidated report basis for JSON and PDF. The JSON adds
  `assessment_coverage` and `discovery_provenance`.
- `app/agents/web_security/crawler.py`: pre-crawl scope controls, capability
  checks, safe artifact naming, and explicit tool failure.
- `app/analysis/benchmark.py`: optional offline scorer. It is not imported by
  the discovery workflow and cannot dispatch work.
- `requirements.txt`: declares the PDF text-inspection test dependency.

## Validation

The focused regression set passes **102 tests**. New cases cover retained
metadata, archive replay/tampering/concurrent publication, changing scan identity,
coverage without findings, missing/synthetic/limited surfaces, all-branch PTES
mapping, failed actions, untrusted PDF text, origin/port isolation, missing
crawler controls, partial tool failure, and independently labelled scoring.
Ruff and `git diff --check` pass for the changed modules.

The all-tests invocation encountered repeated Windows access-violation
diagnostics while entering the new JPype/PyGhidra native analysis tests. That
invocation was stopped; it is **not** a completed full-suite pass. A follow-up
regression invocation explicitly excludes four native tests in
`tests/test_credential_recovery.py`. Their native branch remains under concurrent
development and has not been edited here.

Final wider result: **445 passed, 1 failed, 4 deselected in 40.50 seconds**.
The single failure is the generic-document check described below. The final
isolated run and machine-readable summary are under
`probe-data/pipeline-final-regression-20261101-f1b4bd7d/`.

The broader run also exposed the generic-code check flagging an environment
address in the newly added `docs/BINARY_ANALYSIS_REPORT.md`. That is a concurrently
authored report, so it is left untouched. Move environment-specific run evidence
under a review/run-artifact directory, or reconcile its placement with the
repository's generic-document rule in the owning change. Do not weaken the test
or replace actual evidence with a fabricated neutral address.

Test databases, temporary files, evidence and project directories are isolated.
Local test-server execution uses a pytest-process audit hook blocking external
hostname lookups and non-loopback connects. The hook is not inherited by child
processes; the existing child CLI/fence tests implement their own preflight or
guard checks. The legacy fixture test profile is not a live assessment profile.

The sample PDF `output/pdf/OFFLINE-REPORT-QA_report.pdf` was rendered and visually
checked. Its synthetic-data warning is explicit. It demonstrates layout, not
network discovery, credential recovery, or service access.

## Still open: shared integration and deployment validation

1. Durable claims, stable task identities, deduplication, stored results and
   restart/resume must be connected to actual dispatch. Existing status upserts
   alone do not prevent duplicate work.
2. Typed application/source metadata must become eligible task inputs through
   the shared contract. Retaining raw evidence is complete; automatically
   selecting additional permitted methods from it is separate work.
3. Cancellation must stop target actions and subprocess trees rather than just
   abandoning a worker thread. This requires a worker/guard/dispatch contract.
4. Reconcile database completion status with explicit required-work coverage,
   and standardise activity records at their producers.
5. Demonstrated access transitions need a distinct evidence contract, bound to
   assessment, scope, source, target, operation and proof. Confirmed weaknesses
   and recovered credential candidates never create such transitions here.
6. Independently enforce immutable egress/method scope across web, service,
   crawler, acquisition and other workers. The Nmap boundary does not establish
   that property for every process.
7. Complete native binary tests and a fixture-free end-to-end integration run
   after the concurrent changes stabilise. No authentication or scope expansion
   is required merely to validate these independent changes.

These items are not declared solved by adding report fields or an optional
scorer. The source archive preserves permission context without applying it;
new ranges still require exact evidence and separately recorded authorisation.

## Optional offline comparison

Use only when an independent truth/reference dataset is available:

```text
python -m app.analysis.benchmark --report path/to/report.json --truth path/to/ground-truth.json --output path/to/comparison.json
```

The truth JSON names the matching `assessment_id`, `scope_id`, `tier` (`recon`,
`breach`, or `deep`), an `authority_reference`, lists of exact host/service/
weakness IDs, and `adjudications` keyed by finding ID. An adjudication uses
`verdict` (`true_positive`, `false_positive`, or `unresolved`), optional
`weakness_id`, and `independently_verified`. Host/service denominators are the
supplied truth IDs; duplicate or unknown labels are rejected. No task, discovery
technique, credential, or authorised range is selected by this command.
