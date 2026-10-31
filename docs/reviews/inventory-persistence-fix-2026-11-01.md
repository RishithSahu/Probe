# Inventory persistence fix — 2026-11-01

This is an independent pipeline fix. Claude's Ghidra integration, binary-agent
logic, credential handling, shared schemas, and orchestrator nodes were not
edited. No authentication, binary acquisition, or challenge discovery was
performed.

## Problem and resulting behaviour

Previously, `repository.store_network_graph` replaced the graph snapshot and
unconditionally inserted new asset/service rows. Importing the same inventory
twice produced two device rows and two service rows for the same logical IDs.
That made inventory counts unreliable and could make later finding joins
ambiguous. Ten regression cases failed before the correction.

The existing repository entry point now delegates to
`app/database/inventory.py`:

| Input | Result |
| --- | --- |
| Repeated snapshot | Update the same records; preserve database and logical IDs. |
| Richer observations | Fill or update observed metadata; an absent optional value does not erase a previous observation. |
| New device or service | Add a separate inventory record. |
| Partial snapshot | Retain earlier normalised inventory rows. `load_network_graph` still returns the latest snapshot, not an invented union of current targets. |
| Concurrent imports | Serialize writes before reading existing inventory; keep the union of observed inventory without duplicates. |
| Same IDs in another assessment | Keep the inventories separate. |
| Wrong scope, invalid identities, misplaced services | Reject the import. |
| Existing service ID reused for another device/endpoint, or endpoint silently renamed | Reject rather than changing what old evidence references mean. |
| Existing duplicate rows from earlier code | Stop with an explicit repair requirement; do not guess which historical rows to delete. |
| Later transaction failure | Roll back graph and inventory changes together. |

A no-op update locks the parent assessment for the caller's transaction before
reading inventory. SQLite serializes writers; PostgreSQL uses the assessment
row lock. The function does not commit on its own. The concurrency tests use
independent sessions and a temporary on-disk SQLite database.

The complete graph snapshot retains the source reference, held flags,
classification verdicts, and service metadata. The assessment's permission
policy is not changed. Storing a discovered address is not approval to scan it.

## Validation

The targeted regression command is:

```text
python -m pytest tests/test_inventory_persistence.py tests/test_repository.py tests/test_network_graph_adapter.py tests/test_evidence_validator.py tests/test_pipeline_integrity.py tests/test_reporting.py -q --tb=short
```

Result: **66 passed**, including **17 new inventory cases**. Ruff passed for
the inventory module, repository, and new tests. `git diff --check` passed.

The complete suite also passed: **398 passed in 36.68 seconds**. The run used
isolated temporary databases, reports, evidence, and Ghidra-project directories.
The existing fixture-based test profile was selected explicitly, with the
installed Ghidra and external tool integrations disabled for this test run.
This does not change application configuration or claim a real Ghidra analysis.

The restricted execution environment initially denied even loopback sockets
with Windows error 10013. The successful full run allowed the local test
servers and installed a test-process audit hook blocking non-loopback connects
and external hostname lookups while allowing numeric address parsing.
The hook applies to the pytest process, not its child processes; the suite's
CLI subprocess tests exercise preflight refusal and its fence subprocess tests
install their own guard. No challenge discovery or authentication was run.

The successful run's isolated directory is
`probe-data/inventory-suite-local-20261101-9e86bd07/`. Its
`validation-summary.json` records the result and hashes of the changed
implementation/test files.

## Boundaries and remaining work

- No live database was repaired or migrated. Pre-existing duplicates need a
  deliberate repair that preserves their evidence relationships.
- Database uniqueness constraints have not been added. Concurrent safety
  applies to imports through the repository entry point; direct ORM writes
  can bypass it.
- PostgreSQL execution has not been tested here. Its locking behaviour follows
  the database update transaction; only SQLite concurrency was exercised.
- The latest graph and cumulative inventory serve different purposes. There
  is no new deletion, expiry, last-seen policy, or graph-snapshot history.
- Record identity uses assessment plus supplied asset/service IDs. Changes to
  device identity or endpoint aliases need explicit reconciliation rather than
  automatic merging by IP or hostname.
- Task deduplication, claims, and resume still need dispatch integration in
  the orchestrator files currently being edited by Claude. Those files were
  intentionally left alone.
- This is not Ghidra validation and does not establish a recovered credential,
  service access, or permission for another network segment.
