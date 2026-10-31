# Subsequent discovery architecture

Rules governing what happens to the inventory and to authorisation once a credential (or any other
artifact) has been recovered from a binary. These are architectural constraints, not suggestions — nothing
in this codebase is permitted to violate them automatically.

## 1. Existing inventory is preserved, never overwritten

`app/database/inventory.py::persist_network_graph` merges a newly loaded graph into the existing one by
`asset_id`; it does not delete or replace rows for assets that are not mentioned again. A rerun of discovery
adds to the record, it does not reset it.

## 2. Completed tasks are not repeated

Every unit of work — service assessment, web crawl, content discovery, binary acquisition and analysis — is
a row in the shared task ledger (`AgentTask`), keyed by a stable id derived from what the task is about
(e.g. `TASK-{agent}-discovered-{assessment_id}-{index}`, or, for authorised-access tasks,
`TASK-authorised_credential_access-{assessment_id}-{credential_ref}`). `upsert_agent_task` updates the
existing row for that id rather than creating a duplicate. A completed task is not re-run by a later pass
over the same inputs.

## 3. Newly discovered devices get their own inventory records

A device or service found as a *consequence* of analysis (e.g. a backend a recovered credential might let
someone reach) is never merged into the asset record that led to it. It would need its own `NetworkGraph`
asset, discovered and recorded the same way as anything else — through Probe, under its own scope — not
inferred from, or folded into, the existing record.

## 4. Provenance is preserved end-to-end

Every step in the chain — originating service → acquired binary → derived credential → (if ever
investigated) subsequent topology observation — keeps a link back to the step before it:

- A service is recorded with its `service_id` in the `NetworkGraph`.
- A binary reference names the `asset_id`/service context that led the Web Agent to report it
  (`content_discovery.BinaryReference`).
- An acquired binary's `AcquiredBinary.source_url` names the exact reference it came from.
- A recovered credential's `CredentialProvenance` (`app/core/protected_storage.py`) names the source
  binary's SHA-256, the function it was recovered from, the extraction method, and — if established — the
  associated service.
- The `authorised_credential_access` task links the credential ref back to all of the above.

Nothing in this chain is ever collapsed or summarised away; a report can always be traced back through it.

## 5. Discovering a credential never grants permission to use it

This is the rule the rest of the architecture exists to enforce. Recovering a credential creates:

- A `Finding` (category `recovered_credential`) describing *that* a credential was recovered, its
  confidence, and its limitations — never the value.
- A **separate**, `BLOCKED` task (`authorised_credential_access`) referencing the credential by its
  protected-storage id.

Nothing here authenticates with it, connects anywhere with it, or expands the authorised scope because of
it. A `BLOCKED` task does not become runnable on its own; only an explicit, separate approval (recorded the
same way Probe's own `approve`/method-grant mechanism records one) can change that, and even then the
approval is for a *named* action against a *named* target — never a blanket "now investigate everything this
might unlock."

The same rule already governs Probe's side of this project (`ScopeGuard.freeze()`, and the explicit
`pending`/`method_grants` records in `authorisations.json`): a *network* that discovery turns up is recorded
as a candidate, never auto-added to the authorised scope. This document extends the identical principle to
credentials recovered by binary analysis — discovery output is evidence, not authorisation, regardless of
which agent produced it.

## 6. Authenticated, read-only topology information (future)

If a separately authorised credential is later used (by a person, through the approval workflow above) to
read topology information from a service it unlocks, that information is still **discovery** output — it
must flow back through the same evidence model (a `NetworkGraph` asset/edge with its own provenance), not
be asserted directly as fact. "Authenticated" does not mean "unverified claims become confirmed."
