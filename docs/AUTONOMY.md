# Autonomy audit: where a human used to decide, and what decides now

The requirement: given only an authorised scope, the probe inspects its own environment, chooses and coordinates its
techniques, adapts to what it sees, notices what is incomplete and goes after it with other methods, correlates and
de-duplicates, knows when it has hit the limit of its vantage point, and delivers an evidence-backed inventory and
topology report. The scope stays immutable throughout.

## Audit of the previous architecture

| # | Where a human or a hand-picked method was still needed | Fix |
|---|---|---|
| 1 | The pipeline was a fixed, hard-coded phase list; every phase ran whether or not it applied | Techniques are registered with an **applicability rule** (`Engine._register_techniques`); the planner (`probe/planner.py`) runs or skips each one and journals the reason |
| 2 | `--budget`, `--ports`, `--rate` were values a person had to choose | Derived from the inspected environment (`planner.inspect` / `derive_tuning`); a CLI value is only an *override* |
| 3 | Nothing inspected the environment (is the gateway in scope? is the scope on the scanner's link? is the link wider than the scope? is nmap there?) | `planner.Environment`, recorded in the report; techniques read it in their preconditions |
| 4 | Incomplete discovery was not recognised: one pass, then stop | `planner.open_questions` lists what the evidence leaves unsettled (UNRESOLVED/CONFLICT/SUSPECTED verdicts, layer-3-only hosts with no MAC, ARP responders never probed, silent addresses beside forwarders). `Engine._followups` runs up to 3 adaptive rounds choosing techniques that *answer those questions* |
| 5 | No notion of "more of this is pointless" | Every technique run is measured (`planner.knowledge` before/after = information gain). A repeat that gained nothing is not repeated; a round that gains nothing ends discovery |
| 6 | Inventory was keyed by IP: one machine with several addresses counted several times; a proxy-ARP gateway MAC looked like one device owning many addresses | `analysis/correlate.py`: devices keyed by the MAC that answered ARP, proxy/forwarder/catch-all MACs never merge addresses, layer-3-only addresses are never merged by guesswork, MAC conflicts are reported with the resolution used |
| 7 | No statement of what cannot be known | `analysis/limits.py`: every remaining open question, outside-scope network, held segment, leash stop, decoy, missing tool and unused protocol becomes a limit with *why* and *what would change it*. If the time budget ended the run, the report says it did **not** converge |
| 8 | Results were printed to a terminal and left in the DB | `report.py` writes `probe-data/report.json` + `report.md` (devices with their evidence, segments, topology edges, findings, conflicts, limits, decision journal, safety counters); also `GET /api/report` and `GET /api/decisions` |
| 9 | **Scope could grow**: `ScopeGuard.reload_approvals()` added approved CIDRs to the scope, callable at any time | `ScopeGuard.freeze()` is called at the end of construction. The scope is the CLI/config scope plus the approvals file read **once at start**; after that `reload_approvals()` raises. `hold()` can only restrict. Discovering a network (a segment, a leaked address, the interface's wider subnet) only records it and adds a limit; it can never add to the scope |

## What remains a person's decision, on purpose

* **The scope itself.** A person writes the authorised ranges; a new range means a new run.
* **Overrides** (`--budget`, `--ports`, `--rate`, `--max-hops`, `--allow-silent-hops`): optional; the default is autonomous.
* Anything a limit in the report names under *what would change it*.

## The loop

```
inspect environment -> derive settings -> (core techniques, each: applicable? run, measure gain, journal)
  -> infer -> pivot/verify/waves -> infer
  -> repeat up to 3x: open questions -> techniques that answer them -> measure -> infer   (stop on zero gain)
  -> service enrichment -> infer -> correlate -> limits -> report
```

No assessment phase exists: nothing here tests, exploits or scores weaknesses.
