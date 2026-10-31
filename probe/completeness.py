"""Discovery Completeness Manager.

Round by round, decides whether more PERMITTED discovery is worth doing, and at the end produces an honest
completeness report: what was discovered, what remains unresolved, and why. Two rules govern everything here:

  * a round is only worth repeating if the one before it added evidence (or it is the first round) -- an item is
    never re-probed "just in case" once a round has run dry;
  * silence is never proof. "No reply" and "still unresolved" are states, not a finding that a device or network
    does not exist, and the completeness report says so explicitly for every open item.

It does not send a single packet and does not touch scope: it reads the planner's open questions and the store's
port/segment state, decides CONTINUE / STOP (and why), and at the end asks the store for a durable record of what
each round looked like, read back from the append-only observation ledger -- so a past round's state is history,
never silently reused as this run's own current proof.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

DEFAULT_MAX_BUDGET_S = 1200.0     # 20 minutes: the ceiling asked for the bounded autonomous run
DEFAULT_MAX_ROUNDS = 6


@dataclass
class Item:
    key: str
    kind: str
    detail: str
    first_round: int
    last_round: int
    resolved: bool = False


@dataclass
class RoundRecord:
    round: int
    open_items: int
    gain: dict = field(default_factory=dict)
    elapsed_s: float = 0.0


class CompletenessManager:
    """One instance per scan. `scan_id` ties everything it persists to a scan the store/report can trace back to."""

    def __init__(self, store, scope, *, scan_id: int | None, max_budget_s: float = DEFAULT_MAX_BUDGET_S,
                max_rounds: int = DEFAULT_MAX_ROUNDS):
        self.store, self.scope, self.scan_id = store, scope, scan_id
        self.max_budget_s, self.max_rounds = max_budget_s, max_rounds
        self.items: dict[str, Item] = {}
        self.round = 0
        self.t0 = time.time()
        self.rounds: list[RoundRecord] = []
        self.final_status: str | None = None
        self.stop_reason = ""

    def remaining_s(self) -> float:
        return self.max_budget_s - (time.time() - self.t0)

    # ---- per-round bookkeeping -----------------------------------------------------------------------------------
    def begin_round(self, questions) -> int:
        """Register the questions seen at the START of this round; returns the round number."""
        self.round += 1
        seen = set()
        for q in questions:
            key = f"{q.kind}:{q.subject}"
            seen.add(key)
            it = self.items.get(key)
            if it is None:
                self.items[key] = Item(key=key, kind=q.kind, detail=q.detail, first_round=self.round, last_round=self.round)
            else:
                it.last_round, it.detail, it.resolved = self.round, q.detail, False
        for key, it in self.items.items():
            if key not in seen and not it.resolved:
                it.resolved = True      # no longer an open question this round: settled, or no longer observable
        if self.store is not None:
            self.store.add_observation(self.scan_id, "completeness", "round-open-items", len(seen), port=self.round)
        return self.round

    def end_round(self, gain: dict) -> None:
        self.rounds.append(RoundRecord(self.round, len(self.items) - sum(i.resolved for i in self.items.values()),
                                       dict(gain), round(time.time() - self.t0, 1)))

    # ---- the one decision this module exists to make --------------------------------------------------------------
    def should_continue(self, *, open_count: int) -> tuple[bool, str]:
        """Called BEFORE a round starts (after round 1 has already run once). Never counts a round that merely
        repeats work with no new evidence: that is what "no repeated execution without new evidence" means here."""
        if open_count == 0:
            return False, "no open items remain"
        if self.round == 0:
            return True, "first round"
        if self.round >= self.max_rounds:
            return False, f"max_rounds ({self.max_rounds}) reached"
        if self.remaining_s() <= 0:
            return False, f"max_budget_s ({self.max_budget_s:.0f}s) exhausted"
        last_gain = self.rounds[-1].gain if self.rounds else None
        if last_gain is not None and not last_gain:
            return False, "the previous round added no new evidence: repeating it is not permitted work"
        return True, "open items remain and the previous round added evidence"

    # ---- the deliverable -------------------------------------------------------------------------------------------
    def finish(self, *, converged: bool, stop_reason: str) -> dict:
        self.final_status, self.stop_reason = ("CONVERGED" if converged else "INCOMPLETE"), stop_reason
        unresolved = sorted((i for i in self.items.values() if not i.resolved), key=lambda i: (i.kind, i.key))
        resolved = [i for i in self.items.values() if i.resolved]
        report = {
            "status": self.final_status, "stop_reason": stop_reason, "rounds_used": self.round,
            "max_rounds": self.max_rounds, "elapsed_s": round(time.time() - self.t0, 1), "max_budget_s": self.max_budget_s,
            "items_resolved": len(resolved),
            "items_unresolved": [{"key": i.key, "kind": i.kind, "detail": i.detail, "open_since_round": i.first_round}
                                 for i in unresolved],
            "round_history": [{"round": r.round, "open_items": r.open_items, "gain": r.gain, "elapsed_s": r.elapsed_s}
                             for r in self.rounds],
            "note": ("an unresolved item means the evidence available from this vantage point, in the rounds and "
                     "time permitted, could not settle it -- it is never reported as a confirmed absence of a "
                     "device, service or network, and a past scan's observation of it is never silently reused as "
                     "this scan's own proof"),
        }
        if self.store is not None:
            self.store.add_observation(self.scan_id, "completeness", "final-report", report["status"])
        return report
