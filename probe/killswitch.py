"""Last-resort self-destruct for out-of-scope traffic.

Layered defence, innermost first:
  1. GuardedTransport refuses to emit any frame whose destination is outside
     the scope (the normal path -- the packet never leaves the process).
  2. If anything still *tries* (a guard hit) or an out-of-scope probe of ours is
     *seen on the wire* by the egress watchdog, this switch trips.

Tripping is irreversible for the process: it writes the incident/latch file, starts closing the
NIC in the background and terminates the process within ~150 ms (os._exit: no cleanup, no
waiting, nothing that could send anything). The latch file makes
the next start refuse to run until a human runs `probe reset-tripwire`.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

logger = logging.getLogger("probe.killswitch")

EXIT_CODE = 86


class TripwireLatched(RuntimeError):
    pass


class KillSwitch:
    def __init__(self, latch_path: Path, *, exit_fn: Callable[[int], None] = os._exit, enabled: bool = True):
        self.latch_path = Path(latch_path)
        self._exit = exit_fn
        self.enabled = enabled
        self._closers: list[Callable[[], None]] = []
        self._lock = threading.Lock()
        self.tripped = False
        self.reason: str | None = None

    def check_latch(self) -> None:
        if self.enabled and self.latch_path.exists():
            raise TripwireLatched(
                f"tripwire latched ({self.latch_path}): a previous run sent or attempted an out-of-scope "
                "probe. Inspect the file, then run `python -m probe reset-tripwire`.")

    def register_closer(self, fn: Callable[[], None]) -> None:
        self._closers.append(fn)

    def trip(self, target: str, caller: str = "", detail: str = "") -> None:
        with self._lock:
            if self.tripped:
                return
            self.tripped = True
            self.reason = f"out-of-scope probe to {target} (caller={caller or 'unknown'}) {detail}".strip()
        logger.critical("KILL SWITCH: %s", self.reason)
        if not self.enabled:
            return
        try:  # latch first: one tiny write, so a restart is refused even if everything below hangs
            self.latch_path.write_text(json.dumps({
                "tripped_at": datetime.now(timezone.utc).isoformat(), "target": target,
                "caller": caller, "detail": detail}, indent=2), encoding="utf-8")
        except OSError:
            pass
        # Closing the NIC is best effort and runs in the background: the process dies at once either way
        # (os._exit closes every handle), and nothing may delay the death.
        def _cut():
            for fn in self._closers:
                try:
                    fn()
                except Exception:
                    pass
        t = threading.Thread(target=_cut, daemon=True)
        t.start()
        t.join(0.15)
        self._exit(EXIT_CODE)

    @staticmethod
    def reset(latch_path: Path) -> bool:
        p = Path(latch_path)
        if p.exists():
            p.unlink()
            return True
        return False
