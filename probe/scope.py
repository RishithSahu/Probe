"""Hard scope enforcement for every probe this engine ever sends.

Every packet this codebase puts on the wire goes through GuardedTransport
(probe.net.transport), which asks a ScopeGuard about the packet's *actual*
destination fields (IP dst / ARP target) immediately before sending -- the
check is on the packet itself, not on what the caller claims it is doing.
There is no other way to reach the network from this codebase; that is by
design, not convention.

Two independent restrictions live here:

* scope   -- the owner-authorised ranges. Anything outside is a *stray*
             probe and is refused, counted and logged (scope-safety score:
             Good <= 1 stray, Great = none).
* hold    -- ranges inside (or learned alongside) the scope that the engine
             itself flagged as a separate segment. Classification probes were
             allowed to find it; once held, *no further* probes go there until
             the network owner approves it (probe approve <cidr>).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("probe.scope")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeViolation(Exception):
    """Raised when something tries to probe an address outside the authorized scope."""


@dataclass
class StrayProbe:
    target: str
    caller: str
    at: datetime


class ScopeGuard:
    """The single gatekeeper between the engine and the network.

    The scope is always supplied at runtime (CLI/config), never hard-coded, so
    the same engine works on whatever range it's pointed at.
    """

    def __init__(self, networks: Iterable[str], *, log_path: Path | None = None,
                 approvals_path: Path | None = None):
        parsed = [ipaddress.ip_network(str(n), strict=False) for n in networks]
        if not parsed:
            raise ValueError("ScopeGuard requires at least one authorized network/host")
        self._networks: list[IPNetwork] = parsed
        self._held: dict[IPNetwork, str] = {}
        self._lock = threading.RLock()
        self._stray: list[StrayProbe] = []
        self._held_blocked = 0
        self._log_path = log_path
        self._approvals_path = approvals_path
        self._approved: list[IPNetwork] = []
        self.stray_hook = None  # callable(ip, caller) -- the kill switch plugs in here
        self._ranges: list[tuple[int, int]] = []
        self._held_ranges: list[tuple[int, int]] = []
        self.reload_approvals()
        self._rebuild()

    # ---- scope -------------------------------------------------------
    @property
    def networks(self) -> list[IPNetwork]:
        with self._lock:
            return list(self._networks)

    def _rebuild(self) -> None:
        """Integer ranges for the packet hot path (thousands of checks per second)."""
        with self._lock:
            self._ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self._networks if n.version == 4]
            self._held_ranges = [(int(n.network_address), int(n.broadcast_address)) for n in self._held if n.version == 4]

    def in_scope_int(self, n: int) -> bool:
        for lo, hi in self._ranges:
            if lo <= n <= hi:
                return True
        return False

    def allow_int(self, n: int, *, caller: str = "", deep: bool = False) -> bool:
        """allow() for an IPv4 address already parsed to an int: no string work on the hot path."""
        for lo, hi in self._ranges:
            if lo <= n <= hi:
                if deep:
                    for hlo, hhi in self._held_ranges:
                        if hlo <= n <= hhi:
                            self._held_blocked += 1
                            return False
                return True
        self._record_stray(str(ipaddress.ip_address(n)), caller)
        return False

    def in_scope(self, ip: str) -> bool:
        """Pure check, no side effects -- does NOT count as a probe attempt."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self._lock:
            return any(addr in net for net in self._networks)

    def allow(self, ip: str, *, caller: str = "", deep: bool = False) -> bool:
        """Call immediately before every send. Out-of-scope -> stray, counted.
        deep=True marks enumeration beyond classification (port probes,
        fingerprinting); those are additionally refused for held segments."""
        if not self.in_scope(ip):
            self._record_stray(ip, caller)
            return False
        if deep and self.is_held(ip):
            with self._lock:
                self._held_blocked += 1
            return False
        return True

    def guard(self, ip: str, *, caller: str = "", deep: bool = False) -> None:
        if not self.allow(ip, caller=caller, deep=deep):
            raise ScopeViolation(f"{ip} is outside the authorized scope {self._networks}")

    def filter_in_scope(self, ips: Iterable[str], *, caller: str = "", deep: bool = False) -> list[str]:
        return [ip for ip in ips if self.allow(ip, caller=caller, deep=deep)]

    # ---- hold / approvals ---------------------------------------------
    def hold(self, cidr: str, reason: str = "") -> bool:
        net = ipaddress.ip_network(cidr, strict=False)
        with self._lock:
            if any(net.subnet_of(a) for a in self._approved if a.version == net.version):
                return False
            new = net not in self._held
            self._held[net] = reason
        self._rebuild()
        if new:
            logger.warning("HOLD %s -- no further probing until approved (%s)", net, reason)
        return new

    def is_held(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self._lock:
            return any(addr in net for net in self._held)

    @property
    def held(self) -> dict[str, str]:
        with self._lock:
            return {str(n): r for n, r in self._held.items()}

    def reload_approvals(self) -> None:
        """Approvals are the network owner's one-time permission: an approved CIDR is
        added to the scope and is never held. Written by `probe approve`."""
        if not self._approvals_path or not Path(self._approvals_path).exists():
            return
        try:
            data = json.loads(Path(self._approvals_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.exception("could not read approvals file")
            return
        with self._lock:
            for entry in data.get("approved", []):
                net = ipaddress.ip_network(entry["cidr"], strict=False)
                if net not in self._approved:
                    self._approved.append(net)
                if not any(net.subnet_of(n) for n in self._networks if n.version == net.version):
                    self._networks.append(net)
                self._held.pop(net, None)
        self._rebuild()

    @staticmethod
    def write_approval(path: Path, cidr: str, note: str = "") -> None:
        path = Path(path)
        data = {"approved": []}
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
        net = str(ipaddress.ip_network(cidr, strict=False))
        if not any(e["cidr"] == net for e in data["approved"]):
            data["approved"].append({"cidr": net, "note": note,
                                     "at": datetime.now(timezone.utc).isoformat()})
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ---- accounting ------------------------------------------------------
    def _record_stray(self, ip: str, caller: str) -> None:
        entry = StrayProbe(target=ip, caller=caller, at=datetime.now(timezone.utc))
        with self._lock:
            self._stray.append(entry)
        logger.warning("BLOCKED out-of-scope probe to %s (caller=%s)", ip, caller or "unknown")
        if self._log_path:
            try:
                with self._lock, open(self._log_path, "a", encoding="utf-8") as fh:
                    fh.write(f"{entry.at.isoformat()}\t{ip}\t{caller}\n")
            except OSError:  # pragma: no cover - logging must never crash the run
                logger.exception("failed to write stray-probe log entry")
        if self.stray_hook is not None:
            self.stray_hook(ip, caller)

    @property
    def stray_count(self) -> int:
        """Probes that were *attempted* out of scope and blocked. Nothing was
        ever sent for these -- see GuardedTransport.sent_out_of_scope."""
        return len(self._stray)

    @property
    def held_blocked(self) -> int:
        return self._held_blocked

    @property
    def stray_log(self) -> list[StrayProbe]:
        return list(self._stray)
