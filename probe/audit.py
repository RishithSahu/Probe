"""Independent egress auditor -- a separate OS process, not a library call.

Watches the wire (libpcap/Npcap) for frames leaving the scanner's MAC that carry
our probe markers (IP-ID 0x5052 / ARP target-hw 02:50:52:42:00:01). If it ever
sees one aimed outside the authorised scope it (1) records the violation,
(2) terminates the engine process itself, (3) exits non-zero. It shares no code
path with the discovery engine's decision-making, so a bug there cannot disable it.

While healthy it rewrites a heartbeat file every 0.5 s. The engine refuses to
send unless the heartbeat is fresh and violation-free (fail closed), so a dead,
missing or blocked auditor stops all probing.

  python -m probe.audit --iface <name> --mac <mac> --scope 10.20.30.0/24 --state probe-data --pid <engine pid>
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

PROBE_ID = 0x5052
PROBE_ID_B = PROBE_ID.to_bytes(2, "big")
ARP_MARK = "02:50:52:42:00:01"
ARP_MARK_B = bytes.fromhex(ARP_MARK.replace(":", ""))
# Two heartbeat files written alternately: a reader can always find one that is complete, and the writer never
# needs to rename over a file the engine has open (which raises PermissionError on Windows).
HEARTBEATS = ("audit-heartbeat.0.json", "audit-heartbeat.1.json")
VIOLATION = "audit-violation.json"
STALE_AFTER = 3.0


# Our probes carry more than the IP-ID marker: every one also has our L4 identity. Requiring both makes an accidental
# match with this machine's own traffic (a 16-bit IP-ID collision, ~1 per 65,536 foreign packets) practically impossible.
OUR_ICMP_IDS = {0x5001, 0x5003, 0x5004, 0x5010, 0x5011, 0x5012, 0x5020}
OUR_SPORTS = range(41000, 46000)
OUR_UDP_DPORTS = {40125, 53}


def inspect_frame(raw: bytes) -> tuple[str, int | None]:
    """('probe', dst_int) | ('arp-probe', dst_int) | ('collision', None) | ('other', None) -- judged from raw bytes."""
    if len(raw) < 34:
        return "other", None
    et = raw[12:14]
    if et == b"\x08\x06":
        if len(raw) >= 42 and raw[32:38] == ARP_MARK_B:
            return "arp-probe", int.from_bytes(raw[38:42], "big")
        return "other", None
    if et != b"\x08\x00" or raw[18:20] != PROBE_ID_B:
        return "other", None
    proto = raw[23]
    ok = False
    if proto == 1 and len(raw) >= 40:
        ok = raw[34] in (8, 13, 17) and int.from_bytes(raw[38:40], "big") in OUR_ICMP_IDS
    elif proto == 6 and len(raw) >= 48:
        ok = int.from_bytes(raw[34:36], "big") in OUR_SPORTS and raw[47] in (0x02, 0x10)
    elif proto == 17 and len(raw) >= 38:
        ok = int.from_bytes(raw[34:36], "big") in OUR_SPORTS and int.from_bytes(raw[36:38], "big") in OUR_UDP_DPORTS
    return ("probe", int.from_bytes(raw[30:34], "big")) if ok else ("collision", None)


class Attestation:
    """Engine-side reader of the auditor's heartbeat. A single unreadable moment is tolerated (the last good
    heartbeat is still fresh); a heartbeat older than STALE_AFTER seconds, a violation, or a missing
    auditor is not."""

    def __init__(self, state_dir: Path, *, scope_digest=None, run_id=None):
        self.dir = Path(state_dir)
        self._last: dict = {}
        self.scope_digest, self.run_id = scope_digest, run_id

    def _read(self) -> dict | None:
        best = None
        for _ in range(3):
            for name in HEARTBEATS:
                try:
                    hb = json.loads((self.dir / name).read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if best is None or hb["t"] > best["t"]:
                    best = hb
            if best:
                break
            time.sleep(0.02)
        if best:
            self._last = best
        return best

    def check(self) -> tuple[bool, str]:
        v = self.dir / VIOLATION
        if v.exists():
            return False, f"auditor recorded a violation ({v})"
        hb = self._read() or self._last
        if not hb:
            return False, "auditor heartbeat missing"
        if self.scope_digest is not None:
            if hb.get("scope_digest") != self.scope_digest or hb.get("run_id") != self.run_id:
                return False, "auditor attests a different run or scope"
            if not hb.get("capture_ready"):
                return False, "independent capture is not ready/alive"
            if not hb.get("helper_egress_verified"):
                return False, "independent helper egress is not verified"
        if time.time() - hb["t"] > STALE_AFTER:
            return False, "auditor heartbeat stale"
        if hb.get("violations", 0):
            return False, "auditor reports violations"
        return True, ""

    def wire_summary(self) -> dict:
        return self._read() or self._last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--scope", nargs="+", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--ip", help="the scanner's own address: it must stay inside the scope, on this interface")
    ap.add_argument("--ifindex", type=int, default=0)
    ap.add_argument("--iface-name", default=None)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--egress-policy", required=True)
    a = ap.parse_args(argv)

    from scapy.all import conf
    conf.verb = 0
    nets = [ipaddress.ip_network(s, strict=False) for s in a.scope]
    from .authorisation import scope_digest
    from . import egress
    digest = scope_digest(a.scope)
    policy = json.loads(Path(a.egress_policy).read_text(encoding="utf-8"))
    if policy["scope_digest"] != digest:
        raise ValueError("independent egress policy does not match auditor scope")
    mac, state = a.mac.lower(), Path(a.state)
    state.mkdir(exist_ok=True)
    (state / VIOLATION).unlink(missing_ok=True)
    counters = {"frames_from_scanner": 0, "tagged_probes": 0, "violations": 0, "id_collisions": 0}
    mac_b = bytes.fromhex(mac.replace(":", ""))
    stop_flag = {"stop": False}
    capture = {"ready": False, "error": None}

    ranges = [(int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == 4]

    def inside_int(n: int) -> bool:
        return any(lo <= n <= hi for lo, hi in ranges)

    def violation(dst: str, what: str, frame: bytes = b"") -> None:
        counters["violations"] += 1
        (state / VIOLATION).write_text(json.dumps({"at": time.time(), "dst": dst, "what": what,
                                                   "frame_hex": frame[:96].hex()}), encoding="utf-8")
        try:
            os.kill(a.pid, signal.SIGTERM)
        finally:
            os._exit(87)

    def on_raw(raw: bytes) -> None:
        """Judge the bytes on the wire directly (no dissection: this must keep up with a 2,500 pps sender)."""
        if len(raw) < 34 or raw[6:12] != mac_b:
            return
        counters["frames_from_scanner"] += 1
        kind, dst = inspect_frame(raw)
        if kind == "collision":                  # IP-ID matched by chance but no L4 identity of ours: foreign traffic
            counters["id_collisions"] += 1
            if counters["id_collisions"] <= 20:
                logging.info("ignored an IP-ID collision with foreign traffic: %s", raw[:48].hex())
            return
        if kind in ("probe", "arp-probe"):
            counters["tagged_probes"] += 1
            if not inside_int(dst):
                violation(".".join(map(str, dst.to_bytes(4, "big"))), f"tagged {kind}", raw)

    def sniff_loop() -> None:
        try:
            sock = conf.L2listen(iface=a.iface, filter=f"ether src {mac}")
            capture["ready"] = True
        except Exception as exc:
            capture["error"] = str(exc)
            return
        while stop_flag["stop"] is False:
            try:
                _cls, raw, _ts = sock.recv_raw(65535)
            except Exception as exc:
                logging.exception("capture error")
                capture["error"] = str(exc)
                capture["ready"] = False
                break
            if raw:
                on_raw(bytes(raw))
        sock.close()

    territory = None
    if a.ip:   # the engine checks this too; the auditor repeats it from outside the engine's process
        from .scope import ScopeGuard
        from .territory import Territory
        territory = Territory(ScopeGuard(a.scope), a.ip, if_index=a.ifindex or None, iface_name=a.iface_name)

    import logging
    logging.basicConfig(filename=str(state / "audit.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    sniffer = threading.Thread(target=sniff_loop, daemon=True)
    sniffer.start()
    n = 0
    try:
        while True:
            if not _pid_alive(a.pid):
                logging.info("engine process ended; auditor exiting")
                break
            if territory is not None:
                ok, why = territory.check()
                if not ok:
                    violation("<territory>", f"scanner left the permitted network: {why}")
            ok, why = egress.check(Path(a.egress_policy), expected=policy)
            if not ok:
                violation("<helper-egress>", "independent scope enforcement cannot be verified: " + why)
            if capture["error"] or not sniffer.is_alive():
                violation("<capture>", "independent capture failed: " + str(capture["error"]))
            try:                                      # a hiccup writing the heartbeat must never kill the auditor
                (state / HEARTBEATS[n % 2]).write_text(json.dumps({"t": time.time(), **counters,
                    "scope_digest": digest, "run_id": a.run_id, "auditor_pid": os.getpid(),
                    "capture_ready": capture["ready"] and sniffer.is_alive(), "helper_egress_verified": ok}), encoding="utf-8")
            except OSError as exc:
                logging.warning("heartbeat write failed (will retry): %s", exc)
            n += 1
            time.sleep(0.5)
    except Exception:
        logging.exception("auditor loop crashed")
        raise
    finally:
        stop_flag["stop"] = True
        for name in HEARTBEATS:
            (state / name).unlink(missing_ok=True)
    return 0


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        # NB: os.kill(pid, 0) would *terminate* the process on Windows (TerminateProcess), so never use it here.
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


if __name__ == "__main__":
    sys.exit(main())
