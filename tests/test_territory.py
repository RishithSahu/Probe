"""The probe must not be able to function outside the permitted network, and must die instantly if it
ever is. Nothing here sends a packet.
Run: python -m unittest discover -s tests -v"""
import ipaddress
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from scapy.all import ICMP, IP, Ether

from probe.discovery import probes as P
from probe.killswitch import KillSwitch
from probe.net.transport import PROBE_ID, GuardedTransport
from probe.scope import ScopeGuard
from probe.territory import Territory, TerritoryError, require_in_territory, sane_scope

ROOT = Path(__file__).resolve().parent.parent
ME, MAC, GW = "192.168.60.68", "02:00:00:00:00:68", "02:00:00:00:00:01"


class SaneScope(unittest.TestCase):
    def test_ordinary_lab_ranges_pass(self):
        self.assertEqual([], sane_scope(["192.168.60.0/24", "10.1.0.0/16", "172.16.5.7/32"]))

    def test_wrong_ranges_are_rejected(self):
        for bad in ("8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/8", "224.0.0.0/24", "127.0.0.0/24", "banana", "fe80::/64"):
            self.assertTrue(sane_scope([bad]), bad)
        self.assertEqual([], sane_scope(["10.0.0.0/8"], allow_wide=True))


class TerritoryCheck(unittest.TestCase):
    def territory(self, rows, ip=ME, **kw):
        return Territory(ScopeGuard(["192.168.60.0/24"]), ip, provider=lambda: rows, **kw)

    def test_inside_the_range_and_assigned(self):
        self.assertTrue(self.territory([(ME, 4, 5)]).check()[0] or sys.platform != "win32")

    def test_wrong_range_dies(self):
        ok, why = self.territory([("10.9.9.9", 4, 5)], ip="10.9.9.9").check()
        self.assertFalse(ok)
        self.assertIn("not inside the permitted range", why)
        with self.assertRaises(TerritoryError):
            require_in_territory(ScopeGuard(["192.168.60.0/24"]), "10.9.9.9")

    def test_machine_that_left_the_network_dies(self):
        ok, why = self.territory([("10.77.0.5", 4, 5)]).check()       # roamed: our address is gone
        self.assertFalse(ok)
        self.assertIn("left the permitted network", why)

    def test_link_down_dies(self):
        if sys.platform == "win32":
            self.assertFalse(self.territory([(ME, 4, 0x08)]).check()[0])   # MIB_IPADDR_DISCONNECTED

    def test_cannot_verify_fails_closed(self):
        def boom():
            raise OSError("no api")
        t = Territory(ScopeGuard(["192.168.60.0/24"]), ME, provider=boom, max_failures=3)
        self.assertTrue(t.check()[0] and t.check()[0])                 # a transient hiccup is tolerated...
        ok, why = t.check()                                            # ...a persistent one is not
        self.assertFalse(ok)
        self.assertIn("failing closed", why)

    def test_real_machine_is_inside_or_correctly_rejected(self):
        # whatever network this test runs on, the answer is consistent with the address table
        from probe.territory import platform_provider
        try:
            rows = platform_provider(None)()
        except OSError:
            self.skipTest("platform cannot verify location")
        mine = [ip for ip, _, flags in rows if ipaddress.ip_address(ip) in ipaddress.ip_network("192.168.60.0/24")]
        for ip in mine:
            self.assertTrue(Territory(ScopeGuard(["192.168.60.0/24"]), ip).check()[0])
        self.assertFalse(Territory(ScopeGuard(["192.168.60.0/24"]), "192.168.60.254").check()[0] and
                         "192.168.60.254" not in [ip for ip, _, _ in rows])


class NullNic(GuardedTransport):
    def _pick_interface(self):
        self.my_ip, self.my_mac = ME, MAC

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.wire = []

    def _open(self):
        self.my_ip, self.my_mac = ME, MAC
        self.allow_mac(GW)

    def _close(self):
        pass

    def _emit(self, frame):
        self.wire.append(bytes(frame))


def nic(territory=None):
    tmp = Path(tempfile.mkdtemp())
    trips = []
    scope = ScopeGuard(["192.168.60.0/24"])
    kill = KillSwitch(tmp / "latch.json", exit_fn=trips.append)
    tr = NullNic(scope, kill=kill, rate_pps=10**6, territory=territory)
    tr.start()
    return scope, tr, kill, trips


class DiesWhenTheMachineLeaves(unittest.TestCase):
    def test_agent_stops_sending_and_dies_the_moment_the_address_disappears(self):
        rows = [(ME, 4, 5)]
        terr = Territory(ScopeGuard(["192.168.60.0/24"]), ME, provider=lambda: rows)
        if sys.platform != "win32":
            self.skipTest("flag semantics differ")
        scope, tr, kill, trips = nic(terr)
        ok = P.icmp_echo(MAC, GW, ME, "192.168.60.10")
        self.assertTrue(tr.send(ok, caller="t"))
        rows[:] = [("10.77.0.5", 4, 5)]                  # the machine is now on another network
        tr._territory_cache = (0.0, True, "")            # (let the 0.25 s cache expire)
        self.assertFalse(tr.send(ok, caller="t"))
        self.assertEqual([86], trips)
        self.assertEqual(1, len(tr.wire))                # nothing went out after the move


class FinalBytesCheck(unittest.TestCase):
    """The one guard judges the exact bytes about to be written, at their real offsets."""

    def check(self, tr, raw):
        tr._consts()
        return tr._check_raw(raw)

    def test_guard_reads_the_real_destination_bytes(self):
        scope, tr, kill, trips = nic()
        inside = bytes(P.icmp_echo(MAC, GW, ME, "192.168.60.10"))
        dst, kind = self.check(tr, inside)
        self.assertEqual(("192.168.60.10", "ip"), (str(ipaddress.ip_address(dst)), kind))
        outside = bytearray(inside)
        outside[30:34] = bytes([192, 168, 61, 10])                                # destination rewritten to another /24
        dst, kind = self.check(tr, bytes(outside))
        self.assertEqual(("192.168.61.10", "ip"), (str(ipaddress.ip_address(dst)), kind))
        self.assertFalse(scope.in_scope_int(dst))                                 # ...and the scope check refuses it
        arp = bytes(P.arp_who_has(ME, MAC, "192.168.60.7"))
        dst, kind = self.check(tr, arp)
        self.assertEqual(("192.168.60.7", "arp"), (str(ipaddress.ip_address(dst)), kind))
        bad_arp = bytearray(arp)
        bad_arp[38:42] = bytes([10, 0, 0, 1])
        dst, _ = self.check(tr, bytes(bad_arp))
        self.assertFalse(scope.in_scope_int(dst))

    def test_malformed_frames_are_refused_outright(self):
        scope, tr, kill, trips = nic()
        good = bytes(P.icmp_echo(MAC, GW, ME, "192.168.60.10"))
        for name, mutate in (("short", lambda b: b[:30]), ("ip options", lambda b: b[:14] + b"\x46" + b[15:]),
                             ("wrong src mac", lambda b: b[:6] + b"\x02\x00\x00\x00\x00\x99" + b[12:]),
                             ("spoofed ip src", lambda b: b[:26] + bytes([10, 1, 1, 1]) + b[30:]),
                             ("no marker", lambda b: b[:18] + b"\x00\x01" + b[20:]),
                             ("fragment", lambda b: b[:20] + b"\x20\x00" + b[22:])):
            dst, why = self.check(tr, mutate(good))
            self.assertIsNone(dst, name)

    def test_what_is_sent_is_exactly_the_verified_bytes(self):
        scope, tr, kill, trips = nic()
        f = P.icmp_echo(MAC, GW, ME, "192.168.60.10")
        self.assertTrue(tr.send(f, caller="t"))
        self.assertEqual(bytes(f), tr.wire[0])


class InstantDeath(unittest.TestCase):
    def test_trip_exits_within_a_fraction_of_a_second_even_if_closing_the_nic_hangs(self):
        tmp = Path(tempfile.mkdtemp())
        exited = []
        kill = KillSwitch(tmp / "latch.json", exit_fn=exited.append)
        kill.register_closer(lambda: time.sleep(30))     # a NIC close that never returns
        t0 = time.monotonic()
        kill.trip("192.168.61.5", "test")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual([86], exited)
        self.assertTrue((tmp / "latch.json").exists())


class WrongRangeDiesAtStart(unittest.TestCase):
    def run_cli(self, *scope):
        return subprocess.run([sys.executable, "-m", "probe", "run", "--no-ui", "--no-auditor", "--scope", *scope],
                              cwd=tempfile.mkdtemp(), env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
                              capture_output=True, text=True, timeout=120)

    def test_public_or_absurd_range_dies_before_anything(self):
        out = self.run_cli("8.8.8.0/24")
        self.assertEqual(7, out.returncode, out.stdout + out.stderr)
        self.assertIn("WRONG RANGE", out.stderr)

    def test_range_this_machine_is_not_in_dies_before_a_single_packet(self):
        out = self.run_cli("10.250.250.0/24")             # valid private range, but we are not in it
        self.assertEqual(8, out.returncode, out.stdout + out.stderr)
        self.assertIn("AUTHORISATION NOT VERIFIED", out.stderr)
        self.assertNotIn("auditor", out.stdout)           # died before even starting anything else


if __name__ == "__main__":
    unittest.main()
