"""Unit tests for the safety layers only (scope guard, kill switch, approvals).
They use a transport whose NIC is a no-op that records frames -- it does not
imitate a network. Discovery itself is validated by running against the real
range. Run: python -m unittest discover -s tests -v"""
import tempfile
import unittest
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, Ether

from probe.killswitch import KillSwitch, TripwireLatched
from probe.discovery import probes as P
from probe.net.transport import PROBE_ID, GuardedTransport
from probe.scope import ScopeGuard

SCOPE = "192.168.60.0/24"
ME, MAC = "192.168.60.68", "02:00:00:00:00:68"


class NullNicTransport(GuardedTransport):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.wire: list = []

    def _open(self):
        self.my_ip, self.my_mac = ME, MAC
        self.allow_mac("02:00:00:00:00:10")

    def _close(self):
        pass

    def _emit(self, frame):
        raw = bytes(frame)
        self.wire.append(raw)
        self._rx(Ether(raw))  # feed our own egress back, as a sniffer with no BPF filter would


def make():
    tmp = Path(tempfile.mkdtemp())
    scope = ScopeGuard([SCOPE], approvals_path=tmp / "approvals.json")
    trips = []
    kill = KillSwitch(tmp / "latch.json", exit_fn=trips.append)
    tr = NullNicTransport(scope, kill=kill, rate_pps=10**6)
    tr.start()
    return scope, tr, kill, trips, tmp


def icmp_to(dst, mac="02:00:00:00:00:10", **ipkw):
    ipkw.setdefault("id", PROBE_ID)
    return Ether(src=MAC, dst=mac) / IP(src=ME, dst=dst, **ipkw) / ICMP(type=8)


class TransportGuard(unittest.TestCase):
    def test_in_scope_frame_is_sent(self):
        scope, tr, kill, trips, _ = make()
        self.assertTrue(tr.send(icmp_to("192.168.60.10"), caller="t"))
        self.assertEqual(1, len(tr.wire))
        self.assertEqual([], trips)

    def test_out_of_scope_trips_and_nothing_reaches_the_nic(self):
        scope, tr, kill, trips, tmp = make()
        self.assertFalse(tr.send(icmp_to("192.168.61.5"), caller="t"))
        self.assertEqual([86], trips)
        self.assertEqual([], tr.wire)
        self.assertTrue((tmp / "latch.json").exists())
        self.assertFalse(tr.send(icmp_to("192.168.60.10"), caller="t"), "after a trip even legal probes are refused")

    def test_guard_inspects_the_packet_not_the_caller(self):
        for bad in (
            P.arp_who_has(ME, MAC, "192.168.61.9"),
            icmp_to("192.168.60.10", mac="ff:ff:ff:ff:ff:ff"),     # broadcast MAC
            icmp_to("192.168.60.10", mac="02:00:00:00:00:99"),     # next hop never learned from in-scope ARP
            icmp_to("224.0.0.251"),
            Ether(src=MAC, dst="02:00:00:00:00:10") / IP(src=ME, dst="8.8.8.8", id=PROBE_ID) / TCP(dport=53, flags="S"),
            Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=MAC, psrc=ME, pdst="192.168.60.10", hwdst=P.ARP_MARK),
        ):
            scope, tr, kill, trips, _ = make()
            self.assertFalse(tr.send(bad, caller="t"), bad.summary())
            self.assertEqual([86], trips, bad.summary())
            self.assertEqual([], tr.wire, bad.summary())

    def test_egress_watchdog_catches_a_frame_that_bypassed_the_guard(self):
        scope, tr, kill, trips, _ = make()
        tr._emit(icmp_to("172.16.9.9", id=PROBE_ID))  # a code path that skipped send()
        self.assertEqual([86], trips)

    def test_independent_tally_of_what_was_emitted(self):
        scope, tr, kill, trips, _ = make()
        for i in range(10, 20):
            tr.send(icmp_to(f"192.168.60.{i}"), caller="t")
        self.assertEqual(10, len(tr.sent))
        self.assertEqual(0, tr.sent_out_of_scope)


class Latch(unittest.TestCase):
    def test_latch_blocks_restart_until_reset(self):
        tmp = Path(tempfile.mkdtemp()) / "latch.json"
        KillSwitch(tmp, exit_fn=lambda c: None).trip("1.2.3.4", "t")
        with self.assertRaises(TripwireLatched):
            KillSwitch(tmp).check_latch()
        self.assertTrue(KillSwitch.reset(tmp))
        KillSwitch(tmp).check_latch()


class HoldAndApproval(unittest.TestCase):
    def test_hold_blocks_deep_probes_only_until_approved(self):
        tmp = Path(tempfile.mkdtemp()) / "a.json"
        scope = ScopeGuard([SCOPE], approvals_path=tmp)
        scope.hold("192.168.60.128/26", "t")
        self.assertTrue(scope.allow("192.168.60.140"), "classification probes are still allowed")
        self.assertFalse(scope.allow("192.168.60.140", deep=True))
        self.assertEqual(0, scope.stray_count, "a held target is not a stray probe")
        ScopeGuard.write_approval(tmp, "192.168.60.128/26")
        scope.reload_approvals()
        self.assertTrue(scope.allow("192.168.60.140", deep=True))

    def test_out_of_scope_is_never_allowed(self):
        scope = ScopeGuard([SCOPE])
        for ip in ("192.168.59.255", "192.168.61.0", "10.0.0.1", "not-an-ip", "::1"):
            self.assertFalse(scope.in_scope(ip), ip)


if __name__ == "__main__":
    unittest.main()
