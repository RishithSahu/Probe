"""Tests for the two things that keep the dog inside the yard besides the transport guard:
the process fence (no other way to reach any network) and the leash (probes never travel
past a router not proven to be inside the scope). No packet is ever sent by these tests;
the one that installs the fence runs in a throw-away subprocess and only touches loopback names.
Run: python -m unittest discover -s tests -v"""
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

from probe import fence, selftest
from probe.discovery.ingest import Ingest
from probe.engine import LEAVES_SCOPE, UNEXPLORED_SILENT, Engine
from probe.scope import ScopeGuard
from probe.store import Store

ROOT = Path(__file__).resolve().parent.parent


class FencePolicy(unittest.TestCase):
    def test_only_loopback_sockets(self):
        self.assertIsNotNone(fence.check_event("socket.connect", (None, ("8.8.8.8", 53))))
        self.assertIsNotNone(fence.check_event("socket.connect", (None, ("192.168.60.5", 80))))   # even in-scope: use the transport
        self.assertIsNotNone(fence.check_event("socket.sendto", (None, ("10.0.0.1", 9))))
        self.assertIsNotNone(fence.check_event("socket.bind", (None, ("0.0.0.0", 8080))))
        self.assertIsNone(fence.check_event("socket.connect", (None, ("127.0.0.1", 8080))))
        self.assertIsNone(fence.check_event("socket.bind", (None, ("127.0.0.1", 8080))))
        self.assertIsNone(fence.check_event("socket.connect", (None, "/tmp/unix.sock")))

    def test_no_dns(self):
        self.assertIsNotNone(fence.check_event("socket.getaddrinfo", ("example.com", 443, 0, 0, 0)))
        self.assertIsNotNone(fence.check_event("socket.gethostbyname", ("example.com",)))
        self.assertIsNone(fence.check_event("socket.getaddrinfo", ("127.0.0.1", 8080, 0, 0, 0)))
        self.assertIsNone(fence.check_event("socket.getaddrinfo", ("localhost", 8080, 0, 0, 0)))

    def test_no_other_programs(self):
        for ev in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn"):
            self.assertIsNotNone(fence.check_event(ev, ("ping",)), ev)

    def test_unrelated_events_pass(self):
        self.assertIsNone(fence.check_event("open", ("x", "r", 0)))


class FenceInstalled(unittest.TestCase):
    """Install the real hook in a separate process (it can never be removed) and try to escape."""

    CODE = textwrap.dedent("""
        import socket, subprocess
        from probe import fence
        from probe.scope import ScopeViolation
        fence.install(None)
        def must_raise(label, fn):
            try:
                fn()
            except ScopeViolation:
                print("blocked:", label)
            else:
                print("ESCAPED:", label)
        must_raise("connect to a non-loopback address", lambda: socket.create_connection(("127.0.0.2", 9), timeout=0.1))
        must_raise("spawn a program", lambda: subprocess.run(["cmd", "/c", "echo", "x"]))
        from scapy.all import ICMP, IP, Ether, sendp, conf
        must_raise("scapy sendp", lambda: sendp(Ether() / IP(dst="192.0.2.1") / ICMP(), iface="no-such-iface0", verbose=0))
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); c = socket.create_connection(s.getsockname())
        print("loopback works")
    """)

    def test_cannot_escape_once_installed(self):
        out = subprocess.run([sys.executable, "-c", self.CODE], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertNotIn("ESCAPED", out.stdout + out.stderr, out.stdout + out.stderr)
        for label in ("connect to a non-loopback address", "spawn a program", "scapy sendp"):
            self.assertIn(f"blocked: {label}", out.stdout, out.stdout + out.stderr)
        self.assertIn("loopback works", out.stdout, out.stdout + out.stderr)


class Leash(unittest.TestCase):
    def engine(self, **kw):
        scope = ScopeGuard(["192.168.60.0/24"])
        eng = Engine(scope, Store(":memory:"), None, **kw)
        eng.ingest = Ingest(scope, eng.store, "192.168.60.68", "02:00:00:00:00:68")
        return eng

    def test_first_two_rungs_need_no_proof(self):
        eng = self.engine()
        self.assertTrue(eng._eligible("192.168.60.140", 1))
        self.assertTrue(eng._eligible("192.168.60.140", 2))      # router 1 is the in-scope next hop we chose

    def test_third_rung_needs_router_two_proven_inside(self):
        eng = self.engine()
        self.assertFalse(eng._eligible("192.168.60.140", 3))      # silent router 2: cannot prove what is beyond it
        self.assertEqual(UNEXPLORED_SILENT, eng._stopped["192.168.60.140"])
        eng.ingest.ev.hops["192.168.60.140"][2] = "192.168.60.2"
        self.assertTrue(eng._eligible("192.168.60.140", 3))

    def test_path_that_leaves_the_scope_is_closed(self):
        eng = self.engine()
        eng.ingest.ev.hops["192.168.60.200"][2] = "10.0.0.1"
        for ttl in (3, 4, 8):
            self.assertFalse(eng._eligible("192.168.60.200", ttl))
        self.assertEqual(LEAVES_SCOPE, eng._stopped["192.168.60.200"])

    def test_operator_may_tolerate_silent_hops_but_never_out_of_scope_ones(self):
        eng = self.engine(allow_silent_hops=1)
        self.assertTrue(eng._eligible("192.168.60.140", 3))       # one silent hop tolerated
        self.assertFalse(eng._eligible("192.168.60.140", 4))      # two are not
        eng.ingest.ev.hops["192.168.60.140"][2] = "172.16.0.1"
        self.assertFalse(eng._eligible("192.168.60.140", 3))

    def test_hard_cap_on_ttl(self):
        eng = self.engine(max_hops=4)
        eng.ingest.ev.hops["192.168.60.140"].update({2: "192.168.60.2", 3: "192.168.60.3", 4: "192.168.60.4"})
        self.assertTrue(eng._eligible("192.168.60.140", 4))
        self.assertFalse(eng._eligible("192.168.60.140", 5))


class GuardSelfTest(unittest.TestCase):
    def test_guard_is_sound_for_several_scopes(self):
        for scope in (["192.168.60.0/24"], ["192.168.60.0/24", "10.1.0.0/28"], ["172.16.5.7/32"]):
            self.assertEqual([], selftest.run(scope), scope)


if __name__ == "__main__":
    unittest.main()
