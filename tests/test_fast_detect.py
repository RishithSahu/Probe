"""Tests for the fast byte-level path, the new detection rules (TTL-decrement, forwarders, pivot sweep), the work
ledger other agents use, and the fence's one-program allowance. Nothing here sends a packet.
Run: python -m unittest discover -s tests -v"""
import ipaddress
import time
import unittest

from scapy.all import ICMP, IP, TCP, Ether

from probe import fence
from probe.analysis import classify as C
from probe.analysis import segments as S
from probe.discovery.ingest import Evidence, Ingest
from probe.discovery.rawprobes import FWD_SPORT, RawProbes, mac_bytes
from probe.net.transport import GuardedTransport
from probe.scope import ScopeGuard
from probe.service import ProbeService
from probe.store import Store
from probe.tools import nmap_tool

ME, MAC = "192.168.60.68", "02:00:00:00:00:68"
GW_MAC, H_MAC, H_IP = "dc:62:79:b7:33:7e", "94:b6:09:19:f4:51", "192.168.60.13"
SCOPE = [ipaddress.ip_network("192.168.60.0/24")]
BASE = (192 << 24) | (168 << 16) | (60 << 8)


class NullNic(GuardedTransport):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.wire = []

    def _open(self):
        pass

    def _close(self):
        pass

    def _emit(self, raw):
        self.wire.append(raw)


def nic():
    sc = ScopeGuard(["192.168.60.0/24"])
    tr = NullNic(sc, rate_pps=10**9)
    tr.my_ip, tr.my_mac = ME, MAC
    tr.allow_mac(GW_MAC)
    return sc, tr, RawProbes(MAC, ME)


class FastPath(unittest.TestCase):
    def test_every_raw_probe_type_passes_the_guard_and_matches_scapy(self):
        sc, tr, rp = nic()
        gw = mac_bytes(GW_MAC)
        frames = [rp.arp(BASE + 5), rp.echo(gw, BASE + 5), rp.echo(gw, BASE + 5, ttl=2), rp.timestamp(gw, BASE + 5),
                  rp.mask(gw, BASE + 5), rp.tcp_syn(gw, BASE + 5, 443), rp.tcp_syn(gw, BASE + 5, 80, ttl=2),
                  rp.tcp_ack(gw, BASE + 5, 80), rp.udp(gw, BASE + 5, 40125), rp.fwd_echo(gw, BASE + 5, 1, 3),
                  rp.fwd_tcp_ack(gw, BASE + 5, 80, 2, 4)]
        for f in frames:
            self.assertTrue(tr.send_raw(f, caller="t"), Ether(f).summary())
            Ether(f)                                                 # dissects cleanly
        self.assertEqual(len(frames), len(tr.wire))

    def test_raw_guard_refuses_out_of_scope_and_nothing_is_emitted(self):
        sc, tr, rp = nic()
        gw = mac_bytes(GW_MAC)
        for dst in (BASE - 1, BASE + 256, (10 << 24) + 1, (8 << 24) + 8):
            self.assertFalse(tr.send_raw(rp.tcp_syn(gw, dst, 443), caller="t"))
        self.assertEqual([], tr.wire)
        self.assertEqual(4, sc.stray_count)

    def test_guard_plus_builder_is_fast_enough_that_python_is_not_the_bottleneck(self):
        sc, tr, rp = nic()
        gw = mac_bytes(GW_MAC)
        t0 = time.perf_counter()
        for i in range(20000):
            tr.send_raw(rp.tcp_syn(gw, BASE + (i % 250) + 1, 443, idx=i), caller="t")
        pps = 20000 / (time.perf_counter() - t0)
        self.assertGreater(pps, 20000, f"only {pps:.0f} pps: the engine could no longer saturate a LAN")


def fwd_probe_reply(kind, via_ip=H_IP, via_mac=H_MAC, third="192.168.60.77", idx=7, ttl=1):
    """Build the reply a forwarder/pivot target would send, from the real probe bytes."""
    rp = RawProbes(MAC, ME)
    probe = rp.fwd_echo(mac_bytes(via_mac), (BASE + int(third.split(".")[-1])), ttl, idx)
    quoted = probe[14:14 + 28]
    if kind == "time-exceeded":
        return Ether(bytes(Ether(src=via_mac, dst=MAC) / IP(src=via_ip, dst=ME, ttl=64) / ICMP(type=11) / quoted))
    if kind == "echo-reply":
        return Ether(bytes(Ether(src=via_mac, dst=MAC) / IP(src=third, dst=ME, ttl=62) / ICMP(type=0, id=0x5020, seq=idx)))
    if kind == "tcp-rst":
        return Ether(bytes(Ether(src=via_mac, dst=MAC) / IP(src=third, dst=ME, ttl=62) /
                           TCP(sport=80, dport=FWD_SPORT + idx, flags="R")))


class ForwarderEvidence(unittest.TestCase):
    def ingest(self):
        scope = ScopeGuard(["192.168.60.0/24"])
        ing = Ingest(scope, Store(":memory:"), ME, MAC)
        ing.ev.arp_mac[H_IP] = H_MAC
        ing.ev.fwd_table[7] = ("192.168.60.77", H_IP, 1)
        return ing

    def test_time_exceeded_from_the_mac_we_addressed_proves_a_forwarder(self):
        ing = self.ingest()
        ing.handle(fwd_probe_reply("time-exceeded"))
        self.assertIn(H_IP, ing.ev.forwarders)

    def test_time_exceeded_from_some_other_mac_does_not(self):
        ing = self.ingest()
        ing.handle(fwd_probe_reply("time-exceeded", via_mac="aa:bb:cc:dd:ee:ff"))
        self.assertNotIn(H_IP, ing.ev.forwarders)

    def test_a_silent_address_answering_only_through_a_host_is_recorded_as_behind_it(self):
        ing = self.ingest()
        ing.ev.fwd_table[7] = ("192.168.60.77", H_IP, 2)
        ing.handle(fwd_probe_reply("echo-reply"))
        self.assertEqual({H_IP}, ing.ev.via["192.168.60.77"])
        ing2 = self.ingest()
        ing2.ev.fwd_table_tcp[7] = ("192.168.60.77", H_IP, 2)
        ing2.handle(fwd_probe_reply("tcp-rst"))
        self.assertEqual({H_IP}, ing2.ev.via["192.168.60.77"])

    def test_a_ttl1_answer_means_the_address_is_hosted_by_that_host(self):
        """TTL=1 packets are never forwarded: an answer proves delivery to the addressed host's own stack."""
        ing = self.ingest()
        ing.ev.fwd_table[7] = ("192.168.60.77", H_IP, 1)
        ing.handle(fwd_probe_reply("echo-reply"))
        self.assertEqual({H_IP}, ing.ev.hosted_by["192.168.60.77"])
        self.assertEqual({}, dict(ing.ev.via))

    def test_an_answer_from_an_address_we_did_not_ask_is_never_attributed(self):
        ing = self.ingest()
        ing.ev.fwd_table[7] = ("192.168.60.99", H_IP, 2)        # table says the probe was for .99, reply is from .77
        ing.handle(fwd_probe_reply("echo-reply"))
        self.assertEqual({}, dict(ing.ev.via))

    def test_bulk_flush_writes_hosts_and_ports(self):
        ing = self.ingest()
        ing.handle(Ether(bytes(Ether(src=H_MAC, dst=MAC) / IP(src=H_IP, dst=ME, ttl=63) /
                               TCP(sport=80, dport=42002, flags="SA"))))
        ing.flush()
        h = ing.store.hosts()[0]
        self.assertEqual(H_IP, h["ip"])
        self.assertEqual([80], [p["port"] for p in h["open_ports"]])


def local(ev, ip, mac, ttls=(64, 64)):
    ev.arp_mac[ip] = mac
    ev.mac_ips[mac].add(ip)
    ev.visible[ip].update({"arp", "icmp-echo"})
    ev.reply_mac[ip].add(mac)
    for t in ttls:
        ev.ttls[ip][t] += 1


def classify(ev, ips=None):
    return C.classify_all(list(ips or ev.visible), ev, gateway_mac=GW_MAC, gateway_ip="192.168.60.1")


class NewRules(unittest.TestCase):
    def test_r4_all_replies_one_hop_short_stops_arp_from_proving_onlink(self):
        """Found live: .13 and .139 answered ARP with unique MACs but every reply had TTL 63."""
        ev = Evidence()
        local(ev, H_IP, H_MAC, ttls=(63, 63, 63))
        c = classify(ev)[H_IP]
        self.assertEqual(C.SUSPECTED_SEPARATE, c.verdict)
        self.assertTrue(c.forwarding_anomaly)
        self.assertTrue(any(s.startswith("R4") for s in c.support))

    def test_mixed_ttls_are_wifi_hairpin_noise_not_an_anomaly(self):
        ev = Evidence()
        local(ev, "192.168.60.14", "02:aa:00:00:00:14", ttls=(64, 63, 64))
        self.assertEqual(C.CONFIRMED_ONLINK, classify(ev)["192.168.60.14"].verdict)

    def test_one_odd_reply_is_not_enough(self):
        ev = Evidence()
        local(ev, "192.168.60.15", "02:aa:00:00:00:15", ttls=(63,))
        self.assertEqual(C.CONFIRMED_ONLINK, classify(ev)["192.168.60.15"].verdict)

    def test_r5_an_address_that_answers_only_through_a_host_is_separate_and_behind_it(self):
        ev = Evidence()
        local(ev, H_IP, H_MAC)
        ev.forwarders[H_IP] = {"sender": H_IP, "third": "192.168.60.77"}
        s = "192.168.60.5"
        ev.visible[s].add("icmp-echo")
        ev.via[s].add(H_IP)
        ev.reply_mac[s].add(H_MAC)
        out = classify(ev)
        self.assertEqual(C.CONFIRMED_SEPARATE, out[s].verdict)
        self.assertEqual({1: H_IP}, out[s].path)
        self.assertIn("forwarder", out[H_IP].roles)
        self.assertEqual(C.CONFIRMED_ONLINK, out[H_IP].verdict)         # the forwarder itself is on our link

    def test_pivot_members_become_a_held_segment_behind_the_forwarder(self):
        ev = Evidence()
        local(ev, H_IP, H_MAC)
        local(ev, "192.168.60.20", "02:aa:00:00:00:20")
        ev.forwarders[H_IP] = {"sender": H_IP, "third": "x"}
        for n in (2, 3, 4):
            s = f"192.168.60.{n}"
            ev.visible[s].add("icmp-echo")
            ev.via[s].add(H_IP)
            ev.reply_mac[s].add(H_MAC)
        segs = [x for x in S.infer(classify(ev), ev, SCOPE, gateway_ip="192.168.60.1") if not x.local]
        self.assertEqual(1, len(segs))
        self.assertEqual({"192.168.60.2", "192.168.60.3", "192.168.60.4"}, set(segs[0].members))
        self.assertEqual(H_IP, segs[0].via)
        self.assertEqual("hidden", segs[0].hidden["level"])
        self.assertIn(H_IP, segs[0].hidden["reasons"][0])


class HostedAddress(unittest.TestCase):
    """Found live: 192.168.60.108 answered only a TTL=1 packet addressed to .25's MAC, replying from that MAC."""

    def ev_with_hidden(self, reply_mac=H_MAC, direct=False, check=None):
        ev = Evidence()
        local(ev, H_IP, H_MAC)
        s = "192.168.60.108"
        ev.visible[s].add("icmp-echo")
        ev.hosted_by[s].add(H_IP)
        ev.reply_mac[s].add(reply_mac)
        ev.ttls[s][32] += 1
        if direct:
            ev.visible_direct.add(s)
        if check:
            ev.hidden_checks[s] = check
        return ev, s

    def test_r7_a_hidden_address_hosted_inside_a_neighbour(self):
        ev, s = self.ev_with_hidden()
        out = classify(ev)
        self.assertEqual(C.CONFIRMED_SEPARATE, out[s].verdict)
        self.assertTrue(out[s].proof[0].startswith("R7"))
        self.assertEqual({1: H_IP}, out[s].path)
        self.assertIn("fronts-hidden-network", out[H_IP].roles)

    def test_if_it_also_answers_directly_it_is_not_hidden_at_all(self):
        ev, s = self.ev_with_hidden(direct=True)
        self.assertNotEqual(C.CONFIRMED_SEPARATE, classify(ev)[s].verdict)

    def test_a_reply_from_its_own_mac_is_a_hairpin_not_a_hosted_address(self):
        ev, s = self.ev_with_hidden(reply_mac="aa:bb:cc:00:00:01")
        self.assertNotEqual(C.CONFIRMED_SEPARATE, classify(ev)[s].verdict)

    def test_a_failed_verification_withdraws_the_claim(self):
        ev, s = self.ev_with_hidden(check={"confirmed": False, "summary": "control host answered too"})
        self.assertNotEqual(C.CONFIRMED_SEPARATE, classify(ev)[s].verdict)

    def test_a_passed_verification_is_quoted_in_the_proof(self):
        ev, s = self.ev_with_hidden(check={"confirmed": True, "summary": "5/5 TTL=1 answers, 0/6 controls"})
        self.assertIn("5/5 TTL=1 answers", classify(ev)[s].proof[0])

    def test_the_segment_is_reported_hidden_and_via_the_neighbour(self):
        ev, s = self.ev_with_hidden()
        local(ev, "192.168.60.20", "02:aa:00:00:00:20")
        seg = [x for x in S.infer(classify(ev), ev, SCOPE, gateway_ip="192.168.60.1") if not x.local][0]
        self.assertEqual(["192.168.60.108"], seg.members)
        self.assertEqual("hidden", seg.hidden["level"])
        self.assertEqual(H_IP, seg.via)


class CatchAll(unittest.TestCase):
    """Found live: .25 answered a TTL=1 echo for ~50 addresses, including real laptops'. That is a catch-all
    responder, not 50 hidden hosts. The control is: does it also answer for an address that belongs to someone else?"""

    def ingest(self):
        scope = ScopeGuard(["192.168.60.0/24"])
        ing = Ingest(scope, Store(":memory:"), ME, MAC)
        ing.ev.arp_mac[H_IP] = H_MAC
        ing.ev.arp_mac["192.168.60.20"] = "02:aa:00:00:00:20"          # a real, different device
        return ing

    def reply_for(self, third, idx):
        return Ether(bytes(Ether(src=H_MAC, dst=MAC) / IP(src=third, dst=ME, ttl=32) / ICMP(type=0, id=0x5020, seq=idx)))

    def test_answering_for_another_devices_address_marks_a_catch_all(self):
        ing = self.ingest()
        ing.ev.fwd_table[1] = ("192.168.60.20", H_IP, 1)
        ing.handle(self.reply_for("192.168.60.20", 1))
        self.assertIn(H_IP, ing.ev.catchall)

    def test_answers_for_silent_addresses_alone_do_not(self):
        ing = self.ingest()
        ing.ev.fwd_table[1] = ("192.168.60.77", H_IP, 1)
        ing.handle(self.reply_for("192.168.60.77", 1))
        self.assertNotIn(H_IP, ing.ev.catchall)

    def test_catch_all_answers_never_become_hosts_in_the_inventory(self):
        ing = self.ingest()
        for i, s in enumerate(("192.168.60.77", "192.168.60.78", "192.168.60.20")):
            ing.ev.fwd_table[i] = (s, H_IP, 1)
            ing.handle(self.reply_for(s, i))
        ing.promote_fwd()
        self.assertNotIn("192.168.60.77", ing.ev.visible)
        self.assertNotIn("192.168.60.78", ing.ev.visible)

    def test_a_non_catch_all_front_still_promotes_its_hosted_address(self):
        ing = self.ingest()
        ing.ev.fwd_table[1] = ("192.168.60.77", H_IP, 1)
        ing.handle(self.reply_for("192.168.60.77", 1))
        ing.promote_fwd()
        self.assertIn("192.168.60.77", ing.ev.visible)

    def test_a_promotion_made_before_the_catch_all_was_recognised_is_withdrawn(self):
        ing = self.ingest()
        ing.ev.fwd_table[1] = ("192.168.60.77", H_IP, 1)
        ing.handle(self.reply_for("192.168.60.77", 1))
        ing.promote_fwd()
        self.assertIn("192.168.60.77", ing.ev.visible)                    # promoted: nothing said otherwise yet
        ing.ev.fwd_table[2] = ("192.168.60.20", H_IP, 1)
        ing.handle(self.reply_for("192.168.60.20", 2))                    # the control answers: it IS a catch-all
        ing.promote_fwd()
        self.assertNotIn("192.168.60.77", ing.ev.visible)                 # ...so the earlier guess is demoted again
        self.assertEqual([], [h["ip"] for h in ing.store.hosts() if h["ip"] == "192.168.60.77"])

    def test_classification_ignores_a_catch_all_front_and_flags_the_catch_all(self):
        ev = Evidence()
        local(ev, H_IP, H_MAC)
        ev.catchall.add(H_IP)
        s = "192.168.60.77"
        ev.visible[s].add("icmp-echo")
        ev.hosted_by[s].add(H_IP)
        ev.reply_mac[s].add(H_MAC)
        out = classify(ev)
        self.assertNotEqual(C.CONFIRMED_SEPARATE, out[s].verdict)
        self.assertIn("catch-all-responder", out[H_IP].roles)


class Ledger(unittest.TestCase):
    def test_no_work_is_done_twice(self):
        s = ProbeService(Store(":memory:"), ScopeGuard(["192.168.60.0/24"]))
        key = "web-crawl:192.168.60.13:80"
        self.assertTrue(s.claim(key, "web-agent")["granted"])
        r = s.claim(key, "other-agent")
        self.assertFalse(r["granted"])
        self.assertEqual("claimed", r["status"])
        self.assertTrue(s.claim(key, "web-agent")["granted"])                  # the owner may renew
        self.assertFalse(s.complete(key, "other-agent")["ok"])                 # only the owner can finish it
        self.assertTrue(s.complete(key, "web-agent", {"findings": 3})["ok"])
        again = s.claim(key, "other-agent")
        self.assertFalse(again["granted"])
        self.assertEqual({"findings": 3}, again["result"])                     # ...and the result is reused
        self.assertEqual("work.done", s.events()["events"][-1]["type"])

    def test_an_expired_claim_can_be_taken_over(self):
        s = ProbeService(Store(":memory:"))
        self.assertTrue(s.claim("k", "a", ttl_s=0.01)["granted"])
        time.sleep(0.05)
        self.assertTrue(s.claim("k", "b")["granted"])

    def test_web_targets_and_scope_check(self):
        store = Store(":memory:")
        scope = ScopeGuard(["192.168.60.0/24"])
        store.bulk_upsert_hosts([{"ip": "192.168.60.13", "mac": "aa", "ttl": 63, "mask": None, "seen_macs": set(),
                                  "methods": {"arp"}, "first": "t", "last": "t"}])
        store.bulk_add_ports([("192.168.60.13", 80), ("192.168.60.13", 3306)])
        store.upsert_service("192.168.60.13", 80, service="http", product="nginx")
        svc = ProbeService(store, scope)
        self.assertEqual(["http://192.168.60.13:80/"], [t["url"] for t in svc.web_targets()])
        scope.hold("192.168.60.128/26", "t")
        self.assertTrue(svc.check_scope("192.168.60.10")["allowed"])
        self.assertFalse(svc.check_scope("192.168.60.140")["allowed"])
        self.assertFalse(svc.check_scope("10.0.0.1")["allowed"])

    def test_inventory_reset_keeps_the_shared_ledger(self):
        store = Store(":memory:")
        store.claim("k", "a")
        store.add_event("x", {})
        store.reset()
        self.assertEqual(1, len(store.claims()))
        self.assertEqual(1, len(store.events_since(0)))


class FenceAllowsOnlyNmap(unittest.TestCase):
    def test_a_sanctioned_program_runs_only_inside_tool_context(self):
        fence.allow_program(r"C:\Tools\nmap.exe")
        popen = ("C:\\Tools\\nmap.exe", ["nmap", "-sT"], None, None)
        self.assertIsNotNone(fence.check_event("subprocess.Popen", popen))          # outside the context: refused
        with fence.tool_context():
            self.assertIsNone(fence.check_event("subprocess.Popen", popen))
            self.assertIsNotNone(fence.check_event("subprocess.Popen", ("ping", ["ping", "8.8.8.8"], None, None)))
            self.assertIsNotNone(fence.check_event("os.system", ("ping",)))
        self.assertIsNotNone(fence.check_event("subprocess.Popen", popen))


class NmapParsing(unittest.TestCase):
    XML = ('<?xml version="1.0"?><nmaprun><host><address addr="192.168.60.13" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/>'
           '<script id="http-headers" output="Location: http://10.55.0.7/admin"/></port>'
           '<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>')

    def test_open_ports_only_and_service_fields(self):
        recs = nmap_tool.parse_xml(self.XML)
        self.assertEqual([("192.168.60.13", 80, "http", "nginx")], [(r["ip"], r["port"], r["service"], r["product"]) for r in recs])

    def test_internal_addresses_in_banners_are_reported_as_outside_scope_leaks(self):
        recs = nmap_tool.parse_xml(self.XML)
        leaks = nmap_tool.find_leaks(recs, ScopeGuard(["192.168.60.0/24"]), ME)
        self.assertEqual(["10.55.0.7"], list(leaks))

    def test_a_truncated_document_still_yields_complete_hosts(self):
        self.assertEqual(1, len(nmap_tool.parse_xml(self.XML[:-10])))

    def test_held_and_out_of_scope_targets_are_never_handed_to_nmap(self):
        scope = ScopeGuard(["192.168.60.0/24"])
        scope.hold("192.168.60.128/26", "t")
        res = nmap_tool.enrich.__wrapped__(scope, {}) if hasattr(nmap_tool.enrich, "__wrapped__") else None
        ok = {ip for ip in ("192.168.60.13", "192.168.60.140") if scope.allow(ip, caller="t", deep=True)}
        self.assertEqual({"192.168.60.13"}, ok)


if __name__ == "__main__":
    unittest.main()
