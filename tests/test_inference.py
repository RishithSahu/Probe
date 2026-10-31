"""Unit tests for the reasoning layer, fed with hand-written *observations* (not a simulated network).
Several are regressions for mistakes the first live run exposed on a ~200-client Wi-Fi lab:
  * a lost TTL=1 probe made on-link hosts look "2 hops away"
  * a time-exceeded reply for a probe that was addressed to the gateway made an on-link host look routed
  * the PC's own internet traffic was read as probe replies from out-of-scope hosts
Run: python -m unittest discover -s tests -v"""
import ipaddress
import unittest

from scapy.all import IP, TCP, Ether

from probe.analysis import classify as C
from probe.analysis import segments as S
from probe.discovery.ingest import Evidence, Ingest
from probe.scope import ScopeGuard
from probe.store import Store

SCOPE = [ipaddress.ip_network("192.168.60.0/24")]
GW, GW_MAC = "192.168.60.1", "dc:62:79:b7:33:7e"


def mac(n: int) -> str:
    return f"02:00:00:00:00:{n:02x}"


def local(ev, ip, n, *, ladder=None, extra=()):
    ev.arp_mac[ip] = mac(n)
    ev.mac_ips[mac(n)].add(ip)
    ev.visible[ip].update({"arp", "icmp-echo", *extra})
    ev.reply_mac[ip].add(mac(n))
    if ladder:
        ev.ladder[ip]["icmp-echo"] = ladder


def separate(ev, ip, *kinds, ladder=2, arp_failed=True, hop1=None):
    ev.visible[ip].update(kinds or {"tcp-syn:443"})
    ev.ladder[ip]["tcp-syn"] = ladder
    ev.reply_mac[ip].add(GW_MAC)
    if arp_failed:
        ev.arp_failed.add(ip)
    if hop1:
        ev.hops[ip][1] = hop1


def classify(ev, ips=None, **kw):
    return C.classify_all(list(ips or ev.visible), ev, gateway_mac=GW_MAC, gateway_ip=GW, **kw)


class Rules(unittest.TestCase):
    def test_arp_with_own_unique_mac_is_onlink_even_if_the_ttl1_probe_was_lost(self):
        ev = Evidence()
        local(ev, "192.168.60.100", 100, ladder=2)             # first answered at TTL=2: just a lost TTL=1 probe
        c = classify(ev)["192.168.60.100"]
        self.assertEqual(C.CONFIRMED_ONLINK, c.verdict)
        self.assertTrue(any("first answered at TTL=2" in s for s in c.support))

    def test_time_exceeded_for_a_probe_sent_to_the_gateway_does_not_make_an_onlink_host_separate(self):
        ev = Evidence()
        ev.router_macs[GW] = GW_MAC
        local(ev, "192.168.60.228", 228)
        ev.visible["192.168.60.228"] = {"arp"}                  # ARP-only phone
        ev.hops["192.168.60.228"][1] = GW                       # an early probe had gone via the gateway
        self.assertEqual(C.CONFIRMED_ONLINK, classify(ev)["192.168.60.228"].verdict)

    def test_l3_answers_without_arp_are_only_suspected_until_the_arp_retest_fails(self):
        ev = Evidence()
        separate(ev, "192.168.60.140", arp_failed=False, ladder=3)
        c = classify(ev)["192.168.60.140"]
        self.assertEqual(C.SUSPECTED_SEPARATE, c.verdict)
        ev.arp_failed.add("192.168.60.140")
        self.assertEqual(C.CONFIRMED_SEPARATE, classify(ev)["192.168.60.140"].verdict)

    def test_proxy_arp_router_is_proven_by_time_exceeded_from_the_arp_answering_mac(self):
        ev = Evidence()
        rmac = "02:aa:aa:aa:aa:aa"
        ev.router_macs["192.168.60.2"] = rmac
        ip = "192.168.60.141"
        ev.arp_mac[ip] = rmac
        ev.mac_ips[rmac].add(ip)
        ev.visible[ip].update({"arp", "icmp-echo"})
        ev.hops[ip][1] = "192.168.60.2"                         # the device that answered ARP forwards instead of terminating
        c = classify(ev, [ip])[ip]
        self.assertEqual(C.CONFIRMED_SEPARATE, c.verdict)
        self.assertTrue(c.proxy_arp)

    def test_a_mac_shared_by_several_addresses_is_not_proof_of_onlink(self):
        ev = Evidence()
        for ip in ("192.168.60.150", "192.168.60.151"):
            ev.arp_mac[ip] = "02:bb:bb:bb:bb:bb"
            ev.mac_ips["02:bb:bb:bb:bb:bb"].add(ip)
            ev.visible[ip].update({"arp", "icmp-echo"})
        self.assertEqual(C.SUSPECTED_SEPARATE, classify(ev)["192.168.60.150"].verdict)

    def test_phone_that_ignores_arp_but_answers_pings_from_its_own_mac_is_onlink(self):
        """Found live: 192.168.60.137 ignored directed ARP but replied from its own unique MAC."""
        ev = Evidence()
        ip = "192.168.60.137"
        ev.visible[ip].add("icmp-echo")
        ev.ladder[ip]["icmp-echo"] = 2
        ev.reply_mac[ip].add("a6:14:58:e7:f3:70")
        ev.arp_failed.add(ip)
        c = classify(ev, [ip])[ip]
        self.assertEqual(C.CONFIRMED_ONLINK, c.verdict)
        self.assertTrue(any(p.startswith("L5") for p in c.proof))

    def test_host_whose_replies_come_via_the_router_and_ignores_arp_is_separate(self):
        ev = Evidence()
        ip = "192.168.60.140"
        ev.visible[ip].add("icmp-echo")
        ev.reply_mac[ip].add(GW_MAC)                            # replies arrive from the gateway's MAC
        ev.arp_failed.add(ip)
        self.assertEqual(C.CONFIRMED_SEPARATE, classify(ev, [ip])[ip].verdict)

    def test_the_gateway_itself_is_onlink(self):
        ev = Evidence()
        ev.arp_mac[GW] = GW_MAC
        ev.visible[GW].add("arp")
        self.assertEqual(C.CONFIRMED_ONLINK, classify(ev, [GW])[GW].verdict)

    def test_answer_at_ttl1_proves_onlink(self):
        ev = Evidence()
        ev.visible["192.168.60.9"].add("icmp-echo")
        ev.ladder["192.168.60.9"]["icmp-echo"] = 1
        self.assertEqual(C.CONFIRMED_ONLINK, classify(ev)["192.168.60.9"].verdict)

    def test_contradicting_proofs_are_a_conflict_not_a_guess(self):
        ev = Evidence()
        separate(ev, "192.168.60.9", "icmp-echo")
        ev.ladder["192.168.60.9"]["icmp-echo"] = 1               # answered at TTL=1 AND ignores ARP
        self.assertEqual(C.CONFLICT, classify(ev)["192.168.60.9"].verdict)

    def test_nothing_known_is_unresolved(self):
        ev = Evidence()
        ev.visible["192.168.60.77"].add("icmp-error")
        self.assertEqual(C.UNRESOLVED, classify(ev)["192.168.60.77"].verdict)


class OsTrafficIsNotProbeReplies(unittest.TestCase):
    def test_internet_replies_to_this_pc_never_become_hosts_or_foreign_networks(self):
        scope = ScopeGuard(["192.168.60.0/24"])
        ing = Ingest(scope, Store(":memory:"), "192.168.60.68", "02:00:00:00:00:68")
        for src in ("142.251.222.131", "13.223.216.197", "100.62.19.108", "192.168.60.7"):
            ing.handle(Ether(src=GW_MAC, dst="02:00:00:00:00:68") / IP(src=src, dst="192.168.60.68") /
                       TCP(sport=443, dport=51234, flags="SA"))     # a browser's own connection, not our probe
        self.assertEqual({}, dict(ing.ev.foreign))
        self.assertEqual({}, dict(ing.ev.visible))
        self.assertEqual([], ing.store.hosts())


class Segments(unittest.TestCase):
    def build(self, local_ips, sep_ips, masks=None):
        ev = Evidence()
        ev.masks = masks or {}
        ev.router_macs[GW] = GW_MAC
        for i, ip in enumerate(local_ips):
            local(ev, ip, 10 + i, ladder=1)
        for ip in sep_ips:
            separate(ev, ip, "tcp-syn:443", ladder=2, hop1=GW)
        return ev, classify(ev)

    def test_hidden_block_is_bounded_not_guessed(self):
        ev, cls = self.build(["192.168.60.10", "192.168.60.20"], ["192.168.60.130", "192.168.60.140", "192.168.60.150"])
        segs = S.infer(cls, ev, SCOPE, gateway_ip=GW)
        hid = [s for s in segs if not s.local]
        self.assertEqual(1, len(hid))
        self.assertEqual("192.168.60.128/27", hid[0].covering)      # smallest block holding the members
        self.assertEqual("192.168.60.128/25", hid[0].max_extent)    # largest block with no foreign host
        self.assertEqual("hidden", hid[0].hidden["level"])           # nobody answered ping
        self.assertEqual(1, [s.local for s in segs].count(True))

    def test_the_local_link_is_one_network_not_a_pile_of_fragments(self):
        ev, cls = self.build([f"192.168.60.{n}" for n in (10, 20, 100, 136, 138, 200, 250)], ["192.168.60.137"])
        segs = S.infer(cls, ev, SCOPE, gateway_ip=GW)
        loc = [s for s in segs if s.local]
        self.assertEqual(1, len(loc))
        self.assertEqual("192.168.60.0/24", loc[0].covering)
        self.assertTrue(any("holes: 192.168.60.137" in e for e in loc[0].evidence))
        self.assertEqual(["192.168.60.137/32"], [s.cidr for s in segs if not s.local])

    def test_mask_reply_collapses_the_interval(self):
        ev, cls = self.build(["192.168.60.10"], ["192.168.60.130", "192.168.60.140"],
                             masks={"192.168.60.130": "255.255.255.192"})
        hid = [s for s in S.infer(cls, ev, SCOPE, gateway_ip=GW) if not s.local][0]
        self.assertEqual(("192.168.60.128/26", "192.168.60.128/26"), (hid.covering, hid.max_extent))

    def test_suspected_hosts_never_create_a_segment(self):
        ev = Evidence()
        for ip in ("192.168.60.130", "192.168.60.131", "192.168.60.132"):
            separate(ev, ip, "tcp-ack:80", arp_failed=False)          # ARP re-test not failed -> only suspected
        cls = classify(ev)
        self.assertEqual({C.SUSPECTED_SEPARATE}, {c.verdict for c in cls.values()})
        self.assertEqual([], S.infer(cls, ev, SCOPE))

    def test_a_segment_that_answers_ping_is_visible_not_hidden(self):
        ev = Evidence()
        for ip in ("192.168.60.130", "192.168.60.131"):
            separate(ev, ip, "icmp-echo")
        cls = classify(ev)
        self.assertEqual("visible", [s for s in S.infer(cls, ev, SCOPE) if not s.local][0].hidden["level"])

    def test_foreign_address_is_reported_without_inventing_a_prefix(self):
        ev = Evidence()
        ev.foreign["10.99.0.1"].add("router interface that answered about 192.168.60.140")
        out = [s for s in S.infer({}, ev, SCOPE) if s.kind == "outside-scope"]
        self.assertEqual(1, len(out))
        self.assertFalse(out[0].prefix_known)
        self.assertEqual("10.99.0.1/32", out[0].cidr)


if __name__ == "__main__":
    unittest.main()
