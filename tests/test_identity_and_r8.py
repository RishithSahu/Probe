"""Exact address identity, R8 TTL evidence (initial-TTL ambiguity vs genuine forwarding), service-identification states,
missing enrichment results, duplicate/conflicting observations, lead-to-host joins. Synthetic observations only."""
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest import mock

from scapy.all import ICMP, IP, TCP, Ether, IPerror, TCPerror

from probe import netutil
from probe.analysis import classify as C
from probe.discovery import probes as P
from probe.discovery.ingest import Evidence, Ingest
from probe.engine import Engine
from probe.orchestrator import Orchestrator
from probe.scope import ScopeGuard
from probe.service import ProbeService
from probe.store import Store

SCOPE = "10.20.30.0/24"
A, B = "10.20.30.13", "10.20.30.139"          # one is a string prefix of the other: they are different hosts
MAC_A, MAC_B = "02:aa:00:00:00:13", "02:aa:00:00:01:39"
ME, ME_MAC = "10.20.30.2", "02:00:00:00:00:02"


def add_host(store, ip, mac=None):
    store._x("INSERT OR IGNORE INTO hosts (ip, mac, first_seen, last_seen) VALUES (?,?,'t','t')", (ip, mac))


class ExactIdentity(unittest.TestCase):
    def test_netutil_parses_instead_of_prefix_matching(self):
        self.assertFalse(netutil.same_ip(A, B))
        self.assertEqual(A, netutil.address_part(f"{A}:80"))
        self.assertEqual(A, netutil.address_part(f"{A}:80/tcp"))
        self.assertIsNone(netutil.address_part("10.20.30.0/24"))        # a CIDR is not a host
        self.assertIsNone(netutil.address_part("not-an-ip"))
        self.assertTrue(netutil.in_network("10.20.30.200", SCOPE))
        self.assertFalse(netutil.in_network("10.20.31.1", SCOPE))

    def test_compress_ranges(self):
        self.assertEqual(["10.0.0.1-10.0.0.3", "10.0.0.9"], netutil.compress_ranges(["10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.9"]))

    def test_leads_for_one_host_never_include_a_longer_address_sharing_its_prefix(self):
        s = Store(":memory:")
        s.add_lead(f"{B}:80", "about the long one", "anomaly:ttl-differential")
        s.add_lead(B, "about the long one too", "anomaly:forwarder")
        s.add_lead(f"{A}:22", "about the short one", "anomaly:ttl-differential")
        self.assertEqual([f"{A}:22"], [l["address"] for l in s.leads_for_ip(A)])
        self.assertEqual({f"{B}:80", B}, {l["address"] for l in s.leads_for_ip(B)})
        self.assertEqual([], s.leads_for_ip("10.20.30.1"))               # '.1' is a prefix of both
        self.assertEqual([], s.leads_for_ip("garbage"))

    def test_host_lookup_returns_only_that_host_and_its_own_leads(self):
        s = Store(":memory:")
        add_host(s, A, MAC_A)
        add_host(s, B, MAC_B)
        s.add_lead(f"{B}:80", "x", "anomaly:ttl-differential")
        svc = ProbeService(s, ScopeGuard([SCOPE]))
        self.assertEqual(A, svc.host(A)["ip"])
        self.assertEqual([], svc.host(A)["leads"])
        self.assertEqual(1, len(svc.host(B)["leads"]))
        self.assertIsNone(svc.host("10.20.30.1"))

    def test_service_filter_is_an_exact_name_not_a_substring(self):
        s = Store(":memory:")
        add_host(s, A)
        s.add_port(A, 80, service="http")
        s.add_port(A, 443, service="https")
        s.add_port(A, 8080, service="http-proxy")
        names = [x["service"] for x in ProbeService(s, ScopeGuard([SCOPE])).services(service="http")]
        self.assertEqual(["http"], names)

    def test_clear_leads_removes_a_kind_and_its_subkinds_only(self):
        s = Store(":memory:")
        s.add_lead(A, "e", "anomaly")
        s.add_lead(A, "e", "anomaly:forwarder")
        s.add_lead(A, "e", "anomalyX")
        s.clear_leads("anomaly")
        self.assertEqual(["anomalyX"], [l["source"] for l in s.leads()])

    def test_claim_prefix_wildcards_are_literal(self):
        s = Store(":memory:")
        s.claim("web-crawl:a", "agent")
        s.claim("webXcrawl:a", "agent")
        self.assertEqual(["web-crawl:a"], [c["key"] for c in s.claims("web_crawl:".replace("_", "-"))])
        self.assertEqual([], s.claims("web_crawl"))                        # '_' is not a wildcard

    def test_orchestrator_supersedes_only_the_same_endpoint(self):
        s = Store(":memory:")
        o = Orchestrator(s, ScopeGuard([SCOPE]))
        for ip in (A, B):
            s.add_event("service.discovered", {"ip": ip, "port": 9000, "proto": "tcp", "service": None})
        o.consume()
        s.add_event("service.updated", {"ip": A, "port": 9000, "proto": "tcp", "service": "mysql"})
        o.consume()
        st = {r["key"]: r["status"] for r in s.query("SELECT key, status FROM tasks")}
        self.assertEqual("superseded", st[f"service-generic:{A}:9000/tcp"])
        self.assertEqual("pending", st[f"service-generic:{B}:9000/tcp"])      # the host that shares A's prefix is untouched


def ev_with(baseline_kind="tcp-rst", baseline=(64, 64, 64), port_ttls=None, ttl1_synack=0, ttl1_exceeded=0, extra_icmp=()):
    ev = Evidence()
    ev.arp_mac[B] = MAC_B
    ev.mac_ips[MAC_B].add(B)
    ev.reply_mac[B].add(MAC_B)
    ev.visible[B].update({"arp", "icmp-echo"})
    for t in baseline:
        ev.ttl_kind[B][baseline_kind][t] += 1
        ev.ttls[B][t] += 1
    for t in extra_icmp:
        ev.ttl_kind[B]["icmp-echo"][t] += 1
        ev.ttls[B][t] += 1
    for port, ttls in (port_ttls or {}).items():
        ev.ttl_port[B][port] = Counter(ttls)
        for t in ttls:
            ev.ttl_kind[B]["tcp-syn"][t] += 1
            ev.ttls[B][t] += 1
    ev.ttl1_synack[(B, 80)] = ttl1_synack
    ev.ttl1_exceeded[(B, 80)] = ttl1_exceeded
    return C.classify_all([B], ev, gateway_mac="aa:aa:aa:aa:aa:aa")[B]


class R8Evidence(unittest.TestCase):
    def test_a_one_hop_differential_on_the_same_protocol_is_only_suspected_until_verified(self):
        c = ev_with(port_ttls={80: [63, 63, 63]})
        self.assertEqual("suspected", c.behind_status[80])
        self.assertIn("serves-ports-from-behind", c.roles)
        self.assertNotIn("publishes-forwarded-service", c.roles)
        self.assertEqual(C.CONFIRMED_ONLINK, c.verdict)                   # the host itself stays a normal on-link host

    def test_an_icmp_only_baseline_is_ambiguous_because_stacks_use_different_initial_ttls(self):
        c = ev_with(baseline_kind="icmp-echo", baseline=(64, 64, 64), port_ttls={80: [63, 63]})
        self.assertEqual({}, c.behind_ports)                              # ICMP 64 vs TCP 63 proves nothing about TCP

    def test_a_differing_initial_ttl_family_is_not_a_hop(self):
        # ICMP 255 / TCP 64 is a normal embedded stack: SYN-ACKs at 64 against an RST baseline of 64 -> no differential
        c = ev_with(baseline=(64, 64), port_ttls={80: [64, 64]}, extra_icmp=(255, 255))
        self.assertEqual({}, c.behind_ports)

    def test_ttl1_syn_answered_by_the_host_refutes_r8(self):
        c = ev_with(port_ttls={80: [63, 63]}, ttl1_synack=3)
        self.assertEqual({}, c.behind_ports)
        self.assertTrue(any("R8 refuted" in s for s in c.support))

    def test_ttl1_syn_answered_with_time_exceeded_confirms_a_forwarded_service(self):
        c = ev_with(port_ttls={80: [63, 63]}, ttl1_exceeded=3)
        self.assertEqual("confirmed", c.behind_status[80])
        self.assertIn("publishes-forwarded-service", c.roles)
        self.assertEqual(C.CONFIRMED_ONLINK, c.verdict)                   # still not a "hidden host": a forwarded service

    def test_a_single_sample_or_mixed_samples_are_not_evidence(self):
        self.assertEqual({}, ev_with(port_ttls={80: [63]}).behind_ports)
        self.assertEqual({}, ev_with(port_ttls={80: [63, 64, 63]}).behind_ports)

    def test_syn_ack_ttls_do_not_make_a_host_look_routed(self):
        ev = Evidence()
        ev.arp_mac[B] = MAC_B
        ev.mac_ips[MAC_B].add(B)
        ev.reply_mac[B].add(MAC_B)
        ev.visible[B].update({"arp", "icmp-echo", "tcp-syn:80"})
        for t in (64, 64):
            ev.ttl_kind[B]["icmp-echo"][t] += 1
            ev.ttls[B][t] += 1
        for t in (63, 63, 63):                    # service behind the host
            ev.ttl_kind[B]["tcp-syn"][t] += 1
            ev.ttls[B][t] += 1
        c = C.classify_all([B], ev, gateway_mac="aa:aa:aa:aa:aa:aa")[B]
        self.assertFalse(c.forwarding_anomaly)
        self.assertEqual(64, ev.stack_ttl(B))


class IngestObservations(unittest.TestCase):
    def ingest(self):
        scope = ScopeGuard([SCOPE])
        ing = Ingest(scope, Store(":memory:"), ME, ME_MAC)
        return ing

    def syn_ack(self, ing, ttl, dport):
        ip = IP(src=B, dst=ME, ttl=ttl)
        ing._tcp_reply(TCP(sport=80, dport=dport, flags="SA"), ip, MAC_B)

    def test_ttl_probe_replies_are_not_counted_as_port_samples_and_do_not_set_the_stack_ttl(self):
        ing = self.ingest()
        self.syn_ack(ing, 63, P.SPORT_SYN + 4)
        self.syn_ack(ing, 63, P.SPORT_SYN + 5)
        self.syn_ack(ing, 64, P.LADDER_SPORT + 1)                          # reply to a TTL=1 SYN: served locally
        self.assertEqual(Counter({63: 2}), ing.ev.ttl_port[B][80])
        self.assertEqual(1, ing.ev.ttl1_synack[(B, 80)])
        self.assertNotIn(B, ing.ev.reply_ttl)                              # a SYN-ACK does not define the host's stack
        self.assertIsNone(ing._hosts[B]["ttl"])

    def test_time_exceeded_from_the_host_for_a_ttl1_syn_is_recorded_per_port(self):
        ing = self.ingest()
        ing.ev.arp_mac[B] = MAC_B
        pkt = (Ether(src=MAC_B, dst=ME_MAC) / IP(src=B, dst=ME) / ICMP(type=11, code=0)
               / IP(src=ME, dst=B) / TCP(sport=P.LADDER_SPORT + 1, dport=80))
        pkt = Ether(bytes(pkt))
        ing._icmp_error(pkt, pkt[IP], MAC_B)
        self.assertEqual(1, ing.ev.ttl1_exceeded[(B, 80)])

    def test_a_time_exceeded_from_a_different_mac_does_not_count_as_the_host_forwarding(self):
        ing = self.ingest()
        ing.ev.arp_mac[B] = MAC_B
        pkt = Ether(bytes(Ether(src=MAC_A, dst=ME_MAC) / IP(src=B, dst=ME) / ICMP(type=11, code=0)
                          / IP(src=ME, dst=B) / TCP(sport=P.LADDER_SPORT + 1, dport=80)))
        ing._icmp_error(pkt, pkt[IP], MAC_A)
        self.assertEqual(0, ing.ev.ttl1_exceeded[(B, 80)])

    def test_duplicate_open_port_observations_are_one_port_and_conflicting_macs_are_both_kept(self):
        ing = self.ingest()
        for d in (P.SPORT_SYN + 1, P.SPORT_SYN + 2, P.SPORT_SYN + 3):
            self.syn_ack(ing, 64, d)
        self.assertEqual(1, len([k for k in ing._ports if k == (B, 80)]))
        ing._tcp_reply(TCP(sport=22, dport=P.SPORT_SYN + 9, flags="SA"), IP(src=B, dst=ME, ttl=64), MAC_A)   # same IP, other MAC
        self.assertEqual({MAC_A, MAC_B}, ing.ev.reply_mac[B])


class ServiceStates(unittest.TestCase):
    def store(self):
        s = Store(":memory:")
        add_host(s, B)
        return s

    def row(self, s, port):
        return s.query("SELECT * FROM ports WHERE host_ip=? AND port=?", (B, port))[0]

    def test_discovered_guessed_identified_product_and_unsuccessful_are_distinct(self):
        s = self.store()
        for p in (80, 22, 9999, 7000, 8081):
            s.add_port(B, p)
        s.upsert_service(B, 22, service="ssh", product="OpenSSH", version="9.2")
        s.upsert_service(B, 7000, service="unknown")                           # nmap connected, could not name it
        s.mark_ident(B, 8081, "tcp", "unidentified-attempted", "nmap did not finish")
        s.label_unidentified_ports(lambda port, proto: {80: "http"}.get(port))
        self.assertEqual(("guessed", "http?"), (self.row(s, 80)["identification"], self.row(s, 80)["service"]))
        self.assertEqual("identified-product", self.row(s, 22)["identification"])
        self.assertEqual("discovered", self.row(s, 9999)["identification"])     # no name for this number: stays merely discovered
        self.assertEqual("unidentified-attempted", self.row(s, 7000)["identification"])
        self.assertEqual("unidentified-attempted", self.row(s, 8081)["identification"])
        self.assertEqual(5, len(s.query("SELECT * FROM ports")))                # nothing was discarded

    def test_a_failed_attempt_never_downgrades_an_identified_port(self):
        s = self.store()
        s.add_port(B, 80)
        s.upsert_service(B, 80, service="http", product="nginx")
        s.mark_ident(B, 80, "tcp", "unidentified-attempted", "late timeout")
        self.assertEqual("identified-product", self.row(s, 80)["identification"])

    def test_enrichment_that_returns_nothing_marks_each_port_with_the_reason_and_keeps_it(self):
        scope = ScopeGuard([SCOPE])
        e = Engine(scope, Store(":memory:"), SimpleNamespace(my_ip=ME, my_network=None))
        e.ingest = SimpleNamespace(ev=Evidence(), _ports={(B, 80): None, (B, 81): None, (B, 82): None}, flush=lambda: None)
        e.env = SimpleNamespace(nmap=True)
        e.planner = None
        add_host(e.store, B)
        for p in (80, 81, 82):
            e.store.add_port(B, p)
        res = {"records": [], "leaks": {}, "vulnerable_apps": [], "ran": 1, "seconds": 1.0, "error": None, "hosts": {},
               "attempted": {B: {80: "complete", 81: "incomplete", 82: "not-started"}}}
        e._remaining = lambda: 100
        with mock.patch("probe.engine.nmap_tool.enrich", return_value=res):
            e._enrich()
        rows = {r["port"]: r for r in e.store.query("SELECT * FROM ports")}
        self.assertEqual(3, len(rows))
        self.assertEqual("unidentified-attempted", rows[80]["identification"])
        self.assertIn("did not report the port open", rows[80]["ident_note"])
        self.assertIn("did not finish", rows[81]["ident_note"])
        self.assertEqual("discovered", rows[82]["identification"])               # never reached: not claimed as attempted
        self.assertIn("ran out of time", rows[82]["ident_note"])


class LeadJoins(unittest.TestCase):
    def test_a_port_level_r8_lead_is_not_also_filed_as_a_forwarder_lead(self):
        scope = ScopeGuard([SCOPE])
        store = Store(":memory:")
        t = SimpleNamespace(my_ip=ME, gateway_ip=None, my_network=None)
        e = Engine(scope, store, t)
        ing = Ingest(scope, store, ME, ME_MAC)
        e.ingest, e.gw_mac, e._scan_id = ing, None, 1
        ev = ing.ev
        ev.arp_mac[B] = MAC_B
        ev.mac_ips[MAC_B].add(B)
        ev.reply_mac[B].add(MAC_B)
        ev.visible[B].update({"arp", "icmp-echo"})
        for tt in (64, 64):
            ev.ttl_kind[B]["tcp-rst"][tt] += 1
            ev.ttls[B][tt] += 1
        ev.ttl_port[B][80] = Counter([63, 63])
        store.add_port(B, 80)
        add_host(store, B, MAC_B)
        e._infer()
        leads = {(l["address"], l["source"]) for l in store.leads()}
        self.assertIn((f"{B}:80", "anomaly:ttl-differential"), leads)
        self.assertNotIn((B, "anomaly:forwarder"), leads)
        self.assertEqual([f"{B}:80"], [l["address"] for l in store.leads_for_ip(B) if l["source"].startswith("anomaly")])
        self.assertEqual(64, store.query("SELECT ttl FROM hosts WHERE ip=?", (B,))[0]["ttl"])      # stack TTL, not the SYN-ACK's


if __name__ == "__main__":
    unittest.main()


class VerificationProbeIsGuarded(unittest.TestCase):
    def transport(self):
        from probe.selftest import _NoNic
        tr = _NoNic(ScopeGuard([SCOPE]), rate_pps=10 ** 6)
        tr.wire = []
        tr.my_ip, tr.my_mac = ME, ME_MAC
        tr.allow_mac(MAC_B)
        return tr

    def test_the_ttl1_syn_to_a_hosts_own_mac_and_ip_passes_the_byte_guard(self):
        from probe.discovery.rawprobes import RawProbes, mac_bytes
        tr = self.transport()
        rp = RawProbes(ME_MAC, ME)
        frame = rp.tcp_syn(mac_bytes(MAC_B), int.from_bytes(bytes(map(int, B.split("."))), "big"), 80, 1)
        self.assertTrue(tr.send_raw(frame, caller="r8-verify:ttl1-syn"))

    def test_the_same_probe_to_an_out_of_scope_address_is_refused(self):
        from probe.discovery.rawprobes import RawProbes, mac_bytes
        tr = self.transport()
        rp = RawProbes(ME_MAC, ME)
        frame = rp.tcp_syn(mac_bytes(MAC_B), int.from_bytes(bytes(map(int, "10.99.0.5".split("."))), "big"), 80, 1)
        self.assertFalse(tr.send_raw(frame, caller="r8-verify:ttl1-syn"))
        self.assertEqual(0, len(tr.wire) - 1 if tr.wire else 0)
