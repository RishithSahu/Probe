"""Discovery Completeness Manager: bounded rounds, bounded wall-clock budget, no repeat without new evidence,
honest INCOMPLETE/CONVERGED reporting -- plus the engine-level R8 decoupling, exact ICMP correlation, persistent
observation ledger and persistent-anomaly priority it relies on. Synthetic evidence only; nothing here sends a packet."""
import time
import unittest
import unittest.mock
from collections import Counter
from types import SimpleNamespace

from probe import completeness, planner
from probe.analysis import classify as C
from probe.analysis import correlate
from probe.discovery import probes as P
from probe.discovery.ingest import Evidence, Ingest
from probe.engine import Engine
from probe.scope import ScopeGuard
from probe.store import Store

SCOPE = "10.20.30.0/24"
A, B = "10.20.30.69", "10.20.30.209"
MAC_B = "02:aa:00:00:02:09"
ME, ME_MAC = "10.20.30.2", "02:00:00:00:00:02"


def q(kind="k", subject="x", detail="d"):
    return planner.Question(kind, subject, detail)


class ManagerBasics(unittest.TestCase):
    def cm(self, **kw):
        return completeness.CompletenessManager(None, None, scan_id=1, **kw)

    def test_no_open_items_stops_immediately_as_converged(self):
        cm = self.cm()
        ok, why = cm.should_continue(open_count=0)
        self.assertFalse(ok)
        self.assertEqual("no open items remain", why)

    def test_first_round_always_runs_when_items_are_open(self):
        cm = self.cm()
        ok, _ = cm.should_continue(open_count=3)
        self.assertTrue(ok)

    def test_a_round_that_adds_nothing_is_not_repeated(self):
        cm = self.cm(max_rounds=10, max_budget_s=10_000)
        cm.begin_round([q()])
        cm.end_round({})                      # round 1 gained nothing
        ok, why = cm.should_continue(open_count=1)
        self.assertFalse(ok)
        self.assertIn("no new evidence", why)

    def test_a_round_that_gained_something_earns_another_round(self):
        cm = self.cm(max_rounds=10, max_budget_s=10_000)
        cm.begin_round([q()])
        cm.end_round({"hosts": 1})
        ok, _ = cm.should_continue(open_count=1)
        self.assertTrue(ok)

    def test_max_rounds_is_a_hard_ceiling_even_with_gain(self):
        cm = self.cm(max_rounds=2, max_budget_s=10_000)
        for _ in range(2):
            cm.begin_round([q()])
            cm.end_round({"hosts": 1})            # gain every round: only the round cap should stop it
        ok, why = cm.should_continue(open_count=1)
        self.assertFalse(ok)
        self.assertIn("max_rounds", why)

    def test_max_budget_is_a_hard_ceiling(self):
        cm = self.cm(max_rounds=100, max_budget_s=0.01)
        cm.begin_round([q()])
        cm.end_round({"hosts": 1})
        time.sleep(0.02)
        ok, why = cm.should_continue(open_count=1)
        self.assertFalse(ok)
        self.assertIn("max_budget_s", why)

    def test_default_budget_is_the_20_minute_ceiling_asked_for(self):
        self.assertEqual(1200.0, completeness.DEFAULT_MAX_BUDGET_S)

    def test_items_persist_across_rounds_and_resolution_is_tracked(self):
        cm = self.cm(max_rounds=10, max_budget_s=10_000)
        cm.begin_round([q("k1", "a"), q("k2", "b")])
        cm.end_round({"hosts": 1})
        cm.begin_round([q("k1", "a")])         # 'b' is no longer open: resolved
        cm.end_round({})
        rep = cm.finish(converged=False, stop_reason="test")
        self.assertEqual(1, rep["items_resolved"])
        self.assertEqual(["k1:a"], [i["key"] for i in rep["items_unresolved"]])

    def test_report_never_claims_proof_of_absence(self):
        cm = self.cm()
        cm.begin_round([q()])
        rep = cm.finish(converged=False, stop_reason="budget")
        self.assertIn("never reported as a confirmed absence", rep["note"])
        self.assertEqual("INCOMPLETE", rep["status"])

    def test_converged_report_says_so(self):
        cm = self.cm()
        rep = cm.finish(converged=True, stop_reason="questions-settled")
        self.assertEqual("CONVERGED", rep["status"])

    def test_observations_are_persisted_when_a_store_is_given(self):
        store = Store(":memory:")
        cm = completeness.CompletenessManager(store, ScopeGuard([SCOPE]), scan_id=7, max_rounds=5, max_budget_s=1000)
        cm.begin_round([q()])
        cm.end_round({})
        cm.finish(converged=False, stop_reason="x")
        rows = store.query("SELECT * FROM observations WHERE ip='completeness'")
        self.assertTrue(any(r["kind"] == "round-open-items" for r in rows))
        self.assertTrue(any(r["kind"] == "final-report" for r in rows))


class ObservationLedger(unittest.TestCase):
    def test_observations_survive_a_store_reset(self):
        store = Store(":memory:")
        store.add_observation(1, A, "r8-status", "confirmed", port=80, proto="tcp")
        store.reset()
        self.assertEqual(1, len(store.observations_for(A, "r8-status")))

    def test_observations_for_one_ip_never_includes_a_different_address(self):
        store = Store(":memory:")
        store.add_observation(1, A, "r8-status", "confirmed", port=1)
        store.add_observation(1, B, "r8-status", "confirmed", port=1)
        self.assertEqual([A], {o["ip"] for o in store.observations_for(A)} and [A])
        self.assertEqual(1, len(store.observations_for(A)))

    def test_ever_observed_is_a_union_across_scans(self):
        store = Store(":memory:")
        store.add_observation(1, A, "r8-status", "suspected", port=80)
        store.add_observation(2, B, "r8-status", "confirmed", port=8000)
        self.assertEqual({A, B}, store.ever_observed("r8-status"))


def ev_with_r8(ip, *, baseline=(64, 64), port_ttls=None, synack=0, exceeded=0):
    ev = Evidence()
    mac = "02:aa:00:00:00:ff"
    ev.arp_mac[ip] = mac
    ev.mac_ips[mac].add(ip)
    ev.reply_mac[ip].add(mac)
    ev.visible[ip].update({"arp", "icmp-echo"})
    for t in baseline:
        ev.ttl_kind[ip]["tcp-rst"][t] += 1
        ev.ttls[ip][t] += 1
    for port, ttls in (port_ttls or {}).items():
        ev.ttl_port[ip][port] = Counter(ttls)
        for t in ttls:
            ev.ttl_kind[ip]["tcp-syn"][t] += 1
    ev.ttl1_synack[(ip, 80)] = synack
    ev.ttl1_exceeded[(ip, 80)] = exceeded
    return C.classify_all([ip], ev, gateway_mac="aa:aa:aa:aa:aa:aa")[ip], ev


class DecoupledR8(unittest.TestCase):
    """Requirement: the TTL=1 check must not depend on a prior passive-TTL suspicion, and must cover the port on
    its own evidence. These construct active (TTL=1) results with NO qualifying passive differential at all."""

    def test_forwarding_is_confirmed_from_active_evidence_alone_no_passive_differential(self):
        # baseline 64, SYN-ACK ALSO 64 (no passive differential the old code would ever have noticed) -- but the
        # TTL=1 check itself (independent evidence) says the host forwards this port.
        c, _ = ev_with_r8(B, baseline=(64, 64), port_ttls={80: [64, 64]}, exceeded=3)
        self.assertEqual("confirmed", c.behind_status[80])
        self.assertIn("publishes-forwarded-service", c.roles)

    def test_local_service_is_verified_from_active_evidence_alone_no_passive_differential(self):
        c, _ = ev_with_r8(A, baseline=(64, 64), port_ttls={80: [64, 64]}, synack=3)
        self.assertEqual("verified-local", c.behind_status[80])
        self.assertEqual({}, c.behind_ports)             # settled local service: no forwarding claim at all
        self.assertNotIn("serves-ports-from-behind", c.roles)
        self.assertNotIn("publishes-forwarded-service", c.roles)

    def test_no_open_question_remains_for_a_verified_local_port(self):
        c, ev = ev_with_r8(A, baseline=(64, 64), port_ttls={80: [64, 64]}, synack=3)
        qs = planner.open_questions({A: c}, ev, blitzed={A}, silent=[])
        self.assertFalse(any(x.kind == planner.Q_BACKEND for x in qs))

    def test_an_open_question_remains_for_a_confirmed_forward_backend_is_still_unknown(self):
        c, ev = ev_with_r8(B, baseline=(64, 64), port_ttls={80: [64, 64]}, exceeded=3)
        qs = planner.open_questions({B: c}, ev, blitzed={B}, silent=[])
        self.assertTrue(any(x.kind == planner.Q_BACKEND for x in qs))

    def test_conflicting_or_too_few_active_replies_are_ambiguous_not_a_verdict(self):
        c, _ = ev_with_r8(A, baseline=(64, 64), port_ttls={80: [64, 64]}, synack=1, exceeded=1)
        self.assertEqual("ambiguous-incomplete", c.behind_status[80])
        self.assertNotIn("publishes-forwarded-service", c.roles)

    def test_passive_signal_with_no_active_check_yet_stays_suspected(self):
        c, _ = ev_with_r8(A, baseline=(64, 64), port_ttls={80: [63, 63]})      # no active data at all
        self.assertEqual("suspected", c.behind_status[80])


class EngineProbesEveryOpenPort(unittest.TestCase):
    def test_fwdsvc_sends_ttl1_to_every_open_port_not_only_suspect_ones(self):
        scope = ScopeGuard([SCOPE])
        sent = []

        class FakeRP:
            def tcp_syn(self, mac, ip, port, ttl):
                return ("SYN", mac, ip, port, ttl)

        e = Engine(scope, Store(":memory:"), SimpleNamespace(my_ip=ME, my_network=None))
        e.ingest = SimpleNamespace(ev=Evidence(), _ports={(B, 80): None, (B, 443): None})
        e.ingest.ev.arp_mac[B] = MAC_B
        e.rp = FakeRP()
        e._tx = lambda raw, caller, classification=False: (sent.append((raw[3], caller)), True)[1]
        e._settle = lambda *_a, **_k: None
        e._t_fwdsvc()
        ports_probed = {port for (port, _caller) in sent}
        self.assertEqual({80, 443}, ports_probed)          # BOTH open ports, with no passive suspicion set anywhere


class ExactProbeCorrelation(unittest.TestCase):
    """Requirement: a time-exceeded must correlate to the EXACT original probe (its quoted port, TTL=1 marker,
    and the responding MAC must be the host's known MAC) -- not merely 'some time-exceeded was seen'."""

    def ingest(self):
        return Ingest(ScopeGuard([SCOPE]), Store(":memory:"), ME, ME_MAC)

    def exceeded_pkt(self, *, target, quoted_port, quoted_sport_offset, eth_src):
        from scapy.all import ICMP, IP, TCP, Ether
        inner = IP(src=ME, dst=target) / TCP(sport=P.LADDER_SPORT + quoted_sport_offset, dport=quoted_port)
        pkt = Ether(src=eth_src, dst=ME_MAC) / IP(src=target, dst=ME) / ICMP(type=11, code=0) / inner
        return Ether(bytes(pkt))

    def test_exact_port_and_known_mac_match_is_recorded(self):
        ing = self.ingest()
        ing.ev.arp_mac[B] = MAC_B
        pkt = self.exceeded_pkt(target=B, quoted_port=8000, quoted_sport_offset=1, eth_src=MAC_B)
        ing._icmp_error(pkt, pkt[1], MAC_B)
        self.assertEqual(1, ing.ev.ttl1_exceeded[(B, 8000)])

    def test_unknown_mac_for_the_target_does_not_silently_accept_the_match(self):
        ing = self.ingest()                        # ARP MAC for B never learned
        pkt = self.exceeded_pkt(target=B, quoted_port=8000, quoted_sport_offset=1, eth_src=MAC_B)
        ing._icmp_error(pkt, pkt[1], MAC_B)
        self.assertEqual(0, ing.ev.ttl1_exceeded[(B, 8000)])

    def test_a_mismatched_mac_is_refused_even_with_a_known_target_mac(self):
        ing = self.ingest()
        ing.ev.arp_mac[B] = MAC_B
        pkt = self.exceeded_pkt(target=B, quoted_port=8000, quoted_sport_offset=1, eth_src="02:ff:ff:ff:ff:ff")
        ing._icmp_error(pkt, pkt[1], "02:ff:ff:ff:ff:ff")
        self.assertEqual(0, ing.ev.ttl1_exceeded[(B, 8000)])

    def test_a_different_quoted_port_is_a_different_observation(self):
        ing = self.ingest()
        ing.ev.arp_mac[B] = MAC_B
        ing._icmp_error(self.exceeded_pkt(target=B, quoted_port=8000, quoted_sport_offset=1, eth_src=MAC_B), None, MAC_B) \
            if False else None
        pkt1 = self.exceeded_pkt(target=B, quoted_port=8000, quoted_sport_offset=1, eth_src=MAC_B)
        ing._icmp_error(pkt1, pkt1[1], MAC_B)
        pkt2 = self.exceeded_pkt(target=B, quoted_port=8081, quoted_sport_offset=1, eth_src=MAC_B)
        ing._icmp_error(pkt2, pkt2[1], MAC_B)
        self.assertEqual(1, ing.ev.ttl1_exceeded[(B, 8000)])
        self.assertEqual(1, ing.ev.ttl1_exceeded[(B, 8081)])


class PersistentAnomalyPriority(unittest.TestCase):
    """Requirement: an anomalous device stays in the priority queue even once its CURRENT classification stops
    flagging it (e.g. a lost reply this round) -- read from the observation ledger, which is history, not proof."""

    def test_ever_anomalous_includes_a_host_with_no_current_role(self):
        store = Store(":memory:")
        store.add_observation(1, B, "r8-status", "confirmed", port=8000)      # an EARLIER scan's observation
        e = Engine(ScopeGuard([SCOPE]), store, SimpleNamespace(my_ip=ME, my_network=None))
        e._classes = {B: C.HostClass(ip=B, verdict=C.CONFIRMED_ONLINK)}       # THIS round: no roles at all
        self.assertIn(B, e._ever_anomalous())


class ProxyArpIsNotDeviceIdentity(unittest.TestCase):
    """Requirement: distinguish ARP-identity from device-identity (a proxy ARP responder is not the same device
    as every address it answers for), reusing correlate.py's existing proxy-MAC handling."""

    def test_a_proxy_arp_mac_never_merges_the_addresses_it_answers_for(self):
        ev = Evidence()
        proxy_mac = "02:aa:00:00:00:01"
        hosts = [{"ip": f"10.20.30.{i}", "mac": proxy_mac, "vendor": None, "os_guess": None, "roles": [],
                 "verdict": "CONFIRMED_ONLINK", "open_ports": []} for i in (1, 94, 119, 129)]
        r = correlate.correlate(hosts, ev, gateway_mac=proxy_mac)
        self.assertEqual(4, r["device_count"])
        self.assertTrue(all(d["proxy_mac"] for d in r["devices"]))


if __name__ == "__main__":
    unittest.main()


class EgressRefusalDoesNotCrash(unittest.TestCase):
    """The crash found in live validation: an independent-egress refusal (e.g. a stale auditor heartbeat) raised an
    uncaught RuntimeError from inside a worker thread, which killed the whole engine and lost the final report.
    A refusal must degrade that one host's identification, never the run."""

    def test_run_chunk_catches_an_egress_refusal_instead_of_raising(self):
        from probe.tools import nmap_tool as nt

        def refuse():
            raise RuntimeError("auditor heartbeat stale")
        old = nt._egress_attest
        nt.configure_egress(lambda: (False, "auditor heartbeat stale"))
        try:
            out, err = nt._run_chunk("nmap", ["10.20.30.5"], [80], 5, 10, "probe-data/_no_such_dir/x.xml")
        finally:
            nt._egress_attest = old
        self.assertEqual("", out)
        self.assertTrue(err.startswith("egress-refused"))

    def test_run_generic_catches_an_egress_refusal_instead_of_raising(self):
        from probe.tools import nmap_tool as nt
        old = nt._egress_attest
        nt.configure_egress(lambda: (False, "auditor heartbeat stale"))
        try:
            out, err = nt._run_generic("nmap", ["-sU", "10.20.30.5"], 5, 10, "probe-data/_no_such_dir/x.xml")
        finally:
            nt._egress_attest = old
        self.assertEqual("", out)
        self.assertTrue(err.startswith("egress-refused"))

    def test_a_refused_host_is_reported_as_notrun_not_as_ran(self):
        from probe.tools import nmap_tool as nt
        from probe.scope import ScopeGuard
        old = nt._egress_attest
        nt.configure_egress(lambda: (False, "auditor heartbeat stale"))
        try:
            with unittest.mock.patch.object(nt, "find_nmap", return_value="nmap"), \
                    unittest.mock.patch.object(nt.fence, "allow_program"):
                res = nt.udp_scan(ScopeGuard(["10.20.30.0/24"]), ["10.20.30.5"], workdir="probe-data/_egress_test")
        finally:
            nt._egress_attest = old
        self.assertIn("10.20.30.5", res["notrun"])
        self.assertNotIn("10.20.30.5", res["ran"])
        self.assertTrue(res["errors"]["10.20.30.5"].startswith("egress-refused"))
