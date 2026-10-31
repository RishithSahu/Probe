"""Autonomy: environment inspection, technique choice with reasons, information-gain stopping, correlation, limits, report."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from probe import planner as P
from probe import report
from probe.analysis import classify as C
from probe.analysis import correlate, limits
from probe.discovery.ingest import Evidence
from probe.engine import Engine
from probe.scope import ScopeGuard
from probe.store import Store

SCOPE = "10.20.30.0/24"


def env(**kw):
    base = dict(scope=[SCOPE], addresses=254, scanner_ip="10.20.30.5", link_subnet="10.20.28.0/22", gateway_ip="10.20.30.1",
                gateway_in_scope=True, gateway_mac="aa:aa:aa:aa:aa:aa", scope_on_link=True, link_wider_than_scope=True)
    base.update(kw)
    return P.Environment(**base)


class Inspect(unittest.TestCase):
    def test_environment_comes_from_scope_and_interface_only(self):
        t = SimpleNamespace(my_ip="10.20.30.5", my_network="10.20.28.0/22", gateway_ip="10.20.30.1")
        e = P.inspect(ScopeGuard([SCOPE]), t)
        self.assertEqual(254, e.addresses)
        self.assertTrue(e.gateway_in_scope and e.scope_on_link and e.link_wider_than_scope)

    def test_gateway_outside_scope_is_noticed(self):
        t = SimpleNamespace(my_ip="10.20.30.5", my_network="10.20.30.0/24", gateway_ip="10.99.0.1")
        e = P.inspect(ScopeGuard([SCOPE]), t)
        self.assertFalse(e.gateway_in_scope)
        self.assertFalse(e.link_wider_than_scope)

    def test_tuning_is_derived_and_overridable(self):
        small = P.derive_tuning(env(addresses=254), budget_s=None, tcp_ports=None, rate_pps=None)
        big = P.derive_tuning(env(addresses=16000), budget_s=None, tcp_ports=None, rate_pps=None)
        self.assertGreater(big["budget_s"], small["budget_s"])
        self.assertLess(big["tcp_ports"], small["tcp_ports"])
        self.assertEqual(77, P.derive_tuning(env(), budget_s=77, tcp_ports=None, rate_pps=None)["budget_s"])


class Choosing(unittest.TestCase):
    def planner_with(self, applicable, repeatable=True, runner=None):
        pl = P.Planner(env())
        pl.register(P.Technique("t", "x", runner or (lambda: None), applicable, answers=(P.Q_UNRESOLVED,), repeatable=repeatable))
        return pl

    def test_inapplicable_technique_is_skipped_with_its_reason(self):
        pl = self.planner_with(lambda e, s: (False, "needs two hosts"))
        self.assertFalse(pl.decide("t", P.State(env=pl.env, remaining_s=100)))
        self.assertEqual(("skip", "needs two hosts"), (pl.journal[-1].action, pl.journal[-1].reason))

    def test_not_enough_time_is_a_recorded_skip(self):
        pl = self.planner_with(lambda e, s: (True, "ok"))
        self.assertFalse(pl.decide("t", P.State(env=pl.env, remaining_s=5), min_time_s=30))
        self.assertIn("time budget", pl.journal[-1].reason)

    def test_a_repeat_that_gained_nothing_is_not_repeated(self):
        know = {"hosts": 1, "macs": 1, "open_ports": 0, "forwarders": 0, "via": 0, "hosted_by": 0, "hops": 0, "foreign": 0, "silent": 5}
        pl = self.planner_with(lambda e, s: (True, "ok"))
        st = P.State(env=pl.env, remaining_s=100)
        self.assertTrue(pl.decide("t", st))
        self.assertEqual({}, pl.execute("t", st, lambda: dict(know)))
        self.assertFalse(pl.decide("t", st))
        self.assertIn("no information", pl.journal[-1].reason)

    def test_a_repeat_that_gained_something_runs_again(self):
        state = {"hosts": 1, "macs": 1, "open_ports": 0, "forwarders": 0, "via": 0, "hosted_by": 0, "hops": 0, "foreign": 0, "silent": 5}

        def run():
            state["hosts"] += 1
        pl = self.planner_with(lambda e, s: (True, "ok"), runner=run)
        st = P.State(env=pl.env, remaining_s=100)
        g = pl.execute("t", st, lambda: dict(state))
        self.assertEqual({"hosts": 1}, g)
        self.assertTrue(pl.decide("t", st))

    def test_non_repeatable_runs_once(self):
        pl = self.planner_with(lambda e, s: (True, "ok"), repeatable=False)
        st = P.State(env=pl.env, remaining_s=100)
        pl.execute("t", st, lambda: {"hosts": 0, "macs": 0, "open_ports": 0, "forwarders": 0, "via": 0, "hosted_by": 0,
                                     "hops": 0, "foreign": 0, "silent": 0})
        self.assertFalse(pl.decide("t", st))


class Questions(unittest.TestCase):
    def test_unresolved_and_missing_mac_become_questions(self):
        ev = Evidence()
        ev.arp_failed.add("10.20.30.9")
        ev.arp_mac["10.20.30.7"] = "02:00:00:00:00:07"
        classes = {"10.20.30.9": C.HostClass(ip="10.20.30.9", verdict="UNRESOLVED") if hasattr(C, "HostClass") else None}
        qs = P.open_questions(classes, ev, blitzed=set(), silent=[])
        kinds = {q.kind for q in qs}
        self.assertTrue({P.Q_UNRESOLVED, P.Q_NO_MAC, P.Q_ARP_LOSS} <= kinds)

    def test_nothing_open_when_everything_is_settled(self):
        ev = Evidence()
        self.assertEqual([], P.open_questions({}, ev, blitzed=set(), silent=["10.20.30.4"]))


class Correlation(unittest.TestCase):
    def host(self, ip, mac, **kw):
        return {"ip": ip, "mac": mac, "vendor": None, "os_guess": None, "roles": [], "verdict": "CONFIRMED_ONLINK",
                "open_ports": kw.get("ports", [])}

    def test_one_mac_many_addresses_is_one_device(self):
        ev = Evidence()
        r = correlate.correlate([self.host("10.20.30.2", "02:aa:00:00:00:02"), self.host("10.20.30.3", "02:aa:00:00:00:02"),
                                 self.host("10.20.30.4", "02:aa:00:00:00:04")], ev, gateway_mac="aa:aa:aa:aa:aa:aa")
        self.assertEqual(2, r["device_count"])
        self.assertEqual(1, r["duplicates_removed"])

    def test_a_proxy_mac_does_not_merge_addresses(self):
        ev = Evidence()
        gw = "02:aa:00:00:00:01"
        r = correlate.correlate([self.host("10.20.30.%d" % i, gw) for i in (1, 20, 21, 22)], ev, gateway_mac=gw)
        self.assertEqual(4, r["device_count"])
        self.assertEqual(0, r["duplicates_removed"])
        self.assertTrue(all(d["proxy_mac"] for d in r["devices"]))

    def test_layer3_only_addresses_are_never_merged_by_guesswork(self):
        r = correlate.correlate([self.host("10.20.30.8", None), self.host("10.20.30.9", None)], Evidence())
        self.assertEqual(2, r["device_count"])

    def test_conflicting_macs_are_reported_with_a_resolution(self):
        ev = Evidence()
        ev.arp_mac["10.20.30.7"] = "02:00:00:00:00:07"
        ev.reply_mac["10.20.30.7"].update({"02:00:00:00:00:07", "02:00:00:00:00:99"})
        r = correlate.correlate([self.host("10.20.30.7", "02:00:00:00:00:07")], ev)
        self.assertEqual(1, len(r["conflicts"]))
        self.assertTrue(r["conflicts"][0]["resolved"])
        self.assertEqual("02:00:00:00:00:07", r["conflicts"][0]["kept"])


class Limits(unittest.TestCase):
    def test_outside_scope_network_is_a_limit_that_needs_a_person(self):
        seg = {"cidr": "10.20.31.0/24", "kind": "outside-scope", "state": "held"}
        out = limits.analyse(env=env().as_dict(), questions=[], converged=True, rounds=1, last_gain={}, segments=[seg], leads=[],
                             decisions=[], stopped={}, catchall=[], held_blocked=0, ipv6_ignored=False)
        lim = [x for x in out["limits"] if x["kind"] == "outside-authorised-scope"]
        self.assertEqual(1, len(lim))
        self.assertIn("never grants permission", lim[0]["why"])

    def test_not_converged_is_stated_honestly(self):
        out = limits.analyse(env=env().as_dict(), questions=[{"kind": "x", "subject": "y", "detail": ""}], converged=False, rounds=0,
                             last_gain={}, segments=[], leads=[], decisions=[], stopped={}, catchall=[], held_blocked=0,
                             ipv6_ignored=False)
        self.assertIn("NOT converged", out["statement"])


class ReportAndScope(unittest.TestCase):
    def test_report_has_evidence_limits_and_journal_and_marks_scope_immutable(self):
        corr = correlate.correlate([], Evidence())
        lim = limits.analyse(env=env().as_dict(), questions=[], converged=True, rounds=1, last_gain={}, segments=[], leads=[],
                             decisions=[], stopped={}, catchall=[], held_blocked=0, ipv6_ignored=False)
        r = report.build(scope=[SCOPE], env=env().as_dict(), tuning={"basis": "b"}, hosts=[], segments=[], edges=[], leads=[],
                         correlation=corr, limits=lim, decisions=[{"round": 0, "technique": "t", "action": "run", "reason": "r", "gain": None}],
                         timings={}, notes=[], safety={"probes_sent": 0})
        self.assertTrue(r["scope_immutable"])
        md = report.to_markdown(r)
        for part in ("## Segments", "## Devices", "## Limits of visibility", "## How the probe decided"):
            self.assertIn(part, md)
        j, m = report.write(r, Path(tempfile.mkdtemp()))
        self.assertTrue(j.exists() and m.exists())

    def test_engine_registers_every_technique_with_an_applicability_rule(self):
        e = Engine(ScopeGuard([SCOPE]), Store(":memory:"), SimpleNamespace(my_network=None))
        e.env = env()
        e.planner = P.Planner(e.env)
        e._register_techniques()
        self.assertIn("forwarder-matrix", e.planner.techniques)
        st = P.State(env=e.env, remaining_s=100, arp_known=1, silent=5)
        ok, why = e.planner.techniques["forwarder-matrix"].applicable(e.env, st)
        self.assertFalse(ok)
        self.assertIn("two on-link hosts", why)

    def test_discovery_cannot_extend_scope(self):
        scope = ScopeGuard([SCOPE])
        e = Engine(scope, Store(":memory:"), SimpleNamespace(my_network="10.20.28.0/22"))
        e._record_link_networks()
        self.assertEqual([SCOPE], [str(n) for n in scope.networks])
        self.assertFalse(scope.in_scope("10.20.31.4"))


if __name__ == "__main__":
    unittest.main()


class MultiRangeScope(unittest.TestCase):
    def test_selftest_passes_for_adjacent_ranges_that_merge_into_one_block(self):
        from probe import selftest
        self.assertEqual([], selftest.run(["10.20.30.0/24", "10.20.31.0/24", "10.20.32.0/23"]))

    def test_every_listed_range_is_in_scope_and_the_neighbours_are_not(self):
        s = ScopeGuard(["10.20.30.0/24", "10.20.31.0/24", "10.20.32.0/23"])
        for ip in ("10.20.30.1", "10.20.31.254", "10.20.32.9", "10.20.33.250"):
            self.assertTrue(s.in_scope(ip), ip)
        for ip in ("10.20.29.255", "10.20.34.0"):
            self.assertFalse(s.in_scope(ip), ip)


class NmapDetection(unittest.TestCase):
    def test_environment_finds_nmap_through_the_tools_own_lookup_not_only_PATH(self):
        from unittest import mock
        with mock.patch("shutil.which", return_value=None), \
                mock.patch("probe.tools.nmap_tool.find_nmap", return_value=r"C:\Program Files (x86)\Nmap\nmap.exe"):
            self.assertTrue(P._nmap_available())
        with mock.patch("shutil.which", return_value=None), mock.patch("probe.tools.nmap_tool.find_nmap", return_value=None):
            self.assertFalse(P._nmap_available())
