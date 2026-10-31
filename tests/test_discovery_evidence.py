"""OS view, network candidates (never probed), challenge-artifact recording, nmap host facts, per-finding evidence."""
import ipaddress
import unittest
from types import SimpleNamespace
from unittest import mock

from probe import report
from probe.analysis import challenge, correlate, limits
from probe.discovery import tiers
from probe.discovery.ingest import Evidence
from probe.engine import Engine
from probe.net import osview
from probe.scope import ScopeGuard
from probe.store import Store
from probe.tools import nmap_tool

SCOPE = "10.20.30.0/24"

PROC_ROUTE = """Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t011E140A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t001E140A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t001F140A\t021E140A\t0003\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


class OsView(unittest.TestCase):
    def test_proc_routes_are_parsed(self):
        r = osview.parse_proc_routes(PROC_ROUTE)
        nets = {x.network: x.gateway for x in r}
        self.assertEqual({"0.0.0.0/0": "10.20.30.1", "10.20.30.0/24": None, "10.20.31.0/24": "10.20.30.2"}, nets)

    def test_routed_network_outside_scope_is_a_candidate_and_the_scope_network_is_not(self):
        r = osview.parse_proc_routes(PROC_ROUTE)
        c = osview.candidate_networks(r, scope_nets=[ipaddress.ip_network(SCOPE)], if_index=None, link_subnet="10.20.30.0/24")
        self.assertEqual([("10.20.31.0/24", "routed")], [(x["cidr"], x["kind"]) for x in c])

    def test_other_adapters_are_ignored(self):
        r = [osview.Route("172.17.0.0/16", None, 9), osview.Route("10.20.31.0/24", "10.20.30.2", 4)]
        c = osview.candidate_networks(r, scope_nets=[ipaddress.ip_network(SCOPE)], if_index=4, link_subnet=None)
        self.assertEqual(["10.20.31.0/24"], [x["cidr"] for x in c])

    def test_proc_arp_parsed(self):
        n = osview.parse_proc_arp("IP address HW type Flags HW address Mask Device\n10.20.30.5 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n")
        self.assertEqual(("10.20.30.5", "aa:bb:cc:dd:ee:ff"), (n[0].ip, n[0].mac))


class Candidates(unittest.TestCase):
    def engine(self):
        scope = ScopeGuard([SCOPE])
        e = Engine(scope, Store(":memory:"), SimpleNamespace(my_ip="10.20.30.2", my_network="10.20.30.0/24"))
        e.ingest = SimpleNamespace(ev=Evidence())
        return scope, e

    def test_routes_and_leaks_become_graded_candidates_and_never_extend_the_scope(self):
        scope, e = self.engine()
        e.os_candidates = [{"cidr": "10.20.31.0/24", "kind": "routed", "gateway": "10.20.30.2", "if_index": 1},
                           {"cidr": "10.20.40.0/24", "kind": "attached", "gateway": None, "if_index": 1}]
        e.ingest.ev.foreign["10.20.77.9"].add("appears in the service output of 10.20.30.5:80")
        e._record_candidates()
        got = {s["cidr"]: s["verdict"] for s in e.store.segments()}
        self.assertEqual("SUSPECTED_NETWORK", got["10.20.31.0/24"])
        self.assertEqual("CONFIRMED_NETWORK", got["10.20.40.0/24"])
        self.assertEqual("UNVERIFIED_CANDIDATE", got["10.20.77.9/32"])
        for s in e.store.segments():
            self.assertEqual("outside-scope", s["kind"])
            self.assertEqual("held", s["state"])
        self.assertEqual([SCOPE], [str(n) for n in scope.networks])
        self.assertFalse(scope.in_scope("10.20.31.5"))

    def test_report_marks_every_outside_candidate_as_not_probed(self):
        scope, e = self.engine()
        e.os_candidates = [{"cidr": "10.20.31.0/24", "kind": "routed", "gateway": "10.20.30.2", "if_index": 1}]
        e._record_candidates()
        corr = correlate.correlate([], Evidence())
        lim = limits.analyse(env={}, questions=[], converged=True, rounds=1, last_gain={}, segments=e.store.segments(), leads=[],
                             decisions=[], stopped={}, catchall=[], held_blocked=0, ipv6_ignored=False)
        r = report.build(scope=[SCOPE], env={}, tuning={"basis": ""}, hosts=[], segments=e.store.segments(), edges=[], leads=[],
                         correlation=corr, limits=lim, decisions=[], timings={}, notes=[], safety={})
        c = r["network_candidates"][0]
        self.assertEqual(("suspected", "OUTSIDE the authorised scope"), (c["status"], c["scope_relation"]))
        self.assertIn("none", c["probing"])
        self.assertEqual({"confirmed": 0, "suspected": 1, "unverified": 0}, r["summary"]["network_candidates"])


class Challenge(unittest.TestCase):
    def host(self, text, field="banner"):
        p = {"port": 80, "proto": "tcp", "banner": None, "scripts": {}}
        if field == "banner":
            p["banner"] = text
        else:
            p["scripts"] = {field: text}
        return [{"ip": "10.20.30.7", "open_ports": [p]}]

    def test_flag_shaped_marker_is_located_and_its_value_withheld(self):
        out = challenge.find_candidates(self.host("welcome flag{this_is_secret_value}"))
        self.assertEqual(1, len(out))
        self.assertEqual("withheld", out[0]["value"])
        self.assertNotIn("this_is_secret_value", str(out))
        self.assertIn("explicit", out[0]["needs"])

    def test_wording_is_recorded_without_a_value(self):
        out = challenge.find_candidates(self.host("Capture The Flag arena", "http-title"))
        self.assertEqual(1, len(out))

    def test_ordinary_banners_are_not_flagged(self):
        self.assertEqual([], challenge.find_candidates(self.host("Apache httpd 2.4 {ok}")))

    def test_rules_default_to_the_most_restrictive_reading(self):
        self.assertFalse(challenge.RULES["official_rules_provided_to_the_probe"])
        self.assertIn("retrieving or reading any flag/artifact", challenge.RULES["requires_explicit_approval"])


class NmapFacts(unittest.TestCase):
    XML = ('<?xml version="1.0"?><nmaprun><host><address addr="10.20.30.5" addrtype="ipv4"/><hostscript>'
           '<script id="smb-os-discovery" output="OS: Windows 10\n  Computer name: LAB-PC\n  FQDN: LAB-PC.lab"/></hostscript>'
           '<os><osmatch name="Linux 5.4" accuracy="97"><osclass type="general purpose"/></osmatch></os></host></nmaprun>')

    def test_hostname_and_os_are_read_from_nmap_output(self):
        h = nmap_tool.parse_hosts(self.XML)["10.20.30.5"]
        self.assertEqual(("LAB-PC.lab", "smb-os-discovery"), (h["hostname"], h["hostname_source"]))
        self.assertEqual(("Linux 5.4", 97, "general purpose"), (h["os"], h["os_accuracy"], h["device_type"]))

    def test_extra_stages_revalidate_every_target_against_scope_and_holds(self):
        scope = ScopeGuard([SCOPE])
        scope.hold("10.20.30.128/25", "held")
        launched = []
        with mock.patch.object(nmap_tool, "find_nmap", return_value="nmap"), \
                mock.patch.object(nmap_tool.fence, "allow_program"), \
                mock.patch.object(nmap_tool, "_run_generic", side_effect=lambda nm, args, *a: (launched.append(args[-1]) or ("", ""))):
            res = nmap_tool.udp_scan(scope, ["10.20.30.5", "10.99.0.5", "10.20.30.200"], workdir="probe-data/test-nmap")
        self.assertEqual(["10.20.30.5"], launched)                       # out-of-scope and held never launched
        self.assertIn("10.99.0.5", res["notrun"])                        # and reported, not silently dropped
        self.assertIn("10.20.30.200", res["notrun"])


class PerFindingEvidence(unittest.TestCase):
    def test_ports_record_method_and_time_and_unidentified_ports_are_marked_as_guesses(self):
        store = Store(":memory:")
        store._x("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.9','t','t')")
        store.add_port("10.20.30.9", 22)
        store.add_port("10.20.30.9", 80)
        store.upsert_service("10.20.30.9", 80, service="http", product="nginx")
        store.label_unidentified_ports(tiers.service_name)
        rows = {r["port"]: r for r in store.query("SELECT * FROM ports")}
        self.assertEqual("ssh?", rows[22]["service"])                    # a guess by number, marked
        self.assertEqual("http", rows[80]["service"])                    # identified: untouched
        self.assertEqual("tcp-syn-probe", rows[22]["method"])
        self.assertTrue(rows[22]["found_at"])

    def test_devices_carry_confidence_segment_and_methods(self):
        host = {"ip": "10.20.30.9", "mac": "02:aa:00:00:00:09", "vendor": None, "os_guess": None, "roles": [],
                "verdict": "CONFIRMED_ONLINK", "open_ports": [], "discovery_methods": ["arp", "icmp-echo"],
                "first_seen": "2026-01-01T00:00:00", "hostname": "lab", "hostname_source": "tls-certificate"}
        corr = correlate.correlate([host], Evidence())
        lim = limits.analyse(env={}, questions=[], converged=True, rounds=1, last_gain={}, segments=[], leads=[], decisions=[],
                             stopped={}, catchall=[], held_blocked=0, ipv6_ignored=False)
        r = report.build(scope=[SCOPE], env={}, tuning={"basis": ""}, hosts=[host], segments=[], edges=[], leads=[],
                         correlation=corr, limits=lim, decisions=[], timings={}, notes=[], safety={})
        d = r["devices"][0]
        self.assertEqual(("confirmed", "lab", ["arp", "icmp-echo"]), (d["confidence"], d["hostname"], d["discovery_methods"]))
        self.assertIn("authorised scope", d["segment"])
        self.assertEqual("2026-01-01T00:00:00", d["first_seen"])


if __name__ == "__main__":
    unittest.main()


class StoreShapes(unittest.TestCase):
    def test_challenge_scan_accepts_scripts_as_stored_json_text(self):
        hosts = [{"ip": "10.20.30.7", "open_ports": [{"port": 80, "proto": "tcp", "banner": None,
                                                      "scripts": '{"http-title": "flag{abcdef}"}'}]}]
        self.assertEqual(1, len(challenge.find_candidates(hosts)))

    def test_a_real_store_round_trip_feeds_the_report_without_error(self):
        store = Store(":memory:")
        store._x("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.7','t','t')")
        store.add_port("10.20.30.7", 80)
        store.upsert_service("10.20.30.7", 80, service="http", scripts={"http-title": "hello"})
        self.assertEqual([], challenge.find_candidates(store.hosts()))


class ChallengeFalsePositives(unittest.TestCase):
    def test_css_and_script_braces_are_not_flags(self):
        for text in ("body{margin:0;padding:0}", "html{font-family:sans-serif}", "function{return value_here}", "div{color_red_blue}"):
            hosts = [{"ip": "10.20.30.7", "open_ports": [{"port": 3000, "banner": None, "scripts": {"x": text}}]}]
            self.assertEqual([], challenge.find_candidates(hosts), text)

    def test_a_real_looking_flag_still_matches(self):
        hosts = [{"ip": "10.20.30.7", "open_ports": [{"port": 80, "banner": None, "scripts": {"http-title": "CTF{w3lcome_to_the_lab}"}}]}]
        self.assertEqual(1, len(challenge.find_candidates(hosts)))


class PlannerTimeGuard(unittest.TestCase):
    def test_a_technique_with_no_time_requirement_runs_even_past_the_budget(self):
        from probe import planner as P2
        pl = P2.Planner(P2.Environment(scope=[], addresses=1, scanner_ip=None, link_subnet=None, gateway_ip=None, gateway_in_scope=False))
        pl.register(P2.Technique("t", "x", lambda: None, lambda e, s: (True, "ok")))
        self.assertTrue(pl.decide("t", P2.State(env=pl.env, remaining_s=-50)))


class NbstatName(unittest.TestCase):
    def test_netbios_name_from_udp_137_becomes_the_hostname(self):
        xml = ('<?xml version="1.0"?><nmaprun><host><address addr="10.20.30.5" addrtype="ipv4"/><ports><port protocol="udp" portid="137">'
               '<state state="open"/><service name="netbios-ns"/><script id="nbstat" output="NetBIOS name: LAB-PC, NetBIOS user: &lt;unknown&gt;"/>'
               '</port></ports></host></nmaprun>')
        self.assertEqual("LAB-PC", nmap_tool.parse_hosts(xml)["10.20.30.5"]["hostname"])
