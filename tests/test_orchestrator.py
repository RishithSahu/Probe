"""Orchestrator: no missed events, one task per finding, scope enforced when creating AND leasing, nothing silently dropped."""
import time
import unittest
from types import SimpleNamespace

from probe.engine import Engine
from probe.orchestrator import MAX_ATTEMPTS, Orchestrator, specialist_for
from probe.scope import ScopeGuard
from probe.store import Store

SCOPE = "10.20.30.0/24"


def setup():
    store = Store(":memory:")
    scope = ScopeGuard([SCOPE])
    return store, scope, Orchestrator(store, scope)


def svc_event(store, ip, port, service, product=None, type_="service.discovered"):
    return store.add_event(type_, {"ip": ip, "port": port, "proto": "tcp", "service": service, "product": product})


class Routing(unittest.TestCase):
    def test_services_go_to_the_matching_specialist(self):
        self.assertEqual("web", specialist_for("http"))
        self.assertEqual("ssh", specialist_for("ssh"))
        self.assertEqual("database", specialist_for("mysql"))
        self.assertEqual("web", specialist_for(None, 8080))
        self.assertEqual("service-generic", specialist_for("weirdproto"))


class Delivery(unittest.TestCase):
    def test_every_event_is_consumed_in_order_and_the_cursor_advances(self):
        store, _scope, o = setup()
        for i in range(1, 8):
            svc_event(store, f"10.20.30.{i}", 80, "http")
        self.assertEqual(7, o.consume(page=3))                 # paged: nothing lost at page boundaries
        self.assertEqual(0, o.consume())
        self.assertEqual(7, o.status()["tasks"])

    def test_a_failing_handler_does_not_skip_the_event(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 80, "http")
        real, calls = o._handle, {"n": 0}

        def flaky(ev):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return real(ev)
        o._handle = flaky
        self.assertEqual(0, o.consume())                       # failed: cursor must NOT move
        self.assertEqual(1, o.consume())                       # redelivered and handled
        self.assertEqual(1, o.status()["tasks"])

    def test_cursor_survives_a_rescan_reset(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 80, "http")
        o.consume()
        store.reset()
        self.assertEqual(1, o._cursor())


class Dedupe(unittest.TestCase):
    def test_the_same_finding_twice_is_one_task(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 80, "http")
        svc_event(store, "10.20.30.5", 80, "http")
        o.consume()
        self.assertEqual(1, o.status()["tasks"])

    def test_a_later_identification_supersedes_the_generic_task(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 9999, None)
        o.consume()
        svc_event(store, "10.20.30.5", 9999, "mysql", type_="service.updated")
        o.consume()
        rows = {r["key"]: r["status"] for r in store.query("SELECT key, status FROM tasks")}
        self.assertEqual("superseded", rows["service-generic:10.20.30.5:9999/tcp"])
        self.assertEqual("pending", rows["database:10.20.30.5:9999/tcp"])


class ScopeEnforcement(unittest.TestCase):
    def test_no_task_is_created_for_an_out_of_scope_address(self):
        store, _scope, o = setup()
        svc_event(store, "10.99.0.5", 80, "http")
        o.consume()
        self.assertEqual(0, o.status()["tasks"])
        self.assertTrue(any(e["type"] == "task.refused" for e in store.events_since(0)))

    def test_no_task_for_a_held_address_and_none_leased_after_a_hold(self):
        store, scope, o = setup()
        svc_event(store, "10.20.30.5", 80, "http")
        o.consume()
        scope.hold("10.20.30.0/28", "found separate")
        self.assertIsNone(o.lease("web", "agent-1"))           # re-checked at lease time
        self.assertEqual(1, len(o.status()["failed"]))

    def test_a_discovered_network_never_becomes_a_task_that_can_be_leased(self):
        store, _scope, o = setup()
        store.add_event("network.candidate", {"cidr": "10.77.0.0/24", "status": "UNVERIFIED_CANDIDATE", "evidence": "x"})
        o.consume()
        self.assertIsNone(o.lease("network-structure", "a"))
        self.assertEqual(["network-structure:10.77.0.0/24"], o.status()["blocked"])

    def test_challenge_artifact_tasks_need_a_human_approval(self):
        store, _scope, o = setup()
        store.add_event("lead.recorded", {"source": "challenge-artifact", "address": "10.20.30.7:80", "shape": "x{..}"})
        o.consume()
        self.assertIsNone(o.lease("challenge-artifact", "agent"))
        o.approve("challenge-artifact:10.20.30.7:80", "operator")
        self.assertIsNotNone(o.lease("challenge-artifact", "agent"))


class Tracking(unittest.TestCase):
    def test_lease_complete_and_failure_retry(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 22, "ssh")
        o.consume()
        t = o.lease("ssh", "a1")
        self.assertEqual("ssh:10.20.30.5:22/tcp", t["key"])
        self.assertIsNone(o.lease("ssh", "a2"))                # leased: nobody else gets it
        self.assertFalse(o.complete(t["key"], "a2")["ok"])     # only the holder completes
        self.assertEqual("pending", o.complete(t["key"], "a1", ok=False)["status"])   # failed once: retry
        for _ in range(MAX_ATTEMPTS - 1):
            t = o.lease("ssh", "a1")
            r = o.complete(t["key"], "a1", ok=False)
        self.assertEqual("failed", r["status"])
        self.assertEqual(1, len(o.status()["failed"]))

    def test_an_expired_lease_is_offered_again(self):
        store, _scope, o = setup()
        svc_event(store, "10.20.30.5", 22, "ssh")
        o.consume()
        o.lease("ssh", "a1", ttl_s=0.01)
        time.sleep(0.05)
        self.assertIsNotNone(o.lease("ssh", "a2"))

    def test_sync_rebuilds_tasks_from_the_store_without_events(self):
        store, _scope, o = setup()
        store.add_port("10.20.30.9", 443, service="https")
        store._x("INSERT OR IGNORE INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.9','t','t')")
        self.assertEqual(1, o.sync())
        self.assertEqual(0, o.sync())                          # idempotent


class Announce(unittest.TestCase):
    def engine(self, store):
        e = Engine(ScopeGuard([SCOPE]), store, SimpleNamespace(my_ip="10.20.30.2", my_network=None))
        e._scan_id = 1
        return e

    def test_each_finding_is_announced_once_and_improvements_as_updates(self):
        store = Store(":memory:")
        store._x("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.9','t','t')")
        store.add_port("10.20.30.9", 80)
        e = self.engine(store)
        e._announce()
        e._announce()                                          # nothing changed: no duplicate events
        types = [x["type"] for x in store.events_since(0)]
        self.assertEqual(1, types.count("host.discovered"))
        self.assertEqual(1, types.count("service.discovered"))
        store.upsert_service("10.20.30.9", 80, service="http", product="nginx", version="1.2")
        e._announce()
        self.assertEqual(1, [x["type"] for x in store.events_since(0)].count("service.updated"))

    def test_upserting_the_same_service_twice_is_one_record(self):
        store = Store(":memory:")
        store._x("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.9','t','t')")
        store.add_port("10.20.30.9", 80)
        store.upsert_service("10.20.30.9", 80, service="http")
        store.upsert_service("10.20.30.9", 80, service="http")
        rows = store.query("SELECT * FROM ports WHERE host_ip='10.20.30.9'")
        self.assertEqual(1, len(rows))
        self.assertEqual("tcp-syn-probe+nmap-service-detection", rows[0]["method"])


if __name__ == "__main__":
    unittest.main()


class Stale(unittest.TestCase):
    def test_tasks_for_endpoints_that_left_the_inventory_are_retired_not_offered(self):
        store, _scope, o = setup()
        store._x("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.20.30.9','t','t')")
        store.add_port("10.20.30.9", 80, service="http")
        svc_event(store, "10.20.30.9", 80, "http")
        svc_event(store, "10.20.30.8", 22, "ssh")                  # this host is gone from the latest inventory
        o.consume()
        o.sync()
        self.assertIsNone(o.lease("ssh", "a"))
        self.assertIsNotNone(o.lease("web", "a"))
        self.assertEqual("stale", store.query("SELECT status FROM tasks WHERE key='ssh:10.20.30.8:22/tcp'")[0]["status"])

    def test_a_withdrawn_challenge_sighting_is_retired(self):
        store, _scope, o = setup()
        store.add_event("lead.recorded", {"source": "challenge-artifact", "address": "10.20.30.7:80", "shape": "x"})
        o.consume()
        store.set_meta("report", {"challenge_artifact_candidates": []})     # the latest report no longer contains it
        o._retire_stale(set())
        self.assertEqual("stale", store.query("SELECT status FROM tasks WHERE key LIKE 'challenge-artifact:%'")[0]["status"])
