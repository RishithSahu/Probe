"""A service whose banner names one OS on a host whose TCP/IP stack looks like another is probably hosted behind the host."""
import unittest
from types import SimpleNamespace

from probe.discovery.ingest import Evidence
from probe.engine import Engine
from probe.scope import ScopeGuard
from probe.store import Store


def engine(ttls):
    e = Engine(ScopeGuard(["10.20.30.0/24"]), Store(":memory:"), SimpleNamespace(my_network=None))
    e.ingest = SimpleNamespace(ev=Evidence())
    for ip, ttl in ttls.items():
        e.ingest.ev.ttls[ip][ttl] += 1
    return e


def rec(ip, product, title=""):
    return {"ip": ip, "port": 8080, "product": product, "extrainfo": "(Debian)" if "Apache" in product else None,
            "banner": None, "scripts": {"http-title": title} if title else {}}


class Mismatch(unittest.TestCase):
    def test_linux_service_on_a_windows_stack_is_flagged_as_suspected(self):
        e = engine({"10.20.30.16": 128})
        e._service_os_mismatch([rec("10.20.30.16", "Apache httpd")])
        leads = [l for l in e.store.leads() if l["source"] == "anomaly:service-behind-host"]
        self.assertEqual(1, len(leads))
        self.assertIn("Suspected, not proven", leads[0]["evidence"])

    def test_matching_os_is_not_flagged(self):
        e = engine({"10.20.30.20": 64})
        e._service_os_mismatch([rec("10.20.30.20", "Apache httpd")])
        self.assertEqual([], e.store.leads())

    def test_windows_service_on_a_linux_stack_is_flagged_too(self):
        e = engine({"10.20.30.21": 64})
        e._service_os_mismatch([rec("10.20.30.21", "Microsoft IIS httpd")])
        self.assertEqual(1, len(e.store.leads()))

    def test_no_ttl_means_no_claim(self):
        e = engine({})
        e._service_os_mismatch([rec("10.20.30.22", "Apache httpd")])
        self.assertEqual([], e.store.leads())


if __name__ == "__main__":
    unittest.main()
