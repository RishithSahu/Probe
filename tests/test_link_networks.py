"""A scanner whose own interface subnet is wider than the authorised scope shares its link with addresses it must never
probe. Their existence is proven by the OS interface configuration alone, so they are reported as a concealed network.
Run: python -m unittest discover -s tests -v"""
import unittest
from types import SimpleNamespace

from probe.engine import Engine
from probe.scope import ScopeGuard
from probe.store import Store


def engine(scope, my_network):
    e = Engine(ScopeGuard(scope), Store(":memory:"), SimpleNamespace(my_network=my_network))
    return e


class LinkNetworks(unittest.TestCase):
    def test_a_wider_interface_subnet_yields_the_outside_remainder_exactly(self):
        e = engine(["10.20.60.0/24"], "10.20.60.0/22")
        e._record_link_networks()
        segs = {s["cidr"]: s for s in e.store.segments()}
        self.assertEqual({"10.20.61.0/24", "10.20.62.0/23"}, set(segs))
        for s in segs.values():
            self.assertEqual(("outside-scope", "held"), (s["kind"], s["state"]))
            self.assertIn("never probed", s["extra"]["hidden"]["reasons"][0])
        self.assertEqual(2, len([l for l in e.store.leads() if l["source"] == "outside-scope-network"]))

    def test_nothing_is_reported_when_the_scope_covers_the_whole_link(self):
        for scope, link in ((["10.20.60.0/24"], "10.20.60.0/24"), (["10.20.0.0/16"], "10.20.60.0/22"), (["10.20.60.0/24"], None)):
            e = engine(scope, link)
            e._record_link_networks()
            self.assertEqual([], e.store.segments(), (scope, link))

    def test_the_reported_ranges_are_never_inside_the_scope(self):
        scope = ScopeGuard(["10.20.60.0/24"])
        e = engine(["10.20.60.0/24"], "10.20.60.0/22")
        e._record_link_networks()
        for s in e.store.segments():
            self.assertFalse(scope.in_scope(s["cidr"].split("/")[0]), "an outside-scope range overlaps the fence")


if __name__ == "__main__":
    unittest.main()
