"""R8: a service published from a container/VM behind a host answers with TTL-1 while the host's own stack answers with TTL."""
import unittest
from collections import Counter

from probe.analysis import classify as C
from probe.discovery.ingest import Evidence

IP, MAC = "10.20.30.16", "02:aa:00:00:00:16"


def host(own=(64, 64, 64), port_ttls=None, own_kind="tcp-rst"):
    ev = Evidence()
    ev.arp_mac[IP] = MAC
    ev.mac_ips[MAC].add(IP)
    ev.reply_mac[IP].add(MAC)
    ev.visible[IP].update({"arp", "icmp-echo"})
    for t in own:
        ev.ttl_kind[IP][own_kind][t] += 1
        ev.ttls[IP][t] += 1
    for port, ttls in (port_ttls or {}).items():
        ev.ttl_port[IP][port] = Counter(ttls)
    return C.classify_all([IP], ev, gateway_mac="aa:aa:aa:aa:aa:aa")[IP]


class Differential(unittest.TestCase):
    def test_an_open_port_one_hop_shorter_than_the_hosts_own_stack_is_flagged(self):
        c = host(port_ttls={8080: [63, 63, 63]})
        self.assertIn(8080, c.behind_ports)
        self.assertIn("serves-ports-from-behind", c.roles)
        self.assertEqual(C.CONFIRMED_ONLINK, c.verdict)           # the host itself is still on-link

    def test_equal_ttls_are_not_flagged(self):
        self.assertEqual({}, host(port_ttls={8080: [64, 64]}).behind_ports)

    def test_a_single_odd_reply_is_not_enough(self):
        self.assertEqual({}, host(port_ttls={8080: [63]}).behind_ports)

    def test_mixed_port_ttls_are_noise(self):
        self.assertEqual({}, host(port_ttls={8080: [63, 64, 63]}).behind_ports)

    def test_needs_a_reference_ttl_from_the_hosts_own_stack(self):
        self.assertEqual({}, host(own=(), port_ttls={8080: [63, 63]}).behind_ports)

    def test_works_for_other_standard_initial_ttls(self):
        self.assertIn(80, host(own=(128, 128), port_ttls={80: [127, 127]}).behind_ports)
        self.assertEqual({}, host(own=(50, 50), port_ttls={80: [49, 49]}).behind_ports)   # not a standard initial TTL


if __name__ == "__main__":
    unittest.main()
