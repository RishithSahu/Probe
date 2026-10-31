"""The independent auditor must kill the agent for a real out-of-scope probe, and must NOT be fooled by foreign traffic whose
IP-ID happens to equal our 16-bit marker (a live run was killed by exactly that coincidence with ordinary HTTPS traffic).
Run: python -m unittest discover -s tests -v"""
import unittest

from scapy.all import ICMP, IP, TCP, UDP, Ether

from probe.audit import inspect_frame
from probe.discovery.rawprobes import RawProbes, mac_bytes
from probe.net.transport import PROBE_ID

MAC, ME = "02:00:00:00:00:68", "10.20.30.68"
GW = mac_bytes("02:00:00:00:00:01")
BASE = (10 << 24) | (20 << 16) | (30 << 8)


class StrongTag(unittest.TestCase):
    def test_every_genuine_probe_type_is_recognised_as_ours(self):
        rp = RawProbes(MAC, ME)
        frames = [rp.echo(GW, BASE + 5), rp.echo(GW, BASE + 5, ttl=2), rp.timestamp(GW, BASE + 5), rp.mask(GW, BASE + 5),
                  rp.tcp_syn(GW, BASE + 5, 443), rp.tcp_syn(GW, BASE + 5, 80, ttl=2), rp.tcp_ack(GW, BASE + 5, 80),
                  rp.udp(GW, BASE + 5, 40125), rp.fwd_echo(GW, BASE + 5, 1, 9), rp.fwd_tcp_ack(GW, BASE + 5, 80, 2, 4),
                  rp.fwd_tcp_syn(GW, BASE + 5, 22, 1, 3)]
        for f in frames:
            kind, dst = inspect_frame(f)
            self.assertEqual(("probe", BASE + 5), (kind, dst), Ether(f).summary())
        kind, dst = inspect_frame(rp.arp(BASE + 7))
        self.assertEqual(("arp-probe", BASE + 7), (kind, dst))

    def test_a_probe_to_an_outside_address_is_still_reported_with_its_destination(self):
        rp = RawProbes(MAC, ME)
        kind, dst = inspect_frame(rp.tcp_syn(GW, (8 << 24) + 8, 443))           # as if something bypassed the guard
        self.assertEqual("probe", kind)
        self.assertEqual((8 << 24) + 8, dst)

    def test_foreign_traffic_with_the_same_ip_id_is_not_a_probe(self):
        https = bytes(Ether(src=MAC, dst="02:aa:00:00:00:01") / IP(src=ME, dst="160.79.104.10", id=PROBE_ID) /
                      TCP(sport=10672, dport=443, flags="PA"))
        self.assertEqual(("collision", None), inspect_frame(https))
        dns = bytes(Ether(src=MAC, dst="02:aa:00:00:00:01") / IP(src=ME, dst="9.9.9.9", id=PROBE_ID) /
                    UDP(sport=51000, dport=443))
        self.assertEqual(("collision", None), inspect_frame(dns))
        ping = bytes(Ether(src=MAC, dst="02:aa:00:00:00:01") / IP(src=ME, dst="9.9.9.9", id=PROBE_ID) /
                     ICMP(type=8, id=0x1234, seq=1))
        self.assertEqual(("collision", None), inspect_frame(ping))

    def test_traffic_without_our_ip_id_is_simply_other(self):
        f = bytes(Ether(src=MAC, dst="02:aa:00:00:00:01") / IP(src=ME, dst="9.9.9.9", id=1) / TCP(sport=41001, dport=443, flags="S"))
        self.assertEqual(("other", None), inspect_frame(f))


if __name__ == "__main__":
    unittest.main()
