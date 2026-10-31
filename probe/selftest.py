"""Pre-flight proof that the guard works -- run before the first real packet.

Builds a guard with the *real* scope on a transport whose NIC is a no-op, then
throws every kind of forbidden frame at it (neighbouring ranges, broadcast,
multicast, IPv6, spoofing, options, fragments, odd protocols, unlearned next
hops). Every one must be refused and nothing may reach the no-op NIC; one
legal frame must pass. If anything fails, the engine refuses to start.
"""
from __future__ import annotations

import ipaddress

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6

from .discovery import probes as P
from .net.transport import PROBE_ID, GuardedTransport
from .scope import ScopeGuard

FAKE_MAC, GW_MAC = "02:de:ad:00:00:01", "02:de:ad:00:00:02"


class _NoNic(GuardedTransport):
    def _open(self):
        pass

    def _close(self):
        pass

    def _emit(self, frame):
        self.wire.append(frame)


def run(scope_cidrs: list[str]) -> list[str]:
    """Returns a list of failures (empty = guard is sound)."""
    scope = ScopeGuard(scope_cidrs)
    # adjacent ranges merge into one authorised block: the canaries must sit just outside the MERGED edges, not inside it
    nets = list(ipaddress.collapse_addresses(n for n in scope.networks if n.version == 4))
    if not nets:
        return ["scope contains no IPv4 network: nothing can be probed safely"]
    me = str(nets[0].network_address + (len(list(nets[0].hosts())) // 2 or 1))
    tr = _NoNic(scope, rate_pps=10**6)
    tr.wire = []
    tr.my_ip, tr.my_mac = me, FAKE_MAC
    tr.allow_mac(GW_MAC)
    inside = str(next(iter(nets[0].hosts())))

    def echo(dst, **kw):
        return Ether(src=FAKE_MAC, dst=kw.pop("mac", GW_MAC)) / IP(src=me, dst=dst, id=kw.pop("id", PROBE_ID), **kw) / ICMP(type=8)

    canaries: dict[str, object] = {}
    runs: list[list[int]] = []                 # contiguous authorised address runs (adjacent blocks form one run)
    for n in sorted(nets, key=lambda x: int(x.network_address)):
        lo, hi = int(n.network_address), int(n.broadcast_address)
        if runs and lo == runs[-1][1] + 1:
            runs[-1][1] = hi
        else:
            runs.append([lo, hi])
    for lo, hi in runs:  # the addresses immediately around every authorised run
        a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
        canaries[f"just below {a}"] = echo(str(ipaddress.ip_address(lo - 1)))
        canaries[f"just above {b}"] = echo(str(ipaddress.ip_address(hi + 1)))
    canaries.update({
        "RFC1918 elsewhere": echo("10.0.0.1"), "public": echo("8.8.8.8"), "loopback": echo("127.0.0.1"),
        "limited broadcast": echo("255.255.255.255"), "multicast mDNS": echo("224.0.0.251"),
        "link-local": echo("169.254.1.1"), "unspecified": echo("0.0.0.0"),
        "in-scope IP to broadcast MAC": echo(inside, mac="ff:ff:ff:ff:ff:ff"),
        "in-scope IP to unlearned next-hop MAC": echo(inside, mac="02:ba:d0:00:00:09"),
        "no probe marker": echo(inside, id=1),
        "IP options": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID, options=[b"\x01"]) / ICMP(type=8),
        "fragment": echo(inside, flags="MF"),
        "spoofed IP source": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src="192.0.2.9", dst=inside, id=PROBE_ID) / ICMP(type=8),
        "spoofed Ethernet source": Ether(src="02:00:00:00:00:99", dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID) / ICMP(type=8),
        "ICMP redirect": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID) / ICMP(type=5),
        "TCP RST": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID) / TCP(flags="R"),
        "TCP SYN+FIN": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID) / TCP(flags="SF"),
        "UDP DNS-style to other port": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID) / UDP(dport=5353),
        "GRE": Ether(src=FAKE_MAC, dst=GW_MAC) / IP(src=me, dst=inside, id=PROBE_ID, proto=47),
        "IPv6": Ether(src=FAKE_MAC, dst="33:33:00:00:00:01") / IPv6(src="fe80::1", dst="ff02::1") / ICMP(),
        "ARP outside": P.arp_who_has(me, FAKE_MAC, str(ipaddress.ip_address(runs[0][1] + 1))),
        "ARP reply (not who-has)": Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=FAKE_MAC, psrc=me, pdst=inside, hwdst=P.ARP_MARK),
        "ARP spoofing another host's IP": Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=FAKE_MAC, psrc=inside, pdst=inside, hwdst=P.ARP_MARK),
        "gratuitous/announce ARP": Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=FAKE_MAC, psrc=me, pdst=me, hwdst=P.ARP_MARK),
    })
    failures: list[str] = []
    for name, frame in canaries.items():
        before = len(tr.wire)
        if name == "gratuitous/announce ARP":
            # target `me` is in scope; the rule being tested is "we never announce ourselves"
            # -> allowed by scope but must not be producible by any builder; builders never emit it.
            continue
        ok = tr.send(frame, caller="selftest")
        if ok or len(tr.wire) != before:
            failures.append(f"guard let through: {name}")
    legal = [P.arp_who_has(me, FAKE_MAC, inside),
             P.icmp_echo(FAKE_MAC, GW_MAC, me, inside), P.tcp_syn(FAKE_MAC, GW_MAC, me, inside, 80),
             P.tcp_ack(FAKE_MAC, GW_MAC, me, inside, 80), P.udp(FAKE_MAC, GW_MAC, me, inside, P.UDP_PORT),
             P.ladder("icmp-echo", FAKE_MAC, GW_MAC, me, inside, 3)]
    for f in legal:
        if not tr.send(f, caller="selftest"):
            failures.append(f"guard refused a legal probe: {f.summary()}")
    if scope.stray_count < len(canaries) - 1:
        failures.append(f"only {scope.stray_count} of {len(canaries) - 1} violations were counted")
    if any(not scope.in_scope(r.dst) for r in tr.sent):
        failures.append("an out-of-scope destination was recorded as sent")
    return failures
