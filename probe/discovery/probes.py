"""Frame builders. Pure functions -- they only construct packets; sending is
GuardedTransport's job and nothing here can reach the wire.

Probe identity is encoded in header fields we control so a reply (or an ICMP
error quoting our probe) can be matched back without keeping per-probe state:
  * ICMP id  = probe family, ICMP seq = target's low 16 bits (liveness) or the TTL (ladder)
  * TCP/UDP source port 41000+ = liveness, 42000+ttl = TTL-ladder probe
  * IP-ID    = PROBE_ID on every IP packet (lets the external auditor recognise our traffic)
  * ARP target-hw-address = ARP_MARK on every ARP who-has (same reason)
"""
from __future__ import annotations

import ipaddress
import struct

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw

from ..net.transport import PROBE_ID

ID_ECHO = 0x5001
ID_TS = 0x5003
ID_MASK = 0x5004
ID_LADDER = 0x5010          # echo ladder
ID_LADDER_TS = 0x5011       # timestamp ladder
ID_LADDER_MASK = 0x5012
LADDER_IDS = {ID_LADDER, ID_LADDER_TS, ID_LADDER_MASK}
SPORT_SYN = 41000           # 41000..41499
SPORT_ACK = 41500           # 41500..41999
LADDER_SPORT = 42000        # 42000+ttl
UDP_PORT = 40125            # a port nothing listens on: a live host answers ICMP port-unreachable
UDP_PORTS = (UDP_PORT, 53)
BROADCAST = "ff:ff:ff:ff:ff:ff"
ARP_MARK = "02:50:52:42:00:01"


def low16(ip: str) -> int:
    return int(ipaddress.ip_address(ip)) & 0xFFFF


def arp_who_has(my_ip: str, my_mac: str, target: str):
    return Ether(src=my_mac, dst=BROADCAST) / ARP(op=1, hwsrc=my_mac, psrc=my_ip, hwdst=ARP_MARK, pdst=target)


def _ip(my_ip: str, dst: str, ttl: int) -> IP:
    return IP(src=my_ip, dst=dst, ttl=ttl, id=PROBE_ID, flags=0)


def icmp_echo(my_mac, dst_mac, my_ip, dst, *, ttl=64):
    return Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, ttl) / ICMP(type=8, id=ID_ECHO, seq=low16(dst))


def icmp_timestamp(my_mac, dst_mac, my_ip, dst):
    return Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, 64) / ICMP(type=13, id=ID_TS, seq=low16(dst))


def icmp_mask(my_mac, dst_mac, my_ip, dst):
    return Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, 64) / ICMP(type=17, id=ID_MASK, seq=low16(dst))


def tcp_syn(my_mac, dst_mac, my_ip, dst, dport, *, idx=0):
    return (Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, 64)
            / TCP(sport=SPORT_SYN + (idx % 500), dport=dport, flags="S", seq=0x50524F42 + dport))


def tcp_ack(my_mac, dst_mac, my_ip, dst, dport, *, idx=0):
    return (Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, 64)
            / TCP(sport=SPORT_ACK + (idx % 500), dport=dport, flags="A", seq=0x50524F42, ack=1))


def udp(my_mac, dst_mac, my_ip, dst, dport, *, idx=0):
    return Ether(src=my_mac, dst=dst_mac) / _ip(my_ip, dst, 64) / UDP(sport=SPORT_SYN + (idx % 500), dport=dport)


def ladder(kind: str, my_mac, dst_mac, my_ip, dst, ttl: int, port: int = 0):
    """One rung of a TTL ladder, using whatever protocol this host already
    proved it answers. The probe's TTL is recoverable from the reply (ICMP seq
    / TCP dport) *and* from any ICMP error that quotes it."""
    e, i = Ether(src=my_mac, dst=dst_mac), _ip(my_ip, dst, ttl)
    if kind == "icmp-echo":  # payload carries the target's low 16 bits: a reply from another address = second interface
        return e / i / ICMP(type=8, id=ID_LADDER, seq=ttl) / Raw(struct.pack("!H", low16(dst)))
    if kind == "icmp-timestamp":
        return e / i / ICMP(type=13, id=ID_LADDER_TS, seq=ttl)
    if kind == "icmp-mask":
        return e / i / ICMP(type=17, id=ID_LADDER_MASK, seq=ttl)
    if kind in ("tcp-syn", "tcp-rst"):
        return e / i / TCP(sport=LADDER_SPORT + ttl, dport=port, flags="S", seq=0x50524F42 + ttl)
    if kind == "tcp-ack":
        return e / i / TCP(sport=LADDER_SPORT + ttl, dport=port, flags="A", seq=0x50524F42, ack=1)
    if kind == "udp-unreach":
        return e / i / UDP(sport=LADDER_SPORT + ttl, dport=port or UDP_PORT)
    raise ValueError(kind)


# Preference order when choosing the ladder protocol for a host: cheapest, most reliable first.
LADDER_PREFERENCE = ("icmp-echo", "tcp-syn", "tcp-rst", "tcp-ack", "udp-unreach", "icmp-timestamp", "icmp-mask")
