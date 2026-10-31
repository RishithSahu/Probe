"""Byte-level probe builders: ~5 microseconds per frame instead of ~150 with scapy objects.

These produce the same wire format and the same identity encoding as probes.py (ICMP id/seq, TCP/UDP
source port, IP-ID marker, ARP marker), so the ingest layer decodes replies unchanged. Nothing here sends:
frames go to GuardedTransport.send_raw(), which re-validates the exact bytes before the NIC sees them.

Encoding (see probes.py for the scapy twins):
  direct probes (TTL 64, addressed to a host's own MAC)   ICMP id ID_ECHO,   TCP/UDP sport 41000..41999
  leash rungs   (TTL <= 16, via a router)                 ICMP id ID_LADDER, TCP/UDP sport 42000 + ttl
  forwarder / pivot probes (addressed to another host's MAC with a *different* destination IP)
                                                          ICMP id ID_FWD, seq = table index; TCP sport 43000 + index
"""
from __future__ import annotations

import struct

from ..net.transport import ARP_MARK, PROBE_ID
from .probes import (ID_ECHO, ID_LADDER, ID_LADDER_MASK, ID_LADDER_TS, ID_MASK, ID_TS, LADDER_SPORT, SPORT_ACK,
                     SPORT_SYN)

ID_FWD = 0x5020
FWD_SPORT = 43000                  # 43000 + index (index < 3000)
FWD_SPORT_MAX = 45999
MAX_LADDER_TTL = 16

_H_IP = struct.Struct("!BBHHHBBH4s4s")
_H_TCP = struct.Struct("!HHIIBBHHH")
_H_UDP = struct.Struct("!HHHH")
_H_ARP = struct.Struct("!HHBBH6s4s6s4s")
_PSEUDO = struct.Struct("!4s4sBBH")
BROADCAST_B = b"\xff" * 6
ARP_MARK_B = bytes.fromhex(ARP_MARK.replace(":", ""))


def csum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) >> 1), data))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


class RawProbes:
    def __init__(self, my_mac: str, my_ip: str):
        self.mac = mac_bytes(my_mac)
        self.ip_i = int.from_bytes(bytes(map(int, my_ip.split("."))), "big")
        self.ip_b = self.ip_i.to_bytes(4, "big")
        self._eth_arp = BROADCAST_B + self.mac + b"\x08\x06"

    # ---- helpers ------------------------------------------------------------------------------
    def _ip(self, dst_ip: int, ttl: int, proto: int, payload_len: int) -> bytes:
        dst = dst_ip.to_bytes(4, "big")
        hdr = _H_IP.pack(0x45, 0, 20 + payload_len, PROBE_ID, 0, ttl, proto, 0, self.ip_b, dst)
        return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]

    def _frame(self, dst_mac: bytes, dst_ip: int, ttl: int, proto: int, l4: bytes) -> bytes:
        return dst_mac + self.mac + b"\x08\x00" + self._ip(dst_ip, ttl, proto, len(l4)) + l4

    # ---- ARP ----------------------------------------------------------------------------------
    def arp(self, target_ip: int) -> bytes:
        body = _H_ARP.pack(1, 0x0800, 6, 4, 1, self.mac, self.ip_b, ARP_MARK_B, target_ip.to_bytes(4, "big"))
        return (self._eth_arp + body).ljust(60, b"\x00")

    # ---- ICMP ---------------------------------------------------------------------------------
    def _icmp(self, dst_mac, dst_ip, ttl, typ, ident, seq, extra=b"") -> bytes:
        head = struct.pack("!BBHHH", typ, 0, 0, ident, seq) + extra
        icmp = head[:2] + struct.pack("!H", csum(head)) + head[4:]
        return self._frame(dst_mac, dst_ip, ttl, 1, icmp)

    def echo(self, dst_mac: bytes, dst_ip: int, ttl: int = 64) -> bytes:
        """Echo request. The payload carries the target's low 16 bits: a reply from a different address
        reveals a second interface of the same device."""
        pay = struct.pack("!H", dst_ip & 0xFFFF)
        if ttl <= MAX_LADDER_TTL:
            return self._icmp(dst_mac, dst_ip, ttl, 8, ID_LADDER, ttl, pay)
        return self._icmp(dst_mac, dst_ip, ttl, 8, ID_ECHO, dst_ip & 0xFFFF, pay)

    def timestamp(self, dst_mac: bytes, dst_ip: int, ttl: int = 64) -> bytes:
        ident, seq = (ID_LADDER_TS, ttl) if ttl <= MAX_LADDER_TTL else (ID_TS, dst_ip & 0xFFFF)
        return self._icmp(dst_mac, dst_ip, ttl, 13, ident, seq, b"\x00" * 12)

    def mask(self, dst_mac: bytes, dst_ip: int, ttl: int = 64) -> bytes:
        ident, seq = (ID_LADDER_MASK, ttl) if ttl <= MAX_LADDER_TTL else (ID_MASK, dst_ip & 0xFFFF)
        return self._icmp(dst_mac, dst_ip, ttl, 17, ident, seq, b"\x00" * 4)

    def fwd_echo(self, via_mac: bytes, third_ip: int, ttl: int, index: int) -> bytes:
        """Echo addressed to `via_mac` but destined for `third_ip`: asks "do you forward?"."""
        return self._icmp(via_mac, third_ip, ttl, 8, ID_FWD, index, struct.pack("!H", third_ip & 0xFFFF))

    # ---- TCP / UDP ----------------------------------------------------------------------------
    def _tcp(self, dst_mac, dst_ip, ttl, sport, dport, flags, seq, ack, mss: bool) -> bytes:
        opts = b"\x02\x04\x05\xb4" if mss else b""
        off = (5 + len(opts) // 4) << 4
        hdr = _H_TCP.pack(sport, dport, seq & 0xFFFFFFFF, ack, off, flags, 1024, 0, 0) + opts
        pseudo = _PSEUDO.pack(self.ip_b, dst_ip.to_bytes(4, "big"), 0, 6, len(hdr))
        tcp = hdr[:16] + struct.pack("!H", csum(pseudo + hdr)) + hdr[18:]
        return self._frame(dst_mac, dst_ip, ttl, 6, tcp)

    @staticmethod
    def _sport(ttl: int, idx: int, base: int) -> int:
        return LADDER_SPORT + ttl if ttl <= MAX_LADDER_TTL else base + (idx % 500)

    def tcp_syn(self, dst_mac, dst_ip, dport, ttl=64, idx=0) -> bytes:
        return self._tcp(dst_mac, dst_ip, ttl, self._sport(ttl, idx, SPORT_SYN), dport, 0x02,
                         0x50524F42 + dport, 0, True)

    def tcp_ack(self, dst_mac, dst_ip, dport, ttl=64, idx=0) -> bytes:
        return self._tcp(dst_mac, dst_ip, ttl, self._sport(ttl, idx, SPORT_ACK), dport, 0x10, 0x50524F42, 1, False)

    def fwd_tcp_syn(self, via_mac, third_ip, dport, ttl, index) -> bytes:
        return self._tcp(via_mac, third_ip, ttl, FWD_SPORT + index, dport, 0x02, 0x50524F42 + dport, 0, True)

    def fwd_tcp_ack(self, via_mac, third_ip, dport, ttl, index) -> bytes:
        return self._tcp(via_mac, third_ip, ttl, FWD_SPORT + index, dport, 0x10, 0x50524F42, 1, False)

    def udp(self, dst_mac, dst_ip, dport, ttl=64, idx=0) -> bytes:
        sport = self._sport(ttl, idx, SPORT_SYN)
        hdr = _H_UDP.pack(sport, dport, 8, 0)
        pseudo = _PSEUDO.pack(self.ip_b, dst_ip.to_bytes(4, "big"), 0, 17, 8)
        udp = hdr[:6] + struct.pack("!H", csum(pseudo + hdr) or 0xFFFF)
        return self._frame(dst_mac, dst_ip, ttl, 17, udp)
