"""GuardedTransport -- the one and only place a frame can leave this process.

There is exactly ONE guard, and it judges the exact bytes about to be written to the NIC (not scapy fields,
which can be lazy, symbolic or overridden). Scapy packets are converted to bytes first, so every path --
the fast byte-level engine and the object-based tests -- goes through the same check. A frame is sent only if
ALL of these hold; anything else is refused, counted and trips the kill switch (fail closed):

  * Ethernet source is our own MAC; nothing is spoofed.
  * ARP: a who-has from our own MAC/IP, to the broadcast MAC, asking about an in-scope address, carrying our
    marker. Never replies, never gratuitous ARP.
  * IPv4 only: our source address, destination in scope and not held (for deep probes), no IP options, not
    fragmented, our probe marker, no broadcast/multicast, and the destination MAC is a next hop we *learned
    from an in-scope ARP answer* (so a frame can never be steered to an out-of-scope gateway).
  * Protocol whitelist: ICMP echo/timestamp/mask request; TCP SYN or ACK; UDP to two whitelisted ports.
    No IPv6, no DNS, no multicast joins.
  * A global packet budget derived from the scope size.
  * Territory (still inside the permitted network) and, optionally, an independent auditor's attestation.

Listening is libpcap/Npcap capture with a BPF filter for frames addressed to us (plus DHCP for enrichment): it
transmits nothing and joins no multicast group (no IGMP).
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Callable

from ..scope import ScopeGuard

logger = logging.getLogger("probe.net")

PROBE_ID = 0x5052  # IP-ID on every IP probe ("PR"): lets the external auditor recognise our traffic
ARP_MARK = "02:50:52:42:00:01"
BROADCAST = "ff:ff:ff:ff:ff:ff"
ALLOWED_ICMP_TYPES = {8, 13, 17}
ALLOWED_UDP_PORTS = {40125, 53}
MAX_PAYLOAD = 64

_PROBE_ID_B = PROBE_ID.to_bytes(2, "big")
_ARP_MARK_B = bytes.fromhex(ARP_MARK.replace(":", ""))
_BCAST_B = b"\xff" * 6


class SentRecord:
    __slots__ = ("t", "dst_int", "kind", "caller", "deep")

    def __init__(self, t: float, dst_int: int, kind: str, caller: str, deep: bool):
        self.t, self.dst_int, self.kind, self.caller, self.deep = t, dst_int, kind, caller, deep

    @property
    def dst(self) -> str:
        return str(ipaddress.ip_address(self.dst_int))


class GuardedTransport:
    def __init__(self, scope: ScopeGuard, *, iface: str | None = None, rate_pps: int = 400,
                 on_packet: Callable | None = None, kill=None, max_packets: int | None = None,
                 attest: Callable[[], tuple[bool, str]] | None = None, territory=None):
        self.scope = scope
        self.kill = kill  # probe.killswitch.KillSwitch | None
        if kill is not None:
            scope.stray_hook = lambda ip, caller: kill.trip(ip, caller, "blocked before send")
            kill.register_closer(self._close)
        self.iface = iface
        self.rate_pps = max(1, rate_pps)
        self._gap = 1.0 / self.rate_pps
        self.on_packet = on_packet
        self.attest = attest
        self.territory = territory          # probe.territory.Territory | None; set after prepare()
        self.if_index: int | None = None
        self.max_packets = max_packets
        self.my_ip: str | None = None
        self.my_mac: str | None = None
        self.gateway_ip: str | None = None
        self.my_network: str | None = None   # the scanner NIC's own subnet (may be wider than the scope)
        self.sent: list[SentRecord] = []
        self.allowed_macs: set[str] = set()
        self._allowed_b: set[bytes] = set()
        self.refused_budget = 0
        self.tx_errors = 0
        self._lock = threading.Lock()
        self._next_slot = 0.0
        self._sock = None
        self._sniffer = None
        self._prepared = False
        self._attest_cache = (0.0, True, "")
        self._territory_cache = (0.0, True, "")
        self._const_key = None
        self._mac_b = b""
        self._ip_b = b""

    # ---- lifecycle ----------------------------------------------------------
    def prepare(self) -> None:
        """Pick the interface. Sends nothing -- lets the auditor attach before the first probe."""
        if not self._prepared:
            self._pick_interface()
            self._prepared = True

    def start(self) -> None:
        self.prepare()
        self._open()

    def stop(self) -> None:
        self._close()

    def set_rate(self, pps: int) -> None:
        self.rate_pps = max(1, int(pps))
        self._gap = 1.0 / self.rate_pps

    def allow_mac(self, mac: str) -> None:
        """Only ever called with a MAC that answered ARP for an in-scope address."""
        m = mac.lower()
        self.allowed_macs.add(m)
        self._allowed_b.add(bytes.fromhex(m.replace(":", "")))

    def _bpf(self) -> str:
        # frames addressed to us (replies to probes) + DHCP (optional enrichment); everything else is never dissected
        return f"ether dst {self.my_mac} or (udp and (port 67 or port 68))"

    def _open(self) -> None:  # pragma: no cover - needs a NIC
        from scapy.all import AsyncSniffer, conf
        conf.verb = 0
        conf.sniff_promisc = False                    # we only want frames addressed to us: no promiscuous load
        # the sending handle must not pile up captured frames nobody reads: give it a filter that matches nothing
        self._sock = conf.L2socket(iface=self.iface, promisc=False, filter="ether host 00:00:00:00:00:01")
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._rx, store=False, filter=self._bpf())
        self._sniffer.start()
        time.sleep(0.4)

    def _close(self) -> None:  # pragma: no cover
        for obj, fn in ((self._sniffer, "stop"), (self._sock, "close")):
            try:
                if obj is not None:
                    getattr(obj, fn)()
            except Exception:
                pass

    def _pick_interface(self) -> None:  # pragma: no cover
        from scapy.all import conf
        chosen = None
        for ifc in conf.ifaces.values():
            ip = getattr(ifc, "ip", None)
            if not ip or ip in ("0.0.0.0", "127.0.0.1"):
                continue
            if self.iface and self.iface not in (ifc.name, getattr(ifc, "description", ""), ifc.network_name):
                continue
            if self.scope.in_scope(ip):          # even with --iface: the scanner itself must be inside the scope
                chosen = ifc
                break
        if chosen is None:
            from ..territory import TerritoryError
            raise TerritoryError("WRONG RANGE: no network interface on this machine has an address inside the "
                                 f"permitted scope {[str(n) for n in self.scope.networks]}. The probe will not run here.")
        self.iface = chosen.network_name if hasattr(chosen, "network_name") else chosen.name
        self.my_ip, self.my_mac = chosen.ip, chosen.mac
        self.if_index = getattr(chosen, "index", None)
        try:  # the NIC's own subnet, e.g. a /22 around a /24 scope: longest on-link prefix (< /32) containing our IP
            me, best = ipaddress.ip_address(self.my_ip), None
            for net, msk, gw, _ifname, addr, _metric in conf.route.routes:
                if gw != "0.0.0.0" or not (0 < msk < 0xFFFFFFFF):
                    continue
                cand = ipaddress.ip_network(f"{ipaddress.ip_address(net)}/{bin(msk).count('1')}", strict=False)
                if me in cand and not cand.is_multicast and (best is None or cand.prefixlen > best.prefixlen):
                    best = cand
            self.my_network = str(best) if best else None
        except Exception:
            pass
        try:
            gw = conf.route.route("0.0.0.0")[2]
            self.gateway_ip = gw if gw and gw != "0.0.0.0" else None
        except Exception:
            self.gateway_ip = None
        logger.info("interface=%s ip=%s mac=%s gateway=%s", self.iface, self.my_ip, self.my_mac, self.gateway_ip)

    # ---- receive ---------------------------------------------------------------------
    def _egress_watchdog(self, pkt) -> None:
        """Belt and braces for frames that happen to be captured: a frame carrying our marker, leaving our MAC
        for an out-of-scope address, means something bypassed the guard. (The independent auditor process does
        the real wire watching; this only fires if our own egress is ever fed back to the sniffer.)"""
        from scapy.all import ARP, IP, Ether
        if self.kill is None or not pkt.haslayer(Ether) or not self.my_mac:
            return
        if pkt[Ether].src.lower() != self.my_mac.lower():
            return
        if pkt.haslayer(IP) and pkt[IP].id == PROBE_ID and not self.scope.in_scope(pkt[IP].dst):
            self.kill.trip(pkt[IP].dst, "egress-watchdog", "frame seen on the wire")
        elif pkt.haslayer(ARP) and pkt[ARP].hwdst.lower() == ARP_MARK and not self.scope.in_scope(pkt[ARP].pdst):
            self.kill.trip(pkt[ARP].pdst, "egress-watchdog", "ARP seen on the wire")

    def _rx(self, pkt) -> None:
        self._egress_watchdog(pkt)
        if self.on_packet is not None:
            try:
                self.on_packet(pkt)
            except Exception:  # a parser bug must not kill the sniffer
                logger.exception("packet handler failed")

    def _emit(self, raw: bytes) -> None:  # pragma: no cover - needs a NIC
        from ..fence import authorized_send
        with authorized_send():          # the only place the process fence lets a frame leave
            rc = self._sock.send(raw)
        if rc is not None and rc < 0:            # pcap_inject returns bytes written, -1 on failure (e.g. driver queue full)
            self.tx_errors += 1

    # ---- the guard ---------------------------------------------------------------------
    def _consts(self) -> None:
        key = (self.my_ip, self.my_mac)
        if key != self._const_key:
            self._mac_b = bytes.fromhex((self.my_mac or "").replace(":", ""))
            self._ip_b = bytes(map(int, (self.my_ip or "0.0.0.0").split(".")))
            self._const_key = key

    def _check_raw(self, raw: bytes) -> tuple[int | None, str]:
        """(destination as int, kind) if the exact bytes are something we may send, else (None, reason)."""
        n = len(raw)
        if n < 42 or n > 128:
            return None, "bad-length"
        if raw[6:12] != self._mac_b:
            return None, "spoofed-ethernet-source"
        et = raw[12:14]
        if et == b"\x08\x06":                                          # ---- ARP
            if n > 60 or raw[14:20] != b"\x00\x01\x08\x00\x06\x04" or raw[20:22] != b"\x00\x01":
                return None, "arp-not-our-own-who-has"
            if raw[22:28] != self._mac_b or raw[28:32] != self._ip_b:
                return None, "arp-not-our-own-who-has"
            if raw[0:6] != _BCAST_B or raw[32:38] != _ARP_MARK_B:
                return None, "arp-malformed"
            return int.from_bytes(raw[38:42], "big"), "arp"
        if et != b"\x08\x00":
            return None, "not-ip-or-arp"
        if raw[14] != 0x45:                                              # ---- IPv4, header length 5 (no options)
            return None, "ip-options-or-not-v4"
        if raw[0] & 1:
            return None, "ip-to-broadcast-or-multicast-mac"
        if raw[0:6] not in self._allowed_b:
            return None, "next-hop-mac-not-learned-from-in-scope-arp"
        if raw[26:30] != self._ip_b:
            return None, "ip-not-ours"
        if raw[18:20] != _PROBE_ID_B:
            return None, "missing-probe-marker"
        if (raw[20] & 0x3F) or raw[21]:
            return None, "ip-options-or-fragment"
        totlen = (raw[16] << 8) | raw[17]
        if totlen < 28 or totlen + 14 > n or totlen - 20 > MAX_PAYLOAD + 24:
            return None, "bad-ip-length"
        proto = raw[23]
        if proto == 1:
            if raw[34] not in ALLOWED_ICMP_TYPES or raw[35] != 0:
                return None, "icmp-type-not-whitelisted"
        elif proto == 6:
            doff = raw[46] >> 4
            if doff not in (5, 6) or raw[47] not in (0x02, 0x10) or totlen != 20 + doff * 4:
                return None, "tcp-flags-not-whitelisted"
        elif proto == 17:
            if ((raw[36] << 8) | raw[37]) not in ALLOWED_UDP_PORTS or totlen != 28:
                return None, "udp-port-not-whitelisted"
        else:
            return None, "protocol-not-whitelisted"
        return int.from_bytes(raw[30:34], "big"), "ip"

    def _attested(self) -> bool:
        if self.attest is None:
            return True
        now = time.monotonic()
        t, ok, why = self._attest_cache
        if now - t > 0.25:
            ok, why = self.attest()
            self._attest_cache = (now, ok, why)
        if not ok and self.kill is not None:
            self.kill.trip("<auditor>", "attestation", why)
        return ok

    def _in_territory(self) -> bool:
        """Is this machine still inside the permitted network? Cheap local OS query, cached 0.25 s."""
        if self.territory is None:
            return True
        now = time.monotonic()
        t, ok, why = self._territory_cache
        if now - t > 0.25:
            ok, why = self.territory.check()
            self._territory_cache = (now, ok, why)
        if not ok and self.kill is not None:
            self.kill.trip("<territory>", "territory-lock", why)
        return ok

    def send(self, frame, *, caller: str, deep: bool = False) -> bool:
        """Object-friendly entry (scapy Packet or bytes): converts to bytes, then the one guard decides."""
        return self.send_raw(bytes(frame), caller=caller, deep=deep)

    def send_raw(self, raw: bytes, *, caller: str, deep: bool = False) -> bool:
        if self.kill is not None and self.kill.tripped:
            return False
        if not self._in_territory():
            return False
        self._consts()
        dst, kind = self._check_raw(raw)
        if dst is None:
            self.scope.allow(f"<{kind}>", caller=caller)   # always out of scope: counted, trips the kill switch
            return False
        if not self.scope.allow_int(dst, caller=caller, deep=deep):
            return False
        if not self._attested():
            return False
        if self.max_packets is not None and len(self.sent) >= self.max_packets:
            self.refused_budget += 1
            return False
        self._pace()
        self._emit(raw)
        self.sent.append(SentRecord(time.time(), dst, kind, caller, deep))
        return True

    def _pace(self) -> None:
        """Token schedule with a small burst allowance. Python 3.11 sleeps with ~1 ms resolution on Windows, so we
        sleep only when we are more than 1 ms ahead of schedule and otherwise send immediately."""
        now = time.perf_counter()
        ahead = self._next_slot - now
        if ahead > 0.001:
            time.sleep(ahead)
            now = time.perf_counter()
        self._next_slot = max(self._next_slot, now - 0.005) + self._gap

    @property
    def sent_out_of_scope(self) -> int:
        """Second, independent tally over what was *actually* emitted. Must be 0."""
        return sum(1 for r in list(self.sent) if not self.scope.in_scope_int(r.dst_int))
