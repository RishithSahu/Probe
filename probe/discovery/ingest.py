"""Turns captured packets into typed *observations* (Evidence) and inventory.

Everything the conclusions depend on comes from replies to probes we sent (or ICMP errors that quote them).
Overheard traffic is optional enrichment (DHCP lease info only, since capture is BPF-filtered to frames
addressed to us); no classification rule reads it, so the engine gives identical answers on a network where
passive capture sees nothing.

Performance: host/port bookkeeping lives in memory and is flushed to SQLite in bulk (flush()), because a
commit per reply would cap the whole scan at a few hundred packets per second.

This module never sends.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Callable

from scapy.all import ARP, ICMP, IP, TCP, Ether, IPerror
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMPerror, TCPerror, UDPerror

from ..scope import ScopeGuard
from ..store import Store
from . import probes as P
from .rawprobes import FWD_SPORT, FWD_SPORT_MAX, ID_FWD


class Evidence:
    """Facts, each with a precise meaning (see analysis/classify.py for what they entail)."""

    def __init__(self):
        self.arp_mac: dict[str, str] = {}                  # ip -> MAC that answered ARP for it
        self.arp_failed: set[str] = set()                  # answered L3 (so is awake) yet ignored repeated ARP
        self.mac_ips: dict[str, set[str]] = defaultdict(set)   # MAC -> IPs it answered ARP for
        self.visible: dict[str, set[str]] = defaultdict(set)   # ip -> probe kinds the host itself answered
        self.ladder: dict[str, dict[str, int]] = defaultdict(dict)  # ip -> {kind: smallest TTL that got the HOST to answer}
        self.hops: dict[str, dict[int, str]] = defaultdict(dict)    # target -> {ttl: router that sent TTL-exceeded}
        self.router_macs: dict[str, str] = {}
        self.unreach: dict[str, list[tuple[str, int]]] = defaultdict(list)  # target -> [(third-party router, ICMP code)]
        self.redirected_onlink: set[str] = set()           # gateway said "send to <ip> directly"
        self.reply_mac: dict[str, set[str]] = defaultdict(set)
        self.foreign: dict[str, set[str]] = defaultdict(set)   # out-of-scope address -> why we know it
        self.masks: dict[str, str] = {}
        self.reply_ttl: dict[str, int] = {}                 # first reply TTL (display)
        self.ttls: dict[str, Counter] = defaultdict(Counter)    # every reply TTL seen per host
        self.ttl_kind: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))   # ip -> reply kind -> TTLs
        self.ttl_port: dict[str, dict[int, Counter]] = defaultdict(dict)     # ip -> open port -> TTLs of its SYN-ACKs
        self.ttl1_synack: Counter = Counter()      # (ip, port) -> SYN-ACKs received for a TTL=1 SYN: the service is terminated locally
        self.ttl1_exceeded: Counter = Counter()    # (ip, port) -> time-exceeded from the host itself for a TTL=1 SYN: it FORWARDS that port
        self.alias_replies: list[tuple[str, int]] = []     # (source, probed-low16) where source != probed target
        # ---- forwarder / pivot evidence ----
        self.fwd_table: dict[int, tuple[str, str, int]] = {}   # ICMP probe seq -> (third-party dst S, addressed host H, TTL)
        self.fwd_table_tcp: dict[int, tuple[str, str, int]] = {}   # TCP probe sport offset -> same
        self.hosted_by: dict[str, set[str]] = defaultdict(set)  # S -> {H}: S answered a TTL=1 packet addressed to H's MAC
        self.hidden_checks: dict[str, dict] = {}                # S -> verification result (see engine._verify_hidden)
        self.fwd_hits: Counter = Counter()                      # (S, H, ttl) -> replies seen (verification counts deltas)
        self.catchall: set[str] = set()                         # H answers for addresses that belong to OTHER devices
        self.fwd_seen: dict[str, tuple] = {}                    # S -> (kind, ttl, eth_src) of an answer obtained through a host
        self.fwd_open: dict[tuple[str, str], set[int]] = defaultdict(set)   # (S, H) -> TCP ports that SYN-ACKed through H
        self.forwarders: dict[str, dict] = {}              # H -> {"sender", "third"}: H decremented TTL for a packet not for it
        self.via: dict[str, set[str]] = defaultdict(set)   # S -> {H}: S answered only when addressed through H
        self.visible_direct: set[str] = set()              # answered a probe that was NOT addressed through a forwarder
        self.hops_via: dict[tuple[str, str], str] = {}     # (S, H) -> router beyond H that sent TTL-exceeded
        # ---- passive enrichment (never required) ----
        self.dhcp_nets: list[str] = []
        self.overheard_unicast = 0
        self.frames_seen = 0

    def stack_ttl(self, ip: str) -> int | None:
        """The TTL of the host's OWN IP stack: ICMP replies and RSTs, not SYN-ACKs. A SYN-ACK may be generated by a
        service published from behind the host (NAT / container / VM) and so carries a different TTL."""
        c: Counter = Counter()
        for kind, cnt in self.ttl_kind.get(ip, {}).items():
            if kind != "tcp-syn":
                c.update(cnt)
        if not c:
            c = self.ttls.get(ip) or Counter()
        return c.most_common(1)[0][0] if c else None


class Ingest:
    def __init__(self, scope: ScopeGuard, store: Store, my_ip: str, my_mac: str,
                 on_mac: Callable[[str], None] | None = None):
        self.scope, self.store = scope, store
        self.my_ip, self.my_mac = my_ip, (my_mac or "").lower()
        self.on_mac = on_mac            # transport.allow_mac: next-hop MACs are learned from in-scope ARP only
        self.ev = Evidence()
        self.targets_low16: dict[int, str] = {}
        self._lock = threading.Lock()
        self._hosts: dict[str, dict] = {}
        self._ports: dict[tuple[str, int], None] = {}
        self._dirty_hosts: set[str] = set()
        self._dirty_ports = False
        self.replies = 0
        self._promoted: set[str] = set()

    # ---- bookkeeping (in memory, bulk-flushed) --------------------------------------------------
    def _touch(self, ip: str, *, mac=None, method=None, ttl=None, seen_mac=None, mask=None) -> None:
        h = self._hosts.get(ip)
        if h is None:
            now = datetime.now(timezone.utc).isoformat()
            h = self._hosts[ip] = {"ip": ip, "mac": None, "ttl": None, "mask": None, "seen_macs": set(),
                                   "methods": set(), "first": now}
        if mac:
            h["mac"] = mac
        if ttl is not None:
            h["ttl"] = ttl
        if mask:
            h["mask"] = mask
        if seen_mac:
            h["seen_macs"].add(seen_mac)
        if method:
            h["methods"].add(method)
        h["last"] = datetime.now(timezone.utc).isoformat()
        self._dirty_hosts.add(ip)

    def flush(self) -> None:
        with self._lock:
            hosts = [self._hosts[i] for i in self._dirty_hosts]
            ports = list(self._ports) if self._dirty_ports else []
            self._dirty_hosts.clear()
            self._dirty_ports = False
        if hosts:
            self.store.bulk_upsert_hosts(hosts)
        if ports:
            self.store.bulk_add_ports(ports)

    # ---- entry point ----------------------------------------------------------------------------
    def handle(self, pkt) -> None:
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        src, dst = eth.src.lower(), eth.dst.lower()
        if src == self.my_mac:
            return  # our own egress echoed back by the capture
        with self._lock:
            self.ev.frames_seen += 1
            if pkt.haslayer(ARP):
                self._arp(pkt[ARP], dst)
            elif pkt.haslayer(IP):
                self._ip(pkt, src, dst)

    def promote_fwd(self) -> None:
        """Make answers obtained THROUGH another host visible in the inventory -- unless only a catch-all responder gave
        them (they prove nothing about the address). Re-evaluated every call: an address promoted before its front was
        recognised as a catch-all is DEMOTED again, so late evidence can always correct an early guess."""
        from types import SimpleNamespace
        with self._lock:
            for third, (kind, ttl, eth_src) in self.ev.fwd_seen.items():
                fronts = self.ev.hosted_by.get(third, set()) | self.ev.via.get(third, set())
                tainted = bool(fronts) and fronts <= self.ev.catchall
                if tainted and third in self._promoted:
                    self._promoted.discard(third)
                    for d in (self.ev.visible, self.ev.reply_mac, self.ev.ttls, self.ev.reply_ttl, self.ev.ladder):
                        d.pop(third, None)
                    self._hosts.pop(third, None)
                    self._dirty_hosts.discard(third)
                    self.store.delete_host(third)
                elif not tainted and third not in self._promoted and third not in self.ev.visible_direct:
                    self._promoted.add(third)
                    self._seen(SimpleNamespace(src=third, ttl=ttl), kind, ttl, eth_src, direct=False)

    # ---- ARP --------------------------------------------------------------------------
    def _arp(self, a, eth_dst: str) -> None:
        psrc, hw = a.psrc, a.hwsrc.lower()
        if a.op == 2 and eth_dst == self.my_mac and psrc != "0.0.0.0" and self.scope.in_scope(psrc):
            self.ev.arp_mac[psrc] = hw
            self.ev.mac_ips[hw].add(psrc)
            self.ev.visible[psrc].add("arp")
            self._touch(psrc, mac=hw, method="arp")
            if self.on_mac:
                self.on_mac(hw)

    # ---- IP ----------------------------------------------------------------------------
    def _ip(self, pkt, eth_src: str, eth_dst: str) -> None:
        ip = pkt[IP]
        if ip.dst != self.my_ip:
            if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
                self._dhcp(pkt)
            return
        self.replies += 1
        if pkt.haslayer(ICMPerror) or (pkt.haslayer(ICMP) and pkt[ICMP].type in (3, 5, 11)):
            self._icmp_error(pkt, ip, eth_src)
        elif pkt.haslayer(ICMP):
            self._icmp_reply(pkt[ICMP], ip, eth_src)
        elif pkt.haslayer(TCP):
            self._tcp_reply(pkt[TCP], ip, eth_src)

    def _seen(self, ip, kind: str, ttl: int, eth_src: str, *, ladder_ttl: int | None = None,
              method: str | None = None, mask: str | None = None, direct: bool = True) -> None:
        src = ip.src
        if not self.scope.in_scope(src):
            self.ev.foreign[src].add(f"answered a {kind} probe")
            return
        if direct:
            self.ev.visible_direct.add(src)
        service = kind.startswith("tcp-syn")             # an open-port SYN-ACK says nothing certain about the host's own stack
        self.ev.visible[src].add(kind)
        self.ev.reply_mac[src].add(eth_src)
        if not service:
            self.ev.reply_ttl.setdefault(src, ttl)
        self.ev.ttls[src][ttl] += 1
        self.ev.ttl_kind[src][kind.split(":")[0]][ttl] += 1
        self._touch(src, method=method or kind.split(":")[0], ttl=None if service else ttl, seen_mac=eth_src, mask=mask)
        if ladder_ttl is not None:
            family = kind.split(":")[0]
            cur = self.ev.ladder[src].get(family)
            self.ev.ladder[src][family] = ladder_ttl if cur is None else min(cur, ladder_ttl)

    def _fwd_reply(self, ip, idx: int, kind: str, eth_src: str, tcp: bool = False, open_port: int | None = None) -> None:
        """A reply to a probe that was addressed to another host's MAC but destined for a third address S.
        TTL=1 probes are never forwarded, so an answer means S is hosted by that host's own stack; TTL>=2 probes
        may have been forwarded, so an answer only means S is reachable through it."""
        entry = (self.ev.fwd_table_tcp if tcp else self.ev.fwd_table).get(idx)
        if entry is None or entry[0] != ip.src:
            return
        third, via_host, ttl = entry
        self.ev.fwd_hits[(third, via_host, ttl)] += 1
        if open_port is not None:
            self.ev.fwd_open[(third, via_host)].add(open_port)
        if third in self.ev.arp_mac and third != via_host and eth_src == self.ev.arp_mac.get(via_host):
            # via_host answered, from its own MAC, for an address that provably belongs to ANOTHER device:
            # it answers for every address, so its answers say nothing about any individual address
            self.ev.catchall.add(via_host)
        (self.ev.hosted_by if ttl == 1 else self.ev.via)[third].add(via_host)
        # not promoted into the inventory yet: promote_fwd() does that once we know whether via_host is a catch-all
        self.ev.fwd_seen[third] = (kind, ip.ttl, eth_src)

    def _icmp_reply(self, ic, ip, eth_src: str) -> None:
        t = ic.type
        if t == 0 and ic.id == ID_FWD:
            self._fwd_reply(ip, ic.seq, "icmp-echo", eth_src)
        elif t == 0 and ic.id in (P.ID_ECHO, P.ID_LADDER):
            lad = ic.seq if ic.id == P.ID_LADDER else None
            self._seen(ip, "icmp-echo", ip.ttl, eth_src, ladder_ttl=lad)
            raw = bytes(ic.payload)[:2]
            probed16 = int.from_bytes(raw, "big") if len(raw) == 2 else None
            if probed16 is not None and (int(ipaddress.ip_address(ip.src)) & 0xFFFF) != probed16:
                # answered from an address we did not probe: a multi-homed device revealing another interface
                self.ev.alias_replies.append((ip.src, probed16))
                target = self.targets_low16.get(probed16)
                if target and not self.scope.in_scope(ip.src):
                    self.ev.foreign[ip.src].add(f"replied from this address to a probe for {target} (second interface)")
        elif t == 14 and ic.id in (P.ID_TS, P.ID_LADDER_TS):
            self._seen(ip, "icmp-timestamp", ip.ttl, eth_src, ladder_ttl=ic.seq if ic.id == P.ID_LADDER_TS else None)
        elif t == 18 and ic.id in (P.ID_MASK, P.ID_LADDER_MASK):
            mask = getattr(ic, "addr_mask", None)
            self._seen(ip, "icmp-mask", ip.ttl, eth_src, mask=mask, ladder_ttl=ic.seq if ic.id == P.ID_LADDER_MASK else None)
            if mask and self.scope.in_scope(ip.src):
                self.ev.masks[ip.src] = mask

    def _tcp_reply(self, t, ip, eth_src: str) -> None:
        # Only replies to OUR probes: they target our source-port ranges. Everything else addressed to this
        # machine (browser, Tailscale, updates...) is the OS's own traffic and must never be read as a probe reply.
        if not (P.SPORT_SYN <= t.dport <= FWD_SPORT_MAX) or not self.scope.in_scope(ip.src):
            return
        flags = int(t.flags)
        if FWD_SPORT <= t.dport <= FWD_SPORT_MAX:
            if flags & 0x04 or flags & 0x12 == 0x12:
                self._fwd_reply(ip, t.dport - FWD_SPORT, f"tcp-ack:{t.sport}" if not flags & 0x02 else f"tcp-syn:{t.sport}", eth_src,
                                tcp=True, open_port=t.sport if flags & 0x12 == 0x12 else None)
            return
        lad = t.dport - P.LADDER_SPORT if P.LADDER_SPORT < t.dport <= P.LADDER_SPORT + 255 else None
        if flags & 0x12 == 0x12:       # SYN+ACK: open port, answers a SYN
            self._seen(ip, f"tcp-syn:{t.sport}", ip.ttl, eth_src, ladder_ttl=lad, method="tcp")
            self._ports[(ip.src, t.sport)] = None
            if lad is None:
                self.ev.ttl_port[ip.src].setdefault(t.sport, Counter())[ip.ttl] += 1
            elif lad == 1:                 # answer to a TTL=1 SYN: reached the host's IP stack and was served locally
                self.ev.ttl1_synack[(ip.src, t.sport)] += 1
            self._dirty_ports = True
        elif flags & 0x04 and flags & 0x10:   # RST+ACK: closed port answering a SYN
            self._seen(ip, f"tcp-rst:{t.sport}", ip.ttl, eth_src, ladder_ttl=lad, method="tcp")
        elif flags & 0x04:                    # bare RST: answers an unsolicited ACK (stateless filter)
            self._seen(ip, f"tcp-ack:{t.sport}", ip.ttl, eth_src, ladder_ttl=lad, method="tcp")

    def _icmp_error(self, pkt, ip, eth_src: str) -> None:
        """Time-exceeded / unreachable / redirect. The quoted header is the
        probe we sent, so the error says which target it was about."""
        if not pkt.haslayer(IPerror):
            return
        icmp, inner, sender = pkt[ICMP], pkt[IPerror], ip.src
        target = inner.dst
        if not self.scope.in_scope(target):
            return
        code_ttl, quoted_dport, fwd_idx = None, None, None
        if pkt.haslayer(ICMPerror):
            qid = getattr(pkt[ICMPerror], "id", None)
            if qid in P.LADDER_IDS:
                code_ttl = pkt[ICMPerror].seq
            elif qid == ID_FWD:
                fwd_idx = pkt[ICMPerror].seq
        elif pkt.haslayer(TCPerror):
            sp = pkt[TCPerror].sport
            quoted_dport = pkt[TCPerror].dport
            if FWD_SPORT <= sp <= FWD_SPORT_MAX:
                fwd_idx = sp - FWD_SPORT
            elif P.LADDER_SPORT < sp <= P.LADDER_SPORT + 255:
                code_ttl = sp - P.LADDER_SPORT
        elif pkt.haslayer(UDPerror):
            sp = pkt[UDPerror].sport
            quoted_dport = pkt[UDPerror].dport
            code_ttl = sp - P.LADDER_SPORT if P.LADDER_SPORT < sp <= P.LADDER_SPORT + 255 else None

        if fwd_idx is not None:                               # an error about a forwarder/pivot probe
            entry = (self.ev.fwd_table_tcp if pkt.haslayer(TCPerror) else self.ev.fwd_table).get(fwd_idx)
            if entry and icmp.type == 11:
                third, via_host, ttl = entry
                if ttl == 1 and eth_src == self.ev.arp_mac.get(via_host):
                    # we addressed via_host's MAC with TTL=1 for somebody else, and THAT device said
                    # "time exceeded": it decrements TTL, i.e. it forwards IP packets
                    self.ev.forwarders[via_host] = {"sender": sender, "third": third}
                    if self.scope.in_scope(sender):
                        self.ev.router_macs[sender] = eth_src
                elif ttl >= 2:
                    self.ev.hops_via[(third, via_host)] = sender
                    if not self.scope.in_scope(sender):
                        self.ev.foreign[sender].add(f"router interface beyond forwarder {via_host}")
            return

        if icmp.type == 5:  # redirect: "for <target> use gateway <gw>"
            if getattr(icmp, "gw", None) == target:
                self.ev.redirected_onlink.add(target)
            return
        if sender == target:  # the target itself spoke (ICMP port-unreachable to our UDP probe)
            if icmp.type == 3 and icmp.code == 3:
                self._seen(ip, f"udp-unreach:{quoted_dport}", ip.ttl, eth_src, ladder_ttl=code_ttl, method="udp")
            elif icmp.type == 11 and code_ttl == 1 and quoted_dport is not None and pkt.haslayer(TCPerror):
                # our TTL=1 SYN to this exact port (quoted_dport, from the quoted inner header) reached the host and
                # was NOT answered locally: the host tried to forward it. The MAC must be KNOWN and must match --
                # with no known MAC yet this would silently accept an answer from anybody, which is not the host's
                # own identity being confirmed.
                known_mac = self.ev.arp_mac.get(target)
                if known_mac and eth_src.lower() == known_mac.lower():
                    self.ev.ttl1_exceeded[(target, quoted_dport)] += 1
            return
        # a third party (router/firewall) answered about the target
        if self.scope.in_scope(sender):
            self.ev.router_macs[sender] = eth_src
            self._touch(sender, method="icmp-error", ttl=ip.ttl, seen_mac=eth_src)
            self.ev.visible[sender].add("icmp-error")
        else:
            self.ev.foreign[sender].add(f"router interface that answered about {target}")
        if icmp.type == 11 and code_ttl is not None:
            self.ev.hops[target][code_ttl] = sender
        elif icmp.type == 3:
            self.ev.unreach[target].append((sender, int(icmp.code)))

    # ---- passive enrichment ------------------------------------------------------------
    def _dhcp(self, pkt) -> None:
        opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
        mask, yi = opts.get("subnet_mask"), pkt[BOOTP].yiaddr
        if opts.get("message-type") in (2, 5) and mask and yi and yi != "0.0.0.0":
            net = str(ipaddress.ip_network(f"{yi}/{mask}", strict=False))
            if net not in self.ev.dhcp_nets:
                self.ev.dhcp_nets.append(net)
                self.store.add_lead(net, f"DHCP lease from this subnet was overheard ({yi}/{mask})", "passive-dhcp")
