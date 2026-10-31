"""The autonomous discovery agent -- the sniffer dog. One call, Engine.run(), does a full pass.

Design goal: the whole pass fits in ~3 minutes on a /24 WITHOUT finding less than a slow scan would.
Speed comes from removing waiting and overhead, never from probing less:

  * byte-level probes (2 us each) and a byte-level guard (4 us): the scan is limited by the network, not by Python
  * every packet is sent round-robin across hosts at ~2,500 pps, replies are consumed concurrently
  * "wait" means "until replies go quiet", not a fixed sleep
  * loss is handled by retransmission until a repeat pass finds nothing new (and the rate drops if it does)
  * host/port bookkeeping is in memory and flushed in bulk

Phases (timings are recorded and reported):
  gateway    ARP the in-scope gateway
  arp        tier 0 on the whole scope, retransmitted until stable
  blitz      the full tier suite on EVERY address: ICMP echo/timestamp/mask, TCP ACK, UDP, then SYN to the top-N
             ports. ARP-known hosts are addressed directly (TTL 64); the rest go via the gateway at TTL 2 (leash)
  loss       retransmit the cheap suite until a pass adds no new host or port
  recheck    immediate ARP re-test for hosts that answer L3 but ignored ARP (R3)
  forwarders ask every on-link host "do you forward IP?" with a TTL=1 packet that is not for it (R6)
  infer      classify by proof, cut address space into segments, HOLD separate segments, build the graph
  pivot      sweep the still-silent addresses THROUGH each forwarder / anomaly host / gateway: hosts that only
             answer that way sit behind it (R5) -- this is how a network behind a dual-homed box shows up
  waves      leash rungs TTL>=3, only along paths proven inside the scope
  enrich     nmap -sT -sV + scripts on hosts with open ports (service/banner/leak data for the other agents)
  infer      final classification including leaked addresses

The leash and the fence are unchanged: a probe never travels past a router not proven inside the scope, every
frame is judged byte-for-byte by the one guard, and held segments get no deep probing.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from pathlib import Path
from typing import Callable

from .analysis import classify, topology
from .analysis import segments as seg
from .discovery import tiers
from .discovery.ingest import Ingest
from .discovery.rawprobes import RawProbes, mac_bytes
from .net.transport import GuardedTransport
from .scope import ScopeGuard
from .store import Store
from .tools import nmap_tool

logger = logging.getLogger("probe.engine")

MAX_TARGETS = 16384
OS_BY_TTL = {32: "Windows 9x / embedded", 64: "Linux / Unix / macOS / IoT", 128: "Windows",
             255: "Network device (router / switch / printer)"}
UNEXPLORED_SILENT = "silent hop: cannot prove the next router is inside the scope"
LEAVES_SCOPE = "path leaves the scope"


def load_oui() -> dict[str, str]:
    for p in (Path(__file__).parent / "data" / "oui.txt", Path(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes"),
              Path(r"C:\Program Files\Nmap\nmap-mac-prefixes"), Path("/usr/share/nmap/nmap-mac-prefixes"),
              Path("/usr/local/share/nmap/nmap-mac-prefixes")):
        try:
            out = {l[:6].upper(): l[7:].strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines()
                   if l and not l.startswith("#") and len(l) > 7}
            if out:
                return out
        except OSError:
            continue
    return {}


def os_hint(ttl: int | None) -> str | None:
    """Supporting hint only: the initial TTL is not observable, so this is a family guess."""
    if not ttl:
        return None
    return OS_BY_TTL[next(s for s in (32, 64, 128, 255) if ttl <= s)]


def ip_int(ip: str) -> int:
    a, b, c, d = map(int, ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


class Engine:
    def __init__(self, scope: ScopeGuard, store: Store, transport: GuardedTransport, *,
                 budget_s: float = 170, tcp_ports: int = 200, max_hops: int = 8, allow_silent_hops: int = 0,
                 enrich: bool = True, auditor=None, wait_scale: float = 1.0,
                 on_done: Callable[["Engine"], None] | None = None):
        self.scope, self.store, self.transport = scope, store, transport
        self.budget_s, self.max_hops, self.allow_silent = budget_s, max_hops, allow_silent_hops
        self.enrich, self.auditor, self.wait_scale, self.on_done = enrich, auditor, wait_scale, on_done
        self.ports = tiers.top_tcp_ports(tcp_ports)
        # the cheap suite (first wave and loss checks): the most commonly open ports by nmap's own ranking
        self.cheap_ports = tuple(dict.fromkeys([443, 80, 22, *tiers.top_tcp_ports(10)]))
        self.deep = False
        self.ingest: Ingest | None = None
        self.rp: RawProbes | None = None
        self.gw_mac: str | None = None
        self.oui = load_oui()
        self.timings: dict[str, float] = {}
        self.notes: list[str] = []
        self._classes: dict[str, classify.HostClass] = {}
        self._stopped: dict[str, str] = {}
        self._fwd_next = 0
        self._fwd_ctr = 0
        self._fwd_tcp_ctr = 0
        self._blitzed: set[str] = set()
        self._t0, self._phase, self._scan_id = 0.0, "init", None
        self._pass_done = False

    # ---- plumbing ----------------------------------------------------------------
    def _remaining(self) -> float:
        return self.budget_s - (time.time() - self._t0)

    def _status(self, phase: str | None = None) -> None:
        if phase:
            self._phase = phase
            logger.info("phase: %s (+%.1fs)", phase, time.time() - self._t0)
        t, ev = self.transport, self.ingest.ev
        targets = self._all_targets()
        answered = sum(1 for x in targets if self._known(x))
        stops = list(self._stopped.values())
        self.store.set_meta("status", {
            "phase": self._phase, "elapsed": round(time.time() - self._t0, 1), "budget_s": self.budget_s,
            "timings": self.timings, "notes": self.notes, "scan_id": self._scan_id, "rate_pps": t.rate_pps,
            "scope": [str(n) for n in self.scope.networks], "scanner": t.my_ip, "gateway": t.gateway_ip,
            "scanner_subnet": t.my_network, "packets_sent": len(t.sent), "stray_blocked": self.scope.stray_count,
            "sent_out_of_scope": t.sent_out_of_scope, "held_blocked": self.scope.held_blocked,
            "held": self.scope.held, "addresses_in_scope": len(targets), "answered": answered,
            "silent": len(targets) - answered, "forwarders": sorted(ev.forwarders),
            "paths_leaving_scope": stops.count(LEAVES_SCOPE), "paths_unexplored_silent": stops.count(UNEXPLORED_SILENT),
            "passive_visibility": "n/a (capture is filtered to replies; nothing depends on overhearing)",
            "wire": self.auditor.wire_summary() if self.auditor else {},
        })

    def _event(self, type_: str, **payload) -> None:
        self.store.add_event(type_, {"scan_id": self._scan_id, **payload})

    def _all_targets(self) -> list[str]:
        out: list[str] = []
        for net in self.scope.networks:
            if net.version != 4:
                logger.warning("IPv6 scope %s ignored: IPv6 discovery needs multicast, outside scope-safe bounds", net)
                continue
            out += [str(h) for h in net.hosts()]
        out = [x for x in dict.fromkeys(out) if x != self.transport.my_ip]
        if len(out) > MAX_TARGETS:
            logger.warning("scope has %d addresses; truncating to %d", len(out), MAX_TARGETS)
            out = out[:MAX_TARGETS]
        return out

    def _targets(self) -> list[str]:
        return [x for x in self._all_targets() if not (self.deep and self.scope.is_held(x))]

    def _l3_answered(self, ip: str) -> bool:
        return bool(self.ingest.ev.visible.get(ip, set()) - {"icmp-error", "arp"})

    def _known(self, ip: str) -> bool:
        return bool(self.ingest.ev.visible.get(ip, set()) - {"icmp-error"})

    def _answering(self) -> list[str]:
        return sorted((x for x in self.ingest.ev.visible if self.scope.in_scope(x) and self._known(x)), key=ip_int)

    def _next_hop(self, ip: str) -> tuple[bytes | None, int]:
        """(MAC to address, TTL). On-link hosts (ARP answered) are addressed directly at TTL 64: a frame addressed to
        a host's own MAC cannot go anywhere else. Everything else goes via the in-scope gateway at TTL 2, so it can
        be forwarded by exactly one proven-in-scope router and expires on the next (the leash)."""
        m = self.ingest.ev.arp_mac.get(ip)
        if m:
            return mac_bytes(m), 64
        return (mac_bytes(self.gw_mac), 2) if self.gw_mac else (None, 2)

    def _tx(self, raw: bytes, caller: str, *, classification: bool = False) -> bool:
        """classification=True is only for the handful of confirmation probes that VERIFY an already-detected hidden
        address (never a port scan of it); everything else is 'deep' once segments are held."""
        return self.transport.send_raw(raw, caller=caller, deep=self.deep and not classification)

    def _settle(self, max_s: float, quiet_s: float = 0.45) -> None:
        """Wait for replies to stop arriving (not a fixed sleep)."""
        ing = self.ingest
        end = time.time() + max_s * self.wait_scale
        last, quiet_since = (ing.replies, len(ing.ev.arp_mac)), time.time()
        while time.time() < end:
            time.sleep(0.04)
            cur = (ing.replies, len(ing.ev.arp_mac))
            if cur != last:
                last, quiet_since = cur, time.time()
            elif time.time() - quiet_since >= quiet_s * self.wait_scale:
                return

    def _phase_timer(self, name: str, t_start: float) -> None:
        self.timings[name] = round(time.time() - t_start, 2)

    # ---- tier 0 -----------------------------------------------------------------------
    ARP_RATE = 300        # broadcasts are the first thing a Wi-Fi driver / AP drops under a burst: send them gently

    def _arp(self, ips: list[str], settle: float = 1.2) -> None:
        fast = self.transport.rate_pps
        self.transport.set_rate(min(fast, self.ARP_RATE))
        for ip in ips:
            self._tx(self.rp.arp(ip_int(ip)), "tier0:arp")
        self.transport.set_rate(fast)
        self._settle(settle)

    def _arp_stable(self, targets: list[str]) -> None:
        pending = targets
        for rnd in range(6):
            before = len(self.ingest.ev.arp_mac)
            self._arp(pending, settle=1.4)
            pending = [x for x in targets if x not in self.ingest.ev.arp_mac]
            if rnd >= 2 and len(self.ingest.ev.arp_mac) == before:
                break          # three rounds, and a further one found nothing new: loss is not hiding anyone

    # ---- the blitz --------------------------------------------------------------------
    def _suite_cheap(self, targets: list[str]) -> int:
        """echo + ACK80/443 + SYN to the cheap ports, to every target. Used by the blitz and by loss checks."""
        sent = 0
        for ip in targets:
            mac, ttl = self._next_hop(ip)
            if mac is None:
                continue
            n = ip_int(ip)
            sent += self._tx(self.rp.echo(mac, n, ttl), "tier1:echo")
            sent += self._tx(self.rp.tcp_ack(mac, n, 80, ttl), "tier2:ack80")
            sent += self._tx(self.rp.tcp_ack(mac, n, 443, ttl), "tier2:ack443")
            for p in self.cheap_ports:
                sent += self._tx(self.rp.tcp_syn(mac, n, p, ttl), "tier2:syn")
        return sent

    def _suite_rest(self, targets: list[str]) -> int:
        """tier 3/4 and the remaining top-N ports, interleaved across hosts (round-robin) so no host is hammered."""
        sent = 0
        hops = {ip: self._next_hop(ip) for ip in targets}
        ints = {ip: ip_int(ip) for ip in targets}
        for ip in targets:
            mac, ttl = hops[ip]
            if mac is None:
                continue
            self._blitzed.add(ip)
            sent += self._tx(self.rp.timestamp(mac, ints[ip], ttl), "tier3:ts")
            sent += self._tx(self.rp.mask(mac, ints[ip], ttl), "tier3:mask")
            sent += self._tx(self.rp.udp(mac, ints[ip], 40125, ttl), "tier4:udp")
        rest = [p for p in self.ports if p not in self.cheap_ports]
        for p in rest:
            for ip in targets:
                mac, ttl = hops[ip]
                if mac is not None:
                    sent += self._tx(self.rp.tcp_syn(mac, ints[ip], p, ttl), "tier2:syn")
        return sent

    def _open_count(self) -> int:
        return len(self.ingest._ports)

    def _blitz(self, targets: list[str]) -> None:
        t0 = time.time()
        self.ingest.targets_low16 = {ip_int(x) & 0xFFFF: x for x in self._all_targets()}
        n = self._suite_cheap(targets)
        self._settle(1.2)
        n += self._suite_rest(targets)
        self._settle(2.0)
        self._phase_timer("blitz", t0)
        logger.info("blitz: %d probes in %.1fs (%.0f pps)", n, time.time() - t0, n / max(0.1, time.time() - t0))

    def _loss_passes(self, targets: list[str]) -> None:
        """Retransmit until a repeat pass adds no new host and no new open port. If one does, packets were being
        lost: halve the rate and go again. This is what guarantees speed does not cost coverage."""
        t0 = time.time()
        for rnd in range(1, 4):
            hosts0, ports0 = len([x for x in targets if self._known(x)]), self._open_count()
            self._arp([x for x in targets if x not in self.ingest.ev.arp_mac], settle=0.8)
            fast = self.transport.rate_pps
            self.transport.set_rate(min(fast, 800))            # the repeat pass is gentle: it exists to catch loss
            self._suite_cheap(targets)
            self.transport.set_rate(fast)
            self._settle(1.2)
            hosts1, ports1 = len([x for x in targets if self._known(x)]), self._open_count()
            gained = (hosts1 - hosts0, ports1 - ports0)
            logger.info("loss pass %d: +%d hosts +%d open ports", rnd, *gained)
            if gained == (0, 0):
                break
            self.transport.set_rate(max(300, self.transport.rate_pps // 2))
            self.notes.append(f"loss detected in pass {rnd} (+{gained[0]} hosts, +{gained[1]} ports): rate halved "
                              f"to {self.transport.rate_pps} pps and the pass repeated")
            if rnd == 2 and self._remaining() > 60:    # a lossy link also lost deep-port replies: repeat that suite once
                self._suite_rest([x for x in targets if self._l3_answered(x) or x in self.ingest.ev.arp_mac])
                self._settle(2.0)
        self._phase_timer("loss", t0)

    def _stragglers(self) -> None:
        """Hosts that answer ARP late (sleeping phones, congested Wi-Fi) must still get the full probe suite."""
        t0 = time.time()
        targets = self._targets()
        for _ in range(2):
            self._arp([x for x in targets if x not in self.ingest.ev.arp_mac], settle=1.2)
            late = [x for x in targets if x in self.ingest.ev.arp_mac and x not in self._blitzed]
            if not late:
                continue
            logger.info("stragglers: %d late ARP responder(s) get the full suite", len(late))
            fast = self.transport.rate_pps
            self.transport.set_rate(min(fast, 1200))
            self._suite_cheap(late)
            self._suite_rest(late)
            self.transport.set_rate(fast)
            self._settle(1.5)
        self._phase_timer("stragglers", t0)

    # ---- R3: immediate ARP re-test --------------------------------------------------------------
    def _arp_recheck(self) -> None:
        t0 = time.time()
        ev = self.ingest.ev
        todo = [x for x in self._answering() if self._l3_answered(x) and x not in ev.arp_mac
                and x not in ev.arp_failed and not (self.deep and self.scope.is_held(x))]
        for _ in range(3):
            if not todo:
                break
            self._arp(todo, settle=0.8)
            todo = [x for x in todo if x not in ev.arp_mac]
        ev.arp_failed.update(todo)
        self._phase_timer("recheck", t0)

    # ---- R6: forwarder discovery ----------------------------------------------------------------
    def _third(self, avoid: str) -> str | None:
        """A silent in-scope address to use as the 'not for you' destination."""
        silent = [x for x in self._all_targets() if not self._known(x) and x != avoid]
        pool = silent or [x for x in self._all_targets() if x != avoid]
        if not pool:
            return None
        self._fwd_next += 1
        return pool[self._fwd_next % len(pool)]

    def _fwd_index(self, third: str, via: str, ttl: int, tcp: bool = False) -> int:
        """Probe identity: ICMP seq (60,000 slots) or TCP source-port offset (2,900 slots) -> (S, H, TTL)."""
        ev = self.ingest.ev
        if tcp:
            i, self._fwd_tcp_ctr = self._fwd_tcp_ctr % 2900, self._fwd_tcp_ctr + 1
            ev.fwd_table_tcp[i] = (third, via, ttl)
        else:
            i, self._fwd_ctr = self._fwd_ctr % 60000, self._fwd_ctr + 1
            ev.fwd_table[i] = (third, via, ttl)
        return i

    def _control_probe(self, h: str, k: int, tag: str, classification: bool = False) -> int:
        """Ask H to answer, via a TTL=1 echo addressed to its MAC, for the address of ANOTHER real device."""
        ev = self.ingest.ev
        pool = [x for x in ev.arp_mac if self.scope.in_scope(x) and x != h and x != self.transport.gateway_ip]
        if not pool:
            return 0
        x = pool[(k * 13 + sum(map(int, h.split("."))) * 5 + 3) % len(pool)]
        return self._tx(self.rp.fwd_echo(mac_bytes(ev.arp_mac[h]), ip_int(x), 1, self._fwd_index(x, h, 1)), tag,
                        classification=classification)

    def _forwarder_tests(self) -> None:
        """The alias / forwarder MATRIX: every on-link host H against every silent in-scope address S, with a TTL=1
        echo addressed to H's MAC but destined for S. TTL=1 is never forwarded, so:
          * time-exceeded from H           -> H forwards IP packets (a router / NAT / VM host)       (R6)
          * an echo reply FROM S           -> S is an address hosted by H's own stack: a hidden
                                              interface/secondary IP/container gateway behind H      (R7)
        Every pair is tested (not a sample), so no hidden address can be skipped.

        False-alarm control, ordered so it cannot be starved: devices that rate-limit their ICMP replies would answer
        the first few probes and then go quiet, so the CONTROL (does H also answer for another real device's address?)
        is sent FIRST, fronts already shown to be catch-alls are not probed further, and any front that still answers
        for several silent addresses is re-tested after a cool-down (spaced, so the rate limiter has refilled)."""
        t0 = time.time()
        ev = self.ingest.ev
        hosts = [h for h in ev.arp_mac if self.scope.in_scope(h) and not (self.deep and self.scope.is_held(h))]
        silent = [x for x in self._targets() if not self._known(x)]
        macs = {h: mac_bytes(ev.arp_mac[h]) for h in hosts}
        controls = 0
        for k in range(2):                              # 1) controls first: two per host, before anything can drain a limiter
            for h in hosts:
                if h != self.transport.gateway_ip:
                    controls += self._control_probe(h, k, "alias-matrix:control")
        self._settle(1.5)
        sent = 0
        for s_ip in silent:                             # 2) the matrix, round-robin over H; known catch-alls are skipped
            n = ip_int(s_ip)
            for h in hosts:
                if h != s_ip and h not in ev.catchall:
                    sent += self._tx(self.rp.fwd_echo(macs[h], n, 1, self._fwd_index(s_ip, h, 1)), "alias-matrix:ttl1")
        self._settle(2.5)
        # 3) any front that answered for several silent addresses gets a COOL-DOWN re-test: wait for rate limiters to
        #    refill, then spaced controls. A front that answers for another device's address is a catch-all.
        busy = [h for h in hosts if h not in ev.catchall and sum(1 for fs in ev.hosted_by.values() if h in fs) >= 2]
        if busy:
            time.sleep(2.5 * self.wait_scale)
            for k in range(4):
                for h in busy:
                    controls += self._control_probe(h, 7 + k, "alias-matrix:control2")
                time.sleep(0.6 * self.wait_scale)
            self._settle(1.5)
        self.ingest.promote_fwd()
        if ev.catchall:
            self.notes.append(f"catch-all responder(s) {sorted(ev.catchall)}: they answer for addresses that belong to other "
                              "devices, so their answers are not evidence of hidden hosts")
        self._phase_timer("forwarders", t0)
        logger.info("alias matrix: %d probes + %d controls (%d hosts x %d silent addresses); forwarders=%d catch-all=%s "
                    "hosted-addresses(non-catch-all)=%s", sent, controls, len(hosts), len(silent), len(ev.forwarders),
                    sorted(ev.catchall), {s_: sorted(h_) for s_, h_ in ev.hosted_by.items() if not set(h_) <= ev.catchall})

    def _characterize_catchall(self) -> None:
        """A catch-all answers ICMP for every address. What does it do with TCP? A tarpit/honeypot SYN-ACKs everything;
        a plain AnyIP stack RSTs everything; a DNAT gateway in front of a hidden network SYN-ACKs ONLY specific
        address:port pairs -- and those pairs are the hidden services. ~10 SYNs per silent address, TTL=1 (never
        forwarded): classification of the responder, not a scan of any target."""
        ev = self.ingest.ev
        if not ev.catchall:
            return
        t0 = time.time()
        silent = [x for x in self._all_targets() if not self._known(x) or x in ev.hosted_by]
        ports = self.cheap_ports[:8]
        for h in sorted(ev.catchall):
            mac = mac_bytes(ev.arp_mac[h])
            for p in ports:
                for s_ip in silent:
                    if s_ip != h:
                        self._tx(self.rp.fwd_tcp_syn(mac, ip_int(s_ip), p, 1, self._fwd_index(s_ip, h, 1, tcp=True)),
                                 "catchall:syn", classification=True)
        self._settle(2.0)
        for h in sorted(ev.catchall):
            openmap = {s_: sorted(p) for (s_, hh), p in ev.fwd_open.items() if hh == h and p}
            addrs_open = len(openmap)
            if addrs_open == 0:
                kind = "answers ICMP for every address but SYN-ACKs nothing: a plain catch-all stack (RST on closed ports)"
            elif addrs_open >= max(3, int(0.8 * len(silent))):
                kind = "SYN-ACKs on almost every address: a tarpit / honeypot that fakes services everywhere"
            else:
                kind = f"SYN-ACKs ONLY on {addrs_open} specific address(es): a DNAT-style gateway; those are real services behind it"
            self.notes.append(f"catch-all {h}: {kind}" + (f" -> {openmap}" if 0 < addrs_open < 12 else ""))
            logger.info("catch-all %s: %s | open=%s", h, kind, openmap)
        self._phase_timer("catchall", t0)

    # ---- verification: controls, repeats ---------------------------------------------------------------
    def _verify_hidden(self) -> None:
        """Turn a detection into a verified finding. For every address S claimed to be hosted by H:
          1. repeat the TTL=1 test via H's MAC five times       -> must answer on most of them
          2. same probe via six OTHER hosts' MACs                -> must NEVER answer (a TTL=1 packet only reaches
                                                                    the host whose MAC it was addressed to)
          3. ARP who-has S three times                           -> must stay silent (hidden from ARP)
          4. echo straight to S via the gateway                  -> must stay silent (not reachable directly)
        ~30 packets per address, classification only: no port scan, nothing beyond identifying the host."""
        t0 = time.time()
        ev = self.ingest.ev
        cands = {s_: sorted(h_ for h_ in hs if h_ not in ev.catchall) for s_, hs in ev.hosted_by.items()
                 if s_ not in ev.visible_direct and not set(hs) <= ev.catchall}
        cands = dict(list(cands.items())[:8])          # a verified finding needs a handful of addresses, not a hundred
        if not cands:
            self._phase_timer("verify", t0)
            return
        others_pool = [h for h in ev.arp_mac if self.scope.in_scope(h)]
        for s_ip, fronts in cands.items():
            if time.time() - t0 > 20:                  # hard cap: verification must never eat the scan budget
                self.notes.append("verification stopped at its 20s cap")
                break
            h = fronts[0]
            controls = [x for x in others_pool if x != h and x != s_ip][:6]
            n = ip_int(s_ip)
            hits0 = {k: ev.fwd_hits[k] for k in ev.fwd_hits}
            for k in range(3):                       # is the FRONT a catch-all? (spaced, so a rate limiter has refilled)
                self._control_probe(h, 20 + k, "verify:front-control", classification=True)
                time.sleep(0.5 * self.wait_scale)
            self._settle(1.0)
            if h in ev.catchall:
                ev.hidden_checks[s_ip] = {"confirmed": False, "via": h, "summary": f"{h} turned out to be a catch-all responder"}
                logger.info("verify %s: REFUTED, front %s is a catch-all", s_ip, h)
                continue
            for _ in range(5):
                self._tx(self.rp.fwd_echo(mac_bytes(ev.arp_mac[h]), n, 1, self._fwd_index(s_ip, h, 1)), "verify:ttl1",
                         classification=True)
                time.sleep(0.15 * self.wait_scale)
            for c in controls:
                for _ in range(2):
                    self._tx(self.rp.fwd_echo(mac_bytes(ev.arp_mac[c]), n, 1, self._fwd_index(s_ip, c, 1)),
                             "verify:control", classification=True)
            for _ in range(3):
                self._tx(self.rp.arp(n), "verify:arp", classification=True)
                time.sleep(0.2 * self.wait_scale)
            if self.gw_mac:
                for _ in range(3):
                    self._tx(self.rp.echo(mac_bytes(self.gw_mac), n, 2), "verify:gateway", classification=True)
            self._settle(1.5)
            got = ev.fwd_hits[(s_ip, h, 1)] - hits0.get((s_ip, h, 1), 0)
            ctl = sum(ev.fwd_hits[(s_ip, c, 1)] - hits0.get((s_ip, c, 1), 0) for c in controls)
            arp_ans, direct = s_ip in ev.arp_mac, s_ip in ev.visible_direct
            ok = got >= 3 and ctl == 0 and not arp_ans and not direct
            ev.hidden_checks[s_ip] = {
                "confirmed": ok, "via": h, "answers": got, "of": 5, "controls_answered": ctl,
                "controls_sent": 2 * len(controls), "arp_answered": arp_ans, "answered_directly": direct,
                "summary": f"{got}/5 TTL=1 answers via {h}, {ctl}/{2 * len(controls)} answers via other hosts, "
                           f"ARP {'answered' if arp_ans else 'silent'}, direct/gateway {'answered' if direct else 'silent'}"}
            logger.info("verify %s: %s", s_ip, ev.hidden_checks[s_ip]["summary"] + (" -> CONFIRMED" if ok else " -> REFUTED"))
        self._phase_timer("verify", t0)

    # ---- pivot sweep ----------------------------------------------------------------------------
    def _pivot_sweep(self) -> None:
        t0 = time.time()
        ev = self.ingest.ev
        silent = [x for x in self._targets() if not self._known(x)]
        via_hosts = set(ev.forwarders)
        via_hosts |= {ip for ip, c in self._classes.items() if c.forwarding_anomaly}
        if self.gw_mac and self.transport.gateway_ip:
            via_hosts.add(self.transport.gateway_ip)
        via_hosts = {h for h in via_hosts if (h in ev.arp_mac or h == self.transport.gateway_ip)}
        sent = 0
        for h in sorted(via_hosts, key=ip_int):
            mac = mac_bytes(ev.arp_mac.get(h) or self.gw_mac)
            for s in silent:
                if s == h:
                    continue
                n = ip_int(s)
                sent += self._tx(self.rp.fwd_echo(mac, n, 2, self._fwd_index(s, h, 2)), "pivot:echo")
                sent += self._tx(self.rp.fwd_tcp_ack(mac, n, 80, 2, self._fwd_index(s, h, 2, tcp=True)), "pivot:ack80")
                sent += self._tx(self.rp.fwd_tcp_ack(mac, n, 443, 2, self._fwd_index(s, h, 2, tcp=True)), "pivot:ack443")
        self._settle(2.5)
        self._phase_timer("pivot", t0)
        found = sorted(s for s in ev.via if s in set(silent))
        logger.info("pivot sweep: %d probes via %d host(s); %d previously silent address(es) answered: %s",
                    sent, len(via_hosts), len(found), found)

    # ---- the leash: TTL >= 3 -----------------------------------------------------------------------
    def _eligible(self, ip: str, ttl: int) -> bool:
        if ttl > self.max_hops:
            return False
        silent, hops = 0, self.ingest.ev.hops.get(ip, {})
        for h in range(2, ttl):
            router = hops.get(h)
            if router is None:
                silent += 1
                if silent > self.allow_silent:
                    self._stopped[ip] = UNEXPLORED_SILENT
                    return False
            elif not self.scope.in_scope(router):
                self._stopped[ip] = LEAVES_SCOPE
                return False
        return True

    def _waves(self) -> None:
        t0 = time.time()
        for ttl in range(3, self.max_hops + 1):
            elig = [x for x in self._targets() if not self._known(x) and self._eligible(x, ttl)]
            if not elig or self._remaining() < 40:
                break
            logger.info("leash wave TTL=%d: %d address(es)", ttl, len(elig))
            for ip in elig:
                mac, _ = self._next_hop(ip)
                if mac is None:
                    continue
                n = ip_int(ip)
                self._tx(self.rp.echo(mac, n, ttl), f"ttl{ttl}:echo")
                self._tx(self.rp.tcp_ack(mac, n, 80, ttl), f"ttl{ttl}:ack")
                self._tx(self.rp.tcp_syn(mac, n, 443, ttl), f"ttl{ttl}:syn")
            self._settle(1.0)
        self._phase_timer("waves", t0)

    # ---- infer ---------------------------------------------------------------------------------------
    def _infer(self) -> list[seg.Segment]:
        self.ingest.promote_fwd()
        self.ingest.flush()
        ev, t = self.ingest.ev, self.transport
        self._classes = classify.classify_all(self._answering(), ev, gateway_mac=self.gw_mac, gateway_ip=t.gateway_ip)
        found = seg.infer(self._classes, ev, self.scope.networks, gateway_ip=t.gateway_ip)

        self.store.clear_segments()
        for s in found:
            if s.kind == "in-scope" and not s.local:
                self.scope.hold(s.max_extent, "separate segment: no deeper probing until the network owner approves")
                state = "held" if self.scope.is_held(s.members[0]) else "approved"
            else:
                state = "local" if s.local else "held"
            self.store.upsert_segment(
                s.cidr, kind=s.kind, state=state, verdict=s.verdict, via=s.via, evidence=s.evidence, hosts=s.members,
                extra={"covering": s.covering, "max_extent": s.max_extent, "basis": s.basis, "hidden": s.hidden,
                       "path": s.path, "distance": s.distance, "local": s.local, "prefix_known": s.prefix_known})
        self._record_link_networks()
        self.store.clear_leads("unconfirmed")
        self.store.clear_leads("anomaly")
        for ip, c in self._classes.items():
            reasons = c.proof + c.support + c.contradicts
            self.store.update_host(ip, verdict=c.verdict, distance=c.distance, visible_to=c.visible_to,
                                   reasons=reasons, roles=c.roles, held=int(self.scope.is_held(ip)))
            if c.verdict not in (classify.CONFIRMED_ONLINK, classify.CONFIRMED_SEPARATE):
                self.store.add_lead(ip, "; ".join(reasons) or "answered but not classifiable", f"unconfirmed:{c.verdict}")
            elif c.forwarding_anomaly or c.roles:
                self.store.add_lead(ip, "; ".join(c.support) or "forwarding behaviour", "anomaly:forwarder")
        self.store.clear_leads("hidden-host")
        for ip, c in self._classes.items():
            if c.verdict == classify.CONFIRMED_SEPARATE and c.proof and c.proof[0][:2] in ("R5", "R7"):
                self.store.add_lead(ip, c.proof[0], "hidden-host")
        odd: dict[int, list[str]] = {}
        for ip, ttl in ev.reply_ttl.items():
            if ttl not in (64, 128, 255):
                odd.setdefault(ttl, []).append(ip)
        for ttl, ips in odd.items():
            if len(ips) >= 2:
                for ip in ips:
                    self.store.add_lead(ip, f"reply TTL {ttl} is shared by {len(ips)} hosts ({', '.join(sorted(ips, key=ip_int))}): "
                                            "an unusual stack common to all of them, i.e. probably one controlled image", "anomaly:ttl-cluster")
        for addr, why in ev.foreign.items():
            self.store.add_lead(addr, "; ".join(sorted(why)), "outside-scope-address")
        self.store.clear_edges()
        for a, b, kind, evid in topology.build_edges(t.my_ip, self.store.hosts(), found):
            self.store.add_edge(a, b, kind, evid)
        return found

    def _record_link_networks(self) -> None:
        """The scanner's own interface subnet may be WIDER than the authorised scope (a /22 around a /24). The addresses
        in the difference share the scanner's link yet are outside the fence: they are a network that scope-limited
        discovery cannot see. Their existence is proven by the OS interface configuration alone (nothing is sent), so
        they are recorded -- and never probed."""
        mynet = self.transport.my_network
        if not mynet:
            return
        link = ipaddress.ip_network(mynet, strict=False)
        scopes = [n for n in self.scope.networks if n.version == 4]
        if link.version != 4 or any(link.subnet_of(sn) for sn in scopes):
            return
        rest = [link]
        for sn in scopes:
            nxt = []
            for r in rest:
                nxt += list(r.address_exclude(sn)) if sn.subnet_of(r) else ([] if r.subnet_of(sn) else [r])
            rest = nxt
        for r in sorted(rest, key=lambda n: int(n.network_address)):
            self.store.upsert_segment(
                str(r), kind="outside-scope", state="held", verdict="CONFIRMED_NETWORK", via=None,
                evidence=[f"the scanner's own interface subnet is {mynet}, which extends beyond the authorised scope: "
                          f"{r} is on the same link but outside the fence"],
                hosts=[], extra={"covering": str(r), "max_extent": str(r), "prefix_known": True, "local": False,
                                 "basis": "the scanner's own interface subnet (operating-system configuration); nothing was sent",
                                 "hidden": {"level": "hidden", "answered_by": [], "reasons": [
                                     "shares the scanner's link but lies outside the authorised scope, so scope-limited "
                                     "discovery cannot see it; it is recorded and never probed"]}, "path": [], "distance": None})
            self.store.add_lead(str(r), f"network on the scanner's own link but outside the authorised scope ({mynet})",
                                "outside-scope-network")

    # ---- enrichment (nmap) -----------------------------------------------------------------------------
    def _enrich(self) -> None:
        t0 = time.time()
        if not self.enrich:
            return
        budget = min(60.0, self._remaining() - 10)
        if budget < 10:
            self.notes.append("service enrichment skipped: not enough time budget left")
            return
        by_ip: dict[str, list[int]] = {}
        for (ip, port) in self.ingest._ports:
            by_ip.setdefault(ip, []).append(port)
        hints = {ip: 1 for ip, c in self._classes.items() if c.forwarding_anomaly or c.roles or not c.onlink}
        res = nmap_tool.enrich(self.scope, by_ip, my_ip=self.transport.my_ip, budget_s=budget, hints=hints,
                               workdir=str(Path("probe-data") / "nmap"))
        for r in res["records"]:
            self.store.upsert_service(r["ip"], r["port"], service=r["service"], product=r["product"],
                                      version=r["version"], extrainfo=r["extrainfo"], banner=r["banner"],
                                      scripts=r["scripts"])
        for addr, why in res["leaks"].items():
            self.ingest.ev.foreign[addr].update(why)
        self.store.clear_leads("vulnerable-app")
        for v in res["vulnerable_apps"]:
            self.store.add_lead(f"{v['ip']}:{v['port']}", f"deliberately vulnerable application ({v['match']}): {v['title']}",
                                "vulnerable-app")
            self.notes.append(f"VULNERABLE APP {v['ip']}:{v['port']} -> {v['match']} ({v['title'][:60]})")
        if res["error"]:
            self.notes.append(res["error"])
        self._phase_timer("enrich", t0)
        logger.info("enrichment: %d hosts, %d services, %d leaked address(es) in %.1fs", res["ran"],
                    len(res["records"]), len(res["leaks"]), res["seconds"])

    def _identify(self) -> None:
        for h in self.store.hosts():
            if h["ip"] == self.transport.my_ip:
                continue
            vendor = self.oui.get((h["mac"] or "").replace(":", "")[:6].upper())
            self.store.update_host(h["ip"], vendor=vendor, os_guess=os_hint(h["ttl"]))

    # ---- main -------------------------------------------------------------------------------------------------
    def run(self) -> None:
        self._t0 = time.time()
        t = self.transport
        self.ingest = Ingest(self.scope, self.store, "", "", on_mac=t.allow_mac)
        t.on_packet = self.ingest.handle
        if t.max_packets is None:
            t.max_packets = len(self._all_targets()) * (len(self.ports) + 60) + 20000
        t.start()
        self.ingest.my_ip, self.ingest.my_mac = t.my_ip, (t.my_mac or "").lower()
        self.rp = RawProbes(t.my_mac, t.my_ip)
        self._scan_id = self.store.start_scan([str(n) for n in self.scope.networks])
        self._event("scan.started", scope=[str(n) for n in self.scope.networks])
        try:
            self._status("gateway")
            if t.gateway_ip and self.scope.in_scope(t.gateway_ip):
                self._arp([t.gateway_ip], settle=1.0)
                self.gw_mac = self.ingest.ev.arp_mac.get(t.gateway_ip)
            if not self.gw_mac:
                self.notes.append(f"no in-scope gateway MAC learned (gateway={t.gateway_ip}): only hosts that answer ARP "
                                  "can be reached; routed segments will be missed")
                logger.warning(self.notes[-1])
            targets = self._targets()

            t1 = time.time()
            self._status("arp")
            self._arp_stable(targets)
            self._phase_timer("arp", t1)

            self._status("blitz")
            self._blitz(targets)
            self._status("loss")
            self._loss_passes(targets)
            self._status("stragglers")
            self._stragglers()
            self._status("recheck")
            self._arp_recheck()
            self._status("forwarders")
            self._forwarder_tests()

            self._status("catchall")
            self._characterize_catchall()
            self._status("infer")
            t2 = time.time()
            self._infer()
            self.deep = True                       # from here on held segments are off limits
            self._phase_timer("infer", t2)

            self._status("pivot")
            self._pivot_sweep()
            self._status("verify")
            self._verify_hidden()
            self._status("waves")
            self._waves()
            self._status("infer")
            self._infer()

            self._status("enrich")
            self._enrich()
            self._status("infer")
            self._infer()
            self._identify()

            self.timings["total"] = round(time.time() - self._t0, 1)
            summary = self.summary()
            self.store.finish_scan(self._scan_id, "done", summary)
            self._event("scan.finished", **summary)
            self._pass_done = True
            self._status("done")
            if self.on_done:
                self.on_done(self)
        finally:
            self._status()
            t.stop()

    def summary(self) -> dict:
        segs = self.store.segments()
        return {"hosts": len(self._answering()), "open_ports": self._open_count(),
                "segments": [{"cidr": s["cidr"], "kind": s["kind"], "state": s["state"], "via": s["via"]} for s in segs],
                "forwarders": sorted(self.ingest.ev.forwarders), "timings": self.timings, "notes": self.notes,
                "probes_sent": len(self.transport.sent), "sent_out_of_scope": self.transport.sent_out_of_scope,
                "seconds": self.timings.get("total")}
