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

from . import completeness, netutil, planner, report as report_mod
from .analysis import challenge, classify, correlate, limits, topology
from .analysis import segments as seg
from .discovery import tiers
from .discovery.ingest import Ingest
from .discovery.rawprobes import RawProbes, mac_bytes
from .net import osview
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
                 budget_s: float | None = None, tcp_ports: int | None = None, rate_pps: int | None = None,
                 max_hops: int = 8, allow_silent_hops: int = 0,
                 enrich: bool = True, auditor=None, wait_scale: float = 1.0,
                 on_done: Callable[["Engine"], None] | None = None, report_dir: Path | None = None,
                 priority_addresses=(), max_completeness_budget_s: float = completeness.DEFAULT_MAX_BUDGET_S,
                 max_completeness_rounds: int = completeness.DEFAULT_MAX_ROUNDS):
        # budget / port depth / rate default to None == "derive from the environment" (planner.derive_tuning); an
        # explicit value is an operator override.
        self.scope, self.store, self.transport = scope, store, transport
        self._override = (budget_s, tcp_ports, rate_pps)
        self.budget_s, self.max_hops, self.allow_silent = budget_s or 170, max_hops, allow_silent_hops
        self.enrich, self.auditor, self.wait_scale, self.on_done = enrich, auditor, wait_scale, on_done
        self.report_dir = report_dir
        self.priority_addresses = set(priority_addresses)
        self.max_completeness_budget_s, self.max_completeness_rounds = max_completeness_budget_s, max_completeness_rounds
        self.completeness: completeness.CompletenessManager | None = None
        self.stop_reason = "not-started"
        self.planner: planner.Planner | None = None
        self.env: planner.Environment | None = None
        self.tuning: dict = {}
        self.open_questions: list[planner.Question] = []
        self.converged = False
        self.followup_rounds = 0
        self.last_round_gain: dict = {}
        self.report: dict | None = None
        self.os_candidates: list[dict] = []
        self._announced: dict[str, tuple] = {}     # what the change feed has already told consumers (key -> signature)
        self.coverage: dict[str, dict] = {}       # optional stages: how many hosts each reached
        self.os_neighbours: list = []
        self.os_routes: list = []
        self.ports = tiers.top_tcp_ports(tcp_ports or 200)
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
        self._service_records: list[dict] = []     # nmap results, re-applied after every inference pass
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
    def _suite_cheap(self, targets: list[str], light: bool = False) -> int:
        """echo + ACK80/443 + SYN to the cheap ports, to every target. Used by the blitz and by loss checks.
        light=True (retransmits to addresses that have answered nothing): echo + the two ACK probes only."""
        sent = 0
        for ip in targets:
            mac, ttl = self._next_hop(ip)
            if mac is None:
                continue
            n = ip_int(ip)
            sent += self._tx(self.rp.echo(mac, n, ttl), "tier1:echo")
            sent += self._tx(self.rp.tcp_ack(mac, n, 80, ttl), "tier2:ack80")
            sent += self._tx(self.rp.tcp_ack(mac, n, 443, ttl), "tier2:ack443")
            if light:
                continue
            for p in self.cheap_ports:
                sent += self._tx(self.rp.tcp_syn(mac, n, p, ttl), "tier2:syn")
        return sent

    def _suite_rest(self, targets: list[str], ports: list[int] | None = None) -> int:
        """tier 3/4 and the remaining top-N ports, interleaved across hosts (round-robin) so no host is hammered."""
        sent = 0
        hops = {ip: self._next_hop(ip) for ip in targets}
        ints = {ip: ip_int(ip) for ip in targets}
        for ip in targets:
            mac, ttl = hops[ip]
            if mac is None:
                continue
            if ports is None:
                self._blitzed.add(ip)          # 'blitzed' = got the FULL port list; quiet addresses can still be upgraded later
            sent += self._tx(self.rp.timestamp(mac, ints[ip], ttl), "tier3:ts")
            sent += self._tx(self.rp.mask(mac, ints[ip], ttl), "tier3:mask")
            sent += self._tx(self.rp.udp(mac, ints[ip], 40125, ttl), "tier4:udp")
        rest = [p for p in (ports if ports is not None else self.ports) if p not in self.cheap_ports]
        for p in rest:
            for ip in targets:
                mac, ttl = hops[ip]
                if mac is not None:
                    sent += self._tx(self.rp.tcp_syn(mac, ints[ip], p, ttl), "tier2:syn")
        return sent

    QUIET_PORTS = 20         # port depth for addresses that answered nothing
    MATRIX_PAIRS = 20000     # cap on host x silent-address pairs in one alias-matrix pass (~30 s at line rate)

    def _open_count(self) -> int:
        return len(self.ingest._ports)

    def _blitz(self, targets: list[str]) -> None:
        t0 = time.time()
        self.ingest.targets_low16 = {ip_int(x) & 0xFFFF: x for x in self._all_targets()}
        n = self._suite_cheap(targets)
        self._settle(1.2)
        # Depth follows evidence. Anything that answered the cheap suite or ARP gets the full port list; an address that
        # answered NOTHING (on a big scope most of them) gets the tier-3/4 probes and the next-most-common ports. An on-link
        # host cannot hide from ARP, so this loses no on-link host; it stops spending ~200 packets on every empty address.
        live = [x for x in targets if self._known(x) or x in self.ingest.ev.arp_mac]
        quiet = [x for x in targets if x not in set(live)]
        n += self._suite_rest(live)
        if quiet:
            n += self._suite_rest(quiet, ports=self.ports[:self.QUIET_PORTS])
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
            live = [x for x in targets if self._known(x) or x in self.ingest.ev.arp_mac]
            liveset = set(live)
            self._suite_cheap(live)                                             # full cheap suite where something lives
            self._suite_cheap([x for x in targets if x not in liveset], light=True)   # empty addresses: 3 probes, not 14
            self.transport.set_rate(fast)
            self._settle(1.2)
            hosts1, ports1 = len([x for x in targets if self._known(x)]), self._open_count()
            gained = (hosts1 - hosts0, ports1 - ports0)
            logger.info("loss pass %d: +%d hosts +%d open ports", rnd, *gained)
            if gained == (0, 0):
                break
            if sum(gained) <= max(3, (hosts1 + ports1) // 50):
                continue                                                         # a trickle is not congestion: repeat, same rate
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
        if len(hosts) * len(silent) > self.MATRIX_PAIRS and silent:
            # too many pairs for one pass: test the most telling hosts first (forwarders, then hosts with the most open
            # ports), as many as fit; the rest are reported as not covered rather than silently skipped
            nports: dict[str, int] = {}
            for (pip, _pp) in self.ingest._ports:
                nports[pip] = nports.get(pip, 0) + 1
            hosts.sort(key=lambda h: (h not in self.priority_addresses, h not in ev.forwarders, -nports.get(h, 0), ip_int(h)))
            keep = max(8, self.MATRIX_PAIRS // len(silent))
            if keep < len(hosts):
                self.notes.append(f"alias matrix: {keep} of {len(hosts)} on-link hosts tested against {len(silent)} silent addresses "
                                  f"(pair cap {self.MATRIX_PAIRS}); the remaining hosts were not used as a front")
                hosts = hosts[:keep]
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
        ports = self.cheap_ports[:8 if len(silent) < 200 else 3]
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
                for boundary in ([s.cidr] if s.prefix_known else [f"{ip}/32" for ip in s.members]):
                    self.scope.hold(boundary, "separate attachment: hold the observed address/prefix, never a guessed covering range")
                state = "held" if self.scope.is_held(s.members[0]) else "approved"
            else:
                state = "local" if s.local else "held"
            self.store.upsert_segment(
                s.cidr, kind=s.kind, state=state, verdict=s.verdict, via=s.via, evidence=s.evidence, hosts=s.members,
                extra={"covering": s.covering, "max_extent": s.max_extent, "basis": s.basis, "hidden": s.hidden,
                       "path": s.path, "distance": s.distance, "local": s.local, "prefix_known": s.prefix_known})
        self._record_link_networks()
        self._record_candidates()
        self.store.clear_leads("unconfirmed")
        self.store.clear_leads("anomaly")
        for ip, c in self._classes.items():
            reasons = c.proof + c.support + c.contradicts
            self.store.update_host(ip, verdict=c.verdict, distance=c.distance, visible_to=c.visible_to,
                                   reasons=reasons, roles=c.roles, held=int(self.scope.is_held(ip)))
            stack = ev.stack_ttl(ip)
            if stack is not None:
                self.store.update_host(ip, ttl=stack)          # the host's own stack, not whichever reply came last
            if c.verdict not in (classify.CONFIRMED_ONLINK, classify.CONFIRMED_SEPARATE):
                self.store.add_lead(ip, "; ".join(reasons) or "answered but not classifiable", f"unconfirmed:{c.verdict}")
            else:
                if c.forwarding_anomaly or "forwarder" in c.roles:
                    self.store.add_lead(ip, "; ".join(c.support) or "forwarding behaviour", "anomaly:forwarder")
                for role in c.roles:                          # one lead kind per role, so a lead says what it is about
                    if role not in ("forwarder", "serves-ports-from-behind", "publishes-forwarded-service"):
                        self.store.add_lead(ip, "; ".join(c.support) or role, f"anomaly:{role}")
        self._service_os_mismatch(self._service_records)      # _infer clears 'anomaly*' leads: re-derive this one from evidence
        self.store.clear_leads("anomaly:ttl-differential")
        self.store.clear_leads("forwarded-service")
        for ip, c in self._classes.items():
            for port, status in c.behind_status.items():
                # append-only history, tagged with THIS scan: a status seen in an earlier scan is never silently
                # reused as today's proof -- _state()/hints below read observations_for() explicitly as history.
                self.store.add_observation(self._scan_id, ip, "r8-status", status, port=port, proto="tcp")
            for port, why in c.behind_ports.items():
                if c.behind_status.get(port) == "confirmed":
                    self.store.add_lead(f"{ip}:{port}", why, "forwarded-service")
                else:
                    self.store.add_lead(f"{ip}:{port}", why + " (suspected: a container/VM/port-forward target behind the host)",
                                        "anomaly:ttl-differential")
        self.store.clear_leads("hidden-host")
        for ip, c in self._classes.items():
            if c.verdict == classify.CONFIRMED_SEPARATE and c.proof and c.proof[0][:2] in ("R5", "R7"):
                self.store.add_lead(ip, c.proof[0], "hidden-host")
        odd: dict[int, list[str]] = {}
        for ip in list(ev.visible):
            ttl = ev.stack_ttl(ip)
            if ttl is not None and ttl not in (64, 128, 255):
                odd.setdefault(ttl, []).append(ip)
        for ttl, ips in odd.items():
            if len(ips) >= 2:
                for ip in ips:
                    self.store.add_lead(ip, f"reply TTL {ttl} is shared by {len(ips)} hosts ({', '.join(sorted(ips, key=ip_int))}): "
                                            "an unusual stack common to all of them, i.e. probably one controlled image", "anomaly:ttl-cluster")
        for addr, why in ev.foreign.items():
            self.store.add_lead(addr, "; ".join(sorted(why)), "outside-scope-address")
        self.store.clear_edges()
        for a, b, kind, evid in topology.build_edges(t.my_ip, self.store.hosts(), found,
                                                   link_subnet=t.my_network, classes=self._classes):
            self.store.add_edge(a, b, kind, evid)
        self._announce()
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
                str(r), kind="outside-scope", state="held", verdict="ADDRESS_SLICE", via=None,
                evidence=[f"the scanner's own interface subnet is {mynet}, which extends beyond the authorised scope: "
                          f"{r} is on the same link but outside the fence"],
                hosts=[], extra={"covering": str(r), "max_extent": str(r), "prefix_known": False, "local": False,
                                 "basis": "authorisation remainder of the configured interface prefix; an address slice, not a separate discovered subnet",
                                 "hidden": {"level": "hidden", "answered_by": [], "reasons": [
                                     "shares the scanner's link but lies outside the authorised scope, so scope-limited "
                                     "discovery cannot see it; it is recorded and never probed"]}, "path": [], "distance": None})
            self.store.add_lead(str(r), f"network on the scanner's own link but outside the authorised scope ({mynet})",
                                "outside-scope-network")

    # ---- enrichment (nmap) -----------------------------------------------------------------------------
    ANOMALY_KINDS = ("r8-status",)       # observation `kind`s that keep an address in the priority queue across scans

    def _ever_anomalous(self) -> set[str]:
        """Addresses flagged anomalous in ANY past scan (this run's own classification may have stopped flagging
        them this round, e.g. a lost reply). History read from the observation ledger, used only to keep the
        priority queue from dropping a device just because its role flickered off for one scan."""
        out: set[str] = set()
        for kind in self.ANOMALY_KINDS:
            out |= self.store.ever_observed(kind)
        return out

    def _enrich(self) -> None:
        t0 = time.time()
        if not self.enrich:
            return
        budget = min(110.0, max(self._remaining(), 50.0) - 10)       # floor: service identification is never starved by follow-ups
        if budget < 10:
            self.notes.append("service enrichment skipped: not enough time budget left")
            return
        by_ip: dict[str, list[int]] = {}
        for (ip, port) in self.ingest._ports:
            by_ip.setdefault(ip, []).append(port)
        ever = self._ever_anomalous()
        hints = {ip: (1 + (5 if ip in ever else 0)) for ip, c in self._classes.items()
                 if c.forwarding_anomaly or c.roles or not c.onlink or ip in ever}
        res = nmap_tool.enrich(self.scope, by_ip, my_ip=self.transport.my_ip, budget_s=budget, hints=hints, skip_noise=False,
                               workdir=str((self.report_dir or Path("probe-data")) / "nmap"))
        for r in res["records"]:
            self.store.upsert_service(r["ip"], r["port"], service=r["service"], product=r["product"],
                                      version=r["version"], extrainfo=r["extrainfo"], banner=r["banner"],
                                      scripts=r["scripts"])
        got = {(r["ip"], r["port"]) for r in res["records"]}
        reasons = {"not-started": "not attempted: the identification stage ran out of time before reaching this host",
                   "incomplete": "attempted: nmap did not finish (timeout) -- the port was open to a raw SYN but no full "
                                 "connection produced a banner",
                   "complete": "attempted: nmap finished but did not report the port open (it did not complete a full TCP "
                               "connection: closed, filtered, reset, or answered only to raw SYNs)",
                   "egress-refused": "not attempted: the independent egress enforcement check refused this launch "
                                     "(nmap was never started for this host) -- a precondition failure, not evidence "
                                     "about the port itself"}
        for ip, ports in (res.get("attempted") or {}).items():
            for port, st in ports.items():
                if (ip, port) not in got:
                    self.store.mark_ident(ip, port, "tcp", "unidentified-attempted" if st != "not-started" else "discovered",
                                          reasons.get(st, st))
        for addr, why in res["leaks"].items():
            self.ingest.ev.foreign[addr].update(why)
        self.store.clear_leads("vulnerable-app")
        for v in res["vulnerable_apps"]:
            self.store.add_lead(f"{v['ip']}:{v['port']}", f"deliberately vulnerable application ({v['match']}): {v['title']}",
                                "vulnerable-app")
            self.notes.append(f"VULNERABLE APP {v['ip']}:{v['port']} -> {v['match']} ({v['title'][:60]})")
        for ip, info in (res.get("hosts") or {}).items():
            if info.get("hostname"):
                self.store.update_host(ip, hostname=info["hostname"], hostname_source=info.get("hostname_source"))
        self._service_records.extend(res["records"])
        self._service_os_mismatch(self._service_records)
        if res["error"]:
            self.notes.append(res["error"])
        self._phase_timer("enrich", t0)
        self._announce()
        logger.info("enrichment: %d hosts, %d services, %d leaked address(es) in %.1fs", res["ran"],
                    len(res["records"]), len(res["leaks"]), res["seconds"])

    LINUX_MARKS = ("debian", "ubuntu", "alpine", "centos", "fedora", "red hat", "rhel", "(unix)", "linux", "alpine")
    WINDOWS_MARKS = ("microsoft", "iis", "win32", "win64", "windows")

    def _service_os_mismatch(self, records: list[dict]) -> None:
        """A service whose own banner names one operating system, on a host whose TCP/IP stack looks like another, is
        probably not running on that host: it is published from a container / VM / port-forward behind it, i.e. there is
        a system (and network) behind the host that the scan cannot address directly. Evidence only: SUSPECTED, never
        proof, and nothing behind the host is probed."""
        ev = self.ingest.ev
        self.store.clear_leads("anomaly:service-behind-host")
        for r in records:
            text = " ".join([r.get("product") or "", r.get("extrainfo") or "", r.get("banner") or "",
                             *(r.get("scripts") or {}).values()]).lower()
            ttl = ev.stack_ttl(r["ip"])
            if not ttl or not text:
                continue
            stack = os_hint(ttl) or ""
            banner_os = ("Linux/Unix" if any(m in text for m in self.LINUX_MARKS) else
                         "Windows" if any(m in text for m in self.WINDOWS_MARKS) else None)
            if banner_os == "Linux/Unix" and stack.startswith("Windows") or banner_os == "Windows" and stack.startswith("Linux"):
                self.store.add_lead(
                    f"{r['ip']}:{r['port']}",
                    f"the service banner names {banner_os} ({(r.get('product') or '')} {(r.get('extrainfo') or '')}".strip() +
                    f") but the host's TCP/IP stack looks like {stack} (reply TTL {ttl}): the service is probably hosted in a "
                    "container/VM/port-forward behind this host (an unseen system or network segment). Suspected, not proven.",
                    "anomaly:service-behind-host")

    def _identify(self) -> None:
        self.store.label_unidentified_ports(tiers.service_name)
        for h in self.store.hosts():
            if h["ip"] == self.transport.my_ip:
                continue
            vendor = self.oui.get((h["mac"] or "").replace(":", "")[:6].upper())
            self.store.update_host(h["ip"], vendor=vendor, os_guess=os_hint(h["ttl"]))

    # ---- autonomy: environment -> technique choice -> adaptive rounds -> report -----------------------------------
    def _http_inventory(self) -> None:
        targets = {}
        for ip, port in self.ingest._ports:
            targets.setdefault(ip, []).append(port)
        ever = self._ever_anomalous()
        hints = {ip: (10 if ip in self.priority_addresses else 5 if ip in ever else 1)
                 for ip, c in self._classes.items() if ip in self.priority_addresses or c.roles or ip in ever}
        res = nmap_tool.http_inventory(self.scope, targets, budget_s=min(45, max(0, self._remaining() - 20)),
                                       hints=hints, workdir=str((self.report_dir or Path("probe-data")) / "nmap"))
        records = [r for _, rows in res["results"] for r in rows]
        for r in records:
            self.store.upsert_service(r["ip"], r["port"], service=r["service"], product=r["product"],
                                      version=r["version"], extrainfo=r["extrainfo"], banner=r["banner"], scripts=r["scripts"])
        self._service_records.extend(records)
        for addr, why in nmap_tool.find_leaks(records, self.scope, self.transport.my_ip).items():
            self.ingest.ev.foreign[addr].update(why)
        self.coverage["http_inventory"] = {"total": len(res["ran"]) + len(res["notrun"]),
                                           "covered": sum(any(r.get("scripts", {}).get("http-inventory") for r in rows) for _, rows in res["results"]),
                                           "notrun": res["notrun"]}
        if res.get("error"):
            self.notes.append(res["error"])

    def _t_gateway(self) -> None:
        t = self.transport
        self._arp([t.gateway_ip], settle=1.0)
        self.gw_mac = self.ingest.ev.arp_mac.get(t.gateway_ip)
        self.env.gateway_mac = self.gw_mac

    def _t_osview(self) -> None:
        """Read the OS's routing and neighbour tables (local query, nothing sent)."""
        t = self.transport
        self.os_routes = osview.routes()
        self.os_neighbours = osview.neighbours()
        self.os_candidates = osview.candidate_networks(self.os_routes, scope_nets=self.scope.networks,
                                                       if_index=getattr(t, "if_index", None),
                                                       link_subnet=getattr(t, "my_network", None))

    def _candidate_segment(self, cidr: str, verdict: str, evidence: list[str], basis: str, prefix_known: bool, reason: str) -> None:
        self.store.upsert_segment(
            cidr, kind="outside-scope", state="held", verdict=verdict, via=None, evidence=evidence, hosts=[],
            extra={"covering": cidr, "max_extent": cidr, "prefix_known": prefix_known, "local": False, "basis": basis,
                   "hidden": {"level": "hidden", "answered_by": [], "reasons": [reason]}, "path": [], "distance": None,
                   "authorisation": "NOT AUTHORISED: recorded only, never probed"})

    def _record_candidates(self) -> None:
        """Networks beyond the fence, from three kinds of evidence, labelled by how strong it is:
          CONFIRMED_NETWORK    the OS reports it directly attached to the scanner's interface (configuration fact)
          SUSPECTED_NETWORK    the OS has a route to it via a gateway (configured, not observed answering)
          UNVERIFIED_CANDIDATE an address leaked in service output / an out-of-scope router answered: the network exists
                               but its prefix is unknown; it is stored as an address-only /32
        None is probed, and none changes the scope."""
        have = [ipaddress.ip_network(s["cidr"]) for s in self.store.segments() if s["kind"] == "outside-scope"]
        for c in self.os_candidates:
            net = ipaddress.ip_network(c["cidr"])
            if net in have:
                continue
            have.append(net)
            if c["kind"] == "attached":
                self._candidate_segment(c["cidr"], "CONFIRMED_NETWORK",
                                        [f"the operating system reports {c['cidr']} directly attached to the scanner's interface"],
                                        "OS routing table (nothing sent)", True,
                                        "attached to the scanner's link but outside the authorised scope")
            else:
                self._candidate_segment(c["cidr"], "SUSPECTED_NETWORK",
                                        [f"the operating system has a route to {c['cidr']} via {c['gateway']}; no host in it has been seen"],
                                        "OS routing table (nothing sent)", True,
                                        "routed network outside the authorised scope: a configured route is not an observation")
        for addr, why in sorted(self.ingest.ev.foreign.items()):
            try:
                a = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if a.version != 4 or self.scope.in_scope(addr) or any(a in n for n in have):
                continue
            net = ipaddress.ip_network(f"{addr}/32", strict=False)
            have.append(net)
            self._candidate_segment(str(net), "UNVERIFIED_CANDIDATE",
                                    [f"{addr}: " + "; ".join(sorted(why))],
                                    "address reference only; /32 identifies an address, not a discovered subnet", False,
                                    "inferred from a single observed address; prefix unknown")

    def _t_fingerprint(self) -> None:
        """UDP services and OS fingerprints, concurrently, on every answering host that is not a known catch-all decoy."""
        import threading
        ev = self.ingest.ev
        hosts = [ip for ip in self._answering() if ip not in ev.catchall and ip != self.transport.my_ip
                 and not self.scope.is_held(ip)]
        tcp: dict[str, list[int]] = {}
        for (ip, port) in self.ingest._ports:
            tcp.setdefault(ip, []).append(port)
        ever = self._ever_anomalous()
        hosts.sort(key=lambda h: (h not in self.priority_addresses, h not in ever, -len(tcp.get(h, [])), ip_int(h)))
        wd = str((self.report_dir or Path("probe-data")) / "nmap")
        out: dict[str, dict] = {}
        threads = [
            threading.Thread(target=lambda: out.__setitem__("udp", nmap_tool.udp_scan(self.scope, hosts, budget_s=45, workdir=wd))),
            threading.Thread(target=lambda: out.__setitem__("os", nmap_tool.os_scan(
                self.scope, {ip: sorted(tcp[ip]) for ip in hosts if ip in tcp}, budget_s=45, workdir=wd)))]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        udp, osr = out.get("udp") or {}, out.get("os") or {}
        n_udp = 0
        for ip, parsed in udp.get("results", []):
            for k, v in (parsed.get("hosts") or {}).items():
                if v.get("hostname"):
                    self.store.update_host(k, hostname=v["hostname"], hostname_source=v.get("hostname_source"))
            for r in parsed.get("records") or []:
                self.store.upsert_service(ip, r["port"], proto="udp", service=r["service"], product=r["product"],
                                          version=r["version"], extrainfo=r["extrainfo"], banner=r["banner"],
                                          scripts=r["scripts"], method="nmap-udp-scan")
                n_udp += 1
        n_os = 0
        for ip, parsed in osr.get("results", []):
            info = parsed.get(ip) or {}
            if info.get("os"):
                self.store.update_host(ip, os_detail=f"{info['os']} (accuracy {info['os_accuracy']}%)",
                                       device_type=info.get("device_type"))
                n_os += 1
        self.coverage["udp"] = {"covered": len(udp.get("completed", [])), "attempted": len(udp.get("ran", [])), "total": len(hosts), "open_found": n_udp,
                                "ports": nmap_tool.UDP_PORTS}
        self.coverage["os"] = {"covered": len(osr.get("completed", [])), "attempted": len(osr.get("ran", [])), "total": len([ip for ip in hosts if ip in tcp]),
                               "fingerprinted": n_os}
        self._announce()
        self.notes.append(f"UDP: top-{nmap_tool.UDP_PORTS} ports on {self.coverage['udp']['covered']}/{len(hosts)} hosts, "
                          f"{n_udp} open; OS fingerprint for {n_os} of {self.coverage['os']['covered']} attempted")

    def _t_fwdsvc(self) -> None:
        """Send a TTL=1 SYN to EVERY open TCP port whose host has a known MAC -- independent of any prior passive
        signal. TTL expiry is decisive by itself (RFC 791): a port a passive baseline never flagged (too few replies
        sampled, or a non-standard initial TTL) is still verified directly, so a genuinely forwarded service cannot
        be missed merely because the passive evidence for it was thin. A service terminated ON the host answers
        (local delivery ignores TTL); one the host only forwards (NAT / port-forward / container) cannot forward a
        TTL=1 packet, so the host answers time-exceeded instead. Four SYNs per port, addressed to the host's own MAC
        and its own IP only -- never sent through a held segment."""
        ev = self.ingest.ev
        by_ip: dict[str, set[int]] = {}
        for (ip, port) in self.ingest._ports:
            by_ip.setdefault(ip, set()).add(port)
        for ip, ports in by_ip.items():
            mac = ev.arp_mac.get(ip)
            if not mac or self.scope.is_held(ip):
                continue
            for port in ports:
                for _ in range(4):
                    self._tx(self.rp.tcp_syn(mac_bytes(mac), ip_int(ip), port, 1), "r8-verify:ttl1-syn")
        self._settle(1.5)

    def _register_techniques(self) -> None:
        T, reg = planner.Technique, self.planner.register
        Q = planner

        def when(cond, yes: str, no: str):
            return lambda e, s: (True, yes) if cond(e, s) else (False, no)

        reg(T("http-inventory", "read HTTP root metadata before slow version detection; no redirects or credentials",
              self._http_inventory,
              when(lambda e, s: e.nmap and self.enrich and s.ports_open > 0 and s.remaining_s > 25,
                   "known open ports may expose topology references", "no open ports, helper unavailable or budget exhausted"),
              answers=(Q.Q_BACKEND, Q.Q_PREFIX, Q.Q_SUSPECT)))
        reg(T("os-network-view", "read the OS's interfaces/routes/neighbours: attached and routed networks (no packets)",
              self._t_osview, when(lambda e, s: True, "local query; reveals attached/routed networks without sending anything", "")))
        reg(T("gateway-resolution", "learn the in-scope gateway's MAC so routed targets get an in-scope next hop", self._t_gateway,
              when(lambda e, s: e.gateway_in_scope, "a gateway lies inside the scope: resolve it",
                   "no gateway inside the scope: routed targets cannot be given an in-scope next hop")))
        reg(T("arp-sweep", "ownership of every address on the scanner's link (authoritative, cannot be spoofed by a router)",
              lambda: self._arp_stable(self._targets()),
              when(lambda e, s: True, "ARP is the proof of on-link ownership; run first on every scope",
                   "")))
        reg(T("tiered-probe-blitz", "ICMP / TCP ACK / SYN / UDP suite on every address, round-robin",
              lambda: self._blitz(self._targets()),
              when(lambda e, s: s.arp_known > 0 or bool(e.gateway_mac), "a next hop is known (ARP responders and/or gateway)",
                   "needs a next-hop MAC: neither an ARP responder nor a gateway MAC is known")))
        reg(T("loss-recovery", "repeat the cheap suite until nothing new appears; slow down if loss is detected",
              lambda: self._loss_passes(self._targets()),
              when(lambda e, s: s.answered > 0, "hosts answered, so repeated passes can expose lost replies", "nothing answered yet"),
              answers=(Q.Q_NO_MAC, Q.Q_UNRESOLVED, Q.Q_CONFLICT), repeatable=True))
        reg(T("straggler-probing", "give late ARP responders the full suite",
              self._stragglers,
              when(lambda e, s: s.silent > 0 or s.arp_known > 0, "ARP responders may still be arriving",
                   "needs hosts or silent addresses to chase"),
              answers=(Q.Q_ARP_LOSS,), repeatable=True))
        reg(T("arp-recheck", "re-ask ARP for hosts that answered at layer 3 only (decides on-link vs routed)",
              self._arp_recheck,
              when(lambda e, s: s.answered > 0, "layer-3-only answers need ARP ownership to be classified", "nothing answered"),
              answers=(Q.Q_NO_MAC, Q.Q_UNRESOLVED, Q.Q_CONFLICT), repeatable=True))
        reg(T("forwarder-matrix", "TTL=1 echo to each host's MAC for every silent address: finds routers/NAT hosts and hosted aliases",
              self._forwarder_tests,
              when(lambda e, s: s.arp_known >= 2 and s.silent > 0, "silent addresses exist and there are hosts to test them against",
                   "needs at least two on-link hosts and one silent address"),
              answers=(Q.Q_UNRESOLVED, Q.Q_CONFLICT, Q.Q_SUSPECT, Q.Q_SILENT_BEHIND), repeatable=True))
        reg(T("catchall-characterization", "classify catch-all responders (tarpit / plain stack / DNAT gateway)",
              self._characterize_catchall,
              when(lambda e, s: s.catchall > 0, "catch-all responder(s) were detected", "no catch-all responder detected")))
        reg(T("pivot-sweep", "sweep still-silent addresses through each forwarder/anomaly host/gateway",
              self._pivot_sweep,
              when(lambda e, s: s.silent > 0 and (s.forwarders > 0 or bool(e.gateway_mac)),
                   "silent addresses remain and a proven forwarder/gateway exists", "needs silent addresses and a forwarder or gateway"),
              answers=(Q.Q_SILENT_BEHIND,), repeatable=True))
        reg(T("forwarded-service-check", "TTL=1 SYN to every port whose SYN-ACK TTL differs from the host's stack (R8)",
              self._t_fwdsvc,
              when(lambda e, s: s.ports_open > 0, "open TCP ports exist: verify each one with a TTL=1 SYN regardless "
                   "of whether a passive TTL differential was ever noticed", "no open TCP port to verify"),
              repeatable=True))
        reg(T("hidden-verification", "controls + repeats on every address claimed to be hosted behind another host",
              self._verify_hidden,
              when(lambda e, s: s.hosted > 0, "an address was claimed to be hosted behind a host: verify it",
                   "no hosted-address claim to verify")))
        reg(T("ttl-leash-waves", "TTL>=3 probes, only along paths proven inside the scope",
              self._waves,
              when(lambda e, s: s.silent > 0 and bool(e.gateway_mac), "silent addresses remain and the gateway is a proven in-scope hop",
                   "needs silent addresses and an in-scope gateway MAC"),
              answers=(Q.Q_SILENT_BEHIND,), repeatable=True))
        reg(T("host-fingerprinting", "UDP services and OS fingerprint (nmap -sU / -O), budgeted, per-launch scope check",
              self._t_fingerprint,
              when(lambda e, s: e.nmap and self.enrich and s.answered > 0, "answering hosts exist and nmap is available",
                   "nmap not available, disabled, or nothing answered"), phase="final"))
        reg(T("service-enrichment", "identify services/banners on open ports (nmap, connect scan)",
              self._enrich,
              when(lambda e, s: e.nmap and self.enrich and s.ports_open > 0, "open ports exist and nmap is available",
                   "nmap not available, disabled, or no open port found"), phase="final"))

    def _silent(self) -> list[str]:
        return [x for x in self._targets() if not self._known(x)]

    def _state(self) -> planner.State:
        ev = self.ingest.ev
        return planner.State(
            env=self.env, answered=len(self._answering()), silent=len(self._silent()), arp_known=len(ev.arp_mac),
            forwarders=len(ev.forwarders), ports_open=self._open_count(),
            unresolved=sum(1 for c in self._classes.values() if c.verdict not in (classify.CONFIRMED_ONLINK, classify.CONFIRMED_SEPARATE)),
            held_segments=len(self.scope.held), catchall=len(ev.catchall), hosted=len(ev.hosted_by),
            remaining_s=self._remaining())

    def _questions(self) -> list[planner.Question]:
        qs = planner.open_questions(self._classes, self.ingest.ev, blitzed=self._blitzed, silent=self._silent())
        for h in self.store.hosts():
            for p in h.get("open_ports", []):
                if p.get("identification") not in ("identified", "identified-product"):
                    qs.append(planner.Question("service-identification-incomplete", f"{h['ip']}:{p['port']}/{p.get('proto','tcp')}",
                                               p.get("ident_note") or "open endpoint; service identity not established"))
        for lead in self.store.leads():
            if lead["source"] == "anomaly:service-behind-host":
                qs.append(planner.Question(planner.Q_BACKEND, lead["address"], lead["evidence"]))
        return qs

    def _snapshot(self) -> dict:
        snap = planner.knowledge(self.ingest.ev, self._open_count(), len(self._silent()))
        snap["service_metadata"] = sum(len(r.get("scripts") or {}) for r in self._service_records)
        return snap

    def _step(self, name: str, phase: str, *, min_time: float = 0.0) -> None:
        st = self._state()
        if self.planner.decide(name, st, min_time_s=min_time):
            self._status(phase)
            self.planner.execute(name, st, self._snapshot)
            self.store.set_meta("decisions", self.planner.as_list())

    def _autonomous_pass(self) -> None:
        t = self.transport
        self.completeness = completeness.CompletenessManager(
            self.store, self.scope, scan_id=self._scan_id, max_budget_s=self.max_completeness_budget_s,
            max_rounds=self.max_completeness_rounds)
        if not self.env.gateway_in_scope or not t.gateway_ip:
            self.gw_mac = None
        self._step("os-network-view", "osview")
        self._step("gateway-resolution", "gateway")
        if not self.gw_mac:
            self.notes.append(f"no in-scope gateway MAC learned (gateway={t.gateway_ip}): only hosts that answer ARP "
                              "can be reached; routed segments will be missed")
            logger.warning(self.notes[-1])
        for name, phase in (("arp-sweep", "arp"), ("tiered-probe-blitz", "blitz"), ("loss-recovery", "loss"),
                            ("straggler-probing", "stragglers"), ("arp-recheck", "recheck"),
                            ("forwarder-matrix", "forwarders"), ("catchall-characterization", "catchall")):
            self._step(name, phase)
        self._status("infer")
        t2 = time.time()
        self._infer()
        self.deep = True                           # from here on held segments are off limits
        self._phase_timer("infer", t2)
        for name, phase in (("pivot-sweep", "pivot"), ("hidden-verification", "verify"),
                            ("forwarded-service-check", "fwdsvc"), ("ttl-leash-waves", "waves")):
            self._step(name, phase)
        self._status("infer")
        self._infer()
        self._step("http-inventory", "http-inventory")
        self._infer()
        self._followups()
        self.timings["discovery"] = round(time.time() - self._t0, 1)      # everything up to here is discovery proper
        # sequential on purpose: run beside service identification, ~80 concurrent nmap processes starved it and only 13 of
        # 270 services were identified (vs 50 when it ran alone)
        self._step("service-enrichment", "enrich")
        self._step("host-fingerprinting", "fingerprint")
        self._status("infer")
        self._infer()
        self._step("forwarded-service-check", "post-service-forwarding")
        self._infer()
        self.open_questions = self._questions()
        if self.open_questions:
            self.converged = False
            self.stop_reason = "unresolved-evidence-or-capability"
        self._identify()

    FOLLOWUP_RESERVE_S = 20          # follow-up rounds may use the ENGINE's own budget down to this; enrichment has its own floor

    _STOP_TOKEN = {
        "no open items remain": "questions-settled",
        "the previous round added no new evidence: repeating it is not permitted work": "no-observed-information-gain",
    }

    def _stop_token(self, why: str) -> str:
        if why in self._STOP_TOKEN:
            return self._STOP_TOKEN[why]
        if why.startswith("max_rounds"):
            return "completeness-max-rounds-reached"
        if why.startswith("max_budget_s"):
            return "completeness-budget-exhausted"
        return why

    def _followups(self) -> None:
        """Adaptive rounds, governed by the Discovery Completeness Manager (probe/completeness.py): look at what is
        still unresolved, pick the techniques that can answer THAT, run them, measure what they added, and stop when
        the manager says to -- a bounded number of rounds, a bounded wall-clock budget, and never a round that
        merely repeats work the previous round already showed adds nothing."""
        pl, ev = self.planner, self.ingest.ev
        qmap: dict[str, list[str]] = {}
        for tq in pl.techniques.values():
            for k in tq.answers:
                qmap.setdefault(k, []).append(tq.name)
        cm = self.completeness
        self.converged = False
        while True:
            self.open_questions = self._questions()
            ok, why = cm.should_continue(open_count=len(self.open_questions))
            if not ok:
                pl.note("adaptive-loop", "stop", why)
                self.converged = (why == "no open items remain")
                self.stop_reason = self._stop_token(why)
                break
            rnd = cm.begin_round(self.open_questions)
            pl.round = rnd
            if self._remaining() < self.FOLLOWUP_RESERVE_S:
                pl.note("adaptive-loop", "defer", f"{len(self.open_questions)} open question(s) but only {self._remaining():.0f}s "
                        f"of the engine's own budget left (reserve {self.FOLLOWUP_RESERVE_S}s for enrichment and the report)")
                cm.end_round({})
                self.converged = False
                self.stop_reason = "engine-time-budget-exhausted"
                break
            kinds = sorted({q.kind for q in self.open_questions})
            wanted = list(dict.fromkeys(n for k in kinds for n in qmap.get(k, [])))
            total: dict[str, int] = {}
            ran = False
            for name in wanted:
                if self._remaining() < self.FOLLOWUP_RESERVE_S:
                    break
                st = self._state()
                if pl.decide(name, st):
                    self._status(f"followup:{name}")
                    why2 = sorted({k for k in kinds if name in qmap.get(k, [])})
                    g = pl.execute(name, st, self._snapshot, reason="answers open question(s): " + ", ".join(why2))
                    ran = True
                    for k, v in g.items():
                        total[k] = total.get(k, 0) + v
                    self._infer()
            self.followup_rounds, self.last_round_gain = rnd, total
            self.store.set_meta("decisions", pl.as_list())
            cm.end_round(total)
            if not ran:
                pl.note("adaptive-loop", "stop", "no applicable technique is left for the remaining questions")
                self.converged = False
                self.stop_reason = "no-applicable-method"
                break
            self._infer()
        self.open_questions = self._questions()

    def _announce(self) -> None:
        """Publish what is new or changed since the last announcement to the change feed, so a consumer (the orchestrator)
        learns of every host, service, segment and candidate network exactly once and sees later improvements (a service
        identified after it was first found) as updates. Derived from the store, so nothing found can be left out."""
        add, seen = self.store.add_event, self._announced

        def emit(key: str, sig: tuple, first: str, again: str, payload: dict) -> None:
            old = seen.get(key)
            if old == sig:
                return
            seen[key] = sig
            add(first if old is None else again, {"scan_id": self._scan_id, **payload})

        for h in self.store.hosts():
            ip = h["ip"]
            if ip == self.transport.my_ip:
                continue
            emit("h:" + ip, (h["verdict"], tuple(h["roles"] if isinstance(h["roles"], list) else [])), "host.discovered", "host.updated",
                 {"ip": ip, "mac": h["mac"], "verdict": h["verdict"], "roles": h["roles"] if isinstance(h["roles"], list) else [],
                  "held": bool(h["held"])})
            for p in h.get("open_ports") or []:
                emit(f"s:{ip}:{p['port']}/{p.get('proto', 'tcp')}", (p.get("service"), p.get("product"), p.get("version")),
                     "service.discovered", "service.updated",
                     {"ip": ip, "port": p["port"], "proto": p.get("proto", "tcp"), "service": p.get("service"),
                      "product": p.get("product"), "version": p.get("version"), "method": p.get("method")})
        for g in self.store.segments():
            if g["kind"] == "in-scope" and g.get("extra", {}).get("local"):
                continue
            outside = g["kind"] != "in-scope"
            emit("g:" + g["cidr"], (g["verdict"],), "network.candidate" if outside else "segment.found",
                 "network.candidate" if outside else "segment.found",
                 {"cidr": g["cidr"], "status": g["verdict"], "kind": g["kind"], "evidence": (g["evidence"] or [""])[0]})

    def _neighbour_crosscheck(self) -> dict:
        """Compare the OS neighbour table with what this run's own ARP found. The table is a cross-check, never a source of
        hosts: a stale entry is not a discovery."""
        ev = self.ingest.ev
        mism, only_os = [], []
        for n in self.os_neighbours:
            if not self.scope.in_scope(n.ip) or n.ip == self.transport.my_ip:
                continue
            mine = ev.arp_mac.get(n.ip)
            if mine and mine.lower() != n.mac.lower():
                mism.append({"address": n.ip, "os_neighbour_mac": n.mac, "probe_arp_mac": mine})
            elif not mine:
                only_os.append({"address": n.ip, "mac": n.mac, "state": n.state})
        return {"entries_in_scope": sum(1 for n in self.os_neighbours if self.scope.in_scope(n.ip)),
                "mac_mismatches": mism, "in_os_table_but_silent_this_run": only_os,
                "note": "the OS table is history, not discovery: silent entries are not added to the inventory"}

    def _finish_report(self) -> None:
        hosts = self.store.hosts()
        ev = self.ingest.ev
        from .analysis import network_facts
        facts = network_facts.collect(hosts, ev, self.env.as_dict(), self.os_routes)
        corr = correlate.correlate(hosts, ev, gateway_mac=self.gw_mac, my_ip=self.transport.my_ip)
        segs = self.store.segments()
        lim = limits.analyse(
            env=self.env.as_dict(), questions=[q.as_dict() for q in self.open_questions], converged=self.converged,
            rounds=self.followup_rounds, last_gain=self.last_round_gain, segments=segs, leads=self.store.leads(),
            decisions=self.planner.as_list(), stopped=self._stopped, catchall=sorted(ev.catchall),
            held_blocked=self.scope.held_blocked, ipv6_ignored=self.env.ipv6_scope, coverage=self.coverage)
        silent = self._silent()
        unanswered = {"addresses_in_scope": len(self._all_targets()), "answered": len(self._answering()), "count": len(silent),
                      "ranges": netutil.compress_ranges(silent),
                      "note": "these addresses are not known to answer; stage coverage and actual send records determine which probes reached them; "
                              "silence is not proof of absence, and no device record is invented"}
        safety = {"scope_frozen": self.scope.frozen, "probes_sent": len(self.transport.sent),
                  "sent_out_of_scope": self.transport.sent_out_of_scope, "blocked_before_send": self.scope.stray_count,
                  "held_probes_refused": self.scope.held_blocked}
        safety["independent_audit"] = self.auditor.wire_summary() if self.auditor else {"verified": False}
        safety["authorisation"] = self.store.meta().get("authorisation")
        self.report = report_mod.build(
            scope=[str(n) for n in self.scope.networks], env=self.env.as_dict(), tuning=self.tuning, hosts=hosts, segments=segs,
            edges=self.store.edges(), leads=self.store.leads(), correlation=corr, limits=lim,
            decisions=self.planner.as_list(), timings=self.timings, notes=self.notes, safety=safety,
            crosscheck=self._neighbour_crosscheck(), challenge=challenge.find_candidates(hosts), unanswered=unanswered,
            challenge_rules=challenge.RULES)
        self.report["network_observations"] = facts
        self.report["open_questions"] = [q.as_dict() for q in self.open_questions]
        self.report["stop_reason"] = self.stop_reason
        if self.completeness is not None:
            self.report["completeness"] = self.completeness.finish(converged=self.converged, stop_reason=self.stop_reason)
        sent = self.transport.sent
        self.report["coverage"] = {"targets": len(self._all_targets()), "tcp_ports_per_target": len(self.ports),
            "addresses_probed": len({r.dst for r in sent}), "stages": self.coverage,
            "note": "bounded ranked-port coverage, not all 65535 TCP/UDP ports; silence is inconclusive"}
        for c in self.report["challenge_artifact_candidates"]:
            self.store.add_event("lead.recorded", {"scan_id": self._scan_id, "source": "challenge-artifact",
                                                   "address": f"{c['address']}:{c['port']}", "shape": c["shape"]})
        self.store.set_meta("report", self.report)
        self.store.set_meta("decisions", self.planner.as_list())
        try:
            jp, mp = report_mod.write(self.report, self.report_dir or Path("probe-data"))
            self.notes.append(f"report written: {mp} and {jp}")
        except OSError as exc:                                         # pragma: no cover - the DB copy still exists
            self.notes.append(f"could not write report files: {exc}")

    # ---- main -------------------------------------------------------------------------------------------------
    def run(self) -> None:
        self._t0 = time.time()
        t = self.transport
        self.ingest = Ingest(self.scope, self.store, "", "", on_mac=t.allow_mac)
        t.on_packet = self.ingest.handle
        self.env = planner.inspect(self.scope, t)
        self.tuning = planner.derive_tuning(self.env, budget_s=self._override[0], tcp_ports=self._override[1],
                                            rate_pps=self._override[2])
        self.budget_s = self.tuning["budget_s"]
        if self._override[1] is None or self.tuning["tcp_ports"] != len(self.ports):
            self.ports = tiers.top_tcp_ports(self.tuning["tcp_ports"])
        if self._override[2] is None:
            t.set_rate(self.tuning["rate_pps"])
        self.planner = planner.Planner(self.env)
        self._register_techniques()
        if t.max_packets is None:
            t.max_packets = len(self._all_targets()) * (len(self.ports) + 60) + 20000
        t.start()
        self.ingest.my_ip, self.ingest.my_mac = t.my_ip, (t.my_mac or "").lower()
        self.rp = RawProbes(t.my_mac, t.my_ip)
        self._scan_id = self.store.start_scan([str(n) for n in self.scope.networks])
        self._event("scan.started", scope=[str(n) for n in self.scope.networks])
        try:
            self._autonomous_pass()
            self.timings["total"] = round(time.time() - self._t0, 1)
            self._finish_report()
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
                "seconds": self.timings.get("total"), "converged": self.converged, "follow_up_rounds": self.followup_rounds,
                "open_questions": len(self.open_questions), "techniques_run": sorted(self.planner.runs) if self.planner else [],
                "derived_settings": self.tuning}
