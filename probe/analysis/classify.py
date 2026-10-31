"""Per-host classification by *proof*, not by score.

Question answered for every responding in-scope host: is it attached to the same layer-2 broadcast
domain as the scanner (ON-LINK), or is it SEPARATE (reachable only through a router/proxy)?

Lessons from field testing on a busy Wi-Fi network are baked in:
  * "first answered at TTL=2" is NOT proof of a router: on busy Wi-Fi a TTL=1 probe is often just lost,
    or the phone was asleep. Distance is supporting evidence only.
  * a time-exceeded reply is NOT proof either, if the probe was addressed to the gateway's MAC while the
    host was really on-link (its own ARP answer had not arrived yet).
  * the thing that cannot be faked by loss or sleep is *who owns the MAC that answered ARP*.

Each rule is an observation that entails a conclusion (given the assumption stated beside it).
CONFIRMED needs an entailing observation and nothing entailing the opposite; the rest is SUSPECTED /
UNRESOLVED and is shown as unconfirmed, never as a network.

  ON-LINK proofs
    L5  its L3 replies reach us from one MAC that is no known router's and belongs to no other address
                                                               => delivered directly: same link
        (seen in the field: a phone that ignored ARP but answered pings from its own MAC; ARP alone cannot
        separate "asleep" from "elsewhere", the reply MAC can)
    L1  the host itself answered a probe sent with TTL=1      => delivered without being forwarded
    L2  the gateway ICMP-redirected traffic straight to it     => same link as the gateway and us
    L3  it answered ARP with a MAC that belongs to no known router and to no other address, and every
        L3 reply from it arrives from that same MAC            => that MAC is the host's own interface
        (assumes no unknown device proxy-ARPs with a unique MAC; R1p below catches such a proxy)
    L4  it is itself a router/gateway address answered from its own MAC on our link
  SEPARATE proofs
    R5  it never answered directly or via the gateway, yet answers when its packets are addressed through an
        in-scope host H, AND its replies come back through H's MAC
                                                               => it sits behind H (H forwards IP)
        (a forwarder also hairpins packets to ordinary on-link hosts; those reply from their OWN MAC, so the
        return path is what separates "behind H" from "on our link but ignoring ARP")
        (the pivot sweep: this is how a network behind a dual-homed host / VM host / proxy-ARP box shows up)
    R1p a probe addressed to the MAC that answered ARP for the host drew ICMP time-exceeded from that
        very MAC                                               => that device forwards instead of
        terminating: it is a proxy-ARP router for the host
    R3  the host answered L3 probes yet ignored repeated ARP sent immediately afterwards, AND every
        L3 reply reached us via a known router's MAC (a host that really sits behind a router answers
        from the router's MAC)                                 => it is not on our broadcast domain
        (assumes no Wi-Fi client isolation blocking ARP between clients: then the honest reading is
        "L2-separate", not necessarily a different IP subnet; the report says so)

  FORWARDING EVIDENCE (changes what the ON-LINK proofs may conclude)
    R4  every reply from the host has TTL = standard-initial minus one (63, 127, 254, 31), at least twice
                                                               => the reply crossed a forwarding hop; when it
        also arrives from the MAC that answered ARP, that device forwards on the host's behalf (NAT / bridge /
        VM / container host). L3 and L5 are then NOT allowed to call the host on-link (their assumption "no
        unknown proxy" is refuted); it becomes SUSPECTED_SEPARATE and is queued for the pivot sweep and the
        service/banner enrichment, which can confirm or refute it.
    R8  a host's OWN stack (ping, closed-port RST) answers with TTL T, but a specific open port answers with TTL T-1
                                                               => that service is served one forwarding hop behind the
        host (DNAT / port-forward to a container or VM): a system and network the scan cannot address directly.
        Needs no banner and no extra probing; suspected, never proof.
    R6  an in-scope host H answered a TTL=1 packet that was NOT for it with ICMP time-exceeded
                                                               => H forwards IP packets: a pivot candidate
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..discovery.ingest import Evidence

CONFIRMED_ONLINK = "CONFIRMED_ONLINK"
CONFIRMED_SEPARATE = "CONFIRMED_SEPARATE"
SUSPECTED_ONLINK = "SUSPECTED_ONLINK"
SUSPECTED_SEPARATE = "SUSPECTED_SEPARATE"
CONFLICT = "CONFLICT"
UNRESOLVED = "UNRESOLVED"

BASELINE = {"arp", "icmp-echo"}   # what a "standard" ARP + ping sweep can see
DECREMENTED = {31, 63, 127, 254}   # standard initial TTLs (32/64/128/255) minus one forwarding hop


@dataclass
class HostClass:
    ip: str
    verdict: str = UNRESOLVED
    distance: int | None = None            # supporting only: wave in which the host first answered
    min_distance: int | None = None
    path: dict[int, str] = field(default_factory=dict)   # ttl -> router address that sent time-exceeded
    proof: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    support: list[str] = field(default_factory=list)
    proxy_arp: bool = False
    visible_to: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)          # e.g. "forwarder"
    forwarding_anomaly: bool = False                         # R4
    behind_ports: dict[int, str] = field(default_factory=dict)   # R8: port -> evidence
    behind_status: dict[int, str] = field(default_factory=dict)  # R8: port -> suspected | confirmed (forwarded service)

    @property
    def separate(self) -> bool:
        return self.verdict == CONFIRMED_SEPARATE

    @property
    def onlink(self) -> bool:
        return self.verdict == CONFIRMED_ONLINK

    @property
    def baseline_visible(self) -> bool:
        return bool(BASELINE & set(self.visible_to))


def _one(ip: str, ev: Evidence, router_macs: set[str], gateway_ip: str | None,
         reply_owners: dict[str, set[str]]) -> HostClass:
    c = HostClass(ip=ip, visible_to=sorted(ev.visible.get(ip, ())))
    ladder = ev.ladder.get(ip, {})
    c.distance = min(ladder.values()) if ladder else None
    exceeded = {t: r for t, r in ev.hops.get(ip, {}).items() if r != ip}
    c.path = dict(exceeded)
    if exceeded:
        c.min_distance = max(exceeded) + 1

    mac = (ev.arp_mac.get(ip) or "").lower() or None
    shared = bool(mac) and len(ev.mac_ips.get(mac, ())) > 1
    replies = {m.lower() for m in ev.reply_mac.get(ip, ())}
    l3 = bool(set(c.visible_to) - {"arp", "icmp-error"})
    on, sep = [], []

    if ip in ev.catchall:
        c.roles.append("catch-all-responder")
        c.support.append("it answers ICMP for EVERY address, including addresses that belong to other devices "
                         "(decoy / tarpit / AnyIP gateway): its answers say nothing about any single address")
    # R8 passive baseline: the host's own TCP stack (RST to a closed port / unsolicited ACK), same protocol as the
    # SYN-ACK it is compared with (stacks may use a different initial TTL for ICMP than for TCP). Supporting only.
    own = Counter()
    for fam in ("tcp-rst", "tcp-ack"):
        own.update(ev.ttl_kind.get(ip, {}).get(fam, {}))
    own_ttl = None
    if sum(own.values()) >= 2:
        candidate, own_n = own.most_common(1)[0]
        if candidate in (32, 64, 128, 255) and own_n >= 0.8 * sum(own.values()):
            own_ttl = candidate

    # R8 active verification: a TTL=1 SYN to a port is decisive by itself (TTL expiry is a property of the IP layer,
    # independent of any passive baseline), so it is sent to every open TCP port regardless of whether a passive
    # differential was ever noticed (Engine._t_fwdsvc) -- a thin or absent passive baseline can no longer hide a
    # forwarded service. Four states, told apart explicitly:
    #   confirmed            >=2 TTL=1 SYNs answered by the host's own MAC with time-exceeded: it forwards this port
    #   verified-local        >=2 TTL=1 SYNs answered directly (local delivery ignores TTL): settled, not a question
    #   ambiguous-incomplete   some active replies, too few/mixed to call either way, or only a passive differential
    #                          with the active check not yet run: still open
    #   (absent)               nothing anomalous observed for this port
    active_ports = ({p for (h, p) in ev.ttl1_synack if h == ip} | {p for (h, p) in ev.ttl1_exceeded if h == ip}
                    | set(ev.ttl_port.get(ip, {})))
    for port in sorted(active_ports):
        synack, exceeded_n = ev.ttl1_synack.get((ip, port), 0), ev.ttl1_exceeded.get((ip, port), 0)
        cnt = ev.ttl_port.get(ip, {}).get(port)
        passive_diff = bool(cnt and own_ttl and sum(cnt.values()) >= 2 and set(cnt) == {own_ttl - 1})
        base_msg = (f"port {port} answers with TTL {(own_ttl - 1) if own_ttl else '?'} while this host's own TCP "
                    f"stack answers with TTL {own_ttl}") if own_ttl else f"port {port}"
        if exceeded_n >= 2:
            c.behind_ports[port] = (f"{base_msg}: a TTL=1 SYN to that port is answered by the host's own MAC with "
                                    f"time-exceeded ({exceeded_n}x) instead of being served -- the host FORWARDS this "
                                    "port to a device behind it")
            c.behind_status[port] = "confirmed"
        elif synack >= 2:
            if passive_diff:
                c.support.append(f"R8 refuted for port {port}: {base_msg}, but a TTL=1 SYN to that port is answered "
                                 f"by the host itself ({synack}x): the service is terminated locally")
            c.behind_status[port] = "verified-local"
        elif synack or exceeded_n:            # the active check ran but gave too few/mixed replies to call
            c.behind_status[port] = "ambiguous-incomplete"
            if passive_diff:
                c.behind_ports[port] = f"{base_msg}: TTL=1 verification attempted but inconclusive (too few replies)"
        elif passive_diff:                    # passive signal only; the active check has not run on this port yet
            c.behind_ports[port] = f"{base_msg}: consistent with a forwarded service (not yet verified with TTL=1)"
            c.behind_status[port] = "suspected"
    if c.behind_ports:
        c.roles.append("publishes-forwarded-service" if "confirmed" in c.behind_status.values() else "serves-ports-from-behind")
        c.support.append("R8: " + "; ".join(sorted(c.behind_ports.values()))[:400])
    non_service = Counter()                     # SYN-ACK TTLs describe a service, not the stack: leave them out of R4
    for kind, cnt in ev.ttl_kind.get(ip, {}).items():
        if kind != "tcp-syn":
            non_service.update(cnt)
    ttls = non_service or ev.ttls.get(ip)
    dec = bool(ttls) and sum(ttls.values()) >= 2 and all(t in DECREMENTED for t in ttls)
    c.forwarding_anomaly = dec
    if ip in ev.forwarders:
        c.roles.append("forwarder")
        c.support.append(f"R6: it answered a TTL=1 packet that was not for it with time-exceeded "
                         f"(from {ev.forwarders[ip]['sender']}): it forwards IP packets, so it may front another network")

    if ip in ev.redirected_onlink:
        on.append("L2: the gateway ICMP-redirected traffic for it straight to itself")
    if c.distance == 1 and 1 not in exceeded:
        on.append("L1: it answered a probe sent with TTL=1 (reached its IP stack without being forwarded)")
    if ip == gateway_ip and mac:
        on.append("L4: it is the default gateway, reached directly by its own MAC")
    elif ip in ev.router_macs and mac and ev.router_macs[ip].lower() == mac:
        on.append("L4: it is a router address answering from its own MAC on our link")
    elif ip in ev.forwarders and mac and not dec:
        on.append("L4: it forwards IP packets and answers ARP from its own MAC on our link (a pivot/router host)")
    elif not dec and not mac and len(replies) == 1 and not (replies & router_macs) and len(reply_owners.get(next(iter(replies)), ())) == 1:
        on.append(f"L5: its L3 replies reach us from MAC {next(iter(replies))}, which is no known router's and "
                  "belongs to no other address: delivered directly, so it shares our link")
    elif not dec and mac and mac not in router_macs and not shared and (not replies or replies <= {mac}):
        on.append(f"L3: ARP answered by MAC {mac}, which belongs to no known router and to no other address; "
                  "its replies come from that same MAC")

    if mac:
        for t, r in exceeded.items():
            if (ev.router_macs.get(r) or "").lower() == mac:
                sep.append(f"R1p: a probe addressed to {mac} (the MAC that answered ARP for it) drew "
                           f"TTL-exceeded from {r}: that device forwards rather than terminates (proxy ARP)")
                c.proxy_arp = True
                break
    elif ip in ev.arp_failed and replies and replies <= router_macs:
        sep.append("R3: it answers layer-3 probes (so it is awake) but ignored repeated ARP sent immediately "
                   "afterwards, and its replies arrive via a router's MAC, so it is not on the scanner's "
                   "broadcast domain")

    vias = {h for h in (ev.via.get(ip) or ()) if h not in ev.catchall}
    h_macs = {(ev.arp_mac.get(h) or "").lower() for h in (vias or ())}
    if vias and not mac and ip not in ev.visible_direct and replies and replies <= h_macs:
        h = sorted(vias)[0]
        sep.append(f"R5: it never answered directly or via the gateway, but answers when addressed through {h} "
                   f"(a host that forwards IP), and its replies come back through {h}'s MAC: it sits behind {h}")
        c.path = {1: h}
    hosted = {h for h in (ev.hosted_by.get(ip) or ()) if h not in ev.catchall}
    hosted_macs = {(ev.arp_mac.get(h) or "").lower() for h in (hosted or ())}
    chk = ev.hidden_checks.get(ip)
    if hosted and not mac and ip not in ev.visible_direct and replies and replies <= hosted_macs \
            and not (chk and not chk.get("confirmed")):
        h = sorted(hosted)[0]
        extra = f" Verified: {chk['summary']}." if chk else ""
        sep.append(f"R7: it answered a TTL=1 packet addressed to {h}'s MAC (never forwarded, so it was delivered to "
                   f"{h}'s own network stack), yet it ignores ARP and every direct probe: the address is hosted INSIDE "
                   f"{h} (secondary IP / virtual interface / container or VM gateway), a hidden address behind it.{extra}")
        c.path = {1: h}
    elif vias and not mac and replies and not (replies & h_macs):
        c.support.append(f"answered a packet addressed through {sorted(vias)[0]}, but the reply came straight from its "
                         "own MAC (the forwarder merely hairpinned it): it shares our link and only ignores ARP")
    if dec and not sep:
        c.support.append(f"R4: all its replies have TTL {sorted(ttls)} (= standard initial TTL minus 1): the reply path "
                         "crosses a forwarding hop (NAT / bridge / VM or container host?)")

    if c.distance and c.distance >= 2 and not sep:
        c.support.append(f"first answered at TTL={c.distance} (a lost or slow TTL=1 probe looks identical)")
    if exceeded and not sep:
        k = max(exceeded)
        c.support.append(f"router {exceeded[k]} sent TTL-exceeded at TTL={k} (it forwards towards the host; the "
                         "probe may simply have been addressed to the gateway)")

    if on and sep:
        c.verdict, c.proof, c.contradicts = CONFLICT, on, sep
    elif sep:
        c.verdict, c.proof = CONFIRMED_SEPARATE, sep
    elif on:
        c.verdict, c.proof = CONFIRMED_ONLINK, on
    elif mac:
        c.verdict = SUSPECTED_SEPARATE
        if dec:
            c.support.append("ARP-unique MAC, but the reply TTL shows a forwarding hop (R4): on-link is NOT proven")
        else:
            c.support.append(f"answered ARP with MAC {mac}, which belongs to a router or to several addresses: "
                             "proxy ARP is possible")
    elif l3:
        c.verdict = SUSPECTED_SEPARATE
        c.support.append("answers layer-3 probes but has never answered ARP; the immediate ARP re-test has "
                         "not (yet) been run or was inconclusive")
    return c


def classify_all(ips: list[str], ev: Evidence, gateway_mac: str | None = None,
                 gateway_ip: str | None = None) -> dict[str, HostClass]:
    router_macs = {m.lower() for m in ev.router_macs.values()}
    router_macs |= {ev.arp_mac[h].lower() for h in ev.forwarders if h in ev.arp_mac}   # forwarders are routers too
    if gateway_mac:
        router_macs.add(gateway_mac.lower())
    owners: dict[str, set[str]] = {}
    for host, macs in ev.reply_mac.items():
        for m in macs:
            owners.setdefault(m.lower(), set()).add(host)
    out = {ip: _one(ip, ev, router_macs, gateway_ip, owners) for ip in ips}
    for ip, c in out.items():                     # hosts that front a hidden address get a role the report can show
        if c.verdict == CONFIRMED_SEPARATE and c.path.get(1) in out and c.path[1] != ip:
            front = out[c.path[1]]
            if "fronts-hidden-network" not in front.roles:
                front.roles.append("fronts-hidden-network")
            front.support.append(f"hidden address {ip} is hosted behind this device")
    return out
