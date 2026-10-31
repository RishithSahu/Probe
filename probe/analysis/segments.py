"""Subnet / segment inference.

Facts we start from (all from probe replies, see classify.py): which hosts are
CONFIRMED_ONLINK or CONFIRMED_SEPARATE, and for routed ones the router path.

Model: an IP subnet is one aligned, contiguous CIDR block, and every host in it
is attached to the same place. So:

 1. Label every confirmed host by its attachment point: "local" (our link) or
    the router path it sits behind. Hosts whose known path hops disagree, or
    whose measured distance differs, cannot share an attachment point.
 2. Sort labelled hosts by address. A maximal run of one label is a candidate
    segment; labels never interleave inside a single subnet.
 3. For each run report what the evidence actually bounds, instead of a guess:
      covering    smallest aligned block containing the members (lower bound)
      max_extent  largest aligned block that stays inside the scope and contains
                  no host of any other attachment point (upper bound)
    The true subnet is an aligned block between the two. A host that tells us
    its own prefix length (ICMP address-mask reply) collapses the interval to
    that exact block, provided it is consistent with the other labelled hosts.
 4. Hidden-ness is not a score: it is "which probe classes ever made a member
    answer", compared with a standard ARP + ping sweep.

Unlabelled hosts (SUSPECTED / UNRESOLVED / CONFLICT) never create or move a
segment; they are reported as unconfirmed leads so a wrong guess cannot become a
false alarm.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..discovery.ingest import Evidence
from .classify import CONFIRMED_ONLINK, CONFIRMED_SEPARATE, HostClass

LOCAL = "local"


@dataclass
class Segment:
    cidr: str                      # lower-bound block (or the exact block when basis == icmp-mask)
    kind: str                      # in-scope | outside-scope
    verdict: str                   # CONFIRMED | CONFIRMED_ADDRESS (existence proven, prefix unknown)
    local: bool = False
    via: str | None = None
    distance: int | None = None
    path: list[str | None] = field(default_factory=list)
    members: list[str] = field(default_factory=list)
    covering: str = ""
    max_extent: str = ""
    basis: str = "members"
    prefix_known: bool = True
    hidden: dict = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


def _summarise(cls: list[HostClass]) -> list[str]:
    """One line per proof rule, with a count and one example, instead of hundreds of near-identical lines."""
    groups: dict[str, list[str]] = {}
    for c in cls:
        for p in c.proof:
            groups.setdefault(p.split(":")[0], []).append(p)
    return [f"{k} x{len(v)}: {v[0]}" if len(v) > 1 else v[0] for k, v in sorted(groups.items())]


def _ip(i: str):
    return ipaddress.ip_address(i)


def _cover(ips) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(f"{ips[0]}/32")
    while not all(i in net for i in ips) and net.prefixlen > 0:
        net = net.supernet()
    return net


def _compatible(a: HostClass, b: HostClass) -> bool:
    if a.distance and b.distance and a.distance != b.distance:
        return False
    return all(a.path[t] == b.path[t] for t in set(a.path) & set(b.path))


def _label(routed: list[HostClass]) -> dict[str, str]:
    """Group routed hosts into attachment points (greedy, order-independent enough
    because incompatibility is only ever a hard disagreement on a known fact)."""
    clusters: list[list[HostClass]] = []
    for c in sorted(routed, key=lambda c: int(_ip(c.ip))):
        for cl in clusters:
            if all(_compatible(c, m) for m in cl):
                cl.append(c)
                break
        else:
            clusters.append([c])
    return {c.ip: f"via#{n}" for n, cl in enumerate(clusters) for c in cl}


def _split(ips, others, scope_net) -> list[list]:
    """Partition one run into the fewest aligned blocks that contain no foreign host."""
    net = _cover(ips)
    if len(ips) == 1 or not any(o in net for o in others):
        return [ips]
    lo, hi = list(net.subnets(prefixlen_diff=1))
    out: list[list] = []
    for half in (lo, hi):
        part = [i for i in ips if i in half]
        if part:
            out += _split(part, others, scope_net)
    return out


def infer(classes: dict[str, HostClass], ev: Evidence, scope_nets, *, gateway_ip: str | None = None) -> list[Segment]:
    scope_nets = [n for n in scope_nets if n.version == 4]
    labels: dict[str, str] = {c.ip: LOCAL for c in classes.values() if c.verdict == CONFIRMED_ONLINK}
    routed = [c for c in classes.values() if c.verdict == CONFIRMED_SEPARATE]
    labels.update(_label(routed))
    ordered = sorted(labels, key=lambda i: int(_ip(i)))
    segments: list[Segment] = []

    # ---- maximal runs of one label ---------------------------------------------------
    runs: list[list[str]] = []
    for ip in ordered:
        if runs and labels[runs[-1][-1]] == labels[ip]:
            runs[-1].append(ip)
        else:
            runs.append([ip])

    # The scanner's own link is ONE network however many separate hosts sit among its addresses: report it
    # whole (with the separate hosts listed as holes) instead of fragmenting it around them.
    for sn in scope_nets:
        loc = [_ip(i) for i in ordered if labels[i] == LOCAL and _ip(i) in sn]
        if not loc:
            continue
        cover = _cover(loc)
        holes = [i for i in ordered if labels[i] != LOCAL and _ip(i) in cover]
        cls = [classes[str(i)] for i in loc]
        seg = Segment(cidr=str(cover), kind="in-scope", verdict="CONFIRMED", local=True,
                      members=[str(i) for i in loc], covering=str(cover), max_extent=str(sn),
                      basis="members-only (no host reported its prefix length)", evidence=_summarise(cls))
        if holes:
            seg.evidence.append(f"holes: {', '.join(holes)} sit inside this block but are not on this link")
        seg.hidden = hidden_verdict(cls, ev, seg)
        segments.append(seg)

    for run in runs:
        label = labels[run[0]]
        if label == LOCAL:
            continue
        scope_net = next((n for n in scope_nets if _ip(run[0]) in n), None)
        if scope_net is None:
            continue
        others = [_ip(i) for i in ordered if labels[i] != label]
        for part in _split([_ip(i) for i in run], others, scope_net):
            members = [str(i) for i in part]
            cover = _cover(part)
            # upper bound: grow while we stay in scope and swallow no host of another attachment point
            upper = cover
            while upper.prefixlen > scope_net.prefixlen:
                bigger = upper.supernet()
                if any(o in bigger for o in others):
                    break
                upper = bigger
            basis, exact = "members-only (no host reported its prefix length)", None
            masks = {ev.masks[m] for m in members if m in ev.masks}
            if len(masks) == 1:
                cand = ipaddress.ip_network(f"{members[0]}/{next(iter(masks))}", strict=False)
                if all(i in cand for i in part) and not any(o in cand for o in others) \
                        and cand.subnet_of(scope_net):
                    exact, basis = cand, "prefix length reported by the hosts themselves (ICMP address mask)"
            cls = [classes[m] for m in members]
            seg = Segment(
                cidr=str(exact or cover), kind="in-scope", verdict="CONFIRMED", local=label == LOCAL,
                members=members, covering=str(exact or cover), max_extent=str(exact or upper), basis=basis,
                evidence=_summarise(cls))
            if label != LOCAL:
                d = {c.distance for c in cls if c.distance}
                seg.distance = min(d) if d else None
                hops = [{t: c.path[t] for t in c.path} for c in cls]
                maxt = max([max(h) for h in hops if h] + [(seg.distance or 1) - 1])
                seg.path = [next((h[t] for h in hops if t in h), None) for t in range(1, maxt + 1)]
                known = [h for h in seg.path if h]
                seg.via = known[-1] if known else gateway_ip
            seg.hidden = hidden_verdict(cls, ev, seg)
            segments.append(seg)

    # ---- networks outside the authorised range: existence only, never probed --------------
    for addr, why in sorted(ev.foreign.items()):
        a = _ip(addr)
        if a.is_multicast or a.is_unspecified or a.is_loopback or any(a in n for n in scope_nets):
            continue
        segments.append(Segment(
            cidr=f"{addr}/32", kind="outside-scope", verdict="CONFIRMED_ADDRESS", via=addr, members=[addr],
            covering=f"{addr}/32", max_extent="unknown", basis="address only: no prefix length was observed",
            prefix_known=False, evidence=sorted(why),
            hidden={"level": "hidden", "reasons": ["reachable only as a router/interface address revealed by "
                                                   "an in-scope probe; outside the authorised range"]}))
    return segments


def hidden_verdict(members: list[HostClass], ev: Evidence, seg: Segment) -> dict:
    """'Hidden' = a standard ARP + ping sweep would not have revealed this segment."""
    seen_by = sorted({k.split(":")[0] for c in members for k in c.visible_to})
    echo = "icmp-echo" in seen_by
    reasons: list[str] = []
    via_only = bool(members) and all(m.ip in ev.via or m.ip in ev.hosted_by for m in members)
    if via_only:
        hosts = sorted({h for m in members for h in (ev.via.get(m.ip, set()) | ev.hosted_by.get(m.ip, set()))})
        return {"level": "hidden", "answered_by": seen_by, "reasons": [
            f"never answered directly or via the gateway: reachable only when packets are addressed through "
            f"{', '.join(hosts)} (a host that forwards IP), so a standard sweep from the scanner reveals nothing",
            "answered only: " + (", ".join(seen_by) or "nothing")]}
    if seg.local:
        level = "visible"
        reasons.append("on the scanner's own link")
    else:
        level = "visible" if echo else "hidden"
        if not echo:
            reasons.append("no member answered ICMP echo, so a ping sweep reveals nothing")
        if "arp" not in seen_by:
            reasons.append("no member answered ARP: not on the scanner's link")
        if seg.distance:
            reasons.append(f"{seg.distance - 1} router hop(s) in front of it")
        if any(c.proxy_arp for c in members):
            reasons.append("ARP for some members is answered by a proxy, masking that they are routed")
        blocked = sorted({r for m in seg.members for r, code in ev.unreach.get(m, ()) if code in (9, 10, 13)})
        if blocked:
            reasons.append(f"filtering device(s) {', '.join(blocked)} report 'administratively prohibited'")
    reasons.append("answered only: " + (", ".join(seen_by) or "nothing"))
    return {"level": level, "reasons": reasons, "answered_by": seen_by}
