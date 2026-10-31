"""Correlation: turn per-address observations into DEVICES, remove duplicates, and resolve conflicting evidence.

An address is not a device. The same machine can own several addresses (aliases, multi-homing, a container host), and
one MAC can answer for many addresses without owning them (a proxy-ARP gateway, a catch-all). Counting addresses as
devices would inflate the inventory and report phantom hosts; this module counts devices, with the reasoning attached.

Rules (all evidence-based, none tuned to a network):
  * Hardware identity is the MAC that ANSWERED ARP for the address. Addresses sharing one such MAC are one device
    -- unless that MAC is known to speak FOR others (the gateway/router MAC, a forwarder, a catch-all responder), in
    which case it is a proxy and its addresses stay separate, each marked "answered via <mac>".
  * Addresses with no MAC (answered only at layer 3, e.g. behind a forwarder) stay their own devices, marked
    unattributed: there is nothing to merge them on and guessing would be a fabrication.
  * Conflicts are never silently resolved: an address that answered with two different MACs is reported with both and
    a resolution that says which was kept and why (the MAC that answered ARP directly beats one inferred from replies).
"""
from __future__ import annotations

from collections import defaultdict


def _key(a: str) -> tuple:
    return tuple(int(x) for x in a.split("."))


def correlate(hosts: list[dict], ev, *, gateway_mac: str | None = None, my_ip: str | None = None) -> dict:
    rm = getattr(ev, "router_macs", None) or {}
    proxies = {str(x).lower() for x in [*rm.keys(), *rm.values()] if ":" in str(x)}
    if gateway_mac:
        proxies.add(gateway_mac.lower())
    for f in set(getattr(ev, "forwarders", None) or set()) | set(getattr(ev, "catchall", None) or set()):
        m = ev.arp_mac.get(f)
        if m:
            proxies.add(m.lower())

    by_mac: dict[str, list[dict]] = defaultdict(list)
    no_mac: list[dict] = []
    for h in hosts:
        if h["ip"] == my_ip:
            continue
        mac = (h.get("mac") or "").lower()
        (by_mac[mac] if mac else no_mac).append(h)

    devices: list[dict] = []
    merged: list[dict] = []
    for mac, group in by_mac.items():
        if mac in proxies and len(group) > 1:
            for h in group:
                devices.append(_device([h], mac, f"answered via proxy/forwarder MAC {mac}: shares the MAC with "
                                       f"{len(group) - 1} other address(es) but is not claimed to be the same machine",
                                       proxy=True))
            continue
        devices.append(_device(group, mac, None))
        if len(group) > 1:
            merged.append({"mac": mac, "addresses": sorted((h["ip"] for h in group), key=_key),
                           "reason": "one hardware address answered ARP for all of these: one device with several addresses"})
    for h in no_mac:
        devices.append(_device([h], None, "no MAC learned (answers only at layer 3): cannot be merged with another device"))

    conflicts = []
    for ip, macs in (getattr(ev, "reply_mac", None) or {}).items():
        macs = {m.lower() for m in macs if m}
        if len(macs) > 1:
            direct = (ev.arp_mac.get(ip) or "").lower()
            conflicts.append({"address": ip, "macs": sorted(macs), "kept": direct or sorted(macs)[0],
                              "resolution": ("kept the MAC that answered ARP directly" if direct
                                             else "no direct ARP answer: unresolved, first MAC shown"),
                              "resolved": bool(direct)})
    for d in devices:
        d["conflicts"] = [c for c in conflicts if c["address"] in d["addresses"]]
    devices.sort(key=lambda d: _key(d["addresses"][0]))
    return {"devices": devices, "merged": merged, "conflicts": conflicts,
            "address_count": sum(len(d["addresses"]) for d in devices), "device_count": len(devices),
            "duplicates_removed": sum(len(m["addresses"]) - 1 for m in merged)}


def _device(group: list[dict], mac: str | None, note: str | None, proxy: bool = False) -> dict:
    ips = sorted((h["ip"] for h in group), key=_key)
    first = group[0]
    return {"id": mac or f"addr:{ips[0]}", "mac": mac, "addresses": ips, "vendor": first.get("vendor"),
            "hostname": next((h.get("hostname") for h in group if h.get("hostname")), None),
            "hostname_source": next((h.get("hostname_source") for h in group if h.get("hostname")), None),
            "os_guess": first.get("os_guess"),
            "os_detail": next((h.get("os_detail") for h in group if h.get("os_detail")), None),
            "device_type": next((h.get("device_type") for h in group if h.get("device_type")), None),
            "first_seen": min((h.get("first_seen") for h in group if h.get("first_seen")), default=None),
            "discovery_methods": sorted({m for h in group for m in (h.get("discovery_methods") or [])}), "roles": sorted({r for h in group for r in (h.get("roles") or [])}),
            "verdicts": sorted({h.get("verdict") for h in group if h.get("verdict")}),
            "open_ports": sorted({(p["port"] if isinstance(p, dict) else p) for h in group for p in (h.get("open_ports") or [])}),
            "proxy_mac": proxy, "note": note}
