"""The operating system's own view of the network: interfaces, routes, neighbours. Read-only, sends nothing.

The OS already knows things a scanner would otherwise have to infer: which networks are directly attached to which
interface, which networks the host has a route to (and via which gateway), and which neighbours it has recently
talked to. Reading those tables is a local query (Windows iphlpapi / Linux procfs), needs no packet, and cannot leave
the scope. Used for two things only:

  * network CANDIDATES: routes and attached subnets that are not inside the authorised scope are recorded with their
    evidence and a proposed CIDR -- and never probed;
  * CROSS-CHECKS: the neighbour table is compared with what this run's own ARP found. It is not a source of hosts
    (a stale entry is not a discovery); a disagreement is reported as a conflict.
"""
from __future__ import annotations

import ipaddress
import struct
import sys
from dataclasses import dataclass


@dataclass
class Route:
    network: str          # CIDR
    gateway: str | None   # None = directly attached
    if_index: int | None
    metric: int | None = None


@dataclass
class Neighbour:
    ip: str
    mac: str
    if_index: int | None
    state: str


def _ip_le(v: int) -> str:
    return str(ipaddress.ip_address(struct.pack("<I", v)))


def _prefix(mask_ip: str) -> int:
    return bin(int(ipaddress.ip_address(mask_ip))).count("1")


def parse_proc_routes(text: str) -> list[Route]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        dest, gw, mask = (_ip_le(int(x, 16)) for x in (f[1], f[2], f[7]))
        out.append(Route(f"{dest}/{_prefix(mask)}", None if gw == "0.0.0.0" else gw, None, int(f[6])))
    return out


def parse_proc_arp(text: str) -> list[Neighbour]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[3] != "00:00:00:00:00:00":
            out.append(Neighbour(f[0], f[3].lower(), None, "reachable" if f[2] == "0x2" else "stale"))
    return out


def _windows_routes() -> list[Route]:
    import ctypes
    from ctypes import wintypes
    api = ctypes.windll.iphlpapi
    size = wintypes.ULONG(0)
    api.GetIpForwardTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value or 4)
    if api.GetIpForwardTable(buf, ctypes.byref(size), False) != 0:
        raise OSError("GetIpForwardTable failed")
    (n,) = struct.unpack_from("<I", buf, 0)
    out = []
    for i in range(n):
        dest, mask, _pol, nh, idx, _typ, _proto, _age, _as, metric = struct.unpack_from("<10I", buf, 4 + i * 56)
        d, m, g = _ip_le(dest), _ip_le(mask), _ip_le(nh)
        out.append(Route(f"{d}/{_prefix(m)}", None if g == "0.0.0.0" else g, idx, metric))
    return out


def _windows_neighbours() -> list[Neighbour]:
    import ctypes
    from ctypes import wintypes
    api = ctypes.windll.iphlpapi
    size = wintypes.ULONG(0)
    api.GetIpNetTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value or 4)
    if api.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
        raise OSError("GetIpNetTable failed")
    (n,) = struct.unpack_from("<I", buf, 0)
    out = []
    types = {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}
    for i in range(n):
        idx, ln, mac, addr, typ = struct.unpack_from("<II8sII", buf, 4 + i * 24)
        if typ == 2 or ln != 6:
            continue
        out.append(Neighbour(_ip_le(addr), ":".join(f"{b:02x}" for b in mac[:6]), idx, types.get(typ, "other")))
    return out


def routes() -> list[Route]:
    try:
        if sys.platform == "win32":
            return _windows_routes()
        with open("/proc/net/route", encoding="ascii") as fh:
            return parse_proc_routes(fh.read())
    except Exception:
        return []


def neighbours() -> list[Neighbour]:
    try:
        if sys.platform == "win32":
            return _windows_neighbours()
        with open("/proc/net/arp", encoding="ascii") as fh:
            return parse_proc_arp(fh.read())
    except Exception:
        return []


def candidate_networks(rts: list[Route], *, scope_nets, if_index: int | None, link_subnet: str | None) -> list[dict]:
    """Networks the OS has a route to that lie (even partly) outside the scope. Only routes on the scanner's own
    interface count: other adapters (VPNs, virtual switches) say nothing about the network under test."""
    link = ipaddress.ip_network(link_subnet, strict=False) if link_subnet else None
    out = []
    for r in rts:
        try:
            net = ipaddress.ip_network(r.network, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.prefixlen == 0 or net.prefixlen == 32 or net.is_loopback or net.is_multicast \
                or net.is_link_local or net.network_address == ipaddress.ip_address("255.255.255.255"):
            continue
        on_iface = (r.if_index == if_index) if (if_index and r.if_index) else bool(
            link and (r.gateway is None or ipaddress.ip_address(r.gateway) in link))
        if not on_iface:
            continue
        if any(net.subnet_of(s) for s in scope_nets if s.version == 4):
            continue                                   # entirely inside the authorised scope: not a candidate
        if any(s.subnet_of(net) for s in scope_nets if s.version == 4):
            continue                                   # a supernet of the scope: its outside part is recorded by the link-network logic
        kind = "attached" if r.gateway is None else "routed"
        out.append({"cidr": str(net), "kind": kind, "gateway": r.gateway, "if_index": r.if_index})
    return out
