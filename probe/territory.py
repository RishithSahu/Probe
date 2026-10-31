"""Territory lock: the agent only lives while this machine is inside the permitted network.

Three independent questions, all answered without sending anything:
  1. Is the scanner's own IPv4 address inside the scope?          (wrong range -> die)
  2. Is that address still assigned, on the same interface, with the link up?
                                                                   (moved / roamed / unplugged -> die)
  3. Can we even tell?                                             (cannot verify -> die: fail closed)

The check is a cheap local OS query (Windows iphlpapi GetIpAddrTable, Linux ioctl), so it can run
before every send and every half second in the independent auditor, in separate processes.
"""
from __future__ import annotations

import ipaddress
import struct
import sys
import time
from typing import Callable

from .scope import ScopeGuard


class TerritoryError(RuntimeError):
    """The scanner is not inside the permitted network (or cannot prove it is)."""


def sane_scope(cidrs: list[str], *, allow_wide: bool = False) -> list[str]:
    """Reject ranges that are almost certainly a mistake. A wrong range kills the agent at start."""
    problems = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            problems.append(f"{c!r} is not a valid network")
            continue
        if net.version != 4:
            problems.append(f"{c}: only IPv4 scopes are supported")
        elif not (net.is_private or net.network_address in ipaddress.ip_network("100.64.0.0/10")):
            problems.append(f"{c}: not a private range -- a public range can never be a lab scope")
        elif net.is_multicast or net.is_loopback or net.is_unspecified:
            problems.append(f"{c}: multicast/loopback/unspecified is not a scope")
        elif net.prefixlen < 16 and not allow_wide:
            problems.append(f"{c}: wider than a /16 ({net.num_addresses} addresses) -- almost certainly a typo; "
                            "pass --allow-wide if it is intended")
    return problems


# ---- platform queries -----------------------------------------------------------------------
BAD_WINDOWS_FLAGS = 0x08 | 0x40 | 0x80      # DISCONNECTED | DELETED | TRANSIENT


def _windows_addresses() -> list[tuple[str, int, int]]:
    import ctypes
    from ctypes import wintypes
    api = ctypes.windll.iphlpapi
    size = wintypes.ULONG(0)
    api.GetIpAddrTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value or 4)
    if api.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
        raise OSError("GetIpAddrTable failed")
    (n,) = struct.unpack_from("<I", buf, 0)
    out = []
    for i in range(n):
        addr, idx, _mask, _bcast, _reasm, _unused, wtype = struct.unpack_from("<IIIIIHH", buf, 4 + i * 24)
        out.append((str(ipaddress.ip_address(struct.pack("<I", addr))), idx, wtype))
    return out


def _linux_addresses(iface: str) -> list[tuple[str, int, int]]:
    import fcntl
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", iface.encode()[:15])
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])            # SIOCGIFADDR
        flags = struct.unpack("H", fcntl.ioctl(s.fileno(), 0x8913, ifreq)[16:18])[0]    # SIOCGIFFLAGS
    finally:
        s.close()
    up = (flags & 0x1) and (flags & 0x40)                                               # IFF_UP and IFF_RUNNING
    return [(ip, 0, 0 if up else 0x08)]


def platform_provider(iface_name: str | None) -> Callable[[], list[tuple[str, int, int]]]:
    if sys.platform == "win32":
        return _windows_addresses
    if sys.platform.startswith("linux") and iface_name:
        return lambda: _linux_addresses(iface_name)
    def unsupported():
        raise OSError(f"cannot verify the network location on {sys.platform}")
    return unsupported


class Territory:
    def __init__(self, scope: ScopeGuard, my_ip: str, *, if_index: int | None = None,
                 iface_name: str | None = None, provider: Callable | None = None, max_failures: int = 3):
        self.scope, self.my_ip, self.if_index = scope, my_ip, if_index
        self.provider = provider or platform_provider(iface_name)
        self.max_failures, self._failures = max_failures, 0

    def check(self) -> tuple[bool, str]:
        if not self.scope.in_scope(self.my_ip):
            return False, f"this machine's address {self.my_ip} is not inside the permitted range"
        try:
            rows = self.provider()
            self._failures = 0
        except Exception as exc:
            self._failures += 1
            if self._failures >= self.max_failures:
                return False, f"cannot verify the network location ({exc}); failing closed"
            return True, ""
        for ip, idx, flags in rows:
            if ip == self.my_ip and (self.if_index in (None, 0) or idx in (0, self.if_index)):
                if sys.platform == "win32" and flags & BAD_WINDOWS_FLAGS:
                    return False, f"{self.my_ip} is disconnected/transient: the link is down or the network changed"
                if sys.platform != "win32" and flags & 0x08:
                    return False, f"interface for {self.my_ip} is down"
                return True, ""
        return False, f"{self.my_ip} is no longer assigned to the interface: the machine left the permitted network"


def require_in_territory(scope: ScopeGuard, my_ip: str | None) -> None:
    if not my_ip or not scope.in_scope(my_ip):
        raise TerritoryError(
            f"WRONG RANGE: this machine's address ({my_ip}) is not inside the permitted scope "
            f"{[str(n) for n in scope.networks]}. The probe will not run here.")
