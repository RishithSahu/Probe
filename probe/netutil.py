"""Identity helpers: an IP address is compared as an address, never as a string prefix.

'10.0.0.5' is a string prefix of '10.0.0.55'; a LIKE / startswith / substring match on an address silently joins two
different hosts. Everything that looks a host up, joins a lead to a host, or tests network membership goes through here.
"""
from __future__ import annotations

import ipaddress


def norm_ip(value) -> str | None:
    """Canonical text form of an IPv4/IPv6 address, or None if `value` is not an IP address."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def same_ip(a, b) -> bool:
    na, nb = norm_ip(a), norm_ip(b)
    return na is not None and na == nb


def address_part(address: str) -> str | None:
    """The IP inside a lead/task address such as '10.0.0.5', '10.0.0.5:80' or '10.0.0.5:80/tcp' (None for a CIDR)."""
    s = str(address).strip()
    if "/" in s and ":" not in s:
        return None                                  # a CIDR, not a host address
    s = s.split("/", 1)[0]                           # '10.0.0.5:80/tcp' -> '10.0.0.5:80'
    if s.count(":") == 1:
        s = s.split(":", 1)[0]                       # drop the port (IPv4)
    return norm_ip(s)


def in_network(ip, cidr) -> bool:
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return False


def like_escape(text: str) -> str:
    """Escape SQL LIKE wildcards so a prefix is matched literally (use with ESCAPE '\\')."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def compress_ranges(ips) -> list[str]:
    """['10.0.0.1','10.0.0.2','10.0.0.3','10.0.0.9'] -> ['10.0.0.1-10.0.0.3', '10.0.0.9']"""
    ints = sorted({int(ipaddress.ip_address(i)) for i in ips if norm_ip(i)})
    runs: list[list[int]] = []
    for n in ints:
        if runs and n == runs[-1][1] + 1:
            runs[-1][1] = n
        else:
            runs.append([n, n])
    ip = ipaddress.ip_address
    return [str(ip(a)) if a == b else f"{ip(a)}-{ip(b)}" for a, b in runs]
