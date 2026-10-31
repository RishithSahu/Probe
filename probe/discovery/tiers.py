"""Which probes to send, chosen from data instead of by hand.

Host discovery is a cost-ordered ladder of *tiers*; a host leaves the ladder at
the first tier that makes it answer. Hosts that answer nothing at any tier are
reported as "undetectable with this probe set" -- never as "absent".

  tier 0  ARP                       on-link hosts cannot hide from this
  tier 1  ICMP echo                 the "standard" ping sweep
  tier 2  TCP ACK + TCP SYN         hosts/firewalls that drop ICMP (stateless
                                    filters pass ACK; any RST/SYN-ACK = alive)
  tier 3  ICMP timestamp / mask     filters that only block echo
  tier 4  UDP to a closed port      host answers ICMP port-unreachable

TCP ports are the most frequently open ports in Nmap's own measurements
(nmap-services), not a hand-picked list. Falls back to a built-in copy of the
same ranking if Nmap's data file is not installed.
"""
from __future__ import annotations

from pathlib import Path

NMAP_SERVICES = [
    Path(r"C:\Program Files (x86)\Nmap\nmap-services"), Path(r"C:\Program Files\Nmap\nmap-services"),
    Path("/usr/share/nmap/nmap-services"), Path("/usr/local/share/nmap/nmap-services"),
    Path("/opt/homebrew/share/nmap/nmap-services"),
]
# nmap-services top-ranked TCP ports, used only if the file above is missing.
FALLBACK_TOP_TCP = (80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995,
                    993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179)


def top_tcp_ports(n: int) -> list[int]:
    for p in NMAP_SERVICES:
        try:
            ranked: list[tuple[float, int]] = []
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[1].endswith("/tcp"):
                    ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
            if ranked:
                return [port for _, port in sorted(ranked, reverse=True)[:n]]
        except (OSError, ValueError):
            continue
    return list(FALLBACK_TOP_TCP[:n])


_FALLBACK_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 111: "rpcbind",
                   135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
                   995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server", 5900: "vnc", 8080: "http-proxy"}
_NAMES: dict[tuple[str, int], str] = {}


def service_name(port: int, proto: str = "tcp") -> str | None:
    """The IANA/nmap-services name registered for a port NUMBER. A guess about what runs there, never an identification:
    callers must mark it as such (nmap's own convention is a trailing '?')."""
    if not _NAMES:
        for p in NMAP_SERVICES:
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and not line.startswith("#") and "/" in parts[1]:
                        num, pr = parts[1].split("/")
                        _NAMES.setdefault((pr, int(num)), parts[0])
            except (OSError, ValueError):
                continue
        if not _NAMES:
            _NAMES.update({("tcp", k): v for k, v in _FALLBACK_NAMES.items()})
    return _NAMES.get((proto, port))
