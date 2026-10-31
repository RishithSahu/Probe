"""nmap as the service/banner engine -- not reinvented, used for what it is best at.

Probe's own byte-level scanner finds hosts and open ports at ~2,500 packets/s. nmap then identifies WHAT is
listening (product/version, banners, HTTP titles/headers, TLS certificates, SMB/MySQL info) on the hosts that
have open ports. That output is also exactly what the web / binary / vulnerability agents need, so they never
have to re-scan, and it can leak the addresses of other networks (an internal IP in a Location header or a
certificate), which are reported as outside-scope leads.

Safety, honestly stated: nmap runs as a child process, so the in-process guard and the packet tagging the
independent auditor relies on do not see its connections. What bounds it instead:
  * the process fence allows exactly this one executable, only inside tool_context(), never another program
  * every target is validated against the scope (and the hold list) immediately before launch
  * -sT (OS connect scan: no raw packets), -Pn (no host discovery), -n (no DNS), only ports Probe already found open
  * no traceroute, no UDP, no scripts that leave the target (the script list below is fixed)
  * recommended OS-level backstop: enforce/windows-firewall-scope.ps1 (outbound allow-list for nmap.exe)
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .. import fence
from ..scope import ScopeGuard

logger = logging.getLogger("probe.tools.nmap")

# Windows RPC/SMB plumbing and the IANA dynamic range: seldom worth a service-detection pass. Deliberately minimal and
# switchable (skip_noise=False / --no-skip-noise); it is a time-saver, not a statement about any particular network.
NOISE_PORTS = {135, 139, 445, 5357} | set(range(49152, 49200))

# Banners / titles of deliberately vulnerable training apps: a controlled-environment target, flagged by name.
VULN_APPS = ("damn vulnerable", "dvwa", "juice shop", "webgoat", "bwapp", "mutillidae", "metasploitable", "vulnhub",
             "hackable", "xvwa", "security shepherd", "badstore", "gruyere", "vulnerable", "hackme", "pentesterlab",
             "altoro", "testfire", "vampi", "crapi", "dvna", "nodegoat")
SCRIPTS = "banner,http-title,http-server-header,http-headers,ssl-cert,smb-os-discovery,mysql-info"
_PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
_CANDIDATES = (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
               "/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap")


def find_nmap() -> str | None:
    return shutil.which("nmap") or next((p for p in _CANDIDATES if os.path.exists(p)), None)


def _interest(ip: str, ports: list[int], hints: dict[str, int]) -> int:
    """Scan the most telling hosts first so a hard time budget cuts the boring ones, not these."""
    common = {135, 139, 445, 3306, 5900, 49152}
    return hints.get(ip, 0) * 10 + sum(1 for p in ports if p not in common)


def _run_chunk(nmap: str, ips: list[str], ports: list[int], host_timeout: int, budget: float, outfile: str,
               relaxed: bool = False) -> tuple[str, str]:
    """nmap writes the XML file host by host, so a timeout still leaves every finished host on disk.
    relaxed=True is the second chance for hosts the fast pass missed (slow containers / busy dev servers)."""
    timing = ["-T3", "--max-retries", "2", "--script-timeout", "10s"] if relaxed else \
             ["-T4", "--max-retries", "1", "--script-timeout", "5s", "--min-rtt-timeout", "100ms",
              "--max-rtt-timeout", "500ms", "--initial-rtt-timeout", "250ms"]
    # --max-hostgroup 1: nmap writes a host's XML only when its whole host GROUP is done, so one slow host (a dev
    # server that never sends a banner) would hold back every other host in the process and lose them all to the
    # budget. Host-by-host means each finished host is on disk immediately and a slow host costs only itself.
    args = [nmap, "-sT", "-Pn", "-n", "-sV", "--version-light", "--open", "--max-hostgroup", "1", *timing,
            "--host-timeout", f"{host_timeout}s", "--script", SCRIPTS,
            "-p", ",".join(map(str, sorted(ports))), "-oX", outfile, *ips]
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    err = ""
    with fence.tool_context():
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=budget, creationflags=flags)
            err = out.stderr or ""
        except subprocess.TimeoutExpired:
            err = "timeout"
    try:
        with open(outfile, encoding="utf-8", errors="ignore") as fh:
            return fh.read(), err
    except OSError:
        return "", err or "no output file"


def parse_xml(xml_text: str) -> list[dict]:
    """nmap -oX -> [{ip, port, service, product, version, extrainfo, banner, scripts{id: output}}]"""
    out: list[dict] = []
    if "<nmaprun" not in xml_text:
        return out
    try:
        root = ET.fromstring(xml_text[xml_text.index("<?xml"):] if "<?xml" in xml_text else xml_text)
    except ET.ParseError:
        # a timeout can truncate the document: salvage complete <host> elements
        root = ET.fromstring("<nmaprun>" + "".join(re.findall(r"<host\b.*?</host>", xml_text, re.S)) + "</nmaprun>")
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if not addr:
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            scripts = {s.get("id"): (s.get("output") or "").strip() for s in port.findall("script")}
            out.append({
                "ip": addr, "port": int(port.get("portid")), "proto": port.get("protocol", "tcp"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "banner": scripts.get("banner"), "scripts": scripts})
    return out


def find_leaks(records: list[dict], scope: ScopeGuard, my_ip: str | None) -> dict[str, list[str]]:
    """Private addresses that appear inside service output but are NOT in the scope: evidence of another network."""
    leaks: dict[str, list[str]] = {}
    for r in records:
        text = " ".join([r.get("banner") or "", r.get("product") or "", r.get("extrainfo") or "",
                         *r["scripts"].values()])
        for m in _PRIVATE_IP.finditer(text):
            a = m.group(0)
            try:
                ipaddress.ip_address(a)
            except ValueError:
                continue
            if not scope.in_scope(a) and a != my_ip:
                leaks.setdefault(a, []).append(f"appears in the service output of {r['ip']}:{r['port']} ({r['service'] or '?'})")
    return leaks


def find_vulnerable_apps(records: list[dict]) -> list[dict]:
    """Deliberately vulnerable training applications, recognised by their own banner/title."""
    out = []
    for r in records:
        text = " ".join([r.get("product") or "", r.get("extrainfo") or "", r.get("banner") or "", *r["scripts"].values()]).lower()
        hit = next((k for k in VULN_APPS if k in text), None)
        if hit:
            title = (r["scripts"].get("http-title") or r.get("banner") or "")[:120].replace("\n", " ")
            out.append({"ip": r["ip"], "port": r["port"], "match": hit, "title": title})
    return out


# Ports whose services answer immediately and matter most to the web / binary / vulnerability agents: scanned FIRST,
# for every host, so a slow banner on some other port can never starve them. Not tuned to any network: these are
# the well-known web, SSH and developer-server ports.
FAST_PORTS = ({22, 80, 81, 443, 591, 3000, 5000, 7000, 7070, 8443, 8888, 9000, 9090}
              | set(range(8000, 8100)))


def _stage(nmap: str, ok: dict[str, list[int]], order: list[str], workers: int, host_timeout: int, budget: float,
           workdir: str, tag: str, relaxed: bool = False) -> list[dict]:
    """One nmap stage: hosts split across parallel processes; each process streams its XML so partial results survive."""
    chunks = [order[i::workers] for i in range(workers) if order[i::workers]]
    records: list[dict] = []
    t0 = time.time()

    def work(ci):
        i, chunk = ci
        ports = sorted({p for ip in chunk for p in ok[ip]})
        return _run_chunk(nmap, chunk, ports, host_timeout, max(6.0, budget - (time.time() - t0)),
                          os.path.join(workdir, f"{tag}{i}.xml"), relaxed=relaxed)

    if chunks:
        with ThreadPoolExecutor(max_workers=len(chunks)) as ex:
            for stdout, _stderr in ex.map(work, list(enumerate(chunks))):
                records += parse_xml(stdout)
    return records


def enrich(scope: ScopeGuard, targets: dict[str, list[int]], *, my_ip: str | None = None, workers: int = 16,
           budget_s: float = 45, host_timeout: int = 40, hints: dict[str, int] | None = None,
           skip_noise: bool = True, workdir: str = "probe-data/nmap") -> dict:
    """targets: ip -> open ports Probe already found. Stage A = web/SSH/dev ports on every host (fast), stage B = the
    remaining ports with the time left. Returns {records, leaks, vulnerable_apps, ran, skipped, seconds, error}."""
    t0 = time.time()
    nmap = find_nmap()
    if not nmap:
        return {"records": [], "leaks": {}, "vulnerable_apps": [], "ran": 0, "skipped": list(targets), "seconds": 0.0,
                "error": "nmap not installed: service/banner enrichment skipped"}
    fence.allow_program(nmap)
    ok: dict[str, list[int]] = {}
    skipped: list[str] = []
    for ip, ports in targets.items():
        useful = [p for p in ports if not (skip_noise and p in NOISE_PORTS)]
        if useful and scope.allow(ip, caller="nmap-enrich", deep=True):   # scope AND hold list, checked right before launch
            ok[ip] = sorted(set(useful))
        else:
            skipped.append(ip)
    os.makedirs(workdir, exist_ok=True)
    order = sorted(ok, key=lambda ip: -_interest(ip, ok[ip], hints or {}))
    errors: list[str] = []

    # stage A: the ports that matter most, everywhere, quickly
    a_ports = {ip: [p for p in ok[ip] if p in FAST_PORTS] for ip in order}
    a_hosts = [ip for ip in order if a_ports[ip]]
    # slow responders (an app server, a container) can need ~20-30 s; with host-by-host streaming a generous
    # per-host timeout costs nothing for the other hosts
    records = _stage(nmap, {ip: a_ports[ip] for ip in a_hosts}, a_hosts, workers, host_timeout,
                     min(budget_s * 0.7, 42.0), workdir, "fast")
    # stage B: everything else, with whatever time is left (version detection on odd ports can be slow)
    left = budget_s - (time.time() - t0)
    b_ports = {ip: [p for p in ok[ip] if p not in FAST_PORTS] for ip in order}
    b_hosts = [ip for ip in order if b_ports[ip]]
    if b_hosts and left > 8:
        records += _stage(nmap, {ip: b_ports[ip] for ip in b_hosts}, b_hosts, workers, max(host_timeout, 30), left,
                          workdir, "rest")
    elif b_hosts:
        errors.append("remaining ports skipped: not enough time budget left")
    # nmap reports only what it was asked about; never accept an address we did not validate
    records = [r for r in records if r["ip"] in ok]
    return {"records": records, "leaks": find_leaks(records, scope, my_ip), "ran": len(ok), "skipped": skipped,
            "vulnerable_apps": find_vulnerable_apps(records), "seconds": round(time.time() - t0, 1),
            "error": "; ".join(errors) or None}
