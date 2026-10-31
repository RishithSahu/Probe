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
  * no traceroute, no scripts that leave the target (the script list below is fixed); UDP (-sU) and OS detection (-O)
    run as separate, budgeted stages (udp_scan / os_scan) with the same per-launch scope check
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
from pathlib import Path
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
HTTP_INVENTORY = str(Path(__file__).with_name("http-inventory.nse").resolve())
_egress_attest = None


def configure_egress(attest) -> None:
    global _egress_attest
    _egress_attest = attest


def _require_egress() -> None:
    if _egress_attest is None:
        raise RuntimeError("nmap refused: independent helper egress enforcement is not attested")
    ok, why = _egress_attest()
    if not ok:
        raise RuntimeError("nmap refused: " + why)
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
            _require_egress()
            out = subprocess.run(args, capture_output=True, text=True, timeout=budget, creationflags=flags)
            err = out.stderr or ""
        except subprocess.TimeoutExpired:
            err = "timeout"
        except RuntimeError as exc:
            # the independent egress check refused THIS launch (e.g. a stale auditor heartbeat): nmap was never
            # started for this host. This must degrade the one attempt, never crash the run -- a transient auditor
            # hiccup is not a reason to lose every other phase's result and the final report along with it.
            err = f"egress-refused: {exc}"
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
                "service": ((svc.get("name") or "unknown") + ("?" if svc.get("method") == "table" and not scripts else "")) if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "banner": scripts.get("banner"), "scripts": scripts})
    return out


_NAME = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def _hostname_from_scripts(scripts: dict[str, str]) -> tuple[str, str] | None:
    """A name the HOST gave about itself in a service answer (never a DNS lookup: -n, and the fence has no DNS)."""
    nb = re.search(r"NetBIOS name:\s*([^,\s]+)", scripts.get("nbstat") or "")
    if nb and _NAME.match(nb.group(1)):
        return nb.group(1), "netbios-nbstat"
    smb = scripts.get("smb-os-discovery") or ""
    for key in ("FQDN", "Computer name", "NetBIOS computer name"):
        m = re.search(key + r":\s*([^\s\\]+)", smb)
        if m and _NAME.match(m.group(1)):
            return m.group(1), "smb-os-discovery"
    m = re.search(r"commonName=([^/\n,]+)", scripts.get("ssl-cert") or "")
    if m and _NAME.match(m.group(1).strip()) and "*" not in m.group(1):
        return m.group(1).strip(), "tls-certificate"
    return None


def parse_hosts(xml_text: str) -> dict[str, dict]:
    """Per-host facts from nmap XML: self-reported hostname and the OS fingerprint (osmatch + device class)."""
    out: dict[str, dict] = {}
    if "<nmaprun" not in xml_text:
        return out
    try:
        root = ET.fromstring(xml_text[xml_text.index("<?xml"):] if "<?xml" in xml_text else xml_text)
    except ET.ParseError:
        root = ET.fromstring("<nmaprun>" + "".join(re.findall(r"<host\b.*?</host>", xml_text, re.S)) + "</nmaprun>")
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if not addr:
            continue
        info: dict = {}
        scripts: dict[str, str] = {}
        for sc in host.iter("script"):
            scripts[sc.get("id")] = (sc.get("output") or "").strip()
        hn = _hostname_from_scripts(scripts)
        if hn:
            info["hostname"], info["hostname_source"] = hn
        om = host.find("os/osmatch")
        if om is not None:
            oc = om.find("osclass")
            info["os"] = om.get("name")
            info["os_accuracy"] = int(om.get("accuracy") or 0)
            info["device_type"] = oc.get("type") if oc is not None else None
        if info:
            out[addr] = info
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
           workdir: str, tag: str, relaxed: bool = False, hostinfo: dict | None = None,
           outcome: dict | None = None) -> list[dict]:
    """One nmap process PER HOST, run concurrently from a bounded pool. A host that hangs on a banner costs only itself
    (its process is killed at host_timeout); it can no longer starve the hosts queued behind it, which is how the
    slowest services used to go unidentified."""
    records: list[dict] = []
    t0 = time.time()
    deadline = t0 + budget

    def work(ip: str):
        left = deadline - time.time()
        if left < 6:
            if outcome is not None:
                outcome[ip] = "not-started"             # stage budget spent: do not start a new host
            return ""
        # nmap must end ITSELF before the process timeout so it writes a complete XML file; killing it mid-scan left a
        # truncated document with no host in it, which looked like "port open but nothing identified"
        ht = max(5, min(host_timeout, int(left) - 3))
        out, err = _run_chunk(nmap, [ip], ok[ip], ht, min(ht + 6, left),
                              os.path.join(workdir, f"{tag}-{ip}.xml"), relaxed=relaxed)
        if outcome is not None:
            outcome[ip] = ("egress-refused" if err.startswith("egress-refused") else
                           "complete" if "</nmaprun>" in out else "incomplete")
        return out

    if order:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(order)))) as ex:
            for stdout in ex.map(work, order):
                if stdout:
                    records += parse_xml(stdout)
                    if hostinfo is not None:
                        for k, v in parse_hosts(stdout).items():
                            hostinfo.setdefault(k, {}).update(v)
    return records


def _run_generic(nmap: str, args: list[str], host_timeout: int, budget: float, outfile: str) -> tuple[str, str]:
    full = [nmap, *args, "--host-timeout", f"{host_timeout}s", "-oX", outfile]
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    err = ""
    with fence.tool_context():
        try:
            _require_egress()
            err = subprocess.run(full, capture_output=True, text=True, timeout=budget, creationflags=flags).stderr or ""
        except subprocess.TimeoutExpired:
            err = "timeout"
        except RuntimeError as exc:
            # same reasoning as _run_chunk: a refused launch degrades this one attempt, it must never crash the run.
            err = f"egress-refused: {exc}"
    try:
        with open(outfile, encoding="utf-8", errors="ignore") as fh:
            return fh.read(), err
    except OSError:
        return "", err or "no output file"


def _extra_stage(scope: ScopeGuard, ips: list[str], build, parse, *, workers: int, budget: float, host_timeout: int,
                 workdir: str, tag: str, caller: str) -> dict:
    """One nmap process per host for the optional stages (UDP, OS fingerprint). Every target is re-validated against the
    scope and hold list right before launch; a host not started inside the budget is reported, never silently dropped."""
    nmap = find_nmap()
    if not nmap:
        return {"ran": [], "notrun": list(ips), "results": [], "error": "nmap not installed"}
    fence.allow_program(nmap)
    os.makedirs(workdir, exist_ok=True)
    allowed = [ip for ip in ips if scope.allow(ip, caller=caller, deep=True)]
    deadline = time.time() + budget
    ran: list[str] = []
    completed: list[str] = []
    errors: dict[str, str] = {}
    results: list = []

    def work(ip: str):
        left = deadline - time.time()
        if left < 5:
            return ip, None, None
        if not scope.in_scope(ip) or scope.is_held(ip):
            return ip, None, "scope or hold changed before launch"
        out, _e = _run_generic(nmap, build(ip), host_timeout, min(host_timeout + 8, left),
                               os.path.join(workdir, f"{tag}-{ip}.xml"))
        return ip, out, _e

    if allowed:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(allowed)))) as ex:
            for ip, out, error in ex.map(work, allowed):
                if error:
                    errors[ip] = error
                if out is None or (not out and error):   # refused/empty: nmap never actually produced output
                    continue
                ran.append(ip)
                if "</nmaprun>" in out:
                    completed.append(ip)
                results.append((ip, parse(out)))
    return {"ran": ran, "completed": completed, "notrun": [ip for ip in ips if ip not in ran],
            "results": results, "errors": errors, "error": None}


def http_inventory(scope: ScopeGuard, targets: dict[str, list[int]], *, budget_s: float = 45,
                   hints: dict[str, int] | None = None, workdir: str = "probe-data/nmap") -> dict:
    """A short, fair first look before slow version probes. No credentials, redirects or path enumeration."""
    import math
    web = {ip: sorted(set(p for p in ports if p in FAST_PORTS and
           (p in {80, 81, 443, 591, 3000, 5000, 5001, 7070, 8443, 8888, 9000, 9090} or 8000 <= p <= 8100)))
           for ip, ports in targets.items()}
    web = {ip: ports for ip, ports in web.items() if ports and scope.in_scope(ip) and not scope.is_held(ip)}
    order = sorted(web, key=lambda ip: (-(hints or {}).get(ip, 0), int(ipaddress.ip_address(ip))))
    ht = max(4, min(12, int(budget_s / max(1, math.ceil(len(order) / 8))) - 1))
    def build(ip):
        return ["-sT", "-Pn", "-n", "--max-retries", "1", "--script-timeout", f"{max(2,ht-1)}s",
                "--script", HTTP_INVENTORY, "-p", ",".join(map(str, web[ip])), ip]
    return _extra_stage(scope, order, build, parse_xml, workers=8, budget=budget_s, host_timeout=ht,
                        workdir=workdir, tag="http-inventory", caller="nmap-http-inventory")


UDP_PORTS = 15            # nmap's own frequency ranking: the UDP services that actually exist in the wild


def udp_scan(scope: ScopeGuard, ips: list[str], *, budget_s: float = 40, workdir: str = "probe-data/nmap") -> dict:
    """Open UDP ports: nmap -sU on the most common UDP ports. A closed UDP port answers ICMP unreachable, which Linux
    rate-limits, so full UDP coverage is expensive; what was not covered is returned and reported as a limit."""
    def build(ip):
        return ["-sU", "-Pn", "-n", "--top-ports", str(UDP_PORTS), "--open", "--max-retries", "1", "-T4",
                "--script", "nbstat", ip]

    def parse(xml):
        return {"records": [r for r in parse_xml(xml) if r.get("proto") == "udp"], "hosts": parse_hosts(xml)}
    return _extra_stage(scope, ips, build, parse, workers=32, budget=budget_s, host_timeout=22, workdir=workdir,
                        tag="udp", caller="nmap-udp")


def os_scan(scope: ScopeGuard, targets: dict[str, list[int]], *, budget_s: float = 35,
            workdir: str = "probe-data/nmap") -> dict:
    """OS fingerprint (nmap -O). Needs one open and one closed TCP port: the open ones Probe found plus port 1 as the
    closed-port reference."""
    def build(ip):
        ports = sorted(set(targets[ip][:6]) | {1})
        return ["-O", "--osscan-guess", "--max-os-tries", "1", "-Pn", "-n", "-p", ",".join(map(str, ports)), ip]
    return _extra_stage(scope, list(targets), build, parse_hosts, workers=24, budget=budget_s, host_timeout=25,
                        workdir=workdir, tag="os", caller="nmap-os")


def enrich(scope: ScopeGuard, targets: dict[str, list[int]], *, my_ip: str | None = None, workers: int = 24,
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
    hostinfo: dict[str, dict] = {}
    out_a: dict[str, str] = {}
    out_b: dict[str, str] = {}
    out_c: dict[str, str] = {}
    records = _stage(nmap, {ip: a_ports[ip] for ip in a_hosts}, a_hosts, workers, host_timeout,
                     min(budget_s * 0.7, 42.0), workdir, "fast", hostinfo=hostinfo, outcome=out_a)
    # stage B: everything else, with whatever time is left (version detection on odd ports can be slow)
    left = budget_s - (time.time() - t0)
    b_ports = {ip: [p for p in ok[ip] if p not in FAST_PORTS] for ip in order}
    b_hosts = [ip for ip in order if b_ports[ip]]
    if b_hosts and left > 8:
        records += _stage(nmap, {ip: b_ports[ip] for ip in b_hosts}, b_hosts, workers, max(host_timeout, 30), left,
                          workdir, "rest", hostinfo=hostinfo, outcome=out_b)
    elif b_hosts:
        errors.append("remaining ports skipped: not enough time budget left")
    # stage C: slow responders (app servers, containers behind a host) can need a minute. Any host that has a web/SSH/dev port
    # but produced no result gets one patient pass with relaxed timing, so the slowest services are still inventoried.
    got = {r["ip"] for r in records}
    missing = [ip for ip in a_hosts if ip not in got][:12]
    left = budget_s - (time.time() - t0)
    if missing and left > 10:
        records += _stage(nmap, {ip: a_ports[ip] for ip in missing}, missing, min(len(missing), workers), 75, left, workdir,
                          "patient", relaxed=True, hostinfo=hostinfo, outcome=out_c)
    elif missing:
        errors.append(f"{len(missing)} slow host(s) not identified: not enough time budget left")
    # nmap reports only what it was asked about; never accept an address we did not validate
    records = [r for r in records if r["ip"] in ok]
    attempted: dict[str, dict[int, str]] = {}          # ip -> port -> what happened to the identification attempt
    for ip in ok:
        for p in ok[ip]:
            if p in FAST_PORTS:
                st = out_c.get(ip) or out_a.get(ip) or "not-started"
            else:
                st = out_b.get(ip) or "not-started"
            attempted.setdefault(ip, {})[p] = st
    return {"attempted": attempted,"records": records, "leaks": find_leaks(records, scope, my_ip), "ran": len(ok), "skipped": skipped,
            "vulnerable_apps": find_vulnerable_apps(records),
            "hosts": {k: v for k, v in hostinfo.items() if k in ok}, "seconds": round(time.time() - t0, 1),
            "error": "; ".join(errors) or None}
