"""Command line: one command starts everything, and nothing needs a human afterwards.

  python -m probe                                  # scope read from $PROBE_SCOPE or ./probe-scope.txt
  python -m probe run --scope 10.20.30.0/24      # explicit scope
  python -m probe plan --scope ...                 # dry run: what would be sent (sends nothing)
  python -m probe selftest --scope ...             # prove the scope guard refuses everything forbidden
  python -m probe approve 10.20.30.128/26        # the network owner's one-time yes for a held segment
  python -m probe reset-tripwire                   # after a human inspected a kill-switch trip

`run` is fully autonomous: it asks for administrator rights itself (Windows), proves its own
guard, starts the independent auditor, installs the process fence, then scans the whole scope in one
~3-minute pass, reports, and keeps serving the API for the other agents (use --once to exit instead).
"""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import selftest
from .killswitch import KillSwitch, TripwireLatched
from .scope import ScopeGuard
from .territory import Territory, TerritoryError, require_in_territory, sane_scope

DATA = Path("probe-data")
SCOPE_FILE = Path("probe-scope.txt")


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
                st.flush()
            except Exception:
                pass
        return len(s)

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass

    def isatty(self):
        return False


def resolve_scope(args) -> list[str]:
    """The scope is the fence, so it is never guessed: explicit flag, $PROBE_SCOPE, or probe-scope.txt."""
    if args.scope:
        return args.scope
    env = os.environ.get("PROBE_SCOPE", "")
    if env.strip():
        return env.replace(",", " ").split()
    if SCOPE_FILE.exists():
        return [t for line in SCOPE_FILE.read_text(encoding="utf-8").splitlines()
                for t in line.split("#")[0].replace(",", " ").split()]
    sys.exit("no scope: pass --scope, set PROBE_SCOPE, or put the authorised range(s) in probe-scope.txt")


def _is_admin() -> bool:
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def _ensure_privileges() -> None:
    """Raw packets need admin/root. Ask for it ourselves instead of failing."""
    if _is_admin():
        return
    if os.name == "nt":
        import ctypes
        params = " ".join(f'"{a}"' for a in ["-m", "probe", *sys.argv[1:]])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(Path.cwd()), 1)
        if rc > 32:
            print("relaunched with administrator rights in a new window; this one can be closed")
            sys.exit(0)
        sys.exit("administrator rights are required for raw packets and were declined")
    sys.exit("root is required for raw packets: re-run with sudo")


def _plan(args) -> int:
    from .discovery import tiers
    scope = ScopeGuard(resolve_scope(args))
    n = sum(len(list(net.hosts())) for net in scope.networks if net.version == 4)
    ports = tiers.top_tcp_ports(args.ports)
    per_host = 11 + 3 + max(0, len(ports) - 8)          # cheap suite + tier3/4 + remaining ports
    total = n * (per_host + 2) + n * 3 * 4 + n            # + ARP/retransmit, + pivot/forwarder allowance
    print(f"scope: {[str(x) for x in scope.networks]}  ({n} addresses)")
    print(f"per host: ARP + echo + 2 ACK + {len(ports)} SYN + timestamp + mask + UDP; then forwarder test + pivot sweep")
    print(f"about {total:,} frames at {args.rate} pps = ~{total / args.rate:.0f}s of sending; whole pass budget {args.budget:.0f}s")
    print("no frame has been sent. `python -m probe selftest` proves the guard first.")
    return 0


def _selftest(args) -> int:
    failures = selftest.run(resolve_scope(args))
    for f in failures:
        print("FAIL:", f)
    print("guard self-test: " + ("FAILED -- do not run" if failures else "all forbidden frames refused, legal frames pass"))
    return 1 if failures else 0


def _print_result(store, transport, scope, attestation=None, engine=None) -> None:
    wire = attestation.wire_summary() if attestation else {}
    st = store.meta().get("status", {})
    tm = (engine.timings if engine else st.get("timings")) or {}
    print("\n== result" + (f" ({tm.get('total')}s)" if tm.get("total") else "") + " ==")
    hosts = store.hosts()
    print(f"devices answering: {len(hosts)} | with open ports: {sum(1 for h in hosts if h['open_ports'])} | "
          f"open ports: {sum(len(h['open_ports']) for h in hosts)}")
    hidden = [h for h in hosts if h["verdict"] == "CONFIRMED_SEPARATE" and h["reasons"] and h["reasons"][0][:2] in ("R5", "R7")]
    print("\n" + ("=" * 70))
    if hidden:
        print(f"HIDDEN HOSTS FOUND: {len(hidden)}")
        for h in hidden:
            print(f"  {h['ip']}   reply TTL {h['ttl']}   answers: {', '.join(h['visible_to'])}")
            print(f"      {h['reasons'][0]}")
        fronts = [h for h in hosts if "fronts-hidden-network" in h["roles"]]
        for f in fronts:
            print(f"  front device {f['ip']} (MAC {f['mac']}, reply TTL {f['ttl']}, open ports {[p['port'] for p in f['open_ports']] or 'none'})")
        print("  These addresses are HELD: no further probing until the network owner approves (python -m probe approve <cidr>).")
    else:
        print("HIDDEN HOSTS FOUND: none in this pass")
    linknets = [x for x in store.segments() if x["kind"] == "outside-scope" and x["extra"].get("basis", "").startswith("the scanner's own")]
    if linknets:
        print("NETWORKS ON THE SAME LINK BUT OUTSIDE THE AUTHORISED SCOPE (concealed from scope-limited discovery; recorded, never probed):")
        for x in linknets:
            print(f"  {x['cidr']}   <- {x['evidence'][0]}")
    vuln = [l for l in store.leads() if l["source"] == "vulnerable-app"]
    for l in vuln:
        print(f"VULNERABLE APP (controlled-environment target): {l['address']} -- {l['evidence'][:200]}")
    print("=" * 70)
    for s in store.segments():
        ex = s["extra"]
        members = s["hosts"]
        shown = ", ".join(members[:8]) + (f" ... (+{len(members) - 8})" if len(members) > 8 else "")
        print(f"{'LOCAL ' if ex.get('local') else ''}SEGMENT {s['cidr']}  [{s['kind']}, {s['verdict']}, {s['state']}]  via={s['via']}")
        print(f"    members: {shown}")
        print(f"    extent: at least {ex['covering']}, at most {ex['max_extent']}  ({ex['basis']})")
        print(f"    visibility: {ex['hidden']['level'].upper()} -- " + "; ".join(ex["hidden"]["reasons"]))
        for e in s["evidence"][:4]:
            print(f"    proof: {e[:200]}")
    piv = [h for h in hosts if "forwarder" in h["roles"]]
    anomalies = [l for l in store.leads() if l["source"].startswith("anomaly")]
    if piv or anomalies:
        print("PIVOT CANDIDATES (hosts that forward IP or whose replies cross a forwarding hop):")
        for l in anomalies:
            print(f"    {l['address']}: {l['evidence'][:220]}")
    unconf = [l for l in store.leads() if l["source"].startswith("unconfirmed")]
    if unconf:
        print(f"unconfirmed (not reported as networks): {len(unconf)} host(s); see the web view")
    outside = [l for l in store.leads() if l["source"] == "outside-scope-address"]
    for l in outside:
        print(f"OUTSIDE-SCOPE ADDRESS (recorded, never probed): {l['address']} -- {l['evidence'][:160]}")
    if tm:
        print("timings: " + ", ".join(f"{k} {v}s" for k, v in tm.items()))
    for n in (engine.notes if engine else st.get("notes", [])):
        print(f"note: {n}")
    print(f"probes sent: {len(transport.sent)} | sent out of scope: {transport.sent_out_of_scope} | "
          f"blocked attempts: {scope.stray_count}"
          + (f" | auditor saw {wire.get('tagged_probes')} tagged probes on the wire, "
             f"{wire.get('violations')} violations" if wire else ""))
    sys.stdout.flush()


def _run(args) -> int:
    scope_cidrs = resolve_scope(args)
    problems = sane_scope(scope_cidrs, allow_wide=args.allow_wide)
    if problems:                                  # a wrong range kills the agent before it does anything
        print("WRONG RANGE, refusing to run:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 7
    from . import fence
    from .audit import Attestation
    from .engine import Engine
    from .net.transport import GuardedTransport
    from .store import Store

    DATA.mkdir(exist_ok=True)
    kill = KillSwitch(DATA / "TRIPWIRE.json", enabled=not args.no_killswitch)
    try:
        kill.check_latch()
    except TripwireLatched as exc:
        print(exc, file=sys.stderr)
        return 3
    failures = selftest.run(scope_cidrs)         # prove the guard before the first real packet
    if failures:
        print("scope guard self-test FAILED, refusing to start:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 4
    print("scope guard self-test passed")

    scope = ScopeGuard(scope_cidrs, log_path=DATA / "stray-probes.log", approvals_path=DATA / "approvals.json")
    store = Store(DATA / "probe.db")
    transport = GuardedTransport(scope, iface=args.iface, rate_pps=args.rate, kill=kill)
    try:
        transport.prepare()                       # picks the NIC (uses helper programs); nothing sent yet
        require_in_territory(scope, transport.my_ip)
    except TerritoryError as exc:                 # wrong range: the probe dies here, before a single packet
        print(f"\nTERRITORY LOCK: {exc}", file=sys.stderr)
        return 6
    transport.territory = Territory(scope, transport.my_ip, if_index=transport.if_index, iface_name=transport.iface)
    ok, why = transport.territory.check()
    if not ok:
        print(f"\nTERRITORY LOCK: {why}", file=sys.stderr)
        return 6
    print(f"territory lock: {transport.my_ip} is inside the permitted range and on the interface; "
          "the agent dies if that ever stops being true")
    _ensure_privileges()                          # only now: a wrong range dies before even asking for admin rights

    attestation, aud = None, None
    if not args.no_auditor:
        attestation = Attestation(DATA)
        aud = subprocess.Popen([sys.executable, "-m", "probe.audit", "--iface", str(transport.iface),
                                "--mac", transport.my_mac, "--scope", *scope_cidrs, "--state", str(DATA),
                                "--pid", str(os.getpid()), "--ip", transport.my_ip,
                                "--ifindex", str(transport.if_index or 0), "--iface-name", str(transport.iface)])
        deadline = time.time() + 20
        while time.time() < deadline and not attestation.check()[0]:
            time.sleep(0.3)
        ok, why = attestation.check()
        if not ok:
            print(f"independent auditor did not come up ({why}); refusing to send anything.", file=sys.stderr)
            aud.terminate()
            return 5
        transport.attest = attestation.check
        print("independent egress auditor attached (all probing stops if it ever stops attesting)")

    fence.install(kill)                           # from here on: no other network, DNS or subprocess is possible
    print("process fence installed (loopback only, no DNS, no raw send except through the guard; "
          "only nmap may be launched, only for validated in-scope targets)")

    state = {"running": False}
    rescan = threading.Event()

    def request_scan(force: bool, max_age_s: float) -> dict:
        last = store.last_scan()
        if state["running"]:
            return {"state": "running", "scan": last}
        if not force and last and last["status"] == "done" and last["finished"] \
                and time.time() - last["finished"] < max_age_s:
            return {"state": "fresh", "scan": last}
        rescan.set()
        return {"state": "started", "scan": last}

    if not args.no_ui:
        import uvicorn
        from .web.app import create_app
        cfg = uvicorn.Config(create_app(store, scope, request_scan), host="127.0.0.1", port=args.port, log_level="warning")
        threading.Thread(target=uvicorn.Server(cfg).run, daemon=True).start()
        print(f"web view + API: http://127.0.0.1:{args.port}   (API docs: /api/docs)")

    def do_scan() -> Engine:
        state["running"] = True
        store.reset()                             # inventory only: claims, events and scan history survive
        transport.sent.clear()
        transport.set_rate(args.rate)
        engine = Engine(scope, store, transport, budget_s=args.budget, tcp_ports=args.ports, max_hops=args.max_hops,
                        allow_silent_hops=args.allow_silent_hops, enrich=not args.no_enrich, auditor=attestation,
                        on_done=lambda e: _print_result(store, transport, scope, attestation, e))
        try:
            engine.run()
        finally:
            state["running"] = False
        return engine

    try:
        do_scan()
        if not args.once:
            print("scan complete; serving the API (POST /api/scan to rescan, Ctrl-C to quit)")
            while True:
                rescan.wait()
                rescan.clear()
                do_scan()
    except KeyboardInterrupt:
        pass
    if aud:
        aud.terminate()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv = ["run", *argv]                     # `python -m probe` alone means: go
    ap = argparse.ArgumentParser(prog="probe", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--scope", nargs="+", help="authorized CIDR(s); default: $PROBE_SCOPE or ./probe-scope.txt")
        p.add_argument("--rate", type=int, default=2500, help="probes per second (default 2500; auto-halved on packet loss)")
        p.add_argument("--max-hops", type=int, default=8, help="the leash: deepest TTL ever used (default 8)")
        p.add_argument("--ports", type=int, default=200, help="how many top-ranked TCP ports to SYN-scan (default 200)")
        p.add_argument("--budget", type=float, default=170, help="seconds for one full scan pass (default 170)") if p.prog.endswith("plan") else None

    r = sub.add_parser("run", help="discover devices and segments inside the scope, then serve the API")
    common(r)
    r.add_argument("--iface", help="network interface (auto-detected if it has an address in scope)")
    r.add_argument("--budget", type=float, default=170, help="seconds for one full scan pass (default 170)")
    r.add_argument("--once", action="store_true", help="exit after the scan instead of serving the API")
    r.add_argument("--no-enrich", action="store_true", help="skip the nmap service/banner enrichment")
    r.add_argument("--allow-silent-hops", type=int, default=0,
                   help="routers that never answer may be tolerated this many times per path (default 0 = strict fence)")
    r.add_argument("--allow-wide", action="store_true", help="accept a scope wider than a /16 (normally a typo)")
    r.add_argument("--port", type=int, default=8080)
    r.add_argument("--no-ui", action="store_true")
    r.add_argument("--no-auditor", action="store_true", help="NOT recommended: skip the independent egress auditor")
    r.add_argument("--no-killswitch", action="store_true", help="NOT recommended: count strays but do not exit")
    common(sub.add_parser("plan", help="dry run: show what would be sent; sends nothing"))
    common(sub.add_parser("selftest", help="prove the scope guard refuses every forbidden frame"))
    a = sub.add_parser("approve", help="record the network owner's approval for a held segment")
    a.add_argument("cidr")
    a.add_argument("--note", default="approved by the network owner")
    sub.add_parser("reset-tripwire", help="clear the kill-switch latch after human review")
    args = ap.parse_args(argv)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.cmd == "run":                          # the elevated relaunch has its own window: keep a readable record
        DATA.mkdir(exist_ok=True)
        log = open(DATA / "run.log", "a", encoding="utf-8", buffering=1)
        handlers.append(logging.StreamHandler(log))
        sys.stdout = _Tee(sys.stdout, log)
        sys.stderr = _Tee(sys.stderr, log)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=handlers)

    if args.cmd == "run":
        return _run(args)
    if args.cmd == "plan":
        return _plan(args)
    if args.cmd == "selftest":
        return _selftest(args)
    if args.cmd == "approve":
        DATA.mkdir(exist_ok=True)
        ScopeGuard.write_approval(DATA / "approvals.json", args.cidr, args.note)
        print(f"recorded approval for {args.cidr}; the next run will include it in scope")
        return 0
    if args.cmd == "reset-tripwire":
        print("tripwire cleared" if KillSwitch.reset(DATA / "TRIPWIRE.json") else "no tripwire was set")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
