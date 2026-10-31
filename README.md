# Probe

Autonomous network discovery agent: finds every device that answers anything inside an
authorised scope, works out which separate networks they sit on, flags networks a standard
ping sweep would miss, and never sends a packet outside the scope. General purpose â€” the scope
is a runtime argument; nothing is specific to any one network.

Read [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) for the design, the proof rules and the
scope-safety layers.

## Live-run scope preflight

Live discovery now requires `authorisations.json` with explicit discovery/inventory grants matching the configured scope. A discovered address, service reference, or interface supernet cannot extend that scope. `probe approve` releases holds only within the explicit scope.

Windows runs additionally require independently verified Nmap program firewall rules. The run writes an exact policy to its data directory and refuses before any traffic if the rules are missing. Install those rules with administrator rights using `enforce/windows-program-scope.ps1 -PolicyFile <data-directory>/egress-policy.json -Install`, then rerun. The auditor must remain enabled; it verifies capture health, run identity, effective scope, and helper egress continuously. Other platforms currently refuse live execution until an independent enforcement adapter is provided.

Use `--data-dir <directory>` to isolate new reports and audit records. See [the Network Roamer review](docs/reviews/2026-10-31-roamer.md) for the current validation result and remaining capabilities.

## Run

Requirements: Python 3.11+, Npcap (Windows) or libpcap (Linux/macOS).

```bash
pip install -r requirements.txt
python -m probe            # that's it: scope comes from probe-scope.txt (or --scope / $PROBE_SCOPE)
```

It needs no further help: it asks for administrator rights itself, proves its own scope guard, starts an
independent auditor process, installs the process fence, explores, digs deeper until nothing new appears,
prints the result, and keeps watching (`--once` exits instead). Web view: http://127.0.0.1:8080.
`python -m probe plan` shows what would be sent and `python -m probe selftest` proves the guard; neither sends anything.
Results: terminal summary + `probe-data/probe.db` + the web view (devices, segments with minimum/maximum
extent, hidden/visible verdict with reasons, unconfirmed hosts, a connection graph).

When a separate network is found it is **held**: no deeper probing until the network owner approves:

```bash
python -m probe approve 10.20.30.128/26
python -m probe reset-tripwire        # only after a human inspected a kill-switch trip
```

## Tests

```bash
python -m unittest discover -s tests -v
```
Unit tests cover the scope guard, kill switch, approval/hold logic and the inference rules
(hand-written observations, no simulated network). Discovery itself is validated by running
against the real assigned range.
