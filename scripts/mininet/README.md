# Offline lab replica (Mininet)

Replays the real `192.168.60.0/24` lab network — 171 hosts, 263 services, discovered by the Network
Discovery Probe during this project's own live assessments — as a Mininet topology, so the orchestrator,
Probe and the console session agent can all be developed and tested while disconnected from the real
network.

## What is faithful vs. reconstructed

- **Every host's IP and port list** comes straight from a real discovery run (`network_graph.json`,
  exported from `ASSESSMENT-LIVE-REAL-003`). Nothing here is invented topology.
- **Most hosts** get a generic stand-in service (`services/svc_runner.py`) that answers with the *same
  banner the real scan observed* for that service name — enough for the same connect/read/timeout code
  paths to run, not a reimplementation of SSH/MySQL/SMB/etc.
- **`192.168.60.139` is the one host built to be behaviourally faithful end to end**, because it's the
  host this project's own fixes and tests are built against:
  - `/vault/keykeeper` serves the *actual* recovered binary (`assets/keykeeper.elf`), not a stand-in.
  - The home page and `/vault` tree are gated behind the same trusted-proxy-header check the real site
    used (`services/vault_site.py`).
  - Port 8833's `AUTH` step (`services/game_zone.py`) checks the *real* recovered passkey
    (`R3v3rs3_Th3_Z0n3`, derived from the same XOR algorithm Ghidra decompiled from the real binary — see
    `docs/PROGRESS.md` Entry 17). The `WHOAMI` → `PIDREQ` sequence *past* AUTH is a **reconstruction**: this
    project never actually drove the real console that far, so treat anything past the AUTH banner as a
    representative multi-step target for the console session agent, not a captured transcript.

## Why it's sharded across multiple switches

This WSL2 + Open vSwitch combination stops forwarding once a single bridge passes roughly 57 ports —
confirmed empirically (56 ports: works; 58 ports: silent 100% packet loss, nothing in any log). The
topology splits the 171 hosts into shards of 45, each its own `OVSBridge`, all linked into shard 0 — one
flat broadcast domain, same as the real `/24` looked like, just assembled from several switches instead of
one.

## Prerequisites (Linux only — Mininet needs real network namespaces)

```bash
sudo apt-get install mininet openvswitch-switch
sudo service openvswitch-switch start   # WSL2 does not start it automatically; needed after every reboot
```

On Windows, run this under WSL2 (a distro with a real kernel, e.g. Kali or Ubuntu) — Mininet cannot run
directly on Windows.

## Running it

```bash
sudo python3 scripts/mininet/topology.py
```

This brings up all 171 replica hosts plus a `ctrl` host (`192.168.60.254`) that has this repository
mounted and can run the real app, then drops into the Mininet CLI. From there:

```
mininet> ctrl python3 -m app.orchestrator run --assessment-id MININET-001 \
    --scope 192.168.60.0/24 --network-graph scripts/mininet/network_graph.json --max-minutes 20
```

`--network-graph` points the orchestrator at the already-discovered graph instead of running Probe itself
against this topology — the fastest way to get the orchestrator's own agents exercising real sockets
offline. Running Probe's own discovery against the replica is possible in principle (it's just another
host on the same L2 segment) but untested here.

`--self-test` (`python3 scripts/mininet/topology.py --self-test`) skips the interactive CLI and instead
runs a handful of checks from the controller host — gateway reachability, the vault's header gating, the
binary download, and the Game Zone `AUTH` exchange — then tears everything down. Useful for CI or a quick
sanity check after changing a service script.

## Known gaps

- Only `192.168.60.139` has stateful, faithful services. Every other host answers generically; a fix that
  depends on a *specific* other host's exact real behaviour will need its own dedicated script added next
  to `vault_site.py` / `game_zone.py`, the same way those were added.
- The Python environment this topology's `ctrl` host uses to run the real app is whatever `python3` resolves
  to inside the Linux distro — it needs this project's `requirements.txt` installed there. This project
  pins `SQLAlchemy==2.0.29`, which does not import under Python 3.13 (used by current Kali); `pip install -U
  sqlalchemy` inside that environment fixes it for local testing, but that upgrade is this dev environment's
  own fix, not a change made to the project's pinned dependencies.
