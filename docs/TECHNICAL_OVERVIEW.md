# Probe — technical overview

Probe is a general-purpose, autonomous network discovery agent. Given a scope (CIDRs) it finds every responding device,
works out which separate networks they sit on, decides which networks a standard sweep would **not** have revealed,
identifies services, and publishes the result through a local API for other agents — while **provably never sending a
packet outside the scope**. Nothing in it is specific to one network; the scope is the only input.

Example addresses below use a neutral range (`10.20.30.0/24`).

---

## 1. Design goals and how each is met

| Goal | Mechanism |
|---|---|
| Never touch anything outside the scope (hard requirement) | ten independent layers (section 3); fail-closed; kill switch; independent auditor |
| Find hidden networks, not just hosts | proof-based host classification + alias/forwarder matrix + catch-all control + verification (sections 6, 7) |
| ≤ 3 min for a /24, *without* finding less | byte-level probes and guard, round-robin pipelining, adaptive waits, loss-driven retransmission (section 9) |
| Low false-alarm rate | verdicts need an *entailing* observation; suspicions are listed separately; controls; revocable promotion (section 6) |
| Autonomous | one command; self-elevates, self-tests, self-attests, converges, serves an API |
| Plays well with a multi-agent graph | stable JSON contract, change feed, **work ledger** that prevents repeated work (section 11) |

## 2. Architecture

```
                 ┌────────────────────────── safety plane ──────────────────────────┐
                 │ range sanity · territory lock · guard self-test · process fence   │
                 │ independent auditor (separate OS process) · kill switch · hold    │
                 └───────────────────────────────┬──────────────────────────────────┘
                                                 │ every frame passes here
 ┌─ discovery plane ─────────────────────────────▼───────────────────────────────────┐
 │ Engine (phases) ──► RawProbes (bytes) ──► GuardedTransport.send_raw ──► NIC (pcap)   │
 │        ▲                                                                   │ replies │
 │        └──── Evidence ◄── Ingest (BPF-filtered capture, scapy dissect) ◄───┘         │
 └───────────────┬──────────────────────────────────────────────────────────────────────┘
                 │ typed observations
 ┌─ intelligence plane ──────────────────────────────────────────────────────────────┐
 │ classify (proof rules → verdicts) → segments (aligned-CIDR bounds, hidden verdict) │
 │ → topology (graph)         + nmap enrichment (services, banners, leaks, vuln apps)  │
 └───────────────┬──────────────────────────────────────────────────────────────────────┘
                 │ SQLite (WAL)
 ┌─ integration plane ───────────────────────────────────────────────────────────────┐
 │ FastAPI (loopback): inventory · events feed · claim/complete ledger · scan freshness │
 │ probe.client (stdlib) for LangGraph nodes · minimal web view                          │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

Key files: `engine.py` (pipeline), `net/transport.py` (the guard), `discovery/rawprobes.py` (packet builders),
`discovery/ingest.py` (evidence), `analysis/classify.py` + `segments.py` (inference), `fence.py`, `audit.py`,
`killswitch.py`, `territory.py`, `tools/nmap_tool.py`, `service.py` + `web/app.py` + `client.py`.

## 3. Scope safety — the part a security reviewer will attack

Threat model: a bug in our own discovery logic, a library, a dependency, a misconfigured scope, the host moving to
another network, or a helper process must not cause a probe to leave the scope. Ten layers, each independent:

1. **Range sanity** — public, multicast, loopback, malformed, or wider-than-/16 scopes abort at start.
2. **Territory lock** — the scanner's *own* address must be inside the scope (even with `--iface`); a local OS query
   (Windows `GetIpAddrTable`, Linux ioctl) runs before every send and every 0.5 s in the auditor. Leaving the network,
   losing the address or the link kills the agent; "cannot verify" fails closed.
3. **Guard self-test** — ~25 forbidden frames (neighbouring ranges, broadcast, multicast, IPv6, spoofing, options,
   fragments, odd protocols, unlearned next hops) are thrown at the real guard on a no-op NIC before the first real
   packet; any leak aborts.
4. **One byte-level guard** (`GuardedTransport._check_raw`) judges the *exact bytes* that go to the NIC (not scapy
   fields, which can be lazy or symbolic): our MAC/IP only; ARP who-has to broadcast for an in-scope address with our
   marker; IPv4 unicast only, no options/fragments, our IP-ID marker, whitelisted protocols/flags, destination in scope
   **and not held**, next-hop MAC learned *from an in-scope ARP answer* (a frame can never be steered to an out-of-scope
   gateway), packet budget. Scapy objects are converted to bytes first, so every path uses the same check.
5. **Leash** — probes carry small TTLs. Probes to on-link hosts go straight to their own MAC. Everything else goes via
   the in-scope gateway at TTL 2; TTL ≥ 3 is sent only along paths where every router so far has been *proven* in scope
   by ICMP time-exceeded sourced from an in-scope address. A hop outside scope, or a silent hop, closes the path.
6. **Process fence** — a PEP 578 audit hook sees every socket connect/send/bind and DNS lookup in the process and
   refuses all but loopback; refuses launching any program except one sanctioned helper (nmap) inside a context, after
   target validation; scapy's send functions and the libpcap handle are locked so they only work inside the guard.
7. **Independent auditor** — a separate OS process captures our MAC's egress, parses raw bytes, attests every 0.5 s via
   alternating heartbeat files, and **terminates the engine itself** on any tagged frame to an out-of-scope address. The
   engine refuses to send if the attestation lapses (fail closed).
8. **Kill switch** — any attempt, sighting, territory loss or fence breach writes a latch file and exits the process in
   ~150 ms (`os._exit`; NIC close runs in the background and cannot delay death). Restart is refused until a human resets it.
9. **Hold** — once a separate segment is found, deep probing of it is refused by the guard (classification probes that
   *verify* an already-detected address are the only exception, tagged `classification=True`, ~30 packets, no port scan).
10. **No DNS, no IPv6/multicast, no passive dependence** — a resolver or multicast group may be outside scope, so none is used.

Honest boundary: nmap (a child process) uses OS sockets, so the in-process guard and the auditor's tagging do not see it.
It is bounded by: one-program fence allowance, per-target scope+hold validation immediately before launch, `-sT -Pn -n`
only, only ports Probe already found open, a fixed script list. An OS-level egress allow-list (`enforce/`) is the
recommended backstop. Other agents' network actions are outside Probe's guard (see `docs/CONTRACT.md`).

## 4. Probe generation (`discovery/rawprobes.py`, `tiers.py`)

* **Tiers** (cost-ordered, each answered host leaves the ladder): ARP → ICMP echo → TCP ACK (stateless filters pass a
  bare ACK; any RST proves a host) / SYN → ICMP timestamp & mask → UDP to a closed port (host answers ICMP
  port-unreachable). TCP port lists come from **nmap's own frequency ranking** (`nmap-services`), not by hand.
* **Identity in the headers** — no per-probe state: ICMP id/seq, TCP/UDP source port, IP-ID marker `0x5052`, ARP target-hw
  marker. A reply, or an ICMP error that quotes our probe, is matched back from header bytes alone. Echo payload carries
  the target's low 16 bits so a reply from a *different* address reveals a second interface.
* **Byte-level builders**: `struct`-packed Ethernet/IP/TCP/UDP/ICMP with RFC 1071 checksums — 2.4 µs/frame (scapy objects:
  ~150 µs) and verified byte-for-byte against scapy's dissector in tests.

## 5. Evidence model (`discovery/ingest.py`)

Capture is libpcap with a BPF filter (`ether dst <our MAC>` + DHCP): only replies are ever dissected. Replies become typed
observations: `arp_mac`, `visible[ip]` (which probe kinds the host itself answered), `ladder`, `hops`, `ttls`, `reply_mac`,
`router_macs`, `forwarders`, `hosted_by`, `via`, `catchall`, `fwd_hits`, `foreign` (out-of-scope addresses revealed by
in-scope answers), `masks`. Bookkeeping is in memory and flushed to SQLite in bulk (a commit per reply would cap the scan
at a few hundred pps). **No conclusion depends on overhearing** other devices' traffic (it is unavailable on Wi-Fi with
client isolation or switched ports).

## 6. Inference by proof, not by score (`analysis/classify.py`)

Question per host: *is it on the scanner's own broadcast domain, or separate (behind a router/proxy/host)?*
A verdict is **CONFIRMED** only if an observation *entails* it; otherwise it is SUSPECTED / UNRESOLVED / CONFLICT and is
reported as unconfirmed — never as a network. There are no weights and no "N signals = alarm" thresholds.

| Rule | Observation | Entails (assumption) |
|---|---|---|
| L1 | host answered a TTL=1 probe | delivered without forwarding → on-link |
| L2 | gateway ICMP-redirected to the host | same link |
| L3 | ARP answered by a MAC that is no router's, unique to the host, and its replies come from that MAC | that MAC is the host's interface (no unknown proxy; R4/R1p refute this) |
| L4 / L5 | gateway / forwarder on its own MAC; or no ARP but replies from one unique non-router MAC | on-link |
| R1p | probe addressed to the MAC that answered ARP drew time-exceeded **from that MAC** | that device forwards: proxy ARP |
| R3 | answers L3, ignores repeated ARP, replies arrive via a router MAC | not on our broadcast domain |
| R4 | every reply TTL = standard-initial − 1 (63/127/254/31), ≥ 2 replies | reply crossed a forwarding hop → L3/L5 not allowed to call it on-link |
| R5 | silent address answers only when addressed through host H, replies return via H's MAC | behind H |
| R6 | on-link host sends time-exceeded for a TTL=1 packet not for it | H forwards IP (pivot candidate) |
| R7 | silent address answers a **TTL=1** packet addressed to H's MAC, replies from H's MAC | the address lives inside H's own stack (secondary IP / virtual interface / container or VM gateway) |

Why TTL=1 is useful here: a TTL=1 packet is *never forwarded*. A time-exceeded reply therefore proves forwarding, and an
echo reply *from a third address* proves local delivery — i.e. the address is hosted by the device we addressed.
Defects found by field testing and now regression tests: "first answered at TTL=2" is **not** proof of a router on lossy
Wi-Fi; a time-exceeded for a probe sent via the gateway MAC proves nothing about an on-link host; hosts that ignore ARP
but answer pings from their own MAC are on-link.

## 7. Hidden-network detection

"Hidden" is defined operationally: *a standard ARP + ping sweep from the scanner would not reveal it.* Each segment's report
states why (no echo/ARP answer, answered only on kinds X, behind forwarder H, filtering device reports
"administratively prohibited").

Mechanisms, all active and independent of passive listening:

1. **Distance/path** — leash-bounded TTL rungs; router addresses from time-exceeded (an out-of-scope router address is
   recorded as a lead, never probed).
2. **Alias / forwarder matrix** — every on-link host × every silent in-scope address, one TTL=1 echo each (~10k probes,
   ~11 s). Yields forwarders (R6) and hosted addresses (R7).
3. **Catch-all control** — a front that answers for an address that provably belongs to *another* device answers for every
   address, so its answers carry no information (decoy / tarpit / AnyIP-style gateway). Fronts that answer for several
   silent addresses get 14 extra controls. Catch-all answers are **never promoted** into the inventory; promotion is
   *revocable*, so late evidence demotes an early guess. A catch-all is then characterised over TCP (plain stack / tarpit /
   DNAT-style gateway that SYN-ACKs only specific address:port pairs).
4. **Verification with controls** — for each remaining hosted address: repeat the TTL=1 test via the front five times,
   run the same probe via six *other* hosts' MACs (must never answer), re-ARP three times (must stay silent), echo via
   the gateway (must stay silent); capped at 20 s total.
5. **Pivot sweep** — silent addresses probed through each forwarder/anomaly host at TTL 2 (R5), with a control re-probe
   so a host that merely woke up is not mislabelled.
6. **TTL anomaly / cluster** — reply TTL not in {64,128,255} shared by ≥ 2 hosts flags an unusual common stack.
7. **Service leaks** — nmap banners/titles/certs are scanned for private addresses outside the scope; those become
   outside-scope leads (existence only, prefix unknown). Deliberately vulnerable training apps are recognised by name.

Subnet bounds (`analysis/segments.py`): a subnet is one aligned contiguous CIDR block; hosts are labelled by attachment
point; the report gives a **lower bound** (smallest aligned block containing the members) and an **upper bound** (largest
block inside the scope containing no foreign host), collapsed to the exact prefix only by a host's own ICMP address-mask
reply. The local link is one segment with "holes" listed. Prefixes are never guessed.

## 8. The scan pipeline and measured timings (a /24, ~200 hosts, busy Wi-Fi)

| Phase | What | Typical |
|---|---|---|
| gateway, arp | ARP gateway; ARP scope at 300 pps, ≥ 3 rounds | 5–8 s |
| blitz | full tier suite on **every** address, ~52k probes, round-robin across hosts | 37–55 s |
| loss | retransmit until a repeat pass adds nothing; halve rate if it does | 6–12 s |
| stragglers, recheck | late ARP responders get the full suite; immediate ARP re-test (R3) | 5 s |
| forwarders | alias/forwarder matrix + controls | 11–12 s |
| catchall, pivot, verify | characterise catch-alls; pivot sweep; capped verification | 3–10 s |
| enrich | nmap: fast web/SSH/dev-port stage, then the rest, within a budget | ≤ 60 s |
| **total** | one autonomous pass, ~70k probes | **~120–150 s** |

Slow-engine baseline for the same network: first complete answer at ~130 s, full run ~16 min.

## 9. Performance engineering (why it is fast and still complete)

* Per-packet cost: build 148 µs → 2.4 µs; guard+send path 697 µs → 4.5 µs (≈ 220k pps in a no-NIC benchmark). The scan is
  bounded by the radio, not by Python: on Wi-Fi ~1,000–1,250 pps of small frames is the airtime ceiling.
* Waits are "until replies stop arriving" (`_settle`), not fixed sleeps.
* **Speed must not cost detection**, so loss is measured, not assumed: repeat passes of the cheap suite continue until a
  pass finds no new host and no new open port; if one does the rate is halved. ARP (the cheapest, most reliable tier) is
  sent gently (300 pps) over several rounds because Wi-Fi drivers drop broadcast bursts.
* Parity check: vs a slow-engine baseline the fast scan found the same hosts except those that had left the network
  (confirmed with an independent gentle 4-round ARP sweep: 191 ARP responders, 190 in the engine's result) and found
  ~2× more open ports (200 ports instead of 100, SYNs with an MSS option).
* SQLite in WAL mode with bulk upserts; the auditor parses raw bytes (no dissection) so it keeps up with the sender.

## 10. Verification

99 unit tests (no simulated network; guard/fence/auditor logic, byte-exact packet builders against scapy, every
classification rule with hand-written observations incl. each defect found in the field, catch-all/revocation, ledger,
a test that **fails the build if any site-specific string appears** in product code/docs). Live runs repeatedly exposed
real defects (a heartbeat read/rename race, `os.kill(pid, 0)` terminating processes on Windows, the audit hook receiving
a Windows command *string*, false "routed" verdicts from lost TTL=1 probes, 33 false hidden hosts from a catch-all device);
each failed **closed** (kill switch, never an out-of-scope packet) and became a regression test. Across all runs:
0 probes out of scope, 0 auditor violations.

## 11. Integration with the LangGraph agents (`docs/CONTRACT.md`)

Probe owns the inventory; other agents read it and claim work. HTTP API on loopback + a stdlib client:
inventory queries (`/api/hosts`, `/api/services`, `/api/targets/web`, `/api/pivots`, `/api/segments`, `/api/leads`),
an append-only **events** feed (poll with a cursor; store the cursor in the graph checkpointer), `GET /api/scope/check`
(agents must ask before sending anything), and the **claim/complete ledger**: stable idempotency keys
(`web-crawl:<ip>:<port>`), atomic claims with TTL, results stored and returned to later claimants — so graph retries,
parallel branches and re-invocations never repeat work. `ensure_scan(max_age_s)` makes many agents share one scan.

## 12. Limitations (say them before they are asked)

* A segment that drops every probe type and never reveals itself through a router, a banner or an alias cannot be seen
  from outside; it is counted as *silent*, not absent.
* Transparent L3 devices that do not decrement TTL are invisible to distance logic; same-wire subnets without a router are
  one broadcast domain (only mask replies separate them).
* "Separate" means *not on our broadcast domain*; with Wi-Fi client isolation that can be an ordinary host in the same IP
  subnet — the report says "L2-separate", not "different subnet", unless mask/router evidence shows it.
* Strict leash mode will not walk through a silent router (cannot prove the next hop is in scope); `--allow-silent-hops`
  trades fence strictness for reach.
* The first unproven router can receive one TTL-expiring probe — unavoidable when finding networks behind routers.
* nmap and other agents' traffic are outside the in-process guard (section 3).
* Needs raw-socket privileges and Npcap/libpcap; territory check implemented for Windows and Linux (other OS fail closed).

## 13. Questions to expect

* *"How do you know it never leaves the scope?"* One byte-level guard on the exact frame; fail-closed layers around it;
  an independent process verifies on the wire and can kill the agent; the OS-level process is fenced; tests + live runs
  show 0 violations. The remaining gap is stated (nmap child, other agents).
* *"Why not trust ARP?"* Proxy-ARP routers answer for hosts that are elsewhere; ARP is evidence of *who owns the MAC*,
  never of adjacency by itself.
* *"What is a false alarm here?"* A confirmed hidden host that is not one. Hence proofs with stated assumptions, controls
  (other hosts' MACs, ARP, gateway), repeat counts, catch-all detection, and revocable promotion.
* *"Why is it fast?"* Python is out of the critical path; the remaining time is radio airtime and deliberate settling.
* *"Why not just run nmap?"* nmap is used for what it is best at (service/banner identification); it cannot enforce a
  byte-level scope, find TTL=1 alias/forwarder evidence, or run a leash — and its raw traffic would bypass the guard.
