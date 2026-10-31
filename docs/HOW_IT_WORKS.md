# How Probe works

Probe is a general-purpose, autonomous network discovery agent. Give it a scope
(one or more CIDR ranges) and it finds every device that answers anything, works
out which separate networks those devices sit on, says which networks would have
been invisible to a standard ping sweep, and **never sends a packet outside the
scope**. Nothing in it is specific to any one network.

## 1. The problem, and why one trick is not enough

From a single machine you cannot "see" a network; you can only send packets and
interpret replies. Every discovery technique has a blind spot:

| Technique | Finds | Blind spot |
|---|---|---|
| ARP | everything on your own link | nothing beyond the first router; a router doing **proxy ARP** answers for hosts that are *not* on the link |
| ICMP echo (ping) | hosts that allow ping | firewalls drop it |
| TCP SYN / ACK | hosts with open ports / stateless filters | fully filtered hosts |
| ICMP timestamp / mask | hosts behind filters that only block echo | hosts that ignore them |
| UDP to a closed port | hosts that send ICMP port-unreachable | hosts that rate-limit or drop ICMP |
| Traceroute (TTL) | the router path | routers that don't send "time exceeded" |
| Passive listening | whatever you overhear | **nothing** on Wi-Fi with client isolation, switched ports, VLANs |

So Probe uses all of them, in a cost-ordered ladder, and **no conclusion depends
on passive listening**. Passive capture is optional enrichment; the status line
says how much it could see ("limited" on Wi-Fi) so you know.

Related work this design builds on: Nmap's default host discovery combines ARP,
ICMP echo, TCP SYN/ACK and ICMP timestamp
([Nmap host discovery](https://www.hackingarticles.in/nmap-for-pentester-host-discovery/));
ZMap/masscan showed that sending everything first and listening once is far
faster than per-host state ([ZMap paper](https://zmap.io/paper.pdf)); the
TTL=1 vs high-TTL comparison for detecting proxy ARP comes from a
[patent on LAN test tools](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/5708654);
routers that do not decrement TTL are invisible to traceroute
([DRAGO](https://traffic.comics.unina.it/Traffic/drago.php)). Probe's gaps compared
with them are listed in section 9.

## 2. The agent loop (`probe/engine.py`)

```
repeat:
  1 expand    ARP, then TTL waves 1..N. Each wave runs the tiers
              ICMP echo -> TCP ACK/SYN -> ICMP timestamp/mask -> UDP
              for addresses that have not answered yet. The wave in which a host first
              answers IS its hop distance -- sweep and distance measurement are one step.
  2 infer     classify hosts by proof -> cut address space into segments -> HOLD separate segments -> redraw graph
  3 identify  ports / vendor / OS hint, for hosts PROVEN on-link only
  4 deepen    nothing new? dig deeper inside the yard: 12 -> 36 -> 100 top TCP ports on every
              still-silent address, then report convergence and keep watching
```

It is the "sniffer dog": it digs as deep as it likes **inside** the yard (step 4) and cannot get out
(section 7). It needs no help: it finds its scope from `--scope`, `$PROBE_SCOPE` or `probe-scope.txt`,
asks for administrator rights itself, proves its own guard, starts its own auditor, and
runs until convergence on its own.

### The leash (why a probe can't wander out through the gateway)
A probe sent to an unused in-scope address would be forwarded by the gateway's default route
towards the Internet. So every probe carries a small TTL, and **TTL=t is sent only when routers
1..t-1 are proven inside the scope**: router 1 is the in-scope gateway whose MAC we chose as next
hop; routers 2.. are proven by time-exceeded replies sourced from in-scope addresses. A hop
that answers from an out-of-scope address closes that path; a silent hop also closes it (we cannot
prove what lies beyond) unless `--allow-silent-hops N` is given. The final report says how many
address paths were closed and why. Worst case a probe expires at the first *unproven* hop,
which is the closest any physical design can get to "never steps out" while still being able to
find networks behind routers.

### Probe selection (`discovery/tiers.py`, `discovery/probes.py`)
* TCP ports are the highest-ranked ones in Nmap's own measurements
  (`nmap-services`), not a hand-picked list. Fallback copy built in.
* Tier 2 sends a bare **ACK** to 80/443 (stateless firewalls let ACK through; any
  RST proves a host) and **SYN** to the top-N ports (SYN-ACK or RST = alive).
* Tier 4 sends UDP to a port nothing listens on; a live host answers ICMP
  port-unreachable.
* Hosts that answer nothing at any tier are counted as **silent** and reported as
  "undetectable with this probe set". Silence is never read as absence.
* Every probe encodes its identity in header fields (ICMP id/seq, TCP/UDP source
  port) so a reply, or an ICMP error quoting it, is matched back with no per-probe state.

## 3. Evidence (`discovery/ingest.py`)

Every captured packet becomes a typed observation with a precise meaning:
`arp_mac`, `visible[ip]` (which probe kinds the host itself answered),
`ladder[ip]` (smallest TTL that made the host answer), `hops[target][ttl]`
(router that sent time-exceeded), `unreach`, `redirected_onlink`, `masks`,
`foreign` (out-of-scope addresses revealed by in-scope probes). Only
replies to our probes (or errors quoting them) feed these.

## 4. Host classification by proof (`analysis/classify.py`)

Is a host on the scanner's own broadcast domain (ON-LINK) or SEPARATE (reachable only through a router
or proxy)? There are **no weights and no "N signals = alarm" thresholds**. Each rule is an observation
that *entails* a conclusion:

| Rule | Observation | Entails |
|---|---|---|
| L1 | the host itself answered a probe sent with TTL=1 | delivered without forwarding -> **ON-LINK** |
| L2 | the gateway ICMP-redirected traffic straight to the host | same link -> **ON-LINK** |
| L3 | it answered ARP with a MAC that belongs to no known router and no other address, and its replies come from that same MAC | that MAC is its own interface -> **ON-LINK** |
| L4 | it is the gateway / a router address answering from its own MAC | **ON-LINK** |
| R1p | a probe addressed to the MAC that answered ARP for the host drew time-exceeded from *that same MAC* | that device forwards instead of terminating: proxy ARP -> **SEPARATE** |
| L5 | no ARP answer, but all its L3 replies arrive from one MAC that is no router's and belongs to no other address | delivered directly -> **ON-LINK** (a phone that ignores ARP but answers pings) |
| R3 | the host answers L3 probes yet ignores repeated ARP sent right afterwards, **and** its replies arrive via a known router's MAC | not on our broadcast domain -> **SEPARATE** |

(L5 and the "via a router's MAC" condition on R3 exist because field testing showed a sleeping phone that
ignored ARP but answered pings from its own MAC being mislabelled separate.)

Verdicts: `CONFIRMED_ONLINK`, `CONFIRMED_SEPARATE`, `SUSPECTED_*` (consistent with, not proven),
`UNRESOLVED`, `CONFLICT` (contradicting proofs are reported, never guessed).

**What field testing on a busy Wi-Fi network taught (now regression tests).** "First answered
at TTL=2" labelled 15 ordinary on-link phones as routed (a lost TTL=1 probe looks identical), and a
time-exceeded reply for a probe that had been addressed to the *gateway's* MAC made an on-link host look
routed. So: the measured distance and time-exceeded replies are **supporting evidence only**; the proof
comes from *who owns the MAC that answers ARP*. "SEPARATE" means "not on our broadcast domain": on a
network with Wi-Fi client isolation that can also be an ordinary host in the same subnet, and the report
says so rather than claiming a different IP subnet.

The TTL ladder is still how the agent measures distance and walks the router path (always inside the
leash), but it no longer decides attachment by itself.

## 5. Subnet inference (`analysis/segments.py`)

A subnet is one aligned, contiguous CIDR block whose hosts share one attachment
point. So:

1. Label each confirmed host: `local`, or the router path it sits behind. Hosts
   whose known hops or measured distance disagree can never share a label.
2. Sort by address; a maximal run of one label is a candidate segment.
3. Report what the evidence **bounds**, not a guess:
   * `covering` — smallest aligned block containing the members (lower bound)
   * `max_extent` — largest aligned block inside the scope containing no host of
     another attachment point (upper bound)
   * a host's own **ICMP address-mask reply** collapses the interval to the exact
     prefix (ignored if inconsistent with other hosts).
4. Suspected hosts never create or move a segment; they are listed as
   "unconfirmed" so a wrong guess cannot become a false alarm.
5. Out-of-scope router/interface addresses revealed by in-scope probes are reported
   as **address only, prefix unknown** — a prefix is never invented.

## 6. What "hidden" means (`hidden_verdict`)

A segment is **hidden** if a standard ARP + ping sweep would not have revealed
it: no member answered ICMP echo. The report lists exactly why (no ARP answer →
not on our link; N router hops in front; proxy ARP masking it; filtering device
reporting "administratively prohibited"; and the list of probe types that *did*
get answers). A segment is **visible** if ping alone finds it.

## 7. The fence — ten independent layers

The first three layers make the agent unable to *live* outside its territory; the rest stop any
single frame from leaving it.

-2. **Range sanity** (`territory.sane_scope`): a scope that is public, multicast/loopback, malformed,
   or wider than a /16 (almost certainly a typo) kills the agent at start with exit code 7.
-1. **Territory lock** (`territory.py`): the scanner's *own* address must be inside the scope
   (even when `--iface` is given), or it dies with exit code 6 before it asks for admin rights, opens
   a socket, or sends anything. While running, a cheap local OS query (Windows `GetIpAddrTable`,
   Linux ioctl) runs before every send and every 0.5 s in the **independent auditor process**: if the
   address disappears, the link drops, or the machine roams to another network, the kill switch fires
   and the auditor kills the engine from outside. If the location cannot be verified (unsupported OS,
   persistent API failure) it fails closed.
   **Final-bytes check** (`transport._wire_ok`): the exact bytes about to be written to the NIC are
   parsed once more (ARP target / IP destination at their real offsets) and must equal the validated
   target and be in scope; the frame that is sent is re-parsed from those verified bytes, so a lazily
   resolved or overridden scapy field cannot smuggle a destination past the guard.
0. **Process fence** (`fence.py`, installed right before the first probe): a Python audit hook sees
   every socket connect/send/bind and DNS lookup made by *any* code in the process (ours, a library,
   a dependency) and refuses everything except loopback (the local web view); launching any other
   program (ping, nmap, curl, PowerShell) is refused; every scapy send function and socket `send`
   is locked so it only works inside the guarded transport. A violation trips the kill switch.
   This closes "digging under the fence": there is no second way out of the process.

1. **Frame-level guard** (`net/transport.py`): checks the packet's real destination
   immediately before sending. Only ARP who-has from our own MAC/IP, and IPv4
   unicast ICMP-echo/timestamp/mask, TCP SYN/ACK, UDP to two ports. No IPv6, no
   broadcast/multicast, no IP options/fragments, no spoofing.
2. **Learned next hops only:** the destination MAC must have answered ARP for an
   in-scope address, so a frame can never be steered to an out-of-scope gateway.
3. **Pre-flight self-test** (`selftest.py`, runs automatically): throws ~25 forbidden
   frames at the real guard on a no-op NIC; any leak → refuses to start.
4. **Independent auditor** (`audit.py`): a *separate process* watches the wire,
   attests every 0.5 s, kills the engine itself on any out-of-scope tagged frame.
   The engine refuses to send if the attestation lapses (fail closed).
5. **Kill switch** (`killswitch.py`): any attempt, sighting, territory loss or fence breach writes
   `probe-data/TRIPWIRE.json` and ends the process within ~150 ms (`os._exit`; closing the NIC runs in
   the background and can never delay the death). The tool will not restart until a human runs
   `reset-tripwire`.
6. **Hold** (`scope.py`): once a separate segment is found, deep probing of it is
   refused until `probe approve <cidr>`.
7. **Budget + no DNS:** a packet budget from the scope size; no DNS (the resolver
   may be out of scope); IPv6 scope ignored (needs multicast).
   Optional OS-level rules: `enforce/nftables.nft`.

Section 7's layers 1-7 below are numbered from the transport guard.

## 8. Specific problems and how each is solved

| Problem | Solution |
|---|---|
| Host ignores ping | tiers escalate to TCP ACK/SYN, ICMP timestamp/mask, UDP |
| Router doesn't send time-exceeded | distance comes from the host's own first answer on the TTL ladder |
| Proxy ARP makes routed hosts look local | ARP is never proof; ladder proof contradicts it → `proxy_arp`, MAC tainted |
| Your NIC mask is wider than the scope (e.g. /22 around a /24) | scope, not the NIC subnet, drives targets; the NIC subnet is only reported |
| Gateway outside the scope | not used; hosts that don't answer ARP are then unreachable and reported silent |
| Reply from a different address than probed (multi-homed device) | ICMP seq encodes the target; mismatch is recorded as an alias / out-of-scope interface |
| Wi-Fi hides other devices' traffic | nothing relies on overhearing; status reports passive visibility |
| Guessing a prefix | never; lower + upper bounds, collapsed only by the hosts' own mask replies |
| Windows `os.kill(pid, 0)` kills the target | auditor uses a ctypes liveness check instead |

## 9. Known limits (be honest in the report)

* **Fence vs. completeness:** strict mode closes any path through a silent router, so a segment behind
  a router that never sends ICMP errors is reported as "unexplored (cannot prove inside the scope)"
  rather than reached. `--allow-silent-hops N` trades fence strictness for reach; it is off by default.
* The first unproven router can receive one TTL-expiring probe; that is unavoidable for finding networks
  behind routers (its destination is still always in scope).

* A segment whose every host drops all probe types, and that no router reveals,
  cannot be seen from the outside. It is counted as silent, not absent.
* A *transparent* L3 device that does not decrement TTL is invisible to the ladder
  (DRAGO uses IP timestamp options to find those; Probe forbids IP options for scope safety).
* Different subnets on the same wire with no router are not separated by distance
  (they are the same broadcast domain); only mask replies would reveal them.
* ECMP/load-balanced paths can make hosts of one segment look like two attachment points.
* Raw packets need an admin shell and Npcap/libpcap; some Wi-Fi drivers restrict raw sending.
  On Windows, Npcap injection bypasses Windows Firewall, so the independent auditor and
  (on Linux) nftables are the real outside-the-app checks.
