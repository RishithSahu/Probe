# Probe ↔ LangGraph contract

For the agent(s) that orchestrate the web / binary / vulnerability work. Probe is the **discovery agent**: it owns
the network inventory and the fence. Every other agent reads that inventory and claims work through the ledger, so
nothing is scanned or tested twice.

Probe runs as one local process (`python -m probe`, admin shell). It scans once (~2–3 min for a /24), then keeps
serving this API on `http://127.0.0.1:8080` (interactive docs: `/api/docs`). Python callers use `probe.client.ProbeClient`
(stdlib only: no scapy, no admin rights).

## 1. The rules every agent must follow

1. **Never send anything to an address without asking.** `GET /api/scope/check?ip=…` → `allowed: true` only for addresses
   inside the authorised scope and **not inside a held segment**. A held segment is a hidden network Probe found; nobody
   probes it further until the network owner approves (`python -m probe approve <cidr>`). Importing `probe.scope.ScopeGuard`
   gives the same answer offline.
2. **Claim before you work.** One claim per unit of work (section 4). If the claim is not granted, skip the work.
3. **Don't re-scan.** Call `ensure_scan(max_age_s=300)`; it reuses a fresh scan and only starts one when the last is stale.
   Many agents may call it at once: one scan runs, everybody gets the same result.
4. **Read verdicts as written.** `CONFIRMED_*` is proven by an observation listed in `reasons`; `SUSPECTED_*` is not a fact.

## 2. Data model (all JSON)

**Host** — `GET /api/hosts[?held=false&verdict=CONFIRMED&role=forwarder&with_services=true]`, `GET /api/hosts/{ip}`
```json
{ "ip": "10.20.30.16", "mac": "60:45:2e:c6:d0:db", "vendor": null, "os_guess": "Windows", "ttl": 128,
  "verdict": "CONFIRMED_ONLINK",            // CONFIRMED_ONLINK | CONFIRMED_SEPARATE | SUSPECTED_* | CONFLICT | UNRESOLVED
  "reasons": ["L3: ARP answered by MAC … its replies come from that same MAC"],   // the proofs / support, human readable
  "roles": ["forwarder", "fronts-hidden-network", "catch-all-responder"],
  "visible_to": ["arp", "icmp-echo", "tcp-syn:8080"],    // which probe kinds the host answered
  "held": false,                                        // true = inside a held (hidden) segment: do NOT probe
  "open_ports": [ { "port": 8080, "proto": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.68",
                    "extrainfo": null, "banner": null, "scripts": { "http-title": "Login :: Damn Vulnerable …" } } ] }
```

**Segment** — `GET /api/segments`: `{cidr, kind: in-scope|outside-scope, state: local|held|approved, verdict, via, hosts[], evidence[],
extra: {covering, max_extent, basis, hidden: {level: visible|hidden, reasons[]}, path, distance, local, prefix_known}}`.
`covering` is the smallest block proven; `max_extent` the largest consistent one (the true subnet lies between). `outside-scope`
entries are addresses only (prefix unknown) and are **never probed**.

**Leads** — `GET /api/leads`. `source` says what it is: `hidden-host` (proven), `vulnerable-app` (flagged by banner/title, e.g.
DVWA), `anomaly:forwarder`, `anomaly:ttl-cluster`, `outside-scope-address`, `unconfirmed:*` (**not facts**, follow-up candidates).

**Ready-made task inputs**
- `GET /api/targets/web` → `[{ip, port, url, service, product, version, banner, scripts}]` for the web agent (non-held only).
- `GET /api/services?port=3306&service=ssh` → flat list of open services for any other agent.
- `GET /api/pivots` → hosts that forward IP / front another network.

## 3. Change feed (so agents react instead of polling state)

`GET /api/events?since=<id>` → `{events: [{id, ts, type, payload}], next}`. Types: `scan.started`, `scan.finished`
(payload = summary incl. timings, hosts, segments), `work.done`, `work.failed`. Poll with `since=next`.

## 4. The work ledger (prevents repeated work)

Key = the unit of work. Use stable, descriptive keys so two agents deciding the same thing produce the same key:
`web-crawl:10.20.30.16:8080`, `binary-analysis:<sha256>`, `vuln-verify:<finding-id>`, `scan:10.20.30.0/24`.

| Call | Meaning |
|---|---|
| `POST /api/claim {key, agent, ttl_s}` | `granted:true` → do it. `granted:false` + `status:"claimed"` → someone is on it (skip). `status:"done"` → already done; `result` holds the stored result, reuse it. The holder may renew. An expired claim can be taken over. |
| `POST /api/complete {key, agent, result, ok}` | Only the holder can finish. Stores `result` (JSON) for everyone, emits `work.done`. `ok:false` marks it failed so it can be retried. |
| `GET /api/claims?prefix=web-crawl:` | Everything claimed/done under a prefix. |

Claims, events and scan history **survive a rescan**; the inventory is rebuilt each scan.

## 5. Scan freshness

`POST /api/scan {max_age_s, force}` → `{state: "fresh"|"started"|"running", scan}`. `ProbeClient.ensure_scan(max_age_s)` wraps it
and waits for completion.

## 6. LangGraph usage sketch

```python
from probe.client import ProbeClient
probe = ProbeClient()

def discover(state):                      # node 1: one shared scan, never repeated
    probe.ensure_scan(max_age_s=600)
    return {"web_targets": probe.web_targets(), "hidden": [h for h in probe.hosts() if h["verdict"] == "CONFIRMED_SEPARATE"]}

def web_node(state):                      # node 2: fan out over targets; the ledger makes retries/replays idempotent
    for t in state["web_targets"]:
        key = f"web-crawl:{t['ip']}:{t['port']}"
        c = probe.claim(key, "web-agent")
        if not c["granted"]:
            continue                      # claimed or done: reuse c.get("result") if present
        if not probe.check_scope(t["ip"])["allowed"]:
            probe.complete(key, "web-agent", {"skipped": "held or out of scope"}, ok=False); continue
        result = run_web_agent(t)         # your agent
        probe.complete(key, "web-agent", result)
```
Put `probe.claim`/`complete` inside every tool node so graph retries, parallel branches and re-invocations stay idempotent.
A LangGraph checkpointer should store the `events` cursor (`next`) so a resumed graph continues where it stopped.

## 7. Safety guarantees agents can rely on (and must not weaken)

Probe's own packets go through one byte-level guard (destination in scope, not held, whitelisted protocol, learned next hop),
an independent auditor process attests on the wire, a process fence blocks any other network use, and the machine must stay
inside the permitted network or the agent dies. Other agents' network actions are **not** covered by Probe's guard: run them in a
process that uses `ScopeGuard` before every send, and prefer an OS-level egress allow-list (`enforce/`) for web/binary tooling.
