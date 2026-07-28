# Architecture

One container, one Go binary as PID 1, N `tor` child processes.

```
torpool (PID 1)
 ├─ supervisor ──► tor ×N, each with its own SOCKS port,
 │                 control port and DataDirectory on container loopback
 ├─ SOCKS5   :9250   sticky, username = session key
 ├─ HTTP     :9251   CONNECT + absolute-URI
 └─ HTTP     :8080   dashboard, REST, SSE, /metrics, /health
```

| Package | Responsibility |
| --- | --- |
| `internal/config` | Environment parsing, defaults, validation |
| `internal/tor` | torrc rendering, the control-port client, process supervision |
| `internal/pool` | Session pinning, instance selection, health, remediation |
| `internal/proxy` | The two client-facing listeners and the byte relay |
| `internal/stats` | Rolling time series and the audit log |
| `internal/server` | REST, SSE, metrics, embedded dashboard |

The layering is one-way: `proxy` and `server` depend on `pool`, `pool` depends on `tor`,
and `tor` knows nothing about any of them.

## Why torpool is PID 1

It owns the Tor processes, so it has to reap them. Nothing else in the container will.
That also means shutdown is its job: `docker stop` sends SIGTERM to PID 1, and torpool
gives each child its own grace period so Tor can flush its state directory. Cutting that
short is what produces a corrupt `DataDirectory` on the next start.

## Sessions and stickiness

A session key is the SOCKS5 username, or the `Proxy-Authorization` user over HTTP. No
credentials means the key comes from `DEFAULT_SESSION`, so a plain `curl` is sticky too.

The key is an **identity hint, not access control**. Anyone who can reach the port can
claim any key; many callers presenting the same key deliberately share an instance.

New sessions go to the instance with the fewest pinned sessions, with a random
tie-break — a deterministic tie-break would funnel every new session onto the same
instance until its count rose.

**Credentials are not forwarded to Tor.** Tor's `IsolateSOCKSAuth` is on by default, so
passing the key through would give each session its own circuit *inside* one instance.
Two callers pinned to the same instance would then see different exit IPs, and "an
instance is an exit identity" — the model the whole pool rests on — would be false.

## Knowing the exit IP

Resolved entirely from Tor's own view, at no Tor-bandwidth cost:

```
circuit-status → the circuit carrying a live stream → its last hop
              → ns/id/<fingerprint> → the relay's address
              → ip-to-country/<address>
```

The answer must be *stable*, not merely current, because "an instance is an exit
identity" is only true if the reported exit holds still. Tor keeps several built circuits
at once and keeps building more preemptively, so the choice is made in this order:

1. the circuit carrying a stream — the only one Tor has committed traffic to;
2. the exit reported last time, while a circuit to it still stands;
3. the newest circuit, by its `TIME_CREATED`, when there is nothing better to go on.

Naming an exit that no traffic has ever used is what the first implementation did, and it
reported the wrong IP; following Tor around its preemptive circuits is what made one
instance appear to alternate between two exits.

Step 1 is also why `PURPOSE=CONFLUX_LINKED` circuits count as exit-bearing alongside
`GENERAL` ones. Conflux is on by default in current Tor, and its linked legs — which share
an exit by construction — are what streams actually ride; a resolver that accepts only
`GENERAL` reads the preemptive circuits and never the ones in use.

Circuits older than the instance's last `NEWNYM` are excluded outright: that signal makes
every existing circuit unusable for new streams, so their exits are no longer where the
instance goes out. An **idle** instance builds no replacement — Tor waits for traffic — so
after a rotation there is genuinely no current exit until the next request. The API reports
none, and hands the discarded one over separately as `retired_exit_ip` so the dashboard can
show what it was without claiming it is live.

Because a stream only exists during a request, the exit is sampled shortly after a
connection is established, debounced per instance, plus a slow background refresh.

## Failure accounting

Per instance, over a sliding window, from two sources:

- **transport** — refused SOCKS handshakes, resets, timeouts. Free, and blind to
  HTTP-level blocking.
- **client** — `POST /api/sessions/{key}/failure`. The only signal that catches soft
  blocks, because the balancer cannot see inside an HTTPS tunnel.

Quarantine triggers on consecutive failures (a hard-dead instance drops out fast) or on
a windowed count (an instance failing half its requests never accumulates consecutive
failures but is just as unusable). A success resets the consecutive count but not the
window — an instance failing every other request is still unhealthy.

## The remediation ladder

```
newnym  →  wipe-restart  →  wipe-restart with exponential backoff
```

Escalation is driven by recurrence inside `ESCALATION_WINDOW`, not by attempt count.
An instance that misbehaved once weeks ago starts again at the cheapest rung; one
failing repeatedly has proven the cheap fix does not work.

A remediated instance returns **on probation**, where a single failure re-quarantines it
immediately — the cheap fix has demonstrably failed, so there is nothing to wait for.
Surviving a request clears probation.

In a single-container topology the third rung is the strongest action available; there
is no separate container to recreate. The ladder is honestly three rungs, not four.

Separately, a watchdog restarts Tor processes that die on their own. The failure ladder
would never notice: a dead instance takes no traffic and so records no failures.

## State that is not persisted

Time series and the audit log live in memory and reset on restart. Session pinnings do
too — after a restart, callers are simply reassigned. Tor's `DataDirectory` is the only
thing on the volume, and only so restarts re-bootstrap from a cached consensus.

Adding persistence later is contained behind `internal/stats`.

## Invariants

The subtle ones are listed in [AGENTS.md](../AGENTS.md). The two that bite hardest:

1. A proxy connection is pinned to its instance for its entire life, so rotation only
   affects *new* connections. Clients must drop pooled keep-alives after rotating.
2. Listeners bind `0.0.0.0` inside the container — a container-loopback bind is
   unreachable through a port mapping. Exposure is the host-side publish's job.
