# API

No authentication. The API can restart instances and resize the pool, so publish port
8080 to loopback only.

Base URL in the examples: `http://127.0.0.1:8080`.

## Pool

### `GET /api/pool`

Summary plus the effective configuration.

```json
{
  "version": "0.1.0",
  "size": 5, "ready": 5, "routable": 4, "sessions": 12,
  "totals": { "requests": 812, "failures": 9, "bytes_up": 91234, "bytes_down": 8123456 },
  "socks_port": 9250, "http_port": 9251,
  "config": { "pool_size": 5, "session_ttl": "10m0s", "default_session": "ip" }
}
```

`ready` counts bootstrapped instances; `routable` counts those that will actually take
traffic. They differ whenever something is quarantined.

### `POST /api/pool/resize`

```bash
curl -XPOST localhost:8080/api/pool/resize -H 'content-type: application/json' -d '{"size": 8}'
```

Returns immediately. Growing spawns instances that bootstrap in the background;
shrinking retires the highest-numbered ones and moves their sessions off first.

### `POST /api/pool/rotate`

New circuit on every instance, **one at a time**, so the rest of the pool keeps serving
throughout. Returns immediately:

```json
{ "rotating": 5, "in_progress": false }
```

The sweep outlives the request by roughly Tor's NEWNYM cooldown per instance. Asking again
while one is running starts nothing and answers `{"rotating": 0, "in_progress": true}`.

## Instances

### `GET /api/instances` · `GET /api/instances/{id}`

```json
[{
  "id": 0, "ready": true, "running": true, "bootstrap": 100, "pid": 15,
  "uptime_secs": 3612, "sessions": 3, "socks_addr": "127.0.0.1:19000",
  "exit_ip": "185.220.101.5", "exit_country": "DE", "exit_nickname": "SomeRelay",
  "retired_exit_ip": "", "exit_confirmed": true, "pinned_exit": "",
  "health": {
    "state": "healthy", "failures_in_window": 0, "consecutive_failures": 0,
    "transport_failures": 2, "client_failures": 1,
    "remediations": 1, "remediation_rung": "newnym"
  },
  "totals": { "requests": 210, "failures": 3, "bytes_up": 4321, "bytes_down": 987654, "latency_ms": 412.5 }
}]
```

`exit_ip` is the exit **currently in use**, read from Tor's own consensus view and
sampled while a connection is live. It is **empty** whenever the instance has no circuit
whose exit it can name — before bootstrap finishes, and for the second or two after a
rotation while Tor rebuilds.

`exit_confirmed` says whether traffic has actually left through it. Tor holds several
exit-bearing circuits at once and keeps building more preemptively, so with no stream
attached the answer is inferred from whichever it is holding — a relay no request may ever
use. An inferred exit never replaces a confirmed one; the first request through the
instance confirms or corrects it. Treat `false` as "probably this".

`pinned_exit` is the relay the instance is locked to when `PIN_EXIT_RELAY` is on, and empty
otherwise. While it is set, `exit_ip` is a promise about the next request too.

`retired_exit_ip` is set only while `exit_ip` is empty, and carries the exit the rotation
discarded so a dashboard can show what it *was*. Never read it as the current exit.

`state` is one of `starting`, `healthy`, `degraded`, `probation`, `quarantined`,
`remediating`.

### Instance actions

| Endpoint | Effect |
| --- | --- |
| `POST /api/instances/{id}/rotate` | New circuit. Returns as soon as the instance is out of service and its sessions have moved (unless `DRAIN_ON_ROTATE` is off); Tor's cooldown then finishes in the background. `409` if the instance has not bootstrapped |
| `POST /api/instances/{id}/restart` | Restart tor. `?wipe=false` keeps guards and cached consensus; the default wipes for a genuinely new identity |
| `POST /api/instances/{id}/quarantine` | Take out of rotation and move its sessions |
| `POST /api/instances/{id}/release` | Clear quarantine and accumulated failures |
| `POST /api/instances/{id}/drain` | Move sessions off without quarantining |

All return the instance's resulting state. `404` if the id does not exist, `409` if its
state makes the action impossible.

## Sessions

These are the only routes a client needs; it never learns instance ids.

### `GET /api/sessions` · `GET /api/sessions/{key}`

```json
{
  "key": "alice", "instance": 2,
  "created_at": "2026-07-27T21:00:00Z", "last_seen": "2026-07-27T21:04:11Z",
  "requests": 42, "failures": 1, "bytes_up": 8123, "bytes_down": 918273, "active": 0
}
```

### `POST /api/sessions/{key}/rotate`

Moves the session to a different instance. Near-instant — it reassigns to an instance
that has already built its circuits rather than waiting out a NEWNYM cooldown.

```bash
curl -XPOST localhost:8080/api/sessions/alice/rotate
# {"session":"alice","instance":4,"exit_ip":"94.142.244.16","exit_confirmed":true}
```

Add `?newnym=true` to also ask the *vacated* instance for a fresh circuit — worth it
when you believe that exit itself is burnt, not just that you want to move.

If there is nowhere else to move to — a single-instance pool, or one instance routable —
the session stays put and its instance is rotated instead, because a rotation that leaves
the exit IP alone did nothing.

> `exit_ip` here is whatever that instance last confirmed, and `exit_confirmed` says
> whether traffic confirmed it. No stream of *this* session is attached yet either way.

### `POST /api/sessions/{key}/failure`

```bash
curl -XPOST localhost:8080/api/sessions/alice/failure \
  -H 'content-type: application/json' -d '{"reason":"http_403"}'
```

The signal that catches soft blocks. The pool relays opaque bytes and cannot see a 403,
a 429 or a captcha inside an HTTPS tunnel, so without this a burnt exit keeps taking
traffic until it fails at the transport level. The body is optional.

### `DELETE /api/sessions/{key}`

Unpins the session; its next request is reassigned. `204` on success.

## Events, stats, stream

### `GET /api/events?limit=200`

Newest first. Types: `assignment`, `rotate`, `quarantine`, `remediation`, `restart`,
`resize`, `instance`.

### `GET /api/stats/history`

Time series for the charts. `?range=long` returns a coarser series covering hours
instead of minutes.

### `GET /api/stream`

Server-Sent Events, two event names:

- `state` — a full snapshot (pool, instances, newest sample) roughly every second
- `event` — one audit-log entry as it happens

```bash
curl -N localhost:8080/api/stream
```

A subscriber that cannot keep up drops events rather than blocking; a stalled dashboard
never applies backpressure to proxied traffic.

## Operational

- `GET /metrics` — Prometheus text format, prefix `torpool_`.
- `GET /health` — `200` while at least one instance is routable, `503` otherwise. It
  reports routability, not bootstrapped processes: an all-quarantined pool is alive and
  fully bootstrapped while refusing every request.

## Errors

Plain text with a matching status. `404` unknown instance or session, `400` bad input,
`503` when nothing can serve the request. An unmatched `/api/` path returns `404` rather
than falling through to the dashboard.
