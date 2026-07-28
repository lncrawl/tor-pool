# API

Base URL in the examples: `http://127.0.0.1:8080`. Every example below needs the
`Authorization` header from the next section; it is left out to keep them readable.

Keep 8080 on loopback even so. Requiring a credential is defence in depth, not a
substitute for TLS — there is none here, so passwords and tokens cross the wire in
cleartext.

## Authentication

Everything under `/api/` requires a credential. `GET /health`, `GET /metrics`,
`POST /api/auth/login` and the dashboard's static assets do not.

Two kinds of credential, both sent as `Authorization: Bearer …`:

| | Obtained by | Used for |
| --- | --- | --- |
| **Session** (JWT) | signing in | the dashboard, and anything interactive |
| **Token** (`tp_…`) | minting one | scrapers, monitoring, CI |

A token also authenticates the proxy ports, where it is the *password* and the
username stays the session key — see [scraper.md](scraper.md).

### Scopes

A token carries one:

- **`proxy`** — proxy traffic, plus the session routes a caller uses to manage the
  sessions it created: `GET /api/sessions/{key}`, `POST …/rotate`, `POST …/failure`.
- **`admin`** — everything, proxy traffic included.

Give a scraper `proxy`. Under `admin` the credential in its config could also resize
the pool, restart instances and read every session key.

### `POST /api/auth/login`

```bash
curl -XPOST localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","password":"…"}'
# {"token":"eyJ…","expires":1785364800,"user":"admin"}
```

On a first run the password is generated and printed once to the container log. Set
`ADMIN_PASSWORD` to choose your own; one you set is never written to disk.

A wrong username and a wrong password are answered identically. Repeated failures from
one address are refused with `429` and a `Retry-After`.

Signing out is a client-side act: a session is valid until `expires`, so there is
nothing to revoke. Changing `ADMIN_USER` or `ADMIN_PASSWORD` invalidates every
outstanding session immediately.

### `POST /api/auth/ticket`

```bash
curl -XPOST localhost:8080/api/auth/ticket -H "Authorization: Bearer $JWT"
# {"ticket":"eyJ…","expires_in":60}
```

`EventSource` cannot send headers, so the dashboard's stream authenticates with a
short-lived ticket in the query string instead: `GET /api/stream?ticket=…`.

A ticket is good for the stream and nothing else — it is rejected everywhere else, and
cannot mint another. A normal session works on `/api/stream` through the header, which
is how `curl -N` reads it.

### `GET /api/tokens` · `POST /api/tokens` · `DELETE /api/tokens/{id}`

```bash
curl -XPOST localhost:8080/api/tokens \
  -H 'content-type: application/json' \
  -d '{"name":"scraper-prod","scope":"proxy"}'
# {"id":"XkOC5l5K","name":"scraper-prod","scope":"proxy","source":"store",
#  "created_at":1785275812,"secret":"tp_7Kq2mXvR8nB4jL6wYtZaPc"}
```

`secret` appears in that one response and nowhere else: only its digest is stored, so a
lost token means minting another. Listing never returns it.

`DELETE` answers `204`, and the token stops working immediately — before the change
reaches disk, so a revoke cannot be undone by a restart. A token from `PROXY_TOKEN` is
configuration and answers `409`: change it in the environment and restart.

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

Plain text with a matching status. `404` unknown instance, session or token, `400` bad
input, `503` when nothing can serve the request.

`401` is a missing, malformed or expired credential, and always carries a
`WWW-Authenticate` header. `403` is a valid credential without the scope for that route,
and deliberately carries no challenge — there is nothing to retry with, so a client that
signs out on a `401` must not do so on a `403`.

An unmatched `/api/` path is authenticated first and only then `404`s, so the surface
does not report which endpoints exist. It never falls through to the dashboard.
