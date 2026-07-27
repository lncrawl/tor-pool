# Configuration

Every setting is an environment variable. [`.env.example`](../.env.example) is the
annotated list and [`internal/config/config.go`](../internal/config/config.go) holds the
defaults — this page explains *why* you would change something, not what the current
value is.

## Sizing the pool

`POOL_SIZE` is the number of independent exit identities. Each Tor instance costs
roughly 30–40 MB of RAM and a little CPU while bootstrapping.

More instances give more concurrent exits and more headroom when some are quarantined.
They do not make any single request faster. Size it to how many distinct identities you
need at once, plus slack for ones being remediated.

`MIN_READY` lets the pool serve before every instance has bootstrapped. Bootstrapping is
network-bound and mostly parallel, so a pool of ten is usable in about the time one
takes.

`SPAWN_STAGGER` spaces out the launches so N simultaneous consensus fetches do not
compete at boot.

## Sessions

`DEFAULT_SESSION` decides what happens when a caller sends no credentials:

- `ip` — pin per client IP. Plain `curl` is sticky. The default.
- `random` — a new instance per connection. Nothing is sticky; use it when you want
  spray-and-pray behaviour.
- `shared` — every anonymous caller shares one session and therefore one exit.

`SESSION_TTL` unpins an idle session. A session with a request in flight is never
considered idle, however old.

`MAX_SESSIONS` bounds the table. Session keys are untrusted input — a caller cycling
keys would otherwise grow it without limit.

## Health and remediation

Two thresholds, because they catch different failures:

- `QUARANTINE_CONSECUTIVE` catches a hard-dead instance fast.
- `QUARANTINE_FAILURES` within `FAILURE_WINDOW` catches an instance failing half its
  requests, which never accumulates consecutive failures but is just as unusable.

Tune both down for an aggressive target site, up if you see healthy instances being
quarantined for transient network noise.

`ESCALATION_WINDOW` is how long a remediation is remembered. Fail again inside it and
the ladder escalates; fail long after and it starts again at the cheapest rung.

`REMEDIATION_BACKOFF` and `MAX_REMEDIATION_BACKOFF` bound the delay on the last rung, so
a permanently broken instance stops consuming restarts.

## Circuit policy

`TOR_EXIT_NODES` and `TOR_EXCLUDE_EXIT_NODES` take Tor's own syntax, e.g. `{us},{ca}`.
Narrow policies shrink the usable relay set, which makes circuits slower to build and
exits less diverse. `TOR_STRICT_NODES` makes the policy mandatory rather than a
preference — with a narrow list that can leave an instance unable to build a circuit at
all.

`TOR_MAX_CIRCUIT_DIRTINESS` is how long a circuit is reused, and therefore how long an
exit IP stays put. It defaults to far longer than Tor's own ten minutes, because Tor's
default would change the exit under a caller that never asked to rotate. The cost is
linkability: more requests share one observable identity. That is the point here and the
opposite of what a privacy-focused client wants.

`TOR_EXTRA_CONFIG` is appended verbatim to every instance's torrc, for anything not
modelled above.

## Ports

`SOCKS_PORT`, `HTTP_PORT` and `API_PORT` are the published listeners; setting
`HTTP_PORT` to empty disables the HTTP proxy.

`INSTANCE_PORT_BASE` is where the per-instance Tor ports live. They stay on container
loopback and are never published. The pool validates at boot that this range cannot
overlap a listener and refuses to start if it does — a Tor child binding over a listener
would otherwise look like a network fault.

## Observability

`HISTORY_RESOLUTION` and `HISTORY_WINDOW` size the in-memory time series behind the
dashboard charts. Everything is in memory and resets when the container restarts.

`LOG_LEVEL` at `debug` includes Tor's own notice-level lines, which is what you want
when an instance will not bootstrap.
