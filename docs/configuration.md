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
compete at boot, or on a runtime resize.

`BOOTSTRAP_STALL_TIMEOUT` restarts an instance that has stopped making progress towards
being usable. Tor can wedge part-way through bootstrap with a perfectly healthy process,
and nothing else catches it: the supervisor sees a running Tor, and an instance that takes
no traffic never records a failure for the ladder to act on — so the pool quietly runs
under strength. The first restart keeps the state directory; a second wipes it, because a
poisoned cached consensus is the usual cause. Set it to `0` to disable the check.

## Authentication

`ADMIN_USER` and `ADMIN_PASSWORD` are the dashboard login. Leaving the password unset is
a real option rather than an insecure one: the first boot generates a 128-bit password,
prints it once, and stores only its digest — which is safe precisely because a random
password of that size is not a dictionary target. A password you supply is compared in
memory and never written anywhere, so nothing on disk can be attacked offline. The
trade-off is that a generated one only survives while `DATA_DIR` does.

Changing either variable invalidates every dashboard session immediately, which is what
you want after a credential is exposed and is why there is no separate "sign out
everywhere".

`LOGIN_TTL` is how long a session lasts; there is no refresh, so it is the whole
lifetime. Longer is more convenient and leaves a stolen credential usable for longer.

`LOGIN_RATE_LIMIT` bounds wrong passwords per minute from one address. Behind a reverse
proxy every caller shares the proxy's address, so the limit becomes global — set it
higher there, or accept that one attacker can lock out the operator.

`PROXY_TOKEN` fixes a proxy credential in configuration, for deployments provisioned from
files rather than by hand. It is verified like any minted token but never persisted,
because the environment is authoritative: seeding it into the store would leave a stale
value working after the variable changed. Everything else is minted in the dashboard,
where a token can also be revoked individually — which is the reason tokens exist rather
than one shared secret.

## Sessions

`DEFAULT_SESSION` decides what happens when an authenticated caller names no session:

- `ip` — pin per client IP. Plain `curl` is sticky. The default.
- `random` — a new instance per connection. Nothing is sticky; use it when you want
  spray-and-pray behaviour.
- `shared` — every anonymous caller shares one session and therefore one exit.

`SESSION_TTL` unpins an idle session. A session with a request in flight is never
considered idle, however old.

`MAX_SESSIONS` bounds the table. Session keys are untrusted input — a caller cycling
keys would otherwise grow it without limit.

`DRAIN_ON_ROTATE` moves an instance's sessions onto other instances when that instance is
rotated, which is on by default: rotating is a statement that the exit is spent, and its
callers would otherwise sit on the one instance that has just discarded its circuits.
Turn it off when a session's stickiness matters more than its exit — a login the target
site has tied to one IP, say. Either way, connections already in flight keep the instance
they were dialled through; only the next one moves.

Independently of this setting, a *new* session is never pinned to an instance that is
mid-rotation unless there is nothing else to pin it to — the sequence is mark, divert,
then rotate, so requests arriving during a rotation are not handed an instance without
circuits.

## Health and remediation

Two thresholds, because they catch different failures:

- `QUARANTINE_CONSECUTIVE` catches a hard-dead instance fast. It is blind to what the
  failures were, so it caps every report that blames the exit — a caller failing with no
  success in between hits this one first, whatever it reports.
- `QUARANTINE_FAILURES` within `FAILURE_WINDOW` catches an instance failing half its
  requests, which never accumulates consecutive failures but is just as unusable. It
  counts *unclassified* failures: a typed report weighs more or less than one, so a
  captcha spends several of them and a rate limit less than one. No single report can
  cross the threshold on its own unless you set this to `1`. See
  [architecture.md](architecture.md#failure-accounting) for the weights.

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

`TOR_CONFLUX` turns Tor's multipath circuits back on. It is off by default, unlike in Tor
itself, because circuit lifetime is only half of what makes an exit IP stable: Tor holds
several exit-bearing circuits at once and picks between them per stream, and each conflux
set it pre-builds is another distinct exit relay in that pool. With it on, one instance was
observed handing a caller two exit IPs inside a minute with no rotation at all.

`PIN_EXIT_RELAY` goes the whole way: once an instance has an exit, the pool locks Tor to
that relay and closes the standing circuits that leave through a different one, so *one
instance is one exit IP* until it is rotated. A rotation releases the pin, excludes the
relay it just left, and locks the replacement Tor chooses.

It is off by default because it is a real trade. A pinned instance depends on one relay:
if that relay is slow, or rejects the destination port, every request on the instance
suffers until the failure ladder rotates it. Turn it on when a stable exit identity per
instance matters more than that — a session the target site has tied to one IP — and leave
it off when you would rather have Tor spread the load itself.

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
