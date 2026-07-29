# AGENTS.md

Guidance for AI agents working in this repository. `CLAUDE.md` points here; keep guidance in
this file only so the two can never drift.

## What this is

**tor-pool** runs a pool of `tor` instances in one container behind a single sticky proxy
endpoint, a REST API and a dashboard. One Go binary running as PID 1: it forks the tor
children, load-balances over them, tracks their health and remediates the bad ones.

The design goal that shapes everything: **a caller stays pinned to one instance until it asks
to rotate.** Many callers may share an instance; one that fails repeatedly is quarantined and
its callers move elsewhere.

Primary consumer: [lncrawl/scraper](https://github.com/lncrawl/scraper).
[lncrawl/tor-proxy](https://github.com/lncrawl/tor-proxy) is the single-instance image this
grew out of — a separate, still-supported project, not something this replaces. Do not copy
changes between them.

## Commands

```bash
gofmt -l . && go vet ./... && go test ./...   # the gate; gofmt must print nothing
docker run --rm -v "$PWD":/app -w /app golangci/golangci-lint golangci-lint run
docker compose up -d --build && docker compose logs -f
```

**There is no supported way to run this outside Docker.** `tor` is not expected on the host,
so every runtime change is verified by rebuilding the container; `go test` covers pure logic
only. Before considering a change done: the gate, golangci-lint, and a container run that
exercises whatever you touched. See [docs/development.md](docs/development.md).

## Layout

```
cmd/torpool/       entrypoint: env → wire → run → graceful shutdown
internal/auth/     credential store (one JSON file), hand-written HS256, tokens, scopes
internal/config/   env parsing, defaults, validation. The one source of truth for defaults.
internal/tor/      torrc rendering, the control-port client, tor process supervision
internal/pool/     instance state machine, session table, assignment, remediation ladder
internal/proxy/    SOCKS5 and HTTP proxy listeners, byte relay with accounting
internal/stats/    rolling time-series rings, Prometheus exposition
internal/server/   REST API, SSE stream, embedded dashboard assets
web/               dashboard (Vite + React + AntD + Recharts)
docker/            Dockerfile (node build → go build → alpine + tor)
docs/              configuration, api, architecture, operations, scraper, development
```

## Conventions

- **Errors**: wrap with `fmt.Errorf("doing x: %w", err)`; compare with `errors.Is`/`errors.As`,
  never string matching. Validation collects *all* problems with `errors.Join`, so a
  misconfigured container fails once with a complete message.
- **Logging**: `log/slog` with key/value attributes, never formatted prose. An instance is
  always identified by the attribute `instance`.
- **Comments** explain *why*, never *what*. A comment earns its place by recording a
  constraint, a protocol quirk, or a decision the code cannot state itself.
- **Concurrency**: hold a mutex for as short a span as possible, never across a network call
  or a subprocess wait. Every goroutine takes a `context.Context` and exits on cancel.
- **No third-party dependency without a reason.** The standard library covers the SOCKS5 and
  HTTP proxy paths, the Prometheus exposition and the HS256 tokens, and that is why the image
  is small. Hand-written crypto earns its place only because it is one algorithm this process
  both issues and verifies — read the rules in `internal/auth/jwt.go` first, and keep its
  negative tests.
- **Docs must not restate tuning numbers.** Name the constant or file that holds the value
  (`internal/config`) rather than copying it into prose that will rot.
- **Markdown links stay repo-relative.** `docs/` and the README are also published as a site
  (`docs.yml`, see `docs/development.md`); staging rewrites the links, and a build with
  `strict: true` fails the PR if one resolves nowhere.

## Invariants

These break subtly and silently. Violating one produces a container that looks healthy and
isn't.

1. **Listeners bind `0.0.0.0` inside the container.** A container-loopback bind is unreachable
   through a docker port mapping. Exposure is restricted by the *host-side publish*, never by
   the in-container bind address.
2. **Instance SOCKS and control ports are container-loopback and never published.** That is
   what makes cookie authentication with no password safe; publishing one hands anyone on the
   network unauthenticated `SIGNAL`/`SETCONF` over a tor process.
3. **A wipe-restart waits for the tor process to actually exit before deleting its
   `DataDirectory`.** Deleting under a live process leaves the respawn inheriting half-removed
   state, and it fails to bootstrap in ways that look like network problems.
4. **A proxy connection is pinned to its instance for its entire life.** Rotation affects only
   *new* connections, so clients holding keep-alives must drop their pooled connections after
   rotating or they keep exiting through the old instance. This is the most common integration
   bug, and why `scraper` resets its adapters after `rotate()`.
5. **`NEWNYM` has a tor-enforced cooldown and tor will not tell you how much is left.** A
   signal sent inside it answers `250 OK` and is silently coalesced, so rotation appears to
   work while the exit IP never changes. The cooldown is tracked client-side from the last
   `NEWNYM` *this connection* sent — hence one long-lived control connection per instance
   rather than dialling per command. Use `Control.Newnym`, which waits it out. **`NEWNYM` also
   retires nothing by itself**: old circuits stay standing and traffic has been seen still
   leaving through them, so a rotation closes them (`CloseRetiredCircuits`). Drop that and
   rotation silently stops taking effect.
6. **A circuit with *any* stream on it is carrying a request.** Not just `SUCCEEDED` — a
   stream in `SENTCONNECT` or `RESOLVE_WAIT` holds a circuit while it waits on the exit, for
   as long as the destination takes. Closing it fails the request: measured at 4–5% of traffic
   during rotation. "Where is the instance going out" and "which circuits are busy" are
   different questions over the same payload; see the `tor-control` skill.
7. **A rotation must not be blamed for the failures it causes.** Rotating destroys the circuits
   in-flight requests were using, so those requests fail. Scoring them against the instance
   quarantined healthy ones, whose remediation rotated them again. `Pool.RecordFailure` drops
   failures inside an instance's rotation window plus a grace period.
8. **Rotate one instance at a time.** Signalling everything at once leaves nothing with
   circuits for a second or two — the one state a pool exists to prevent.
9. **One instance is not one exit IP by default.** Tor holds several exit-bearing circuits and
   picks per stream, so a pinned caller's IP changes with no rotation at all. `ConfluxEnabled
   0` removes most of that and `PIN_EXIT_RELAY` the rest, at the cost of depending on one
   relay. Anything reported without a stream attached is a *guess*: keep the `confirmed`
   distinction, and never let a guess overwrite a confirmed exit.
10. **Tor can stall part-way through bootstrap with a healthy process.** Nothing else catches
    it — the supervisor sees a live process, and an instance taking no traffic reports no
    failures — so the pool silently runs under strength. `BOOTSTRAP_STALL_TIMEOUT` restarts on
    *lack of progress*, never elapsed time, because a slow consensus fetch is not a stall.
11. **Session keys are untrusted input**, arriving as a SOCKS5 username or a
    `Proxy-Authorization` header. Authentication narrows *who* can send one; it does not make
    them trusted, and a key is still not a tenancy boundary — any valid token may claim any
    key. Bound the table (`MAX_SESSIONS`), and never interpolate a key into a log message, a
    torrc or a shell command without escaping it.
12. **Instance port blocks must not collide with the listeners.** `internal/config` validates
    this at boot; add any new listener to that check. An instance index maps to a fixed pair of
    ports in two blocks a fixed distance apart, so indexes are *reused* rather than counted
    upwards — a counter eventually hands out a SOCKS port that is another instance's control
    port.
13. **Pool size is dynamic.** Instances are created and retired at runtime, so never cache a
    slice of instances or index into one across an await point. Ask the pool.
14. **Nothing on a request path may block on a control port.** A command can take as long as
    the `NEWNYM` cooldown, so the exit poll lives on its own goroutine, pollers give up rather
    than queue, and an instance rotation returns once the instance is out of service and
    finishes the slow half in the background. Credentials follow the same rule: verification
    reads an immutable map behind an `atomic.Pointer` and never takes the store's mutex, which
    sits behind an fsync.
15. **Authentication is default-closed, and the route table is what makes it so.** Endpoints
    are data in `internal/server`, each naming a scope, and a test walks that table asserting
    every route either sits in an explicit public allowlist or answers 401. Registering
    handlers one at a time is default-*open*: the failure is an endpoint added later with no
    scope, which nothing catches. `http.ServeMux` does not expose its patterns, so the table
    has to be data for that test to exist. Only `/health`, `/metrics`, the login and status
    endpoints and the dashboard's static assets are public.
16. **`AUTH_DISABLED` is not a second code path.** The route table still declares every scope
    and the guard still runs; `internal/auth` stops refusing, one branch at the top of each
    `Verify*`. An "if disabled, skip the middleware" shortcut lets the open path drift out of
    step with the closed one, and the closed one is what is tested. The listeners are the
    exception: they challenge *before* they verify, so `internal/proxy` reads the flag itself —
    a check that merely always returned nil would still refuse a SOCKS5 client for offering no
    authentication method, and still answer 407 to a request with no header. Either way a
    caller that *does* send a credential keeps having its username read as the session key;
    dropping that collapses everyone onto `DEFAULT_SESSION` and reads as a routing bug. The
    dashboard asks `/api/auth/status` and must gate the stream on "nothing to connect with",
    not on "no token" — that mistake leaves a reachable pool showing a permanent
    "reconnecting".
17. **The credential is a header, never a cookie.** That is the only reason no CSRF defence
    exists in `internal/server` and none is needed — every mutating endpoint becomes
    cross-site triggerable the day someone adds a "remember me" cookie. It is also no
    substitute for TLS: nothing here encrypts, so the loopback-publishing guidance in the
    README and `compose.yml` stays.
18. **A refused credential is logged, never recorded as an event.** The event ring is bounded,
    so one entry per rejected proxy connection lets anyone flush the audit history in seconds,
    precisely when it matters — and every rejection would serialise through the mutex the
    dashboard streams through. Only operator actions are events.
19. **A generated credential is alphanumeric, drawn by rejection sampling.** base62, not
    base64url: `-` and `_` are legal in URL userinfo but survive a terminal line-break, a
    double-click selection and a YAML round trip only by luck, and a mangled token presents as
    a refused credential with no hint the string changed in transit. `randomBase62` discards
    out-of-range bytes rather than folding them with `%`, which would skew the front of the
    alphabet — small, and still a bias in the bits of a credential. The length still clears the
    128 bits `hashSecret` assumes for a plain unsalted SHA-256.
20. **A failure report is weighed by its kind, and a rate limit is not evidence about the
    exit.** A 429 follows the traffic, not the IP: rotating away spends a working exit and
    lands on the next one still throttled, so `KindRateLimited` stays out of the two paths that
    act on a single report — the consecutive count, and the failure that re-quarantines a
    probationary instance. A captcha is the opposite and quarantines in two. Weights sit around
    a baseline, which is what lets `QUARANTINE_FAILURES` keep meaning that many *untyped*
    failures: change `baselineWeight` and you silently retune every deployment that never
    sends a `kind`. The endpoint must keep accepting a bodyless `POST` and unrecognised text —
    both `KindOther` — because refusing a malformed report throws away the only signal that
    sees inside an HTTPS tunnel.
21. **Every promise about the weights must hold at every `QUARANTINE_FAILURES`, not just the
    default.** A weight is capped so no single report can cross the threshold alone: without
    that, the captcha weight *is* the whole threshold once the setting reaches 3 — and
    `operations.md` tells operators to lower it, so one caller misreading one page would retire
    an instance. `QUARANTINE_FAILURES=1` is the exception, being an operator asking for exactly
    one report. Test across a sweep of thresholds; a single-policy test sees none of this.
    Separately, `QUARANTINE_CONSECUTIVE` is blind to kind and caps every exit-blaming report,
    so weighing only decides the outcome for a caller that succeeds between failures — never
    describe a weight as *the* threshold.

## Skills

Read these before working in their area:

| Skill | Use when |
| --- | --- |
| `.claude/skills/tor-control/` | Anything touching the control port: authentication, `GETINFO`, `SIGNAL`, `SETCONF`, exit-IP resolution |
| `.claude/skills/releasing/` | Cutting a release, editing the publish workflow, or debugging a GHCR push |

The globally available `dataviz` skill applies to any chart work in `web/`.

## Commits

- **Imperative subject, no type prefix.** `Add sticky session routing`, not
  `feat: add sticky session routing`.
- Body bullets for anything non-trivial: what changed and why, not a file list.
- **Never append a `Co-Authored-By` trailer** or any other AI attribution.
- Do not commit or push unless the user asked for it in that moment.

## Releases

**Publishing an image and cutting a release are separate events.** A push to `main` publishes
`ghcr.io/lncrawl/tor-pool:edge`; a release is a `vX.Y.Z` tag (or a `release.yml` dispatch) and
is the only thing that moves `latest`. The version lives in `CHANGELOG.md` and nowhere else —
the release refuses to run without a section for it. A weekly rebuild refreshes the moving tags
against the current Alpine `tor`, never the exact `X.Y.Z`. GHCR is the only registry. See the
`releasing` skill.
