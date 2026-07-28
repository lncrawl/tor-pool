# AGENTS.md

Guidance for AI agents working in this repository. `CLAUDE.md` points here; keep guidance in
this file only so the two can never drift.

## What this is

**tor-pool** runs a pool of `tor` instances inside one container and fronts them with a single
sticky proxy endpoint, a REST API and a dashboard. It is a single Go binary that acts as PID 1:
it forks the tor children, load-balances over them, tracks their health, and remediates the bad
ones.

The design goal that shapes everything: **a caller stays pinned to one instance until it asks to
rotate.** Many callers may share an instance. When an instance fails repeatedly it is
quarantined and its callers move elsewhere.

The primary consumer is [lncrawl/scraper](https://github.com/lncrawl/scraper).

Related: [lncrawl/tor-proxy](https://github.com/lncrawl/tor-proxy) is the single-instance image
this grew out of. It is a separate, still-supported project — do not treat this repo as its
replacement, and do not copy changes between them.

## Commands

```bash
go build ./...                # compile
go test ./...                 # unit tests
gofmt -l .                    # must print nothing
go vet ./...

# golangci-lint via its official image — nothing to install on the host
docker run --rm -v "$PWD":/app -w /app golangci/golangci-lint golangci-lint run

docker compose up -d --build  # the only way to actually run it (see below)
docker compose logs -f
```

**There is no supported way to run this outside Docker.** `tor` is not expected on the host, so
every runtime change is verified by rebuilding the container. Treat `docker compose up -d
--build` plus a `curl` through the proxy as the real test suite; `go test` only covers pure
logic. See [docs/development.md](docs/development.md).

Run the full gate before considering a change done: `gofmt -l . && go vet ./... && go test ./...`
plus golangci-lint, plus a container run that exercises whatever you touched.

## Layout

```
cmd/torpool/       entrypoint: env → wire → run → graceful shutdown
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

- **Errors**: wrap with `fmt.Errorf("doing x: %w", err)`. Compare with `errors.Is`/`errors.As`,
  never string matching. Validation collects *all* problems with `errors.Join` and reports them
  together — a misconfigured container should fail once with a complete message.
- **Logging**: `log/slog` with key/value attributes, never formatted prose. An instance is
  always identified by the attribute `instance`.
- **Comments** explain *why*, never *what*. Do not narrate code. A comment earns its place by
  recording a constraint, a protocol quirk, or a decision that the code cannot state itself.
- **Concurrency**: guard shared state with a mutex held for as short a span as possible, and
  never hold a lock across a network call or a subprocess wait. Every goroutine takes a
  `context.Context` and exits when it is cancelled.
- **No third-party dependency without a reason.** The standard library covers the SOCKS5 and
  HTTP proxy paths; keeping the module lean is why the image is small.
- **Docs must not restate tuning numbers.** Name the constant or the file that holds the value
  (`internal/config`) instead of copying it into prose that will rot.

## Invariants

These break subtly and silently. Violating one produces a container that looks healthy and
isn't.

1. **Listeners bind `0.0.0.0` inside the container.** A container-loopback bind is unreachable
   through a docker port mapping. Exposure is restricted by the *host-side publish* (compose
   publishes the API as `127.0.0.1:8080:8080`), never by the in-container bind address.
2. **Instance SOCKS and control ports are container-loopback and never published.** That is
   precisely what makes cookie authentication with no password safe. Publishing one would hand
   anyone on the network unauthenticated `SIGNAL`/`SETCONF` control over a tor process.
3. **A wipe-restart must wait for the tor process to actually exit before deleting its
   `DataDirectory`.** Deleting under a live process leaves the respawn inheriting half-removed
   state and it will fail to bootstrap in ways that look like network problems.
4. **A proxy connection is pinned to its instance for its entire life.** Rotation only affects
   *new* connections. Clients holding keep-alives must drop their pooled connections after
   rotating or they keep exiting through the old instance — this is the single most common
   integration bug, and it is why `scraper` resets its adapters after `rotate()`.
5. **`NEWNYM` has a tor-enforced cooldown and tor will not tell you how much is left.** A signal
   sent inside the cooldown answers `250 OK` and is then silently coalesced, so rotation appears
   to work while the exit IP never changes. The cooldown is therefore tracked client-side, from
   the last `NEWNYM` *this connection* sent — which is why the pool keeps one long-lived control
   connection per instance instead of dialling per command. Use `Control.Newnym`, which waits it
   out, rather than `Signal("NEWNYM")` directly. **`NEWNYM` also does not retire anything by
   itself** — the old circuits stay standing and usable enough that traffic has been seen still
   leaving through them, so a rotation closes them (`CloseRetiredCircuits`). Drop that and
   rotation silently stops taking effect on the next request.
6. **A circuit with *any* stream on it is carrying a request.** Not just `SUCCEEDED`: a stream in
   `SENTCONNECT` or `RESOLVE_WAIT` has been given a circuit and is waiting on the exit, for as
   long as the destination takes to answer. Closing it fails the request — measured at 4-5% of
   traffic during rotation. "Where is the instance going out" and "which circuits are busy" are
   different questions over the same payload; see the `tor-control` skill.
7. **A rotation must not be blamed for the failures it causes.** Rotating destroys the circuits
   in-flight requests were using, so those requests fail. Scoring them against the instance
   quarantined healthy ones, whose remediation rotated them again. `Pool.RecordFailure` drops
   failures inside an instance's rotation window plus a grace period.
8. **Rotate one instance at a time.** A pool-wide rotation that signals everything at once leaves
   nothing with circuits for a second or two, which is the one state a pool exists to prevent.
9. **One instance is not one exit IP by default.** Tor holds several exit-bearing circuits and
   picks between them per stream, so a pinned caller's IP changes with no rotation at all —
   `ConfluxEnabled 0` removes most of that, and `PIN_EXIT_RELAY` removes the rest at the cost of
   depending on one relay. Anything reported without a stream attached is a *guess*: keep the
   `confirmed` distinction, and never let a guess overwrite a confirmed exit.
10. **Tor can stall part-way through bootstrap with a healthy process.** Nothing else catches it —
    the supervisor sees a live process and an instance taking no traffic records no failures — so
    the pool silently runs under strength. `BOOTSTRAP_STALL_TIMEOUT` restarts on *lack of
    progress*, never on elapsed time, because a slow consensus fetch is not a stall.
11. **Session keys are untrusted input.** They arrive as a SOCKS5 username or a
    `Proxy-Authorization` header from whoever can reach the proxy port. Bound the session table
    (`MAX_SESSIONS`), and never interpolate a key into a log message, a torrc, or a shell command
    without escaping it.
12. **The instance port blocks must not collide with the listeners.** `internal/config`
    validates this at boot; if you add a listener, add it to that check too. An instance index
    maps to a fixed pair of ports in two blocks a fixed distance apart, so indexes are *reused*
    rather than counted upwards — a counter eventually hands out a SOCKS port that is another
    instance's control port.
13. **Pool size is dynamic.** Instances are created and retired at runtime, so never cache a
    slice of instances or index into one across an await point. Ask the pool.
14. **Nothing on a request path may block on a control port.** A command can take as long as the
    NEWNYM cooldown, so the pool's maintenance loop keeps the exit poll on its own goroutine,
    pollers give up rather than queue, and an instance rotation returns once the instance is out
    of service and finishes the slow half in the background.

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

Pushing to `main` bumps a patch tag, which builds and publishes
`ghcr.io/lncrawl/tor-pool`. GHCR is the only registry. See the `releasing` skill.
