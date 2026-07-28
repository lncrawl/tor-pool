# Changelog

All notable changes are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Images are published to `ghcr.io/lncrawl/tor-pool` on every push to `main`; see the
[releasing notes](.claude/skills/releasing/SKILL.md) for what each tag means.

## [Unreleased]

### Fixed

- **Rotation no longer drops requests in flight.** Retiring an instance's circuits spared
  only the ones carrying a *connected* stream, so a request still waiting for its exit to
  reach the destination had its circuit closed underneath it. Measured at 4–5% of requests
  failing while rotating under load, against 0% at rest. Any circuit with a stream on it is
  now left standing, whatever state that stream is in.
- **A rotation no longer quarantines the instance it rotated.** The failures a rotation
  causes were scored against the instance, so a few rotations were enough to quarantine a
  healthy one — whose remediation rotated it again. Failures inside an instance's own
  rotation window are no longer counted against it.
- **`POST /api/pool/rotate` keeps the pool serving.** It rotated every instance at once,
  leaving nothing to route to for a second or two. It now sweeps one instance at a time and
  returns immediately, reporting whether a sweep was already running.
- **The reported exit IP no longer jumps after a rotation.** Tor holds several
  exit-bearing circuits and builds more preemptively, and the API named whichever looked
  newest — an exit no traffic had used. Only a circuit carrying a stream now confirms an
  exit, an inferred one can never displace a confirmed one, and `exit_confirmed` says which
  it is.
- **A session is no longer routed to an instance that is mid-rotation.** Diverting covered
  the sessions pinned when the rotation began, but not the ones arriving during it.
- **A stalled bootstrap is now remediated.** Tor can wedge part-way through with a live
  process, which neither the supervisor nor the failure ladder catches, leaving the pool
  quietly under strength — instances were observed sitting at 45% indefinitely. See
  `BOOTSTRAP_STALL_TIMEOUT`.
- **The maintenance loop cannot be stalled by a control port.** The exit poll shared a loop
  with session sweeping and process supervision, and one instance's NEWNYM cooldown blocked
  all three for up to ten seconds — a pool-wide rotation, for tens of seconds. Control
  commands also had no I/O deadline, so a Tor that stopped answering wedged it forever.
- **HTTP proxy: keep-alive requests are routed individually.** A client sending requests
  for several hosts down one proxy connection had the second delivered to the first host.
  Each request is now routed and dialled on its own, which also means a rotation takes
  effect on the next plain request rather than when the client happens to reconnect.
- **HTTP proxy: IPv6 destinations work.** A bracketed literal was passed to Tor as a
  hostname to resolve.
- A control connection lost while Tor keeps running is redialled, instead of leaving an
  instance that serves traffic but can never be rotated or report its exit again.
- Rotating an instance that has not bootstrapped is refused with 409 rather than spending
  the NEWNYM cooldown on a Tor with no circuits — which silently swallowed the rotation
  asked for once it was ready.
- Rotating a session that lands back on its own instance (a one-instance pool, or one
  instance routable) now rotates that instance's circuit, instead of reporting success
  while changing nothing.
- Instance indexes are reused instead of counted upwards, so enough resizes can no longer
  hand an instance a SOCKS port that is another instance's control port.
- Remediation backoff grows with the attempts at the current rung, not with the instance's
  lifetime count — an instance that misbehaved last week no longer starts at maximum
  backoff.
- Retired instances no longer leave their per-instance counters behind, a resize honours
  `SPAWN_STAGGER`, `POST /api/instances/{id}/drain` answers 404 for an instance that does
  not exist, and `?newnym=1` is accepted alongside `?newnym=true`.
- Fixed data races on an instance's process handle during a restart, and on the NEWNYM
  cooldown timestamp.

### Changed

- **Conflux is off by default** (`TOR_CONFLUX`). Each set Tor pre-builds has its own exit
  relay and successive requests land on different sets, so one instance handed a caller
  several exit IPs with no rotation at all.
- **`POST /api/instances/{id}/rotate` returns as soon as the instance is out of service**,
  finishing Tor's cooldown in the background, instead of holding the request open for up to
  ~13 seconds.

### Added

- **`PIN_EXIT_RELAY`** locks each instance to a single exit relay, so one instance really
  is one exit IP until it rotates. Off by default: a pinned instance depends on one relay.
- **`BOOTSTRAP_STALL_TIMEOUT`** restarts an instance that stops making bootstrap progress,
  keeping its state on the first attempt and wiping it on the next.
- `exit_confirmed` and `pinned_exit` on the instance API, surfaced in the dashboard: an
  exit no traffic has used yet is shown as the guess it is.

- Initial release. A pool of Tor instances in one container, behind a single sticky
  SOCKS5 and HTTP proxy endpoint.
- **Sticky sessions.** The SOCKS5 username (or `Proxy-Authorization` user) is a session
  key; a caller keeps the same instance, and so the same exit IP, until it rotates.
  Callers with no credentials are pinned by client IP.
- **Instant rotation.** `POST /api/sessions/{key}/rotate` reassigns a session to an
  already-built instance, skipping Tor's ~10s NEWNYM cooldown.
- **Failure-driven remediation.** Failures are counted per instance from transport
  errors and from client reports, and a bad instance escalates through new circuit →
  wipe-restart → restart with exponential backoff.
- **Management dashboard** with live updates over SSE: instance grid with per-instance
  actions, sessions view, filterable audit log, and timeline charts.
- **REST API** for instances, sessions, events and history, plus live pool resize.
- Prometheus metrics at `/metrics`, and a `/health` check that reports routability
  rather than process health.
- Multi-arch images (`linux/amd64`, `linux/arm64`), rebuilt weekly so a new Alpine
  `tor` release reaches users without a code change.
