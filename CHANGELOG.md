# Changelog

All notable changes are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Images are published to `ghcr.io/lncrawl/tor-pool` on every push to `main`; see the
[releasing notes](.claude/skills/releasing/SKILL.md) for what each tag means.

## [Unreleased]

### Added

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
