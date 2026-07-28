<div align="center">

# tor-pool

**A pool of Tor exits behind one sticky endpoint — that heals itself when an exit gets blocked.**

[![CI](https://github.com/lncrawl/tor-pool/actions/workflows/ci.yml/badge.svg)](https://github.com/lncrawl/tor-pool/actions/workflows/ci.yml)
[![Publish](https://github.com/lncrawl/tor-pool/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/lncrawl/tor-pool/actions/workflows/docker-publish.yml)
[![CodeQL](https://github.com/lncrawl/tor-pool/actions/workflows/codeql.yml/badge.svg)](https://github.com/lncrawl/tor-pool/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/lncrawl/tor-pool)](LICENSE)

</div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/overview-dark.png">
  <img alt="The tor-pool dashboard" src="docs/images/overview-light.png">
</picture>

One container runs N Tor instances. Your client connects to **one** SOCKS5 or HTTP port
and stays on the same exit IP until it asks to move. When an exit starts failing, the
pool takes it out of rotation, moves its callers elsewhere, and works it back into
service.

- **Sticky by session** — the SOCKS5 username is a session key. Same key, same exit IP.
  Different keys, different exits. Many callers can deliberately share one key.
- **Rotation without the wait** — Tor enforces a ~10 second cooldown between circuit
  changes. Rotating a *session* reassigns it to an instance that has already built its
  circuits, so it takes milliseconds.
- **Self-healing** — failures are counted per instance from two sides, and a bad one
  escalates through new circuit → wipe-and-restart → restart with backoff.
- **Live dashboard** — see every instance's exit IP, state and traffic; rotate, drain,
  quarantine, restart, and resize the pool while it runs.
- **One binary, no dependencies** — Go standard library only, dashboard embedded,
  ~40 MB image.

> [!WARNING]
> The API has **no authentication** and can restart instances and resize the pool.
> Publish port 8080 to `127.0.0.1` only, as the compose file does.

## Quick start

```bash
docker run -d --name tor-pool \
  -e POOL_SIZE=5 \
  -p 127.0.0.1:9250:9250 \
  -p 127.0.0.1:9251:9251 \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/lncrawl/tor-pool:latest
```

Or with compose — copy [`.env.example`](.env.example) to `.env` and run
`docker compose up -d`.

The pool serves as soon as its first instance finishes bootstrapping, usually within
30 seconds. Then prove it works — same username twice, then a different one:

```bash
curl --socks5-hostname alice:x@127.0.0.1:9250 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"185.220.101.5"}
curl --socks5-hostname alice:x@127.0.0.1:9250 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"185.220.101.5"}   ← same session, same exit

curl --socks5-hostname bob:x@127.0.0.1:9250 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"192.42.116.19"}   ← different session, different exit

curl -XPOST localhost:8080/api/sessions/alice/rotate
curl --socks5-hostname alice:x@127.0.0.1:9250 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"94.142.244.16"}   ← alice moved, instantly
```

Then open <http://localhost:8080>.

> [!NOTE]
> Pulling from GHCR needs no login for a public package. If you get a 403, the package
> is still private — see the [releasing](.claude/skills/releasing/SKILL.md) notes.

## Is this the right tool?

tor-pool makes one bet: **an exit IP is part of a caller's identity**, so it should stay
put until that caller asks to move, and the pool should find out when one gets burnt.
That is worth the moving parts when:

- **A session has to keep its exit** — a login, a cart, a paginated crawl; anything
  where the IP changing mid-flow gets you challenged or logged out.
- **You need to move on demand, not on a timer** — and not pay Tor's ~10 second NEWNYM
  cooldown when you do.
- **Blocks are invisible to the proxy** — a 403, a 429 or a captcha arrives inside TLS,
  so only your client can see it, and something has to act on what it reports.
- **You want to watch the pool** — which exit each instance holds, what is failing, and
  resize it without a restart.

If none of that applies — any exit will do, and you just want requests spread across
several — then round-robin over N Tor containers is less code and fewer failure modes,
and you should do that instead. tor-pool also only runs in Docker, and it manages a pool
of Tor instances rather than trying to harden Tor itself.

## How it works

```mermaid
flowchart LR
  A["scraper<br/>user = alice"] -->|SOCKS5 :9250| B
  C["curl<br/>user = bob"] -->|HTTP :9251| B
  B{{"torpool<br/>session → instance"}}
  B --> D["tor 0"]
  B --> E["tor 1"]
  B --> F["tor N"]
  D --> G((Tor network))
  E --> G
  F --> G
  H["dashboard + API<br/>:8080"] -.->|rotate · drain<br/>quarantine · resize| B
```

**Sticky sessions.** The SOCKS5 username, or the `Proxy-Authorization` user over HTTP,
identifies a session. A caller with no credentials is pinned by client IP
(`DEFAULT_SESSION`), so plain `curl` is sticky too. Credentials are *not* forwarded to
Tor: doing so would trigger Tor's own stream isolation and give two callers on the same
instance different exits, which would make "an instance is an exit identity" untrue.

**Failure signals.** Two, because neither is enough alone. The pool sees transport
failures itself — refused handshakes, resets, timeouts — but it relays opaque bytes, so
a 403, a 429 or a captcha is invisible to it. Those come from the client via
`POST /api/sessions/{key}/failure`.

**The remediation ladder.** Enough failures and an instance is quarantined and its
sessions moved. Then:

```mermaid
stateDiagram-v2
  [*] --> healthy
  healthy --> degraded: failures accruing
  degraded --> quarantined: threshold hit
  quarantined --> remediating
  remediating --> probation: new circuit, then wipe-restart,<br/>then restart with backoff
  probation --> healthy: survives a request
  probation --> quarantined: fails once — the fix did not work
```

Escalation is driven by *recurrence*, not attempt count: an instance that misbehaved
once last week starts again at the cheapest rung.

## Configuration

Everything is an environment variable. The common ones:

| Variable | Default | What it does |
| --- | --- | --- |
| `POOL_SIZE` | 5 | Tor instances to run. ~30–40 MB each. |
| `MIN_READY` | 1 | Serve once this many have bootstrapped. |
| `DEFAULT_SESSION` | `ip` | How a caller with no credentials is pinned: `ip`, `random`, `shared`. |
| `SESSION_TTL` | 10m | Unpin a session after this long idle. |
| `QUARANTINE_FAILURES` | 5 | Failures within `FAILURE_WINDOW` before quarantine. |
| `TOR_EXIT_NODES` | — | Restrict exits, e.g. `{us},{ca}`. |

<details>
<summary>Everything else</summary>

See [`.env.example`](.env.example) for the annotated list, and
[`internal/config/config.go`](internal/config/config.go) for the defaults themselves —
that file is the source of truth, not this table.

Worth knowing: `TOR_MAX_CIRCUIT_DIRTINESS` defaults to an hour rather than Tor's ten
minutes. Tor's default would rotate the exit out from under a session that never asked
to move, which breaks the promise this pool exists to make. The trade is linkability:
more requests share one observable identity. Shorten it if you want the opposite.

</details>

## Use it from Python

With [`lncrawl-scraper`](https://github.com/lncrawl/scraper), which reports blocks back
to the pool automatically:

```python
from scraper import Scraper, TorPoolProxyUrl, default_config

config = default_config()
config.proxy.proxy_urls = [TorPoolProxyUrl(session="my-crawl")]
s = Scraper(config=config)

s.get_json("https://example.com/api")   # sticky exit
s.proxy_manager.rotate()                # instant move to another exit
```

With anything else, it is just a proxy:

```python
import httpx

proxy = "socks5h://my-session:x@127.0.0.1:9250"
with httpx.Client(proxy=proxy) as client:
    client.get("https://example.com")

httpx.post("http://127.0.0.1:8080/api/sessions/my-session/rotate")
```

## API

| Endpoint | What it does |
| --- | --- |
| `GET /api/pool` | Summary and effective config |
| `GET /api/instances` | Every instance: state, exit IP, traffic, health |
| `POST /api/instances/{id}/rotate` \| `/restart` \| `/quarantine` \| `/release` \| `/drain` | Act on one instance |
| `POST /api/pool/resize` | Grow or shrink while running |
| `POST /api/sessions/{key}/rotate` | Move a session to another instance |
| `POST /api/sessions/{key}/failure` | Report a block you observed |
| `GET /api/events` | Audit log |
| `GET /api/stream` | Live updates over SSE |
| `GET /metrics` | Prometheus |
| `GET /health` | 503 when nothing can serve |

Full reference with examples: [docs/api.md](docs/api.md).

## Dashboard

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/instances-dark.png">
  <img alt="Instances view" src="docs/images/instances-light.png">
</picture>

## Security

- **No authentication on the API.** Keep 8080 on loopback, or put your own auth in front.
- **Scope the SOCKS and HTTP ports yourself.** Anyone who can reach them can use your
  Tor bandwidth.
- **Tor instance ports never leave the container.** That is what makes password-less
  cookie authentication on the control ports safe — do not publish them.
- **This is not anonymity.** It rotates exit IPs. It does nothing about your TLS
  fingerprint, your cookies, or what you send.

## Docs

[Configuration](docs/configuration.md) ·
[API](docs/api.md) ·
[Architecture](docs/architecture.md) ·
[Operations](docs/operations.md) ·
[Using it from scraper](docs/scraper.md) ·
[Development](docs/development.md)

Contributions welcome — read [AGENTS.md](AGENTS.md) first; it covers the conventions and
a set of invariants that break silently if violated. Licensed under [MIT](LICENSE).
