# Using tor-pool from scraper

[`lncrawl-scraper`](https://github.com/lncrawl/scraper) has first-class support: it
keeps a session key, rotates through the pool's API, and reports blocks back.

It needs a token. Mint one in the dashboard's Tokens tab with the `proxy` scope, or take
the one printed on the pool's first boot. The same token authenticates both the proxy
port and the session routes `scraper` calls, and a `proxy`-scoped one cannot resize the
pool or restart instances if the config leaks.

```python
from scraper import Scraper, TorPoolProxyUrl, default_config

config = default_config()
config.proxy.proxy_urls = [
    TorPoolProxyUrl(
        url="socks5h://127.0.0.1:9250",
        api_url="http://127.0.0.1:8080",
        token="tp_7Kq2mXvR8nB4jL6wYtZaPc",   # a proxy-scoped token
        session="my-crawl",   # omit for a generated per-Scraper key
    )
]
s = Scraper(config=config)

s.get_json("https://example.com/api")   # same exit every time
s.proxy_manager.rotate()                # instant move to another exit
```

A runnable version: [`examples/11_tor_pool.py`](https://github.com/lncrawl/scraper/blob/main/examples/11_tor_pool.py).

## Sessions

Leave `session` blank and each `ProxyManager` generates its own key, so two `Scraper`s
in one process get independent exit IPs. Set it explicitly when you want several
processes to deliberately share an exit, or when you want a stable key to look up in the
dashboard.

## Failure reporting

The engine reports automatically on:

| Signal | Reason sent | Typed as |
| --- | --- | --- |
| `ProxyError` / `ConnectionError` | `transport` | `transport` |
| HTTP 403 | `http_403` | `blocked` |
| A Cloudflare challenge | `challenge` | `captcha` |
| HTTP 429 with no challenge behind it | `rate_limited` | `rate_limited` |

A Cloudflare challenge often arrives *as* a 429, and the challenge handlers look at the
body rather than the status, so a challenged response is reported as one — the last row is
a plain throttle only.

Call it yourself when your own code detects a block:

```python
s.proxy_manager.report_failure("captcha")
```

This matters more than it looks. The pool relays opaque bytes and cannot see a 403 or a
captcha inside an HTTPS tunnel, so without these reports a burnt exit keeps taking
traffic until it happens to fail at the transport level. Set `report_failures=False` to
opt out.

**What you send decides what happens.** The pool types every report and weighs it: a
`captcha` retires the exit in the fewest reports, `http_403` in a few more, and a 429
barely counts because the exit is working and a fresh one arrives to the same rate limit.
So report a throttle as `rate_limited` (or `429`) rather than as a generic failure — and
never as a block, which spends a healthy exit. The engine does this for the signals in the
table above; anything else is a judgement only your own code can make. The
full vocabulary and the thresholds it feeds are in
[api.md](api.md#post-apisessionskeyfailure); anything the pool does not recognise counts
as one unremarkable failure.

## The connection-pool caveat

**A proxy connection is pinned to its exit for its entire life.** Rotating only affects
new connections, so a client holding keep-alives keeps using the old exit and rotation
looks like it silently did nothing.

`scraper` handles this — `rotate()` drops the pooled connections. If you use a different
client, you must do the same:

```python
# httpx: build a new client after rotating.
httpx.post(f"{api}/api/sessions/{key}/rotate",
           headers={"Authorization": f"Bearer {token}"})
client.close()
client = httpx.Client(proxy=proxy)
```

One limitation: `scraper`'s impersonate transport (`curl_cffi`) cannot be reset without
discarding the session for good, so a rotation there takes effect once curl retires the
connection rather than immediately.

## Without scraper

It is an ordinary SOCKS5 proxy. The username is the session key and the password is your
token:

```python
proxy = "socks5h://my-session:tp_7Kq2mXvR8nB4jL6wYtZaPc@127.0.0.1:9250"
```

Use `socks5h`, not `socks5`, so DNS resolves inside Tor.

Both halves are required. A client that offers no credentials is refused during the
SOCKS5 handshake, and one with a wrong password gets RFC 1929's rejection — which most
libraries surface as a generic "SOCKS5 authentication failed" rather than naming the
password, so check the token first when a connection is refused outright.

The HTTP proxy on 9251 takes the same pair, as ordinary proxy credentials:

```python
proxy = "http://my-session:tp_7Kq2mXvR8nB4jL6wYtZaPc@127.0.0.1:9251"
```

Calls to the pool's API need the token too:

```python
httpx.post(f"{api}/api/sessions/{key}/rotate",
           headers={"Authorization": f"Bearer {token}"})
```
