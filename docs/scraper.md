# Using tor-pool from scraper

[`lncrawl-scraper`](https://github.com/lncrawl/scraper) has first-class support: it
keeps a session key, rotates through the pool's API, and reports blocks back.

```python
from scraper import Scraper, TorPoolProxyUrl, default_config

config = default_config()
config.proxy.proxy_urls = [
    TorPoolProxyUrl(
        url="socks5h://127.0.0.1:9250",
        api_url="http://127.0.0.1:8080",
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

| Signal | Reason sent |
| --- | --- |
| `ProxyError` / `ConnectionError` | `transport` |
| HTTP 403 | `http_403` |
| A Cloudflare challenge | `challenge` |

Call it yourself when your own code detects a block:

```python
s.proxy_manager.report_failure("captcha")
```

This matters more than it looks. The pool relays opaque bytes and cannot see a 403 or a
captcha inside an HTTPS tunnel, so without these reports a burnt exit keeps taking
traffic until it happens to fail at the transport level. Set `report_failures=False` to
opt out.

## The connection-pool caveat

**A proxy connection is pinned to its exit for its entire life.** Rotating only affects
new connections, so a client holding keep-alives keeps using the old exit and rotation
looks like it silently did nothing.

`scraper` handles this — `rotate()` drops the pooled connections. If you use a different
client, you must do the same:

```python
# httpx: build a new client after rotating.
httpx.post(f"{api}/api/sessions/{key}/rotate")
client.close()
client = httpx.Client(proxy=proxy)
```

One limitation: `scraper`'s impersonate transport (`curl_cffi`) cannot be reset without
discarding the session for good, so a rotation there takes effect once curl retires the
connection rather than immediately.

## Without scraper

It is an ordinary SOCKS5 proxy where the username is the session key:

```python
proxy = "socks5h://my-session:x@127.0.0.1:9250"
```

Use `socks5h`, not `socks5`, so DNS resolves inside Tor. The password is required by the
SOCKS5 handshake and ignored by the pool — any value works.
