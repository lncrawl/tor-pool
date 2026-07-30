# Using tor-pool from scraper

[`lncrawl-scraper`](https://github.com/lncrawl/scraper) has first-class support: it
keeps a session key, rotates through the pool's API, and reports blocks back.

It needs a token. Mint one in the dashboard's Tokens tab with the `proxy` scope, or take
the one printed on the pool's first boot. The same token authenticates both the proxy
port and the session routes `scraper` calls, and a `proxy`-scoped one cannot resize the
pool or restart instances if the config leaks.

Against a pool running with `AUTH_DISABLED` — which is what `compose.yml` sets — the
`token` below can be any string or left out entirely. Set one anyway if the pool might be
closed later: the password is ignored while the flag is on, so a config with a real token
works in both cases and needs no second edit.

```python
from scraper import Scraper, ScraperConfig, TorPoolSpec

config = ScraperConfig(
    exits=[
        TorPoolSpec(
            url="socks5h://127.0.0.1:9250",
            api_url="http://127.0.0.1:8080",
            token="tp_7Kq2mXvR8nB4jL6wYtZaPc",   # a proxy-scoped token
        )
    ]
)
with Scraper(origin="https://example.com", config=config) as s:
    s.get_json("https://example.com/api")        # same exit every time

    key = s.memory.key("https://example.com/")
    s.exits.rotate(key)                          # instant move to another exit
```

The defaults of `TorPoolSpec` are the ports above, so a pool on this machine needs only
`TorPoolSpec(token=...)` — and nothing at all against one running `AUTH_DISABLED`.

Calling `rotate` yourself is the exception. The library rotates on its own when it
concludes the address is what is being refused, which is the whole reason to report
failures: see below.

## Sessions

**The session key is not yours to choose.** `scraper` mints one per origin it leases an
address for — `s-` followed by twelve hex characters — and uses it as the SOCKS5 username.
So two origins in one `Scraper` get independent exits, and the same origin keeps one for
as long as it keeps working. A rotation mints a new key, which is what makes the move
visible to everything bound to the address.

Two consequences worth knowing. Deliberately sharing one exit across processes is not
expressible through `scraper`; use the proxy directly, as below, if you need it. And a key
is not stable across runs, so a session cannot be looked up in the dashboard from one run
to the next — find it by instance or by exit IP instead.

## Failure reporting

A report goes out whenever the library decides to leave an address, and what it sends is
derived from the **layer** it concluded was binding — not from the status code. That is the
whole point of the mapping: a 403 and a 429 can each be several different things, and the
kind decides how much the report counts for.

| Layer concluded | `kind` sent |
| --- | --- |
| Reputation, bot-fight, super-bot-fight, bot-management | `blocked` |
| Managed challenge, Turnstile, under-attack, CDP detection | `captcha` |
| Per-zone behavioural model | `rate_limited` |
| Nothing attributed — a transport failure through the exit | `transport` |
| Any other layer | `other` |

`reason` carries the layer's own name for the audit log, or `transport` when there is none.

Note the last two rows. A connection error through the proxy is reported as `transport`
with no layer, because the site never answered — there is nothing to conclude about it,
and the pool weighs a transport failure differently from a block for exactly that reason.

Call it yourself when your own code detects a block:

```python
from scraper.layers import Layer

key = s.memory.key("https://example.com/")
s.exits.report(s.exits.lease(key), Layer.MANAGED_CHALLENGE)   # sent as kind=captcha
```

This matters more than it looks. The pool relays opaque bytes and cannot see a 403 or a
captcha inside an HTTPS tunnel, so without these reports a burnt exit keeps taking
traffic until it happens to fail at the transport level. Set
`TorPoolSpec(report_failures=False)` to opt out.

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
