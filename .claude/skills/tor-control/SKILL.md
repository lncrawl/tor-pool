---
name: tor-control
description: Tor control-port protocol as tor-pool uses it — cookie authentication, the GETINFO keys that matter, resolving an exit relay's IP and country, SETCONF for exit policy, and NEWNYM cooldown semantics. Read before touching internal/tor/control.go or anything that talks to a control port.
---

# Tor control port

The control port is a line-based text protocol on a TCP socket. `internal/tor/control.go`
implements the subset tor-pool needs; there is no third-party dependency. This file records the
parts that are easy to get wrong and cannot be inferred from the code.

## Authentication

tor-pool uses **cookie authentication**, set by `CookieAuthentication 1` in the torrc. Tor writes
a 32-byte binary cookie to `<DataDirectory>/control_auth_cookie` and accepts it hex-encoded:

```
AUTHENTICATE <hex of the cookie bytes>
```

Why cookies rather than `HashedControlPassword`: the control ports bind container loopback and
are never published, so there is no password to manage, rotate or leak, and no
`tor --hash-password` fork per instance at boot.

**The cookie appears after the port opens.** Tor starts listening before it has finished writing
the file, so dialling successfully proves nothing — authenticating against a zero-length cookie
fails. `Connect` therefore stats the cookie *first* and requires a non-zero size, then dials.
Both conditions must hold.

## Reply framing

Every reply line is `<3-digit code><separator><text>`, where the separator is:

| Separator | Meaning |
| --- | --- |
| `-` | Continuation; more lines follow |
| `+` | Continuation introducing a dot-quoted multi-line payload |
| ` ` (space) | Final line of the reply |

A `+` payload ends with a line containing only `.`, and a literal leading dot inside it is
escaped by doubling. `readReply` unescapes exactly one.

Two traps:

- **An error code can appear mid-reply.** `250-partial` followed by `552 Unrecognized key` is a
  failure, not a success. `readReply` keeps the first code but lets any code ≥ 400 override it —
  reporting the 250 would silently swallow the error.
- Codes are not all `250`. `514` is a bad authentication *command*, `515` a bad password, `552`
  an unrecognised key. Preserve tor's own code and message in the error (`ControlError` does);
  they are far more specific than anything we could infer.

## GETINFO keys in use

| Key | Returns | Notes |
| --- | --- | --- |
| `status/bootstrap-phase` | `NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"` | Parse `PROGRESS=`. **Not monotonic** — it can fall back after a connection loss, so never treat a decrease as an error |
| `circuit-status` | one line per circuit | Multi-line `+` payload. Each line ends with optional key=value fields, of which `TIME_CREATED=` is the one that dates a circuit — **do not infer age from list order** |
| `stream-status` | one line per stream: `<id> SUCCEEDED <circuitID> host:port` | `NEW`/`NEWRESOLVE` streams carry circuit id `0` |
| `ns/id/<fingerprint>` | consensus entry for a relay | The `r` line's 7th field is the IP |
| `ip-to-country/<ip>` | two-letter country code | Needs the GeoIP databases; Alpine's `tor` package ships them at `/usr/share/tor`, so no extra package is required |

A `GETINFO` reply is either `key=value` on one line, or `key=` followed by a payload whose last
line is `OK` — which must be stripped before use.

## Resolving the exit relay

```
circuit-status + stream-status  →  one chosen circuit  →  last hop  →  ns/id/<fp>  →  IP
                                                                   →  ip-to-country/<IP>
```

An instance has **several** BUILT general-purpose circuits at once, so the hard part is not
parsing, it is choosing — and choosing the same one next time. `selectExit` picks, in order:

1. the circuit carrying a stream (`stream-status`) — the only one tor has committed traffic to;
2. the exit reported last time, while a circuit to it still stands;
3. the newest circuit by `TIME_CREATED`.

Step 2 is not an optimisation. Tor builds circuits preemptively, so a resolver that always takes
the newest reports an exit no traffic has used and **flaps between relays on consecutive polls**
while nothing about the instance has changed. That was a real bug; keep the choice sticky.

Details that matter:

- **`PURPOSE=CONFLUX_LINKED` circuits carry exit traffic and must be accepted.** Conflux is on
  by default in current tor: streams ride linked conflux legs, while the `GENERAL` circuits
  sitting alongside them are usually preemptive. Legs of one set share their exit relay, so they
  all resolve to the same answer. Accepting only `GENERAL` is how the resolver ends up naming an
  exit no traffic uses.
- **`IS_INTERNAL` in `BUILD_FLAGS` means no exit hop**, whatever the purpose says — that is how
  `HS_VANGUARDS` circuits show up.
- **Circuits built before the last NEWNYM are excluded.** That signal marks every existing
  circuit unusable for new streams — clean and dirty alike — so their exits are no longer where
  the instance goes out.
- **After a NEWNYM an idle instance has no exit at all, and not briefly.** Tor does not
  pre-build a replacement without traffic to predict, and the retired circuits linger as `BUILT`
  meanwhile, so the honest answer stays "unknown" until the next request. Do not paper over it by
  reporting the retired exit, and do not reach for `EXTENDCIRCUIT 0`: a controller-built circuit
  is not used for ordinary streams and is closed again shortly after.
- `TIME_CREATED` is `2006-01-02T15:04:05.999999` with **no zone suffix and always UTC**. Parsing
  it as local time silently misdates every circuit.
- Filter on `PURPOSE=GENERAL`. Hidden-service circuits (`HS_CLIENT_INTRO`, …) have no exit in
  the sense we mean.
- Skip anything not `BUILT`; `LAUNCHED` circuits have no usable path yet.
- A hop is `$FINGERPRINT~Nickname` **or** `$FINGERPRINT=Nickname` — named relays use `=`. Split
  on either.
- This resolution reads tor's own consensus view, so it costs **no Tor bandwidth**, unlike
  fetching an IP-echo URL through the circuit.

**What this value actually means.** It is *an* exit currently in use, not a guarantee about the
next request: tor retires circuits on its own schedule (`MaxCircuitDirtiness`, set in
`internal/config`). Report it as "current exit".

Expect failure before a circuit exists: right after bootstrap, and right after a NEWNYM, there
may be no eligible circuit at all. That is a normal transient, not an error worth surfacing to
the user — but it must read as "unknown", never as the previous exit.

## NEWNYM and its cooldown

```
SIGNAL NEWNYM
```

**Tor will not tell you how much cooldown is left.** There is no `GETINFO` for it. A NEWNYM sent
inside the cooldown returns `250 OK` and is then silently coalesced — the single most confusing
failure mode in this area, because rotation appears to succeed while the exit never changes.

So the cooldown (`NewnymCooldown`, 10s) is tracked client-side from the last NEWNYM *this
connection* sent. Two consequences:

1. **Keep one long-lived control connection per instance.** Dialling per command loses the
   timestamp and the tracking becomes wrong.
2. A NEWNYM sent by any other controller is invisible to us. Nothing else should hold a control
   connection to these instances.

Use `Control.Newnym(ctx)`, which waits out the remaining cooldown, rather than
`Signal("NEWNYM")` directly.

NEWNYM also does not touch **existing** connections — it only affects circuits built afterwards.
A client holding a live proxy connection keeps its old exit until it reconnects. The pre-NEWNYM
circuits stay listed as `BUILT` for a while too, which is why the exit resolver dates circuits
against the last NEWNYM instead of trusting whatever is in `circuit-status`.

## SETCONF

```
SETCONF ExitNodes="{us},{ca}"
SETCONF ExitNodes          (no value resets the option to its default)
```

Values containing whitespace, quotes or backslashes must be sent as a QuotedString.
`quoteControlValue` handles this and **strips newlines**, which would otherwise terminate the
command line and let a caller-supplied value inject a second command. Exit policies and anything
else derived from user input must go through it.

## Concurrency

The protocol is a synchronous request/reply stream over one connection, so `Control` is **not**
safe for concurrent use. Callers serialise commands — `Instance` holds the connection and its own
mutex. Never hold that mutex across a control command that can block (`Newnym` waits out a
cooldown); copy the pointer out under the lock and release it first.
