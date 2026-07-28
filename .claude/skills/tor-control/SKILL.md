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
| `stream-status` | one line per stream: `<id> <state> <circuitID> host:port` | `NEW`/`NEWRESOLVE` streams carry circuit id `0`. Every other state — `SENTCONNECT`, `CONNECT_WAIT`, `RESOLVE_WAIT`, `REMAP`, `SUCCEEDED` — names a real circuit. See the two questions below |
| `ns/id/<fingerprint>` | consensus entry for a relay | The `r` line's 7th field is the IP |
| `ip-to-country/<ip>` | two-letter country code | Needs the GeoIP databases; Alpine's `tor` package ships them at `/usr/share/tor`, so no extra package is required |

A `GETINFO` reply is either `key=value` on one line, or `key=` followed by a payload whose last
line is `OK` — which must be stripped before use.

### stream-status answers two different questions

Conflating them cost 4-5% of requests during rotation.

- **"Where is this instance going out?"** — only `SUCCEEDED`. A stream that has not connected
  yet proves nothing about a working path (`attachedCircuitIDs`).
- **"Which circuits must not be closed?"** — every stream with a non-zero circuit id
  (`busyCircuitIDs`). A stream in `SENTCONNECT` is a request in flight: tor has picked its
  circuit and is waiting for the exit to open the TCP connection, which lasts as long as the
  destination takes to answer. Closing that circuit fails the request outright.

If `stream-status` cannot be read at all, close **nothing**. There is then no way to tell a live
request's circuit from an abandoned one, and tor retires them on its own schedule anyway.

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

- **`PURPOSE=CONFLUX_LINKED` circuits carry exit traffic and must be accepted.** Streams ride
  linked conflux legs, while the `GENERAL` circuits sitting alongside them are usually
  preemptive. Legs of one set share their exit relay, so they all resolve to the same answer.
  Accepting only `GENERAL` is how the resolver ends up naming an exit no traffic uses.
  (tor-pool renders `ConfluxEnabled 0` by default — see the exit-stability note below — but the
  parser must still handle these, because the option can be turned back on.)
- **`IS_INTERNAL` in `BUILD_FLAGS` means no exit hop**, whatever the purpose says — that is how
  `HS_VANGUARDS` circuits show up.
- **Circuits built before the last NEWNYM are excluded.** That signal marks every existing
  circuit unusable for new streams — clean and dirty alike — so their exits are no longer where
  the instance goes out.
- **After a NEWNYM the instance has no exit until tor rebuilds**, and it will not rebuild while
  the retired circuits still stand — an idle instance was measured sitting for minutes. Closing
  them (see below) is what makes the replacement appear in a second or two. Until it does, the
  honest answer is "unknown": do not paper over it with the retired exit, and do not reach for
  `EXTENDCIRCUIT 0` — a controller-built circuit is not used for ordinary streams and is closed
  again shortly after.
- `TIME_CREATED` is `2006-01-02T15:04:05.999999` with **no zone suffix and always UTC**. Parsing
  it as local time silently misdates every circuit.
- Filter on `PURPOSE=GENERAL`. Hidden-service circuits (`HS_CLIENT_INTRO`, …) have no exit in
  the sense we mean.
- Skip anything not `BUILT`; `LAUNCHED` circuits have no usable path yet.
- A hop is `$FINGERPRINT~Nickname` **or** `$FINGERPRINT=Nickname` — named relays use `=`. Split
  on either.
- This resolution reads tor's own consensus view, so it costs **no Tor bandwidth**, unlike
  fetching an IP-echo URL through the circuit.

**What this value actually means.** Steps 2 and 3 are *guesses* — inferred from the circuits tor
is holding, several of which it built preemptively and no request will ever use. Only step 1 is
evidence. `ExitNode` returns that distinction as a `confirmed` bool, and an unconfirmed answer
must never displace a confirmed one; publishing guesses as fact is what made a rotation look like
the exit IP jumped once or twice before settling.

It is also not a guarantee about the *next* request unless the exit is pinned: tor retires
circuits on its own schedule (`MaxCircuitDirtiness`, set in `internal/config`).

Expect failure before a circuit exists: right after bootstrap, and right after a NEWNYM, there
may be no eligible circuit at all. That is a normal transient, not an error worth surfacing to
the user — but it must read as "unknown", never as the previous exit.

## One instance, one exit IP

Neither `MaxCircuitDirtiness` nor sticky reporting makes an instance's exit IP *stable*. Tor holds
several exit-bearing circuits at once and picks between them per stream, so a caller pinned to one
instance was measured being served by two different relays inside a minute with no rotation at
all. Two levers, both in `internal/config`:

- `ConfluxEnabled 0` (default here, unlike in tor): every conflux set tor pre-builds is another
  distinct exit in the pool it picks from. Disabling it removes most of the churn.
- `PIN_EXIT_RELAY` (opt-in): `SETCONF ExitNodes=$<fp> StrictNodes=1` after the instance has an
  exit. **A pin only governs circuits built afterwards** — the standing ones keep their own exits
  and tor will attach the next stream to one of them, so `CloseCircuitsExceptExit` has to clear
  them or the pin is one the traffic ignores. Releasing it for a rotation adds the old relay to
  `ExcludeExitNodes` while tor picks, so the rotation cannot hand back the exit just declared
  burnt, and restores the configured exclusions when it locks the replacement.

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

## Retiring circuits after a rotation

```
CLOSECIRCUIT <id>
```

**NEWNYM is not sufficient on its own.** It marks the existing circuits unusable for new streams,
but they stay up, and while they do:

- tor sees no shortage of circuits and builds no replacement, so there is nothing to report;
- traffic has been observed still exiting through a retired conflux set, which is what makes a
  rotation look like it did nothing — the dashboard names a new exit while the client keeps
  seeing the old IP.

So `Control.CloseRetiredCircuits` closes every exit-bearing circuit dated before the last NEWNYM.
Tor then rebuilds at once and the new exit resolves within a second or two.

**Circuits carrying a stream must be spared** — any stream, not just a connected one; see
"stream-status answers two different questions" above. A proxy connection is pinned to its
instance for its whole life, so closing one fails a request already in flight — including an idle
HTTP `CONNECT` tunnel, whose stream stays open between requests.

## SETCONF

```
SETCONF ExitNodes="{us},{ca}"
SETCONF ExitNodes          (no value resets the option to its default)
SETCONF ExitNodes=$AAAA ExcludeExitNodes StrictNodes=1   (several in one command)
```

**Apply options that only make sense together in one command** (`SetConfAll`). A `StrictNodes` that
lands before its `ExitNodes` leaves tor briefly unable to build anything at all; one that lands
after leaves a window where the pin is merely advisory.

Values containing whitespace, quotes or backslashes must be sent as a QuotedString.
`quoteControlValue` handles this and **strips newlines**, which would otherwise terminate the
command line and let a caller-supplied value inject a second command. Exit policies and anything
else derived from user input must go through it.

## Concurrency and failure

The protocol is a synchronous request/reply stream over one connection, so `Control` is **not**
safe for concurrent use. `Instance` serialises commands behind `ctrlMu` and reaches the connection
only through `withControl`. Rules that have each cost a real bug:

- **Never block with the control lock held.** `Instance.Newnym` waits out the cooldown with it
  released and re-checks after; holding it across a ten second sleep blocked the exit poller,
  which blocked the pool's whole maintenance loop.
- **Pollers use `tryWithControl`**, which gives up if the lock is taken rather than queueing
  behind a command that may take as long as the cooldown.
- **Every command has an I/O deadline.** A tor that accepts the connection and then stops
  answering otherwise wedges the caller forever, holding the lock.
- **An I/O failure mid-command poisons the connection.** The reply it did not finish reading would
  be read as the next command's, so `Control` marks itself `Broken` and the instance redials.
  A non-2xx reply is *not* a break — tor said no, in a complete well-framed answer.
- **Redial when the connection is gone.** Nothing else does, and a control connection lost while
  tor keeps running leaves an instance that still serves traffic but can never be rotated or
  report its exit again.
