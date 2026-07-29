# Operations

## Sizing

Each instance is roughly 30–40 MB of RAM and some CPU while bootstrapping. Ten instances
in about half a gigabyte is a reasonable planning figure.

Size by how many distinct exit identities you need *concurrently*, then add slack for
instances being remediated. More instances do not make any single request faster.

Bootstrapping is network-bound and mostly parallel: a pool of ten is usable in roughly
the time one instance takes, which is why `MIN_READY` defaults to 1.

## Reading the dashboard

**Overview** answers "is it working": routable count, error rate, connect latency. A
routable count below the pool size means something is quarantined or still starting.

**Instances** answers "which one is the problem". The failures column shows transport
and client-reported counts separately — a high client count with no transport failures
means that exit is being *blocked*, not broken. Hover it for the breakdown by kind and the
weighted score: captchas mean burnt exits, while a column of nothing but rate limits means
your callers are going too fast and the exits are fine.

**Sessions** answers "why does this caller keep failing". Find the key, see which
instance it is pinned to, cross-reference in Instances.

**Events** is the audit log: every rotation, quarantine, restart and resize, with the
trigger.

## Everything is quarantined

`/health` returns 503 and clients get an immediate failure rather than a hang.

1. Check Events for what quarantined them. All at once usually means the *target* is
   blocking your whole IP range, or your egress is broken — not the instances.
2. If it was a burst of client-reported failures against one site, your thresholds may
   be too tight for that target. Raise `QUARANTINE_FAILURES`. Check what the reports said
   first: a wall of `rate_limited` means your callers are too fast for the target rather
   than the exits being bad, and if a client is sending `blocked` or `captcha` for what is
   really a 429, fix the client — a mislabelled rate limit retires a working exit and the
   next one is throttled just the same.
3. To force recovery now: `POST /api/instances/{id}/release` on one, and see if traffic
   flows. Release clears its accumulated failures.

The pool recovers on its own once the ladder finishes — but on the backoff rung that can
be minutes, deliberately.

## Tuning for an aggressive target

- Lower `QUARANTINE_FAILURES` and `QUARANTINE_CONSECUTIVE` so a burnt exit is retired
  after fewer blocked requests.
- Raise `POOL_SIZE` so there is somewhere to move to.
- Make sure your client actually reports blocks, and reports them honestly. Without
  `POST /api/sessions/{key}/failure`, the pool only sees transport errors and a
  soft-blocked exit looks perfectly healthy; with every failure sent as one undifferentiated
  reason, a captcha waits as long as a 429 does. A client that sends `kind` gets a burnt exit
  retired in two reports without lowering the threshold for everything else.
- Consider `TOR_EXIT_NODES` if the target blocks whole regions — but a narrow policy
  shrinks the relay set and makes circuits slower and less diverse.

## An instance will not bootstrap

Set `LOG_LEVEL=debug` to see Tor's own notice lines. Common causes: no outbound network,
a clock badly out of sync, or an over-restrictive `TOR_EXIT_NODES` combined with
`TOR_STRICT_NODES`.

`POST /api/instances/{id}/restart` wipes its state directory and starts clean, which
clears a corrupt cached consensus.

## Credentials

The dashboard password and every proxy token live in `auth.json` inside `DATA_DIR`, mode
0600. It holds digests, never plaintext, so nothing there can be read back — which is
also why a lost credential is replaced rather than recovered.

**Where did the first-boot credentials go?** They were printed once, at startup:

```bash
docker compose logs tor-pool | grep -A12 'generated credentials'
```

Still there as long as the container has not been recreated and the log has not rotated.

**I lost the dashboard password.** Set `ADMIN_PASSWORD` and restart. A password you set
always wins over a generated one, takes effect immediately, and clears the stored digest
so removing the variable later generates a fresh password rather than resurrecting the
old one.

**Sign every session out.** Change `ADMIN_USER` or `ADMIN_PASSWORD` and restart. Every
outstanding session is bound to both, so all of them stop working at once — there is no
separate revoke, because a session credential is self-contained and valid until it
expires.

**Revoke one consumer.** Dashboard → Tokens → Revoke. It stops working immediately,
before the change reaches disk, so a revoke cannot be undone by a restart. A token from
`PROXY_TOKEN` is configuration: change the variable and restart.

**Nothing works after a `docker compose down -v`.** That destroys the volume, and with it
the credential store. The next boot generates a new password and a new token and prints
them. Set `ADMIN_PASSWORD` and `PROXY_TOKEN` if you would rather they came from config
and survived anything.

**The pool refuses to start with a message about `auth.json`.** The file is unreadable or
corrupt. That is deliberately fatal: starting over would silently mint new credentials
and lock out every consumer while `/health` kept answering 200. Move the file aside to
start fresh, which discards every issued token, or restore it from a backup.

**Anything can connect without a credential.** `AUTH_DISABLED` is set. Confirm it:

```bash
curl -s localhost:8080/api/auth/status     # {"required":false,...}
```

Unset the variable and restart. Nothing else has to be done: the password and token
printed at first boot were still generated and stored while the flag was set, so they start
being enforced immediately — `grep -A12 'generated credentials'` in the log as above. If
that log is gone, set `ADMIN_PASSWORD` and `PROXY_TOKEN` and restart instead.

While it is set, startup prints a banner block naming the flag and the dashboard shows an
`auth disabled` tag where the sign-out control usually is. Both exist because the failure
mode is nobody remembering it was ever set.

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Every instance re-bootstraps, so the pool is briefly at reduced capacity. The volume
keeps the cached consensus, which makes that fast.

Which tag you pull decides what you get:

| Tag | Moves when | Suits |
| --- | --- | --- |
| `latest` | a release is cut, and weekly for a newer Tor | most deployments; what `compose.yml` uses |
| `X.Y` | a patch release in that line, and weekly | pinning a minor version, still taking fixes |
| `X.Y.Z` | never | reproducible deployments — you upgrade on purpose |
| `edge` | every code push to `main`, and weekly | trying unreleased work |

Tor is installed at image build time, so the version you run is fixed when the image is
built. The moving tags above are rebuilt every Monday against the current Alpine `tor`, which
is how a Tor security release reaches you without waiting for a tor-pool release. Each rebuild
is smoke-tested — the image has to boot a pool and bootstrap a circuit before it is published.

`X.Y.Z` is deliberately excluded: it promises the same bytes every time. If you pin it, you
also own upgrading it. Use `X.Y` if you would rather have the fixes.

## What monitoring to wire up

From `/metrics`:

- `torpool_instances_routable` — alert when it hits 0, and when it sits below
  `torpool_instances_total` for a sustained period.
- `torpool_instance_failures_total{source="client"}` — a rising rate means exits are
  being blocked, which no transport-level check would catch.
- `torpool_instance_failure_kinds_total{kind="captcha"}` — the same rate split by what
  the reports said. Captchas climbing while `kind="rate_limited"` is flat is a blocking
  problem; the reverse is a pacing problem, and no amount of rotation fixes it.
- `torpool_instance_failure_score` against `torpool_quarantine_score` — how close each
  instance is to being taken out of rotation, which the report count alone does not say.
- `torpool_instance_remediations_total` — climbing steadily means the ladder is
  thrashing; the thresholds are probably too tight.

`/health` and `/metrics` answer without a credential, so a probe needs no configuration.

Refused credentials are logged at `warn` rather than recorded as events. The audit log is
a bounded ring, so one entry per rejected connection would let anyone flush its whole
history in seconds — exactly when it is worth reading. Watch the log for
`credential refused` instead; operator actions (sign-ins, tokens issued and revoked) *are*
events and show up in the dashboard.
