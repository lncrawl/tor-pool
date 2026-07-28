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
means that exit is being *blocked*, not broken.

**Sessions** answers "why does this caller keep failing". Find the key, see which
instance it is pinned to, cross-reference in Instances.

**Events** is the audit log: every rotation, quarantine, restart and resize, with the
trigger.

## Everything is quarantined

`/health` returns 503 and clients get an immediate failure rather than a hang.

1. Check Events for what quarantined them. All at once usually means the *target* is
   blocking your whole IP range, or your egress is broken — not the instances.
2. If it was a burst of client-reported failures against one site, your thresholds may
   be too tight for that target. Raise `QUARANTINE_FAILURES`.
3. To force recovery now: `POST /api/instances/{id}/release` on one, and see if traffic
   flows. Release clears its accumulated failures.

The pool recovers on its own once the ladder finishes — but on the backoff rung that can
be minutes, deliberately.

## Tuning for an aggressive target

- Lower `QUARANTINE_FAILURES` and `QUARANTINE_CONSECUTIVE` so a burnt exit is retired
  after fewer blocked requests.
- Raise `POOL_SIZE` so there is somewhere to move to.
- Make sure your client actually reports blocks. Without
  `POST /api/sessions/{key}/failure`, the pool only sees transport errors and a
  soft-blocked exit looks perfectly healthy.
- Consider `TOR_EXIT_NODES` if the target blocks whole regions — but a narrow policy
  shrinks the relay set and makes circuits slower and less diverse.

## An instance will not bootstrap

Set `LOG_LEVEL=debug` to see Tor's own notice lines. Common causes: no outbound network,
a clock badly out of sync, or an over-restrictive `TOR_EXIT_NODES` combined with
`TOR_STRICT_NODES`.

`POST /api/instances/{id}/restart` wipes its state directory and starts clean, which
clears a corrupt cached consensus.

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
- `torpool_instance_remediations_total` — climbing steadily means the ladder is
  thrashing; the thresholds are probably too tight.

`/health` is the liveness check and reports routability, not process health.
