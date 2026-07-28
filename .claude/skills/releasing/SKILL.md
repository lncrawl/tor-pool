---
name: releasing
description: How tor-pool releases work — the edge-vs-release split, cutting a version from CHANGELOG.md, what each image tag means, and how to debug a failed publish. Read before editing anything in .github/workflows/ or cutting a release.
---

# Releasing

**Publishing an image and cutting a release are two different events.** Conflating them is
what this workflow layout exists to prevent: when every push to `main` was a release, a
README fix became a version number, a third of all versions contained no product change,
nine tags shipped with no release notes at all, and whatever was half-finished on `main`
was the image most people pulled.

| Workflow | Trigger | Publishes | `main.version` |
| --- | --- | --- | --- |
| `publish-edge.yml` | push to `main` touching code | `edge`, `sha-<short>` | `edge-<short sha>` |
| `release.yml` | `v*` tag, or dispatch with a version | `X.Y.Z`, `X.Y`, `X`, `latest` | `X.Y.Z` |
| `rebuild.yml` | Mondays 02:00 UTC, or dispatch | `edge`; `latest`, `X.Y`, `X` | unchanged |
| `build-image.yml` | called by all three | — | — |
| `verify-image.yml` | called by CI and the rebuild | — | — |

`build-image.yml` is a `workflow_call` reusable workflow holding *how* the image is built
(QEMU, buildx, platforms, cache, GHCR login). The callers decide only what it is called,
what version it stamps, which ref it builds and whether to re-resolve OS packages. Change
build options there, once.

`verify-image.yml` builds for the host architecture and boots a single-instance pool. CI
runs it on every push and PR; the rebuild runs it on each target before publishing.
`.github/version-parts.sh` decides which tags float, so the release and the rebuild cannot
disagree about it.

## Cutting a release

The version lives in exactly one place: **`CHANGELOG.md`**. There is no version file, and
the git tag follows the changelog rather than the other way round.

```bash
# 1. Move [Unreleased] to [X.Y.Z] - YYYY-MM-DD and commit it.
#    Check what will be published:
.github/release-notes.sh 0.2.0

# 2. Either route — both run the same jobs:
git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0
gh workflow run release.yml -f version=0.2.0
```

`release.yml` refuses to release a version `CHANGELOG.md` has no section for, and it checks
that *before* the ten-minute multi-arch build. That guard is the whole point: it is what
keeps the tags, the images and the notes describing the same thing.

The dispatch route creates the tag itself, and only after the image has built — so a failed
build leaves nothing to clean up. The tag-push route works against a tag you already made.

Pick the number by hand. Commit subjects here carry no `feat:`/`fix:` prefix by convention,
so nothing can infer major/minor/patch for you — which is exactly why automatic bumping
produced meaningless digits.

## Tag flavours

| Tag | When | Use it for |
| --- | --- | --- |
| `latest` | newest non-prerelease release | the default for operators; what `compose.yml` pins |
| `X.Y.Z` | that release, immutable | pinning — the only tag that never moves |
| `X.Y` | newest patch in that line | tracking fixes without pinning exactly |
| `X` | newest release in that major line, **only once `X` ≥ 1** | tracking a stable major |
| `edge` | every code push to `main` | trying unreleased work; never for anything you care about |
| `sha-<short>` | every build, immutable | bisecting a regression to a commit |

A **prerelease** (`v0.3.0-rc.1`) publishes its exact version and nothing else. It never
moves `latest`, `X.Y` or `X` — pushing a release candidate onto everyone tracking those is
the failure this avoids — and it is marked as a prerelease on GitHub.

The bare major tag is suppressed while it is `0`. Before 1.0 semver puts breaking changes on
the minor, so a `0` tag would carry someone from 0.1.x straight into an incompatible 0.2.x.

## The weekly rebuild

`tor` is installed from Alpine at image build time, so without a rebuild it only reaches
users when a release happens to be cut. `rebuild.yml` refreshes the two moving targets every
Monday: `edge` from the tip of `main`, and `latest` from the newest release — along with
`X.Y` and `X`, which float to that same release and would otherwise end up staler than
`latest` for identical code.

**The exact `X.Y.Z` is never rebuilt.** It is the one tag that promises the same bytes every
time, and someone who pinned it chose reproducibility over updates. `X.Y` exists for the
other choice.

Three things this gets right that are easy to miss:

- **The `apk` layer has to be invalidated explicitly.** It is a cache hit on its instruction
  alone, so with `cache-from: type=gha` warm, a rebuild reuses the old layer and ships the
  *old* tor — the earlier cron did exactly that and achieved nothing. Hence the named
  `runtime` stage and `refresh-packages: true`, which sets `pull` and
  `no-cache-filters: runtime`. The node and go stages stay cached.
- **Each target is smoke-tested before it is published.** A rebuild is the one change that
  reaches users with nobody having looked at it, and the most likely thing to break it is
  the package it exists to update. Both targets go through `verify-image.yml` first.
- **`sha-<short>` is not republished.** Those name a specific commit's build and are what a
  regression is bisected against; giving one a different tor would destroy the only
  immutable record of that commit.

The rebuilt image still reports the release's own version — the code *is* that release. What
changed is underneath it, recorded in the image's `org.opencontainers.image.created` label
and its digest. A rebuild therefore produces a new digest even when no package changed, so
pin `X.Y.Z` or a digest if byte-stability matters. A failed scheduled run notifies whoever
last touched the workflow file; if `latest` looks stale, check `rebuild.yml`'s history first.

## What is deliberately not automated

- **No conventional-commit tooling** (release-please, semantic-release). Both need commit
  prefixes this repo does not use, and both would take over the hand-curated changelog.
- **No second registry.** GHCR only; another one means another credential to rotate for no
  benefit.

## Docs that must not drift

`latest` means *newest release*, refreshed weekly against the current `tor`. Anything telling
a reader that `latest` follows `main` is wrong — check `README.md`, `docs/operations.md` and
`AGENTS.md` when you change this pipeline.

## First publish of a new package

A GHCR package starts **private even when the repo is public**, so the first `docker pull`
from outside CI fails with a 403 that reads like a missing image. Fix it once, by hand:

**Package settings → Change visibility → Public**, and link it to the repository so it
appears on the repo page.

## Debugging a failed publish

- **`CHANGELOG.md has no '## [X.Y.Z]' section`** — the guard doing its job. Move
  `[Unreleased]` into a version section and commit before tagging.
- **`'X' is not a semantic version`** — the dispatch input or tag name is malformed. Want
  `0.2.0` or `0.2.0-rc.1`, with or without a leading `v`.
- **`denied: permission_denied` on push** — the job is missing `packages: write`, or the
  run came from a fork (a fork's `GITHUB_TOKEN` is read-only by design).
- **`buildx failed` only on arm64** — QEMU emulation is slow enough that the node build can
  time out. Check whether the failure is a timeout before assuming a real break.
- **The image built but the dashboard is the placeholder** — the `web` stage silently
  produced nothing, so `COPY --from=web` copied the committed placeholder. Confirm `npm run
  build` ran and that vite's `outDir` still points into `internal/server/dist`.
- **Nothing ran on a push to `main`** — `publish-edge.yml` ignores markdown, `docs/`,
  `.claude/` and `LICENSE`. A push touching only those is meant to publish nothing.
- **The rebuild published the same tor as last week** — check that the `runtime` stage is
  still named in `docker/Dockerfile` and that `refresh-packages: true` is still passed. Both
  are load-bearing and neither fails loudly.
- **The rebuild cannot find a release** — `gh release view` needs one non-draft,
  non-prerelease release to exist. Before the first one, only the `edge` half can run.
