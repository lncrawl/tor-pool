---
name: releasing
description: How tor-pool releases work — the tag-triggered GHCR publish, what each image tag means, the weekly rebuild, and how to debug a failed push. Read before editing .github/workflows/docker-publish.yml or cutting a release.
---

# Releasing

There is no version file to bump. **Pushing to `main` is the release**:
`docker-publish.yml` bumps a patch tag, builds multi-arch, and pushes to
`ghcr.io/lncrawl/tor-pool`.

## What happens on a push to main

1. `mathieudutour/github-tag-action` reads the commits since the last tag and creates
   the next one (`default_bump: patch`).
2. QEMU + Buildx build `linux/amd64` and `linux/arm64` from `docker/Dockerfile`. That
   one file builds the dashboard *and* the Go binary, so there is nothing to sequence
   in the workflow.
3. The image is pushed with every tag flavour below.

`VERSION` is passed as a build arg and ends up in `main.version`, which the API reports
at `/api/pool` and the dashboard shows in its header. A build without a new tag falls
back to the commit SHA.

## Tag flavours

| Tag | When | Use it for |
| --- | --- | --- |
| `latest` | every push to `main` | trying it out; never for anything you care about |
| `X.Y.Z` | the tag just created | pinning — the only one that cannot move |
| `X.Y` | same build | tracking patch fixes without pinning exactly |
| `sha-<short>` | every build | bisecting a regression to a commit |

## Controlling the bump

The tag action reads conventional-commit prefixes to decide major/minor/patch. This
repo's commit style deliberately has **no type prefix**, so every push is a patch bump.
That is the intended default. To cut a minor or major release, push an annotated tag
yourself first:

```bash
git tag -a v0.3.0 -m "Add X"
git push origin v0.3.0
```

A `v*` tag triggers the same workflow, and `type=semver` produces `0.3.0` and `0.3`.

## The weekly rebuild

The cron rebuilds every Monday with no code change. Alpine's `tor` package is pulled at
build time, so this is how a new tor release reaches users. It publishes `latest` and a
fresh `sha-` tag but does **not** create a version tag — there is no new commit to tag.

## First publish of a new package

A GHCR package starts **private even when the repo is public**, so the first `docker
pull` from outside CI fails with a 403 that reads like a missing image. Fix it once, by
hand:

**Package settings → Change visibility → Public**, and link it to the repository so it
appears on the repo page.

## Debugging a failed publish

- **`denied: permission_denied` on push** — the job is missing `packages: write`, or the
  workflow was triggered from a fork (a fork's `GITHUB_TOKEN` is read-only by design).
- **The tag step is skipped** — it only runs for a `push` to `main`. That is deliberate:
  a scheduled or manual run must not invent a version.
- **`buildx failed` only on arm64** — QEMU emulation is slow enough that the node build
  can time out. Check whether the failure is a timeout before assuming a real break.
- **The image built but the dashboard is the placeholder** — the `web` stage silently
  produced nothing, so `COPY --from=web` copied the committed placeholder. Confirm
  `npm run build` ran and that vite's `outDir` still points into
  `internal/server/dist`.

Do not add a Docker Hub push. GHCR is the only registry by decision; a second one means
another credential to rotate for no benefit.
