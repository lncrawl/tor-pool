# Development

## The loop

`tor` is not expected on your machine, and there is no supported way to run torpool
outside a container. Everything is verified by rebuilding the image:

```bash
docker compose up -d --build
docker compose logs -f
```

That is slower than `go run`, but it is the only environment the project supports, so
it is also the only one worth testing in.

## Checks

```bash
gofmt -l .            # must print nothing
go vet ./...
go test ./...         # pure logic only — the real test is a running container

# golangci-lint via its image, so nothing is installed on the host
docker run --rm -v "$PWD":/app -w /app golangci/golangci-lint golangci-lint run
```

## Dashboard

```bash
npm --prefix web ci
npm --prefix web run dev        # http://localhost:5173, proxies /api to :8080
npm --prefix web run typecheck
npm --prefix web run build
```

The dev server proxies to a torpool container, so bring one up first. `compose.yml` sets
`AUTH_DISABLED=true`, so there is nothing to sign in with and the dashboard opens straight
to the pool.

To work on the sign-in screen or anything scope-related, put `AUTH_DISABLED=false` and an
`ADMIN_PASSWORD` in your `.env` — set the password rather than hunting for the generated one
in `docker compose logs` every time you recreate the container. The provider asks
`GET /api/auth/status` before it renders either branch, so switching the flag needs a
container restart and a page reload, not a rebuild.

`npm run build` writes into `internal/server/dist`, which `go:embed` picks up — a
committed placeholder lives there so `go build` works without ever running npm. Do not
commit the build output over it: the real `index.html` references a hashed asset that is
not tracked, so a binary built from it serves a broken page. `git checkout
internal/server/dist/index.html` after building locally.

## Docs

These pages are published at [lncrawl.github.io/tor-pool](https://lncrawl.github.io/tor-pool/)
by `docs.yml`, with the README as the landing page. To see a change the way a reader will:

```bash
pip install -r .github/requirements-docs.txt
.github/docs-site.sh          # stage README.md + docs/ into .docs-site/
mkdocs serve                  # http://127.0.0.1:8000
```

`mkdocs serve` watches `.docs-site/`, not the sources it was staged from, so re-run the
script after every edit — including to `docs/` pages, which are copies there.

Write links for GitHub — repo-relative, as the existing pages do. Staging rewrites the ones
into `docs/` to site pages and the rest to the repo, and `mkdocs` builds with `strict: true`,
so a link that resolves in neither place fails the pull request instead of shipping.

## Gotchas

- **`networkidle` never fires.** The dashboard holds an SSE connection open for its
  whole life. Any browser automation must wait on a selector instead.
- **`--network host` does not reach the host on Docker Desktop.** Use
  `--add-host=host.docker.internal:host-gateway` and address the host by that name.
- **A listener bound to container-loopback is unreachable through a port mapping.**
  Listeners bind `0.0.0.0` inside the container on purpose; exposure is controlled by
  the host-side publish.

More context on the invariants: [AGENTS.md](../AGENTS.md).
