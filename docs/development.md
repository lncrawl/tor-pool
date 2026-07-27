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

The dev server proxies to a torpool container, so bring one up first. `npm run build`
writes into `internal/server/dist`, which `go:embed` picks up — a committed placeholder
lives there so `go build` works without ever running npm.

## Refreshing the screenshots

See the header of [`web/scripts/screenshots.mjs`](../web/scripts/screenshots.mjs).
Drive some traffic through the pool first, or every chart is empty.

Playwright is deliberately not a project dependency; it is only needed for this.

## Gotchas

- **`networkidle` never fires.** The dashboard holds an SSE connection open for its
  whole life. Any browser automation must wait on a selector instead.
- **`--network host` does not reach the host on Docker Desktop.** Use
  `--add-host=host.docker.internal:host-gateway` and address the host by that name.
- **A listener bound to container-loopback is unreachable through a port mapping.**
  Listeners bind `0.0.0.0` inside the container on purpose; exposure is controlled by
  the host-side publish.

More context on the invariants: [AGENTS.md](../AGENTS.md).
