# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build the dashboard. Its output is embedded into the Go binary, so this stage
# has to run first and the published image always ships the real UI rather than
# the committed placeholder.
#
# --platform=$BUILDPLATFORM pins this to the native builder. The output is
# plain JS and HTML, identical for every target arch, so running it once per
# architecture under QEMU emulation would multiply the slowest step in the
# build for no difference in output.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine AS web

WORKDIR /web

# Manifests first so the dependency install is cached independently of source.
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY web/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Build the Go binary. CGO is off so the result runs on a bare Alpine layer
# without a libc shim — and so this stage can also stay on the native builder
# and cross-compile via GOOS/GOARCH. Emulating the compiler instead would make
# an arm64 build several times slower for a byte-identical result.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Copy the manifests first so dependency resolution is cached independently of
# the source. There are no third-party modules today; this keeps it that way
# cheaply if any are added.
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY internal ./internal

# Replace the committed placeholder with the real bundle before go:embed runs.
COPY --from=web /internal/server/dist ./internal/server/dist

# The cache is keyed by target arch so the two cross-compiles do not evict
# each other's objects on every build.
RUN --mount=type=cache,target=/root/.cache/go-build,id=go-build-${TARGETOS}-${TARGETARCH} \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/torpool ./cmd/torpool

# ---------------------------------------------------------------------------
# Runtime: Alpine's community tor, which tracks the latest release. The package
# already ships the GeoIP databases at /usr/share/tor, which is what makes
# exit-node country lookups work over the control port.
# ---------------------------------------------------------------------------
FROM alpine:latest

LABEL org.opencontainers.image.title="tor-pool" \
    org.opencontainers.image.description="Pool of Tor SOCKS5/HTTP proxies behind one sticky endpoint, with failure-driven circuit remediation and a live management dashboard." \
    org.opencontainers.image.source="https://github.com/lncrawl/tor-pool" \
    org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache tor ca-certificates

COPY --from=build /out/torpool /usr/local/bin/torpool

# torpool runs as the tor user created by the apk package, and owns the state
# directory it hands to each instance.
RUN mkdir -p /var/lib/tor && chown -R tor:tor /var/lib/tor && chmod 700 /var/lib/tor

ENV DATA_DIR=/var/lib/tor \
    POOL_SIZE=5 \
    SOCKS_PORT=9250 \
    HTTP_PORT=9251 \
    API_PORT=8080

# SOCKS5 proxy, HTTP proxy, dashboard/API. Instance ports stay on container
# loopback and are deliberately not exposed.
EXPOSE 9250 9251 8080

USER tor

# No shell wrapper: torpool is PID 1 on purpose, because it owns and must reap
# the tor child processes.
ENTRYPOINT ["/usr/local/bin/torpool"]
