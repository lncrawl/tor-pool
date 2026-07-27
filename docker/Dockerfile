# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build the Go binary. CGO is off so the result runs on a bare Alpine layer
# without a libc shim.
# ---------------------------------------------------------------------------
FROM golang:1.26-alpine AS build

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Copy the manifests first so dependency resolution is cached independently of
# the source. There are no third-party modules today; this keeps it that way
# cheaply if any are added.
COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/root/.cache/go-build \
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
