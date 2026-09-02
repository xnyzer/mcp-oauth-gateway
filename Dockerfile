# Builder — digest-pinned (audit M9; CODING-STANDARDS §7: no floating tags).
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app

ARG TARGETARCH
ARG TARGETOS
# VERSION is injected by the release workflow (git tag); local builds are "dev".
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
    -ldflags "-w -s -X github.com/xnyzer/mcp-oauth-gateway/pkg/version.Version=${VERSION}" \
    -o /app/bin/main . \
    && mkdir /app/data-skeleton

# Runtime — distroless static (audit M9): non-root (uid 65532), no shell, no
# package manager, no interpreters; CA roots and tzdata included. Stdio
# upstreams needing an interpreter (npx/uvx) must run as a separate service
# or in a custom image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b

COPY --from=builder /app/bin/main /usr/local/bin/mcp-oauth-gateway
# /data owned by nonroot so a fresh named volume inherits the ownership.
COPY --from=builder --chown=nonroot:nonroot /app/data-skeleton /data

# Non-privileged defaults: a non-root container cannot bind :80/:443 —
# publish host ports onto these instead (e.g. "443:8443").
ENV DATA_PATH=/data \
    LISTEN=:8080 \
    TLS_LISTEN=:8443

USER nonroot

# The binary probes its own /healthz (no curl/shell in the image); the
# plain-HTTP listener serves /healthz in every TLS mode.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/mcp-oauth-gateway", "healthcheck"]

ENTRYPOINT [ "/usr/local/bin/mcp-oauth-gateway" ]
