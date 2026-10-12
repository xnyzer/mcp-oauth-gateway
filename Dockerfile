# Builder — digest-pinned (audit M9; CODING-STANDARDS §7: no floating tags).
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS builder

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
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

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
