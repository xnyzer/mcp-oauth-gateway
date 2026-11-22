---
id: F-010
title: Rebrand the fork to mcp-oauth-gateway
type: feature
status: DONE
size:
created: 2026-06-25
done: 2026-07-03
depends-on:
superseded-by:
---

# F-010 — Rebrand the fork to mcp-oauth-gateway

## History

### F-010 — Rebrand the fork to mcp-oauth-gateway — DONE 2026-07-03

**Problem:** The imported sigbit code carried upstream branding — binary name `mcp-warp`,
"MCP Auth Proxy" identifiers, upstream naming in the Docker entrypoint. For a distinct,
maintained project these should be our own (without touching auth logic).

**Idea:** Rename the project's surface (binary/CLI, MCP client identity, embedded auth pages,
Dockerfile entrypoint) to mcp-oauth-gateway; keep upstream attribution in NOTICE.

**Dependencies:** F-008 (DONE).

#### What was done
- **CLI:** Cobra root command renamed `mcp-warp` → `mcp-oauth-gateway` (`main.go`); help output
  now shows `Usage: mcp-oauth-gateway [flags]`.
- **Docker:** binary install path + entrypoint renamed to `/usr/local/bin/mcp-oauth-gateway`;
  builder image bumped `golang:1.22-bookworm` → **`golang:1.26-bookworm`** (CODING-STANDARDS
  §11 requires a pinned 1.26 image; previously `GOTOOLCHAIN=auto` downloaded the toolchain at
  build time).
- **MCP identity:** upstream-facing `ClientInfo.Name` in `pkg/backend/proxy.go` renamed to
  `mcp-oauth-gateway` (hardcoded `Version: "dev"` left as is — version wiring belongs to F-007).
- **Auth pages:** titles/H1 in `login.html`, `unauthorized.html`, `error.html` → "MCP OAuth
  Gateway" (human-readable form for UI); fixed upstream leftover `lang="ja"` → `lang="en"` in
  `unauthorized.html`.
- **Storage namespace:** bbolt namespace in `pkg/mcp-proxy/main.go` renamed `mcp-oauth-proxy` →
  `mcp-oauth-gateway`.
- **Test fixture:** `X-Forwarded-By` value in `pkg/proxy/proxy_test.go` aligned (test-only,
  production code sets no branded header).
- **Kept (attribution, per F-008b):** `NOTICE` MIT credit, `FORK.md`, sigbit fork references in
  `README.md`.

**Verification:** gofmt/vet clean, build green, full test suite green (8 packages); Docker image
built and smoke-tested (renamed binary runs in the container and prints correct help), test
image removed afterwards.

**Decisions/deviations:**
- bbolt namespace renamed now while pre-release (no existing deployments); after a release this
  would have been a breaking change.
- UI pages use the human-readable "MCP OAuth Gateway", CLI/binary/ClientInfo the technical
  `mcp-oauth-gateway`.
- Go builder-image pin and the `lang="ja"` fix went beyond the task text — standards-driven
  fixes applied while touching those files.

**Files changed:** `main.go`, `Dockerfile`, `pkg/backend/proxy.go`, `pkg/mcp-proxy/main.go`,
`pkg/auth/templates/login.html`, `pkg/auth/templates/unauthorized.html`,
`pkg/auth/templates/error.html`, `pkg/proxy/proxy_test.go`, `CLAUDE.md` (+ `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` bookkeeping).
