---
id: F-011
title: Trim bundled auth providers to the self-contained model
type: feature
status: DONE
size:
created: 2026-06-25
done: 2026-07-03
depends-on:
superseded-by:
---

# F-011 — Trim bundled auth providers to the self-contained model

## History

### F-011 — Trim bundled auth providers to the self-contained model — DONE 2026-07-03

**Problem:** sigbit bundled hosted-IdP login backends (Google, GitHub) plus generic OIDC. The
project's goal is **no mandatory third-party IdP** (FR-4: self-contained now, self-hosted OIDC
later) — the hosted-IdP providers were out of scope and added attack/dependency surface.

**Idea:** Remove the hosted **Google/GitHub** providers, keep the self-contained password path
as default, and decide keep-vs-defer for **generic OIDC**.

**Dependencies:** F-008 (DONE). Done before F-005's auth rework, as planned.

#### F-011a — Remove the Google/GitHub providers
- Deleted `pkg/auth/google.go`, `pkg/auth/google_test.go`, `pkg/auth/github.go`,
  `pkg/auth/github_test.go` (~680 lines).
- `pkg/auth/auth.go`: removed the Google/GitHub auth/callback endpoint constants (only the
  deleted files used them).
- `pkg/mcp-proxy/main.go`: removed 10 `Run()` parameters and the Google/GitHub provider
  construction blocks; the generic `providers []auth.Provider` wiring is unchanged.
- `main.go`: removed 10 CLI flags + env bindings (`GOOGLE_CLIENT_ID/SECRET`,
  `GOOGLE_ALLOWED_USERS/WORKSPACES`, `GITHUB_URL/API_URL/CLIENT_ID/CLIENT_SECRET/`
  `ALLOWED_USERS/ALLOWED_ORGS`), their locals, CSV parsing, and pass-through.
- `pkg/auth/templates/login.html`: removed the `.google`/`.github` button styles.
- Tests: adapted 4 `proxyRunnerFunc` literals in `main_test.go` and 2 `Run()` call sites in
  `pkg/mcp-proxy/main_test.go` to the new signature.
- `go mod tidy` dropped the transitive **`cloud.google.com/go/compute/metadata`** dependency
  (only pulled in via `golang.org/x/oauth2/google`); `golang.org/x/oauth2` itself stays (used
  by the OIDC provider and the Provider interface).
- Acceptance verified: gofmt/vet/build/tests green (8 packages); `--help` lists no
  google/github flags; no provider references left outside attribution (NOTICE/FORK.md) and
  PROGRESS docs.

#### F-011b — OIDC decision + self-contained default verified
- **Decision: keep generic OIDC, off by default** (active only when `OIDC_CONFIGURATION_URL` +
  client ID/secret are configured). Rationale: FR-4 explicitly plans "external self-hosted
  OIDC later"; the code exists, is tested (483-line test file), and is inert without config.
  Deleting would mean rebuilding later. Trade-off accepted: F-005's auth rework must keep it
  compiling.
- **Smoke test passed:** gateway started with password-only config (`--no-auto-tls`, local
  ports, throwaway data dir) — `/.auth/login` returned 200 rendering only the password form
  (the two `provider-button` grep hits are the CSS rules, no rendered buttons);
  unauthenticated `/mcp` → 401 (fail-closed intact). Test binary/data cleaned up.

**Security effect:** reduced attack surface (SR-10) and dependency surface (SR-11); no
token/PKCE/JWKS/DCR/consent code touched; self-contained login confirmed as default.

**Files changed:** deleted `pkg/auth/{google,google_test,github,github_test}.go`; edited
`main.go`, `main_test.go`, `pkg/auth/auth.go`, `pkg/mcp-proxy/main.go`,
`pkg/mcp-proxy/main_test.go`, `pkg/auth/templates/login.html`, `go.mod`, `go.sum`, `CLAUDE.md`
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).
