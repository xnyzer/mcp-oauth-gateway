---
id: F-008
title: Create the hard fork of sigbit/mcp-auth-proxy
type: feature
status: DONE
size:
created: 2026-06-25
done: 2026-06-25
depends-on:
superseded-by:
---

# F-008 — Create the hard fork of sigbit/mcp-auth-proxy

## History

### F-008 — Create the hard fork of sigbit/mcp-auth-proxy — DONE 2026-06-25

**Problem:** F-001 chose `sigbit/mcp-auth-proxy` (Go + Ory Fosite, MIT) as the base, but no
project code existed yet; the gap-closing work (F-005) needs a clean fork to build on.

**What was done** (three substeps, all green; baseline kept faithful — rebrand is F-010,
provider-trim is F-011):

- **F-008a — Import + green baseline:** imported the upstream Go source (`main.go`, `pkg/**`,
  `go.mod`, `go.sum`, `Dockerfile`) at commit `76cf8e0`; renamed the module path
  `github.com/sigbit/mcp-auth-proxy/v2` → `github.com/xnyzer/mcp-oauth-gateway`; `go build`/`go test`
  green (all packages), gofmt/vet clean. Added `FORK.md` (provenance) and the Go-specific
  **§11** to `CODING-STANDARDS.md` (closes the F-002 follow-up); updated the stack note and
  `.gitignore` (Go artefacts).
- **F-008b — License & NOTICE hygiene:** kept the Apache-2.0 `LICENSE`; added `NOTICE` retaining
  sigbit's full **MIT** attribution + the forked commit; documented the fork in `README.md`.
  `go-licenses check` clean → **no GPL/AGPL/LGPL**. Found 3 weak-copyleft **MPL-2.0** deps
  (`go-sql-driver/mysql`; `hashicorp/go-retryablehttp`/`go-cleanhttp`) — MPL-2.0 is
  Apache-compatible; **accepted** by the user.
- **F-008c — Dependency pruning + CI:** dropped the unused **MySQL + Postgres GORM drivers**
  (standardised on bbolt default + SQLite), which also removed the `go-sql-driver/mysql` MPL dep;
  `go mod tidy`. OTel + `mongo-driver` + the two hashicorp MPL deps stay (transitive via Ory
  Fosite/`ory/x`, unavoidable without dropping Fosite — documented). Added
  **`.github/workflows/ci.yml`** (gofmt, vet, build, test + `go-licenses` check, pinned to the
  go.mod Go version); **CI verified green** on first push (actions later bumped to
  `checkout@v7`/`setup-go@v6` to clear the Node 20 deprecation).

**Decisions:**
- Fork lives in **this** repo; module path `github.com/xnyzer/mcp-oauth-gateway`.
- Persistence standardised on **bbolt (default) + SQLite**; MySQL/Postgres removed (re-addable
  later if F-004's persistence decision calls for it).
- MPL-2.0 (weak copyleft, Apache-compatible) accepted for the unavoidable Fosite-transitive deps.

**Files changed:** `main.go`, `pkg/**` (import), `go.mod`, `go.sum`, `Dockerfile`, `FORK.md`,
`NOTICE`, `README.md`, `CODING-STANDARDS.md`, `.gitignore`, `.github/workflows/ci.yml`,
`pkg/repository/sql.go`, `pkg/mcp-proxy/main.go`.
