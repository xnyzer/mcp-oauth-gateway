# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks / backlog** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

Everything top-down: nothing here is built yet; this is the path from spec → working gateway. **F-001 (build-vs-fork) is the first work item.**

---

## Done

| Step | Description | Completed |
|------|-------------|-----------|
| F-001 | Build vs fork evaluation → **decided: hard-fork `sigbit/mcp-auth-proxy`** (Go + Ory Fosite), validated by a live Claude PoC. Detail in `PROGRESS-ARCHIVE.md`. | 2026-06-25 |
| F-002 | Language + OAuth library → **decided: Go + Ory Fosite** (follows the F-001 fork base). | 2026-06-25 |
| F-003 | DCR vs CIMD → **decided: support both, CIMD-first with DCR as deprecated fallback** (spec 2025-11-25). | 2026-06-25 |

---

## Open tasks

### F-004 — Complete the spec (make it implementable)

**Problem:** The requirements describe intent but not the implementable contract (exact endpoints, schemas, data model, config).

**Idea:** Turn the requirements into precise, RFC-conformant contracts.

**Possible implementation:**
- API contracts: exact endpoint paths, request/response schemas, token claims, error formats (RFC-conformant) for all FRs.
- Data model & persistence (clients, keys, sessions) — choose a store (e.g. SQLite/file).
- Config schema (env vars), defaults, example `docker-compose.yml`, `Dockerfile`.
- Key management: generation on first run, storage, **rotation** strategy.

**Dependencies:** F-002, F-003.

---

### F-005 — Implement on the chosen base (sigbit fork)

**Problem:** The gateway does not exist yet. F-001 chose to hard-fork `sigbit/mcp-auth-proxy`; the base already provides much of this, so the work is **closing the gaps** to our spec/security bar — glue only, no hand-rolled crypto (see `THREAT-MODEL.md`).

**Idea:** Build on the fork (F-008). Keep/verify what sigbit already does (in-process fail-closed enforcement, streaming proxy, embedded persistence, ACME); add and harden the missing pieces below.

**Possible implementation:**
- Discovery (PRM/AS metadata), DCR, authorize+token (PKCE), JWKS, login (passkey), consent.
- Upstream proxy with streaming passthrough + configurable upstream auth injection.
- Rate-limiting, DCR-client expiry/caps, structured auth logging.

**Gap list vs the sigbit fork base (from F-001 code review):**
- **RFC 8707 audience-binding** — sigbit hardcodes `aud` to `externalURL`; bind tokens to the actual MCP resource.
- **CIMD client-registration** — absent; add Client ID Metadata Document resolution (CIMD-first per spec 2025-11-25, see F-003/F-009).
- **`WWW-Authenticate` on the `/mcp` 401** — sigbit returns a bare 401 JSON; emit `Bearer resource_metadata="…"` so clients can discover the PRM.
- **`/revoke` route (RFC 7009)** — storage supports it but no HTTP endpoint is wired.
- **Complete PRM/AS-metadata** — advertise `jwks_uri`/introspection/revocation; PRM is currently thin.
- **RFC 9207 `iss`** in the authorize response.
- **Key management** — rotation + optional ES256 (sigbit ships a single static RS256 key).
- **Self-contained auth** — replace the bcrypt single-shared-secret with passkey/WebAuthn + a real user model.

**Dependencies:** F-004, F-008.

---

### F-006 — Verify against Claude + security review

**Problem:** Nothing ships without verification against real clients and a security review.

**Idea:** End-to-end verify, then a mandatory security review before any public exposure.

**Possible implementation:**
- Local/tooling: discovery valid; DCR works; authorize+token+PKCE round-trip; JWKS; expired/invalid token → 401 (fail-closed); rate-limits fire.
- **Claude web custom connector first** (easier to debug), then **Claude iOS**.
- Negative tests (no token / tampered token / replay).
- **Security review** before any public exposure.

**Dependencies:** F-005.

---

### F-007 — Release hygiene

**Problem:** A public release needs usage docs, SemVer, and license/NOTICE hygiene.

**Idea:** Finalise documentation and release artifacts.

**Possible implementation:**
- README usage docs (front an MCP server; add as a connector), SECURITY.md, SemVer, NOTICE.
- CI with OAuth/MCP conformance tests.
- Verify all dependencies are permissive-licensed (no GPL/AGPL).

**Dependencies:** F-006.

---

## Feature ideas (backlog)

_New ideas beyond the path above are intaked via `/add-feature` and get the next F-number._

### F-008 — Create the hard fork of `sigbit/mcp-auth-proxy`

**Problem:** F-001 chose `sigbit/mcp-auth-proxy` (Go + Ory Fosite, MIT) as the base, but no project repo exists yet; all gap-closing work (F-005) needs a clean fork to build on.

**Idea:** Stand up our own hard fork as the project's codebase — owned and maintained by us from day one (not tracking upstream), licence-clean and lean.

**Possible implementation:**
- Import the source into our repo; retain the upstream **MIT LICENSE/NOTICE** alongside our Apache-2.0 (`NOTICE` file) — both permissive, no GPL/AGPL.
- Prune unused transitive dependency trees (ory/x, OpenTelemetry, mongo-driver) to shrink the audit/supply-chain surface.
- Establish project layout + CI (build/test); baseline must compile and pass the existing unit tests.
- Record provenance (the upstream commit forked from) for future security tracking.

**Dependencies:** F-002, F-003 (both DONE).

**Assessment:** Medium — ~4.2k LoC imported, ~150–250 lines authored across ~10–15 files. Decomposed into three substeps. Build/test natively with Go 1.26 (installed); CI uses a pinned `golang:1.26` image.

#### F-008a — Import + green baseline
- **What:** Import the sigbit source into this repo; rename the module path `github.com/sigbit/mcp-auth-proxy/v2` → `github.com/xnyzer/mcp-oauth-gateway`; fix imports; record upstream provenance (forked commit). Add the **Go-specific section** to `CODING-STANDARDS.md` (closes the F-002 follow-up). Baseline stays faithful (all providers + `mcp-warp` binary name kept — rebrand is F-010, provider-trim is F-011).
- **Files:** Go source tree (`main.go`, `pkg/**`, `go.mod`, `go.sum`, `Dockerfile`), `CODING-STANDARDS.md`, provenance note (README/NOTICE).
- **Acceptance:** ✅ DONE 2026-06-25
  - [x] `go build ./...` succeeds
  - [x] `go test ./...` green (all packages)
  - [x] no `sigbit/mcp-auth-proxy` import path remains (module `github.com/xnyzer/mcp-oauth-gateway`)
  - [x] upstream commit hash recorded (`FORK.md`: `76cf8e0`)
  - [x] Go section added to `CODING-STANDARDS.md` (§11)
- **Dependencies:** F-002, F-003.

#### F-008b — License & NOTICE hygiene
- **What:** Keep the Apache-2.0 `LICENSE`; add a `NOTICE` retaining sigbit's **MIT** attribution + the forked commit; document the fork in `README.md`; run a dependency license scan (e.g. `go-licenses`) → confirm **no GPL/AGPL**.
- **Files:** `LICENSE` (keep), `NOTICE` (new), `README.md`, license report.
- **Acceptance:** ✅ DONE 2026-06-25
  - [x] `NOTICE` present with sigbit MIT credit + provenance
  - [x] `README.md` documents the fork origin
  - [x] license scan shows no GPL/AGPL/LGPL (`go-licenses check` clean)
  - Note: 3 weak-copyleft **MPL-2.0** deps found — `go-sql-driver/mysql` (drop in F-008c) + `hashicorp/go-retryablehttp`/`go-cleanhttp` (transitive via Ory Fosite, unavoidable). MPL-2.0 is Apache-compatible; accepted.
- **Dependencies:** F-008a.

#### F-008c — Dependency pruning + CI
- **What:** Best-effort prune (see explanation): drop unused **GORM postgres/mysql drivers** if standardising on bbolt/SQLite; `go mod tidy`; assess OTel removal; `mongo-driver` stays (transitive via `ory/x`) — document. Add **GitHub Actions CI** (build, test, license check, pinned Go 1.26).
- **Files:** `go.mod`, `go.sum`, storage/provider imports, `.github/workflows/ci.yml`.
- **Acceptance:** ✅ DONE 2026-06-25
  - [x] `go mod tidy` clean
  - [x] unused drivers removed — MySQL + Postgres GORM drivers dropped (keeps bbolt default + SQLite); this also removed the `go-sql-driver/mysql` MPL dep. Limits documented: OTel + `mongo-driver` + the two hashicorp MPL deps are transitive via Ory Fosite/`ory/x` and cannot be pruned without dropping Fosite.
  - [x] CI added (`.github/workflows/ci.yml`: gofmt, vet, build, test, license check on pinned go.mod version) — green status verified on first push.
- **Dependencies:** F-008a (F-008b first, to reuse the license scan).

---

### F-009 — Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)

**Problem:** `REQUIREMENTS.md` §0/FR-2 still frame **DCR** as the registration mechanism, but the MCP authorization spec **2025-11-25** makes **CIMD** the recommended path (SHOULD) and **deprecates DCR** (MAY, fallback). RFC 9207 `iss` and OIDC Discovery (as an RFC 8414 alternative) are newly relevant too.

**Idea:** Bring the source-of-truth docs in line with the current spec so F-003/F-004/F-005 build to the right contract.

**Possible implementation:**
- REQUIREMENTS §0: note CIMD-first / DCR-deprecated; add RFC 9207 `iss` and OIDC-Discovery-as-alternative.
- FR-2: reframe as CIMD primary, DCR fallback; cross-reference F-003.
- Note the 2026-07-28 release candidate as a watch item (re-verify before release).

**Dependencies:** none (documentation).

---

### F-010 — Rebrand the fork to mcp-oauth-gateway

**Problem:** The imported sigbit code carries upstream branding — binary name `mcp-warp`, "SigBit" identifiers, upstream URLs in help/docs. For a distinct, maintained project these should be our own (without touching auth logic).

**Idea:** Rename the project's surface (binary/CLI, version/user-agent strings, embedded help/links, Dockerfile entrypoint, README) to mcp-oauth-gateway; keep upstream attribution in NOTICE.

**Possible implementation:**
- Rename built binary `mcp-warp` → `mcp-oauth-gateway`, the Cobra root command, and version/User-Agent strings.
- Update embedded help text/links, `Dockerfile` entrypoint, README.
- **Do not** remove the upstream MIT credit in `NOTICE` (see F-008b).

**Dependencies:** F-008.

---

### F-011 — Trim bundled auth providers to the self-contained model

**Problem:** sigbit bundles hosted-IdP login backends (Google, GitHub) plus generic OIDC. The project's goal is **no mandatory third-party IdP** (FR-4: self-contained now, self-hosted OIDC later) — the hosted-IdP providers are out of scope and add attack/dependency surface.

**Idea:** Decide which login backends to keep; remove the hosted **Google/GitHub** providers, keep the self-contained password/passkey path as default, and decide keep-vs-defer for **generic OIDC** (wanted later for self-hosted IdPs).

**Possible implementation:**
- Remove Google/GitHub provider packages + their config flags and any deps they alone pull in.
- Keep generic OIDC behind config (off by default) for future self-hosted-IdP use, or defer it — record the decision.
- Ensure self-contained login stays the default; update config docs and example env.

**Dependencies:** F-008. Relates to F-005 (passkey/WebAuthn + user model).

---

<!-- FEATURE-INDEX
next-feature: F-012
F-001 Build vs fork evaluation (do first) (DONE)
F-002 Choose language + OAuth library (DONE)
F-003 DCR vs CIMD decision (DONE)
F-004 Complete the spec (make it implementable)
F-005 Implement on the chosen base (sigbit fork)
F-006 Verify against Claude + security review
F-007 Release hygiene
F-008 Create the hard fork of sigbit/mcp-auth-proxy
F-009 Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)
F-010 Rebrand the fork to mcp-oauth-gateway
F-011 Trim bundled auth providers to the self-contained model
-->
