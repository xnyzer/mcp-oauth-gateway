# mcp-oauth-gateway — Progress Archive

Full documentation of all finished tasks. Filled by `/coding-kit:step-done`: per completed (sub)step, the complete section from `PROGRESS.md` plus the files actually created/changed, what was concretely implemented, and any notable decisions/deviations from the plan.

> **Reading note.** Entries below name `REQUIREMENTS.md`, a document that existed until **F-026**
> dissolved it into `SPEC.md` (its requirement register is now `SPEC.md` §5, its decisions were
> already archived here). Those entries are left as written: they record what was true when the
> work was done, and rewriting them would falsify the record.

---

## F-001 — Build vs fork evaluation — DONE 2026-06-25

**Problem:** Before any code, decide whether to fork an existing MCP-OAuth gateway or build greenfield, to avoid duplicating work.

**Idea:** Evaluate existing projects at the code level as a possible fork base instead of greenfield.

**Dependencies:** none (first item).

### What was done
Code-level evaluation of two primary candidates (cloned and read, including the relevant
submodules), plus an architecture skim of the secondary field, plus a re-verification of the
current Claude/MCP OAuth requirements, plus a **live end-to-end PoC against Claude**.

**Candidates:**
- **`atrawog/mcp-oauth-gateway`** — ❌ not a fork base. Python/authlib but ~10 months stale;
  GitHub login hardcoded into the authorize/callback flow (no auth-backend abstraction);
  enforcement *is* Traefik ForwardAuth (no in-process gate); Redis threaded through every call
  site (no DAO); RFC 9728 PRM referenced but never served; 1-year auth-code TTL; no unit tests
  for the auth package. Reference only.
- **`sigbit/mcp-auth-proxy`** — ✅ **chosen base.** Go 1.26, MIT, single binary, built on
  **Ory Fosite**. Provides in-process fail-closed bearer enforcement, upstream credential
  injection + hiding, SSE/streaming passthrough, stdio→HTTP MCP bridge, embedded persistence
  (bbolt default / GORM SQLite·Postgres·MySQL) behind a clean storage interface, built-in
  password login with **no third-party IdP**, built-in ACME, X-Forwarded trust gating, decent
  unit tests, active (v2.10.2, 2026-05; single maintainer).
- Skimmed: IBM `mcp-context-forge` (downstream OAuth + heavy stack — wrong layer),
  `tigrisdata/mcp-oidc-provider` (DCR shim but mandates a third-party IdP, DCR-only), Pomerium
  MCP (MCP-client AS, Apache-2.0, but heavy platform leaning on an upstream IdP). `hyprmcp/mcp-gateway`
  archived → excluded.

**PoC (2026-06-25):** sigbit ran in Docker on a self-hosted VM, plain HTTP behind a reverse
proxy doing public TLS (Let's Encrypt wildcard via DNS-01), fronting
`@modelcontextprotocol/server-filesystem`. A full Claude custom-connector round-trip succeeded:
OAuth 2.1 discovery (RFC 8414 + RFC 9728) → built-in password login → consent → token issuance →
proxied MCP tool call (list/read `/tmp`). Local smoke-test confirmed the discovery/DCR/JWKS
endpoints and the fail-closed 401 beforehand.

### Decision
**Build on a hard fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite); not greenfield, not atrawog.**
Rationale: it already nails the security-sensitive plumbing we'd otherwise build from scratch,
under a permissive license, and it works with Claude today. We own and maintain it as our own
fork from day one.

### Spec change found (re-verification)
MCP spec **2025-11-25** makes **CIMD** the recommended client-registration mechanism (SHOULD) and
**deprecates DCR** (MAY, fallback only). Also newly relevant: RFC 9207 `iss` (SHOULD), OIDC
Discovery as an RFC 8414 alternative; RFC 8707 audience-binding stays MUST. → Design should be
**CIMD-first, DCR fallback**. Affects F-003/F-004; **REQUIREMENTS §0 needs updating**.

### Gaps to close after adopting the fork
RFC 8707 audience-binding (sigbit hardcodes `aud` to `externalURL`); CIMD support; RFC 9207 `iss`;
complete PRM/AS-metadata (advertise `jwks_uri`/introspection) and emit `WWW-Authenticate` with
`resource_metadata` on the `/mcp` 401 (sigbit returns a bare 401 JSON with no `WWW-Authenticate`);
add a `/revoke` route; passkey/WebAuthn + a real multi-user model (sigbit is bcrypt
single-shared-secret); key rotation + optional ES256. Risks: single maintainer, hand-rolled
metadata/DCR structs drift, transitive dependency bloat (ory/x, OTel, mongo) to prune. License
MIT→Apache-2.0 is compatible (retain MIT NOTICE).

### Deployment learning (generic)
Claude's cloud connects to remote MCP servers from Anthropic egress range **160.79.104.0/21**
(IPv4, documented). Geo/IP firewalls that block US sources make the connection fail **silently
before any request reaches the gateway** (nothing in gateway logs). A Let's Encrypt wildcard cert
obtained via DNS-01 does **not** prove inbound reachability, and NAT hairpin from inside the LAN
can make a server look externally reachable when it is not.

### Files changed
- `PROGRESS.md` — F-001 marked done; recommendation/decision recorded.
- (Evaluation clones and the PoC ran in throwaway scratch/VM environments outside the repo; no
  gateway code committed yet — implementation starts after the fork is created.)

---

## F-002 — Choose language + OAuth library — DONE 2026-06-25

**Problem:** The implementation language and OAuth library were undecided; everything downstream depends on this.

**Decision: Go + Ory Fosite.**

**Rationale:**
- F-001 chose to hard-fork `sigbit/mcp-auth-proxy`, which is built in **Go** on **Ory Fosite** — adopting it dictates the stack, and re-deciding would mean discarding a working base.
- **Ory Fosite** is a vetted OAuth2/OIDC library (powers Ory Hydra), Apache-2.0 (permissive, no GPL/AGPL), so token issuance/PKCE/JWT stay in library code — satisfies SR-1 (no hand-rolled crypto).
- **Go** yields a tiny static single binary (supports GR-3 single-container), strong streaming-proxy support (FR-8), and broad contributor reach.
- Alternative **Python + authlib** rejected: heavier runtime footprint and would imply greenfield rather than reusing the validated fork base.

**Follow-up:** add the Go-specific section to `CODING-STANDARDS.md` (handled as part of F-008).

**Files changed:** `PROGRESS.md` (moved to Done; F-005 already references the stack).

---

## F-003 — DCR vs CIMD decision — DONE 2026-06-25

**Problem:** Decide the client-registration model — DCR, CIMD, or both.

**Decision: support both — CIMD-first, with DCR retained as a deprecated fallback.**

**Rationale:**
- MCP authorization spec **2025-11-25** makes **CIMD** the recommended mechanism (SHOULD) and **deprecates DCR** (MAY, fallback only). Claude supports CIMD/DCR/Anthropic-creds and prefers CIMD.
- The fork base (sigbit) currently implements **DCR only** (open `/register`, no CIMD). So DCR comes for free as the backward-compat fallback; **CIMD must be added** (tracked as a gap in F-005).
- Not DCR-only (would ignore the now-recommended mechanism and cause registration bloat); not CIMD-only (would drop backward-compat with AS/clients that still rely on DCR).
- Regardless of model, apply **SR-5** DCR-abuse mitigations (rate-limit `/register`, auto-expiry, client cap).
- `REQUIREMENTS.md` §0/FR-2 must be updated to reflect CIMD-first — tracked as **F-009**.

**Files changed:** `PROGRESS.md` (moved to Done).

---

## F-008 — Create the hard fork of sigbit/mcp-auth-proxy — DONE 2026-06-25

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

---

## F-009 — Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first) — DONE 2026-07-03

**Problem:** `REQUIREMENTS.md` §0/FR-2 still framed **DCR** as the registration mechanism, but
the MCP authorization spec **2025-11-25** makes **CIMD** the recommended path (SHOULD) and
**deprecates DCR** (MAY, fallback). RFC 9207 `iss` and OIDC Discovery (as an RFC 8414
alternative) were newly relevant too.

**Idea:** Bring the source-of-truth docs in line with the current spec so F-004/F-005 build to
the right contract.

**Dependencies:** none (documentation).

### What was done
- **§0 Verified background:** CIMD documented as the recommended registration mechanism
  (SHOULD), DCR as deprecated fallback (MAY), cross-referencing the F-003 decision. Added
  **RFC 9207** `iss` (SHOULD), **OIDC Discovery** as an RFC 8414 alternative, RFC 8707
  audience-binding staying MUST, and a **watch item**: re-verify against the MCP spec release
  candidate dated **2026-07-28** before any release. Header note no longer flags a pending
  CIMD update.
- **FR-2** reframed from "DCR, optionally CIMD" to **CIMD-first with DCR as deprecated
  fallback** (HTTPS-URL client IDs resolving to a Client ID Metadata Document); SR-5 abuse
  mitigations still apply to DCR registrations.
- **FR-1** gained an optional OIDC Discovery mirror (`/.well-known/openid-configuration`);
  **FR-3** now requires the RFC 9207 `iss` parameter in the authorization response (matching
  the F-005 gap list).
- **§6** converted from "open decisions" to the decided state (F-001/F-002/F-003/F-008c), with
  multi-user evolution as the only remaining open point.
- **Consistency fixes beyond REQUIREMENTS:** `README.md` headline/Why no longer frame the
  project as a DCR gateway (now OAuth 2.1 gateway, CIMD-first with DCR fallback); `CLAUDE.md`
  status/entry pointer moved to F-010.

**Decisions/deviations:** the §6 cleanup and the README/CLAUDE.md alignment went slightly
beyond the task text (which named only §0/FR-2) — done for doc consistency per the approved
plan. Spec facts (SHOULD/MAY, RC date) taken from the F-001/F-003 verified research; live
re-verification is deferred to the pre-release watch item. Documentation only — no endpoints,
config, or dependencies changed.

**Files changed:** `REQUIREMENTS.md`, `README.md`, `CLAUDE.md` (+ `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-010 — Rebrand the fork to mcp-oauth-gateway — DONE 2026-07-03

**Problem:** The imported sigbit code carried upstream branding — binary name `mcp-warp`,
"MCP Auth Proxy" identifiers, upstream naming in the Docker entrypoint. For a distinct,
maintained project these should be our own (without touching auth logic).

**Idea:** Rename the project's surface (binary/CLI, MCP client identity, embedded auth pages,
Dockerfile entrypoint) to mcp-oauth-gateway; keep upstream attribution in NOTICE.

**Dependencies:** F-008 (DONE).

### What was done
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

---

## F-011 — Trim bundled auth providers to the self-contained model — DONE 2026-07-03

**Problem:** sigbit bundled hosted-IdP login backends (Google, GitHub) plus generic OIDC. The
project's goal is **no mandatory third-party IdP** (FR-4: self-contained now, self-hosted OIDC
later) — the hosted-IdP providers were out of scope and added attack/dependency surface.

**Idea:** Remove the hosted **Google/GitHub** providers, keep the self-contained password path
as default, and decide keep-vs-defer for **generic OIDC**.

**Dependencies:** F-008 (DONE). Done before F-005's auth rework, as planned.

### F-011a — Remove the Google/GitHub providers
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

### F-011b — OIDC decision + self-contained default verified
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

---

## F-004 — Complete the spec (make it implementable) — DONE 2026-07-03

**Problem:** The requirements described intent but not the implementable contract (exact
endpoints, schemas, data model, config).

**Idea:** Turn the requirements into precise, RFC-conformant contracts.

**Dependencies:** F-002, F-003, F-009 (all DONE).

**Prep decisions (user-approved):** contracts live in a new root-level **`SPEC.md`**
(REQUIREMENTS stays intent-level); the fork's **`/.idp/*` endpoint paths are kept** (clients
discover paths via RFC 8414/9728 metadata; the prefix avoids collisions with proxied upstream
paths).

### F-004a — API contracts (SPEC.md §0–§1)
- §0 conventions: issuer = `EXTERNAL_URL` **normalized without trailing slash** everywhere
  (code currently ambiguous — pinned for F-005); RFC 6749 error format; normative
  **public-path list** (SR-7); endpoint overview table (RFC + FR mapping + status).
- Contracts with per-section **Delta notes** (current fork behaviour vs target): complete PRM
  (RFC 9728) and AS metadata (RFC 8414 incl. `jwks_uri`/`revocation_endpoint`/
  `introspection_endpoint`/`authorization_response_iss_parameter_supported`; optional OIDC
  Discovery mirror), **CIMD resolution contract** (HTTPS-URL client IDs, 5 s/64 KiB/no-redirect
  fetch limits, SSRF guards rejecting private/link-local/metadata ranges, mandatory public
  client + PKCE, positive/negative caching), DCR fallback with SR-5 hardening (TTL 30 d
  refreshed on use, cap 100, rate limit, redirect-URI validation), authorize/token with PKCE
  S256 for **all** clients + RFC 9207 `iss` + RFC 8707 `resource`→`aud` (gateway = sole
  resource; other values → `invalid_target`), refresh-token rotation, JWKS with rotation
  window, **`/revoke`** (RFC 7009, no token-existence oracle), introspection (client-auth
  required), **`WWW-Authenticate` contract on the proxy 401** (flagged as the key
  client-compatibility delta), auth pages incl. SR-6 targets, `/healthz`.
- Token-claims table (FR-5/SR-4): `iss`/`sub`/`aud`/`exp`/`iat`/`nbf` + target
  `jti`/`client_id`/`scope`; verification rules on the proxy path.

### F-004b — Data model & key management (SPEC.md §2)
- Entity table (10 entities) with key fields, lifetimes, and bbolt/SQLite mapping onto the
  existing `Repository` interface — including new: **CIMD cache** (in-memory acceptable),
  **revoked-`jti` set** (TTL-bounded), **user** and **passkey credential** schemas (implemented
  in F-005). Expiry sweeper contract: lookups treat expired records as absent (fail-closed).
- Signing keys in the data directory (`keys/<kid>.pem` PKCS#8 0600 + atomic `manifest.json`);
  legacy single-key migration path; `AUTH_HMAC_SECRET` unchanged.
- **Rotation:** interval-triggered (default 90 d), new key active, old key retiring with
  `not_after = ACCESS_TOKEN_TTL + 2×CLOCK_SKEW` (no abrupt session invalidation — NFR);
  JWKS serves active + retiring; atomic manifest rewrite.
- **Revocation semantics:** stateless JWT validation first, then deny-list check; store error
  during check → 503 fail-closed; refresh-token revocation cascades to the grant's access
  tokens.
- Schema-version marker + migration/downgrade policy.

### F-004c — Config schema & deployment (SPEC.md §3 + examples)
- Full env/flag tables: existing options (post-F-011) with validation notes, plus 16 new
  target options (`ACCESS_TOKEN_TTL`, `AUTH_CODE_TTL`, `REFRESH_TOKEN_TTL`, `CIMD_*`, `DCR_*`,
  `RATE_LIMIT_*`, `LOGIN_LOCKOUT_*`, `KEY_ALG`, `KEY_ROTATION_INTERVAL`, `CLOCK_SKEW`,
  `OIDC_DISCOVERY_MIRROR`) with defaults and fail-fast validation.
- **`docker-compose.example.yml`** (placeholders only, GR-5; reverse-proxy TLS assumed,
  built-in ACME noted); Dockerfile unchanged; backward-compatibility policy (old env keys ≥1
  minor release + deprecation warning); structured-log event names fixed.
- `REQUIREMENTS.md` header now marks itself intent-level and points to SPEC.md; `README.md`
  docs list and `CLAUDE.md` key documents updated.

**Verification:** compose YAML parses; all referenced files exist; FR-1–FR-9 coverage and all
10 F-001 gap-list items grep-verified in SPEC.md; secrets scan clean (placeholders only).

**Files changed:** new `SPEC.md` (~480 lines), new `docker-compose.example.yml`; edited
`REQUIREMENTS.md` (header), `README.md` (docs list), `CLAUDE.md` (+ `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005a — Discovery & 401 surface (client-compat quick wins) — DONE 2026-07-06

First substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **Enabling refactor:** `mcpproxy.Run` (34 positional params), `proxy.NewProxyRouter` (8) and
  `idp.NewIDPRouter` (6) now take config structs (`mcpproxy.Config`, `proxy.Config`,
  `idp.Config`) per CODING-STANDARDS §3 — every later F-005 substep adds options without
  signature churn. All test literals/mocks simplified accordingly.
- **Issuer normalization (§0):** `EXTERNAL_URL` is validated at startup — absolute, http(s),
  no path/query/fragment — and normalized **without trailing slash**; single source for AS
  metadata `issuer`, PRM `resource`, JWT `iss`/`aud` comparison, and the RFC 9207 `iss`.
  `proxy.NewProxyRouter` re-normalizes defensively.
- **PRM complete (§1.1):** added `jwks_uri`, `bearer_methods_supported: ["header"]`,
  `scopes_supported: []`, `resource_name`.
- **AS metadata complete (§1.2):** added `jwks_uri`, `introspection_endpoint`,
  `authorization_response_iss_parameter_supported: true`; optional **OIDC Discovery mirror**
  (`OIDC_DISCOVERY_MIRROR`, default false) serves the same document under
  `/.well-known/openid-configuration`. `revocation_endpoint` deliberately deferred to F-005b
  (metadata must not advertise a 404).
- **`WWW-Authenticate` on the proxy 401 (§1.11.2):** `Bearer resource_metadata="<PRM URL>"`;
  with a presented-but-invalid token additionally `error="invalid_token"` (RFC 6750 §3 —
  no error attribute when no token was sent).
- **RFC 9207 `iss` (§1.5):** success via `AuthorizeResponder.AddParameter`; error redirects
  via an `issRedirectWriter` wrapper around fosite's `WriteAuthorizeError` (fosite v0.49 has
  no native RFC 9207 support). All 7 error call sites routed through the wrapper.
- **`CLOCK_SKEW` (§1.11.1):** `jwt.WithLeeway` in proxy token validation; new duration
  flag/env (default 30 s, validated 0–5 m fail-fast; malformed env value panics at startup).

**Verification:** gofmt/vet clean, build green, all 8 packages green. New tests:
metadata field-completeness (AS + PRM), OIDC-mirror on/off, 401 challenge (missing / malformed
/ expired token variants), clock-skew leeway (0 s rejects, 30 s accepts a just-expired token),
issuer normalization negative cases (path/query/relative), `iss` asserted in success and error
redirects of the existing flow tests. Live smoke test: gateway started with a trailing-slash
`EXTERNAL_URL` → normalized issuer in metadata, mirror 200, both 401 challenge variants
correct.

**Files changed:** `main.go`, `main_test.go`, `pkg/mcp-proxy/main.go`,
`pkg/mcp-proxy/main_test.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`,
`pkg/proxy/proxy_test.go`, `SPEC.md` (Delta notes updated to reflect implemented state)
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005b — Token binding & lifecycle — DONE 2026-07-06

Second substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **Upstream bug fixed:** the inherited `RevokeRefreshToken`/`RevokeAccessToken` deleted by
  request ID *used as a storage key*, while records are keyed by signature — revocation was a
  silent no-op (never noticed upstream because no `/revoke` endpoint existed). Both backends
  now delete **all records of the grant by request ID** (KVS: prefix scan in one bbolt
  transaction; SQL: new indexed `request_id` column populated at create). fosite's RFC 7009
  handler then provides the refresh→access cascade for free.
- **Design deviation (documented in SPEC §2.1/§2.4):** the planned revoked-`jti` deny-list
  was replaced by a **record-presence check** — the proxy validates statelessly, then requires
  the token's server-side record to exist (`TokenActive` callback in `proxy.Config`; lookup by
  the JWT's signature segment). Missing record → 401; store error → **503 fail-closed**.
  Same guarantees, no extra entity. `jti` stays as a claim, regenerated per issued token
  (fresh JTI in `Session.Clone()` covers refresh-issued tokens).
- **RFC 8707 (§1.5/§1.6):** `resource` validated at authorize and token endpoints — only the
  issuer is a valid resource; other values → `invalid_target` (error redirect carries `iss`).
  Granted audience already flowed into `aud` via fosite's claims merging.
- **Claims (§1.7):** `jti`, `client_id` (session extra), space-separated `scope`
  (`JWTScopeClaimKey: JWTScopeFieldString`). Side-fix: `exp` previously followed fosite's
  hardcoded 24 h lifespan (the +1 h in `NewJWTSessionWithKey` was dead code, overwritten by
  fosite's `With()`); it now follows `ACCESS_TOKEN_TTL`.
- **`/.idp/revoke` (§1.9):** wired via fosite's `NewRevocationRequest` (client auth, hint
  handling, no token-existence oracle — unknown tokens yield 200). Metadata advertises
  `revocation_endpoint`; `grant_types_supported` reflects a disabled refresh grant.
- **TTL config (§3.2):** `ACCESS_TOKEN_TTL` (1 m–24 h, default 1 h), `AUTH_CODE_TTL`
  (30 s–1 h, default 10 m), `REFRESH_TOKEN_TTL` (0 disables the refresh grant incl. its
  fosite factory; else 1 h–8760 h, default 720 h) — flags + env, fail-fast validated.
- **Sweeper + schema version (§2.1/§2.5):** 5-minute GC goroutine deletes session records
  past TTL+skew (both backends; SQLite compares via `julianday()` because the driver stores
  times as strings with mixed UTC offsets); `EnsureSchemaVersion` marker with fail-fast on
  downgrade, checked at startup.

**Verification:** gofmt/vet clean, all 8 packages green. New tests: `invalid_target` negative
tests at both endpoints; revocation suite (record gone, introspection inactive, refresh
cascade, no oracle, client-auth required); proxy `TokenActive` matrix (active/nil/revoked→401/
store-error→503); TTL fail-fast matrix; revoke-by-request-ID, sweeper, and schema-version
tests for **both** storage backends; `jti`/`client_id` claim assertions. Live smoke test:
`revocation_endpoint` advertised, `/revoke` rejects unauthenticated calls,
`ACCESS_TOKEN_TTL=10s` aborts startup with a clear message.

**Files changed:** `main.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`,
`pkg/proxy/proxy_test.go`, `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`,
`pkg/repository/{interface,kvs,sql}.go`, new `pkg/repository/maintenance_test.go`,
`pkg/utils/rand.go`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005c — CIMD + DCR hardening (SR-5) — DONE 2026-07-06

Third substep of F-005; completes the CIMD-first registration model decided in F-003.

**What was done** (SPEC references in parentheses):
- **CIMD resolver** (new `pkg/cimd`, §1.3): HTTPS-URL client IDs resolved with all limits —
  5 s fetch timeout, 64 KiB size cap, no redirects, no userinfo, port 443 only. **SSRF guards
  run at dial time** (`net.Dialer.Control`), so DNS rebinding cannot bypass them; rejected:
  loopback, RFC 1918/ULA, link-local (incl. cloud metadata services), multicast, unspecified.
  Document validation: `client_id` must equal the fetched URL, redirect URIs follow the
  RFC 8252 scheme rules, `token_endpoint_auth_method` must be `none` (absent is treated as
  `none` — decision: common in real CIMD documents; explicit non-`none` is rejected).
  Positive cache (default 1 h) and negative cache (60 s).
- **Integration as fosite client source** (`clientSource` in `pkg/idp`): `https://` client
  IDs resolve via CIMD, everything else via the DCR store — one hook covers the authorize
  and token endpoints. Resolution failures → `invalid_client`; detail only in logs (SR-8).
  `idp.Config.CIMDResolver` is an interface for testability (stub in idp tests; real HTTP
  resolution tested in `pkg/cimd` with in-package-only test knobs).
- **DCR hardening (§1.4)**: registration TTL (default 30 d) **refreshed on token issuance**
  (`TouchClient`; active clients never expire mid-use); expired registrations treated as
  absent on lookup (fail-closed, no reliance on the sweeper); client cap → `503
  temporarily_unavailable` (never eviction); redirect-URI scheme validation (shared
  `cimd.ValidateRedirectURI`), grant/response-type whitelist, auth-method validation;
  `client_secret_expires_at` in the response; `DCR_ENABLED=false` removes the endpoint and
  the metadata entry. Sweeper extended with `DeleteExpiredClients`.
- **Security finding from the smoke test, fixed immediately:** with DCR disabled the
  unregistered `/.idp/register` path fell through to the catch-all proxy — with a valid
  bearer it would have been **forwarded upstream**. The `/.idp/`, `/.auth/`, and
  `/.well-known/` namespaces are now **reserved**: unmatched paths inside them return `404`
  and never reach the upstream (SPEC §0 updated, regression test added).
- **Storage layer:** `models.Client` gained `CreatedAt`/`ExpiresAt`;
  `RegisterClient(…, expiresAt)`, `TouchClient`, `CountClients`, `DeleteExpiredClients` in
  both backends; dead `marshalClient`/`unmarshalClient` helpers removed.
- **Config (§3.2):** `CIMD_ENABLED` (default true), `CIMD_FETCH_TIMEOUT`, `CIMD_MAX_SIZE`,
  `CIMD_CACHE_TTL`, `DCR_ENABLED` (default true), `DCR_CLIENT_TTL`, `DCR_MAX_CLIENTS` —
  fail-fast validated; disabling both mechanisms aborts startup.

**Verification:** gofmt/vet clean, all 9 packages green. New tests: SSRF matrix (8 cases on
the production config) + document-validation matrix + oversize/redirect/cache tests in
`pkg/cimd`; full CIMD authorize+token round-trip with PKCE incl. `client_id` claim; DCR
cap/TTL/disabled/metadata negatives; expired-client rejection; reserved-namespace regression
test; client lifecycle for both storage backends. Live smoke test: both-mechanisms-disabled
fails fast, DCR-off metadata omits `registration_endpoint`, reserved namespaces 404, `/mcp`
still 401.

**Files changed:** new `pkg/cimd/{resolver,resolver_test}.go`; edited `main.go`,
`pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`, `pkg/proxy/proxy_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `pkg/models/models.go`,
`pkg/repository/{interface,kvs,sql}.go`, `pkg/repository/maintenance_test.go`, `SPEC.md`
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005d — Key management — DONE 2026-07-06

Fourth substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **New `pkg/keys` (§2.2):** `Manager` owns the key set — `keys/<kid>.pem` (PKCS#8, 0600, dir
  0700) plus atomic `keys/manifest.json` (temp file + fsync + rename; crash mid-rotation
  leaves the old manifest intact). Startup fails fast on a manifest referencing a
  missing/corrupt key file or a fingerprint/kid mismatch. Manifest gained `active_since`
  (drives the rotation-interval check); `kid` stays the fork's existing scheme (hex
  SHA-256-prefix of the PKIX public key) instead of the drafted base64url form, so
  outstanding tokens keep verifying across the migration — SPEC §2.2 updated accordingly.
- **Legacy migration (§2.2):** pre-F-005d `data/private_key.pem` is adopted as the active key
  on first start (kid preserved, original file left in place); `JWT_PRIVATE_KEY` env keeps
  working as a **static mode** (no directory, rotation disabled with a startup warning,
  `KEY_ALG` must match the key type).
- **Rotation (§2.3):** interval-triggered (`KEY_ROTATION_INTERVAL`, default 90 d, `0`
  disables, else ≥ 1h) — checked at startup and by the existing 5-minute sweeper; a `KEY_ALG`
  change also rotates at startup. The previous key retires with
  `not_after = now + ACCESS_TOKEN_TTL + 2×CLOCK_SKEW`; sweeping removes it from the manifest
  **before** deleting its file (crash-safe order). New tokens sign only with the active key.
- **ES256 shipped (decision resolved):** fosite v0.49 natively signs/verifies
  `*ecdsa.PrivateKey` (ES256), so both `KEY_ALG=RS256` (RSA-2048) and `ES256` (P-256) are
  supported — no follow-up needed.
- **Multi-key verification end to end (§2.3.3):** the key insight was that fosite's
  introspection validates JWTs through its `jwt.Signer` — a multi-key JWKS alone would have
  broken introspection after rotation. `keys.FositeSigner` implements fosite's `jwt.Signer`:
  signs with the active key (kid header injected **at signing time** — sessions are created at
  authorize time and cloned for refresh, so a session-borne kid could go stale), verifies via
  kid lookup against active + retiring with an alg-match guard (no algorithm confusion).
  `proxy.Config.PublicKey` (single RSA key) was replaced by a
  `VerificationKey func(kid) (pub, alg, ok)` hook backed by the manager; unknown/missing kid
  or alg mismatch → 401. `idp.Config.PrivKey` became `Keys *keys.Manager`.
- **JWKS (§1.8):** serves active + retiring keys (EC params per RFC 7518 §6.2.1, fixed-length
  coordinates) with `Cache-Control: max-age=300`.
- **Config (§3.2):** `KEY_ALG` / `KEY_ROTATION_INTERVAL` flags + env, fail-fast validated.
- **Cleanup:** key helpers moved out of `pkg/utils` (`LoadOrGeneratePrivateKey`,
  `SavePrivateKey`, `LoadPrivateKey`, `PrivateKeyFromPEM`, `GenerateKeyID` deleted; secret
  helpers stayed); `NewJWTSessionWithKey` became key-free `NewJWTSession`.

**Verification:** gofmt/vet clean, all 10 packages green. New tests: `pkg/keys` suite
(first-run init, ES256 init, legacy adoption, missing-key/kid-mismatch fail-fast, rotation
persistence, interval/alg-switch triggers, retiring sweep incl. file deletion, rotation
failure leaves manifest intact via read-only dir, static mode, ParseAlg); signer suite
(active-kid injection, validate-across-rotation, reject-after-sweep, ES256 round-trip, forged
alg/kid mismatch); idp integration (`TestKeyRotationKeepsOldTokensValid`: pre-rotation token
introspects active after rotation, JWKS serves both kids, new token carries new kid;
`TestES256TokenIssuance`); proxy multi-key matrix (RS/ES accept, unknown/missing kid,
alg-mismatch, wrong-key 401s); config validation + flag default/env tests. Live smoke test
with the built binary: legacy key adopted with identical kid, `KEY_ALG=ES256` restart rotated
at startup (JWKS = EC active + RSA retiring, correct `not_after`), full password+consent OAuth
flow issued an ES256 token that proxied upstream (200; 401 without token), fail-fast on bad
`KEY_ROTATION_INTERVAL`/`KEY_ALG`, static-mode warning + single-key JWKS + alg-mismatch
abort.

**Files changed:** new `pkg/keys/{keys,manager,manifest,signer}.go` +
`pkg/keys/{manager_test,signer_test}.go`; edited `main.go`, `main_test.go`, `pkg/idp/idp.go`,
`pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`, `pkg/proxy/proxy_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `pkg/utils/{keys,rand}.go`,
`pkg/utils/keys_test.go`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005e1 — User model + passkey/WebAuthn — DONE 2026-07-06

Fifth substep of F-005; first half of the F-005e split (prep decision 2026-07-06: env config
stays the authoritative password source — **Variante A**, user-approved after a pros/cons
walkthrough; B (hash migrated into the user record) was rejected as an operator trap: env
rotation would silently stop working, and it needs a password-change UI that is out of scope).

**What was done** (SPEC references in parentheses):
- **Operator account (FR-4, §1.12):** single persisted `models.User`, bootstrapped on the
  first successful password login; generated 64-char ID doubles as JWT `sub` (§1.7) and
  WebAuthn user handle. The record stores identity, passkeys, and the
  `password_login_disabled` flag — **never a password hash** (Variante A).
- **Storage (§2.1):** `UserStorage` interface on the repository (Get/Create/UpdateUser +
  Add/List/Update/DeleteWebAuthnCredential) implemented for **both backends** (bbolt:
  `user-record` fixed key + `webauthn_credential-` prefix; SQLite: `user_records` +
  `webauthn_credential_records` via GORM auto-migration). Credentials store the marshaled
  go-webauthn credential as JSON so models stays agnostic of the library type.
- **Passkey/WebAuthn (§1.12):** `github.com/go-webauthn/webauthn` v0.17.4 (BSD-3) as the
  vetted ceremony library (SR-1). Public assertion endpoints
  `/.auth/webauthn/login/begin|finish`; session-gated attestation endpoints
  `/.auth/webauthn/register/begin|finish` (existing credentials excluded). RP ID/origin
  derived from the normalized issuer. Ceremony state lives in the cookie session, consumed
  on finish (one finish per begin — replay tested). Fail-closed: clone warning (sign-count
  regression) and a failed sign-count persist both deny the login.
- **Settings page (§1.12):** `/.auth/settings` (+ `settings/password`,
  `settings/credentials/delete` form posts, `SameSite=Lax` CSRF mitigation) — passkey
  list/enroll/delete, password-fallback toggle. Feedback messages are fixed server-side
  texts selected by `?msg=` code (no reflected input). Settings/enrollment additionally
  require the session to belong to the persisted user — OIDC-provider sessions get 403.
- **Fallback rule (§1.12):** disabling the password requires ≥1 passkey; the flag is only
  honoured while a passkey exists — deleting the last one re-activates the password login
  (lockout rescue). Disabled-password logins answer exactly like wrong-password ones
  (uniform body, bcrypt always runs first — no state enumeration, SR-6).
- **Startup check (§3.1):** fail-fast when neither password, OIDC, nor an enrolled passkey
  can log the operator in.
- **Security bug found by test, fixed:** the session-gate middleware (`RequireAuth`)
  redirected unauthenticated requests **without aborting the handler chain** — on bodyless
  (POST) redirects gin's deferred WriteHeader let the downstream handler run and even
  override the 302. Inherited from upstream; now aborts (fail-closed, SR-3).
- **Enabling refactor:** `auth.NewAuthRouter` takes a `Config` struct (CODING-STANDARDS §3);
  templates gained `settings.html` + a shared `webauthn_script.html` (base64url/ArrayBuffer
  helpers + ceremony JS in `login.html`/`settings.html`).
- **Deps:** `go-webauthn/webauthn` v0.17.4 (BSD-3) + transitives (BSD/MIT/Apache-2.0, all
  permissive, verified); test-only `descope/virtualwebauthn` v1.0.5 (MIT).

**Verification:** gofmt/vet clean, all 10 packages green. New tests: full enrollment+login
round-trip with a **virtual authenticator** (bootstrap → enroll → fresh-browser passkey
login → settings reachable → LastUsedAt stamped → replay denied); fallback semantics
(disable refused without passkey, uniform disabled-vs-wrong response, passkey-only login,
auto re-enable after deleting the last passkey); unavailable-before-enrollment; session
gating (anonymous → redirect; foreign/OIDC session → 403); user+credential lifecycle on
both storage backends; auth-backend fail-fast. Live smoke test with the built binary:
fail-fast without backend, bootstrap on first login ("Signed in as admin", no second
bootstrap after restart), settings gated, register/begin returns correct RP options, OAuth
flow issues `sub` = 64-char user ID (not `password_user`), proxied request 200.

**Files changed:** new `pkg/auth/{webauthn,settings}.go`, `pkg/auth/webauthn_test.go`,
`pkg/auth/templates/{settings,webauthn_script}.html`, `pkg/repository/users_test.go`;
edited `pkg/auth/auth.go`, `pkg/auth/auth_test.go`, `pkg/auth/templates/login.html`,
`pkg/models/models.go`, `pkg/repository/{interface,kvs,sql}.go`, `pkg/mcp-proxy/main.go`,
`pkg/mcp-proxy/main_test.go`, `pkg/idp/idp_test.go`, `pkg/utils/rand.go`, `go.mod`,
`go.sum`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005e2 — Rate limits, lockout & auth events — DONE 2026-07-06

Sixth and final substep of F-005; second half of the F-005e split.

**What was done** (SPEC references in parentheses):
- **New `pkg/ratelimit` (SR-5/SR-6, §3.2):** `ParseLimit` for `N/s|m|h` expressions (`0`
  disables, fail-fast otherwise); keyed per-client-IP token buckets on
  `golang.org/x/time/rate` (burst = full window); a gin `Middleware` answering `429` +
  `temporarily_unavailable` and emitting the `rate_limited` event; and a per-account
  `Lockout` (consecutive-failure counter, lock for `LOGIN_LOCKOUT_DURATION`, reset on
  success). Disabled limits/lockouts are typed nils — call sites need no special-casing.
  All state in-memory by design (GR-3, single-instance).
- **New `pkg/authevent` (SR-8, §3.3):** one fixed `"auth event"` log message with a generic
  `event` field (GR-4) + non-secret context. Events wired: `login_ok`/`login_fail`
  (password + passkey, `method` field) in `pkg/auth`; `token_issued` (client_id,
  grant_types) and `register` (client_id) in `pkg/idp`; `revoked` per accepted revocation
  request (RFC 7009 hides token existence, so the event does too); `rate_limited`
  (endpoint) in the middleware.
- **Login hardening (§1.12):** rate limit applied to the password login **and** the passkey
  ceremony endpoints; lockout counts consecutive failed password logins only (passkey
  assertions are cryptographic, not guessable — exempt, documented). A locked account
  rejects even the correct password with a **byte-identical** response to a wrong password
  (SR-6, no lockout oracle); bcrypt always runs first (timing uniformity). The
  disabled-fallback rejection does not count toward the lockout (correct password, not a
  guessing signal).
- **Endpoint wiring:** `TokenRateLimit`/`RegisterRateLimit` handler hooks in `idp.Config`,
  `LoginRateLimit`/`Lockout` in `auth.Config` — routers stay decoupled from the limiter
  types. The 5-minute sweeper also prunes idle rate-limit buckets and expired lockout
  entries.
- **Config (§3.2):** `RATE_LIMIT_REGISTER`/`_TOKEN`/`_LOGIN` (defaults `10/m`/`60/m`/`10/m`),
  `LOGIN_LOCKOUT_THRESHOLD` (default 10; `0` disables) / `LOGIN_LOCKOUT_DURATION` (default
  15m; 1m–24h) — flags + env, fail-fast validated.
- **Dep:** `golang.org/x/time` (BSD-3).

**Verification:** gofmt/vet clean, all 11 packages green. New tests: ParseLimit matrix;
limiter burst/deny/per-key/sweep; lockout threshold/expiry/reset/sweep; middleware 429 +
`rate_limited` event + **TRUSTED_PROXIES client-IP keying** (X-Forwarded-For buckets);
lockout byte-identical uniform response, unlock after duration, streak reset on success;
login rate limit covering the passkey ceremony; register/token 429 matrix with per-endpoint
events; `token_issued`/`register`/`revoked` events; log assertions that no entry carries
passwords, tokens, or client secrets. Live smoke test with the built binary: fail-fast on a
malformed rate limit, `/register` 429 after the bucket, lockout rejects the correct password
uniformly, 429 on the login surface, structured `auth event` JSON lines with correct fields,
no passwords in the log, lockout expiry re-admits, `login_ok` emitted.

**Files changed:** new `pkg/ratelimit/{ratelimit,lockout,middleware,ratelimit_test}.go`,
`pkg/authevent/authevent.go`, `pkg/auth/abuse_test.go`; edited `main.go`, `main_test.go`,
`pkg/auth/{auth,webauthn}.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `go.mod`, `go.sum`, `SPEC.md`
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

---

## F-005 — Implement on the chosen base (sigbit fork) — DONE 2026-07-06 (parent task)

Completed via six substeps (full detail in their sections above): **F-005a** discovery & 401
surface, **F-005b** token binding & lifecycle, **F-005c** CIMD + DCR hardening, **F-005d**
key management, **F-005e1** user model + passkey/WebAuthn, **F-005e2** rate limits, lockout
& auth events.

**Original gap list (from the F-001 code review) — all closed:**
- RFC 8707 audience-binding → F-005b
- CIMD client-registration → F-005c
- `WWW-Authenticate` on the `/mcp` 401 → F-005a
- `/revoke` route (RFC 7009) → F-005b (incl. upstream revoke-no-op bugfix)
- Complete PRM/AS-metadata → F-005a/b
- RFC 9207 `iss` → F-005a
- Key management (rotation + ES256) → F-005d
- Self-contained auth (passkey/WebAuthn + user model) → F-005e1, hardened by F-005e2

**Prep decisions (user-approved), all honoured:** passkey bootstrap via password + session-
gated settings page; ES256 shipped (fosite supports it natively); in-memory rate-limit
state; deps `go-webauthn/webauthn` (BSD-3) + `golang.org/x/time` (BSD-3). Two inherited
security bugs found and fixed along the way: revoke-by-signature no-op (F-005b) and the
RequireAuth chain-continuation after redirect (F-005e1). Next: F-006 (verify against Claude
+ security review).

---

## F-006a — Local end-to-end verification harness — DONE 2026-07-07

First substep of F-006 (verify against Claude + security review). Prep reordered F-006
security-first (audit gates public exposure, so it runs before the live tests): a → F-006b
(adversarial `/audit-code`) → F-006c (live runbook: real CIMD, passkey in browsers, Claude
web/iOS).

**Problem:** No test booted the *assembled* gateway and drove its real HTTP surface. The
per-package tests cover idp/auth/proxy/keys/cimd in isolation; crucially, `idp_test` installs
a mock auth middleware that auto-authorizes and never mounts the proxy — so real password
login gating the authorize flow, and an idp-minted token being accepted by the proxy and
forwarded upstream, were **untested end to end**.

**Idea:** An in-process black-box harness that assembles the gateway exactly as `Run()` mounts
it (session + auth + idp + proxy + real keys + KVS repo on one gin engine) in front of a mock
upstream, wrapped in `httptest`, and drives it over HTTP.

### What was done
- **New test-only files (`package main`, no production code, no new deps):**
  `e2e_harness_test.go` (gateway builder + helpers: upstream recorder, CIMD stub resolver,
  DCR register, PKCE pair, real login+consent driver, JWKS verifier) and `e2e_test.go` (six
  flow tests).
- **Assembled-gateway coverage (all green):** discovery + self-consistency (PRM / AS-metadata
  / OIDC mirror / JWKS, `code_challenge_methods=[S256]`, RFC 9207 advertised, active kid in
  JWKS); DCR register → **real password login + consent** → authorize; PKCE/S256 authorize →
  token; token verified against the **published JWKS**; audience/issuer/`jti`/`client_id`
  claims; RFC 9207 `iss` in the redirect; proxied `/mcp` call returning 200 with **credential
  injection** (upstream sees the injected bearer, never the client token); fail-closed
  negatives — missing (→ 401 + `WWW-Authenticate` pointing at PRM), tampered, replayed code
  (`invalid_grant`), and **revoked** (RFC 7009 → 401 via the proxy's `TokenActive` hook);
  rate-limit 429 + `temporarily_unavailable`; **key-rotation continuity** (`keys.Rotate`, then
  the pre-rotation token still verifies via the retiring key and both kids stay in JWKS);
  reserved-namespace path → 404 (never proxied).
- **Public/confidential and CIMD/DCR both exercised:** confidential client via
  `client_secret_basic`/`_post` + Basic-auth `/revoke`; public client via an **injected CIMD
  resolver stub** (the CIMD URL becomes the `client_id` claim) plus a PKCE-downgrade rejection.

### Decisions / deliberate coverage boundaries
- **CIMD network/SSRF layer stays in `pkg/cimd` units:** the resolver's private-host bypass is
  intentionally unexported ("never exposed via Config"), so a cross-package harness cannot
  drive real localhost CIMD fetches. The happy path here uses a resolver stub (same shape the
  gateway sees for a resolved client); real CIMD over the wire → F-006c live.
- **Expired-but-validly-signed token** cannot be minted black-box (needs the server key) →
  covered in `pkg/proxy` units (`proxy_test.go` exp + clock-skew leeway). The harness covers
  the black-box-mintable negatives (missing/tampered/replayed/revoked).
- **In-process over subprocess:** `Run()` is one ~600-line function that binds ports and only
  exits on SIGINT; the harness composes the same real constructors/mounting instead, giving a
  fast, race-clean, CI-runnable test without port/lifecycle flakiness. (`Run`'s length is an
  audit item for F-006b, not fixed here — refactoring the security-critical assembly right
  before the audit was deliberately avoided.)

**Verification:** `go test ./...` green (all 11 packages), `gofmt`/`go vet ./...` clean,
`go test -race` clean. Six new tests: discovery/self-consistency, auth-code+proxy+revocation
(+4 negative subtests), public-client PKCE via CIMD (+PKCE-required subtest), rate-limit,
key-rotation continuity, reserved-namespace-not-proxied.

**Files changed:** new `e2e_harness_test.go`, `e2e_test.go`; edited `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` (bookkeeping).

---

## F-006b — Security review (adversarial `/audit-code`) + inline fixes — DONE 2026-07-07

Second substep of F-006. Prep ordered it security-first: it gates public exposure, so it runs
before F-006c (live verification).

### Audit
Ran an adversarial full audit via four parallel area agents (auth/login/consent ·
idp/PKCE/DCR/CIMD · keys/JWKS/proxy · config/deploy/deps); **every finding was then re-verified
by the main loop against the actual code path** before reporting. Result in `AUDIT-RESULTS.md`
(gitignored, regenerated): **0 critical, 1 high, 9 medium, 19 low**, no committed secrets, no
fail-open/auth-bypass/token-leak, crypto vetted-library only. Verified-clean positives: aud/iss
binding, RFC 8707/9207, S256-only, no implicit/ROPC grants, kid/alg confusion closed, atomic
crash-safe key rotation, credential injection never leaks the upstream secret, JWKS public-only,
deps pinned & permissive.

Adversarial verification corrected one agent finding: the reported "X-Forwarded-For spoof"
(claimed MEDIUM) is actually LOW — Go's `ReverseProxy` already strips
`Forwarded`/`X-Forwarded-For`/`-Host`/`-Proto` before `Rewrite`, so only `X-Forwarded-Port` was
spoofable.

### Fixes (user chose the "security batch"; each with a regression test)
- **H1 — consent screen (SPEC §1.5):** `handleAuthorizationReturnForm` now renders the client
  identity (`client_id`), redirect target and requested scopes via an auto-escaping
  `html/template`, instead of a bare "Authorize" button. Closes an operator-phishing → token-
  minting path (a logged-in operator could otherwise unknowingly authorize any attacker-hosted
  CIMD client).
- **M1 — CIMD SSRF denylist (SPEC §1.3.2):** `isDisallowedIP` rewritten on `net/netip` to reject
  all non-public ranges the `net.IP` predicates miss — CGNAT `100.64.0.0/10` (incl. Alibaba
  metadata `100.100.100.200`), `192.0.0.0/24`, TEST-NETs, `198.18.0.0/15`, `240.0.0.0/4`,
  broadcast, IPv6 doc, and NAT64 `64:ff9b::/96` — plus IPv4-mapped-IPv6 normalisation; unparseable
  → deny.
- **M2 — `/revoke` fail-closed (SPEC §1.9):** `handleRevoke` now inspects the fosite error and
  writes `503` on a 5xx store failure instead of letting `WriteRevocationResponse` return a
  misleading `200` (which would leave a "revoked" token live).
- **M3 (→LOW) — X-Forwarded-* hygiene:** the transparent backend now explicitly drops all four
  `X-Forwarded-*` headers in the untrusted-peer branch (closing the `X-Forwarded-Port` gap and
  making the "empty `TRUSTED_PROXIES` = nothing trusted" contract explicit).
- **M4 — CIMD DoS bounds:** the resolver cache is now capped (`maxCacheEntries`, expired-purge +
  arbitrary eviction) so unique-client-ID floods can't exhaust memory; and `/.idp/auth` gained a
  per-IP rate limit — **new `RATE_LIMIT_AUTHORIZE`** (flag/env, default `60/m`) wired through
  `main.go` → `mcp-proxy` Config (validated, swept) → `idp` Config → the authorize route.
- **M5 — lockout DoS (`pkg/ratelimit/lockout.go`):** `Fail` now arms the window only on the
  threshold-crossing transition (was: every failure past threshold re-extended it) and resets a
  streak whose window has elapsed — so a remote attacker can no longer keep the sole operator
  permanently locked out with one wrong password per window.
- **M6 — internal-error disclosure (SR-8/§6):** `auth.renderError` logs the cause server-side and
  renders a fixed generic message; the eleven idp `server_error` responses drop the raw
  `err.Error()` description, and the register JSON-bind error returns a generic description.

### Triage of the rest
Deployment/config mediums **M7–M10** (http-issuer warning + Secure flag, bare-IP
`TRUSTED_PROXIES` startup crash, Docker root/interpreters/floating tags, golangci-lint) → folded
into **F-007** (release hygiene). All 19 lows → new backlog task **F-012**.

### Verification
`go test ./...` green (all 11 packages), `gofmt`/`go vet ./...` clean, `go test -race` clean on
the touched packages + the assembled e2e. New/updated tests: lockout re-arm regression;
untrusted X-Forwarded-Port strip + trusted-preserve; `isDisallowedIP` reserved-range matrix;
CIMD cache-bound; revoke-503 via a failing-store wrapper; register-malformed-JSON no-leak;
consent-shows-client-identity+scopes; authorize-endpoint 429; `RATE_LIMIT_AUTHORIZE` config
wiring (defaults + env).

**Files changed:** `pkg/idp/idp.go` (+`idp_test.go`), `pkg/cimd/resolver.go` (+`resolver_test.go`),
`pkg/ratelimit/lockout.go` (+`ratelimit_test.go`), `pkg/backend/transparent.go`
(+`transparent_test.go`), `pkg/auth/auth.go`, `pkg/mcp-proxy/main.go`, `main.go`
(+`main_test.go`), `SPEC.md`, `AUDIT-RESULTS.md` (gitignored); bookkeeping in `PROGRESS.md` /
`PROGRESS-ARCHIVE.md`.

---

## F-006c1 — Deploy + server-side/tooling verification — DONE 2026-07-08

First phase of F-006c (live verification). Deployed the gateway to the operator's environment and
verified the whole public path end to end before involving Claude.

### Target topology (details kept in `private/`, gitignored — GR-5)
Internet → operator's public IP (router port-forward) → **zoraxy** reverse proxy (terminates
publicly-trusted TLS for the connector hostname) → **gateway** in a container on the target host
`:8080` → **upstream MCP = a live Graphiti "Agent Memory" server** (streamable-HTTP, bearer-auth,
itself behind Caddy → graphiti-mcp → neo4j on a separate host).

### Pre-deploy de-risking (local, no public exposure)
- Probed the upstream directly: MCP `initialize` at `/mcp` returns `serverInfo` (streamable-HTTP,
  `Mcp-Session-Id`); root `404`s → so **`PROXY_TARGET` is host-only** (the transparent backend
  joins the inbound `/mcp` onto the target; a target ending in `/mcp` would double it). Verified the
  join behaviour against `httputil` `rewriteRequestURL`.
- **Local dry-run** of the *real binary* against the live upstream, driving the full OAuth flow by
  curl (discovery → DCR → real password login + consent → token → proxied MCP `initialize`): the
  whole chain worked and reached Graphiti with the injected credential. (An initial timeout was a
  red herring — the tool sandbox blocks the Go process's socket to a LAN IP while allowing curl;
  re-running unsandboxed passed. A local Python SSE upstream confirmed the gateway proxies+streams
  SSE correctly and forwards a clean request.)

### Deploy
Minimal **non-root** container (static `linux/amd64` binary on `debian:bookworm-slim` + ca-certs,
no interpreters — sidesteps the M9 heavy release image), `user: 1000:1000`, bind-mounted data dir,
`env_file` for secrets, `unless-stopped`. Config: `EXTERNAL_URL=https://<host>`, `NO_AUTO_TLS=true`,
`LISTEN=:8080`, `TRUSTED_PROXIES=<zoraxy-ip>/32`, `PROXY_TARGET=http://<upstream-host>:<port>`,
`PROXY_BEARER_TOKEN`, `PASSWORD_HASH`, `DATA_PATH=/data`.

### Three real deploy gotchas surfaced + handled
1. **Bare-IP `TRUSTED_PROXIES` aborts startup** (`netip.ParsePrefix: no '/'`) — this is audit
   finding **M8**, hit live. Workaround `/32`; the normalization fix stays in F-007.
2. **`NO_AUTO_TLS=true` required** — an `https` non-loopback `EXTERNAL_URL` otherwise triggers the
   gateway's own ACME and it refuses to start (TLS is terminated by zoraxy).
3. **Docker Compose interpolates `env_file` values** → the bcrypt `$` was eaten (hash length 52,
   login would fail); escaped as `$$`, verified the in-container hash is 60 chars.

### Live verification (through the public URL)
Discovery PRM/AS/JWKS `200` (was `521` with the slot empty); `POST /mcp` no-token → `401` +
`WWW-Authenticate`; `TRUSTED_PROXIES` honoured (client IP resolved as the proxy). Full public
OAuth round-trip (via a throwaway operator password injected only for the test, then removed and
verified absent): DCR → login → consent → token → **proxied MCP `initialize` returned
`"Graphiti Agent Memory"`** — credential injection + SSE streaming confirmed end to end through
zoraxy. Final state: container up, non-root, hash-only login (`PASSWORD` unset, hash intact).

**Files:** new `docs/VERIFICATION.md` (generic runbook — no real IPs/domains/tokens); deploy bundle
in `private/mcp-gateway/` (gitignored); `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping.

**Note:** F-006c2 (Claude web) and the Claude-iOS half of F-006c3 were confirmed the same day —
Claude web + iOS both connect via real CIMD and read/search/write against Graphiti. Remaining open:
passkey enrolment (desktop + iOS) and the tampered/revoked live negatives.

---

## F-006c — Live client verification — DONE 2026-07-08

Second/third phases of F-006c (after F-006c1's deploy). Executed by the operator against the live
deployment; Claude assisted and verified server-side.

- **Claude web connector (F-006c2):** added the gateway as a custom connector; the full OAuth
  flow completed via **real CIMD** (the path F-006a could only stub), and Claude successfully
  **read, searched and wrote** to the live Graphiti upstream through the gateway.
- **Claude iOS (F-006c3):** connects end to end directly in the app; same read/search/write.
- **Passkey / WebAuthn:** enrolled via the session-gated `/.auth/settings` and verified login in
  **Safari (desktop)** and **iOS** (iCloud-Keychain passkey, synced across both). Chrome skipped —
  operator's choice (Apple ecosystem). The operator then **disabled the password fallback**; the
  login page still shows the password field and returns the uniform "invalid password" (SR-6, no
  enumeration — intended), passkey is the sole login, and the env `PASSWORD_HASH` remains as the
  lockout rescue.
- **Live negatives:** no-token / garbage bearer / fake-JWT → `401` (+ `WWW-Authenticate` pointing
  at PRM); reserved `/.idp/*` → `404` (never proxied); `/.idp/revoke` without client auth → `400`.
  Revoked-token→`401` was not scriptable live once password login was off (passkey can't be driven
  by curl) — that exact path is covered by the F-006a assembled e2e.

**Behaviour clarified (not bugs):** browsing the root `https://…/` returns `{"error":"unauthorized"}`
because `/` is the Bearer-protected MCP surface (only Claude carries a token); a direct operator
login redirects there for lack of a dashboard, but the login itself succeeds and Claude's flow
redirects to its own callback instead. No committed code changed in this phase.

## F-006 — Verify against Claude + security review — DONE 2026-07-08 (parent task)

Completed via **F-006a** (assembled-gateway `httptest` e2e harness — the first test to drive an
idp-minted token through the proxy and to exercise the real login), **F-006b** (adversarial
four-agent `/audit-code` with self-verification — 0 critical, 1 high, 9 medium, 19 low — then the
user-chosen security-batch fixes H1/M1–M6 inline, deployment mediums → F-007, lows → F-012), and
**F-006c** (live deploy behind the operator's reverse proxy + end-to-end verification against
**Claude web and iOS** against a live Graphiti upstream, with passkey login).

The gateway is now **running in production and used by Claude on web + iOS**, which is the
project's original goal. Two audit findings were additionally confirmed *live* during the deploy
(M8 bare-IP `TRUSTED_PROXIES` crash; the http-issuer/ACME interaction handled via `NO_AUTO_TLS`).
Remaining before a tagged public release: **F-007** (release hygiene — docs, SemVer, golangci-lint,
the real M7–M10 deployment fixes, and the 2026-07-28 RC re-verify) and the **F-012** backlog.

---

## F-007a — Code fixes: M7 + M8 + manual key-rotation command — DONE 2026-07-08

First F-007 substep (release hygiene): the two remaining code-level audit fixes plus the
SPEC §2.3 ops command deferred from F-005d.

- **M8 — bare-IP `TRUSTED_PROXIES` no longer crashes startup:** new
  `backend.ParseTrustedProxies` / `backend.NormalizeTrustedProxies` accept both documented
  entry forms — CIDR as-is, bare IPs normalised to `/32`·`/128` (4-in-6 unmapped first,
  matching gin); anything else fails fast with a clear message. `Run()` normalises once so
  gin and the transparent backend see the same list; gin's previously ignored
  `SetTrustedProxies` error is now checked.
- **M7 — SPEC §3.1 startup WARNING + cookie `Secure`:** `warnPlainHTTPIssuer` warns on an
  `http` issuer with a non-loopback host (localhost / `*.localhost` / 127.0.0.0/8 / ::1 stay
  silent); the session cookie's `Secure` flag is now "https issuer **or** the gateway itself
  serves TLS" instead of the URL scheme alone.
- **`rotate-key` ops command (SPEC §2.3):** offline cobra subcommand on the data directory —
  same env twins (`DATA_PATH`, `KEY_ALG`, `ACCESS_TOKEN_TTL`, `CLOCK_SKEW`), same retiring
  window as the server, refuses `JWT_PRIVATE_KEY` static mode, prints kid continuity and a
  restart reminder. **Decision:** offline subcommand over signal/admin-endpoint because the
  running manager keeps the key set in memory (it would neither pick up nor reliably preserve
  an on-disk rotation) and an offline command adds no attack surface; the restart requirement
  is documented in the command help and SPEC §2.3.
- **Cobra gotcha:** adding the first subcommand made cobra treat the positional upstream
  target as an "unknown command" — the root command now sets `Args: cobra.ArbitraryArgs`
  (regression caught by the existing root-command tests).

Verification: 13 new test cases (parse/normalise tables, bare-IP constructor + Run-level,
Secure-flag matrix, loopback table, WARNING via zap observer, rotation continuity, static-mode
refusal, flag validation); full suite + `-race` green; live smoke on the built binary (bare-IP
start, WARNING in the JSON log, `/healthz` 200, no-token `/mcp` 401, two `rotate-key` runs with
a correct manifest).

**Files:** `pkg/backend/transparent.go` (+tests), `pkg/mcp-proxy/main.go` (+tests), `main.go`
(+tests), `pkg/keys/manager.go` (comment), `SPEC.md` §2.3, `docs/VERIFICATION.md` (M8 gotcha
scoped to pre-F-007a builds).

---

## F-007b — Container & CI hardening (M9 + M10) — DONE 2026-07-08

Second F-007 substep: the published container image and the CI quality gates.

### M9 — hardened runtime image
- **Runtime switched to `gcr.io/distroless/static-debian12:nonroot`** (digest-pinned, as is the
  `golang:1.26-bookworm` builder): non-root uid 65532, no shell, no package manager, and the
  python/pip/node/npm/curl interpreter surface inherited from sigbit is gone. **Trade-off
  (documented):** stdio upstreams that need `npx`/`uvx` now run as a separate service or a
  custom image — the gateway image stays minimal.
- **Non-privileged in-image defaults** `LISTEN=:8080` / `TLS_LISTEN=:8443` (a non-root container
  cannot bind :80/:443; hosts publish onto them). `/data` is created in-image owned by nonroot,
  so a fresh named volume inherits writable ownership (verified by running `rotate-key` on one).
- **`HEALTHCHECK` without curl:** new `healthcheck` subcommand probes `/healthz` on `LISTEN`
  (redirects count as unhealthy, fail-closed). To make that mode-independent, the plain-HTTP
  listener in both TLS modes now serves `/healthz` directly and redirects everything else
  (`httpFallbackHandler`, deduplicating the two previously copy-pasted redirect handlers).
- **Version wiring:** new `pkg/version` injected via `-ldflags -X` (`VERSION` build arg);
  reported by `--version` and the MCP ClientInfo (was hardcoded `"dev"`).

### M10 — CI quality gates
- **golangci-lint v2.12.2** (pinned; action `golangci/golangci-lint-action@v9.3.0`) with a
  curated `.golangci.yml`: standard linters + `gosec` + `misspell`; `errcheck`/`gosec` off in
  `_test.go` (documented: cleanup-error noise, taint findings against local stubs).
- **First lint run: 76 findings, all triaged.** Real fixes: `ReadHeaderTimeout` on all five
  listeners (Slowloris, SSE-safe), data dir `0700` (SPEC §2.2, pulled from F-012), unchecked
  `json.Unmarshal` of session user info now logged, deprecated `ecdsa.PublicKey.X/.Y` swapped
  for `PublicKey.Bytes()` (JWKS output byte-identical, verified by the suite), best-effort
  cleanup errors made explicit (`_ =`), `Clone()` embedded-selector cleanup. Deliberate
  exceptions carry inline `//nolint:<linter> // reason` (operator-configured stdio exec/OIDC
  fetch/key paths, same-host https upgrade, DCR-secret persistence, endpoint-path G101s).
- **`go-licenses` pinned** to `github.com/google/go-licenses/v2@v2.0.1` (verified locally:
  dependency tree passes).
- **Pulled forward from F-012** (adjacent, tiny): data-dir `0700`; startup errors now exit via
  cobra `RunE` + `os.Exit(1)` instead of `panic()` (root command `SilenceUsage`). F-012 list
  updated.

Verification: gofmt/vet/lint clean, full suite + `-race` green; container smoke — `--version`
reports the injected version, `Config.User=nonroot`, Docker health turns `healthy` via the
in-binary probe, `/healthz` 200 through a published port, `/mcp` without token 401, fresh named
volume writable as nonroot.

**Files:** `Dockerfile`, `.github/workflows/ci.yml`, `.golangci.yml` (new), `pkg/version/` (new),
`main.go` (+tests: healthcheck command, healthURL), `pkg/mcp-proxy/main.go` (+tests:
`httpFallbackHandler`), `pkg/backend/proxy.go`, and lint-driven fixes across `pkg/auth`,
`pkg/cimd`, `pkg/idp`, `pkg/keys`, `pkg/repository`, `pkg/utils`; `SPEC.md` §1.13/§3.3;
`docker-compose.example.yml` (port mapping matches the new image default).

---

## F-007c — Release workflow + install artefacts — DONE 2026-07-08

Third F-007 substep: everything needed to install the gateway from a tag.

- **`.github/workflows/release.yml`** (new): a SemVer tag (`v*.*.*`) builds the multi-arch
  image (linux/amd64 + linux/arm64, QEMU+buildx) and pushes `ghcr.io/<repo>:<version>` +
  `<major>.<minor>` — deliberately **no floating `latest`** (deployments pin versions, SPEC
  §3.3). The tag is injected as the build `VERSION` (→ `pkg/version`). Action majors verified
  current at runtime (docker/setup-qemu@v4, setup-buildx@v4, login@v4, metadata@v6,
  build-push@v7); actionlint clean. The "image pullable after a tag push" acceptance can only
  run with the first real tag → moved to F-007e.
- **`.env.example`** (new): every SPEC §3.1+§3.2 env var, grouped (required / install mode A
  behind a TLS proxy / mode B built-in ACME / listeners+storage / upstream / lifetimes / keys /
  abuse protection / OIDC), defaults documented, placeholders only (GR-5; TEST-NET IPs). The
  Compose `env_file` `$`→`$$` bcrypt pitfall is documented prominently, incl. the 60-char
  in-container check. Also covers `JWT_PRIVATE_KEY`/`AUTH_HMAC_SECRET` as advanced options.
- **`docker-compose.example.yml`**: switched from inline `environment:` to `env_file: .env`;
  gateway relies on the image's built-in `HEALTHCHECK`; upstream gets a placeholder
  `healthcheck` + `depends_on: condition: service_healthy` (with a documented fallback to
  `service_started` for upstreams without a probe).
- **`setup.sh`** (new, universal parts only — no firewall scripting): prompts for the public
  URL + operator password (stdin, hidden, never in argv/history), generates the bcrypt hash
  via `docker run httpd:2.4-alpine htpasswd -niBC 12`, applies the `$`→`$$` escaping, writes
  `.env` (0600) from `.env.example`, refuses to overwrite an existing `.env`, and prints next
  steps incl. the Anthropic-egress (160.79.104.0/21) silent-failure reminder.

**Verified end to end** (scratchpad): piped `setup.sh` run → `.env` correct (0600, escaped
hash); `docker compose up -d --wait` with the F-007b image + env_file + health gating →
upstream healthy → gateway healthy; in-container `PASSWORD_HASH` is the un-escaped 60-char
bcrypt; **login with the real password → 302, wrong password → 400** — proving the whole
escaping chain; workflows actionlint-clean (also fixed the pre-existing SC2046 quoting in
ci.yml's go-licenses step).

**Files:** `.github/workflows/release.yml` (new), `.env.example` (new), `setup.sh` (new),
`docker-compose.example.yml`, `.github/workflows/ci.yml` (quoting).

---

## F-007d — Docs — DONE 2026-07-08

Fourth F-007 substep: the public-facing documentation.

- **`README.md` rewritten as full usage docs** (replacing the "early development / not yet
  released" banner with the audited/live-verified status): quickstart via `setup.sh` +
  compose; **install modes A** (behind a TLS-terminating reverse proxy — `NO_AUTO_TLS`,
  `TRUSTED_PROXIES`, streaming/no-buffering proxy note) **and B** (standalone built-in ACME —
  `TLS_HOST`/`TLS_ACCEPT_TOS`, host 80/443 published onto the non-privileged container
  ports); the **Anthropic-egress firewall note** (160.79.104.0/21 — blocking fails
  *silently*); a step-by-step **Claude custom-connector guide** incl. passkey enrolment and
  disabling the password fallback; upstream fronting (bearer optional, host-only-target path
  gotcha, stdio-needs-own-image note); a **complete §3 config reference** (six grouped
  tables); operations (health, manual + automatic key rotation, backup, auth-event logs,
  version, upgrade policy); endpoint map; security posture.
- **`CHANGELOG.md`** (new, Keep-a-Changelog): `[Unreleased]` section ready to become v0.1.0 —
  everything relative to the forked base (CIMD, discovery, token lifecycle, keys, passkeys,
  abuse protection, packaging), the audit-hardening list, and **upgrade notes** (no
  data-directory compatibility with sigbit/mcp-auth-proxy; legacy single-key adoption).
- **`SECURITY.md`**: scope no longer "once implemented" (it is); supported-versions table
  stays "pre-release" until the F-007e tag flips it.
- **`NOTICE`**: stale `go-sql-driver/mysql` entry removed (dependency dropped long ago),
  license-scan reference updated to the CI job. Attribution (sigbit MIT block) verified.
- **`docs/VERIFICATION.md`**: cross-linked to the README install modes + `.env.example`.

Verified by script: all relative links in README/CHANGELOG resolve; every SPEC §3.1+§3.2 env
var appears in both README and `.env.example`; GR-5 scan clean (only documented public
ranges/TEST-NET addresses).

**Files:** `README.md`, `CHANGELOG.md` (new), `SECURITY.md`, `NOTICE`, `docs/VERIFICATION.md`.

---

## F-007e — Release gate + publish — DONE 2026-07-08

Final F-007 substep — every gate ran, then the operator-gated publish.

### Release gates (all green)
- **MCP 2026-07-28 RC check:** the RC turned out to be **already published** (locked
  2026-05-21; final spec lands 2026-07-28). All six authorization-hardening SEPs verified
  against the gateway: RFC 9207 `iss` supplied on success+error (SEP-2468); DCR tolerates
  `application_type` and accepts RFC 8252 native/localhost redirect URIs (SEP-837);
  issuer-bound tokens (SEP-2352); refresh tokens issued independent of an `offline_access`
  scope, requested scopes granted (SEP-2207/2350); no-path issuer makes both `.well-known`
  suffix forms equivalent (SEP-2351). CIMD-first + DCR fallback unchanged in the RC.
  REQUIREMENTS §0 watch item **resolved**; re-check scheduled at the final spec.
- **govulncheck (new gate):** found **3 reachable vulnerabilities** — fixed by bumping
  `golang.org/x/net` → v0.55.0 (GO-2026-5026), `quic-go` → v0.59.1 (GO-2026-5676), Go
  toolchain → 1.26.5 (GO-2026-5856). Re-scan: 0 reachable; full suite + `-race` green.
- **gitleaks over the entire history** (32 commits): no leaks — cleared the public flip.
- **License sweep:** go-licenses clean; **license decision re-examined with the operator**
  and re-confirmed: **Apache-2.0** over MIT (no patent grant/NOTICE/contribution clause),
  MPL-2.0 (file-copyleft cost without SaaS protection — that would need AGPL) and AGPL
  (adoption cost); memstead-module future favours permissive.
- **Update automation added:** `.github/dependabot.yml` (gomod/docker/actions, weekly) +
  weekly `govulncheck` workflow — dependency vulnerabilities surface automatically
  post-release (documented in SECURITY.md).

### Publish
`chore(release): prepare v0.1.0` pushed together with the 8 pending commits; tag **v0.1.0**
→ release workflow built and pushed the multi-arch image
(`ghcr.io/xnyzer/mcp-oauth-gateway:0.1.0` + `:0.1`, digest `bb5b1216…`). **Operator go/no-go:
repo flipped public** (`gh repo edit`), operator set the GHCR package public + Actions access
"Write" (least privilege); private vulnerability reporting + Dependabot alerts enabled;
GitHub release v0.1.0 published with CHANGELOG notes. Verified as an anonymous user:
`docker pull` works, amd64+arm64 manifests present, `--version` reports `v0.1.0`, container
healthy, discovery 200, tokenless `/mcp` 401.

## F-007 — Release hygiene — DONE 2026-07-08 (parent task)

Completed via **F-007a** (M7/M8 fixes + `rotate-key`), **F-007b** (distroless non-root image,
golangci-lint + go-licenses CI), **F-007c** (release workflow, `.env.example`, health-gated
compose, `setup.sh`), **F-007d** (README usage docs, CHANGELOG, SECURITY/NOTICE) and
**F-007e** (gates + publish). **v0.1.0 is publicly released**: repo public, GHCR image
pullable, all four deployment audit findings (M7–M10) fixed, RC-verified, zero reachable
vulnerabilities, docs complete. Remaining: the F-012 backlog and the final-spec re-check
after 2026-07-28.

---

## F-012a — Fail-fast & crypto/proxy guards — DONE 2026-07-08

First F-012 substep (audit low-severity follow-ups): five independent validation guards from
the F-006b audit lows.

- **Malformed boolean envs abort startup** (`main.go`): `getEnvBoolWithDefault` now accepts
  exactly `true|1|false|0` (words case-insensitive) and panics with a clear message otherwise,
  matching the sibling duration/int parsers — a typo in a security toggle (`DCR_ENABLED`, …)
  can no longer silently disable it. This brings the code in line with the already-normative
  SPEC §3 wording, so no SPEC change was needed.
- **RSA keys below 2048 bits are refused** (`pkg/keys`): `algForKey` checks `N.BitLen()`,
  which covers every ingress path centrally — `JWT_PRIVATE_KEY`, legacy-key adoption, and
  manifest loads all route through `ParsePrivateKeyPEM`/`NewStaticManager`. SPEC §2.2 delta
  noted. **Deployment note (for the F-012e CHANGELOG):** a pre-existing sub-2048 key now
  fails startup (operator-controlled; generated keys were always 2048).
- **`jwt.WithExpirationRequired()`** (`pkg/proxy`): a signed token that omits `exp` no longer
  validates as never-expiring — defence-in-depth; every issued token carries `exp` (§1.7).
- **Redirect-replay body buffering capped at 4 MiB** (`pkg/backend`): named constant
  `maxRedirectReplayBody`; a body over the cap streams through unbuffered via `stitchedBody`
  (buffered prefix + unread remainder, original `Close` preserved) and a 307/308 for it passes
  to the client instead of being followed. **Decision:** fixed constant over a new env var —
  MCP JSON-RPC payloads are orders of magnitude smaller, and the cap only bounds the
  redirect-replay convenience, never the proxy path itself. SPEC §1.11 delta noted.
- **CIMD grant/response-type whitelist** (`pkg/cimd` + `pkg/idp`): new shared
  `IsSupportedGrantType`/`IsSupportedResponseType` (the §1.2 sets) — CIMD documents are now
  validated exactly like DCR registrations (attacker-declared `implicit`/
  `client_credentials`/`token` → `invalid_client`); the duplicate maps in `pkg/idp` were
  replaced by the shared functions (same pattern as `ValidateRedirectURI`). SPEC §1.3 delta
  noted.

Verification: five negative regression tests (bool typos panic; 1024-bit key refused on the
parse and static-manager paths; token without `exp` → 401 without upstream contact; oversized
body → 307 passed through **and** streamed untruncated; CIMD unsupported types →
`invalid_client`); full suite + `-race` green; golangci-lint v2.12.2 (the CI-pinned version)
0 issues; gitleaks over the working tree clean.

**Files:** `main.go` (+tests), `pkg/keys/keys.go` (+new `keys_test.go`), `pkg/proxy/proxy.go`
(+tests), `pkg/backend/transparent.go` (+tests), `pkg/cimd/resolver.go` (+tests),
`pkg/idp/idp.go`, `SPEC.md` (§1.3/§1.11/§2.2 deltas).

## F-012b — Auth-flow hardening — DONE 2026-07-09

Second F-012 substep: six login-path hardening items from the F-006b audit lows, all on
surfaces Claude web/iOS + passkey use live, so the e2e harness had to stay green.

- **`EnforcePKCE: true`** (`pkg/idp`): PKCE is now enforced for **every** client, not only
  public/CIMD ones — confidential DCR clients must send `code_challenge` too. Closes the
  long-standing SPEC §1.5 open delta (the metadata already advertised S256-only). Claude uses
  CIMD/public clients, which were already covered; only confidential DCR clients change.
- **Uniform empty-password** (`pkg/auth`): the empty-password branch that returned a distinct
  "Password is required" body before bcrypt is gone — an empty password now runs the same
  bcrypt comparison and returns the byte-identical uniform "Invalid password" as a wrong one
  (SR-6, no pre-bcrypt oracle), and consequently counts toward the lockout.
- **Constant bcrypt timing** (`pkg/auth`): the comparison loop dropped its early `break`, so
  for a multi-hash `PasswordHashes` config the bcrypt count no longer depends on the match
  index (the in-code uniformity claim now holds; single-hash was already uniform).
- **Dead-branch removal** (`pkg/auth`): the unreachable `if method == "POST"` branch in the
  GET-only `handleLogin` was deleted (POST is wired straight to `handleLoginPost` in
  `SetupRoutes`).
- **Full logout clear** (`pkg/auth`): logout now `session.Clear()` + `Options{MaxAge:-1}`
  instead of deleting only the `authorized` flag — identity, user info, WebAuthn ceremony
  blobs and pending redirect targets are all dropped and the cookie is expired client-side.
- **`redirect_url` same-origin guard** (`pkg/auth`): new pure `safeRedirectTarget` (must start
  with a single `/`, never `//` or `/\`, both scheme-relative in browsers) applied via the
  shared `takeRedirectTarget` at all three login consumers — password login, passkey finish
  (`webauthn.go`), and the OIDC callback. A latent open-redirect invariant closed even though
  only `RequireAuth` writes the value today. SPEC §1.5/§1.12 deltas noted.

**Behaviour-change handling:** `EnforcePKCE: true` broke every confidential-client test that
drove the flow without PKCE. Rather than exempt them, the shared `testAuthFlowWithURL` helper
now appends a shared S256 challenge and the token exchanges send the verifier (idp_test.go);
the four confidential e2e flows (`e2e_test.go`) were threaded through `pkcePair` + a
`code_verifier`, keeping the Claude-representative harness green. A new
`TestConfidentialClientRequiresPKCE` asserts the negative (no `code_challenge` → error, no
code).

Verification: new negatives — confidential-without-PKCE rejected, empty-password response
byte-identical to wrong-password, logout makes the protected route redirect to login again and
expires the cookie, `safeRedirectTarget` table (`//evil`, `/\evil`, `https://evil`, … → `/`);
full suite + `-race` green; golangci-lint v2.12.2 0 issues.

**Files:** `pkg/auth/auth.go`, `pkg/auth/webauthn.go`, `pkg/idp/idp.go`, `SPEC.md` (§1.5/§1.12
deltas); tests `pkg/idp/idp_test.go`, `e2e_test.go`, new `pkg/auth/hardening_test.go`.

---

## F-012c — Login surface: CSRF tokens + discoverable passkey login — DONE 2026-07-09

Third F-012 substep. Two audit lows deliberately bundled because they touch the same login
templates/JS and the live Claude web/iOS + passkey flows — concentrating the behaviour-change
risk in one verify step.

### What was done

**① Per-session anti-CSRF token (defence-in-depth on top of `SameSite=Lax`, SPEC §1.12):**
- New `pkg/utils.GenerateCSRFToken()` — 32 bytes `crypto/rand`, hex (stdlib, no new dep).
- New `pkg/auth/csrf.go` (extracted so `auth.go` stays cohesive): `SessionKeyCSRF` lives with
  the other session keys; `CSRFFieldName`/`CSRFHeaderName` consts; `EnsureCSRFToken` (get-or-
  create, stored in the HMAC-signed session); constant-time `validCSRF` (`crypto/subtle`,
  fail-closed — a missing/empty stored token never matches); `RequireCSRF()` gin middleware
  that checks the `X-CSRF-Token` header **first** (so the JSON WebAuthn fetches never trigger
  form-body parsing, which would consume the ceremony request body) and falls back to the
  hidden `csrf_token` form field.
- Middleware wired onto every state-changing POST on the surface: password login, both
  WebAuthn login ceremonies, both WebAuthn register ceremonies, both settings POSTs
  (`auth.go`), and the consent POST `/.idp/auth/:ar_id` (`idp.go`, on top of its existing
  `ar_id` session binding).
- Token minted + persisted in the GET handlers that render forms: `renderLogin` (`auth.go`),
  `handleSettings` (`settings.go`), `handleAuthorizationReturnForm` (`idp.go`).
- Templates deliver it: a `<meta name="csrf-token">` tag + hidden `csrf_token` fields in
  `login.html`/`settings.html` and the consent form (inline template in `idp.go`); a shared
  `csrfHeader()` JS helper in `webauthn_script.html` adds `X-CSRF-Token` to every WebAuthn
  `fetch()`.

**② Discoverable (usernameless) passkey login (SPEC §1.12, `webauthn.go`):**
- `handleWebAuthnLoginBegin` now calls `BeginDiscoverableLogin()` (empty allow-list), so the
  begin response no longer enumerates the operator's credential IDs to an anonymous caller.
- `handleWebAuthnLoginFinish` uses `FinishDiscoverableLogin` with a single-operator
  `DiscoverableUserHandler` that resolves the sole operator account and validates the asserted
  user handle against its ID (go-webauthn additionally enforces credential ownership + a
  non-blank handle — fail-closed). Clone-warning / sign-count-persist denials unchanged.
- Registration raised from `ResidentKeyRequirementPreferred` to `…Required`, so every newly
  enrolled passkey is guaranteed discoverable.

### Tests

- New `pkg/auth/csrf_test.go` (negatives, acceptance a/b): login POST missing/wrong token →
  `403` (correct token → `302`); session-gated settings POST missing token → `403`; WebAuthn
  login begin missing header → `403`; discoverable begin response omits credential descriptors
  (`allowCredentials`).
- New `TestConsentPostRejectsMissingOrWrongCSRF` in `pkg/idp/idp_test.go`.
- Existing harness threaded through token extraction (acceptance c): `pkg/auth` helpers
  (`passwordLogin`/`enrollPasskey`/`passkeyLogin`/`postLogin`) fetch the token and send it via
  field or header; body-comparison uniformity tests (empty-vs-wrong password, lockout oracle)
  reuse one session so the embedded token is identical; the two discoverable-login tests set
  the virtual authenticator's `Options.UserHandle`; `idp` `testAuthFlowWithURL` + a new
  `postConsent` helper extract the consent token; the root e2e `driveAuthCode`
  (`e2e_harness_test.go`) fetches the login token and the consent token so all five e2e flows
  stay green.

### Decisions / deviations

- **CSRF applied to the public passkey-login ceremony too** (not only the audit-named
  password/consent/settings/register POSTs): the token is minted on the login-page GET and the
  fetch sends it, so it is free defence-in-depth and keeps every state-changing POST uniform.
- **Handler over library user-lookup:** the discoverable handler loads the single operator
  regardless of the raw credential ID (go-webauthn verifies ownership + signature), matching
  the single-operator model.
- **Live/deploy note (rescue path, captured in the SPEC §1.12 delta; CHANGELOG draft belongs
  to F-012e):** a **non-resident** passkey enrolled before F-012c can no longer complete the
  empty-allow-list login. Synced-keychain (iCloud) passkeys are resident → the live setup is
  expected fine. Rescue (unchanged §1.12 lockout-rescue rule): delete the passkey records in
  the data dir → the password fallback re-activates. No real paths/hosts recorded.
- **No new deps, endpoints, or env vars.** `crypto/rand`, `crypto/subtle` are stdlib.

### Verification

Full suite + `go test -race ./...` green; `gofmt`/`go vet` clean; golangci-lint v2.12.2 →
0 issues. The assembled-gateway e2e harness (real login + consent + proxied upstream) exercises
the CSRF-guarded flow end to end; the virtual-authenticator round-trip exercises the
discoverable ceremony.

**Files:** `pkg/utils/rand.go`, new `pkg/auth/csrf.go`, `pkg/auth/auth.go`,
`pkg/auth/settings.go`, `pkg/auth/webauthn.go`, `pkg/auth/templates/{login,settings,
webauthn_script}.html`, `pkg/idp/idp.go`, `SPEC.md` (§1.5/§1.12 deltas); tests
`new pkg/auth/csrf_test.go`, `pkg/auth/{webauthn,abuse,hardening}_test.go`,
`pkg/idp/idp_test.go`, `e2e_harness_test.go`.

---

## F-012d — Persistence hardening — DONE 2026-07-09

Fourth F-012 substep: three persistence-layer audit lows — a TOCTOU-prone DCR cap, missing
SQLite concurrency/durability pragmas, and a session cookie that was only signed (not
encrypted) and shared the raw token secret.

### What was done

**① DCR registration cap enforced inside the write transaction (SR-5, no TOCTOU):**
- `DynamicClientStorage.RegisterClient` gained a `maxClients int` parameter and a new sentinel
  `repository.ErrClientCapReached` (`interface.go`). `maxClients <= 0` means unlimited.
- bbolt (`kvs.go`): count + insert now run in a single `db.Update` transaction; bbolt allows
  one writer at a time, so the cap check cannot race. New `countNonExpiredClients(bucket, now)`
  helper (also used by `CountClients`, DRY). A re-registration of an existing key replaces in
  place and does not count against the cap.
- GORM/SQLite (`sql.go`): count + insert wrapped in `db.Transaction`; new
  `countNonExpiredClientRecords(db, now)` helper (also used by `CountClients`). Same
  re-registration semantics.
- `idp.go handleRegister`: the pre-flight `CountClients` check (the TOCTOU window) is gone; the
  cap is passed to `RegisterClient` and `ErrClientCapReached` maps to `503`
  `temporarily_unavailable`.
- `CountClients` is **kept** on the interface (still used by the maintenance tests as a read
  query) — a deliberate deviation from the plan's "drop if unused" (it is still used).

**② SQLite concurrency/durability (`sql.go`):** new `configureSQLite(db)` runs right after
`gorm.Open`: `SetMaxOpenConns(1)` (single-writer → serialises the cap transaction) plus
`PRAGMA busy_timeout=5000`, `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`. DSN
guidance added to the README config reference (persistent, non-shared, lock-capable path).

**③ Session-cookie key separation (`pkg/mcp-proxy/cookie.go` + `main.go`):** new
`deriveCookieKeys(secret)` expands the 32-byte secret via `crypto/hkdf` (SHA-256, two distinct
context labels) into independent 32-byte auth + AES-256 encryption subkeys; `cookie.NewStore`
now takes both, so the operator session cookie is signed **and** encrypted. Fosite keeps the
**raw** secret as its `GlobalSecret`, so issued/refresh tokens are unaffected — only the
short-lived (`MaxAge` 600 s) operator session cookie changes format and forces a one-time
re-login after upgrade.

### Tests

- New `pkg/repository/cap_test.go`: `TestRegisterClientCapIsAtomicUnderConcurrency` (both
  backends, 40 goroutines vs cap 5 → exactly 5 succeed, 35 `ErrClientCapReached`, final count
  == 5; run under `-race`) and `TestRegisterClientCapAllowsReRegistration` (same ID re-registers
  in place, a new ID is capped).
- New `pkg/mcp-proxy/cookie_test.go`: `TestDeriveCookieKeys` (distinct, 32-byte, deterministic,
  secret-dependent) and `TestSessionCookieIsEncrypted` (a marker stored in the session is not
  present in plaintext in the emitted cookie).
- `maintenance_test.go` updated for the new `RegisterClient` arity (cap `0`).

### Decisions / deviations

- **Cap moved into the storage layer, not a DB unique-constraint:** the count is over
  non-expired records (expiry is inside the JSON blob), so it needs a scan; doing it in the
  same transaction as the insert is the atomic point. `SetMaxOpenConns(1)` makes the SQLite
  case genuinely serial.
- **`CountClients` retained** (plan said drop if unused) — still used by tests as a read query.
- **HKDF for cookie keys, raw secret for fosite:** one configured secret, two purposes, kept
  cryptographically independent — avoids a second env var while giving the cookie its own
  signed+encrypted keys.
- **No new dependencies** (`crypto/hkdf`, `crypto/sha256` are stdlib; bbolt/GORM already present).

### Verification

Full suite + `go test -race ./...` green (incl. the concurrency cap on both backends);
`gofmt`/`go vet` clean; golangci-lint v2.12.2 → 0 issues (one G117 on the kvs client-marshal
carries the same documented nolint as the SQL backend — persisting the DCR secret server-side
is the repository's purpose, SPEC §2.1).

**Files:** `pkg/repository/interface.go`, `pkg/repository/kvs.go`, `pkg/repository/sql.go`,
`pkg/idp/idp.go`, `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/cookie.go`, `README.md`,
`SPEC.md` (§1.12/§2.2 deltas); tests new `pkg/repository/cap_test.go`, new
`pkg/mcp-proxy/cookie_test.go`, `pkg/repository/maintenance_test.go`.

---

## F-012 — Audit low-severity follow-ups — DONE 2026-07-09

Umbrella task closing out the 16 actionable low-severity findings from the F-006b adversarial
audit (the remaining lows after 2 were pulled into F-007b, 2 landed with F-007, and M3/XFF was
fixed in F-006b). Two further notes — introspection accepts any valid access token as auth, and
`handleAuth` persists an authorize request pre-auth — are closed as **accepted, no code change**
(both informational, mitigated by the M4 fixes). Worked in five independently-committed substeps,
each with regression tests incl. negatives, full suite + `-race` + golangci-lint v2.12.2 green,
and its SPEC/README delta in the same commit. Per-substep detail in the F-012a–e sections above.

- **F-012a** (guards, 2026-07-08): bool-parse fail-fast · RSA < 2048 refused ·
  `jwt.WithExpirationRequired()` · redirect-replay body cap (4 MiB) · CIMD grant/response-type
  whitelist shared with DCR.
- **F-012b** (auth flow, 2026-07-09): `EnforcePKCE:true` for all clients · uniform
  empty-password · constant multi-hash bcrypt timing · dead `handleLogin` branch removed ·
  full logout `Clear` + cookie expiry · `safeRedirectTarget` same-origin guard.
- **F-012c** (login surface, 2026-07-09): per-session anti-CSRF token on login/consent/settings/
  WebAuthn POSTs (constant-time, new `pkg/auth/csrf.go`) · discoverable passkey login
  (`BeginDiscoverableLogin`, empty allow-list) + resident-key required.
- **F-012d** (persistence, 2026-07-09): atomic DCR-cap transaction (`ErrClientCapReached` → 503,
  no TOCTOU) · SQLite `SetMaxOpenConns(1)` + WAL/busy_timeout/synchronous/foreign_keys pragmas ·
  HKDF-separated signed+encrypted session cookie (fosite keeps the raw `GlobalSecret`).
- **F-012e** (docs & release, 2026-07-09): `CHANGELOG.md` `[0.1.1]` entry (every behaviour change
  + upgrade notes: one-time operator re-login, stricter startup, resident-passkey rescue);
  `AUDIT-RESULTS.md` (local) findings marked resolved; release-gate `govulncheck` clean
  (0 reachable). **v0.1.1 released:** git tag `v0.1.1` → release workflow green → multi-arch
  (amd64+arm64) image on GHCR as `0.1.1`/`0.1` (metadata-action strips the `v`, as with v0.1.0),
  verified by anonymous `docker manifest inspect`. Operator bumps the live deployment separately.

**Known follow-up (pre-existing) → intaked as F-013, fixed 2026-07-09:**
`.github/workflows/ci.yml` failed to load on every push since v0.1.0 (0 jobs created, GitHub
"No jobs were run") — so the build/test/lint/license CI gate was not actually running. Isolated
to `ci.yml` (the `vulncheck` and `release` workflows run fine). **Root cause (verified with
actionlint), correcting an earlier wrong guess in this note:** it was **not** the
`golangci/golangci-lint-action@v9.3.0` reference (that tag exists and resolves, as do
`actions/checkout@v7` / `actions/setup-go@v6`). The actual bug was a **YAML syntax error** on the
`license-check` job's `run:` line — the value began with a double quote
(`run: "$(go env GOPATH)/bin/go-licenses" check …`), so YAML parsed the quoted scalar and the
trailing ` check …` was invalid, invalidating the whole file. Local checks (`go test ./...`,
`-race`, golangci-lint v2.12.2) were run by hand for every F-012 substep in lieu of the gate.
Fixed in F-013 (block-scalar `run:` + a pinned `actionlint` CI job so a malformed workflow fails
loudly in future).

**Files (umbrella):** see the per-substep sections. **Docs:** `CHANGELOG.md`, `SPEC.md`,
`README.md`, `AUDIT-RESULTS.md` (local), `PROGRESS.md`, `PROGRESS-ARCHIVE.md`; git tag `v0.1.1`.

---

## F-013 — Fix the CI workflow (`ci.yml` never runs) — DONE 2026-07-09

**Problem:** `.github/workflows/ci.yml` had failed to load on every push since v0.1.0 — GitHub
reported "No jobs were run" and created **0 jobs**, so the build/test/`gofmt`/`vet` +
`golangci-lint` + `go-licenses` gate had never actually run (only `vulncheck.yml` and
`release.yml` ran). Surfaced by the operator's repeated GitHub failure emails while closing F-012.

**Root cause (verified with `actionlint`):** the `license-check` job's shell step was
`run: "$(go env GOPATH)/bin/go-licenses" check ./… --disallowed_types=forbidden,restricted`. The
value **begins with a double quote**, so the YAML parser read `"$(go env GOPATH)/bin/go-licenses"`
as a complete double-quoted scalar and the trailing ` check …` was a syntax error ("did not find
expected key"), which invalidates the **entire** workflow file → 0 jobs. An earlier close-out
note had wrongly guessed the `golangci/golangci-lint-action@v9.3.0` reference; that tag resolves
fine (as do `actions/checkout@v7` / `actions/setup-go@v6`) — corrected in the F-012 archive note.

**What was done:**
- Fixed the `run:` step to a block scalar (`run: |` on its own line), so the quoting is preserved
  without the leading-quote parse error.
- Added a new pinned `workflow-lint` job that `go install`s `actionlint@v1.7.12` and lints all
  workflow files (`-shellcheck=` to avoid a shellcheck dependency), so a future malformed workflow
  **fails loudly** instead of being silently dropped by GitHub.
- Ran `actionlint` over all three workflow files locally (clean) before pushing.
- Corrected the inaccurate root-cause note in the F-012 umbrella archive section (and Graphiti).

**Verification:** after the push, the CI run created **4 jobs** (was 0) — `build-test`, `lint`,
`license-check`, `workflow-lint` — and completed **`success`** (all green), confirmed via
`gh api …/actions/runs/<id>/jobs`. So the gate runs and passes again, not merely parses.

**Files:** `.github/workflows/ci.yml`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code
change, no new runtime dependencies.

## F-014 — Bump vulnerable indirect dependencies — DONE 2026-08-20

**Problem:** The weekly `vulncheck` workflow had failed on every run since 2026-07-27, mailing a
failure notice each Monday. Two advisories were reachable from our code, both in indirect
dependencies: GO-2026-6061 (`google.golang.org/grpc` 1.80.0, fixed 1.82.1) and GO-2026-5970 — an
infinite loop on invalid input — (`golang.org/x/text` 0.37.0, fixed 0.39.0).

**Idea:** Bump both modules past their fixed versions, confirm `govulncheck` reports zero
reachable vulnerabilities, and close the gap that let them go stale.

**Scope revision during `/prep-step`:** a dry-run bump plus a local `govulncheck` showed the two
module advisories cleared — but surfaced **six standard-library advisories**, all fixed in
**go1.26.6**, against our pinned **go1.26.5**. They had not appeared in the 2026-08-17 CI run
because they published after it, so the next scheduled run would have failed regardless of the
module bump. Several sit directly on the auth boundary: `html/template` (GO-2026-6091,
login/consent rendering), `encoding/asn1` (GO-2026-5972, signing-key parsing), `net/url`
(GO-2026-6218, redirect following on the proxy path), plus `crypto/tls` (GO-2026-6090),
`net/http` (GO-2026-6089) and `x/net/idna` via `net/http` (GO-2026-5026). The task therefore
grew to cover the Go toolchain in both places it is pinned.

**What was done:**
- Bumped the modules to pinned versions: `golang.org/x/text` 0.41.0, `google.golang.org/grpc`
  1.83.1, and `golang.org/x/crypto` 0.55.0 — the last one deliberately, because the other two
  drag it along transitively and an incidental 0.54.0 would have been worse than an intentional
  0.55.0. `go mod tidy` clean; **no new modules**, only version replacements, so the license set
  is unchanged.
- Raised the Go toolchain to **1.26.7** (latest 1.26.x, above the 1.26.6 fix level) in `go.mod`,
  which drives every CI job via `go-version-file: go.mod`.
- Re-pinned the `Dockerfile` builder image to the current `golang:1.26-bookworm` digest
  `sha256:6ef6e30f…`, verified against the registry as carrying `GOLANG_VERSION=1.26.7` (the
  image also sets `GOTOOLCHAIN=local`, so image and `go.mod` must agree — they now do).
- Extended `.github/dependabot.yml` for the gomod ecosystem with `allow: dependency-type: all`
  plus a `groups` block collapsing all Go updates into one weekly PR.
- Added a `[Unreleased]` → `Security` section to `CHANGELOG.md`.

**Verification:** `go version` inside the module resolves to `go1.26.7`; `go build ./...` and
`go vet ./...` clean; `gofmt -l .` empty; `go test -race ./...` green across all 16 packages
(11 with tests `ok`, 5 without test files, 0 failures); **`govulncheck ./...` reports
"No vulnerabilities found" — 0 reachable, down from 2 module + 6 standard-library advisories.**
The `dependabot.yml` change was parsed as YAML to confirm `allow`/`groups` land where intended.

**Decisions / deviations:**
- The intake text suggested `go get …@latest`; replaced with explicit pinned versions, because
  `CODING-STANDARDS.md` §7 requires pinned versions over `latest`.
- The intake text called both bumps `// indirect`. True for the two named modules, but the bump
  drags `golang.org/x/crypto` — a **direct** dependency — along, which the entry had missed.
- Dependabot: the operator chose the grouped variant (`allow` + `groups`) over bare `allow`,
  because one PR per transitive module would bury the direct ones under
  `open-pull-requests-limit: 5`.
- Supersedes two open Dependabot PRs: #12 (x/crypto → 0.55.0, now included) and #1 (golang
  builder digest, whose target `18aedc1…` was itself already stale — resolved fresh instead).

**Known gap (not closed here):** `ci.yml` does not build the container image; only `release.yml`
does, on a tag push. The new builder digest is therefore first exercised at the next release
rather than on push, and the local Docker daemon was unavailable to smoke it. Adding an
image-build job to CI is a candidate for its own task.

**Files:** `go.mod`, `go.sum`, `Dockerfile`, `.github/dependabot.yml`, `CHANGELOG.md`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code change, no new runtime dependencies.

## F-015 — Advertise CIMD support in the AS metadata — DONE 2026-08-21

**Problem:** `SPEC.md` §1.3 declared Client ID Metadata Documents the primary
client-identification mechanism, but the §1.2 AS metadata table never announced it — and the
implementation faithfully mirrored that omission: `client_id_metadata_document_supported`
appeared nowhere in the repository. Clients could not discover a capability that is implemented
(`pkg/cimd`) and enabled by default (`CIMD_ENABLED=true`), and fell back to the deprecated DCR
path instead. Surfaced while diagnosing an unrelated outage: the live deployment's metadata was
missing the field entirely.

**Idea:** Add the field to SPEC §1.2 and emit it from `authorizationServerResponse`, driven by
the CIMD configuration so the advertisement always matches actual behaviour.

**What was done:**
- `pkg/idp/idp.go`: new `cimdEnabled` field on `IDPRouter`, set from `cfg.CIMDResolver != nil`;
  new `ClientIDMetadataDocumentSupported` field on `authorizationServerResponse`, populated from
  it in `handleOauthAuthorizationServer`.
- `SPEC.md` §1.2: added the field row and a delta note recording why the omission mattered.
- `CHANGELOG.md`: `[Unreleased]` → `Added`.
- Tests: a presence assertion in `TestOAuthServerMetadata` plus a new
  `TestASMetadataAdvertisesCIMD` with three subtests — advertised with a resolver (asserting the
  `none` auth method alongside, since clients require both halves), not advertised without one,
  and mirrored onto the OIDC discovery path.

**Decisions / deviations:**
- **Wired from the resolver, not from a second flag.** `IDPRouter` had no `cimdEnabled` field;
  CIMD hangs off `cfg.CIMDResolver` (nil disables it). Deriving the advertisement from the
  resolver's presence means the metadata and the behaviour cannot drift apart.
- **Always emitted as a boolean**, `true` or `false`, rather than omitted when false — consistent
  with the neighbouring `authorization_response_iss_parameter_supported`.
- **The plan's consent concern was imprecise and needed no work.** The consent screen sources
  identity from `ar.GetClient().GetID()`, which for a CIMD client *is* the document URL — a
  verifiable identifier, better than a self-declared `client_name`. Nothing to change.
- **The test pair came out sharper than planned.** The plan assumed the field would be `true` by
  default in the existing metadata test; in fact `setupTestServerWith` configures no resolver, so
  the honest default there is `false`. The existing test now pins presence *and* `false`, which
  also makes it non-vacuous: were the field absent, the presence assertion fails.
- **Added an OIDC-mirror subtest** that was not in the plan, pinning the claim (made during
  `/prep-step`) that the mirror is covered automatically because it routes to the same handler.

**Verification:** `gofmt -l .` empty, `go vet ./...` clean, `go test -race ./...` green across all
packages; the three new subtests pass. Compared against the live deployment for contrast, whose
metadata still omits the field entirely.

**Expected live effect:** clients that previously used DCR will switch to CIMD once this ships.
That path is already exercised end to end by `TestE2EPublicClientPKCE` (authorize → consent →
token → proxied call, including `iss` and a PKCE negative). Existing DCR registrations stay in
the store until their TTL expires and are simply no longer used.

**Files:** `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `SPEC.md`, `CHANGELOG.md`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No new dependencies, no new config, no new endpoints.

## F-016 — Port-agnostic loopback matching for `localhost` redirect URIs — DONE 2026-08-21

**Problem:** Native clients that use the hostname `localhost` for their loopback redirect could
not complete authorization. Fosite ignores the port only for IP literals — `isLoopbackAddress()`
tests `net.ParseIP(hostname).IsLoopback()` — so a client registering `http://localhost/callback`
and requesting `http://localhost:PORT/callback` was rejected, while the `127.0.0.1` form of the
same request was accepted. Claude Code publishes exactly that shape, so it could not connect.

**Idea:** Extend the RFC 8252 §7.3 port-agnostic rule to the exact hostname `localhost`, keeping
every other component an exact match.

**What the research turned up (it shaped the whole design):**
1. **Only the authorize step needed the fix.** `MatchRedirectURIWithClientRedirectURIs` is a
   package-level function called at two sites, both in the authorize path. The token endpoint only
   string-compares against the authorize request — no re-matching against registered URIs.
2. **An expansion survives the consent round-trip by itself,** because the authorize request is
   serialised including the client and its redirect URIs, then re-hydrated for the consent POST.
3. **No wrapper client type is possible:** `models.FromFositeClient` type-asserts
   `client.(*fosite.DefaultClient)` unchecked, so a foreign type would panic on that round-trip.
4. **Pre-processing was already established** in `handleAuth`, which rewrites the query to inject a
   generated `state`; its request context reaches `clientSource.GetClient`.

**What was done:**
- New `pkg/idp/loopback.go`: `matchesLoopbackHostPort` (the predicate, mirroring fosite's
  `isMatchingAsLoopback` but for the `localhost` hostname), `expandLoopbackRedirects` (returns a
  fresh slice, never aliases the caller's), plus `isLoopbackRedirect`/`allRedirectsLoopback` for
  the consent warning.
- `pkg/idp/idp.go`: `handleAuth` stashes the raw `redirect_uri` on the request context via a
  private key type; `clientSource.GetClient` was split into a lookup plus an expansion step that
  clones the `*fosite.DefaultClient` before extending its redirect list. The client lookup itself
  moved unchanged into `lookupClient`.
- Consent: `consentTemplateData` gained `LoopbackOnly`, and the template shows an explicit warning
  that the application runs on the operator's own device and any local program could have claimed
  the port (recommended by the MCP authorization spec).
- `SPEC.md` §1.3 (port tolerance) and §1.5 (loopback warning); `CHANGELOG.md` `[Unreleased]`.

**Verification:** `gofmt` clean, `go vet` clean, `go test -race ./...` green across all packages.
New tests: 16 predicate table cases, 5 expansion cases, 7 authorize-flow subtests through the real
endpoint, and a consent-template check. **The positive test was proven non-vacuous** by disabling
the context stash and re-running it: `400` instead of a redirect, test red; restored, green.

**Decisions / deviations:**
- **The tests came out at 187 lines against a planned handful.** Not trimmed: this is the
  open-redirect boundary, and each negative is a distinct way the rule could go slack —
  `evil.localhost`, path prefix, appended query, scheme downgrade, and bridging `localhost` to an
  IP literal.
- **No bridge between `localhost` and `127.0.0.1`.** A registered `localhost` does not authorise a
  `127.0.0.1` redirect or vice versa. Both forms work, each on its own.
- **The consent warning keys on "all redirect URIs are loopback", not "any".** A web client that
  also offers a local callback is not a native client, and warning there would train the operator
  to click through the warning that matters.
- **`isLoopbackRedirect`/`allRedirectsLoopback` were moved out of `idp.go`** into `loopback.go`
  during review — they are loopback logic, and `idp.go` is already far over the file-length limit.
- **Rejected alternative:** rewriting `localhost` → `127.0.0.1` in the query would have let
  fosite's existing IP-literal rule do the work, but it sends the user to a different host than
  requested and can break clients that compare the callback URL against what they sent.

**Pre-existing issue found, not fixed here:** `pkg/idp/idp.go` is 1073 lines against a 500-line
hard limit in `CODING-STANDARDS.md`, with no section comments, so the documented exception does not
apply. It was already 1010 lines before this task; splitting it is a refactor of an auth-critical
file and belongs in its own task, not smuggled into a redirect-matching change.

**Files:** new `pkg/idp/loopback.go`, `pkg/idp/loopback_test.go`; changed `pkg/idp/idp.go`,
`SPEC.md`, `CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new dependencies, no new
config, no new endpoints.

## F-018 — Build the container image in CI — DONE 2026-08-21

**Problem:** `ci.yml` ran four jobs — `build-test`, `lint`, `license-check`, `workflow-lint` — and
none built the container image. Only `release.yml` did, on a SemVer tag push, so a broken
`Dockerfile` surfaced as a failed *release* rather than a failed push. F-014 made it concrete: it
re-pinned the builder digest, and nothing exercised that digest until the next tag. The pending
Dependabot bump of the distroless runtime digest was equally untested.

**Idea:** A CI job that builds the image with buildx (no push) and smoke-tests the result, so
base-image and `Dockerfile` changes fail on the pull request instead of at release time.

**What was done:** one new `image-build` job in `.github/workflows/ci.yml` (41 lines):
`docker/setup-buildx-action@v4`, then `docker/build-push-action@v7` with `push: false`,
`load: true`, `platforms: linux/amd64`, `build-args: VERSION=ci`; then `docker run --rm IMAGE
--version`; then a container start that polls `docker inspect --format
'{{.State.Health.Status}}'` until `healthy`, dumping `docker logs` and failing on `unhealthy` or
timeout. Actions pinned by major version like the sibling jobs; the workflow keeps
`permissions: contents: read`, so the job cannot push.

**Correction the plan needed:** the intake sketched the smoke as `docker run --rm IMAGE
healthcheck`, which cannot work — `probeHealth` GETs `/healthz` on the *local listener*, so
without a running server it fails with a refused connection. The sketch also ruled out starting a
container, contradicting itself. Starting one won, because it tests strictly more: it exercises
the image's `HEALTHCHECK` directive from F-007b/M9 and proves the non-root distroless runtime
brings the listener up at all.

**Decisions:**
- **The smoke container's password is generated inside the step** (`openssl rand -hex 16`) rather
  than written into the workflow. The gateway refuses to start without an auth backend, and a
  literal would leave a credential-shaped string in a public repository forever.
- **linux/amd64 only.** `release.yml` still builds both architectures; arm64 here would mean QEMU
  emulation for a gate whose breakage is not architecture-specific.
- **No build cache** (`cache-from/to: type=gha`) for now — roughly 2–3 minutes per push is
  acceptable, and a stale cache is another way for a broken build to slip through.
- **Loop variable renamed `status` → `health`** after local verification: `status` is read-only in
  zsh. CI runs bash, where it never mattered, but anyone reproducing the step by hand would have
  hit a pointless error.

**Verification (the job was proven, not just linted):** `actionlint` v1.7.12 — the version CI
pins — clean. `bash -n` on the extracted step clean; the polling logic was dry-run against a stub
`docker` for all three outcomes: healthy → rc=0, unhealthy → rc=1 with logs, timeout → rc=1 with
logs. Then the real thing, locally with Docker: `docker buildx build --platform linux/amd64`
succeeded against the current `Dockerfile`, `docker run --rm IMAGE --version` printed
`mcp-oauth-gateway version ci` (so the `VERSION` build-arg reaches the binary through ldflags),
and the started container reported **healthy**. All of that ran under amd64 emulation on an arm64
host — harder conditions than CI, which runs amd64 natively. Container and image were removed
afterwards. Go suite unaffected and still green (`gofmt` 0, `vet` rc=0, `go test -race` rc=0).

**Incidental finding:** the builder stage sets `ENV GOTOOLCHAIN=auto`, overriding the base image's
`GOTOOLCHAIN=local`. Had the image and `go.mod` disagreed on the Go patch version, the build would
have downloaded the required toolchain rather than failing — so F-014's alignment saves a download
rather than preventing a break.

**Files:** `.github/workflows/ci.yml`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code
change, no new dependencies, no new config.

## F-020a — Split `idp.go` — DONE 2026-08-21

First substep of F-020. `pkg/idp/idp.go` went from **1072 to 216 lines**, distributed over eight
files that follow the clusters the declarations already formed. Code only — no test file was
touched, which is what makes the green suite mean anything.

| File | Contents | Lines |
|---|---|---|
| `idp.go` | `IDPRouter`, `Config`, `NewIDPRouter`, `customCompose`, `withRateLimit`, endpoint constants, `SetupRoutes` | 216 |
| `register.go` | DCR request/response types, `validateRegistration`, `handleRegister` | 182 |
| `consent.go` | `consentTemplate`/`consentTemplateData`, both consent handlers | 165 |
| `authorize.go` | `handleAuth`, `issRedirectWriter`, `errInvalidTarget`, `validateResource`, `ar_id` session helpers | 165 |
| `metadata.go` | `authorizationServerResponse` + handler, `jwks` | 120 |
| `token.go` | `handleToken`, `handleIntrospect`, `handleRevoke` | 108 |
| `client_source.go` | `CIMDResolver`, `clientSource`, the redirect-URI context stash, `GetClient`, `lookupClient` | 97 |
| `session.go` | `NewJWTSession`, `Session` | 96 |

`loopback.go` (111 lines, from F-016) was already separate and stayed as it is. Every file is now
under the 300-line target, so the 500-line hard limit is comfortably met.

**How it was done:** a script sliced the file at declaration boundaries, walking backwards over
each declaration's doc comment so no comment was orphaned, then `goimports` reduced each new
file's copy of the original import block to what it actually uses.

**One acceptance criterion could not be met, and it was a bad criterion.** The plan asked for
`git diff -M` to report moves rather than rewrites. Git cannot do that here: rename and copy
detection works on whole-file similarity, and a file that splits into eight while the source
survives fits no such pair. Even `--find-copies-harder` reports seven plain `create mode` entries.
Two stronger checks replaced it:

- **Declaration sets are byte-identical:** 47 top-level declarations before, 47 after, `diff` on
  the sorted lists empty — nothing lost, nothing duplicated.
- **Body content is byte-identical:** 954 non-blank lines below the import block before, 954
  after, sorted `diff` empty — not one character of content changed, only its file.
- The net **+77** lines reconcile exactly: **+87** for seven new package/import headers, **−10**
  because `goimports` dropped imports that `idp.go` no longer uses.

**Verification:** no `_test.go` in `git status`; `go test -race ./...` rc=0 across 11 packages with
the tests unchanged; `gofmt -l` empty; `go vet` clean. Import grouping still follows §4 (stdlib,
blank line, then third-party and local alphabetically) — `goimports` preserved the repo's style.

**Left for F-020c, deliberately not fixed here:** ten exported identifiers carry no doc comment
(`IDPRouter`, `NewIDPRouter`, `SetupRoutes`, `GetClient`, `WriteHeader`, `NewJWTSession`,
`Session`, `GetJWTClaims`, `GetJWTHeader`, `Clone`), a §11 violation. Verified as **pre-existing**:
the same ten were undocumented before the split. Adding them here would have added content to a
move-only substep and destroyed the byte-identical proof above.

**Files:** `pkg/idp/idp.go` (shrunk); new `authorize.go`, `client_source.go`, `consent.go`,
`metadata.go`, `register.go`, `session.go`, `token.go`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.
No behaviour, signature, dependency or config change.

## F-020b — Split `idp_test.go` to match — DONE 2026-08-21

Second substep of F-020. `pkg/idp/idp_test.go` (1684 lines, 48 top-level declarations) was
distributed over **ten** files, each sitting next to the code it exercises. Test files only — no
production file was touched.

| File | Lines | | File | Lines |
|---|---|---|---|---|
| `authorize_test.go` | 296 | | `session_test.go` | 147 |
| `helpers_test.go` | 290 | | `register_test.go` | 134 |
| `token_test.go` | 286 | | `ratelimit_test.go` | 119 |
| `metadata_test.go` | 184 | | `consent_test.go` | 97 |
| `revocation_test.go` | 176 | | `client_source_test.go` | 81 |

`loopback_test.go` (187 lines, from F-016) was already separate and stayed.

**Deviation from the plan: ten files instead of nine.** `token_test.go` would have reached ~439
lines once `TestPrivateClient` (148 lines, a full confidential-client flow) joined the audience,
introspection and identity tests — over the 300-line target the substep was meant to enforce. The
revocation tests were split off into `revocation_test.go`; they are self-contained anyway
(RFC 7009), and `token_test.go` lands at 286.

**Two placement decisions worth recording:**
- `stubResolver` went to `helpers_test.go`, not `client_source_test.go`, because `loopback_test.go`
  uses it too. A stub with two consumers belongs with the helpers.
- `failingRevokeRepo` stayed with `revocation_test.go` — only that one test uses it.

**Verification, using the approach F-020a established rather than git's rename detection:**
- **Test set identical:** `go test -list '.*'` returns 34 before and 34 after, `diff` on the sorted
  lists empty. This is the check that matters for a test split — a test function lost in the move
  would leave the suite green and nobody the wiser.
- **Bodies identical:** 1399 non-blank lines below the import block before, 1399 after, sorted
  `diff` empty — no test body changed, only its file.
- No production file in `git status`; `go test -race ./...` rc=0 across 11 packages with 34
  top-level tests executed; `gofmt -l` empty; `go vet` clean.
- Every file under the 300-line target (largest: 296).

**Files:** `pkg/idp/idp_test.go` (removed); new `authorize_test.go`, `client_source_test.go`,
`consent_test.go`, `helpers_test.go`, `metadata_test.go`, `ratelimit_test.go`, `register_test.go`,
`revocation_test.go`, `session_test.go`, `token_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No production code, dependency or config change.

## F-020c — Section comments and final standards pass — DONE 2026-08-21

Third and final substep of F-020, and the one that put content back after two move-only steps.

**Ten doc comments** on the exported identifiers that had none — `IDPRouter`, `NewIDPRouter`,
`SetupRoutes`, `GetClient`, `WriteHeader`, `NewJWTSession`, `Session`, `GetJWTClaims`,
`GetJWTHeader`, `Clone` (§11). They were written to explain *why* something exists rather than
restate the signature. `Clone` now records that fosite clones sessions between the authorize and
token steps, so a shallow copy would let two requests share one claims map — the route by which one
client's identity ends up in another's token. `NewJWTSession` records that the `jti` is generated
there and not at signing time, because revocation is keyed on it (SPEC §1.9). `WriteHeader` records
that fosite's own error writer knows nothing about RFC 9207, so without the wrapper a client could
not tell which authorization server rejected it.

**Ten section rules** in the three files that still group more than one concern:
`authorize.go` (RFC 8707 resource validation · RFC 9207 `iss` on redirects · authorize endpoint ·
authorize-request session binding), `idp.go` (router/config/construction · endpoints and route
registration), and `helpers_test.go` (test server setup · PKCE and flow drivers · small assertion
helpers · stubs and decoding). The other seventeen files hold exactly one concern each after
F-020a/b and need none.

**Deviation from the expectation stated when the substep was queued:** the section comments looked
likely to be redundant, since every file already sits under the 300-line target. Reading the files
showed the opposite — `authorize.go` bundles four clearly separate concerns in 165 lines. The §2
rule is about structure, not length, and applying it by line count would have missed the point.

**Verification:** zero undocumented exported identifiers remain (checked by the same scan that
found the ten); `gofmt -l` empty; `go vet` clean; `go test -race ./...` rc=0 across 11 packages;
the test set is still the identical 34 from before the whole refactor.

**Noted for later, no action needed:** `helpers_test.go` now sits at 298 lines. It satisfies the
criterion — and carries section comments either way — but the next helper added there will cross
the target and call for a further split.

**Files:** `pkg/idp/idp.go`, `authorize.go`, `client_source.go`, `session.go`, `helpers_test.go`;
docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No behaviour, signature, dependency or config change.

## F-020 — Split `pkg/idp/idp.go` along its seams — DONE 2026-08-21

Complete (a/b/c). `pkg/idp/` went from two oversized files — `idp.go` at 1072 lines and
`idp_test.go` at 1684, both far past the 500-line hard limit — to twenty files, the largest 298.
Every file now holds one concern, sits under the 300-line target, and carries section rules where
it still groups several.

The refactor was run as a **pure move first, content second**: F-020a and F-020b relocated code and
tests without changing a character of either, and only F-020c added the doc and section comments.
That order is what made the verification meaningful. Because git cannot recognise a one-into-eight
split as a move — rename detection needs whole-file similarity — the proof came from invariants
instead: identical declaration sets (47/47), identical body lines (954/954 for the code, 1399/1399
for the tests), and an identical test set (34/34 via `go test -list`), the last of which is the one
that matters for a test split, since a test lost in a move leaves the suite green and the loss
invisible.

**Sequencing:** run before F-017 by the operator's decision, so the spec re-check and its
verification pass see the split code rather than the pre-split code.

**Still open, deliberately:** `handleRegister` is 103 lines, over the 50-line hard limit and over
the ~80-line orchestration exception. Splitting it restructures the DCR endpoint instead of
relocating a file, so it never belonged in a move task and still needs its own F-number.

## F-017a — Migrate `mcp-go` to `log/slog` and unblock Dependabot PR #13 — DONE 2026-08-21

First substep of F-017. Dependabot PR #13 ("Bump the go-modules group with 45 updates") was red on
`build-test` and `lint`, and the cause was not a Dependabot error but a real API migration:
`mark3labs/mcp-go` dropped its own `Infof`/`Errorf` logger interface in favour of `log/slog`
between 0.50 and 0.58, and the Streamable-HTTP logger option changed **type** as well as parameter.
Three compiler errors across two call sites, all in `pkg/backend/proxy.go` — the stdio backend is
the only place the gateway drives mcp-go as a library.

**What was done:**

| Before | After |
|---|---|
| `transport.WithCommandLogger(&zapLogger{p.logger})` | `transport.WithCommandLogger(newSlogLogger(p.logger))` |
| `server.WithLogger(&zapLogger{logger})` (a `ServerOption`, rejected by `NewStreamableHTTPServer`) | `server.WithStreamableHTTPLogger(newSlogLogger(logger))` (a `StreamableHTTPOption`) |
| `zapLogger` adapter type + two methods | deleted — dead code (§1) |

The bridge is a single line over a vetted library: `slog.New(zapslog.NewHandler(logger.Core()))`.
Wrapping the **existing** core matters — it keeps the stdio backend's output in the same structured
stream as the rest of the gateway instead of opening a second sink.

**Dependencies:** `go.mod`/`go.sum` were taken from the Dependabot branch verbatim rather than
re-derived, so the local state matches what CI would have tested. Direct bumps:
`mcp-go` 0.50.0 → **0.58.0**, `testify` 1.11.1 → 1.12.1, `bbolt` 1.4.3 → 1.5.0, `gorm` 1.31.1 →
1.31.2, plus 41 indirect. Added `go.uber.org/zap/exp` **v0.3.0** (MIT, by the zap authors).
`go mod tidy` is a no-op afterwards.

**Decision: `go.uber.org/zap/exp` over a hand-written `slog.Handler`.** CODING-STANDARDS §1 prefers
an established pattern over an invented one, and the cost argument that would normally favour
hand-rolling does not apply here: every module `zap/exp` requires (`zap`, `multierr`, `testify`,
`go-spew`, `go-difflib`, `yaml.v3`) is **already in the build at an equal or higher version**, so it
adds no transitive dependency at all. A hand-written handler would have meant owning
`Handle`/`WithAttrs`/`WithGroup` semantics for no gain.

**Decision: mcp-go 0.58.x over v1.0.0-beta.1.** v1.0.0-beta.1 already implements protocol
**2026-07-28** (`server/discover`, `_meta` protocol version, header validation) while 0.58.0 is
still `LATEST_PROTOCOL_VERSION = "2025-11-25"`. Taking the beta would have made the stdio path
spec-current, but CODING-STANDARDS §7 pins stable versions and this is a public auth boundary.
**Consequence, to be documented in F-017c:** the stdio backend speaks 2025-11-25 until mcp-go v1.x
is final. The transparent backend — the documented primary mode — is unaffected, because it
proxies transparently and holds no protocol opinion.

**Tests:** one added, `TestNewSlogLoggerWritesToZap`. The existing `TestSetupProxy` and
`TestProxyBackendRun` do traverse both migrated call sites (the latter against a real subprocess),
but both pass `zap.NewNop()` — a green run there proves type compatibility and nothing more, and
would stay green if the bridge were wired to a discarding core. The new test asserts through
`zaptest/observer` that the record, its level and its slog attributes actually reach the zap core.
**Verified non-vacuous:** repointing the bridge at `zapcore.NewNopCore()` turned it red
(`expected: 1, actual: 0`), and restoring it turned it green again.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages,
0 FAIL; `govulncheck` **0 reachable** (one module-level finding remains, `GO-2026-5932`
`x/crypto/openpgp` — unmaintained, not called, pre-existing); `go-licenses v2.0.1 check
--disallowed_types=forbidden,restricted` rc=0; `golangci-lint v2.12.2` **0 issues**;
`actionlint v1.7.12` rc=0; gitleaks over the working tree: no leaks. All **five** CI jobs were
replicated locally rather than deferred to CI — including `image-build`, which built the amd64
image, ran `--version`, and polled the container's own `HEALTHCHECK` to `healthy` (the F-018 job,
exercised here against a 45-module bump for exactly the reason it was written).

**PR #13 stays open and red on GitHub.** What landed here is the "equivalent commit" the acceptance
criterion allows; Dependabot normally closes the PR itself once the versions reach the default
branch — worth confirming after the push rather than assuming.

**Files:** `pkg/backend/proxy.go`, `pkg/backend/proxy_test.go`, `go.mod`, `go.sum`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No behaviour, config, endpoint or signature change on the
authorization surface.

## F-017b — Transport conformance: prove header pass-through, harden credential injection — DONE 2026-08-21

Second substep of F-017. Two halves: pin the pass-through confirmations down with tests, and close
the one real defect the final-spec re-check turned up.

**The defect (finding 3 of the re-check).** `pkg/proxy/proxy.go` attached each configured
`PROXY_HEADERS` entry with `Header.Add` and, unlike the `HEADER_MAPPING` loop two lines above it,
never deleted an inbound copy first. Appended values keep their order, so a client sending the same
header name landed **in front of** the injected one — and an upstream reading `Header.Get`, which
returns the first value, would read the client's instead of the configured upstream credential
(FR-6, SR-7). Only `Authorization` was special-cased.

The fix is one line, `c.Request.Header.Del(key)` before the add. It replaces the
`strings.EqualFold(key, "Authorization")` branch rather than joining it, because the generic delete
subsumes that case entirely — so closing the gap made the function **shorter**, not longer.

**Why this surfaced now, when the code is unchanged since the fork.** The gap was always reachable
in principle — HTTP clients have always been able to set arbitrary headers. What changed is that
MCP 2026-07-28 makes client-set headers *routine*: SEP-2243 mirrors annotated tool parameters into
`Mcp-Param-{Name}` headers and obliges intermediaries to forward the ones they do not recognise.
A latent gap became one that normal, spec-conformant traffic walks past.

**Tests, and why they assert what they do:**

| Test | File | Guards |
|---|---|---|
| `TestProxyRouter_ProxyHeadersStripClientHeaders` | `pkg/proxy/transport_test.go` | four cases: single-value shadowing, multi-value replacement, `Authorization` via `PROXY_HEADERS`, and **unconfigured headers passing through untouched** |
| `TestProxyRouter_ProxiesServerDiscover` | `pkg/proxy/transport_test.go` | the new `server/discover` RPC reaches the upstream with body and `Mcp-Method` intact |
| `TestTransparentBackendForwardsMCPTransportHeaders` | `pkg/backend/transparent_test.go` | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` arrive unchanged and exactly once, Base64-sentinel value included |

The security assertions compare the **full value slice**, never `Header.Get`. `Get` returns the
first value and would have reported `"upstream-secret"` just the same while the attacker's copy sat
behind it — it cannot tell a fixed gateway from a broken one. The fourth case exists so the strip
stays limited to configured names: an over-broad delete would eat the very transport headers the
gateway is required to forward.

**Both verified non-vacuous**, which is what makes them worth having:
- Reverting the fix turned the security test red with `actual: ["attacker-supplied",
  "upstream-secret"]` — the client's value first, exactly the ordering the vulnerability depends on.
- Deleting `Mcp-Method` inside the transparent backend's `Rewrite` turned the pass-through test red
  with `actual: []string(nil)`.

**No production change in `pkg/backend/transparent.go`.** Nothing was broken there: `ReverseProxy`
clones the inbound request and this backend rewrites only `X-Forwarded-*`. That is a property of
the current implementation rather than a guarantee, so the test records it — the confirmation the
intake asked for, in a form that cannot silently expire.

**`server/discover` cannot collide with the reserved-namespace guard**, confirmed by reading and now
by test: the guard matches URL *path* prefixes (`/.idp/`, `/.auth/`, `/.well-known/`) while
`server/discover` is a JSON-RPC method in the request *body*. The test exists against a future guard
rewritten in terms of method names.

**Deviation from the plan, found during review.** The plan put the new tests in
`pkg/proxy/proxy_test.go`. That file was already **1035 lines**, twice the 500-line hard limit in
CODING-STANDARDS §2, and the addition would have pushed it to 1180 — making a pre-existing violation
worse. The tests went into a new `pkg/proxy/transport_test.go` (163 lines) instead, and
`proxy_test.go` is left **byte-identical to HEAD**. Splitting the 1035-line file is real work of the
F-020 kind and is **reported as open**, not silently carried: it needs its own F-number.

**Files:** `pkg/proxy/proxy.go` (one line + comment), new `pkg/proxy/transport_test.go`,
`pkg/backend/transparent_test.go` (+54), `SPEC.md` (§1.11.4 now states the strip for both
mechanisms, plus an F-017b delta line); docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No config,
endpoint or signature change.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues; gitleaks no leaks. **Behaviour change worth an upgrade note:** a
deployment that (unwisely) relied on clients supplying a header also listed in `PROXY_HEADERS` will
see that client value dropped from now on.

## F-017c — Documentation sweep and conformance record — DONE 2026-08-21

Third substep of F-017. The sweep itself was mechanical; the part worth keeping is what replaced
the prose.

**Seven live "release candidate" caveats became statements about the final revision** — `README.md`
(status blurb), `REQUIREMENTS.md` §0 (the watch item), the `SPEC.md` header, `THREAT-MODEL.md`,
`CLAUDE.md`, the `PROGRESS.md` state line, and the `docs/VERIFICATION.md` close-out. What remains
is either inside F-017's own task text (archived with this entry) or explicitly historical, in the
v0.1.0 CHANGELOG entry.

**The watch item was closed, not re-dated.** REQUIREMENTS §0 now records that the final spec
published, that the authorization surface needed no change, and — deliberately — that there is **no
successor watch item**: the specification will keep moving, and re-checking it is ordinary
maintenance rather than a standing exception. A watch item that renews itself forever is a reminder
nobody reads.

**New `SPEC.md` §4 — the conformance record.** Three tables replacing the claim "we are conformant"
with something a reader can walk:

- **§4.1 Authorization**, 16 requirement rows. Every server-side MUST and SHOULD of the
  authorization spec, each with its status and the section that implements it. Client-side
  obligations are omitted with the reason stated: the gateway is an AS and a resource server,
  never an MCP client.
- **§4.2 Streamable HTTP**, 10 rows, each attributed to **gateway** or **upstream**. The
  attribution is the point: "the upstream owns it" is only an answer while the gateway provably
  forwards enough for the upstream to comply — which F-017b's tests now assert.
- **§4.3 Recorded limitations**, the two deliberate gaps: the scope-less design behind the two
  "not applicable" rows, and the stdio backend's 2025-11-25 ceiling from F-017a.

**§4.2 carries a ✘.** `Origin` validation is a MUST the gateway does not satisfy — unchanged since
protocol 2025-03-26 and missed by the F-006b audit. The table records it as unmet with its
mitigation (bearer-protected `/mcp`, CSRF plus `SameSite=Lax` on `/.auth/*`, loopback the exposed
case) and points at F-021, rather than quietly omitting the row. The same limitation appears in
`CHANGELOG.md` under "Known limitations" and in `THREAT-MODEL.md`, so a reader meets it wherever
they look.

**Two normative rows were missing on the first pass** and were caught by self-auditing §4.1 against
the specification instead of trusting the draft: the error-status table (401/403/400, MUST) and
scope-hierarchy handling (MUST). Without them the acceptance criterion "covers every MUST and
SHOULD" would have been ticked while being false — the exact failure mode a conformance table is
supposed to prevent.

**`CHANGELOG.md` v0.2.0**, with Added / Security / Changed / Known limitations / Upgrade notes. The
upgrade note names the F-017b behaviour change: a deployment relying on *clients* supplying a header
also listed in `PROXY_HEADERS` now sees that value dropped. Intended setups get stricter and are
otherwise unaffected. Recorded as **minor, not patch**, because F-015, F-016 and F-017b each change
behaviour rather than only repairing a defect.

**Deliberate decision to revisit in F-017d:** `## [Unreleased]` was renamed to `## [0.2.0] —
2026-08-21` here rather than at tag time, so the acceptance criterion could be met. If the tag slips
past that date, F-017d must correct it.

**Verification:** all relative links in the changed files resolve; every `SPEC.md` section
referenced from §4 exists; the §4 tables are column-consistent (5 and 6); gitleaks clean; GR-5 scan
found no paths, IPs, e-mail addresses or hostnames. No Go file was touched, so the suite was not
re-run — `git status` showing no `.go` entry is the evidence.

**Files:** `README.md`, `REQUIREMENTS.md`, `SPEC.md` (+62, new §4), `THREAT-MODEL.md`, `CLAUDE.md`,
`PROGRESS.md`, `docs/VERIFICATION.md`, `CHANGELOG.md`; plus `PROGRESS-ARCHIVE.md`. No code, config
or behaviour change.

## F-023 — CIMD documents rejected over a foreign grant type — DONE 2026-08-21

Found during the F-017d live verification, minutes after v0.2.0 went live. It is the defect that
made the whole F-015/F-017d exercise worth running.

**Symptom.** The operator clicked "connect" in Claude and got an error page:
`invalid_client … The requested OAuth 2.0 Client does not exist.` The gateway logged:

```
CIMD resolution failed
client_id: https://claude.ai/oauth/mcp-oauth-client-metadata
error: invalid CIMD client ID: unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"
```

**Cause.** `pkg/cimd/resolver.go` validated a document's declared `grant_types` against the §1.2
supported set and rejected the **entire client** if any entry fell outside it. Claude's published
document is perfectly valid and declares three grants — `authorization_code`, `refresh_token` and
`urn:ietf:params:oauth:grant-type:jwt-bearer`. Two are exactly what this gateway offers; the third
is a capability Claude uses at other authorization servers.

That is the conceptual error: **a CIMD document is published once and presented to every
authorization server**, so it necessarily declares the union of the client's abilities. A server
that refuses the client because that union names something it does not offer makes CIMD unusable
with any real client. DCR is different — a registration request is addressed to one server, so
rejecting an unsupported declaration there is correct, and it stays strict.

**Why it stayed hidden until now.** Before F-015 the AS metadata never advertised CIMD, so clients
took the deprecated DCR path and no real document ever reached this code. F-015 fixed the
advertisement, clients switched to CIMD — and walked straight into the rejection. The shared
whitelist came from F-012a, where sharing it between DCR and CIMD looked like consistency rather
than a category error.

**Fix.** Narrow instead of reject: `grant_types` and `response_types` are intersected with the
supported sets, order preserved, via a small `intersect` helper. A document that leaves *nothing*
supported is still rejected — no flow would remain to run. Narrowing is strictly fail-closed: the
resolved client only ever ends up with a subset of what it asked for, and fosite refuses an
unsupported flow at the endpoints if one is attempted anyway.

**Tests.** New `TestResolverNarrowsUnsupportedFlows`, table-driven over Claude's real document,
a mixed `client_credentials` case (order preservation) and a mixed response-type case.
**Verified non-vacuous:** restoring the old validation turns it red with
`unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"` — byte-identical to the
message from the live log.

Two existing cases in `TestResolverDocumentValidation` encoded the old behaviour and were
**deliberately changed**: `["authorization_code", "client_credentials"]` must now resolve rather
than fail, so it moved into the narrowing test. The two remaining rejection cases were renamed to
`no supported grant_type` / `no supported response_type`, which is what they actually assert.

**Known limitation recorded alongside** (`CHANGELOG.md`), from
[anthropics/claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650), surfaced by
the operator: fetching Claude's CIMD document from **datacenter IP ranges** can return a Cloudflare
challenge (403) instead of the document. Nothing a server-side OAuth implementation can solve;
`CIMD_ENABLED=false` is the escape hatch for deployments hit by it. This gateway's host is
unaffected — the document fetches with HTTP 200.

**Files:** `pkg/cimd/resolver.go`, `pkg/cimd/resolver_test.go`, `SPEC.md` §1.3, `CHANGELOG.md`
(v0.2.1); docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues.

## F-017d — Live verification and release — DONE 2026-08-21

Fourth substep of F-017, and the one that justified the whole task: it found a defect that no test
and no amount of reading would have caught.

**Two releases, not one.** `v0.2.0` shipped F-014/F-015/F-016/F-017a–c. The live verification then
broke, and `v0.2.1` shipped the fix (F-023) forty minutes later.

**Phase 0 — publish.** Tag `v0.2.0` → `release.yml` → multi-arch GHCR image, verified the way any
user would get it: logged out of ghcr.io, anonymous pull, `--version` → `v0.2.0`, amd64 + arm64,
tags `0.2.0` and `0.2` present, `latest` correctly absent, GitHub release published.

**Phase 1–2 — deploy.** A fresh `data/` backup first (the newest on the host was six weeks old and
predated the 0.1.1 switch), compose image tag bumped, `down && up -d` → healthy in ~8 s. Total
downtime seconds.

**Phase 3 — server-side, all green.** Discovery, JWKS, `/healthz` 200; **JWKS `kid` unchanged**, so
signing keys survived and issued tokens stayed valid; PRM self-consistent; `POST /mcp` without a
token → 401 with the bare `WWW-Authenticate` challenge; garbage bearer → `401 invalid_token`;
reserved namespaces not proxied. And the one that mattered: **`client_id_metadata_document_supported`
was absent before the switch and `true` after** — F-015 demonstrated in the field rather than in a
commit.

**The correction that made this substep honest.** The plan assumed the deployment ran `0.1.0` and
warned at length about crossing v0.1.1's breaking changes (encrypted session cookie, resident-passkey
requirement) with the password fallback disabled. The operator said otherwise and the host confirmed
it: **`0.1.1` was live**, so those changes had shipped weeks earlier and carried no risk at all. The
cause was drift — `private/mcp-gateway/docker-compose.yml` still pinned `0.1.0` because the 0.1.1
deployment was never mirrored back. Assumption replaced by an SSH-verified inventory; the local copy
is now a verbatim mirror and the plan says to re-sync after every deployment.

**Phase 3, client side — where it went wrong, and why that was worth it.** Claude web, iOS and
passkey login all worked immediately. But the acceptance criterion asked for proof that clients now
pick **CIMD**, and getting it defeated three approaches in a row:

1. A second connector on the same URL — Claude refuses; it de-duplicates by URL.
2. Removing and re-adding the connector — **no OAuth flow at all**. MCP traffic arrived, but no
   `register`, no `token_issued`, no `login_ok`: Claude kept its stored credentials for that URL.
3. Waiting for `DCR_CLIENT_TTL` — never fires, because the registration is refreshed on every token
   issuance (SPEC §2.1), so one in active use never expires.

The log did establish the starting point: web and iOS both issued tokens against **one** opaque DCR
client id, registered before the switch under metadata that never advertised CIMD.

With operator approval, the active DCR record was deleted from the store (second backup first;
gateway stopped for the bbolt lock; a purpose-built helper printing key names and sizes only, never
record contents). Inventory **before: 2 client records** — the store *had* been growing, which is
itself the evidence F-019 wanted — **after: 1**, the older orphan left in place so a new DCR record
would be unmistakable. Deleting the client does not invalidate live tokens (revocation checks the
token record), so the access and refresh records went too: **58 refresh-token records** for that one
client, a rotation history nobody had looked at before.

**Then Claude switched to CIMD and the gateway refused it** —
`invalid CIMD client ID: unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"`.
That became **F-023** and `v0.2.1`. After deploying it:

```
20:22:41  login_ok
20:22:57  token_issued   client_id = https://claude.ai/oauth/mcp-oauth-client-metadata
```

A URL, so CIMD; **zero `register` events**, so no DCR registration was created; and the operator
confirmed tool calls against the upstream succeed. F-015, F-023 and F-019's evidence, all settled at
once.

**The lesson, written into `docs/VERIFICATION.md` rather than left in a chat.** The runbook gained
"Force a fresh client registration": the three routes that do not work, the one that does, and the
reason it matters — *a verification that only exercises an already-connected client passes even
while the gateway is broken for every new one.* That is precisely what happened here, and it is the
part most likely to be repeated wrongly next time.

**Files:** `docs/VERIFICATION.md` (final-spec checkbox ticked with the §4 walk recorded, plus the
new section); evidence and the full run log in `private/UPDATE-PLAN-v0.2.0.md` (gitignored). Host
cleanup: the one-off helper removed, and the v0.1.0-era leftovers (35 MB cross-compiled binary,
`Dockerfile`, stale compose backup, superseded `0.1.0` image) deleted afterwards at the operator's
request.

**Left open on purpose:** Dependabot `#9` and `#6` — the latter bumps `action-gh-release`, the step
that publishes releases, so it was held back until after both tags landed.

## F-017 — Re-verify against the final MCP 2026-07-28 authorization spec — DONE 2026-08-21

Complete (a/b/c/d). The standing watch item, open since F-007e checked the release candidate, is
closed — and deliberately without a successor: the specification will keep moving, and re-checking
it is ordinary maintenance rather than a standing exception.

| Substep | Outcome |
|---|---|
| **F-017a** | mcp-go 0.50 → 0.58 with the stdio backend migrated to `log/slog`; unblocked a red Dependabot PR that turned out to be a real API migration, not a bot error |
| **F-017b** | closed a spoofing path on credential injection — a client could shadow a configured `PROXY_HEADERS` value — plus tests pinning the MCP transport-header pass-through |
| **F-017c** | seven RC caveats became final-spec statements; new `SPEC.md` §4 records conformance requirement by requirement, including one **unmet** MUST |
| **F-017d** | released `v0.2.0`, deployed, verified live — and surfaced F-023, which required `v0.2.1` |

**The authorization surface needed no change.** All six SEPs remained satisfied, and CIMD-first with
a DCR fallback still matches a spec that now formally deprecates DCR. Everything this task actually
fixed lay elsewhere: on the proxy surface (F-017b), in the CIMD resolver (F-023), and in
documentation that claimed conformance without evidence (F-017c).

**What the task is really worth, in hindsight.** A re-check that had only compared the specification
against the code would have concluded "conformant, no action" — and been wrong in two places. The
`PROXY_HEADERS` gap needed reading the code against a *new* spec feature (`Mcp-Param-*`) to become
visible; the CIMD defect needed a live client pushed through a fresh registration, which took
deleting production state. Both were invisible to the test suite, and one of them had been sitting
in the code since F-012a.

**Recorded as unmet rather than glossed over:** `Origin` validation, a MUST since protocol
2025-03-26 that this gateway never implemented and the F-006b audit missed. It sits in `SPEC.md`
§4.2 with a ✘, in the CHANGELOG under "Known limitations", and in `THREAT-MODEL.md`, tracked as
**F-021**.

**Spawned:** F-021 (`Origin`), F-022 (six files past the §2 hard limit), F-023 (done, the CIMD fix),
F-024 (operator client list with a kill switch — the manual store surgery this task required is the
argument for it).

## F-021 — Validate the `Origin` header (DNS rebinding, SR-9) — DONE 2026-08-22

Closes the one **unmet MUST** the F-017 spec re-check turned up. `SPEC.md` §4.2 carried a ✘ from
v0.2.0 until now; the row reads ✔.

**What it does.** A request whose `Origin` header names anything other than the `EXTERNAL_URL`
origin is answered `403`. A request **without** an `Origin` header passes — deliberately, and as the
specification intends: server-side MCP clients send none, so treating absence as a violation would
reject every real client and turn a hardening measure into an outage. `Origin: null` counts as
present and invalid. Comparison is on scheme + host + port, host lower-cased, default ports elided.

**Two intake questions decided at prep time, one third found during it:**

- **No `ALLOWED_ORIGINS` list**, only `ORIGIN_CHECK_ENABLED` (default `true`). The gateway emits no
  CORS headers, so every cross-origin browser request already fails in the browser; a list would
  widen a door that is bricked up, and it belongs with CORS if CORS ever arrives. The boolean also
  matches the eight existing `*_ENABLED` variables.
- **Global check.** `GET /healthz` falls outside it for free, being registered before any
  `router.Use`. `.well-known` stays inside — a cross-origin fetch cannot work without CORS headers
  anyway, so a 403 there breaks nothing that functions.
- **`Origin: null`** was missing from the intake entirely. Browsers send it from sandboxed iframes,
  `file://` documents and some redirect chains. Naming it up front is what kept the implementation
  from getting it wrong.

**The bug the test caught — worth recording, because the code was wrong and the comment was
confident.** The first implementation compared `normalizeOrigin(origin) == expected`. Since
`normalizeOrigin` returns `""` for anything unusable, an expected origin that itself normalized to
`""` would have matched `Origin: null`, and the guard would have degraded into a wildcard while its
doc comment claimed "fail-closed". `TestNormalizeOriginRejectsUnusableAsExpectedValue` — written
for exactly that suspicion — went red. Fixed by requiring a **non-empty** match. Unreachable in
practice, since `EXTERNAL_URL` is validated at startup, which is precisely why it would have
survived review.

**Second deviation: IPv6.** `url.Hostname()` strips the brackets from a literal, so the first
re-assembly turned `[::1]:8080` into the unparseable `::1:8080`. Fixed and covered by two rows in
`TestNormalizeOrigin`.

**Third, and the one that generalises beyond this task: the e2e suite does not prove the wiring.**
`e2e_harness_test.go` builds its **own** `gin.New()` router, so a green suite says nothing about
whether middleware added in `pkg/mcp-proxy/main.go` is actually mounted. Verified instead against
the **running binary**, the way F-007a did:

| Request | Result |
|---|---|
| `GET /healthz` with a foreign Origin | `200` — outside the check, as designed |
| `POST /mcp` foreign Origin | `403` |
| `POST /mcp` `Origin: null` | `403` |
| `POST /mcp` no Origin | `401` — passed the check, then hit auth |
| `POST /mcp` own Origin | `401` — same |
| `GET /.auth/login` own Origin | `200` |
| WARN log line | carries the offending **and** the expected origin |
| `ORIGIN_CHECK_ENABLED=false` | `401` instead of `403`, plus the startup warning |

**Tests:** 13 middleware cases and 15 normalization rows, plus the fail-closed guard.
**Verified non-vacuous:** removing the comparison turns seven rejection cases red at once.

**Standards note:** `pkg/mcp-proxy/main.go` grew 934 → 948 lines and `main.go` 565 → 568, both
already past the §2 hard limit. Unavoidable here, unlike F-017b where the tests could move: a global
middleware must be wired where the router is assembled, and a flag where the other flags live. The
*logic* lives in a new `origin.go`, so only the wiring touches the oversized files. **F-022** tracks
the split.

**Files:** new `pkg/mcp-proxy/origin.go` (96 lines) and `pkg/mcp-proxy/origin_test.go` (110);
`pkg/mcp-proxy/main.go` and `main.go` (wiring + flag); `SPEC.md` (§0 contract, §3 config table,
§4.2 row now ✔), `README.md` (an "Origin validation and `EXTERNAL_URL`" note beside the firewall and
CIMD ones), `.env.example`, `CHANGELOG.md` (Unreleased, with an upgrade note).

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues; gitleaks clean over the tree **and** the untracked new files.

**The risk this ships with, stated plainly in README and CHANGELOG rather than buried:** browsers
send `Origin` on same-origin POSTs, so the operator's own login and consent POSTs now carry it. An
`EXTERNAL_URL` that does not match the browser's address bar locks the operator out. The WARN log
names both origins so the cause is one line, and `ORIGIN_CHECK_ENABLED=false` is the rescue.

## F-019 — Evaluate whether DCR can be switched off — DONE 2026-08-22

A decision task, and it produced exactly that: **`DCR_ENABLED` stays `true` by default.** No code,
no config default, no behaviour change — `git status` showing only `.md` files is the evidence.

**Why the question was open.** F-003 chose "CIMD-first, DCR as deprecated fallback" at a time when
the AS metadata did not advertise CIMD at all — the gap F-015 closed. Once clients could actually
choose CIMD, whether this gateway still needed DCR became a live question rather than a settled one.

**The evidence asked for exists, and answers a narrower question than the one posed.** F-017d proved
live on 2026-08-21 that Claude switches to CIMD and the DCR store stops growing. That shows *Claude*
does not need DCR. It cannot show that *no* client needs it, and the README promises any OAuth-only
MCP client, not one vendor's.

**The decisive argument post-dates the entry entirely.** F-023, the evening before, made DCR the
**documented escape hatch**: `README.md` and `CHANGELOG.md` now tell deployments hit by the
Cloudflare challenge on datacenter IPs ([claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650))
to set `CIMD_ENABLED=false` and fall back to DCR. With DCR defaulting to `false`, that instruction
would not merely be clumsier — it would be **broken**: an operator flipping only `CIMD_ENABLED=false`
hits the both-disabled fail-fast and their gateway refuses to start. A workaround would become an
outage.

**The original motivation was also already gone.** The DCR store grew *because* the missing
advertisement forced clients onto DCR; F-015 fixed that. Disabling DCR would have solved a problem
that no longer existed, at the cost of the rescue path.

**The deliverable is guidance, not a bare verdict.** "No change" would have wasted the analysis, so
the outcome is written where an operator will meet it:

- `README.md` gained **"Should you turn DCR off?"** — what `false` actually removes (`POST
  /.idp/register` unrouted, `registration_endpoint` gone from the metadata), when the trade is
  reasonable (only CIMD-capable clients, smaller public surface per SR-10), and two warnings: never
  combine it with `CIMD_ENABLED=false`, and any client that cannot do CIMD stops working outright
  with no partial degradation.
- `REQUIREMENTS.md` §6 records the re-decision with its date and reason **beside** F-003 rather
  than rewriting it, so the history stays readable.

**Deviation from the plan: a fourth file.** The plan named two or three; `SPEC.md` §4.1 still read
"F-019 asks whether it should default to off". Leaving that would have left the conformance table
carrying an open question this very task answered — precisely the staleness F-017c built the table
to prevent.

**Counter-argument, recorded rather than dismissed:** `/.idp/register` is an open endpoint by spec,
and removing it would shrink the public surface (SR-10). It is bounded by SR-5 — TTL, a cap enforced
atomically inside the write transaction (F-012d), rate limiting — and the F-006b audit left nothing
open there. The escape hatch outweighs it for the *default*; for a single-client deployment the
trade goes the other way, which is what the README section is for.

**Files:** `README.md`, `REQUIREMENTS.md` §6, `SPEC.md` §4.1; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. The operator confirmed they are leaving their own deployment on the default.

**Verification:** only `.md` files touched; `DCR_ENABLED` unchanged in `main.go` and `.env.example`;
all relative links and every README anchor resolve; gitleaks clean.

## F-024a — Enumerate and revoke in the repository layer — DONE 2026-08-22

First substep of F-024. The repository layer had **no enumeration at all** — no `List`, no `All`, on
either backend — which is why deleting a single client record in F-017d needed a purpose-built bbolt
tool. It now has `InventoryStorage`, implemented for bbolt and SQLite, with no UI attached.

### What was done

| Method | Purpose |
|---|---|
| `ListClientGrants` | One row per client: origin, registration state and expiry, redirect URIs, scope union, per-grant breakdown, access/refresh record counts, first and last activity — newest activity first |
| `RevokeClient` | Every record of one client, registration included |
| `RevokeGrant` | One authorization, client and registration untouched |
| `RevokeAll` | The panic button, in one transaction |

**The listing is built from token records, not client records.** That is the finding the whole task
turns on and it survived contact with the code: since v0.3.0 Claude connects via CIMD, and a CIMD
client has **no stored registration** — `clientSource.lookupClient` re-resolves it from its URL on
every lookup. Enumerating `client-*` would have listed precisely the clients the operator cares
about least. Rows are therefore grouped from `access_token-*` / `refresh_token-*` by the client
snapshot each record carries, with stored registrations joined as a second source so a registration
without tokens still shows. `TestListClientGrantsFindsCIMDClientWithoutRegistration` is the guard.

**One aggregator, two backends.** `inventory.go` holds the grouping logic and both backends feed it:
bbolt walks key prefixes, SQL decodes request blobs. The two listings cannot drift apart, because
there is only one of them.

**Recognisability needed no new field**, as the prep predicted: a CIMD client's ID is its URL, and
every token record carries a client snapshot with the redirect URIs, so a DCR client with a random
ID is still identifiable. A stored registration outranks the snapshot — it is the live record.

### Decisions and deviations from the plan

- **`RevokeAll` added** — a fourth method where the plan named three. The approved panic button
  looped over `RevokeClient` would be N transactions, and a failure in the middle would leave
  clients with access while the UI reported a kill. One transaction per backend instead.
- **bbolt does not reuse `deleteMatching`**, which the plan assumed it would: that helper sweeps one
  prefix per transaction and returns no count, while the kill needs five prefixes plus the
  registration in **one**. New `staleRecords` + `revoke`; `deleteMatching` stays untouched for the
  RFC 7009 path it was written for.
- **SQL deletes uniformly by primary key**, not over the indexed `request_id` as the plan sketched.
  `RevokeClient` has to decode the request blobs regardless — no column holds the client — so a
  second, index-based path for two of the five tables would be a second chance to disagree. The
  index still serves fosite's own revocation.
- **An unreadable record is an error, not a skip.** This departs from the sweeper's precedent
  (`kvs.go`: "undecodable records are reclaimed by the sweeper, not revocation") and does so
  deliberately: for a kill switch, skipping a record means reporting a revoke that did not happen,
  and for the listing it means hiding a client that holds access. Both now fail loudly, and the
  transaction rolls back whole.
- **No schema change.** `SchemaVersion` stays 1 and a downgrade stays possible; SQL filters in Go
  rather than gaining an indexed `client_id` column, which is affordable because the tables are
  bounded by the DCR cap and the token TTLs.
- **The panic button spares the operator.** `RevokeAll` sweeps clients only — the user record, the
  passkeys and the schema marker survive. Answering a compromise by locking out the only person who
  can respond to it would be the wrong reflex, so a test guards it.

### Verification

- **30 subtests green** — 15 tests against both backends through the existing `testRepos` helper.
- **The green suite was not taken on trust.** Two deliberate mutations: dropping the
  authorization-code sweep from the revoke turned `TestRevokeClientRemovesEveryRecordKindAndSparesOthers`
  red on **both** backends, and making an undecodable record a skip instead of an error turned both
  fail-closed tests red. Restored, green again.
- Rotation history aggregates: **58 refresh records → one row, one grant** (the number F-017d found
  in the field).
- Revoking one client leaves another's records untouched, asserted **per record kind** rather than
  on tokens alone.
- `TestInventoryNeedsNoMigration` writes, closes and reopens each store, then lists — proof that a
  store written before this change needs no migration.
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**; `govulncheck` 0 vulnerabilities. No dependency change
  (`go.mod`/`go.sum` untouched), so licensing is unaffected.

**Standards work done alongside:** three functions came in over the §3 hard limit of 50 lines (55,
63 and 45) and were split into named helpers rather than parked under the ~80-line orchestration
exception; the longest is now 42. The test file crossed the §2 300-line target at 470 and was split
along its own section rules into `inventory_test.go` (listing, 249) and `inventory_revoke_test.go`
(revocation, 235) — F-022 should not inherit a fresh violation from the task queued ahead of it. Two
**pre-existing** §11 gaps in the file being edited were closed at the same time: `Repository` and
`AuthorizeRequestStorage` had no doc comment.

**Noted for F-022, not fixed here:** the bbolt key prefixes now exist as constants in
`kvs_inventory.go` while `kvs.go` still builds its keys from the same literals. Consolidating them
means editing `kvs.go`, which F-022 will split anyway.

**Files:** `pkg/repository/interface.go` (extended); new `pkg/repository/inventory.go`,
`kvs_inventory.go`, `sql_inventory.go`, `inventory_test.go`, `inventory_revoke_test.go`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No config, endpoint, dependency or schema change; no UI —
nothing calls the new methods yet, which is F-024b.

## F-024b — The settings surface and its wiring — DONE 2026-08-23

Second substep of F-024. `/.auth/settings` gained a **Connected clients** section: who holds
access, what they hold, and the actions that take it away — per client, per authorization, and the
panic button for everything at once. It sits behind the page's existing gates (`RequireAuth` +
`RequireCSRF` + `requireOwnUser`) and follows the "delete passkey" POST as the working template for
a destructive per-row action.

### What was done

- **`pkg/auth/clients.go`** — the view model and three handlers. `clientView` is a projection *by
  construction*: the stored records carry the client's hashed secret and the type has nowhere to put
  it, so no later template change can leak one. Redirect URIs are reduced to their distinct hosts —
  the recognisable part for a DCR client, whose ID is random — and a URI that does not parse
  contributes nothing rather than being rendered raw.
- **The template** shows one row per client (identity, CIMD or registration, redirect hosts,
  registration expiry, counts, last activity) with the authorizations behind a `<details>`. The
  wording says what an entry actually is: **per client and per authorization, not per device**, and
  a revoke ends access without banning the client.
- **Auth events (SR-8):** every revoke logs `revoked` with actor, scope, record count and client IP —
  an operator kill is now visible in the log beside the client-initiated RFC 7009 revocations that
  share the event name. Only non-secret context travels.
- **Wiring:** one line in `pkg/mcp-proxy/main.go`.

### The mutation that mattered

The suite was green on the first run, and one of its security tests was green **for the wrong
reason**. Removing `requireOwnUser` from the client-revoke handler left
`TestSettingsRevokeRejectsForeignSession` passing: the test used a bare `&http.Client{}`, which
*follows redirects*, so the handler's `302` was chased to the settings page — and that page's own
`403` satisfied the assertion. The test could never have failed when the gate it names was deleted.
Fixed by using the non-following client the package already has; the mutation then turns it red as
it should. The pattern came from the existing `TestSettingsRejectForeignSession`, where it is
harmless because the WebAuthn endpoint answers `403` directly instead of redirecting.

Two further mutations behaved correctly: dropping `RequireCSRF` from the revoke route turned the
CSRF test red, and swallowing the enumeration error turned the fail-closed test red.

### Decisions and deviations from the plan

- **`Config.Clients` is required when `Users` is set**, not optional with a nil check. A nil check
  in the handler would have been exactly the second visibility rule the acceptance criterion rules
  out; requiring it removes the nil case, mirrors the `ExternalURL` contract already documented in
  the same struct, and fails at construction rather than at the operator's first visit (§7). Cost:
  five construction sites updated — one production, four test files.
- **`pkg/auth/settings.go` was touched** although the plan did not list it: `handleSettings` renders
  the page, so that is where the list has to be loaded. `credentialViews` was extracted while there
  to keep the handler under the §3 limit (47 lines).
- **The confirmation is a server-rendered two-step** (`?confirm=revoke_all` renders a panel that
  carries the POST), not a JavaScript dialog — it works without JS and is genuinely two deliberate
  actions. The code records what it is: a guard against a slip, **not** against an attacker. The
  CSRF token and the session are what make the POST authentic; a direct POST by the logged-in
  operator still works, and that is the correct boundary.
- **The panic button only appears when something can be revoked**, and its panel states that the
  operator's own login, passkeys and settings are untouched and that no client is banned.
- **An unknown client ID answers exactly like a successful revoke** — same status, same `Location`.
  The operator's own page gains nothing from an existence oracle, and a typo should not read
  differently from a kill.

### Verification

- 15 tests in `pkg/auth` covering the surface, including every negative case the plan demanded:
  missing and wrong CSRF token (403, **and the record survives**), an OIDC-provider session on all
  three endpoints, and the unknown-client oracle check.
- The no-secret assertion was made non-vacuous: the test first proves the **store** holds the secret
  (a token record keeps a full client snapshot), then proves the rendered body does not.
- The fail-closed test asserts `500`, the absence of "No client currently holds access", **and** that
  the cause stays in the log rather than reaching the page (§6).
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**. No dependency change.

**Recorded rather than glossed over:** `pkg/auth/auth.go` grew by 24 lines to **558**, past the §2
hard limit it was already over before this change — the config field and the routes belong there,
and F-022 owns the split. `clients_test.go` sits at 347, over the 300 target and under the hard
limit, with section rules. And a doc comment on `handleSettings` that no longer described the page
was corrected.

**What this substep does *not* prove:** that the surface is reachable in the running binary. The e2e
harness builds its own gin router, so route registration and middleware in `pkg/mcp-proxy/main.go`
go unexercised — the same blind spot F-021 ran into. Only inspection backs it here
(`authRouter.SetupRoutes` is called, `Clients: repo` is set). F-024c supplies the proof.

**Files:** new `pkg/auth/clients.go`, `pkg/auth/clients_test.go`; changed `pkg/auth/auth.go`,
`pkg/auth/settings.go`, `pkg/auth/templates/settings.html`, `pkg/mcp-proxy/main.go`, and the four
construction sites in `e2e_harness_test.go`, `pkg/auth/abuse_test.go`,
`pkg/auth/hardening_test.go`, `pkg/auth/webauthn_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. Three new endpoints under `/.auth/settings/clients/`; no new config, no new
dependency, no schema change. `SPEC.md` and `README.md` are deliberately untouched — documentation
is F-024c.

## F-024c — Verify against the running binary, then document — DONE 2026-08-23

Third and final substep of F-024, and the one that had to answer a question no test suite in this
repo can: **is the surface actually reachable in the running process?** `e2e_harness_test.go` builds
its own gin router, so a green suite says nothing about route registration or middleware in
`pkg/mcp-proxy/main.go` — the blind spot F-021 ran into and recorded.

### Verified twice, deliberately

**First against a locally built binary**, the way F-021 did, before anything reached a deployment:
a real OAuth + PKCE flow (DCR registration → authorize → consent → token) produced a genuine access
token; `POST /mcp` with it was proxied; the settings page listed the client with its grant; the
page's own revoke POST returned `302 …?msg=revoked`; and the **same token was refused `401`
immediately afterwards**. The guards were exercised against the production router rather than the
test one: a revoke POST without a CSRF token and with a wrong one both got `403`, and without a
session cookie the surface redirected to the login. The panic button proved two-step — the list
offers only a link, the confirmation panel carries the POST — and after *Revoke everything* the
operator was still logged in.

**Then against the deployment**, with the operator's real Claude connector. The evidence came from
the auth-event log and the access log, and it lines up to the second:

| Time | Event |
|---|---|
| 11:55:12 | `revoked actor=operator scope=client` **records=7** — matching the page's "1 access / 6 refresh" |
| **11:55:56 / 11:55:58** | `POST /mcp` → **401**, user agent `Claude-User` |
| 11:56:17 | `POST /mcp` → `401` from the second client |
| 11:57:53 | `revoked scope=client` **records=1** — the leftover DCR registration, exactly one record |
| 11:58:17 | `login_ok method=passkey` |
| 11:58:34 | `token_issued` with a **CIMD** client id |
| from 11:58:35 | `/mcp` → `200`/`202` — the client works again |

**The decisive number is 44 seconds.** `ACCESS_TOKEN_TTL` is one hour, so without the
record-presence rule (SPEC §2.4) the revoked client would have kept working for up to sixty
minutes. It was refused on its next request.

**Two things only the live run could show.** The real client's row read **1 access / 6 refresh** as
a *single* row — rotation history aggregated on real data, the case F-017d met as 58 records. And a
**DCR registration left over from before the CIMD switch** appeared with `0 authorizations` and
*never*: the "a registration without tokens must still be listed" branch, seen for the first time
against something real rather than a fixture.

### What the verification found

**The two revoke buttons read as duplicates.** The operator asked what the difference was — a fair
question, because a client with exactly one authorization makes "Revoke" and "Revoke this one" do
the same thing, and a CIMD client has no registration for the client-level action to additionally
remove. Only the wording distinguishes them, and the wording did not. Relabelled to **"Revoke
client"** and **"Revoke this authorization"**, with a sentence in the expanded view stating what the
client-level action additionally takes. A test pins the distinction; renaming both back to the same
word turns it red. Fixed inside this substep rather than deferred, by the operator's decision and
following F-023's precedent that a defect found by live verification is fixed, not filed.

**One acceptance criterion was written too strongly by its own author.** "Re-authorization requires
the passkey" holds only when no operator session is open. With a live session the **consent page**
is what stands between a revoked client and a new token — which is the design (SPEC §1.5), and the
anti-phishing property is the consent step, shown in both cases. The operator noticed this
unprompted while testing and checked both paths. `SPEC.md` §1.12 and the runbook now state the
actual contract instead of the overstated one.

### Documentation

- **`docs/VERIFICATION.md`** — the F-017d manual store-editing procedure is **gone**, not annotated:
  the steps are replaced by "press Revoke client", with one sentence recording that hand-editing a
  live auth store used to be the only way and is not a routine step to keep on file. A new
  checklist group in §5 covers the client list, placed with the other manual checks rather than
  after the close-out.
- **`SPEC.md`** — §1.12 gains the three endpoints in the table and a contract paragraph (built from
  token records, not registrations; per client and per authorization, never per device; a revoke
  ends access at once and bans nobody); §2.1 records that the listing adds **no entity** and needs
  no migration.
- **`README.md`** — the settings paragraph and the endpoint table.
- **`CHANGELOG.md`** — an `[Unreleased]` entry with the two properties an operator has to know
  before using it, and the measured 44 seconds.

**Verification of the docs themselves:** every relative link in the four changed files resolves;
`gofmt`/`go vet`/`go test -race` green across 11 packages; `golangci-lint` 0 issues; GR-5 scan
clean — no hostname, IP, path or personal detail from the live run reached the repository.

**Operational state, recorded because it is easy to forget:** the deployment runs a **locally built,
unreleased image** carrying this work, by the operator's decision, and the data directory and
compose file were backed up before the swap. It is not reproducible from the registry until a
release replaces it — and the operator has chosen to do **F-025 and F-022 first**, so that state
persists for now.

**Files:** `SPEC.md`, `README.md`, `CHANGELOG.md`, `docs/VERIFICATION.md`,
`pkg/auth/templates/settings.html`, `pkg/auth/clients_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No behaviour change beyond the two button labels.

## F-024 — Operator view of connected clients, with a kill switch — DONE 2026-08-23


**Problem:** The operator cannot see which clients hold access, and cannot take it away. If a
device or a session is compromised, the only remedy today is stopping the gateway and editing the
bbolt store by hand — which is literally what F-017d had to do, with a purpose-built tool, to
delete one client record. `/.idp/revoke` does not help: it is RFC 7009 and **client-authenticated**,
so it lets a client drop its *own* token, never the operator drop someone else's.

**Idea:** Extend `/.auth/settings` with a list of clients and their active authorizations, with
timestamps, plus a per-entry action that deletes the client's registration and every token issued
to it. Access dies at once; a CIMD client can only return through a fresh authorization, which
needs the operator's passkey.

**Possible implementation:**
- The real work is **enumeration**, which the repository layer does not have — there is no `List`
  or `All` on either backend. It has to be added for client records and token records, for bbolt
  (cursor over the `client-` / `access_token-` / `refresh_token-` prefixes) and for SQL.
- The UI slot already exists: `/.auth/settings` runs behind `RequireAuth` + `RequireCSRF`, and the
  "delete passkey" POST is a working template for a destructive per-row action.
- **Granularity is per client and per grant, never per device.** A token record carries
  `RequestedAt`, `Client`, scopes and `RotatedAt` — no IP, no user agent. In the field Claude web
  and iOS shared a single client id, so "log out my old phone" is not expressible. The UI should
  say what it actually shows instead of implying device identity.
- **CIMD and DCR revoke differently.** A DCR client has a stored registration to delete; a CIMD
  client has none, because it is re-resolved from its URL on every use. Revoking it means
  destroying its tokens, after which it may re-authorize — the right property for a compromised
  device, since re-authorization requires the passkey, but the UI must not suggest a permanent
  ban. A denylist was weighed at intake and deliberately left out of scope.
- Revoking must cover **access and refresh tokens together**: a refresh token left behind mints a
  new access token immediately. F-017d found **58** refresh-token records for one client, so
  enumeration has to cope with rotation history rather than assuming a single row per client.
- Emit an auth event (SR-8) when the operator revokes, so a kill is visible in the log next to the
  existing `revoked` event.

**Dependencies:** none. Would retire the manual store-editing procedure that F-017d had to write
into `docs/VERIFICATION.md`.

**Substeps (`/prep-step`, 2026-08-22) — Large: ~950 lines across ~11 files, of which ~380 are
tests.** Reading the code moved three things the intake could not have known, and each one changes
the design rather than merely detailing it:

| # | Finding | Consequence |
|---|---|---|
| 1 | Since v0.3.0 Claude connects via **CIMD**, and a CIMD client has **no stored record at all** — `clientSource.lookupClient` re-resolves it from its URL on every lookup. An enumeration over `client-*` would therefore list precisely the clients the operator cares about **least**. | The list is built from **token records** grouped by `Request.Client.ID`; stored DCR registrations join as a second source, so a registration without tokens still shows. |
| 2 | Recognisability needs **no new field**. A CIMD client's `client_id` *is* its URL (`https://claude.ai/oauth/mcp-oauth-client-metadata`, the one F-023 recorded live), and a DCR registration stores its `redirect_uris`, whose host names the client just as well. | Identity in the list = `client_id` + redirect-URI hosts. No client-supplied free text enters the operator UI here; the naming idea became **F-025** instead. |
| 3 | "Last active" falls out of `RequestedAt`/`RotatedAt` on the token records. | The `last_used_at` that `SPEC.md` §2.1 lists for the DCR client entity, and that was never implemented, is not needed for this task. |

Decisions taken at prep time: **the panic button is in** (operator-approved) — a "revoke
everything" action with a confirmation step, cheap once enumeration exists and the thing the title
promises. **No schema change**: SQL filtering decodes the request blobs in Go rather than gaining an
indexed `client_id` column, so `SchemaVersion` stays 1 and a downgrade stays possible. **All new
code lands in new files** — `kvs.go` (470) and `sql.go` (694) and `auth.go` (534) are already at or
past the §2 limits that F-022 exists to fix, and this task must not make that worse.

### Complete (a/b/c)

The operator can now see who holds access and take it away — a capability the gateway simply did
not have. `/.idp/revoke` never provided it: RFC 7009 is **client-authenticated**, so it lets a
client drop its *own* token and never lets the operator drop someone else's. Before this, the
remedy was to stop the gateway and edit the bbolt store by hand, which is literally what F-017d had
to do with a purpose-built tool to delete a single record. That procedure has been removed from
`docs/VERIFICATION.md`; a button replaces it.

| Substep | Delivered |
|---|---|
| **F-024a** | `InventoryStorage` on the repository interface — `ListClientGrants`, `RevokeClient`, `RevokeGrant`, `RevokeAll` — for bbolt and SQLite, fed by one shared aggregator |
| **F-024b** | The *Connected clients* section in `/.auth/settings`, behind the page's existing gates, with per-client, per-authorization and panic actions |
| **F-024c** | Verification against a local binary **and** the live deployment, then the documentation |

**The finding that shaped everything** came from reading the code at prep time and held up in the
field: since v0.3.0 Claude connects via **CIMD**, and a CIMD client has **no stored registration**.
The obvious implementation — enumerate the client records — would have listed precisely the clients
the operator cares about least. The listing is therefore built from **token records**, with
registrations joined as a second source. The live run confirmed both halves at once: the real
Claude client appeared with no registration behind it, and a leftover DCR registration from before
the CIMD switch appeared with zero authorizations.

**What the design refuses to promise, deliberately:** granularity is per client and per
authorization, **never per device** — token records carry no IP or user agent, and every device
signed into the same client shares one client id, so "log out my old phone" is not expressible and
the page says so. And a revoke **bans nobody**: a CIMD client keeps no server-side registration, so
destroying its tokens is the whole of the action and it may authorize again. A denylist was weighed
at intake and left out of scope.

**Proof rather than assertion.** Three deliberate mutations were run against the finished code, and
one of them earned its keep: a security test in F-024b was passing **for the wrong reason** — a bare
`http.Client` follows redirects, so the handler's `302` was chased to the settings page and that
page's own `403` satisfied the assertion. The own-user gate could have been deleted unnoticed. The
generalisable lesson is recorded in F-024b: on this surface, any test asserting a status code
against a handler that can redirect must use a non-following client. Live, the decisive measurement
was **44 seconds** — the time between the operator's revoke and the real client's `401`, against an
`ACCESS_TOKEN_TTL` of one hour.

**Spawned:** **F-025** (naming a connection at consent time, which also closes a `SPEC.md` §1.5
identity requirement that has been unmet since it was written — DCR and CIMD both parse
`client_name` today and both discard it).

**Left for F-022:** `pkg/auth/auth.go` grew to 558 lines, past a §2 hard limit it already exceeded.
The config field and the routes belong there; the split does not belong in this task.

**Not yet released.** The deployment runs a locally built image carrying this work, by the
operator's decision, with the data directory and compose file backed up beforehand. The operator
chose to complete **F-025 and F-022 before the next release**, so that state persists until then.

## F-025a — The label, end to end — DONE 2026-08-23

First substep of F-025. A connection can now be given a name at consent time; the name is stored
with the authorization, shown wherever that authorization appears, and deleted with it.

### What was done

The name rides the gateway's **own session type** (`pkg/idp/session.go`), which fosite already
persists as `SessionData` with every record of the grant. That location decides three properties at
once, which is why it was chosen over the request `Form` the first sketch proposed: the session is
**server-built**, so no client can plant a label; it is written with every token record, so the name
travels; and it is deleted with those records, so there is **no cleanup path to forget**.
`models.Request` gains a `Label` lifted out of the session through a new `models.Labeled` interface,
so the repository and F-024's client list read it directly instead of decoding session JSON.

The consent page gains an optional text field. Its value is sanitized **once, where it enters**:
control characters dropped, trimmed, capped at 64 runes. One write point means one place to get it
right — and the log needs it as much as the page does, because `html/template` escaping does not
reach a structured log field. The list shows the name as the row's primary identifier with the
client id beneath it, and both `token_issued` and `revoked` carry it, so the auth log reads in the
operator's words.

### The mutations found two of my own test defects

The suite was green, and **two of its assertions did not test what they claimed.**

**First: the acceptance criterion itself was wrong.** It read "the label survives the token exchange
and every refresh — `Session.Clone` copies it, and the test goes red when that one line is removed."
Removing the line left everything green. The reason is worth recording, because it contradicts the
plan's mental model: at the authorize→token exchange the session is restored **from its stored
JSON**, so `Clone` is not on that path at all. `Clone` carries the name only on the **refresh**
grant, where fosite clones the loaded session in memory and persists the clone. The code comment
now states that, measured rather than assumed.

**Second: the refresh test could not see the difference.** It read the name through
`ListClientGrants`, which aggregates every record of a grant — so the *first* token's record, which
still had the name, answered for the refreshed one that had lost it. Both tests now look up the
record of **that specific token** by its signature. With that fix the mutation behaves correctly:
dropping the `Clone` line leaves the token exchange green and turns the refresh red.

A third assertion had the same shape: "the name identifies the row" was checked with a loose
`Contains`, which also matched the name in the per-authorization table below. Removing the row's
rendering left it green. It now asserts the row's own markup and fails as it should.

**Four mutations in total, each red after the fixes:** the `Clone` line, the label lift in
`models.FromFositeReq`, the row rendering in the template, and the `label` field on the `revoked`
event.

### Decisions and deviations

- **The label is set after `NewJWTSession`, not passed to it.** The constructor already takes four
  parameters where §3 allows three; the value comes from the consent form, so the assignment belongs
  at the call site rather than in a fifth parameter.
- **`logRevoke` now takes a `revokeEvent` struct** instead of four parameters — the label would have
  been a fifth. This removes a §3 violation that existed before this substep rather than growing it.
- **`handleToken` was already past the 50-line limit** and would have grown to 59; the event context
  moved into `tokenIssuedFields`, leaving the handler shorter than it was.
- The label is deliberately **not a JWT claim**: only `JWTClaims` reaches the token, and the
  operator's private note about a connection has no business travelling to the client.

### Verification

- 22 passing (sub)tests across `pkg/idp`, `pkg/repository` and `pkg/auth`, covering the flow, both
  storage backends and the rendered page.
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**. No dependency change.

**Noted for F-025b, not fixed here:** `pkg/auth/clients_test.go` reached 426 lines (§2 target 300,
hard limit 500) and F-025b adds prefill tests to it — the split belongs there.
`handleAuthorizationReturn` is at 71 lines, inside §3's orchestration exception, and the plan
already earmarks its split for F-025b.

**Files:** `pkg/idp/session.go`, `pkg/idp/consent.go`, `pkg/idp/token.go`, `pkg/models/models.go`,
`pkg/repository/inventory.go`, `pkg/auth/clients.go`, `pkg/auth/templates/settings.html`; new
`pkg/idp/label_test.go`; extended `pkg/repository/inventory_test.go`, `pkg/auth/clients_test.go`;
docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new endpoint, config, dependency or schema change.

## F-025b — The prefill, and the documentation — DONE 2026-08-23

Second and final substep of F-025. The consent field is now prefilled with the name the client
declares about itself, which also closes the `SPEC.md` §1.5 client-identity requirement that had
been unmet since F-004 wrote it.

### What was done

- **DCR:** `models.Client` gained `Name`, and `RegisterClient` now takes a `ClientRegistration`
  struct instead of four positional parameters — the fifth would have pushed it further past the
  three §3 allows, so the fix **removes** a violation rather than growing it. Seven call sites
  updated.
- **CIMD:** `IDPRouter` keeps the resolver it already hands to fosite, so the consent page reads the
  document's `client_name` through the **same** resolver — and therefore from the same cache.
- **New repository method `GetClientName`**, which the plan did not anticipate but the code
  demanded: fosite's client type has nowhere to carry a name, so `GetClient` can never return one.
  Kept deliberately narrow rather than a `GetClientRecord`, which would have handed callers the
  hashed client secret.
- Documentation: `SPEC.md` §1.5 (the requirement, now recorded as satisfied, plus the naming
  contract), §1.12 (rows identified by the operator's name), §2.1 (`client_name` is stored since
  this substep; the operator's own name rides the session and is no entity); `README.md`;
  `CHANGELOG.md` under `[Unreleased]`.

### The review caught a defect the tests could not

`step-done`'s file-by-file review found that **the SQL backend never stored the name**: the bbolt
implementation set `client.Name`, the SQLite one did not. Neither the suite nor the live
verification could have caught it —

- the `pkg/idp` prefill test drives a test server that is **always bbolt** (`setupTestServerWith`),
  so the DCR prefill was only ever exercised on one backend;
- the deployment runs bbolt too (no `REPOSITORY_BACKEND` set), so the live check passed for the
  same reason rather than despite it.

A SQLite deployment would have shown an empty prefill for every DCR client, silently. Fixed, and
covered by `TestClientNameRoundTrip` plus the unknown- and expired-registration cases, all running
against **both** backends through `testRepos`. Verified by re-removing the fixed line: the `sql`
subtest goes red, `kvs` stays green — which is precisely the shape the defect had.

The general lesson, and the reason it is recorded here rather than only fixed: **a contract that
both backends implement needs a test that runs against both.** The two-backend helper existed; the
new method simply had no test using it.

### The cache criterion, split honestly

The acceptance criterion read "resolving the CIMD name issues no additional outbound request". That
cannot be proven end to end at the `pkg/idp` layer: the real resolver's SSRF guard blocks a test
server, and the hook that works around it is package-internal to `pkg/cimd`. So the claim was split
into the two halves that *can* be proven, and both are:

- `TestConsentUsesTheConfiguredCIMDResolver` shows the consent page goes through the resolver the
  router was configured with — not a second one, not a direct fetch. Measured: **two consultations**
  per authorization, one from fosite's client lookup and one from the render.
- `pkg/cimd`'s existing `TestResolverHappyPathAndCache` shows that resolver serves a repeat
  resolution from cache without fetching.

Together: one document fetch per authorization. Recorded as two halves rather than asserted as one.

### Live verification

Deployed to the running gateway and exercised with the operator's real Claude connector. The
prefill arrived as **"Claude"** — the `client_name` in Claude's published CIMD document, which no
local test could have known, since the tests supply their own stub. The operator overrode it with
their own wording, and the log then read
`token_issued client_id=https://claude.ai/oauth/… label=claude.ai`. The omit-when-empty branch
verified itself in the same run: the `revoked` event for the *older* grant, authorized before this
feature existed, carried no label field at all.

### Cleanups this substep carried, both noted by F-025a

- `handleAuthorizationReturn` (71 lines) split into `approvedSession` and `grantRequested`; the
  latter now carries a statement that had been implicit — approval is all-or-nothing, not scope by
  scope (SPEC §1.5). The handler is at 48 lines.
- `pkg/auth/clients_test.go` (429 lines) split along its section rules into 230 + 220
  (`clients_revoke_test.go`). Verified as a pure move the way F-020 established: **19 declarations
  before, 19 after**, nothing lost — a green suite proves nothing about a move.

**Files:** `pkg/idp/idp.go`, `pkg/idp/consent.go`, `pkg/idp/register.go`, `pkg/models/models.go`,
`pkg/repository/interface.go`, `kvs.go`, `sql.go`; new `pkg/idp/prefill_test.go`,
`pkg/auth/clients_revoke_test.go`; tests in `pkg/repository/inventory_test.go`, `cap_test.go`,
`maintenance_test.go`, `pkg/auth/clients_test.go`; docs `SPEC.md`, `README.md`, `CHANGELOG.md`,
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new endpoint, config or dependency; no schema change.

## F-025 — Name a connection at consent time, and show the client's own name — DONE 2026-08-23


**Problem:** Three different names meet on this surface and are easy to confuse, so this entry names
them first: the **`client_id`** is fixed and verifiable (a URL for CIMD, a random string for DCR);
the **`client_name`** is what the client declares about *itself*; and there is **no third name** —
nowhere for the operator to write down what a connection actually is. F-024's list therefore
identifies a connection by its `client_id`, which for a DCR client is unreadable. Separately and
pre-existing: both mechanisms **parse** `client_name` and both throw it away — `registrationRequest`
in `pkg/idp/register.go` echoes it back and never stores it, `cimd.Client` never reads it — although
`SPEC.md` §1.5 says the consent page MUST show it. That is a literal gap in the gateway's own
contract; it sits outside the §4 conformance table, which tracks the MCP spec rather than our own.

**Idea:** Add **one field**. At consent time — the moment the operator is already looking at the
connection they started — a text box takes a short name, prefilled with the client's declared name
where there is one. It is stored with the authorization and shown wherever that authorization
appears. Everything already on the consent page stays exactly as it is.

**Solution (decided at `/prep-step`, 2026-08-23 — this replaces the intake sketch):**
- The label lives on the gateway's **own session type** (`pkg/idp/session.go`), which is already
  persisted as `SessionData` with every token record and deleted with the grant. **No new entity,
  no new table, no schema change** — and it is deliberately *not* the request `Form`, which is
  filled from the client's query parameters and would let a client plant its own label.
- `models.Request` gains a `Label` field, filled in `FromFositeReq`, so F-024's list and the
  repository layer read it directly instead of decoding session JSON.
- Prefill: CIMD through the resolver (cached, no extra outbound request), DCR from the
  `client_name` the registration already parses but has never stored.
- **Presentation stays plain** — a normal prefilled field, no claim marking. Operator decision, and
  it holds: the flow is operator-initiated and login-gated, the verified `client_id`, redirect URI
  and scopes stay visible below, and the page already warns to approve only self-started requests.
  The prefill only matters on a first connection; after that the field holds the operator's own text.
- The label travels into the auth events, so the log reads in the operator's words.
- **Renaming later is out of scope**: re-authorizing asks again, and the field is right there.

**Dependencies:** F-024 (done) — its list is where the name pays off.

### Complete (a/b)

A connection can be given a name where the operator is already looking at it, and that name follows
the authorization everywhere it appears — the client list, the auth log — and is deleted with it.

**The design came out of the operator's own pushback.** The first plan was three substeps with a new
entity keyed by client id, renaming in the list, and a claim-marked presentation of the client's
declared name. The operator asked why it was that complicated, and the question was fair: their
framing — "a new data field, not a new storage structure" — pointed at a place the plan had missed.
The name rides the gateway's **own session**, which fosite already persists with every record of a
grant. That single choice settled three properties at once: server-built, so no client can plant a
label; written with every token record, so it travels; deleted with those records, so no cleanup
path exists. Two of the three substeps fell away with it, and the renaming UI was never needed —
re-authorizing asks again.

**Presentation stayed plain**, also the operator's call, and the reasoning holds: the flow is
operator-initiated and login-gated, the verified client id and redirect URI stay visible beneath,
and the page already warns to approve only self-started requests. The prefill only matters on a
first connection; afterwards the field holds the operator's own words.

**It closed a spec violation nobody had noticed.** `SPEC.md` §1.5 required consent to show the
client's declared name; both registration mechanisms parsed `client_name` and discarded it, so the
page had shown the bare client id since F-004. The gap surfaced only because this task went looking
at the same code — and it prompted **F-026**, since the reason it stayed hidden is that §1.12 and
§1.5 read as changelogs rather than contracts.

**Three defects found, none by the suite being red.**

| Found by | What |
|---|---|
| Mutation (F-025a) | The acceptance criterion was wrong: `Session.Clone` does **not** carry the label through the token exchange — the session is restored from stored JSON there. `Clone` matters only on **refresh**. |
| Mutation (F-025a) | Two assertions could never fail: one read an aggregate where a specific record was meant, one used a loose `Contains` that matched elsewhere on the page. |
| Review (F-025b) | The **SQL backend never stored the declared name**. Invisible to both the suite (the idp tests are bbolt-only) and the live check (the deployment is bbolt too). |

The first two are now rules in `CODING-STANDARDS.md` §9 and §11; the third has its two-backend
contract test.

**Live-verified** with the real Claude connector: the prefill arrived as **"Claude"** from Claude's
published CIMD document, the operator's override reached the store, the list and the
`token_issued` event, and the older unnamed grant's `revoked` event correctly carried no label.


---

## F-026 — Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC — DONE 2026-08-23


**Problem:** Two documents describe what must hold, and one of them also narrates how it came to
hold. `SPEC.md` carries three jobs at once — contracts, the MCP conformance record (§4), and
implementation history: **108 of its 763 lines name an F-number**, across **15 "Delta" paragraphs**.
That history already lives in `PROGRESS-ARCHIVE.md`, in more detail, so the same story is told
twice and the worse telling sits in the contract document. It is not cosmetic: whoever opens §1.12
reads mostly *what changed when* instead of *what must hold*, which is how the §1.5 client-identity
MUST sat unread from F-004 until F-025 tripped over it. Meanwhile `REQUIREMENTS.md` is a second
document for the same genre, still marked "Status: draft" while v0.3.0 is public.

**Idea:** One document for rules, one for finished work, one for open work. `REQUIREMENTS.md`
disappears: its requirement register moves into `SPEC.md`, the parts that are duplicated elsewhere
are deleted, and the one statement that exists nowhere else is moved rather than lost. `SPEC.md`
then loses its history, because the archive already holds it.

**Decided at `/prep-step` (2026-08-23), with the measurements behind each decision:**

- **The register goes to `SPEC.md` as a new §5 — appended, never inserted.** Code references are
  distributed **§0 (9×), §1 (156×), §2 (64×), §3 (22×)**; inserting requirements as §0 or
  renumbering anything would break up to **251** references. Nothing points at §4, which is why §4
  stays where it is rather than becoming its own file — moving it would cost doc references for no
  gain, and splitting documents is what this task undoes.
- **Rejected: pointing the references at `PROGRESS-ARCHIVE.md`.** It conflates *work* with *rules*.
  Work has a lifecycle (backlog → done → archive); a rule is in force or repealed — SR-3
  (fail-closed) is satisfied today and must stay satisfied tomorrow, so it is never "done". The
  mapping is not one-to-one either: **SR-8 is referenced from 11 files and was implemented across at
  least five F-numbers** (F-005e2, F-006b, F-012c, F-024b, F-025a), **SR-5 from 13 files**. There is
  no single entry to point at, and new code — tomorrow's log line — would have no rule to cite at
  all. The archive is also append-only: when a contract changes the old entry stays correct about
  the past and wrong about the present, so a "current truth" pointer into it rots by construction.
- **Delete what is genuinely duplicated, verified item by item, not assumed:** §0 background (the
  archive holds F-001/F-003/F-009/F-017 in more detail; the watch item closed with F-017), §6
  decisions (the archive holds each with full rationale — the section's own heading says so), and
  from §5 the backup statement (`README.md`, Operations) and the env-compatibility rule
  (`SPEC.md` §3.3).
- **Move what exists nowhere else.** The **out-of-scope statement** is unique: README and CLAUDE.md
  say what the project *is*, but nothing anywhere says what it is *not* — no general-purpose IdP, no
  multi-tenant SaaS, and the constraint that multi-user must not be architecturally precluded. A
  search for "multi-user"/"single user" across README, CLAUDE.md and SPEC returns nothing.
  Suggested home: README's "Why" section, beside the rest of the project's identity.
- **References are repointed, including in the archive — pointers only, never claims.** An archive
  entry saying "REQUIREMENTS §6 records the re-decision beside F-003" becomes a pointer to the new
  location or carries "(formerly REQUIREMENTS §6)". Rewriting what an entry *asserted* would
  falsify the record; git makes it traceable, but nobody reads git history to learn what a document
  originally said. Nine files reference `REQUIREMENTS.md` today, two of them project skills
  (`audit-code`, `prep-step`).
- **`last_used_at` in §2.1 is corrected, not built.** F-025b made `client_name` real, leaving
  `last_used_at` as the only field in that row nothing has ever written. F-024 settled that "last
  active" comes from the token records and §2.1 itself says the client list needs no new entity, so
  a second timestamp on the registration would be a competing source of truth.

**Substeps** — the order is the point: build the safety net, then move, then edit.

### F-026a — The reference guard, before the surgery

**What:** A test in the repo (not a one-off script) that collects every `SPEC §…` and
`FR`/`GR`/`SR` reference from code and documentation and asserts each resolves. It runs in CI, so
the guarantee does not decay after this task. **Use the prefix rule:** a reference `§A.B.C` resolves
when any prefix of it is a real heading — `SPEC §1.11.3` means list item 3 inside §1.11, not a
heading `1.11.3`. A naive checker reports **36 false positives** on today's tree; with the prefix
rule the answer is **0**, and that zero is the baseline this task must preserve.

**Files:** one new `*_test.go` (placement to be decided — it checks repository documents, so the
root package is the natural home)

**Acceptance:**
- [ ] Green against today's tree, with the reference count reported so a silent drop to zero checks
      is visible (~251 `SPEC §…` + ~80 FR/GR/SR + ~30 in other docs)
- [ ] Red when a heading is renamed or a requirement ID removed — verified by doing it, not assumed
- [ ] Runs in CI with the normal `go test` invocation; no new tooling, no new dependency

### F-026b — Dissolve REQUIREMENTS.md

**What:** FR/GR/SR/NFR move verbatim into `SPEC.md` as **§5**, identifiers unchanged. The
out-of-scope statement moves to README. The duplicated parts are deleted. Every pointer to
`REQUIREMENTS.md` is updated — README, CLAUDE.md, THREAT-MODEL.md, CHANGELOG.md, PROGRESS.md,
PROGRESS-ARCHIVE.md, `HOW-TO-CODE-WITH-CLAUDE.md`, and the two skills in `.claude/skills/`. Then the
file is deleted.

**Files:** `REQUIREMENTS.md` (deleted), `SPEC.md`, `README.md`, `CLAUDE.md`, `THREAT-MODEL.md`,
`CHANGELOG.md`, `PROGRESS.md`, `PROGRESS-ARCHIVE.md`, `HOW-TO-CODE-WITH-CLAUDE.md`,
`.claude/skills/audit-code/SKILL.md`, `.claude/skills/prep-step/SKILL.md`

**Acceptance:**
- [ ] The F-026a guard stays green; **no §0–§4 heading number changed**
- [ ] All 25 requirement IDs present in §5, wording unchanged
- [ ] No file references `REQUIREMENTS.md` any more, and no dead link anywhere
- [ ] The out-of-scope statement survives in README — checked by searching for it, not by memory
- [ ] Archive edits are pointer-only; a diff review confirms no claim was altered

### F-026c — Strip the history out of SPEC

**What:** The 15 "Delta" paragraphs and the 108 lines naming F-numbers go, along with the
endpoint-overview status column ("exists, thin", "new") and the "Status: draft" marker. The
`last_used_at` row in §2.1 is corrected. **The editorial rule is the work:** where a Delta records a
*decision* rather than a date — why CIMD grant types are narrowed instead of rejected, why the
revoked-`jti` deny-list became a record-presence check — the statement stays and only the
bookkeeping goes. A regex that deletes every F-number line would take contract text with it.

**Files:** `SPEC.md`

**Acceptance:**
- [ ] The F-026a guard stays green
- [ ] No F-number and no "done," remains in `SPEC.md`
- [ ] Spot-checked: every removed Delta statement either survives in the contract text or is present
      in `PROGRESS-ARCHIVE.md` — listed explicitly in the step-done entry, not asserted
- [ ] `SPEC.md` reads as a contract from top to bottom: what must hold, not what changed when

**Dependencies:** none. F-022 touches Go files only, so the two can run in either order.

---

---

### What was actually done

**F-026a — the reference guard.** New `docs_refs_test.go` (root package, no new dependency): three
tests over every **git-tracked** text file. `TestSectionReferencesResolve` (348 refs),
`TestRequirementReferencesResolve` (258 refs against 25 IDs), `TestDocumentLinksResolve` (35 links).

**The plan's prefix rule was too weak, and the mutation proved it.** The plan specified "a reference
resolves when any prefix of it is a real heading". Built that way, renaming `### 1.11` to `### 1.14`
left the suite **green**: every `1.x` resolves as long as §1 exists. The rule now **counts the
ordered list items** of the parent section, so `§1.11.3` resolves because §1.11 really has a third
item — and a renamed heading goes red. Seven mutations were verified red: heading renamed, list item
deleted, item 9 of 5 cited, requirement definition removed, register split across two documents,
document link broken, `SPEC.md` deleted.

**Two scope corrections found by measuring, not by reading the plan:**
- The guard first walked the filesystem, which read **gitignored** files (`AUDIT-RESULTS.md`, and it
  would have read `private/`). It now reads `git ls-files`.
- After the register moved, the guard skipped the register document — which silently left SPEC's own
  61 requirement citations unchecked. Removed the skip; the count went 224 → 251.

**F-026b — the dissolution.** `REQUIREMENTS.md` deleted; its register is `SPEC.md` §5 (appended, no
§0–§4 heading renumbered), all 25 IDs verbatim. The out-of-scope statement moved to README ("Why").
Nine files repointed. In `PROGRESS-ARCHIVE.md` a **single reading note** at the top replaced fifteen
inline edits — no archived claim was altered.

**One plan decision reversed on evidence.** The plan called the backup statement and the
env-compatibility rule duplicates to be deleted. They are *cited* — `SPEC.md` §2.2 and §3.3 point at
them. Deleting them would have aimed two pointers at nothing, so both stayed in §5.5 as
intent-level lines with the concrete contract in §2.2/§3.3.

**F-026c — the redaction.** All 15 Delta paragraphs, all 108 F-number lines, the endpoint-overview
status column, the 11 `**target**` markers and the "Status: draft" header are gone. The contract text
went from 763 to 645 lines while gaining the 85-line register.

**Four statements existed only inside a Delta** and were lifted into the contract, or they would have
been lost: `exp` MUST be present (§1.11.1), the 4 MiB cap on redirect-replay body buffering (§1.11.3),
the post-login redirect normalisation (§1.12), and the SQLite pragmas plus cap atomicity (§2.5/§1.4).
An audit checked all 28 removed Delta statements: **28/28** survive in contract text, and the four
history-only claims (the upstream `Revoke*` no-op bug, the session-gate side fix, the non-resident
passkey upgrade note, the original base64url `kid` draft) are all present in this archive.

**Three editorial calls were put to the operator rather than decided here:** strip the `**target**`
markers (yes), strip the F-numbers from the conformance section too (yes), and the pre-F-012c
non-resident passkey note (delete — the lockout rescue it referenced was already stated in §1.12's
own prose).

Also corrected: the `last_used_at` field on the DCR client row in §2.1, which `models.Client` never
had and nothing ever wrote; and the §1.5 loopback warning, which sat **inside** the Errors sentence
(between "redirectable errors (`access_denied`," and "`invalid_scope`") and now precedes it.

**Files:** `docs_refs_test.go` (new), `SPEC.md`, `README.md`, `CLAUDE.md`, `CHANGELOG.md`,
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`, `HOW-TO-CODE-WITH-CLAUDE.md`, `REQUIREMENTS.md` (deleted),
`.claude/skills/audit-code/SKILL.md` and `.claude/skills/prep-step/SKILL.md` (edited, then deleted
outright in F-027).

**Deviation from the plan's file list:** it named `THREAT-MODEL.md` as carrying a `REQUIREMENTS.md`
reference. It does not — it only uses FR/GR/SR IDs, which kept working unchanged.


---

## F-027 — Retire the local skills and finish the documentation architecture — DONE 2026-08-23

**Intake note:** this task was not written by `/coding-kit:add-feature`. It came out of the
operator's review of the finished F-026 — three questions ("why were the local skills touched?",
"the spec is still long — rules or documentation?", "is anything duplicated or in the wrong
place?") — and was executed in the same session on their instruction. It is recorded as its own
F-number because the work is a separate concern from dissolving `REQUIREMENTS.md`, and finished
work without a home is worse than an out-of-band intake.

### The local skills are gone

`.claude/skills/` held four skills (`add-feature`, `prep-step`, `step-done`, `audit-code`) that the
project no longer uses — the workflow runs on the **coding-kit plugin** instead. F-026b had dutifully
*edited* two of them because its plan named them; the plan never asked whether they were still alive.
All four are deleted.

Deleting them was the smaller half. Six documents pointed at them: `CLAUDE.md` (three places),
`HOW-TO-CODE-WITH-CLAUDE.md` (rewritten — most of the file was about these four skills),
`CODING-STANDARDS.md` and `CONTRIBUTING.md` (both cite "the `step-done` skill" for commit-email and
secrets hygiene), plus the live workflow sentences in `PROGRESS.md` and `PROGRESS-ARCHIVE.md`.
Historical mentions of past `/audit-code` and `/prep-step` runs in the archive were left alone.

Two facts the repository did not record and now does: the workflow has **four** stages, not three
(`add-feature` → `prep-step` → **`build-step`** → `step-done`), and the plugin's `step-done` runs
"checks via just" while this project has **no justfile** — so `HOW-TO-CODE-WITH-CLAUDE.md` now names
the real gate (`gofmt`, `go vet`, `go test -race`, plus pinned `golangci-lint`, `go-licenses`,
`govulncheck`).

### SPEC is a rules document, and now says so

Measured rather than asserted: **325 citations from Go code against 46 from documentation**. Nobody
reads `SPEC.md` to *use* the gateway; it is read to *change* it. Two consequences:

- **§3 was a duplicate of README.** A first pass compared env-var *names* (52 of 56 shared) — too
  shallow a measurement to act on, so it was redone against content: README carries the validation
  ranges (1 m–24 h, `N/s|m|h`, `0` disables) **and** the three startup contracts the Go code cites
  from §3.1 (the plain-http WARNING, the auth-backend fail-fast, `TRUSTED_PROXIES` normalisation).
  The duplication was total. The tables are gone; §3 keeps only what is normative and points at
  README + `.env.example` for the reference — **−33 % characters** (6631 → 4415). Line count barely
  moved (73 → 76), which is why characters are the honest metric for a table-to-prose change.
- **§4 was a verification record, not a contract** (zero code citations). Moved to
  `docs/MCP-CONFORMANCE.md`. A 12-line stub stays at §4 so that the existing `SPEC.md §4` references
  in `CHANGELOG.md` and this archive — append-only records — keep resolving, and so no section is
  renumbered.

**A mistake worth recording:** qualifying the moved record's bare `§1.5`-style references (they meant
SPEC, but collided with the new file's own §1) was done with a blanket regex, which also rewrote
`RFC 8707 §2` and `CODING-STANDARDS §7`, and pointed the file's own §4.3 references at the stub.
Caught by inspection and repaired. A second slip — rewriting §3 dropped four requirement anchors
(FR-6, GR-1, SR-5, SR-9) — was caught by diffing the requirement-ID **multiset** against the previous
state, not by reading.

### The tidy-up the operator asked for, audited rather than assumed

Four checks were run; **five** things failed them:

1. **`docs/README.md` was a dead stub** — unlinked from anywhere, listing three "planned" documents
   (fronting an MCP server, adding the Claude connector, the configuration reference) that have all
   existed as full README sections for months. Deleted.
2. **`CLAUDE.md` claimed `v0.1.0` while the latest tag is `v0.3.0`** — two releases stale, the cost
   of keeping the release state in three documents. Fixed at the cause: `CLAUDE.md` now points at
   `PROGRESS.md` for the live state and keeps only what does not change.
3. **Three live pointers at the moved `SPEC.md` §4** (`THREAT-MODEL.md`, the close-out checklist in
   `docs/VERIFICATION.md`, the `PROGRESS.md` state paragraph) — repointed. Historical mentions left.
4. **Three competing document indexes** (README 9 entries, `CLAUDE.md` 5, `HOW-TO` 7, overlapping).
   `HOW-TO` now lists only the four files the workflow itself writes and defers to README.
5. **README's index named neither `CODING-STANDARDS.md` nor `CONTRIBUTING.md`.** It now separates
   **the rules** (`SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`) from **the records**
   (`docs/MCP-CONFORMANCE.md`, `docs/VERIFICATION.md`, `CHANGELOG.md`, `CONTRIBUTING.md`), each with
   a line on when to reach for it.

`SPEC.md` states in its own header that it is binding and names the two documents beside it;
`CLAUDE.md` names the same three up front. After the fixes, all 15 tracked documents are reachable
from README or `CLAUDE.md`, and no live pointer aims at a moved or deleted target.

**Files:** `.claude/skills/` (4 files deleted), `docs/README.md` (deleted),
`docs/MCP-CONFORMANCE.md` (new), `SPEC.md`, `README.md`, `CLAUDE.md`,
`HOW-TO-CODE-WITH-CLAUDE.md`, `CODING-STANDARDS.md`, `CONTRIBUTING.md`, `THREAT-MODEL.md`,
`docs/VERIFICATION.md`, `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.


---

## F-022a — The persistence and auth glue — DONE 2026-08-24

**What:** Cut `pkg/repository/sql.go` along its entity seams (token sessions, schema version,
clients, PKCE, authorize requests, user, WebAuthn, marshal helpers) and `pkg/auth/auth.go` along
its three concerns (router + setup, login flow, template rendering). Pure move, no behaviour change.

**Files:** `pkg/repository/sql.go` → several `sql_*.go`; `pkg/auth/auth.go` → several `*.go`

**Acceptance:**
- [x] Every touched file ≤ 500 lines; no new file above the 300-line target
- [x] **Identical declaration set** before/after (compared, not assumed) and identical body-line
      counts per declaration
- [x] `go test -race ./...` green with the test files untouched

### What was actually done

`pkg/repository/sql.go` (712) became four files, following the `sql_*.go` convention the package
already used for `sql_inventory.go`:

| File | Lines | Holds |
|---|---|---|
| `sql.go` | 173 | connection, `configureSQLite`, schema version, marshal helpers |
| `sql_sessions.go` | 275 | authorization codes, access/refresh tokens, PKCE, authorize requests |
| `sql_clients.go` | 197 | DCR registrations including the atomic cap check |
| `sql_users.go` | 106 | the operator account and passkey credentials |

`pkg/auth/auth.go` (558) became four files with concern names, as `pkg/idp` got them in F-020:

| File | Lines | Holds |
|---|---|---|
| `auth.go` | 176 | `AuthRouter`, `Config`, constructor, template constants |
| `routes.go` | 98 | `SetupRoutes`, `withRateLimit` |
| `login.go` | 206 | login/logout, lockout, redirect normalisation, `RequireAuth` |
| `render.go` | 105 | template data types and the three render functions |

**The cut was mechanical, not hand-edited.** A script assigned whole declaration segments — each
declaration extended upward over its contiguous doc comment — so every line after the import block
landed in exactly one output file. `goimports` then fixed the per-file import sets. Hand-editing
730 lines of seams is where a "pure move" quietly stops being one.

**The plan's invariant was proven with an AST parser, not with text patterns.** A throwaway tool
(`go/parser`) printed `kind name bodyLines` per top-level declaration, sorted, for the whole
package including its tests. `pkg/repository`: **215 declarations identical**. `pkg/auth`: **197
identical**. Body-line counts come from the AST, so comments and formatting cannot shift them.

**One check beyond the plan.** The declaration invariant cannot see a comment stranded between the
import block and the first declaration — it would simply vanish with no declaration changing. A
multiset comparison of every content line, original against the union of the new files, reported
**0 lost and 0 gained** for both files. Worth keeping for F-022b and F-022c: the AST invariant
proves declarations moved intact, the line multiset proves nothing fell out between them.

**A first attempt failed and was reverted before it could mislead.** The assignment patterns were
written against the tool's `Type.Method` output form while the source reads `) Method(`, so almost
nothing matched and `sql.go` stayed at 496 lines with three near-empty siblings. `git checkout` on
the original, corrected patterns, re-run.

**Not fixed here, deliberately: import grouping.** CODING-STANDARDS §4 asks for stdlib →
third-party → local, and the new files put the local imports in the third-party group. That is not
a regression — measured, **46 of 46** files in the repository carrying a local import do the same,
including the originals of both split files and files this task never touched. Fixing it here would
break the pure move and leave four files unlike the other ninety. Worth its own task; noted rather
than silently built.

**Files:** `pkg/repository/sql.go`, `pkg/repository/sql_sessions.go` (new),
`pkg/repository/sql_clients.go` (new), `pkg/repository/sql_users.go` (new), `pkg/auth/auth.go`,
`pkg/auth/routes.go` (new), `pkg/auth/login.go` (new), `pkg/auth/render.go` (new). No test file was
touched, which is what makes the green suite evidence rather than decoration.


---

## F-022b — The CLI surface — DONE 2026-08-24

**What:** `main.go` (env helpers vs. the three Cobra commands) and `main_test.go` (parsing tests vs.
command tests) are one surface and get one cut, so the test layout mirrors the production layout.

**Files:** `main.go`, `main_test.go` → `env.go`/`env_test.go` + command files

**Acceptance:**
- [x] Both files ≤ 500 lines
- [x] Identical declaration sets and body-line counts
- [x] **`go test -list '.*'` returns the identical test set** before/after

### What was actually done

`main.go` (568) and `main_test.go` (776) were cut together into **five pairs**, each production file
carrying a test file of the same name:

| Production | Lines | Test | Lines | Holds |
|---|---|---|---|---|
| `main.go` | 248 | `main_test.go` | 204 | `main`, `newRootCommand`, flag wiring |
| `env.go` | 73 | `env_test.go` | 154 | the five `getEnv*WithDefault` readers |
| `parse.go` | 106 | `parse_test.go` | 260 | `splitCSV`, `splitWithEscapes`, attribute and header mapping |
| `healthcheck.go` | 73 | `healthcheck_test.go` | 88 | the `healthcheck` command, `probeHealth`, `healthURL` |
| `rotatekey.go` | 96 | `rotatekey_test.go` | 96 | the `rotate-key` command and its options |

**Deviation from the plan: five pairs instead of the planned two or three files.** The plan said
"env helpers vs. the three Cobra commands". Reading environment variables and splitting strings are
different jobs, and separating them is what keeps `parse_test.go` at 260 lines instead of ~415 —
otherwise one file would have stayed above the 300-line target while still satisfying the ≤ 500
criterion. The exact mirroring is the second reason: five names, five twins, so the test for a
function is always in the file named after the file that holds it.

**All three invariants held, each compared rather than asserted:** the AST declaration set including
body-line counts (**94 declarations**, unchanged), `go test -list '.*'` (**29 tests**, identical
set), and the line multiset (**0 lost, 0 gained** for both files). The multiset check earns its
place here more than in F-022a: this substep *does* touch test files, so a green suite no longer
proves on its own that nothing was dropped.

**One check specific to splitting a Go file by name.** A file whose name ends in something Go reads
as a build constraint is silently excluded from the build rather than rejected. `go list` confirms
all five production files land in `GoFiles`, all five test files in `TestGoFiles`, and
`IgnoredGoFiles` is empty.

**Two pre-existing test fixtures tripped the secrets scan and were deliberately left alone:**
`user@domain.com` (a placeholder in a string-splitting table) and `10.0.0.5:8080` (an example of a
wildcard listen address in `healthURL`'s doc comment). Both are in `HEAD` unchanged — generic
examples, not deployment internals or a real address. Rewriting them would have broken the pure
move for no gain; if the project ever wants RFC 5737 placeholders throughout, that is its own task.

**Files:** `main.go`, `main_test.go`, `env.go` (new), `env_test.go` (new), `parse.go` (new),
`parse_test.go` (new), `healthcheck.go` (new), `healthcheck_test.go` (new), `rotatekey.go` (new),
`rotatekey_test.go` (new).


---

## F-022c — The proxy test file — DONE 2026-08-24

**What:** Split `pkg/proxy/proxy_test.go` (1035) by theme — token validation, header mapping,
discovery/PRM, reserved namespaces and streaming — with the shared helpers (lines 26–64) kept in
one place.

**Files:** `pkg/proxy/proxy_test.go` → several `proxy_*_test.go`

**Acceptance:**
- [x] Every file ≤ 500 lines
- [x] `go test -list '.*'` identical before/after; no helper duplicated

### What was actually done

`pkg/proxy/proxy_test.go` (1035) became four files. Mirroring production, as F-022b did, was not
available here: `pkg/proxy` has a **single** production file (`proxy.go`, 251 lines, already inside
the limit). So the cut is thematic, along the seams `proxy.go` itself forms, and the names follow the
package's existing convention — `transport_test.go` carries no `proxy_` prefix, so neither do these:

| File | Lines | Covers |
|---|---|---|
| `token_test.go` | 343 | bearer validation: signature, `iss`/`aud`, missing `exp`, clock skew, multi-key JWKS, record presence |
| `upstream_test.go` | 414 | what leaves toward the upstream: claim-to-header mapping, anti-spoofing, credential policy |
| `metadata_test.go` | 116 | protected-resource metadata and the 401 challenge that points at it |
| `proxy_test.go` | 203 | the shared helpers, reserved namespaces, SSE gating |

**Deviation from F-022a and F-022b: two files stay above the 300-line target.** `token_test.go` (343)
and `upstream_test.go` (414) are under the 500-line hard limit, which is the acceptance criterion,
but not under the target that a and b both reached. §2 asks to *check* whether a file above 300 can
be split, and the check was made: the finer cuts are artificial. Separating "is the token valid"
from "is the token still active", or claim mapping from credential policy, tears apart tests that
exercise the same contract line. Four coherent themes under the hard limit beat six invented ones
under the target.

**One line that is not a move, and is in scope precisely because of that.**
`pkg/proxy/transport_test.go` opened with "They live apart from proxy_test.go because that file is
already far past the 500-line hard limit in CODING-STANDARDS §2 (F-022 tracks the split)". This
substep is that split, so the sentence became false the moment it landed. It now states what the
file is delimited *against* — the ordinary proxy path's mapping and credential tests in
`upstream_test.go` — instead of citing a limit that no longer applies.

**All invariants held:** 35 AST declarations with identical body-line counts, `go test -list`
identical at 17 tests, line multiset **0 lost / 0 gained** across 885 content lines, and each of the
five shared helpers (`testKid`, `testKeyLookup`, `generateRSAKeyPair`, `createJWT`,
`createDummyBackendServer`) has exactly **one** definition in the package — the criterion that
matters most when a test file is split, because duplicating a helper compiles and then silently
drifts. `go list` confirms every new file is in `TestGoFiles` and `IgnoredGoFiles` is empty.

**Files:** `pkg/proxy/proxy_test.go`, `pkg/proxy/token_test.go` (new), `pkg/proxy/metadata_test.go`
(new), `pkg/proxy/upstream_test.go` (new), `pkg/proxy/transport_test.go` (comment only).

**One file remains past the hard limit:** `pkg/mcp-proxy/main.go` (949), for F-022d and F-022e — the
part where these invariants stop applying, because `Run` is decomposed rather than relocated.


---

## F-022d — `Run`, part 1: configuration and dependencies — DONE 2026-08-24

**What:** Extract phases 1–4 of `Run` (lines 218–485) into named functions that take configuration
and return values: issuer normalisation, TTL and proxy validation, data directory and logger,
repository open plus schema check, key manager, abuse-protection limiters and the expiry sweeper.
New files follow the package's existing concern-file convention (`cookie.go`, `origin.go`).

**Files:** `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/config.go` and `pkg/mcp-proxy/deps.go`,
new/extended `pkg/mcp-proxy/*_test.go`

**Acceptance:**
- [x] `Run` no longer performs configuration normalisation, validation, data-directory, logger,
      repository, key-manager, limiter or sweeper setup inline
- [x] The one genuinely uncovered fail-fast branch gets a test: **CIMD and DCR both disabled**
      (`main.go:167.41,169.3`, execution count 0 today)
- [x] The 13 existing `Run`-level fail-fast cases stay green **unchanged** — they are the
      regression net for this refactor, not something to be replaced by finer tests
- [x] Coverage of `pkg/mcp-proxy` **recorded before and after** (46.9 % today). No target number is
      promised: most uncovered statements are the router and server code that F-022e moves, so a
      large rise here would be surprising rather than good
- [x] `go test -race ./...` green

### What was actually done

`Run` went from **645 to 415 lines**, `pkg/mcp-proxy/main.go` from 949 to 716. Not under the limit
yet — phases 5–7 are F-022e's ~380 lines.

| File | Lines | Holds |
|---|---|---|
| `config.go` | 124 | `resolveConfig`: issuer normalisation, TTL defaults, `validateTTLs`, `TRUSTED_PROXIES`, TLS flag combinations |
| `deps.go` | 249 | `openDependencies`: data directory, session secret, logger, upstream backend, proxy headers, repository + schema check, key manager |
| `sweeper.go` | 78 | `limiters`, `newLimiters`, `startSweeper`, `sweep` |
| `config_test.go` | 119 | the new tests |

**The order of the checks is contract, and it was preserved deliberately.** A misconfigured
deployment sees the *first* problem found, and the 13 existing fail-fast cases assert on those
messages. `resolveConfig` reproduces the original sequence exactly; all 13 stayed green without a
single test being touched, which is what makes them evidence here rather than decoration.

**Three deviations from the plan, each for a reason:**

- **Three new files, not two.** `deps.go` came out at 324 lines, above the 300-line target. The
  sweeper is a background maintenance loop rather than startup work, so it moved to `sweeper.go`;
  both are now comfortably under.
- **`servesTLS()` was written and then deleted.** It was speculative, for F-022e. `golangci-lint`
  flagged it as unused and was right — it returns when it has a caller.
- **`sweep` had four parameters, against §3's maximum of three.** Caught in review, not by a tool:
  `golangci-lint` does not check that. Fixed by moving the refresh-window fallback onto
  `resolvedConfig` as `refreshSweepTTL()`, which is where it belongs anyway — it is a property of
  the configuration, not an argument to a sweep.

**Coverage 46.9 % → 48.1 %, measured.** The modest rise was predicted in the plan: most uncovered
statements are the router and server code F-022e moves. The one branch this substep was supposed to
close — CIMD and DCR both disabled — now shows execution count **1** in the profile where it showed
0.

**Three new assertions, each proven able to fail** (CODING-STANDARDS §9): removing the
both-disabled check makes the new test fail; removing `issuerURL.Path = ""` makes the issuer test
report the trailing slash; forcing the TLS-combination branch to `false` makes the table fail.

**One behaviour that changed shape without changing outcome.** `Run` used to register
`defer repo.Close()` immediately after opening the store, so any later failure closed it. Now
`openRepository` closes it on a schema-version failure and `openDependencies` closes it when the key
manager fails; the caller only takes ownership on success. Same guarantee, stated explicitly
instead of relying on the defer frame — and documented on the `dependencies` type, because a
half-built gateway leaving an open store is exactly the kind of thing that is invisible until it
is not.

**Files:** `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/config.go` (new), `pkg/mcp-proxy/deps.go` (new),
`pkg/mcp-proxy/sweeper.go` (new), `pkg/mcp-proxy/config_test.go` (new). No existing test touched.


---

## F-022 — Bring the remaining oversized files under the §2 limits — DONE 2026-08-24

**Problem:** CODING-STANDARDS §2 sets a 300-line target and a **500-line hard limit**. F-020 brought
`pkg/idp` under it, but nothing ever surveyed the rest of the tree: **six files are still past the
hard limit**, the largest at 1035 lines, and fourteen more sit above the 300-line target. F-017b ran
straight into this — its new tests could not go into `pkg/proxy/proxy_test.go` without pushing a
1035-line file to 1180, so they went into a new file and the underlying violation stayed untouched.

| File | Lines | Kind | State |
|---|---|---|---|
| `pkg/proxy/proxy_test.go` | 1035 | tests | **done (F-022c)** |
| `pkg/mcp-proxy/main.go` | 949 | production — assembly and config wiring | F-022d/e |
| `main_test.go` | 776 | tests | **done (F-022b)** |
| `pkg/repository/sql.go` | 712 | production — SQL persistence | **done (F-022a)** |
| `main.go` | 568 | production — CLI surface | **done (F-022b)** |
| `pkg/auth/auth.go` | 558 | production — password/session/WebAuthn glue | **done (F-022a)** |

Same origin as F-020's two files: they came over with the F-008 fork and grew through F-005 and
everything after it. Size is not cosmetic in this repo — these are the files a reviewer has to hold
in their head to reason about the auth boundary.

**Idea:** Repeat the F-020 method. Cut each file along the seams its declarations already form, as a
**pure move** with no behaviour change, so the existing tests are the proof rather than something
that also changed.

**Decided at `/prep-step` (2026-08-23), with the measurements behind each decision:**

- **Five of the six files are pure moves. One is not, and that governs the shape of this task.**
  `pkg/mcp-proxy/main.go` holds a **single 650-line function**, `Run` (lines 217–866). Moving out
  everything else — the `Config` struct with its validation (~170 lines) and the small helpers
  below `Run` (~83 lines) — still leaves ~690 lines around one 650-line function. The file cannot
  reach the limit by relocation; `Run` has to be decomposed, which is restructuring, not moving.
- **The invariant proof does not transfer to `Run`.** F-020's method rests on identical declaration
  sets and identical body-line counts, which only prove anything while nothing changes. `Run` is
  called from exactly one place (`main.go:189`) and the e2e suite does **not** exercise it —
  `e2e_harness_test.go` says so itself ("builds the gateway exactly as `Run()` mounts it"), i.e. it
  is a parallel implementation. This is the same gap F-021 found, so the proof for the wiring has
  to be the running binary.
- **Correction, re-planned 2026-08-24: the fail-fast paths are *not* untested.** The first plan
  claimed they were and made "tests for the paths that had none" the point of F-022d. Measured
  instead of inferred: `TestRun_ValidatesTTLs` (11 cases), `TestRun_RequiresAuthBackend` and
  `TestRun_NormalizesTrustedProxies` already cover three of the four, all through `Run` itself.
  Exactly one branch is genuinely uncovered — **both CIMD and DCR disabled**, `main.go:167.41,169.3`
  with execution count 0, and no test sets both flags to `false`. Two of the checks do not even sit
  in `Run`'s body but in `validateTTLs`, which is already extracted. The claim came from reading
  `Run`'s **35.0 % statement coverage** as if it described its branches: the figure is low because
  the tests return at the fail-fast and never reach the ~500 lines of router construction and server
  start — the fail-fast paths are the part that *is* covered. `CODING-STANDARDS.md` §9 lists that
  trap first: "Reading an aggregate where one record was meant."
- **Splitting `Run` is still two substeps, not one** — that decision rested on size and risk, which
  are unchanged — cut at the seam its own phases already form: configuration and dependencies
  (218–485) against wiring and server lifecycle (486–861).
- **The real testing gain is retiring the parallel implementation, and it has already drifted.**
  `newE2EGateway` (76 lines) rebuilds what `Run` mounts, and a helper beside it says it "mirrors
  Run's construction". The two have diverged where it matters: `Run` builds the operator session
  cookie with HKDF-derived subkeys so it is signed **and** encrypted and sets `HttpOnly`, `Secure`,
  `SameSite=Lax` and `MaxAge 600`; the harness calls `cookie.NewStore(secret[:])` and never calls
  `store.Options` at all. The e2e suite therefore cannot catch a regression in any of those §1.12
  properties. Once the wiring is a named function the harness can call it, which closes this by
  construction rather than by vigilance.
- **§3 violations stay out of scope.** `handleRegister` (109 lines), `newRootCommand` (232) and
  `handleProxy` (118) are function-length problems, not file-length ones. `Run` is the sole
  exception, because §2 is unreachable there without §3.
- **The fourteen files between 300 and 500 stay out of scope** unless a cut makes them fall out
  naturally; §2 only asks to "check whether it can be split" at 300, and the hard limit is the
  actual violation. `pkg/repository/kvs.go` (487) mirrors `sql.go` and would be worth the same cut
  afterwards for package symmetry — as its own task, not here.

**Substeps** — the pure moves first, so the invariant harness is established before the one change
it cannot prove. **F-022a–d are done.** `pkg/mcp-proxy/main.go` is down from 949 to 716 lines;
F-022e's phases 5–7 are the remaining ~380 that bring it under the limit.

The verification harness F-022a established, to be reused by b and c: an AST parser prints
`kind name bodyLines` per top-level declaration for the whole package (tests included) — identical
before and after proves the declarations moved intact — plus a **line multiset** comparison, which
catches what the declaration invariant cannot: a comment stranded between the import block and the
first declaration would vanish without any declaration changing.

### F-022e — `Run`, part 2: wiring and lifecycle

**What:** Extract phases 5–7 (lines 486–861): auth/IDP/proxy router construction, the gin assembly
(trusted proxies, `/healthz`, logging, origin check, session store) and the server lifecycle
(listeners, TLS/ACME, shutdown). The extraction must yield a function that builds and returns the
`*gin.Engine` **without** starting a listener — otherwise `e2e_harness_test.go`, which needs
`httptest`, still cannot call it. That is the design decision of this substep.

**Files:** `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/router.go` and `pkg/mcp-proxy/server.go`,
`e2e_harness_test.go`

**Acceptance:**
- [x] `pkg/mcp-proxy/main.go` ≤ 500 lines and `Run` within the §3 orchestration exception (~80)
- [x] `e2e_harness_test.go` calls the extracted wiring instead of rebuilding it — **or** the reason
      it cannot is recorded in the step-done entry, in which case the drift below is raised as its
      own task rather than left implicit
- [x] The known divergence is closed or explicitly recorded: the harness builds the session cookie
      with `cookie.NewStore(secret[:])` and never calls `store.Options`, so it runs without
      encryption, `HttpOnly`, `Secure` or `SameSite` — unlike `Run`
- [x] **Verified against the running binary**, not only the suite: the gateway starts against a
      deployment-like configuration, serves the three discovery documents, and answers `/mcp`
      without a token with `401` plus the `WWW-Authenticate` challenge
- [x] Each fail-fast path still aborts startup with its message, checked against the built binary
- [x] `go test -race ./...` green

**Dependencies:** none — but like F-020 it must not land between F-017's verification and the v0.2.0
tag, or the release would ship code the verification never saw.

---

### F-022e — what was actually done

`Run` went from 415 to **27 lines** and `pkg/mcp-proxy/main.go` from 716 to **312**. Counting the
whole task: `main.go` 949 → 312, `Run` 645 → 27. **No file in the repository exceeds the 500-line
hard limit any more** — the goal F-022 was raised for.

| File | Lines | Holds |
|---|---|---|
| `router.go` | 265 | `BuildRouter` plus the auth/IDP/proxy constructors, the session store and the revocation check |
| `server.go` | 223 | `serverGroup`, `gateway`, the three TLS modes, `acmeHost` |
| `main.go` | 312 | `Run` and the small helpers |

**The server phase was three near-identical blocks.** Each TLS mode carried its own copy of the
listen goroutine plus the shutdown goroutine — roughly 150 lines of duplication. They collapse into
`serverGroup.serve`, which decides TLS from the server's own `TLSConfig`. One consequence worth
naming: the plain-HTTP branch previously logged no "server closed" debug line where the other two
did; unifying them gives it one.

**The design constraint was met.** `BuildRouter` returns the assembled `*gin.Engine` **without
listening**, which is what the plan required so the end-to-end tests could drive the real wiring.

**But the harness still cannot call it, and that was not foreseen.** `resolvedConfig` and
`*dependencies` are package-private while `e2e_harness_test.go` lives in package `main`. The
package boundary, not the listener, is the blocker. Per the acceptance criterion's own escape
clause this was recorded rather than solved here, and the operator chose a separate F-number:
**F-028** carries the relocation, the cookie divergence, the third `tokenActiveChecker` copy — and
explicitly the retrofit of what this substep left behind. Concretely, `BuildRouter` was exported in
anticipation of a caller that cannot exist: **its parameter types are package-private, so nothing
outside the package can call it at all**, and its only caller is `Run`. F-028 owns that correction.

**Verified against the running binary, not only the suite** — the point of this substep, because
the e2e suite provably does not exercise this path. All five fail-fast paths abort with their
message (no auth backend, CIMD and DCR both disabled, malformed TTL, invalid `TRUSTED_PROXIES`, no
upstream). Running against a mock upstream: the three discovery documents answer `200` and are
self-consistent (PRM `resource` equals AS `issuer`), `code_challenge_methods_supported` is
`["S256"]`, CIMD is advertised, `POST /mcp` without a token answers `401` with
`WWW-Authenticate: Bearer resource_metadata="…"`, a foreign `Origin` gets `403` and the gateway's
own gets `200`.

**One documented linter exception.** gosec G118 wants the shutdown context derived from `ctx`. That
would be **wrong**: `ctx` is already cancelled when the shutdown goroutine runs — that is why it
runs — and a cancelled parent makes `Shutdown` return at once instead of draining in-flight
requests. `//nolint:gosec` with that reason, in the form the repository already uses in nine places.

Coverage of `pkg/mcp-proxy` rose 46.9 % → **52.7 %** across F-022d and F-022e, without a single
existing test being modified in either.

**Files:** `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/router.go` (new), `pkg/mcp-proxy/server.go` (new).

### F-022 as a whole

Six files were past the hard limit, the largest at 1035 lines. Four substeps were **pure moves**,
proven by invariants — identical AST declaration sets with per-declaration body-line counts,
identical `go test -list` output, and a line multiset showing nothing lost or gained. The fifth was
not a move and could not use those invariants, which is why it was split off and verified
behaviourally instead.

Two lessons the task produced beyond the file sizes. **The planned safety net was too weak, and
only a mutation showed it:** built to the specified prefix rule, renaming a heading left the suite
green, because every `1.x` resolves while `§1` exists. **And a plan built on an inferred fact had to
be re-planned mid-task:** F-022d's stated purpose rested on reading `Run`'s 35 % statement coverage
as if it described its branches, when three of the four fail-fast paths were already covered. Both
are recorded where they happened rather than smoothed over.


---

## F-028a — Move the end-to-end tests into the package — DONE 2026-08-24

**What:** Relocate `e2e_harness_test.go` and `e2e_test.go` (794 lines) to `pkg/mcp-proxy`, otherwise
unchanged — they keep building the gateway themselves for now. One change is forced: the harness's
`tokenActiveChecker` collides with the production copy in `router.go`, so **the compiler proves the
duplication** the moment they share a package.

**Files:** `e2e_harness_test.go`, `e2e_test.go` (both moved)

**Acceptance:**
- [x] `go test -list '.*'` returns the same test set across the repository as before the move
- [x] `go test -race ./...` green; the root package keeps its other tests
- [x] The collision is resolved by renaming the harness copy, not by keeping two implementations

### What was actually done

`e2e_harness_test.go` (460 lines) and `e2e_test.go` (334) moved from the repository root to
`pkg/mcp-proxy`, by `git mv` so the history follows them. The package clause changed; nothing else
about the tests did.

**The compiler proved the duplication, exactly as the plan predicted.** The move produced one error
and only one: `tokenActiveChecker redeclared in this block`. The two implementations turned out to
be identical line for line — one reads `repo`, the other `deps.repo` — and the harness copy carried
a comment saying so itself: "copied from Run".

**Deviation from the plan, and it is an improvement.** The substep called for *renaming* the harness
copy and deleting it in F-028b. Renaming would have left two identical functions under two names,
which is the drift this whole task exists to end. Since the production function needs nothing but
`deps.repo`, the harness now calls it directly:

    TokenActive: tokenActiveChecker(&dependencies{repo: repo}),

The acceptance criterion — "not by keeping two implementations" — is therefore met literally in this
substep rather than deferred. `tokenActiveChecker` now exists exactly **once** in the repository.

**Verified:** `go test -list '.*'` returns the identical set of **240 tests** across the whole
repository before and after; `go test -race ./...`, gofmt, vet and golangci-lint are green; the root
package keeps its six other test files (`docs_refs_test.go`, `env_test.go`, `healthcheck_test.go`,
`main_test.go`, `parse_test.go`, `rotatekey_test.go`).

The harness header now says why the file sits in this package. The claim it still makes — that it
assembles the gateway "the way `Run()` mounts it" — stays untrue until F-028b, and the header says
that too rather than leaving a reader to discover it.

**Files:** `e2e_harness_test.go` → `pkg/mcp-proxy/e2e_harness_test.go`,
`e2e_test.go` → `pkg/mcp-proxy/e2e_test.go`.


---

## F-028 — Retire the parallel gateway in the end-to-end harness — DONE 2026-08-24

**Problem:** `e2e_harness_test.go` builds the gateway a second time instead of using the one `Run`
builds, and the two have already drifted apart. Three findings, all measured during F-022e. The
harness creates the operator session cookie with `cookie.NewStore(secret[:])` and never calls
`store.Options`, so it runs **without encryption, `HttpOnly`, `Secure` or `SameSite`** — the
end-to-end suite therefore cannot catch a regression in any of those SPEC §1.12 properties, which
makes this a testing gap with a security edge rather than tidiness. The revocation check
`tokenActiveChecker` exists there a **third** time, beside the production copy. And although F-022e
turned the wiring into a callable function, the harness still cannot call it: it lives in package
`main` while the parameter types are package-private. This is the same gap F-021 found once and
closed by hand — by hand does not hold.

**Idee:** Let the end-to-end tests drive the real wiring through `httptest` and delete the parallel
construction rather than keep it in sync. The suite then exercises what the binary runs by
construction instead of by vigilance.

**Decided at `/coding-kit:prep-step` (2026-08-24), with the measurements behind each decision:**

- **The move is feasible and cycle-free.** The two test files import only packages `pkg/mcp-proxy`
  already imports (`auth`, `cimd`, `idp`, `keys`, `proxy`, `ratelimit`, `repository`), and they
  reference nothing from package `main`.
- **The intake sketch overstated the seams.** Of the four options the harness injects, **three map
  onto real configuration fields** — `oidcMirror` → `OIDCDiscoveryMirror`, `registerLimit` /
  `tokenLimit` → `RateLimitRegister` / `RateLimitToken`. Only the CIMD stub genuinely needs one.
- **Drive the real startup path, not a hand-assembled one.** `resolveConfig` → `openDependencies` →
  `BuildRouter` covers everything except `serve`. The mock upstream is an `http.Handler`, so putting
  it behind `httptest.NewServer` and passing that URL as `ProxyTargets` runs it through the **real
  transparent backend** — more faithful, not more complicated.
- **The logger is the second seam.** Without `MODE=debug`, `openDependencies` builds a production
  logger that floods the test output. The three direct `os.Getenv` reads in the startup path
  (`AUTH_HMAC_SECRET`, `MODE`, `JWT_PRIVATE_KEY`) are safe to set per test, because no end-to-end
  test uses `t.Parallel()`.
- **Move first, rewire second — the reverse does not compile clean.** A package-private seam with no
  caller is removed by the `unused` linter on sight. That happened in this project during F-022d,
  when `servesTLS()` was written one substep ahead of its user.

**Substeps**

### F-028b — Drive the real wiring and delete the second gateway

**What:** Add the two package-internal seams (CIMD resolver, logger), rewire `newE2EGateway` to run
`resolveConfig` → `openDependencies` → `BuildRouter`, serve the mock upstream through `httptest` as
a real `ProxyTargets` URL, and delete the parallel construction along with the duplicate revocation
check. **Retrofit from F-022e:** `BuildRouter` goes back to unexported, because its caller now lives
in the same package — it was exported for a caller that could never exist, its parameter types being
package-private.

**Files:** `pkg/mcp-proxy/e2e_harness_test.go`, `pkg/mcp-proxy/router.go`, `pkg/mcp-proxy/deps.go`

**Acceptance:**
- [x] No second gateway construction remains — verified by searching, not by memory
- [x] The harness session cookie comes from `newSessionStore`, so the tests run **with** encryption,
      `HttpOnly`, `Secure` and `SameSite` — the gap that motivated this task
- [x] `tokenActiveChecker` exists exactly once in the repository
- [x] `BuildRouter` is unexported and nothing outside the package references it
- [x] Same test set, `go test -race ./...` green, and the seams are package-internal — the public
      API is unchanged

**Abhängigkeiten:** F-022e (done — it produced the callable wiring this task builds on).

---

### F-028b — what was actually done

`newE2EGateway` now runs the binary's own startup path — `resolveConfig` →
`openDependenciesWithLogger` → `buildRouter` — and serves the resulting engine through
`httptest`. It assembles **nothing**: no `gin.New()`, no `cookie.NewStore`, no `NewAuthRouter`,
`NewIDPRouter` or `NewProxyRouter`, verified by searching rather than by memory. The mock upstream
runs as a real HTTP server whose URL is passed as `ProxyTargets`, so the tests additionally exercise
the transparent backend, and the assertion that the upstream sees `/mcp` proves the path join works.

**Two package-internal seams, and one of them is a structural improvement rather than a
concession.** The CIMD resolver moved from `router.go` into `deps.go`: it is a collaborator like the
repository and the key manager, so it belongs where those are built. A test overrides the field
afterwards. The second is `openDependenciesWithLogger`, so the suite can run the real startup path
without a production logger writing JSON across its output. Neither widens the public API.

**The gap that motivated the whole task is closed, and it was checked empirically rather than
argued.** A throwaway probe drove the real login and printed what the harness now receives:

    Set-Cookie: session=…; Path=/; Max-Age=600; HttpOnly; SameSite=Lax

with the value in securecookie's signed-and-encrypted form. Before, the harness called
`cookie.NewStore(secret[:])` and never called `store.Options`, so none of those attributes existed
and the value was signed only. The probe was deleted after the reading; it existed to answer the
question, not to stay. (`Secure` is correctly absent: the issuer is `http://localhost`, and
`sessionCookieSecure` decides exactly as it does in production.)

**A decision beyond the plan: `OriginCheckEnabled: true`.** Production defaults it on. Leaving it
off in the harness would have introduced a *fresh* divergence in the very task that exists to end
divergence. The tests send no `Origin`, and an absent one passes by design (SPEC §0), so fidelity
cost nothing.

**The retrofit from F-022e is done.** `BuildRouter` no longer exists — it is `buildRouter` again.
The exported form was never callable from outside the package, its parameter types being
package-private, so the export bought nothing and implied something false. `pkg/mcp-proxy` exports
`Run`, `Config` and `ServerShutdownTimeout` again: exactly its surface before F-022e.

**Also removed:** `limiterMiddleware`, the helper whose own comment said it "mirrors Run's
construction" — with nothing left to mirror, it went.

**Verified:** identical set of **240 tests** across the repository; `go test -race ./...`, gofmt,
`go vet` and golangci-lint green; `tokenActiveChecker` exists once.

**Files:** `pkg/mcp-proxy/e2e_harness_test.go`, `pkg/mcp-proxy/deps.go`, `pkg/mcp-proxy/router.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/server.go`.

### F-028 as a whole

The end-to-end suite tested a gateway it built itself, and the two had drifted where it mattered
most: the session cookie. Two substeps ended that — a proven move into the package, then the rewire
onto the real startup path. What the suite exercises is now what the binary runs, by construction
rather than by vigilance, which is the difference F-021 could not achieve by fixing the symptom
once by hand.

The task also carried a correction of its predecessor, at the operator's instruction: work that
leaves a loose end should name the task that will pick it up, and that task should actually pick it
up. F-022e exported a function for a caller that could not exist; F-028 removed the export.
