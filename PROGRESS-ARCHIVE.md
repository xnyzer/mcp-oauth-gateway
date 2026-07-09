# mcp-oauth-gateway — Progress Archive

Full documentation of all finished tasks. Filled by `/step-done`: per completed (sub)step, the complete section from `PROGRESS.md` plus the files actually created/changed, what was concretely implemented, and any notable decisions/deviations from the plan.

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
