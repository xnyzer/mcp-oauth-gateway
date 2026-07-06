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
