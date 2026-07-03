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
