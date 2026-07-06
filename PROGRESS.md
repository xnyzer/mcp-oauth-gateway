# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State:** the base gateway now exists — a working **hard fork of `sigbit/mcp-auth-proxy`** (Go + Ory Fosite) builds and tests green on `main`, and `SPEC.md` defines the implementable contracts. F-001/F-002/F-003/F-004/F-008/F-009/F-010/F-011 are done (rationale archived in `PROGRESS-ARCHIVE.md`). **Open tasks below are ordered for top-to-bottom execution — start at the top (F-005).** F-numbers are stable IDs; the document order, not the number, is the path.

---

## Done

| Step | Description | Completed |
|------|-------------|-----------|
| F-001 | Build vs fork evaluation → **decided: hard-fork `sigbit/mcp-auth-proxy`** (Go + Ory Fosite), validated by a live Claude PoC. Detail in `PROGRESS-ARCHIVE.md`. | 2026-06-25 |
| F-002 | Language + OAuth library → **decided: Go + Ory Fosite** (follows the F-001 fork base). | 2026-06-25 |
| F-003 | DCR vs CIMD → **decided: support both, CIMD-first with DCR as deprecated fallback** (spec 2025-11-25). | 2026-06-25 |
| F-008 | Create the hard fork → **sigbit source imported** as `github.com/xnyzer/mcp-oauth-gateway` (build+tests green, CI added, NOTICE/license clean). Detail in `PROGRESS-ARCHIVE.md`. | 2026-06-25 |
| F-009 | Update REQUIREMENTS for MCP 2025-11-25 → **CIMD-first documented** (§0/FR-1/FR-2/FR-3; RFC 9207 `iss`, OIDC Discovery, 2026-07-28 RC watch item); README/CLAUDE.md aligned. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-03 |
| F-010 | Rebrand the fork → **binary/CLI/Docker/UI/ClientInfo/bbolt namespace renamed to `mcp-oauth-gateway`** (NOTICE/FORK attribution kept; Go builder image pinned to 1.26). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-03 |
| F-011 | Trim bundled auth providers → **Google/GitHub removed** (~680 lines + 10 flags/env vars + 1 transitive dep); **generic OIDC kept, off by default**; password login verified as default (smoke test). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-03 |
| F-004 | Complete the spec → **`SPEC.md` created** (API contracts incl. CIMD/RFC 8707/9207/7009 + `WWW-Authenticate`; data model + `jti` revocation + key rotation; full config schema) + `docker-compose.example.yml`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-03 |
| F-005a | Discovery & 401 surface → **complete PRM/AS metadata, `WWW-Authenticate` challenge, RFC 9207 `iss`, issuer normalization, `CLOCK_SKEW`, OIDC mirror** + config-struct refactor. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |
| F-005b | Token binding & lifecycle → **RFC 8707 `resource`→`aud`, `jti`/`client_id`/`scope` claims, `/revoke` (RFC 7009) + fail-closed proxy revocation check, TTL config, sweeper + schema version**; fixed upstream revoke-by-signature no-op bug. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |

---

## Open tasks — work top to bottom

| Order | Task | Ready? |
|-------|------|--------|
| 1 | **F-005** — Implement the gap list on the fork | ✅ ready (F-004 done) |
| 2 | **F-006** — Verify against Claude + security review | ⛔ after F-005 |
| 3 | **F-007** — Release hygiene | ⛔ after F-006 |

The remaining tasks are a hard chain: 1→2→3. Each task below carries its own `**Dependencies:**` line.

---

### F-005 — Implement on the chosen base (sigbit fork)

**Problem:** The base fork (F-008) exists but does not yet meet our spec/security bar. The work is **closing the gaps** — glue only, no hand-rolled crypto (see `THREAT-MODEL.md`).

**Idea:** Build on the fork. Keep/verify what sigbit already does (in-process fail-closed enforcement, streaming proxy, embedded persistence, ACME); add and harden the missing pieces below.

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

**Dependencies:** F-004, F-008, F-011 (all DONE). Implement against the `SPEC.md` contracts (each §1 section carries a Delta note).

**Decisions (prep, user-approved):** passkey bootstrap = first login via `PASSWORD`/`PASSWORD_HASH`, then passkey enrollment on a session-gated settings page (password stays as a disableable fallback); ES256 ships only if Fosite supports it cleanly, otherwise documented follow-up; rate-limit state is in-memory (single-instance deployment, GR-3). New deps: `github.com/go-webauthn/webauthn` (BSD-3), `golang.org/x/time/rate` (BSD).

#### F-005c — CIMD + DCR hardening (SR-5)

**What:** CIMD resolver per §1.3 (5 s/64 KiB/no redirects, SSRF guards, document validation, positive/negative cache) integrated at authorize/token; `CIMD_*` config. DCR: client TTL refreshed on use, cap, `DCR_ENABLED`, redirect-URI scheme validation (§1.4).
**Files:** new `pkg/cimd/`, `pkg/idp/`, `pkg/repository/` + tests.
**Dependencies:** F-005b (DONE).
- [ ] SSRF negative tests (private/loopback/metadata IPs, redirects, oversize, non-https)
- [ ] CIMD client full authorize+token round-trip in tests
- [ ] DCR expiry/cap enforced (negative tests); `DCR_ENABLED=false` removes endpoint + metadata entry

#### F-005d — Key management

**What:** Key directory + atomic `manifest.json`, migration from the legacy single key, interval-based rotation with retiring window, multi-key JWKS, `KEY_ALG` (RS256/ES256 if Fosite allows) + `KEY_ROTATION_INTERVAL` (§2.2/§2.3).
**Files:** new `pkg/keys/` (from `pkg/utils/keys.go`), `pkg/idp/` + tests.
**Dependencies:** F-005b (sweeper).
- [ ] rotation test: pre-rotation token stays valid until `exp`; JWKS serves both keys
- [ ] legacy key adopted on first start (migration test)
- [ ] crash-safe manifest rewrite (atomic rename)

#### F-005e — Self-contained auth & abuse protection

**What:** User model + passkey/WebAuthn (`github.com/go-webauthn/webauthn`) with password-bootstrap enrollment (session-gated settings page); rate limits on `/register`, `/token`, login + account lockout (SR-6); structured auth events `login_ok`/`login_fail`/`token_issued`/`register`/`rate_limited`/`revoked` (SR-8).
**Files:** `pkg/auth/`, `pkg/repository/`, new `pkg/ratelimit/` + tests.
**Dependencies:** F-005b (user/`sub` claims), F-005d not required.
- [ ] passkey enrollment + login round-trip (WebAuthn test vectors / virtual authenticator)
- [ ] lockout + rate-limit negative tests; uniform login errors (no enumeration)
- [ ] auth events emitted without secrets (log assertion tests)
- [ ] split into e1/e2 if implementation exceeds ~1000 lines

---

### F-006 — Verify against Claude + security review

**Problem:** Nothing ships without verification against real clients and a security review.

**Idea:** End-to-end verify, then a mandatory security review before any public exposure.

**Possible implementation:**
- Local/tooling: discovery valid; DCR works; authorize+token+PKCE round-trip; JWKS; expired/invalid token → 401 (fail-closed); rate-limits fire.
- **Claude web custom connector first** (easier to debug), then **Claude iOS**. (A faithful-baseline PoC already connected end-to-end in F-001 — see archive.)
- Negative tests (no token / tampered token / replay).
- **Security review** before any public exposure.

**Dependencies:** F-005.

---

### F-007 — Release hygiene

**Problem:** A public release needs usage docs, SemVer, and license/NOTICE hygiene.

**Idea:** Finalise documentation and release artifacts.

**Possible implementation:**
- README usage docs (front an MCP server; add as a connector), SECURITY.md, SemVer, NOTICE.
- CI with OAuth/MCP conformance tests (extend the existing `.github/workflows/ci.yml`).
- Verify all dependencies are permissive-licensed (no GPL/AGPL; MPL-2.0 accepted — see F-008b).

**Dependencies:** F-006.

---

## Feature ideas (backlog)

_New ideas beyond the path above are intaked via `/add-feature` and get the next F-number. (None pending.)_

---

<!-- FEATURE-INDEX
next-feature: F-012
F-001 Build vs fork evaluation (DONE)
F-002 Choose language + OAuth library (DONE)
F-003 DCR vs CIMD decision (DONE)
F-008 Create the hard fork of sigbit/mcp-auth-proxy (DONE)
F-009 Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first) (DONE)
F-010 Rebrand the fork to mcp-oauth-gateway (DONE)
F-011 Trim bundled auth providers to the self-contained model (DONE)
F-004 Complete the spec (make it implementable) (DONE)
F-005 Implement on the chosen base (sigbit fork)
F-006 Verify against Claude + security review
F-007 Release hygiene
-->
