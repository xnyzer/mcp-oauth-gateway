# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State:** the gateway is **feature-complete against `SPEC.md`** — the hard fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite) builds and tests green on `main`, and F-005 closed every gap from the F-001 review (discovery/401 surface, token binding + revocation, CIMD + DCR hardening, key rotation + ES256, passkey auth, rate limits + auth events). F-001–F-005 and F-008–F-011 are done (rationale archived in `PROGRESS-ARCHIVE.md`). **Open tasks below are ordered for top-to-bottom execution — start at the top (F-006: verify against Claude + security review).** F-numbers are stable IDs; the document order, not the number, is the path.

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
| F-005c | CIMD + DCR hardening → **`pkg/cimd` resolver (dial-time SSRF guards, limits, cache) as fosite client source; DCR TTL/cap/validation/`DCR_ENABLED`**; reserved-namespace guard (disabled endpoints 404, never proxied). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |
| F-005d | Key management → **new `pkg/keys`: key dir + atomic manifest, legacy-key migration (kid preserved), interval/alg-switch rotation with retiring window, multi-key JWKS + kid verification end to end (incl. introspection via custom fosite signer), `KEY_ALG` RS256/ES256 + `KEY_ROTATION_INTERVAL`**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |
| F-005e1 | User model + passkey/WebAuthn → **single operator account (bootstrap on first password login, `sub` = user ID), go-webauthn ceremonies + session-gated `/.auth/settings`, disableable password fallback (env stays authoritative) with lockout rescue, §3.1 auth-backend fail-fast**; fixed inherited RequireAuth chain-continuation bug. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |
| F-005e2 | Rate limits, lockout & auth events → **new `pkg/ratelimit` (per-IP token buckets on `/register`/`/token`/login, 429 + `rate_limited`) + per-account lockout with byte-identical uniform errors; `pkg/authevent` structured events (`login_ok`/`login_fail`/`token_issued`/`register`/`rate_limited`/`revoked`) without secrets**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |
| F-005 | **Implement on the chosen base — complete** (all six substeps a/b/c/d/e1/e2 done; every gap from the F-001 review closed). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-06 |

---

## Open tasks — work top to bottom

| Order | Task | Ready? |
|-------|------|--------|
| 1 | **F-006** — Verify against Claude + security review | ✅ ready (F-005 done) |
| 2 | **F-007** — Release hygiene | ⛔ after F-006 |

The remaining tasks are a hard chain: 1→2. Each task below carries its own `**Dependencies:**` line.

---

### F-006 — Verify against Claude + security review

**Problem:** Nothing ships without verification against real clients and a security review.

**Idea:** End-to-end verify, then a mandatory security review before any public exposure.

**Possible implementation:**
- Local/tooling: discovery valid; **CIMD client identification** (primary — what Claude uses, F-005c) and DCR fallback both work; authorize+token+PKCE round-trip; JWKS; expired/invalid token → 401 (fail-closed); rate-limits fire; key rotation keeps outstanding tokens valid (F-005d).
- **Passkey/WebAuthn in real browsers:** enrollment + login in Safari and Chrome (desktop), then iOS — so far only covered by the virtual authenticator (F-005e1).
- **Claude web custom connector first** (easier to debug), then **Claude iOS**. (A faithful-baseline PoC already connected end-to-end in F-001 — see archive; the codebase has changed substantially since.)
- Negative tests (no token / tampered token / replay).
- **Security review** before any public exposure — at minimum a full `/audit-code` run (adversarial, not the per-step self-review).
- If the MCP authorization spec **2026-07-28 RC** has landed by then: re-verify the contracts against it (watch item, REQUIREMENTS §0); otherwise this check moves to the F-007 release gate.

**Dependencies:** F-005 (DONE).

---

### F-007 — Release hygiene

**Problem:** A public release needs usage docs, SemVer, and license/NOTICE hygiene.

**Idea:** Finalise documentation and release artifacts.

**Possible implementation:**
- README usage docs (front an MCP server; add as a connector; **complete config reference** for the §3 env vars — F-005 added ~20), SECURITY.md, SemVer, NOTICE.
- **Manual key-rotation ops command** (deferred here from F-005d — SPEC §2.3: v1 rotates on interval only).
- CI: add **golangci-lint** (CODING-STANDARDS §11 expects it; the workflow only runs gofmt/vet/build/test today) + OAuth/MCP conformance tests (extend the existing `.github/workflows/ci.yml`).
- Verify all dependencies are permissive-licensed (no GPL/AGPL; MPL-2.0 accepted — see F-008b).
- **Release gate:** re-verify against the MCP authorization spec **2026-07-28 RC** (watch item, REQUIREMENTS §0), unless already done in F-006.

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
F-005 Implement on the chosen base (sigbit fork) (DONE)
F-006 Verify against Claude + security review
F-007 Release hygiene
-->
