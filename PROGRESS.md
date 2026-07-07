# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State:** the gateway is **feature-complete against `SPEC.md`** — the hard fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite) builds and tests green on `main`, and F-005 closed every gap from the F-001 review (discovery/401 surface, token binding + revocation, CIMD + DCR hardening, key rotation + ES256, passkey auth, rate limits + auth events). F-001–F-006 and F-008–F-011 are done (rationale archived in `PROGRESS-ARCHIVE.md`) — including
**F-006, which verified the gateway live against Claude web + iOS and passed the security review**.
**The only remaining task is F-007 (release hygiene);** the backlog holds F-012 (audit low-severity
follow-ups). F-numbers are stable IDs; the document order, not the number, is the path.

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
| F-006a | Local end-to-end verification harness → **assembled-gateway `httptest` e2e** (`e2e_test.go` + `e2e_harness_test.go`): discovery/JWKS self-consistency, DCR + real login + consent, PKCE/S256 authorize→token, proxied upstream call with credential injection, fail-closed negatives (missing/tampered/replay/**revoked**), rate-limit 429, key-rotation continuity; gofmt/vet/race clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-07 |
| F-006b | Adversarial `/audit-code` (4 parallel agents, findings self-verified) → **`AUDIT-RESULTS.md`** (0 crit / 1 high / 9 med / 19 low), then fixed the user-chosen security batch inline: **H1** consent screen shows client identity+scopes, **M1** CIMD SSRF denylist (Alibaba/CGNAT/NAT64/reserved), **M2** `/revoke` 503 on store failure, **M3** untrusted `X-Forwarded-Port` strip, **M4** CIMD cache bound + `/.idp/auth` rate limit, **M5** lockout re-arm DoS, **M6** internal-error disclosure — each with a regression test; gofmt/vet/race clean. Deployment mediums→F-007, lows→F-012. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-07 |
| F-006c1 | Deploy + server-side verification → **gateway live behind the operator's reverse proxy (non-root container), public discovery/JWKS `200`, `/mcp` fail-closed `401`, and a full OAuth+PKCE round-trip with a proxied MCP `initialize` reaching the upstream verified end-to-end through the proxy** (credential injection + SSE streaming confirmed). Runbook `docs/VERIFICATION.md`; deploy artefacts in `private/` (gitignored). Surfaced/handled 3 deploy gotchas (bare-IP `TRUSTED_PROXIES`=M8→`/32`, `NO_AUTO_TLS`, Compose `env_file` `$`→`$$`). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-006c | Live client verification → **Claude web *and* iOS both connect via real CIMD and read/search/write against the live upstream; passkey enrol+login verified in Safari (desktop) + iOS (iCloud Keychain); operator disabled the password fallback (passkey-only, SR-6 uniform error); live negatives denied**. Chrome skipped (operator's choice). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-006 | **Verify against Claude + security review — complete** (a/b/c1/c2/c3 done): assembled e2e harness, adversarial audit + security fixes, and live end-to-end verification against Claude web + iOS. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |

---

## Open tasks — work top to bottom

| Order | Task | Ready? |
|-------|------|--------|
| 1 | **F-007** — Release hygiene | ✅ ready (F-006 done) |

Then the backlog **F-012** (audit low-severity follow-ups). Each task below carries its own
`**Dependencies:**` line.

---

### F-007 — Release hygiene

**Problem:** A public release needs usage docs, SemVer, and license/NOTICE hygiene.

**Idea:** Finalise documentation and release artifacts.

**Possible implementation:**
- README usage docs (front an MCP server; add as a connector; **complete config reference** for the §3 env vars — F-005 added ~20), SECURITY.md, SemVer, NOTICE.
- **Manual key-rotation ops command** (deferred here from F-005d — SPEC §2.3: v1 rotates on interval only).
- CI: add **golangci-lint** (CODING-STANDARDS §11 expects it; the workflow only runs gofmt/vet/build/test today) + OAuth/MCP conformance tests (extend the existing `.github/workflows/ci.yml`).
- Verify all dependencies are permissive-licensed (no GPL/AGPL; MPL-2.0 accepted — see F-008b).
- **Deployment/config hardening from the F-006b audit (M7–M10):** ① `Dockerfile` non-root `USER`, drop/justify the python/node/npm interpreters, digest-pin base images (currently `debian:bookworm-slim` runs as root); ② implement the SPEC §3.1 startup WARNING for an `http` non-loopback issuer and base the session-cookie `Secure` flag on whether TLS is actually served; ③ normalise bare-IP `TRUSTED_PROXIES` (a bare IP currently crashes startup with an http upstream); ④ add a `HEALTHCHECK` + compose `depends_on: condition: service_healthy`; ⑤ pin `go-licenses` (CI installs `@latest`).
- **Release gate:** re-verify against the MCP authorization spec **2026-07-28 RC** (watch item, REQUIREMENTS §0), unless already done in F-006.

**Dependencies:** F-006.

---

## Feature ideas (backlog)

### F-012 — Audit low-severity follow-ups (from the F-006b `/audit-code` run)

**Problem:** The F-006b audit surfaced 19 low-severity findings — hardening and hygiene, none
a security hole — deferred so F-006 could gate on the high/medium security batch.

**Idea:** Work through them in a focused hardening pass (each is small and independent).

**Possible implementation (grouped):**
- **Fail-fast/config:** reject malformed boolean env values (currently silently `false`); create
  the data dir `0700` (SPEC §2.2); print+`os.Exit(1)` instead of `panic()` on startup errors.
- **Auth hardening:** confidential-client PKCE (`EnforcePKCE: true`); passkey login via
  `BeginDiscoverableLogin` (don't expose credential IDs pre-auth); `session.Clear()` on logout;
  uniform empty-password response; delete the dead GET-only `handleLogin` POST branch; per-session
  CSRF tokens on login/consent/settings/register; same-origin-validate `redirect_url`; constant
  bcrypt count for multi-hash configs.
- **Crypto/proxy:** reject RSA `JWT_PRIVATE_KEY`/legacy keys `< 2048` bits; add
  `jwt.WithExpirationRequired()`; cap proxy request-body buffering (only buffer on a followed
  redirect); apply the DCR grant/response-type whitelist to CIMD documents too.
- **Persistence:** enforce the DCR client cap inside the write transaction (TOCTOU); SQLite
  `SetMaxOpenConns(1)` + busy-timeout/WAL (or document required DSN pragmas); cookie-store block
  key + key-separation from the fosite HMAC secret.

Full detail per finding: `AUDIT-RESULTS.md` (regenerated; gitignored).

**Dependencies:** none (independent hardening; can follow F-006/F-007).

---

_New ideas beyond the path above are intaked via `/add-feature` and get the next F-number._

---

<!-- FEATURE-INDEX
next-feature: F-013
F-001 Build vs fork evaluation (DONE)
F-002 Choose language + OAuth library (DONE)
F-003 DCR vs CIMD decision (DONE)
F-008 Create the hard fork of sigbit/mcp-auth-proxy (DONE)
F-009 Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first) (DONE)
F-010 Rebrand the fork to mcp-oauth-gateway (DONE)
F-011 Trim bundled auth providers to the self-contained model (DONE)
F-004 Complete the spec (make it implementable) (DONE)
F-005 Implement on the chosen base (sigbit fork) (DONE)
F-006 Verify against Claude + security review (DONE)
F-007 Release hygiene
F-012 Audit low-severity follow-ups (from F-006b)
-->
