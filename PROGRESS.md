# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released.** **v0.1.0 is public** — repo public, GitHub release published, multi-arch
image on GHCR (`ghcr.io/xnyzer/mcp-oauth-gateway`), verified against the MCP **2026-07-28 spec
RC**. The gateway is feature-complete against `SPEC.md`, security-audited (F-006b) and live-
verified against Claude web + iOS (F-006c). All roadmap tasks F-001–F-011 incl. F-007 (release
hygiene) are done — rationale archived in `PROGRESS-ARCHIVE.md`. **Open: F-012** (audit
low-severity follow-ups — prepared into substeps a–e, target patch release **v0.1.1**) and the
watch item to re-check the final MCP spec after 2026-07-28. F-numbers are stable IDs; the
document order, not the number, is the path.

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
| F-007a | Code fixes → **M8 bare-IP `TRUSTED_PROXIES` normalised to `/32`·`/128` (fail-fast on garbage), M7 §3.1 http-issuer startup WARNING + cookie `Secure` from actually-served TLS, `rotate-key` offline ops command (SPEC §2.3)**; 13 regression tests, suite + `-race` green, live smoke on the binary. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-007b | Container & CI hardening → **M9 digest-pinned distroless non-root image (no interpreters, `HEALTHCHECK` via new `healthcheck` subcommand, non-privileged default ports, `/data` owned in-image) + M10 pinned golangci-lint v2.12.2 in CI (76 findings triaged: real fixes incl. `ReadHeaderTimeout`, data-dir `0700`, deprecated-ECDSA-API swap; documented nolints) + `go-licenses/v2` pinned**; version wired via ldflags (`--version` + MCP ClientInfo); container smoke green. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-007c | Release workflow + install artefacts → **`release.yml` (SemVer tag → multi-arch amd64+arm64 → GHCR, no `latest`, VERSION from tag), `.env.example` covering every §3 env var (incl. the `$`→`$$` Compose pitfall), compose example on `env_file:` + health-gated `depends_on`, `setup.sh` quickstart (stdin bcrypt hash, writes `.env` 0600)**; verified live: setup.sh run → compose up healthy → login 302/400 proves the escaping chain; workflows actionlint-clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-007d | Docs → **README rewritten as full usage docs (quickstart, install modes A/B, Claude-connector guide, Anthropic-egress 160.79.104.0/21 silent-failure note, complete §3 config reference, upstream/path/stdio gotchas, ops incl. `rotate-key`, endpoints, security posture); `CHANGELOG.md` (Keep-a-Changelog, Unreleased→v0.1.0 incl. upgrade notes); SECURITY.md + NOTICE refreshed (stale mysql line dropped); runbook cross-linked**; links + §3 completeness verified by script, GR-5 clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-007e | Release gate + publish → **RC-check: the 2026-07-28 RC is out and all six authorization SEPs are already satisfied (watch item resolved; re-check at the final spec); govulncheck found 3 reachable vulns → x/net v0.55.0, quic-go v0.59.1, Go 1.26.5 (0 reachable after); gitleaks over the full history clean; Dependabot + weekly govulncheck CI added; tag `v0.1.0` → multi-arch GHCR image verified by anonymous pull + smoke; repo + package public (operator go); GitHub release published; PVR + Dependabot alerts enabled**. License decision re-confirmed: Apache-2.0 over MIT/MPL/AGPL. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-007 | **Release hygiene — complete** (a/b/c/d/e done): M7–M10 deployment fixes, `rotate-key`, hardened image, lint/license/vuln CI, release pipeline, install artefacts, full docs, **v0.1.0 released publicly**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-012a | Fail-fast & crypto/proxy guards → **malformed boolean envs abort startup; RSA < 2048 refused (`JWT_PRIVATE_KEY`/legacy/manifest); `jwt.WithExpirationRequired()`; redirect-replay body buffering capped at 4 MiB (larger bodies stream, redirect passed through); CIMD grant/response-type whitelist shared with DCR** — five negative regression tests; suite + `-race` + golangci-lint clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-08 |
| F-012b | Auth-flow hardening → **`EnforcePKCE: true` (confidential DCR clients need PKCE too, closes the SPEC §1.5 delta); empty password takes the uniform bcrypt+error path; bcrypt loop without early `break` (constant multi-hash timing); dead `handleLogin` POST branch removed; logout `session.Clear()` + cookie `MaxAge -1`; shared `safeRedirectTarget` same-origin guard at all three login consumers** — new negative tests (confidential-without-PKCE, empty==wrong-password, logout clears, redirect-guard table); e2e confidential flows threaded through PKCE; suite + `-race` + golangci-lint clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |

---

## Open tasks — work top to bottom

Standing watch item: **re-check the final MCP authorization spec once it publishes on
2026-07-28** (v0.1.0 is verified against its RC; becomes its own small task once published).

### F-012 — Audit low-severity follow-ups (from the F-006b `/audit-code` run)

**Problem:** The F-006b audit surfaced 19 low-severity findings — hardening and hygiene, none a
security hole — deferred so F-006 could gate on the high/medium security batch. Since then:
2 were pulled forward into F-007b (data dir `0700`; `os.Exit(1)` via cobra `RunE`), 2 landed
with F-007 (compose health gating; `go-licenses` pin), and M3 (XFF) was already fixed in
F-006b. **16 actionable items remain** (full detail per finding: `AUDIT-RESULTS.md`, local/
gitignored). Two further notes are informational only (introspection breadth; pre-auth
authorize records — both mitigated by the M4 fixes) and are closed as accepted, no code change.

**Goal:** Work through the 16 items in five substeps (guards → auth flow → login surface →
persistence → release). Every substep is independently committable (one commit each), ships
regression tests incl. negatives (CODING-STANDARDS §9), keeps the full suite + `-race` +
`golangci-lint` green, and updates its SPEC delta notes in the same commit. Finish with patch
release **v0.1.1**. No new endpoints, no new env vars, no new dependencies (`crypto/hkdf` is
stdlib since Go 1.24).

**Dependencies:** none (independent hardening; F-006/F-007 done).

**F-012a done** (2026-07-08 — fail-fast & crypto/proxy guards, all five items with negative
regression tests; see Done table + archive).

**F-012b done** (2026-07-09 — auth-flow hardening: EnforcePKCE for all clients, uniform
empty-password, constant bcrypt timing, dead-branch removal, full logout clear, redirect
same-origin guard; negative tests + e2e threaded through PKCE; see Done table + archive).

#### F-012c — Login surface: CSRF tokens + discoverable passkey login

- **What:** ① per-session CSRF token (crypto/rand via `pkg/utils`, stored in the HMAC-signed
  session): hidden field + constant-time check on the password-login, consent, and both
  settings POSTs; the WebAuthn fetches send it as a request header (defence-in-depth on top of
  `SameSite=Lax`, SPEC §1.12); ② passkey login via `BeginDiscoverableLogin` /
  `FinishDiscoverableLogin` (empty allow-list — no credential-ID disclosure to anonymous
  callers), registration raised to `ResidentKeyRequirementRequired` so new passkeys are
  guaranteed discoverable.
- **Files:** `pkg/auth/auth.go`, `pkg/auth/webauthn.go`, `pkg/auth/templates/login.html` +
  `settings.html` + `webauthn_script.html`, `pkg/idp/idp.go` (consent template + handler),
  `e2e_test.go`/`e2e_harness_test.go` (token extraction), `SPEC.md` (§1.12 delta) (+ tests).
- **Dependencies:** none (ordered after F-012b to avoid overlapping edits in the same
  handlers). Both items deliberately share one substep: they touch the same templates/JS and
  the live login flows, concentrating the behaviour-change risk in a single verify step.
- **Acceptance:**
  - [ ] Negative tests: form POSTs without / with a wrong CSRF token are rejected;
        `login/begin` response contains no credential descriptors.
  - [ ] e2e login + consent flows green with token extraction; full suite + `-race` +
        `golangci-lint` green.
  - [ ] Deploy note recorded (CHANGELOG draft): non-resident passkeys stop working
        (synced-keychain passkeys are resident → live setup expected fine); rescue path =
        delete passkey records in the data dir → password fallback re-activates (SPEC §1.12
        lockout-rescue rule).

#### F-012d — Persistence hardening

- **What:** ① DCR cap enforced inside the write transaction (TOCTOU): `RegisterClient` takes
  the cap, both backends count+insert atomically (bbolt `Update` tx; GORM `Transaction`),
  sentinel error → 503 in the handler; drop `CountClients` from the interface if unused
  afterwards; ② SQLite backend sets `SetMaxOpenConns(1)` + `busy_timeout` + WAL pragmas after
  open, DSN note in the README config reference; ③ session-cookie store gets HKDF-derived
  subkeys (stdlib `crypto/hkdf`) from the 32-byte secret: distinct auth + block key → cookies
  signed **and encrypted**; **fosite keeps the raw secret**, so outstanding grants/refresh
  tokens stay valid — only operator session cookies (MaxAge 600) break once (intentional,
  documented).
- **Files:** `pkg/repository/interface.go` + `kvs.go` + `sql.go`, `pkg/idp/idp.go`,
  `pkg/mcp-proxy/main.go`, `README.md` (DSN note), `SPEC.md` (§1.12/§2.2 delta) (+ tests).
- **Dependencies:** none.
- **Acceptance:**
  - [ ] Concurrency regression test: parallel registrations never exceed the cap (under
        `-race`).
  - [ ] Cookie value is opaque (no plaintext session keys readable); fosite HMAC secret
        unchanged — existing e2e token flows pass untouched.
  - [ ] Full suite + `-race` + `golangci-lint` green.

#### F-012e — Docs, bookkeeping & release v0.1.1

- **What:** `CHANGELOG.md` v0.1.1 entry (upgrade notes: one-time operator-session reset;
  startup now fails on bool-typo envs and RSA < 2048; passkey resident-key note); mark the
  findings done in `AUDIT-RESULTS.md` (local); move F-012 to the Done table + archive the
  rationale; Graphiti update; then — **only after explicit operator go** — tag `v0.1.1`
  (release workflow builds + pushes the multi-arch image; operator bumps the live deployment
  afterwards).
- **Files:** `CHANGELOG.md`, `AUDIT-RESULTS.md` (local), `PROGRESS.md`,
  `PROGRESS-ARCHIVE.md`, git tag.
- **Dependencies:** F-012a–d.
- **Acceptance:**
  - [ ] CHANGELOG documents every behaviour change; SPEC/README deltas consistent.
  - [ ] Tag pushed only after operator go; release workflow green, GHCR image pullable.

---

## Feature ideas (backlog)

_None parked. New ideas are intaked via `/add-feature` and get the next F-number._

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
F-007 Release hygiene (DONE)
F-012 Audit low-severity follow-ups (from F-006b)
-->
