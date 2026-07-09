# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released.** **v0.1.1 is public** — repo public, multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.1.1`/`0.1`), verified against the MCP **2026-07-28
spec RC**. The gateway is feature-complete against `SPEC.md`, security-audited (F-006b) and live-
verified against Claude web + iOS (F-006c). All roadmap tasks F-001–F-011 and **F-012** (audit
low-severity follow-ups, substeps a–e → v0.1.1) are done — rationale archived in
`PROGRESS-ARCHIVE.md`. **No tasks in the execution queue;** parked in the backlog is **F-013**
(fix the CI `ci.yml` workflow, which never runs), plus the standing watch item to re-check the
final MCP spec after 2026-07-28. F-numbers are stable IDs; the document order, not the number, is
the path.

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
| F-012c | Login surface: CSRF + discoverable passkey → **per-session anti-CSRF token (32 B crypto/rand in the HMAC-signed session; new `pkg/auth/csrf.go`) checked constant-time (`crypto/subtle`) on password-login, consent, both settings POSTs, and all WebAuthn ceremonies — hidden field for forms, `X-CSRF-Token` header for the fetches; passkey login switched to `BeginDiscoverableLogin`/`FinishDiscoverableLogin` (empty allow-list → no credential-ID disclosure), registration raised to `ResidentKeyRequirementRequired`** — negatives (missing/wrong token → 403, begin omits descriptors), consent-CSRF test, whole login+consent+e2e harness threaded through token extraction; suite + `-race` + golangci-lint clean. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |
| F-012 | **Audit low-severity follow-ups — complete** (a/b/c/d/e done): all 16 actionable F-006b lows fixed across guards → auth flow → login surface → persistence, each with negative regression tests; **v0.1.1 released** (git tag `v0.1.1`, multi-arch `0.1.1`/`0.1` image on GHCR, release workflow green, anonymous pull verified). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |
| F-012d | Persistence hardening → **DCR cap enforced inside the write transaction (`RegisterClient(…, maxClients)` counts+inserts atomically — bbolt `Update` / GORM `Transaction`; sentinel `ErrClientCapReached` → 503, no TOCTOU; handler pre-check dropped); SQLite `SetMaxOpenConns(1)` + `busy_timeout`/WAL/`synchronous=NORMAL`/`foreign_keys=ON`; session cookie signed *and* encrypted via HKDF-derived auth+AES-256 subkeys (`crypto/hkdf`, new `pkg/mcp-proxy/cookie.go`) while fosite keeps the raw `GlobalSecret`** — concurrency cap test (both backends, `-race`: exactly cap succeed) + cookie-opaqueness test; suite + `-race` + golangci-lint clean; README DSN note + SPEC §1.12/§2.2 deltas. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |

---

## Open tasks — work top to bottom

Standing watch item: **re-check the final MCP authorization spec once it publishes on
2026-07-28** (v0.1.0 is verified against its RC; becomes its own small task once published).

---

## Feature ideas (backlog)

### F-013 — Fix the CI workflow (`ci.yml` never runs)

**Problem:** `.github/workflows/ci.yml` has failed to load on **every** push since v0.1.0 —
GitHub reports "No jobs were run" / "workflow file issue" and creates **0 jobs**, so the
build/test/`gofmt`/`vet` + `golangci-lint` + `go-licenses` gate has been effectively disabled the
whole time (only `vulncheck.yml` and `release.yml` actually run). The operator receives repeated
GitHub failure emails. F-012 was validated by running the checks by hand locally instead.

**Idea:** Fix the YAML syntax error, lint **all** workflow files with `actionlint` to catch any
other silent rejection, and verify by observing that the jobs actually run and pass — not merely
that the file parses.

**Possible implementation:**
- Root cause (verified locally with `actionlint`): [`ci.yml:59`](.github/workflows/ci.yml#L59) in
  the `license-check` job — `run: "$(go env GOPATH)/bin/go-licenses" check ./… --disallowed_types=…`.
  The value **begins with a double quote**, so YAML parses `"$(go env GOPATH)/bin/go-licenses"` as
  a quoted scalar and the trailing ` check …` is a syntax error ("did not find expected key"),
  which invalidates the entire file. Fix with a block scalar (`run: |` on the next line) or by not
  starting the scalar with a quote.
- Run `actionlint` over `.github/workflows/*.yml` (all three) as part of the fix; consider adding
  it as a lightweight CI step so a future malformed workflow fails loudly instead of silently
  producing 0 jobs.
- **Verify it actually runs:** after pushing, confirm via `gh run list` / `gh run view` that the
  `build-test`, `lint` and `license-check` jobs are created and **pass** (the action refs
  `actions/checkout@v7`, `actions/setup-go@v6`, `golangci/golangci-lint-action@v9.3.0` were all
  verified to exist — they are **not** the cause).
- Correct the earlier incorrect root-cause note in `PROGRESS-ARCHIVE.md` (F-012 umbrella section)
  and Graphiti, which speculated the `golangci-lint-action@v9.3.0` ref was to blame — it resolves
  fine; the actual cause is the YAML quoting above.
- No product-code change; CI-infra/hygiene only. No new runtime dependencies.

**Dependencies:** none.

---

<!-- FEATURE-INDEX
next-feature: F-014
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
F-012 Audit low-severity follow-ups (from F-006b) (DONE)
F-013 Fix the CI workflow (ci.yml never runs)
-->
