# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released.** **v0.1.1 is public** — repo public, multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.1.1`/`0.1`), verified against the MCP **2026-07-28
spec RC**. The gateway is feature-complete against `SPEC.md`, security-audited (F-006b) and live-
verified against Claude web + iOS (F-006c). All roadmap tasks F-001–F-011 and **F-012** (audit
low-severity follow-ups, substeps a–e → v0.1.1) are done — rationale archived in
`PROGRESS-ARCHIVE.md`. All roadmap tasks through **F-013** (CI `ci.yml` repair) are done.
**Two open tasks** in execution order below: splitting the oversized `pkg/idp/idp.go` (F-020,
decomposed into three substeps), then the now-due re-check against the published final MCP spec
(F-017), which also gates the next release. One idea parked in the backlog (F-019). F-numbers are stable IDs; the document order, not the
number, is the path.

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
| F-013 | Fix the CI workflow → **`ci.yml` had a YAML syntax error (the `license-check` `run:` value began with a `"`), which invalidated the whole file → GitHub created 0 jobs on every push since v0.1.0 ("No jobs were run"). Fixed with a block-scalar `run:` + a new pinned `actionlint` job that lints all workflow files so a malformed one fails loudly**; verified the run now creates 4 jobs (build-test/lint/license-check/workflow-lint), all green. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |
| F-012 | **Audit low-severity follow-ups — complete** (a/b/c/d/e done): all 16 actionable F-006b lows fixed across guards → auth flow → login surface → persistence, each with negative regression tests; **v0.1.1 released** (git tag `v0.1.1`, multi-arch `0.1.1`/`0.1` image on GHCR, release workflow green, anonymous pull verified). Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |
| F-012d | Persistence hardening → **DCR cap enforced inside the write transaction (`RegisterClient(…, maxClients)` counts+inserts atomically — bbolt `Update` / GORM `Transaction`; sentinel `ErrClientCapReached` → 503, no TOCTOU; handler pre-check dropped); SQLite `SetMaxOpenConns(1)` + `busy_timeout`/WAL/`synchronous=NORMAL`/`foreign_keys=ON`; session cookie signed *and* encrypted via HKDF-derived auth+AES-256 subkeys (`crypto/hkdf`, new `pkg/mcp-proxy/cookie.go`) while fosite keeps the raw `GlobalSecret`** — concurrency cap test (both backends, `-race`: exactly cap succeed) + cookie-opaqueness test; suite + `-race` + golangci-lint clean; README DSN note + SPEC §1.12/§2.2 deltas. Detail in `PROGRESS-ARCHIVE.md`. | 2026-07-09 |
| F-014 | Bump vulnerable indirect dependencies → **`x/text` 0.41.0 + `grpc` 1.83.1 (+ `x/crypto` 0.55.0), Go toolchain 1.26.5 → **1.26.7** in `go.mod` *and* the digest-pinned builder image** — a dry-run `govulncheck` surfaced **six standard-library advisories** (fixed in 1.26.6, published after the last green CI run) on top of the two module ones, several on the auth boundary (`html/template`, `encoding/asn1`, `net/url`); Dependabot now covers indirect Go modules, grouped into one weekly PR. **0 reachable vulns afterwards** (was 8); suite + `-race` + `gofmt` green. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-20 |
| F-015 | Advertise CIMD support in the AS metadata → **`client_id_metadata_document_supported` added to SPEC §1.2 and emitted from `authorizationServerResponse`**, driven by whether a CIMD resolver is configured so metadata and behaviour cannot drift. §1.3 had declared CIMD primary since F-005c while §1.2 never announced it — and clients pick CIMD only when the metadata says so *and* offers `none` auth, so every client silently fell back to deprecated DCR (and toward `DCR_MAX_CLIENTS`). Consent needed no change: it shows `GetClient().GetID()`, which for CIMD is the document URL. New `TestASMetadataAdvertisesCIMD` (with/without resolver + OIDC mirror); suite + `-race` + `gofmt` green. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-016 | Port-agnostic loopback matching for `localhost` redirect URIs → **new `pkg/idp/loopback.go`; `handleAuth` stashes the raw `redirect_uri` on the request context and `clientSource.GetClient` clones the client to admit a port variant** — fosite ignores the port for IP literals only, so a client registering `http://localhost/callback` and redirecting to an ephemeral port was rejected (Claude Code's exact shape). Scheme/host/path/query still match exactly; no bridge between `localhost` and `127.0.0.1`; consent now warns when *all* redirect URIs are loopback. 28 new test cases incl. 7 through the real authorize endpoint; the positive test verified non-vacuous by disabling the stash (400, red). Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-018 | Build the container image in CI → **new `image-build` job**: buildx `push: false`/`load: true` (amd64), `--version` smoke, then a container start polled until Docker's own `HEALTHCHECK` reports `healthy` (failing loudly with `docker logs` otherwise). Closes the gap where a broken `Dockerfile` or base-image bump surfaced only as a failed *release* — F-014's builder digest had been unexercised. The intake's `docker run IMAGE healthcheck` was corrected: it probes `/healthz` on the local listener and needs a running server. Smoke password generated in-step, never written to the repo. **Verified locally against real Docker** (build + `version ci` + healthy), under amd64 emulation. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-020a | Split `idp.go` → **1072 → 216 lines across eight files** (`authorize`, `client_source`, `consent`, `metadata`, `register`, `session`, `token` + the assembly), each under the 300-line target. Sliced at declaration boundaries with doc comments pulled along; `goimports` trimmed each file's imports. **No test file touched** — suite green unchanged is the proof. The planned `git diff -M` criterion turned out unusable (rename detection needs whole-file similarity) and was replaced by stronger checks: 47/47 identical declarations and 954/954 identical body lines, with the +77 net reconciling to seven new headers minus ten dropped imports. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-020b | Split `idp_test.go` to match → **1684 lines across ten files**, each beside the code it exercises, shared helpers lifted into `helpers_test.go`. Ten rather than the planned nine: `token_test.go` would have hit ~439 lines with `TestPrivateClient`, so the RFC 7009 revocation tests became their own file. `stubResolver` went to the helpers because `loopback_test.go` uses it too. **No production file touched**; verified by test-set equality (34/34 via `go test -list`) and identical bodies (1399/1399 lines) — a lost test would otherwise leave the suite green and unnoticed. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |

---

## Open tasks — work top to bottom

### F-020 — Split `pkg/idp/idp.go` along its seams

**Problem:** `pkg/idp/idp.go` is **1073 lines** against the 500-line hard limit in
`CODING-STANDARDS.md` §2, and it carries no section comments, so the documented exception for
"clearly delimited modules" does not apply. `pkg/idp/idp_test.go` is **1684 lines** for the same
reason. The file predates the limit (it came over with the F-008 fork and grew through F-005a–e);
F-016 found it during review and moved its own helpers out rather than adding to it. Size is not
cosmetic here: this is the OAuth authorization surface, the file a reviewer must hold in their head
to reason about token issuance, consent and DCR at once.

**Idea:** Split it along the seams it already has — the declarations cluster cleanly by endpoint —
without changing a single behaviour. A pure move: same package, same identifiers, no signature
changes, so the diff is reviewable as "lines relocated" and the existing tests are the proof.

**Possible implementation:**
- Candidate cut, following the current order of declarations:
  - `idp.go` — `IDPRouter`, `Config`, `NewIDPRouter`, `customCompose`, `withRateLimit`, the
    endpoint constants and route registration (the assembly, ~250 lines).
  - `client_source.go` — `clientSource`, `CIMDResolver`, the redirect-URI context stash
    (joins `loopback.go`, which F-016 already carved out).
  - `authorize.go` — `handleAuth`, `issRedirectWriter`, `errInvalidTarget`, the authorize-request
    ID helpers.
  - `consent.go` — `consentTemplate`, `consentTemplateData`, both consent handlers.
  - `token.go` — token, introspection and revocation handlers.
  - `register.go` — DCR: `registrationRequest`/`registrationResponse`, `validateRegistration`,
    `handleRegister`, `supportedAuthMethods`.
  - `metadata.go` — `authorizationServerResponse`, its handler, `jwks`.
  - `session.go` — `NewJWTSession`, `Session`.
- Split `idp_test.go` to match, so each test file sits next to the code it exercises.
- Add the ASCII section comments §2 asks for wherever a file still groups more than one concern.
- Acceptance: `go test -race ./...` green with **no test changed** beyond its file location, and
  `git diff --find-copies-harder` showing moves rather than rewrites.

**Substeps (`/prep-step`, 2026-08-21) — Large: ~2757 lines relocated across 17 files, net new
~100 (import headers, section comments). No behaviour, signature or file outside `pkg/idp/`
changes.** Both files were mapped declaration by declaration first; the cut below follows the
clusters they already form, and every target file lands under the 300-line target:

| File | Contents | ~Lines |
|---|---|---|
| `idp.go` | `IDPRouter`, `Config`, `NewIDPRouter`, `customCompose`, `withRateLimit`, endpoint constants, `SetupRoutes` | 215 |
| `client_source.go` | `CIMDResolver`, `clientSource`, the redirect-URI context stash, `GetClient`, `lookupClient` | 95 |
| `authorize.go` | `handleAuth`, `issRedirectWriter`, `errInvalidTarget`, `validateResource`, the `ar_id` session helpers | 155 |
| `consent.go` | `consentTemplate`/`consentTemplateData`, both consent handlers | 158 |
| `token.go` | `handleToken`, `handleIntrospect`, `handleRevoke` | 105 |
| `register.go` | DCR request/response types, `validateRegistration`, `handleRegister` | 175 |
| `metadata.go` | `authorizationServerResponse` + handler, `jwks` | 120 |
| `session.go` | `NewJWTSession`, `Session` | 95 |

#### F-020c — Section comments and final standards pass

**What:** Add the ASCII section rules §2 asks for wherever a file still groups more than one
concern, then re-check the whole package against `CODING-STANDARDS.md`.

**Acceptance:**
- [ ] Every file in `pkg/idp/` under the 300-line target, or carrying section comments
- [ ] Full suite + `-race` + `gofmt` + `vet` green

**Explicit non-goal:** `handleRegister` is **103 lines**, over the 50-line hard limit and over the
~80-line orchestration exception. Splitting it changes the DCR endpoint's structure, not a file's
location, so it does not belong in a move-only task — it needs its own F-number.

**Dependencies:** none. Sequencing decided 2026-08-21: F-020 runs **before** F-017, so the spec
re-check and its verification pass see the split code. The earlier note said "not before the
release"; the real constraint is narrower — the split must not land *between* F-017's verification
and the tag, which running it first satisfies.

### F-017 — Re-verify against the final MCP 2026-07-28 authorization spec

**Problem:** The standing watch item is due: v0.1.x was verified against the 2026-07-28 release
candidate, and the final specification has since published. `README.md`, `REQUIREMENTS.md` §0,
`SPEC.md`, `THREAT-MODEL.md`, `PROGRESS.md` and `docs/VERIFICATION.md` all still name the RC as the
reference point.

**Idea:** Re-check the gateway against the published final spec, then replace every RC caveat in
the living documentation with a statement about the final revision, and close the watch item for
good.

**Possible implementation:**
- Authorization surface: changes are small and largely already satisfied — RFC 9207 `iss` stays a
  SHOULD, `application_type` applies to DCR clients, client credentials are issuer-bound (a
  client-side obligation), and DCR is now formally deprecated in favour of CIMD, which F-015
  addresses.
- Transport surface is where the revision is large: no `initialize`/`notifications/initialized`
  handshake, no `Mcp-Session-Id`, mandatory `Mcp-Method`/`Mcp-Name` headers on Streamable HTTP
  POSTs, a new `server/discover` RPC, no SSE resumability. The gateway proxies transparently, so
  this lands on the upstream — but confirm the transparent backend forwards the new headers
  untouched (`httputil.ReverseProxy`, no allow-list, so a confirmation rather than a change) and
  that the reserved-namespace guard does not trip over `server/discover`.
- `pkg/backend/proxy.go` (stdio upstreams) still performs an `initialize` handshake via
  `mark3labs/mcp-go`. Check what the pinned version supports and whether the stdio path must follow
  the revision; Dependabot PRs for that module are open.
- Re-run `docs/VERIFICATION.md` end to end against a live deployment and tick its final-spec
  checkbox.
- Documentation sweep: every "release candidate" caveat becomes a final-spec statement.
- Release gate: once F-014 to F-017 are done, cut the patch release — v0.1.2, or v0.2.0 if the
  re-check forces behaviour changes.
- History, so it is not lost with this section: the RC check (F-007e, 2026-07-08) and the interim
  re-check on 2026-07-09 both found the six authorization SEPs (SEP-2468 `iss`/RFC 9207, SEP-837
  DCR `application_type`, SEP-2352 issuer-bound credentials, SEP-2207 OIDC refresh tokens,
  SEP-2350 step-up scope accumulation, SEP-2351 `.well-known` suffix) satisfied and unamended.

**Dependencies:** F-015 (the DCR-deprecation finding is settled there); best done last so the
re-verification covers the fixed state.

---

## Feature ideas (backlog)

### F-019 — Evaluate whether DCR can be switched off

**Problem:** F-003 decided "CIMD-first with DCR as the deprecated fallback" at a time when the AS
metadata did not advertise CIMD at all — the very gap F-015 closed. With the advertisement in
place, real clients pick CIMD, and the final MCP 2026-07-28 spec formally deprecates DCR while
keeping it for authorization servers that cannot do CIMD. Whether *this* gateway still needs it
is now an open question rather than a settled one.

**Idea:** Re-run the F-003 decision against the post-F-015 reality: which clients would still need
DCR, what breaks if it is off, and under what conditions `DCR_ENABLED` could default to `false`.
A decision task — "keep it as it is" is a valid outcome.

**Possible implementation:**
- Evidence first: confirm from a live deployment that clients actually switched to CIMD after
  F-015 (the DCR store should stop growing).
- Inventory what changes when DCR is off: `registration_endpoint` disappears from the AS metadata
  (already conditional on `dcrEnabled`), `POST /.idp/register` is not routed, and
  `DCR_CLIENT_TTL`/`DCR_MAX_CLIENTS` become inert. Startup fails fast if neither mechanism is
  enabled, so the off-switch cannot strand the gateway.
- Weigh it against the generic-gateway promise: the README targets *any* OAuth-only MCP client,
  not only Claude. A `false` default trades reach for a smaller attack surface and a smaller store.
- If the answer is "switch the default", that is its own implementation task with a CHANGELOG
  upgrade note — this entry produces only the decision.

**Dependencies:** F-015 (live-verified, not merely committed) and F-017.

---

<!-- FEATURE-INDEX
next-feature: F-021
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
F-013 Fix the CI workflow (ci.yml never runs) (DONE)
F-014 Bump vulnerable indirect dependencies (DONE)
F-015 Advertise CIMD support in the AS metadata (DONE)
F-016 Port-agnostic loopback matching for localhost redirect URIs (DONE)
F-017 Re-verify against the final MCP 2026-07-28 authorization spec
F-018 Build the container image in CI (DONE)
F-019 Evaluate whether DCR can be switched off (backlog)
F-020 Split pkg/idp/idp.go along its seams
-->
