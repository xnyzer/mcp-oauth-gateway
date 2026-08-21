# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released.** **v0.1.1 is public** — repo public, multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.1.1`/`0.1`), verified against the **final MCP spec
2026-07-28** (F-017, conformance table in `SPEC.md` §4). The gateway is feature-complete against `SPEC.md`, security-audited (F-006b) and live-
verified against Claude web + iOS (F-006c). All roadmap tasks F-001–F-011 and **F-012** (audit
low-severity follow-ups, substeps a–e → v0.1.1) are done — rationale archived in
`PROGRESS-ARCHIVE.md`. All roadmap tasks through **F-013** (CI `ci.yml` repair) are done.
**One open task** below: the now-due re-check against the published final MCP spec (F-017,
decomposed into four substeps), which also gates the next release — **v0.2.0**, not a patch, because
F-015, F-016 and F-017b each change behaviour. One idea parked in the backlog (F-019). F-numbers are stable IDs; the document order, not the
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
| F-020c | Section comments and final standards pass → **ten doc comments** on the exported identifiers that had none (§11), written to explain why rather than restate the signature, plus **ten section rules** in the three files that still group several concerns (`authorize.go`, `idp.go`, `helpers_test.go`). The expectation that section comments would be redundant proved wrong: `authorize.go` bundles four concerns in 165 lines, and §2 is about structure, not length. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-020 | **Split `pkg/idp/idp.go` along its seams — complete** (a/b/c): two oversized files (1072 + 1684 lines, both past the 500-line hard limit) became twenty, the largest 298, each with one concern. Run as a pure move first and content second, which is what made the verification meaningful — git cannot see a one-into-eight split as a move, so the proof came from invariants: 47/47 declarations, 954/954 and 1399/1399 body lines, 34/34 tests. Sequenced before F-017 so the spec re-check sees the split code. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-017a | Migrate `mcp-go` to `log/slog` and unblock Dependabot PR #13 → **the red dependency PR was a real API migration, not a Dependabot error**: mcp-go dropped its own logger interface for `log/slog` between 0.50 and 0.58, and the Streamable-HTTP logger option changed type too (3 compiler errors, 2 call sites, all in the stdio backend). `zapLogger` deleted; one-line bridge `slog.New(zapslog.NewHandler(logger.Core()))` wraps the *existing* core so stdio output stays in the gateway's stream. Took Dependabot's `go.mod`/`go.sum` verbatim (45 updates) + `go.uber.org/zap/exp` v0.3.0, which adds **no** transitive dependency — all six of its requirements were already in the build. New `TestNewSlogLoggerWritesToZap`, because the two existing tests traverse both call sites but with `zap.NewNop()` and would stay green against a discarding core; verified non-vacuous. **Chose 0.58.x over v1.0.0-beta.1** (§7 pins stable versions), so the stdio path speaks 2025-11-25 until v1.x is final — documented in F-017c. All five CI jobs replicated locally, incl. `image-build`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-017b | Transport conformance → **closed a real spoofing path on the credential injection**: `PROXY_HEADERS` entries were attached with `Header.Add` and, unlike the `HEADER_MAPPING` loop two lines above, no inbound copy was deleted first — so a client-supplied header of the same name landed *in front of* the injected one, where an upstream reading `Header.Get` finds it instead of the credential (FR-6/SR-7). Always reachable in principle; MCP 2026-07-28 made it routine by mirroring tool parameters into client-set `Mcp-Param-*` headers (SEP-2243). Fix is one line that *replaces* the `Authorization` special case, so the function got shorter. Three tests: header pass-through (incl. Base64 sentinel), `server/discover` not swallowed by the path-prefix guard, and the negative asserted on the **full value slice** — `Header.Get` would have passed while the attacker's copy sat behind. Both **verified non-vacuous** (reverting → `["attacker-supplied", "upstream-secret"]`). `transparent.go` needed no change. Tests went to a new `transport_test.go`, not the 1035-line `proxy_test.go` (§2 hard limit — split reported as open). Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-017c | Documentation sweep and conformance record → **seven live "release candidate" caveats became final-spec statements** and the standing watch item was **closed rather than re-dated** (no successor: a watch item that renews itself forever is a reminder nobody reads). New **`SPEC.md` §4**: 16 authorization rows covering every server-side MUST/SHOULD, 10 transport rows each attributed to **gateway** or **upstream** — the attribution is the point, since "the upstream owns it" only holds while the gateway provably forwards enough for it to comply — plus §4.3 for the two deliberate gaps (scope-less design, stdio at 2025-11-25). **§4.2 carries a ✘**: `Origin` is an unmet MUST, recorded with its mitigation and F-021 rather than omitted. Self-auditing the table against the spec caught **two missing normative rows** the draft had — the criterion would otherwise have been ticked while false. CHANGELOG v0.2.0 with upgrade note for the F-017b header change. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |

---

## Open tasks — work top to bottom

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

**Substeps (`/prep-step`, 2026-08-21) — Large: ~350 lines across ~16 files, of which ~200 are
documentation.** The final specification has published and was read end to end against the code.
The authorization surface needs **no change** — but the re-check turned up four things the intake
above did not anticipate, and one of them is a security fix:

| # | Finding | Verdict |
|---|---|---|
| 1 | `authorization_response_iss_parameter_supported` is now a **MUST** for servers that send `iss` (it was implied before) | Already `true` in `metadata.go` — satisfied |
| 2 | `scope` in the `WWW-Authenticate` challenge is a new **SHOULD**; `offline_access` **SHOULD NOT** appear in `scopes_supported` | The gateway is scope-less by design (`scopes_supported: []`, no `offline_access`) — a decision to *document*, not to implement |
| 3 | **`Mcp-Param-{Name}` (SEP-2243)** makes client-set HTTP headers a first-class feature and obliges intermediaries to forward unrecognised ones. That elevates a latent gap: `pkg/proxy/proxy.go` adds each configured `PROXY_HEADERS` entry with `Header.Add` and **no preceding `Del`**, so a client-supplied header of the same name survives and — since `Header.Get` returns the first value — can shadow an injected upstream credential. `HEADER_MAPPING` and `Authorization` are stripped correctly on the two lines above it; the other proxy headers are not. | **Real spoofing path on FR-6 → fix in F-017b** |
| 4 | The stdio backend's protocol version is whatever `mark3labs/mcp-go` implements. `v0.58.0` is still `2025-11-25`; only `v1.0.0-beta.1` implements `2026-07-28` (`server/discover`, `_meta` protocol version, header validation). | Stay on the stable 0.58 line; record the ceiling as a documented limitation and file the v1.x move separately once it is final |

Confirmed by reading, no change needed: `httputil.ReverseProxy` forwards
`MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` untouched — `transparent.go` only
rewrites `X-Forwarded-*` — and the reserved-namespace guard matches **URL path prefixes**
(`/.idp/`, `/.auth/`, `/.well-known/`), so the new `server/discover` RPC, which lives in the
JSON-RPC body, cannot collide with it. Both get a regression test in F-017b so the confirmation
does not silently expire.

Decisions taken at prep time: **mcp-go 0.58.x** over `v1.0.0-beta.1` (CODING-STANDARDS §7 pins
stable versions; a pre-release on a public auth boundary is not worth the stdio path's spec
currency); **`go.uber.org/zap/exp`** for the zap→slog bridge over a hand-written handler (MIT, by
the zap authors, no new transitive dependencies, and §1 prefers an established pattern);
**v0.2.0** over v0.1.2 as the release version.

#### F-017d — Live verification and release

**What:** Run `docs/VERIFICATION.md` end to end against the deployment and tick its final-spec
checkbox. This is also the step that finally *ships* F-015 and F-016: the live gateway still runs
0.1.0, so the fix for Claude failing to connect has been merged but not deployed. Then tag and
release.

**Files:** `docs/VERIFICATION.md` (close-out), evidence in `private/` (gitignored)

**Acceptance:**
- [ ] Discovery, JWKS and the fail-closed `401` verified live
- [ ] Claude connects again, and via **CIMD** rather than the DCR fallback (F-015 working in the
      field, not merely committed — the DCR store should stop growing, which also feeds F-019)
- [ ] Live negatives denied: no token, tampered token, revoked token
- [ ] Every runbook row recorded in `private/`
- [ ] `v0.2.0` tagged, multi-arch GHCR image verified by an anonymous pull, GitHub release published

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

### F-021 — Validate the `Origin` header (DNS rebinding, SR-9)

**Status:** BACKLOG

**Problem:** The Streamable HTTP transport has required servers to validate `Origin` and answer
`403 Forbidden` when a present value is invalid since protocol version **2025-03-26** — this is not
new in 2026-07-28, it was simply never noticed, including by the F-006b audit. The gateway reads
`Origin` nowhere. It also leaves half of **SR-9** ("Tight CORS/headers") unfulfilled: SPEC §0
implements only the `Cache-Control: no-store` part, and nothing tracks the other half as open.

**Idea:** Validate `Origin` **only when the client actually sends it**, against the origin derived
from `EXTERNAL_URL`, and answer 403 otherwise — plus an env option to switch the check off, so an
operator whose deployment it breaks can rescue it instead of having to downgrade.

**Possible implementation:**
- **Act on a present header only.** Server-side MCP clients send no `Origin` at all: Claude connects
  from Anthropic's cloud, not from the user's browser, so the common deployment is untouched by
  design rather than by luck. A *missing* `Origin` must stay allowed — treating absence as a
  violation would reject every real client and turn a hardening measure into an outage.
- Natural allow-list: the origin of `EXTERNAL_URL`. The gateway emits no CORS headers at all, so no
  legitimate cross-origin browser client works today anyway — a strict default costs nothing that
  currently functions.
- **Off-switch via env, defaulting to enabled** (SR-3 stays fail-closed; disabling is an explicit
  operator decision, and the disabled state belongs in the startup log so it cannot be forgotten).
- Severity is **defence-in-depth, not an open hole** — the entry should not be read as urgent.
  `/mcp` is bearer-protected, so a rebinding attacker without a token already gets 401; `/.auth/*`
  is the browser surface where rebinding would actually bite, and it has carried per-session CSRF
  tokens and `SameSite=Lax` since F-012c. The case this genuinely improves is a **loopback
  deployment**, the classic rebinding target — and F-016 showed those are real here.
- **Sequenced after the release on purpose.** This is exactly the class of change that silently
  broke the Claude connector twice (F-015, F-016). Landing it once v0.2.0 is released *and* live-
  verified gives a known-good state to measure against, instead of two variables at once.

**Still to analyse:** whether the env option should be a boolean off-switch or an
`ALLOWED_ORIGINS` list that widens the accepted set. A list is the more useful shape if
browser-based MCP clients ever matter; an off-switch is the simpler rescue. Also open: whether the
check belongs on every route or only on `/mcp` and `/.auth/*` — the `.well-known` documents are
public by definition and a 403 there would be surprising.

**Dependencies:** F-017 (F-017c records the gap in its conformance table; this entry must not delay
the v0.2.0 release, and it wants a live-verified deployment to land against).

---

### F-022 — Bring the remaining oversized files under the §2 limits

**Status:** BACKLOG

**Problem:** CODING-STANDARDS §2 sets a 300-line target and a **500-line hard limit**. F-020 brought
`pkg/idp` under it, but nothing ever surveyed the rest of the tree: **six files are still past the
hard limit**, the largest at 1035 lines, and twelve more sit above the 300-line target. F-017b ran
straight into this — its new tests could not go into `pkg/proxy/proxy_test.go` without pushing a
1035-line file to 1180, so they went into a new file and the underlying violation stayed untouched.

| File | Lines | Kind |
|---|---|---|
| `pkg/proxy/proxy_test.go` | 1035 | tests |
| `pkg/mcp-proxy/main.go` | 934 | production — assembly and config wiring |
| `main_test.go` | 776 | tests |
| `pkg/repository/sql.go` | 694 | production — SQL persistence |
| `main.go` | 565 | production — CLI surface |
| `pkg/auth/auth.go` | 534 | production — password/session/WebAuthn glue |

Same origin as F-020's two files: they came over with the F-008 fork and grew through F-005 and
everything after it. Size is not cosmetic in this repo — these are the files a reviewer has to hold
in their head to reason about the auth boundary.

**Idea:** Repeat the F-020 method. Cut each file along the seams its declarations already form, as a
**pure move** with no behaviour change, so the existing tests are the proof rather than something
that also changed.

**Possible implementation:**
- Sequence by value rather than by size: `pkg/mcp-proxy/main.go` (934) is the gateway's assembly and
  config wiring — the file most often opened to answer "what does this deployment actually do" — and
  is worth more than the larger test file.
- `main.go` and `main_test.go` are one CLI surface and want a single cut.
- `pkg/repository/sql.go` and `pkg/auth/auth.go` each carry several concerns already (persistence per
  entity; password, session and WebAuthn glue).
- **Carry F-020's verification lesson over:** `git diff -M` cannot see a one-into-many split as a
  move, because rename detection works on whole-file similarity. The proof has to come from
  invariants instead — identical declaration sets, identical body-line counts, identical test sets
  via `go test -list`. Run the move first and any content change strictly second, or those
  invariants stop proving anything.
- The twelve files above the 300-line target are **out of scope** unless a cut makes them fall out
  naturally; §2 only asks to "check whether it can be split" at 300, and the hard limit is the
  actual violation.

**Still to analyse:** whether this is one F-number with a substep per file, or several — six files
is a good deal more than F-020's single package. Also open: whether `handleRegister` (103 lines,
against the 50-line hard limit and the ~80-line orchestration exception in §3), which F-020
explicitly recorded as a non-goal, belongs here or stays its own task; splitting it restructures the
DCR endpoint rather than relocating a file, which is a different kind of change.

**Dependencies:** none — but like F-020 it must not land between F-017's verification and the v0.2.0
tag, or the release would ship code the verification never saw.

---

<!-- FEATURE-INDEX
next-feature: F-023
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
F-020 Split pkg/idp/idp.go along its seams (DONE)
F-021 Validate the Origin header (DNS rebinding, SR-9) (BACKLOG)
F-022 Bring the remaining oversized files under the §2 limits (BACKLOG)
-->
