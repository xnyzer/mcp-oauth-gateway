# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/coding-kit:add-feature` intakes new tasks (F-number), `/coding-kit:prep-step` prepares and decomposes, `/coding-kit:build-step` implements, `/coding-kit:step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released and live.** **v0.4.2 is public** — repo public, multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.4.2`/`0.4`), verified against the **final MCP spec
2026-07-28** (F-017; conformance recorded requirement by requirement in
`docs/MCP-CONFORMANCE.md`). Feature-
complete against `SPEC.md`, security-audited (F-006b) and **live-verified end to end on 2026-08-21**:
Claude connects via **CIMD**, no longer via the deprecated DCR fallback. The rationale for every
finished task is archived in `PROGRESS-ARCHIVE.md`.

**One task planned, two in the backlog:** F-031 (dependency and platform updates, five substeps a–e, ending in v0.5.0) is planned and under way — **F-031a, F-031b and F-031c are done**, d and e are open; F-032 (repository and supply-chain hardening) and F-033 (a dated watch item, re-check on 2027-01-15: frozen OpenTelemetry exporters) wait in the backlog. Every task F-001–F-030 is done. **F-024** added the operator's client
list with its kill switch and **F-025** the name each connection carries — both live-verified on
2026-08-23 (a revoke reached the real client in **44 seconds** against a one-hour token TTL; the
name prefilled from Claude's own metadata document). **F-026** dissolved `REQUIREMENTS.md` into
`SPEC.md` §5 and stripped the implementation history that hid a MUST from F-004 until F-025 tripped
over it; **F-027** retired the project's local skills and settled the documentation architecture —
rules (`SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`) apart from records (`docs/`). A
reference guard (`docs_refs_test.go`) now keeps every `SPEC §…` and FR/GR/SR pointer honest in CI.
**F-022 is done** (a–e): six files sat past the §2 hard limit, **none does now**. The last of them,
`pkg/mcp-proxy/main.go`, could not be fixed by moving declarations at all — a single 645-line
function filled it — so `Run` was decomposed and verified against the running binary rather than by
the invariants the four pure moves used. It spawned **F-028**, which retires the parallel gateway
the end-to-end harness still builds.

**Released: v0.4.0.** It carries the operator's client list with its kill switch (F-024), the name
a connection gets at consent time (F-025), and the documentation and structural work behind them
(F-022, F-026, F-027, F-028). The deployment ran ahead of the registry on a locally built image
since 2026-08-23; **pulling `0.4.0` makes it reproducible again**, which is the point of the
release.

**Released: v0.4.1**, a security patch (F-029) — `0.4.0` was built with Go 1.26.7 and carries 11
reachable standard-library advisories plus five in `x/net`; `0.4.1` has none reachable. **The
deployment runs `0.4.1` since 2026-10-12**, pulled from the registry; the signing key carried
over, so connected clients kept their tokens, and the operator confirmed Claude connects.

**Released: v0.4.2**, the version display on the settings page (F-030) — a patch release on
the operator's decision. **The deployment runs `0.4.2` since
2026-10-12**; the signing key carried over again, and the operator confirmed the footer in the
browser — the one check F-030's own verification could not make.

F-numbers are stable IDs; the document order, not the number, is the path.

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
| F-023 | CIMD documents rejected over a foreign grant type → **the defect v0.2.0 made reachable**. Claude's published document declares `jwt-bearer` beside `authorization_code` and `refresh_token`; the resolver validated the whole list against its supported set and rejected the **entire client** (`invalid_client`, connector dead). A CIMD document is published once and shown to *every* AS, so it names the union of the client's abilities — refusing it for that makes CIMD unusable. Now **narrowed** to the supported subset (fail-closed; nothing-supported still rejected); **DCR stays strict**, since a registration request addresses one server. Hidden until F-015 made clients actually choose CIMD. Regression test reproduces the live error message verbatim; two tests that encoded the old behaviour were deliberately changed. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-017d | Live verification and release → **released `v0.2.0`, deployed, verified live — and the verification broke, which is what made it worth running.** Server side all green, incl. the F-015 proof: `client_id_metadata_document_supported` was **absent before** the switch and `true` after. Client side defeated three approaches (second connector refused; remove+re-add reuses stored credentials and produces *no* OAuth flow; `DCR_CLIENT_TTL` never fires because it is refreshed on every token issuance), so the DCR record was deleted from the store — 2 records before, F-019's evidence that it *had* been growing. Claude then switched to CIMD and the gateway refused it → **F-023 → v0.2.1**, after which `token_issued` carried a **URL** client_id and **zero** `register` events. Corrected a wrong premise en route: the host ran **0.1.1**, not 0.1.0 — the local compose copy had drifted for six weeks. Runbook gained "Force a fresh client registration", because a verification that only exercises an already-connected client passes while the gateway is broken for every new one. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-017 | **Re-verify against the final MCP 2026-07-28 spec — complete** (a/b/c/d): watch item closed, deliberately without a successor. The authorization surface needed **no change** — all six SEPs still satisfied — so everything this task fixed lay elsewhere: a credential-injection spoofing path (F-017b), a CIMD resolver defect that made CIMD unusable with real clients (F-023), and documentation claiming conformance without evidence (F-017c, now `SPEC.md` §4). A paper re-check would have concluded "conformant, no action" and been wrong twice. One MUST recorded as **unmet** rather than glossed over: `Origin` validation (F-021). Released **v0.2.0** and **v0.2.1**, both live-verified. Spawned F-021, F-022, F-023, F-024. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-21 |
| F-021 | Validate the `Origin` header (DNS rebinding, SR-9) → **closes the one unmet MUST** the F-017 re-check found; `SPEC.md` §4.2 now reads ✔. A foreign or `null` Origin gets `403`; an **absent** header passes, deliberately — server-side MCP clients send none, so rejecting absence would take the gateway offline for every real client. Comparison on scheme+host+port, host lower-cased, default ports elided. `ORIGIN_CHECK_ENABLED=false` is the rescue, logged at startup. **The fail-closed test caught a real bug:** an expected origin normalizing to `""` would have matched `Origin: null` and turned the guard into a wildcard while its comment claimed otherwise. Also found: IPv6 bracket handling, and that **the e2e suite does not prove the wiring** (it builds its own router) — verified against the running binary instead. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-22 |
| F-019 | Evaluate whether DCR can be switched off → **decision: `DCR_ENABLED` stays `true`**, no code. F-017d supplied the evidence asked for (Claude picks CIMD, the store stops growing) — but that shows *Claude* needs no DCR, not that no client does. The decisive argument arrived after the entry was written: **F-023 made DCR the documented escape hatch** when a CIMD document cannot be fetched (#650), so a `false` default would *break* that advice — flipping only `CIMD_ENABLED=false` hits the both-disabled fail-fast and the gateway refuses to start. The original motivation was gone anyway: the store grew *because* clients were forced onto DCR, which F-015 fixed. Delivered as guidance rather than a bare verdict — a README section on when an operator *should* disable it, the re-decision beside F-003 in the then-separate `REQUIREMENTS.md` §6 (dissolved in F-026), and `SPEC.md` §4.1 updated because it still posed the question this task answered. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-22 |
| F-024a | Enumerate and revoke in the repository layer → **the layer had no enumeration at all**, which is why F-017d needed a purpose-built bbolt tool to delete one record. New `InventoryStorage` (`ListClientGrants`, `RevokeClient`, `RevokeGrant`, `RevokeAll`) on both backends, fed by **one** shared aggregator so the two listings cannot drift. Built from **token records, not client records**: a CIMD client has no stored registration, so enumerating `client-*` would miss exactly the clients that matter. A revoke sweeps all five record kinds plus the registration in **one transaction**; an unreadable record **fails loudly** instead of being skipped, unlike the sweeper — skipping would report a kill that did not happen. `RevokeAll` spares the operator's account and passkeys. No schema change. 30 subtests, **non-vacuity proven by two mutations**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-22 |
| F-024b | The settings surface and its wiring → `/.auth/settings` gained **Connected clients**: one row per client with its authorizations behind a `<details>`, actions per client and per grant, and the panic button behind a **server-rendered two-step** confirmation (no JS). Behind the page's existing gates; `authevent.Revoked` now carries an operator kill beside the client-initiated RFC 7009 ones. **A mutation caught a security test passing for the wrong reason** — a bare `&http.Client{}` followed the handler's redirect and scored the settings page's own 403, so the own-user gate could have been deleted unnoticed; fixed and re-proven. `Config.Clients` is **required** when `Users` is set rather than nil-checked, so no second visibility rule appears. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-024c | Verify against the running binary, then document → the substep no test suite could stand in for: `e2e_harness_test.go` builds its own router, so the wiring was proven against a **local binary** (full OAuth+PKCE flow, real token, revoke, immediate `401`) and then against the **live deployment** with the operator's own Claude connector. The measurement that matters: **44 seconds** from revoke to the client's `401`, against an `ACCESS_TOKEN_TTL` of one hour. Live-only findings: rotation history aggregated on real data (`1 access / 6 refresh` as one row), and a leftover DCR registration showing with `0 authorizations`. The operator asked what the two revoke buttons differ in — a fair question, so they were relabelled **Revoke client** / **Revoke this authorization** and pinned by a test. One acceptance criterion of mine was overstated and got corrected in the spec, not glossed over. F-017d's manual store-editing procedure is **gone** from the runbook. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-024 | **Operator view of connected clients, with a kill switch — complete** (a/b/c). The gateway can now show who holds access and take it away; `/.idp/revoke` never could, being client-authenticated. Built from **token records, not registrations**, because a CIMD client has no stored registration — the obvious implementation would have missed exactly the clients that matter, and the live run confirmed it. Per client and per authorization, **never per device**, and a revoke bans nobody. Three mutations were run against the finished code; one caught a security test **passing for the wrong reason**. Retires the manual bbolt procedure F-017d had to write. Spawned **F-025**. Not yet released. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-025a | The label, end to end → a connection can be **named at consent time**; the name rides the gateway's own session, so it is server-set (no client can plant one), written with every token record, and deleted with the authorization — **no new entity, no cleanup path**. Sanitized once where it enters (control characters, 64 runes), shown as the row's primary identifier, and carried into `token_issued` and `revoked`. **Mutation testing found two of my own defective assertions:** the acceptance criterion claimed `Session.Clone` carries the label through the token exchange — it does not, the session is restored from stored JSON there, and `Clone` matters **only on refresh**; and the refresh test read an aggregate, so an older record answered for the newer one that had lost the name. Both fixed, then four mutations verified red. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-025b | The prefill, and the documentation → the consent field is prefilled with the `client_name` the client declares, which **closes the `SPEC.md` §1.5 identity requirement** unmet since F-004: both mechanisms parsed that name and threw it away. DCR stores it now (`RegisterClient` took an options struct, removing a §3 violation instead of growing it); CIMD reads it through the **same** resolver fosite uses, so its cache serves it. **The review caught a defect the tests could not:** the SQL backend never stored the name — invisible because the idp tests and the deployment are both bbolt. Fixed, with a two-backend contract test that goes red on exactly that. Live-verified: the prefill arrived as "Claude" from Claude's real document. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-025 | **Name a connection at consent time — complete** (a/b). The design came from the operator's pushback against a three-substep plan: their "a new data field, not a new storage structure" pointed at the gateway's own **session**, which is already persisted with every record of a grant — server-built, so no client can plant a label, and deleted with the authorization, so no cleanup path exists. Two substeps and the renaming UI fell away with it. Closed a §1.5 violation nobody had noticed, and spawned **F-026**. **Three defects found, none by a red suite:** two by mutation (a wrong acceptance criterion about `Session.Clone`, two assertions that could never fail) and one by review (SQL never stored the name). The first two are now rules in `CODING-STANDARDS.md`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-026 | **Dissolve `REQUIREMENTS.md` into SPEC, and strip the history out of SPEC — complete** (a/b/c). One document for rules, one for finished work, one for open work. The register is now `SPEC.md` §5 (appended — **no §0–§4 heading renumbered**, because 251 code references point there); the 15 Delta paragraphs and 108 F-number lines are gone, and the contract text is **645 lines instead of 763** while carrying the register. **The plan's own safety net was too weak, and the mutation proved it:** built to the specified prefix rule, renaming `§1.11` to `§1.14` left the suite green — every `1.x` resolves while §1 exists. The guard now counts the parent's list items; seven mutations verified red. **Four contract statements existed only inside a Delta** (`exp` MUST be present, the 4 MiB redirect-replay cap, the post-login redirect normalisation, the SQLite pragmas) and were lifted out before deleting; an audit confirmed 28/28 removed statements survive. **One plan decision reversed on evidence:** two "duplicated" NFR lines are *cited* from §2.2/§3.3, so deleting them would have aimed two pointers at nothing. Spawned **F-027**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-027 | **Retire the local skills and finish the documentation architecture — complete.** Came out of the operator's review of F-026, not from `/add-feature`. The four skills in `.claude/skills/` are dead — the workflow runs on the coding-kit plugin — so F-026b had politely *edited* files that should have been deleted; six documents pointed at them. `SPEC.md` is a **rules** document, measured (**325 code citations against 46 from docs**), and now says so in its own header: §3's option tables were a total duplicate of README (**−33 % characters**) and §4 was a verification record, moved to `docs/MCP-CONFORMANCE.md` behind a stub so append-only references keep resolving. **The tidy-up audit found five real faults, not zero:** a dead unlinked `docs/README.md`, `CLAUDE.md` two releases stale at `v0.1.0`, three live pointers at the moved §4, three competing document indexes, and a README index naming neither `CODING-STANDARDS.md` nor `CONTRIBUTING.md`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-23 |
| F-022a | Persistence and auth glue split → `pkg/repository/sql.go` (712) into four files along its entity seams and `pkg/auth/auth.go` (558) into four along its concerns; **largest new file 275 lines**, under the 300-line target rather than merely under the 500 limit. Cut by script — whole declaration segments including their doc comments — because hand-editing 730 lines of seams is where a "pure move" quietly stops being one. **Proven, not asserted:** an AST parser reports the declaration set and per-declaration body-line counts identical (215 in `pkg/repository`, 197 in `pkg/auth`), and a line multiset shows **0 lost, 0 gained** — a check beyond the plan, because the declaration invariant cannot see a comment stranded between the imports and the first declaration. No test file touched, so the green suite is evidence. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-022b | CLI surface split → `main.go` (568) and `main_test.go` (776) cut **together** into five pairs, each production file with a test file of the same name; largest is 260 lines. Deviated from the plan's two-or-three files: separating environment reading from string parsing is what keeps every file under the 300-line target rather than merely under the 500 limit, and it makes the mirroring exact. **Three invariants compared, not asserted:** 94 AST declarations with identical body-line counts, `go test -list` identical at 29 tests, line multiset 0 lost / 0 gained — the last one matters more here than in F-022a, because this substep touches test files, so a green suite alone no longer proves nothing fell out. Also verified that no file name accidentally reads as a build constraint (`IgnoredGoFiles` empty). Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-022c | Proxy test file split → `pkg/proxy/proxy_test.go` (1035) into four thematic files; mirroring production was unavailable because the package has a **single** production file, so the cut follows the seams `proxy.go` itself forms. **Deviation from a and b:** two files stay above the 300-line target (343, 414) though under the 500 limit — the finer cuts would separate "is the token valid" from "is it still active", tearing apart tests of the same contract line. **The criterion that matters when splitting a test file:** each of the five shared helpers has exactly one definition — a duplicated helper compiles and then silently drifts. 35 declarations, 17 tests, 0 lines lost. Also corrected `transport_test.go`, whose opening comment justified its existence by the limit this substep removed. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-022d | `Run` part 1 → phases 1–4 (config normalisation, validation, data directory, logger, upstream, store, keys, limiters, sweeper) extracted into `config.go`, `deps.go` and `sweeper.go`; **`Run` 645 → 415 lines**, `main.go` 949 → 716. The check order is contract — a misconfigured deployment sees the *first* problem — so it was reproduced exactly, and the **13 existing fail-fast cases stayed green with no test touched**, which is what makes them evidence. Closed the one genuinely uncovered branch (CIMD and DCR both disabled: execution count 0 → 1); coverage **46.9 % → 48.1 %**, measured, the modest rise predicted because the uncovered remainder is what F-022e moves. Three new assertions each proven able to fail. **Review caught a §3 violation no linter checks:** `sweep` had four parameters against the maximum of three. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-022e | `Run` part 2 → phases 5–7 into `router.go` and `server.go`; **`Run` 645 → 27 lines**, `main.go` 949 → 312, and **no file in the repository is past the 500-line hard limit any more**. The server phase was three near-identical blocks — ~150 lines of listen/shutdown goroutine duplication — now one `serverGroup.serve` that decides TLS from the server's own `TLSConfig`. **Verified against the running binary, not the suite**, which provably does not exercise this path: five fail-fast paths abort with their message; live, the three discovery documents answer 200 and are self-consistent, `/mcp` without a token gives 401 with `WWW-Authenticate`, a foreign `Origin` gets 403. The design constraint was met — the wiring returns the engine without listening — but the harness still cannot call it, because the parameter types are package-private and it lives in package `main`. Recorded as **F-028**, which also owns the retrofit: `BuildRouter` was exported for a caller that cannot exist. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-022 | **Bring the remaining oversized files under the §2 limits — complete** (a–e). Six files were past the hard limit, the largest at 1035 lines; **none is now**. Four substeps were pure moves proven by invariants — identical AST declaration sets with body-line counts, identical `go test -list`, and a line multiset showing nothing lost or gained; the fifth decomposed a 645-line function and was verified behaviourally instead, because those invariants only prove while nothing changes. **Two lessons outlast the line counts.** The planned safety net was too weak and only a mutation showed it: built to the specified prefix rule, renaming a heading left the suite green. And the task had to be **re-planned mid-flight** because F-022d's stated purpose rested on reading `Run`'s 35 % coverage as if it described its branches — three of four fail-fast paths were already covered. Spawned **F-028**. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-028a | End-to-end tests moved into `pkg/mcp-proxy` (794 lines, by `git mv`) so they can reach the gateway's own assembly instead of rebuilding it. **The compiler proved the duplication:** the move produced exactly one error, `tokenActiveChecker redeclared`, and the two implementations were identical line for line — the harness copy even said "copied from Run". **Deviated from the plan for the better:** it called for renaming the copy and deleting it in F-028b, which would have left two identical functions under two names; the harness now calls the production one, so `tokenActiveChecker` exists exactly once already. Identical test set of **240** across the repository, verified by `go test -list`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-028b | Harness onto the real startup path → `newE2EGateway` runs `resolveConfig` → `openDependenciesWithLogger` → `buildRouter` and **assembles nothing itself**; the mock upstream runs as a real HTTP server behind `ProxyTargets`, so the transparent backend is exercised too. **The gap that motivated the task is closed and was measured, not argued:** a throwaway probe against the real login printed `Path=/; Max-Age=600; HttpOnly; SameSite=Lax` with a signed-and-encrypted value, where the old harness had none of it. Two package-internal seams, one of them a structural fix — the CIMD resolver moved to `deps.go`, where collaborators are built. **Retrofit from F-022e done:** `BuildRouter` is unexported again, so `pkg/mcp-proxy` exports exactly what it did before F-022e. Beyond the plan: `OriginCheckEnabled: true`, because leaving it off would have created a fresh divergence in the task that exists to end divergence. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-028 | **Retire the parallel gateway in the end-to-end harness — complete** (a/b). The suite tested a gateway it built itself, and the two had drifted where it mattered most: the session cookie ran without encryption, `HttpOnly`, `Secure` or `SameSite`, so a regression in any of those SPEC §1.12 properties was invisible to it. Now the suite drives the binary's own startup path and constructs nothing — by construction rather than by vigilance, which is what F-021 could not achieve by fixing the symptom once by hand. **The compiler proved the duplication** during the move: exactly one redeclaration error, and the two `tokenActiveChecker` bodies were identical line for line. Carried its predecessor's correction too: F-022e had exported a function for a caller that could never exist. Detail in `PROGRESS-ARCHIVE.md`. | 2026-08-24 |
| F-029 | Close reachable vulnerabilities and scan the toolchain we ship → **`x/net` 0.61.0, `grpc` 1.83.2, Go toolchain 1.26.7 → 1.26.9 in `go.mod` *and* the digest-pinned builder image, and `vulncheck.yml` fixed to scan the pinned toolchain**. Triggered by the weekly `vulncheck` failing on five HTTP/2 advisories in `x/net`. **The real finding was the blind spot behind it:** `govulncheck-action` defaults `go-version-input` to `stable`, which overrides `go-version-file`, so CI scanned the standard library of Go 1.27.2 — the shipped binary, built with 1.26.7, carried **11 reachable standard-library advisories** (net/http, HTTP/2, crypto/tls, html/template, net/textproto) that no run ever reported. Run against 1.26.9: **0 reachable**. Suite + `-race`, gofmt, vet, golangci-lint, go-licenses, actionlint and a local image build polled to `healthy` all green. Detail in `PROGRESS-ARCHIVE.md`. | 2026-10-12 |
| F-030 | Show the running version on the settings page → **footer on the session-gated `/.auth/settings`, fed from the build-time version that `--version` reports** (passed in through `auth.Config`, wired where the router is built), so the operator can confirm in the browser which build is live. **The boundary is the point, not the rendering:** a version string tells an anonymous caller which advisories apply, so `/healthz` (SPEC §1.13) and every other public endpoint still disclose none — asserted on the assembled gateway, where `/healthz` on the real router had no exact-body test before. **Eight mutations, each seen red:** footer removed, wiring removed, version leaked into `/healthz`, onto the login page, into the redirect, the empty-value guard dropped, `Abort` removed, the session gate removed. One of them exposed a gap in the new end-to-end test itself, closed in the same step. Detail in `PROGRESS-ARCHIVE.md`. | 2026-10-12 |
| F-031a | Routine dependency bumps → **35 minor and patch updates applied with pinned versions, no product code** (OpenTelemetry 1.47, gin-contrib, quic-go 0.63, sqlite3, grpc 1.84, `x/oauth2`, `x/time` and the rest); 37 modules moved, because the two `genproto` modules follow transitively — with the three held back for their own substeps (`glob`, `go-webauthn`, `mcp-go`) that is exactly the forty of Dependabot's grouped PR. **One new indirect module**, `go.opentelemetry.io/otel/log` (Apache-2.0), compiled in through `ory/x`. Matched the `/prep-step` dry run line for line. Full check set green with Go 1.26.9, `govulncheck` 0 reachable, image built and `healthy`. **Surfaced F-033:** `go get` printed that the Zipkin exporter is deprecated and due for removal in early 2027 — it and the long-frozen Jaeger exporter sit in the binary via `ory/x`. Detail in `PROGRESS-ARCHIVE.md`. | 2026-10-12 |
| F-031b | `gobwas/glob` 1.0 — and, on the operator's instruction, the OIDC allow-list hardened → **three security fixes for deployments that log in through OIDC:** (1) the old glob engine was over-permissive — `admin*n@corp.example` matched `admin@corp.example`, `?` matched the empty value; (2) the four `OIDC_ALLOWED_*` settings dropped every entry they could not read, and an allow-list left empty that way meant *no restriction*; (3) **OIDC without any allow-list admitted every account of the provider** — it now refuses to start, and "everyone" has to be written as `OIDC_ALLOWED_USERS_GLOB=*`. Differences between the engines measured, not assumed: both run side by side over 9,512 patterns × 1,555 values, every difference traced to one of six causes, all in the CHANGELOG. README gained an *OIDC allow-lists* section (syntax, the `\,` rule), SPEC §3.1 the normative rule. **21 mutations, each seen red.** The operator is unaffected (no OIDC). Detail in `PROGRESS-ARCHIVE.md`. | 2026-10-13 |
| F-031c | `mark3labs/mcp-go` 1.x → **the stdio backend speaks MCP 2026-07-28 and bridges to what came before**: towards the upstream it probes `server/discover` and falls back to the `initialize` handshake down to 2024-11-05; towards the client it serves 2026-07-28 and the handshake revisions back to 2025-03-26. The two sides are independent — a current client reaches a tool on a 2025-06-18 upstream, proven with a tool call across the bridge. **The one cost:** an older stdio upstream that *ignores* unknown methods delays start-up by the probe timeout, now a named gateway value (`MCPDiscoverProbeTimeout`, 5 s) instead of a library default. `docs/MCP-CONFORMANCE.md` states the versions with `pkg/backend/proxy_protocol_test.go` as evidence, which names each as a literal. Eight mutations, each seen red; `TestSetupProxy`, whose second half tested the upstream instead of the gateway, was removed on the operator's instruction. The transparent backend — and with it the live deployment — is untouched. Detail in `PROGRESS-ARCHIVE.md`. | 2026-10-13 |

---

## Open tasks — work top to bottom

### F-031 — Bring dependencies and the platform up to date

**Status:** PLANNED

**Problem:** About forty dependency updates are pending, and Dependabot's grouped PR cannot
land them: it fails to compile. None closes a known vulnerability — `govulncheck` reports zero
reachable and no alert is open — but the longer the gap grows, the larger and riskier the next
security bump becomes; F-029 showed how a routine fix turns into a toolchain move when the
baseline has drifted.

**Idea:** Take the updates in on `main` in separately verified pieces instead of as one
grouped PR: the routine bumps first, then each update that changes behaviour on its own, then
the Go toolchain. Ship the result as minor release **v0.5.0**.

**What `/prep-step` measured (2026-10-12, dry run in a throwaway worktree):**
- **Only one update breaks the build.** `gobwas/glob` 1.0 turns the `glob.Glob` interface into
  `*glob.Pattern` — a one-word change in `pkg/auth/oidc.go`. `go-webauthn` 0.18.2 and `mcp-go`
  1.2.1 compile untouched, and with all forty updates applied the full suite, lint, licences
  and `govulncheck` are green. The intake's "three API-changing updates" was wrong.
- **The risk is in behaviour, which no compiler reports and our tests do not cover:**
  - `glob` 1.0 is a rewrite of the matching engine closing 23 issues, two of them crashes in
    `Match`. It decides the OIDC allow-list — an authorization decision — and the only test
    for it has two patterns.
  - `go-webauthn` 0.18 validates the relying-party ID as a domain: an IP address as the
    `EXTERNAL_URL` host passed `webauthn.New` under 0.17.4 and fails it under 0.18.2, so such a
    gateway **no longer starts**. Single-label hosts (`http://gateway:8080`) were already
    refused under 0.17.4.
  - `go-webauthn` 0.18 fails a ceremony when the client returns an extension output nobody
    requested. An operator who has disabled the password login is locked out if their
    authenticator does that.
  - `mcp-go` 1.x makes `LATEST_PROTOCOL_VERSION` 2026-07-28; the stdio backend requests it.
    The transparent backend forwards bytes and is unaffected.
- **Go 1.27 needs more than the builder image.** golangci-lint v2.12.2 fails its typecheck
  under Go 1.27, so the pinned linter moves too (v2.14.0 is current). `gofmt` 1.27 realigns
  one struct literal in `pkg/idp/metadata.go`; suite and `govulncheck` are green under 1.27.2.
  Dependabot's PR #17 touches the `Dockerfile` only and would have gone red in `lint`.
- **`distroless/static-debian12` is no longer updated.** The distroless README lists only
  Debian 13 as published and updated and calls every other tag deprecated — which is the
  likely reason Dependabot proposed no new runtime digest.

**Decisions (operator, 2026-10-12):**
- **IP address in `EXTERNAL_URL`: fail fast with a clear message**, over starting without
  passkeys — single-label hosts are already refused the same way, a passkey never could work
  on an IP, and degrading would mean uncoupling the settings page from WebAuthn on the login
  surface. It gets a prominent upgrade note in the CHANGELOG.
- **Unsolicited extension outputs: keep the library's strict default**, verified against the
  operator's real authenticators before the deployment switches.
- **Deployment safety net:** passkeys are bound to the production domain and cannot be tried
  on a staging host, so the operator re-enables the password login before the update, tests a
  passkey login after it, and disables the password again.
- **Runtime image: move to `distroless/static-debian13`**, over re-pinning the deprecated
  `debian12` tag.
- **One minor release, v0.5.0,** after all five substeps — the changed start-up condition and
  the `mcp-go` major are not patch material.

**Still to be analysed:** whether the missing runtime-digest PR is fully explained by the
deprecated tag (F-031d, else F-032).

**Dependencies:** none. Supersedes Dependabot PRs #24 and #17.

#### F-031d — Go 1.27 and the images

**What:** Toolchain 1.27 in `go.mod`, the builder on digest-pinned `golang:1.27-bookworm`,
the runtime on digest-pinned `distroless/static-debian13:nonroot`, golangci-lint on a version
that supports 1.27, and the `gofmt` realignment in `pkg/idp/metadata.go`. The rules that name
1.26 follow.

**Files:** `go.mod`, `Dockerfile`, `.github/workflows/ci.yml`, `pkg/idp/metadata.go`,
`CODING-STANDARDS.md` (§11), `SPEC.md` (§3.3), `CHANGELOG.md`.

**Dependencies:** F-031a–c, so the toolchain moves under a settled dependency set.

**Acceptance criteria:**
- [ ] All five CI jobs replicated locally and green, `lint` with the new pinned version.
- [ ] Image builds; `--version` runs; the container reports `healthy`; it still runs as
      non-root and can write its data directory.
- [ ] `govulncheck` against the 1.27 toolchain: 0 reachable.
- [ ] No reference to Go 1.26 or `static-debian12` is left in the rules or the README.

#### F-031e — `go-webauthn` 0.18

**What:** Last, so the real-device check runs on the final combination. Bump to 0.18.2; turn
the library's relying-party-ID error into a start-up message that names `EXTERNAL_URL` and
says what to use instead; prove that a passkey stored under 0.17 still logs in under 0.18;
cover the stricter response checks.

**Files:** `go.mod`, `go.sum`, `pkg/auth/webauthn.go`, `pkg/auth/webauthn_test.go`,
`pkg/mcp-proxy/` (start-up path test), `README.md`, `SPEC.md` (§1.12, §3.1), `CHANGELOG.md`.

**Dependencies:** F-031d.

**Acceptance criteria:**
- [ ] A credential record written by 0.17.4 completes a login under 0.18.2 (fixture test).
- [ ] An IP address as `EXTERNAL_URL` host stops the gateway at start-up with a message naming
      the setting and the remedy; a domain and `localhost` start. Seen red once.
- [ ] An unsolicited extension output fails the ceremony, pinned by a test, so the strict
      policy is a decision and not an accident of the default.
- [ ] CHANGELOG carries a prominent upgrade note for the `EXTERNAL_URL` change.
- [ ] Full check set green.
- [ ] **On the live deployment:** password login re-enabled first, update applied with a
      backup, the operator's passkey login succeeds, password login disabled again.

## Feature ideas (backlog)

### F-032 — Harden the repository and the supply chain

**Status:** BACKLOG

**Problem:** GitHub's free security features for public repositories are switched off here:
secret scanning, push protection and Dependabot security updates. The actions are pinned by
major tag rather than by commit, and nothing scans the built image — `govulncheck` covers the
Go code and standard library, not the runtime base image. F-029 was a reminder that a check
which does not look at the shipped artefact reports green regardless.

**Idea:** Switch on what costs nothing, and close the two gaps in what CI verifies. Mostly
settings and workflow changes, no product code.

**Solution sketch:**
- Enable secret scanning with push protection and Dependabot security updates in the
  repository settings (operator action, or via the API with the operator's go).
- Pin third-party actions to commit SHAs, with the version as a comment so Dependabot keeps
  them current (CODING-STANDARDS §7: pinned versions).
- Scan the built container image for known vulnerabilities in CI and on a schedule, with a
  permissively licensed scanner — the image-level counterpart to `vulncheck.yml`.
- Consider CodeQL code scanning; decide on signal versus noise before adopting it.

**To be analysed:** which image scanner (licence, maintenance, false-positive rate on a
distroless static image); whether CodeQL adds anything over golangci-lint + `govulncheck`.

**Dependencies:** none. Small enough to go before F-031.

### F-033 — Watch the frozen OpenTelemetry exporters pulled in through `ory/x`

**Status:** BACKLOG

**Problem:** Two trace exporters are compiled into the binary that the gateway never uses and
cannot drop: `ory/fosite` imports `ory/x/otelx`, which imports the OpenTelemetry Zipkin and
Jaeger exporters. The Jaeger exporter was removed upstream long ago and is frozen at v1.17.0;
the Zipkin exporter is announced as "deprecated and will be removed in early 2027". A frozen
module receives no fixes, and the first OpenTelemetry release it no longer compiles against
turns a routine bump into a blocked one — found during F-031a, when `go get` printed the
deprecation notice.

**Idea:** Nothing to build now — the gateway configures no tracing, so the code is never
executed, and both exporters still compile against OpenTelemetry 1.47. Re-check on a date, and
earlier on a trigger, so the removal is met on our schedule rather than in the middle of a
security bump.

**Re-check on 2027-01-15**, or earlier as soon as one of these happens:
- an OpenTelemetry bump fails to build;
- `govulncheck` or a Dependabot alert names either exporter;
- `ory/fosite` or `ory/x` publishes a new version.

**Solution sketch:**
- At the re-check: has OpenTelemetry removed the Zipkin exporter, and at which last version;
  has `ory/x` dropped the two imports (it had not on 2026-10-12, at v0.0.729, and carried no
  issue about it); does the current tree still build against the then-current OpenTelemetry.
- If `ory/x` has not moved: raise it upstream, and decide whether holding OpenTelemetry at the
  last compatible version is acceptable for an auth boundary, or for how long.
- No new dependency; a replacement for Fosite is out of scope here.

**Dependencies:** none.

<!-- FEATURE-INDEX
next-feature: F-034
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
F-017 Re-verify against the final MCP 2026-07-28 authorization spec (DONE)
F-018 Build the container image in CI (DONE)
F-019 Evaluate whether DCR can be switched off (DONE)
F-020 Split pkg/idp/idp.go along its seams (DONE)
F-021 Validate the Origin header (DNS rebinding, SR-9) (DONE)
F-022 Bring the remaining oversized files under the §2 limits (DONE)
F-023 CIMD documents rejected over a foreign grant type (DONE)
F-024 Operator view of connected clients, with a kill switch (DONE)
F-025 Name a connection at consent time, and show the client's own name (DONE)
F-026 Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC (DONE)
F-027 Retire the local skills and finish the documentation architecture (DONE)
F-028 Retire the parallel gateway in the end-to-end harness (DONE)
F-029 Close reachable vulnerabilities and scan the toolchain we ship (DONE)
F-030 Show the running version on the settings page (DONE)
F-031 Bring dependencies and the platform up to date (PLANNED)
F-032 Harden the repository and the supply chain
F-033 Watch the frozen OpenTelemetry exporters pulled in through ory/x
-->
