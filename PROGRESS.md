# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks in execution order** below, **feature index** at the very end.

How it works: `/coding-kit:add-feature` intakes new tasks (F-number), `/coding-kit:prep-step` prepares and decomposes, `/coding-kit:build-step` implements, `/coding-kit:step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

**State: released and live.** **v0.3.0 is public** — repo public, multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.3.0`/`0.3`), verified against the **final MCP spec
2026-07-28** (F-017; conformance recorded requirement by requirement in
`docs/MCP-CONFORMANCE.md`). Feature-
complete against `SPEC.md`, security-audited (F-006b) and **live-verified end to end on 2026-08-21**:
Claude connects via **CIMD**, no longer via the deprecated DCR fallback. The rationale for every
finished task is archived in `PROGRESS-ARCHIVE.md`.

**One task open.** Every roadmap task F-001–F-027 is done. **F-024** added the operator's client
list with its kill switch and **F-025** the name each connection carries — both live-verified on
2026-08-23 (a revoke reached the real client in **44 seconds** against a one-hour token TTL; the
name prefilled from Claude's own metadata document). **F-026** dissolved `REQUIREMENTS.md` into
`SPEC.md` §5 and stripped the implementation history that hid a MUST from F-004 until F-025 tripped
over it; **F-027** retired the project's local skills and settled the documentation architecture —
rules (`SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`) apart from records (`docs/`). A
reference guard (`docs_refs_test.go`) now keeps every `SPEC §…` and FR/GR/SR pointer honest in CI.
**F-022** is planned and ready to build (a–e): six files sit past the §2 hard limit, and one of
them — `pkg/mcp-proxy/main.go` — cannot be fixed by moving declarations at all, because a single
650-line function fills it. It is wanted **before the next release**.

**Released: v0.3.0 — but the deployment is ahead of it.** It runs a locally built image carrying
F-024 **and F-025**, by the operator's decision, and is not reproducible from the registry until a
release replaces it. `CHANGELOG.md` carries the work under `[Unreleased]`.

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

---

## Open tasks — work top to bottom

### F-022 — Bring the remaining oversized files under the §2 limits

**Status:** PLANNED

**Problem:** CODING-STANDARDS §2 sets a 300-line target and a **500-line hard limit**. F-020 brought
`pkg/idp` under it, but nothing ever surveyed the rest of the tree: **six files are still past the
hard limit**, the largest at 1035 lines, and fourteen more sit above the 300-line target. F-017b ran
straight into this — its new tests could not go into `pkg/proxy/proxy_test.go` without pushing a
1035-line file to 1180, so they went into a new file and the underlying violation stayed untouched.

| File | Lines | Kind |
|---|---|---|
| `pkg/proxy/proxy_test.go` | 1035 | tests |
| `pkg/mcp-proxy/main.go` | 949 | production — assembly and config wiring |
| `main_test.go` | 776 | tests |
| `pkg/repository/sql.go` | 712 | production — SQL persistence |
| `main.go` | 568 | production — CLI surface |
| `pkg/auth/auth.go` | 558 | production — password/session/WebAuthn glue |

Same origin as F-020's two files: they came over with the F-008 fork and grew through F-005 and
everything after it. Size is not cosmetic in this repo — these are the files a reviewer has to hold
in their head to reason about the auth boundary.

**Idea:** Repeat the F-020 method. Cut each file along the seams its declarations already form, as a
**pure move** with no behaviour change, so the existing tests are the proof rather than something
that also changed.

**Decided at `/prep-step` (2026-08-23), with the measurements behind each decision:**

- **Five of the six files are pure moves. One is not, and that governs the shape of this task.**
  `pkg/mcp-proxy/main.go` holds a **single 650-line function**, `Run` (lines 217–866). Moving out
  everything else — the `Config` struct with its validation (~170 lines) and the small helpers
  below `Run` (~83 lines) — still leaves ~690 lines around one 650-line function. The file cannot
  reach the limit by relocation; `Run` has to be decomposed, which is restructuring, not moving.
- **The invariant proof does not transfer to `Run`.** F-020's method rests on identical declaration
  sets and identical body-line counts, which only prove anything while nothing changes. Worse,
  measured: `Run` has **35.0 % statement coverage**, it is called from exactly one place
  (`main.go:189`), and the e2e suite does **not** exercise it — `e2e_harness_test.go` says so
  itself ("builds the gateway exactly as `Run()` mounts it"), i.e. it is a parallel implementation.
  This is the same gap F-021 found. The proof there has to be the running binary, including the
  fail-fast paths (no auth backend, both registration mechanisms disabled, malformed values) that
  live in `Run` and that no test covers today.
- **Splitting `Run` is therefore two substeps, not one**, cut at the seam its own phases already
  form: configuration and dependencies (218–485) against wiring and server lifecycle (486–866).
- **A by-product worth having:** once the wiring phase is a named function, `e2e_harness_test.go`
  can call it instead of rebuilding it, which retires the parallel implementation F-021 flagged.
  Not a goal of this task, but the reason to prefer this cut over an arbitrary one.
- **§3 violations stay out of scope.** `handleRegister` (109 lines), `newRootCommand` (232) and
  `handleProxy` (118) are function-length problems, not file-length ones. `Run` is the sole
  exception, because §2 is unreachable there without §3.
- **The fourteen files between 300 and 500 stay out of scope** unless a cut makes them fall out
  naturally; §2 only asks to "check whether it can be split" at 300, and the hard limit is the
  actual violation. `pkg/repository/kvs.go` (487) mirrors `sql.go` and would be worth the same cut
  afterwards for package symmetry — as its own task, not here.

**Substeps** — the pure moves first, so the invariant harness is established before the one change
it cannot prove.

#### F-022a — The persistence and auth glue

**What:** Cut `pkg/repository/sql.go` along its entity seams (token sessions, schema version,
clients, PKCE, authorize requests, user, WebAuthn, marshal helpers) and `pkg/auth/auth.go` along
its three concerns (router + setup, login flow, template rendering). Pure move, no behaviour change.

**Files:** `pkg/repository/sql.go` → several `sql_*.go`; `pkg/auth/auth.go` → several `*.go`

**Acceptance:**
- [ ] Every touched file ≤ 500 lines; no new file above the 300-line target
- [ ] **Identical declaration set** before/after (compared, not assumed) and identical body-line
      counts per declaration
- [ ] `go test -race ./...` green with the test files untouched

#### F-022b — The CLI surface

**What:** `main.go` (env helpers vs. the three Cobra commands) and `main_test.go` (parsing tests vs.
command tests) are one surface and get one cut, so the test layout mirrors the production layout.

**Files:** `main.go`, `main_test.go` → `env.go`/`env_test.go` + command files

**Acceptance:**
- [ ] Both files ≤ 500 lines
- [ ] Identical declaration sets and body-line counts
- [ ] **`go test -list '.*'` returns the identical test set** before/after

#### F-022c — The proxy test file

**What:** Split `pkg/proxy/proxy_test.go` (1035) by theme — token validation, header mapping,
discovery/PRM, reserved namespaces and streaming — with the shared helpers (lines 26–64) kept in
one place.

**Files:** `pkg/proxy/proxy_test.go` → several `proxy_*_test.go`

**Acceptance:**
- [ ] Every file ≤ 500 lines
- [ ] `go test -list '.*'` identical before/after; no helper duplicated

#### F-022d — `Run`, part 1: configuration and dependencies

**What:** Extract phases 1–4 of `Run` (lines 218–485) into named functions that take configuration
and return values: issuer normalisation and TTL/proxy validation, data directory + logger,
repository open and schema check, key manager, abuse-protection limiters and the expiry sweeper.
Because each becomes a function with inputs and a returned error, **the fail-fast paths become unit
testable for the first time** — that is the point, not the line count.

**Files:** `pkg/mcp-proxy/main.go`, plus new files in `pkg/mcp-proxy/`; new `*_test.go`

**Acceptance:**
- [ ] `Run` no longer performs any of the extracted work directly
- [ ] New tests cover the fail-fast paths that had none: missing auth backend, both CIMD and DCR
      disabled, malformed TTL, invalid `TRUSTED_PROXIES` entry
- [ ] Coverage of `pkg/mcp-proxy` rises from its current **46.9 %** — recorded, not estimated
- [ ] `go test -race ./...` green

#### F-022e — `Run`, part 2: wiring and lifecycle

**What:** Extract phases 5–7 (lines 486–866): auth/IDP/proxy router construction, the gin assembly
(trusted proxies, `/healthz`, logging, origin check, session store) and the server lifecycle
(listeners, TLS/ACME, shutdown). `Run` ends up a readable sequence of named steps.

**Files:** `pkg/mcp-proxy/main.go`, plus new files in `pkg/mcp-proxy/`

**Acceptance:**
- [ ] `pkg/mcp-proxy/main.go` ≤ 500 lines and `Run` within the §3 orchestration exception (~80)
- [ ] **Verified against the running binary**, not only the suite: the gateway starts against the
      deployment configuration, serves discovery, completes a login, and each fail-fast path still
      aborts startup with its message
- [ ] `go test -race ./...` green
- [ ] Recorded either way: whether `e2e_harness_test.go` can now call the wiring function instead
      of rebuilding it, or why not

**Dependencies:** none — but like F-020 it must not land between F-017's verification and the v0.2.0
tag, or the release would ship code the verification never saw.

---

## Feature ideas (backlog)

*Empty.* Everything raised so far is either done or planned above.

<!-- FEATURE-INDEX
next-feature: F-028
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
F-022 Bring the remaining oversized files under the §2 limits (PLANNED)
F-023 CIMD documents rejected over a foreign grant type (DONE)
F-024 Operator view of connected clients, with a kill switch (DONE)
F-025 Name a connection at consent time, and show the client's own name (DONE)
F-026 Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC (DONE)
F-027 Retire the local skills and finish the documentation architecture (DONE)
-->
