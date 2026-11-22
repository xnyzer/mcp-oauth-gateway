---
id: F-006
title: Verify against Claude + security review
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-07-08
depends-on:
superseded-by:
---

# F-006 — Verify against Claude + security review

## History

### F-006a — Local end-to-end verification harness — DONE 2026-07-07

First substep of F-006 (verify against Claude + security review). Prep reordered F-006
security-first (audit gates public exposure, so it runs before the live tests): a → F-006b
(adversarial `/audit-code`) → F-006c (live runbook: real CIMD, passkey in browsers, Claude
web/iOS).

**Problem:** No test booted the *assembled* gateway and drove its real HTTP surface. The
per-package tests cover idp/auth/proxy/keys/cimd in isolation; crucially, `idp_test` installs
a mock auth middleware that auto-authorizes and never mounts the proxy — so real password
login gating the authorize flow, and an idp-minted token being accepted by the proxy and
forwarded upstream, were **untested end to end**.

**Idea:** An in-process black-box harness that assembles the gateway exactly as `Run()` mounts
it (session + auth + idp + proxy + real keys + KVS repo on one gin engine) in front of a mock
upstream, wrapped in `httptest`, and drives it over HTTP.

#### What was done
- **New test-only files (`package main`, no production code, no new deps):**
  `e2e_harness_test.go` (gateway builder + helpers: upstream recorder, CIMD stub resolver,
  DCR register, PKCE pair, real login+consent driver, JWKS verifier) and `e2e_test.go` (six
  flow tests).
- **Assembled-gateway coverage (all green):** discovery + self-consistency (PRM / AS-metadata
  / OIDC mirror / JWKS, `code_challenge_methods=[S256]`, RFC 9207 advertised, active kid in
  JWKS); DCR register → **real password login + consent** → authorize; PKCE/S256 authorize →
  token; token verified against the **published JWKS**; audience/issuer/`jti`/`client_id`
  claims; RFC 9207 `iss` in the redirect; proxied `/mcp` call returning 200 with **credential
  injection** (upstream sees the injected bearer, never the client token); fail-closed
  negatives — missing (→ 401 + `WWW-Authenticate` pointing at PRM), tampered, replayed code
  (`invalid_grant`), and **revoked** (RFC 7009 → 401 via the proxy's `TokenActive` hook);
  rate-limit 429 + `temporarily_unavailable`; **key-rotation continuity** (`keys.Rotate`, then
  the pre-rotation token still verifies via the retiring key and both kids stay in JWKS);
  reserved-namespace path → 404 (never proxied).
- **Public/confidential and CIMD/DCR both exercised:** confidential client via
  `client_secret_basic`/`_post` + Basic-auth `/revoke`; public client via an **injected CIMD
  resolver stub** (the CIMD URL becomes the `client_id` claim) plus a PKCE-downgrade rejection.

#### Decisions / deliberate coverage boundaries
- **CIMD network/SSRF layer stays in `pkg/cimd` units:** the resolver's private-host bypass is
  intentionally unexported ("never exposed via Config"), so a cross-package harness cannot
  drive real localhost CIMD fetches. The happy path here uses a resolver stub (same shape the
  gateway sees for a resolved client); real CIMD over the wire → F-006c live.
- **Expired-but-validly-signed token** cannot be minted black-box (needs the server key) →
  covered in `pkg/proxy` units (`proxy_test.go` exp + clock-skew leeway). The harness covers
  the black-box-mintable negatives (missing/tampered/replayed/revoked).
- **In-process over subprocess:** `Run()` is one ~600-line function that binds ports and only
  exits on SIGINT; the harness composes the same real constructors/mounting instead, giving a
  fast, race-clean, CI-runnable test without port/lifecycle flakiness. (`Run`'s length is an
  audit item for F-006b, not fixed here — refactoring the security-critical assembly right
  before the audit was deliberately avoided.)

**Verification:** `go test ./...` green (all 11 packages), `gofmt`/`go vet ./...` clean,
`go test -race` clean. Six new tests: discovery/self-consistency, auth-code+proxy+revocation
(+4 negative subtests), public-client PKCE via CIMD (+PKCE-required subtest), rate-limit,
key-rotation continuity, reserved-namespace-not-proxied.

**Files changed:** new `e2e_harness_test.go`, `e2e_test.go`; edited `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` (bookkeeping).

### F-006b — Security review (adversarial `/audit-code`) + inline fixes — DONE 2026-07-07

Second substep of F-006. Prep ordered it security-first: it gates public exposure, so it runs
before F-006c (live verification).

#### Audit
Ran an adversarial full audit via four parallel area agents (auth/login/consent ·
idp/PKCE/DCR/CIMD · keys/JWKS/proxy · config/deploy/deps); **every finding was then re-verified
by the main loop against the actual code path** before reporting. Result in `AUDIT-RESULTS.md`
(gitignored, regenerated): **0 critical, 1 high, 9 medium, 19 low**, no committed secrets, no
fail-open/auth-bypass/token-leak, crypto vetted-library only. Verified-clean positives: aud/iss
binding, RFC 8707/9207, S256-only, no implicit/ROPC grants, kid/alg confusion closed, atomic
crash-safe key rotation, credential injection never leaks the upstream secret, JWKS public-only,
deps pinned & permissive.

Adversarial verification corrected one agent finding: the reported "X-Forwarded-For spoof"
(claimed MEDIUM) is actually LOW — Go's `ReverseProxy` already strips
`Forwarded`/`X-Forwarded-For`/`-Host`/`-Proto` before `Rewrite`, so only `X-Forwarded-Port` was
spoofable.

#### Fixes (user chose the "security batch"; each with a regression test)
- **H1 — consent screen (SPEC §1.5):** `handleAuthorizationReturnForm` now renders the client
  identity (`client_id`), redirect target and requested scopes via an auto-escaping
  `html/template`, instead of a bare "Authorize" button. Closes an operator-phishing → token-
  minting path (a logged-in operator could otherwise unknowingly authorize any attacker-hosted
  CIMD client).
- **M1 — CIMD SSRF denylist (SPEC §1.3.2):** `isDisallowedIP` rewritten on `net/netip` to reject
  all non-public ranges the `net.IP` predicates miss — CGNAT `100.64.0.0/10` (incl. Alibaba
  metadata `100.100.100.200`), `192.0.0.0/24`, TEST-NETs, `198.18.0.0/15`, `240.0.0.0/4`,
  broadcast, IPv6 doc, and NAT64 `64:ff9b::/96` — plus IPv4-mapped-IPv6 normalisation; unparseable
  → deny.
- **M2 — `/revoke` fail-closed (SPEC §1.9):** `handleRevoke` now inspects the fosite error and
  writes `503` on a 5xx store failure instead of letting `WriteRevocationResponse` return a
  misleading `200` (which would leave a "revoked" token live).
- **M3 (→LOW) — X-Forwarded-* hygiene:** the transparent backend now explicitly drops all four
  `X-Forwarded-*` headers in the untrusted-peer branch (closing the `X-Forwarded-Port` gap and
  making the "empty `TRUSTED_PROXIES` = nothing trusted" contract explicit).
- **M4 — CIMD DoS bounds:** the resolver cache is now capped (`maxCacheEntries`, expired-purge +
  arbitrary eviction) so unique-client-ID floods can't exhaust memory; and `/.idp/auth` gained a
  per-IP rate limit — **new `RATE_LIMIT_AUTHORIZE`** (flag/env, default `60/m`) wired through
  `main.go` → `mcp-proxy` Config (validated, swept) → `idp` Config → the authorize route.
- **M5 — lockout DoS (`pkg/ratelimit/lockout.go`):** `Fail` now arms the window only on the
  threshold-crossing transition (was: every failure past threshold re-extended it) and resets a
  streak whose window has elapsed — so a remote attacker can no longer keep the sole operator
  permanently locked out with one wrong password per window.
- **M6 — internal-error disclosure (SR-8/§6):** `auth.renderError` logs the cause server-side and
  renders a fixed generic message; the eleven idp `server_error` responses drop the raw
  `err.Error()` description, and the register JSON-bind error returns a generic description.

#### Triage of the rest
Deployment/config mediums **M7–M10** (http-issuer warning + Secure flag, bare-IP
`TRUSTED_PROXIES` startup crash, Docker root/interpreters/floating tags, golangci-lint) → folded
into **F-007** (release hygiene). All 19 lows → new backlog task **F-012**.

#### Verification
`go test ./...` green (all 11 packages), `gofmt`/`go vet ./...` clean, `go test -race` clean on
the touched packages + the assembled e2e. New/updated tests: lockout re-arm regression;
untrusted X-Forwarded-Port strip + trusted-preserve; `isDisallowedIP` reserved-range matrix;
CIMD cache-bound; revoke-503 via a failing-store wrapper; register-malformed-JSON no-leak;
consent-shows-client-identity+scopes; authorize-endpoint 429; `RATE_LIMIT_AUTHORIZE` config
wiring (defaults + env).

**Files changed:** `pkg/idp/idp.go` (+`idp_test.go`), `pkg/cimd/resolver.go` (+`resolver_test.go`),
`pkg/ratelimit/lockout.go` (+`ratelimit_test.go`), `pkg/backend/transparent.go`
(+`transparent_test.go`), `pkg/auth/auth.go`, `pkg/mcp-proxy/main.go`, `main.go`
(+`main_test.go`), `SPEC.md`, `AUDIT-RESULTS.md` (gitignored); bookkeeping in `PROGRESS.md` /
`PROGRESS-ARCHIVE.md`.

### F-006c1 — Deploy + server-side/tooling verification — DONE 2026-07-08

First phase of F-006c (live verification). Deployed the gateway to the operator's environment and
verified the whole public path end to end before involving Claude.

#### Target topology (details kept in `private/`, gitignored — GR-5)
Internet → operator's public IP (router port-forward) → **zoraxy** reverse proxy (terminates
publicly-trusted TLS for the connector hostname) → **gateway** in a container on the target host
`:8080` → **upstream MCP = a live Graphiti "Agent Memory" server** (streamable-HTTP, bearer-auth,
itself behind Caddy → graphiti-mcp → neo4j on a separate host).

#### Pre-deploy de-risking (local, no public exposure)
- Probed the upstream directly: MCP `initialize` at `/mcp` returns `serverInfo` (streamable-HTTP,
  `Mcp-Session-Id`); root `404`s → so **`PROXY_TARGET` is host-only** (the transparent backend
  joins the inbound `/mcp` onto the target; a target ending in `/mcp` would double it). Verified the
  join behaviour against `httputil` `rewriteRequestURL`.
- **Local dry-run** of the *real binary* against the live upstream, driving the full OAuth flow by
  curl (discovery → DCR → real password login + consent → token → proxied MCP `initialize`): the
  whole chain worked and reached Graphiti with the injected credential. (An initial timeout was a
  red herring — the tool sandbox blocks the Go process's socket to a LAN IP while allowing curl;
  re-running unsandboxed passed. A local Python SSE upstream confirmed the gateway proxies+streams
  SSE correctly and forwards a clean request.)

#### Deploy
Minimal **non-root** container (static `linux/amd64` binary on `debian:bookworm-slim` + ca-certs,
no interpreters — sidesteps the M9 heavy release image), `user: 1000:1000`, bind-mounted data dir,
`env_file` for secrets, `unless-stopped`. Config: `EXTERNAL_URL=https://<host>`, `NO_AUTO_TLS=true`,
`LISTEN=:8080`, `TRUSTED_PROXIES=<zoraxy-ip>/32`, `PROXY_TARGET=http://<upstream-host>:<port>`,
`PROXY_BEARER_TOKEN`, `PASSWORD_HASH`, `DATA_PATH=/data`.

#### Three real deploy gotchas surfaced + handled
1. **Bare-IP `TRUSTED_PROXIES` aborts startup** (`netip.ParsePrefix: no '/'`) — this is audit
   finding **M8**, hit live. Workaround `/32`; the normalization fix stays in F-007.
2. **`NO_AUTO_TLS=true` required** — an `https` non-loopback `EXTERNAL_URL` otherwise triggers the
   gateway's own ACME and it refuses to start (TLS is terminated by zoraxy).
3. **Docker Compose interpolates `env_file` values** → the bcrypt `$` was eaten (hash length 52,
   login would fail); escaped as `$$`, verified the in-container hash is 60 chars.

#### Live verification (through the public URL)
Discovery PRM/AS/JWKS `200` (was `521` with the slot empty); `POST /mcp` no-token → `401` +
`WWW-Authenticate`; `TRUSTED_PROXIES` honoured (client IP resolved as the proxy). Full public
OAuth round-trip (via a throwaway operator password injected only for the test, then removed and
verified absent): DCR → login → consent → token → **proxied MCP `initialize` returned
`"Graphiti Agent Memory"`** — credential injection + SSE streaming confirmed end to end through
zoraxy. Final state: container up, non-root, hash-only login (`PASSWORD` unset, hash intact).

**Files:** new `docs/VERIFICATION.md` (generic runbook — no real IPs/domains/tokens); deploy bundle
in `private/mcp-gateway/` (gitignored); `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping.

**Note:** F-006c2 (Claude web) and the Claude-iOS half of F-006c3 were confirmed the same day —
Claude web + iOS both connect via real CIMD and read/search/write against Graphiti. Remaining open:
passkey enrolment (desktop + iOS) and the tampered/revoked live negatives.

### F-006c — Live client verification — DONE 2026-07-08

Second/third phases of F-006c (after F-006c1's deploy). Executed by the operator against the live
deployment; Claude assisted and verified server-side.

- **Claude web connector (F-006c2):** added the gateway as a custom connector; the full OAuth
  flow completed via **real CIMD** (the path F-006a could only stub), and Claude successfully
  **read, searched and wrote** to the live Graphiti upstream through the gateway.
- **Claude iOS (F-006c3):** connects end to end directly in the app; same read/search/write.
- **Passkey / WebAuthn:** enrolled via the session-gated `/.auth/settings` and verified login in
  **Safari (desktop)** and **iOS** (iCloud-Keychain passkey, synced across both). Chrome skipped —
  operator's choice (Apple ecosystem). The operator then **disabled the password fallback**; the
  login page still shows the password field and returns the uniform "invalid password" (SR-6, no
  enumeration — intended), passkey is the sole login, and the env `PASSWORD_HASH` remains as the
  lockout rescue.
- **Live negatives:** no-token / garbage bearer / fake-JWT → `401` (+ `WWW-Authenticate` pointing
  at PRM); reserved `/.idp/*` → `404` (never proxied); `/.idp/revoke` without client auth → `400`.
  Revoked-token→`401` was not scriptable live once password login was off (passkey can't be driven
  by curl) — that exact path is covered by the F-006a assembled e2e.

**Behaviour clarified (not bugs):** browsing the root `https://…/` returns `{"error":"unauthorized"}`
because `/` is the Bearer-protected MCP surface (only Claude carries a token); a direct operator
login redirects there for lack of a dashboard, but the login itself succeeds and Claude's flow
redirects to its own callback instead. No committed code changed in this phase.

### F-006 — Verify against Claude + security review — DONE 2026-07-08 (parent task)

Completed via **F-006a** (assembled-gateway `httptest` e2e harness — the first test to drive an
idp-minted token through the proxy and to exercise the real login), **F-006b** (adversarial
four-agent `/audit-code` with self-verification — 0 critical, 1 high, 9 medium, 19 low — then the
user-chosen security-batch fixes H1/M1–M6 inline, deployment mediums → F-007, lows → F-012), and
**F-006c** (live deploy behind the operator's reverse proxy + end-to-end verification against
**Claude web and iOS** against a live Graphiti upstream, with passkey login).

The gateway is now **running in production and used by Claude on web + iOS**, which is the
project's original goal. Two audit findings were additionally confirmed *live* during the deploy
(M8 bare-IP `TRUSTED_PROXIES` crash; the http-issuer/ACME interaction handled via `NO_AUTO_TLS`).
Remaining before a tagged public release: **F-007** (release hygiene — docs, SemVer, golangci-lint,
the real M7–M10 deployment fixes, and the 2026-07-28 RC re-verify) and the **F-012** backlog.
