---
id: F-005
title: Implement on the chosen base (sigbit fork)
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-07-06
depends-on:
superseded-by:
---

# F-005 — Implement on the chosen base (sigbit fork)

## History

### F-005a — Discovery & 401 surface (client-compat quick wins) — DONE 2026-07-06

First substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **Enabling refactor:** `mcpproxy.Run` (34 positional params), `proxy.NewProxyRouter` (8) and
  `idp.NewIDPRouter` (6) now take config structs (`mcpproxy.Config`, `proxy.Config`,
  `idp.Config`) per CODING-STANDARDS §3 — every later F-005 substep adds options without
  signature churn. All test literals/mocks simplified accordingly.
- **Issuer normalization (§0):** `EXTERNAL_URL` is validated at startup — absolute, http(s),
  no path/query/fragment — and normalized **without trailing slash**; single source for AS
  metadata `issuer`, PRM `resource`, JWT `iss`/`aud` comparison, and the RFC 9207 `iss`.
  `proxy.NewProxyRouter` re-normalizes defensively.
- **PRM complete (§1.1):** added `jwks_uri`, `bearer_methods_supported: ["header"]`,
  `scopes_supported: []`, `resource_name`.
- **AS metadata complete (§1.2):** added `jwks_uri`, `introspection_endpoint`,
  `authorization_response_iss_parameter_supported: true`; optional **OIDC Discovery mirror**
  (`OIDC_DISCOVERY_MIRROR`, default false) serves the same document under
  `/.well-known/openid-configuration`. `revocation_endpoint` deliberately deferred to F-005b
  (metadata must not advertise a 404).
- **`WWW-Authenticate` on the proxy 401 (§1.11.2):** `Bearer resource_metadata="<PRM URL>"`;
  with a presented-but-invalid token additionally `error="invalid_token"` (RFC 6750 §3 —
  no error attribute when no token was sent).
- **RFC 9207 `iss` (§1.5):** success via `AuthorizeResponder.AddParameter`; error redirects
  via an `issRedirectWriter` wrapper around fosite's `WriteAuthorizeError` (fosite v0.49 has
  no native RFC 9207 support). All 7 error call sites routed through the wrapper.
- **`CLOCK_SKEW` (§1.11.1):** `jwt.WithLeeway` in proxy token validation; new duration
  flag/env (default 30 s, validated 0–5 m fail-fast; malformed env value panics at startup).

**Verification:** gofmt/vet clean, build green, all 8 packages green. New tests:
metadata field-completeness (AS + PRM), OIDC-mirror on/off, 401 challenge (missing / malformed
/ expired token variants), clock-skew leeway (0 s rejects, 30 s accepts a just-expired token),
issuer normalization negative cases (path/query/relative), `iss` asserted in success and error
redirects of the existing flow tests. Live smoke test: gateway started with a trailing-slash
`EXTERNAL_URL` → normalized issuer in metadata, mirror 200, both 401 challenge variants
correct.

**Files changed:** `main.go`, `main_test.go`, `pkg/mcp-proxy/main.go`,
`pkg/mcp-proxy/main_test.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`,
`pkg/proxy/proxy_test.go`, `SPEC.md` (Delta notes updated to reflect implemented state)
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005b — Token binding & lifecycle — DONE 2026-07-06

Second substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **Upstream bug fixed:** the inherited `RevokeRefreshToken`/`RevokeAccessToken` deleted by
  request ID *used as a storage key*, while records are keyed by signature — revocation was a
  silent no-op (never noticed upstream because no `/revoke` endpoint existed). Both backends
  now delete **all records of the grant by request ID** (KVS: prefix scan in one bbolt
  transaction; SQL: new indexed `request_id` column populated at create). fosite's RFC 7009
  handler then provides the refresh→access cascade for free.
- **Design deviation (documented in SPEC §2.1/§2.4):** the planned revoked-`jti` deny-list
  was replaced by a **record-presence check** — the proxy validates statelessly, then requires
  the token's server-side record to exist (`TokenActive` callback in `proxy.Config`; lookup by
  the JWT's signature segment). Missing record → 401; store error → **503 fail-closed**.
  Same guarantees, no extra entity. `jti` stays as a claim, regenerated per issued token
  (fresh JTI in `Session.Clone()` covers refresh-issued tokens).
- **RFC 8707 (§1.5/§1.6):** `resource` validated at authorize and token endpoints — only the
  issuer is a valid resource; other values → `invalid_target` (error redirect carries `iss`).
  Granted audience already flowed into `aud` via fosite's claims merging.
- **Claims (§1.7):** `jti`, `client_id` (session extra), space-separated `scope`
  (`JWTScopeClaimKey: JWTScopeFieldString`). Side-fix: `exp` previously followed fosite's
  hardcoded 24 h lifespan (the +1 h in `NewJWTSessionWithKey` was dead code, overwritten by
  fosite's `With()`); it now follows `ACCESS_TOKEN_TTL`.
- **`/.idp/revoke` (§1.9):** wired via fosite's `NewRevocationRequest` (client auth, hint
  handling, no token-existence oracle — unknown tokens yield 200). Metadata advertises
  `revocation_endpoint`; `grant_types_supported` reflects a disabled refresh grant.
- **TTL config (§3.2):** `ACCESS_TOKEN_TTL` (1 m–24 h, default 1 h), `AUTH_CODE_TTL`
  (30 s–1 h, default 10 m), `REFRESH_TOKEN_TTL` (0 disables the refresh grant incl. its
  fosite factory; else 1 h–8760 h, default 720 h) — flags + env, fail-fast validated.
- **Sweeper + schema version (§2.1/§2.5):** 5-minute GC goroutine deletes session records
  past TTL+skew (both backends; SQLite compares via `julianday()` because the driver stores
  times as strings with mixed UTC offsets); `EnsureSchemaVersion` marker with fail-fast on
  downgrade, checked at startup.

**Verification:** gofmt/vet clean, all 8 packages green. New tests: `invalid_target` negative
tests at both endpoints; revocation suite (record gone, introspection inactive, refresh
cascade, no oracle, client-auth required); proxy `TokenActive` matrix (active/nil/revoked→401/
store-error→503); TTL fail-fast matrix; revoke-by-request-ID, sweeper, and schema-version
tests for **both** storage backends; `jti`/`client_id` claim assertions. Live smoke test:
`revocation_endpoint` advertised, `/revoke` rejects unauthenticated calls,
`ACCESS_TOKEN_TTL=10s` aborts startup with a clear message.

**Files changed:** `main.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`,
`pkg/proxy/proxy_test.go`, `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`,
`pkg/repository/{interface,kvs,sql}.go`, new `pkg/repository/maintenance_test.go`,
`pkg/utils/rand.go`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005c — CIMD + DCR hardening (SR-5) — DONE 2026-07-06

Third substep of F-005; completes the CIMD-first registration model decided in F-003.

**What was done** (SPEC references in parentheses):
- **CIMD resolver** (new `pkg/cimd`, §1.3): HTTPS-URL client IDs resolved with all limits —
  5 s fetch timeout, 64 KiB size cap, no redirects, no userinfo, port 443 only. **SSRF guards
  run at dial time** (`net.Dialer.Control`), so DNS rebinding cannot bypass them; rejected:
  loopback, RFC 1918/ULA, link-local (incl. cloud metadata services), multicast, unspecified.
  Document validation: `client_id` must equal the fetched URL, redirect URIs follow the
  RFC 8252 scheme rules, `token_endpoint_auth_method` must be `none` (absent is treated as
  `none` — decision: common in real CIMD documents; explicit non-`none` is rejected).
  Positive cache (default 1 h) and negative cache (60 s).
- **Integration as fosite client source** (`clientSource` in `pkg/idp`): `https://` client
  IDs resolve via CIMD, everything else via the DCR store — one hook covers the authorize
  and token endpoints. Resolution failures → `invalid_client`; detail only in logs (SR-8).
  `idp.Config.CIMDResolver` is an interface for testability (stub in idp tests; real HTTP
  resolution tested in `pkg/cimd` with in-package-only test knobs).
- **DCR hardening (§1.4)**: registration TTL (default 30 d) **refreshed on token issuance**
  (`TouchClient`; active clients never expire mid-use); expired registrations treated as
  absent on lookup (fail-closed, no reliance on the sweeper); client cap → `503
  temporarily_unavailable` (never eviction); redirect-URI scheme validation (shared
  `cimd.ValidateRedirectURI`), grant/response-type whitelist, auth-method validation;
  `client_secret_expires_at` in the response; `DCR_ENABLED=false` removes the endpoint and
  the metadata entry. Sweeper extended with `DeleteExpiredClients`.
- **Security finding from the smoke test, fixed immediately:** with DCR disabled the
  unregistered `/.idp/register` path fell through to the catch-all proxy — with a valid
  bearer it would have been **forwarded upstream**. The `/.idp/`, `/.auth/`, and
  `/.well-known/` namespaces are now **reserved**: unmatched paths inside them return `404`
  and never reach the upstream (SPEC §0 updated, regression test added).
- **Storage layer:** `models.Client` gained `CreatedAt`/`ExpiresAt`;
  `RegisterClient(…, expiresAt)`, `TouchClient`, `CountClients`, `DeleteExpiredClients` in
  both backends; dead `marshalClient`/`unmarshalClient` helpers removed.
- **Config (§3.2):** `CIMD_ENABLED` (default true), `CIMD_FETCH_TIMEOUT`, `CIMD_MAX_SIZE`,
  `CIMD_CACHE_TTL`, `DCR_ENABLED` (default true), `DCR_CLIENT_TTL`, `DCR_MAX_CLIENTS` —
  fail-fast validated; disabling both mechanisms aborts startup.

**Verification:** gofmt/vet clean, all 9 packages green. New tests: SSRF matrix (8 cases on
the production config) + document-validation matrix + oversize/redirect/cache tests in
`pkg/cimd`; full CIMD authorize+token round-trip with PKCE incl. `client_id` claim; DCR
cap/TTL/disabled/metadata negatives; expired-client rejection; reserved-namespace regression
test; client lifecycle for both storage backends. Live smoke test: both-mechanisms-disabled
fails fast, DCR-off metadata omits `registration_endpoint`, reserved namespaces 404, `/mcp`
still 401.

**Files changed:** new `pkg/cimd/{resolver,resolver_test}.go`; edited `main.go`,
`pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`, `pkg/proxy/proxy_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `pkg/models/models.go`,
`pkg/repository/{interface,kvs,sql}.go`, `pkg/repository/maintenance_test.go`, `SPEC.md`
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005d — Key management — DONE 2026-07-06

Fourth substep of F-005 (implement the SPEC.md contracts on the fork).

**What was done** (SPEC references in parentheses):
- **New `pkg/keys` (§2.2):** `Manager` owns the key set — `keys/<kid>.pem` (PKCS#8, 0600, dir
  0700) plus atomic `keys/manifest.json` (temp file + fsync + rename; crash mid-rotation
  leaves the old manifest intact). Startup fails fast on a manifest referencing a
  missing/corrupt key file or a fingerprint/kid mismatch. Manifest gained `active_since`
  (drives the rotation-interval check); `kid` stays the fork's existing scheme (hex
  SHA-256-prefix of the PKIX public key) instead of the drafted base64url form, so
  outstanding tokens keep verifying across the migration — SPEC §2.2 updated accordingly.
- **Legacy migration (§2.2):** pre-F-005d `data/private_key.pem` is adopted as the active key
  on first start (kid preserved, original file left in place); `JWT_PRIVATE_KEY` env keeps
  working as a **static mode** (no directory, rotation disabled with a startup warning,
  `KEY_ALG` must match the key type).
- **Rotation (§2.3):** interval-triggered (`KEY_ROTATION_INTERVAL`, default 90 d, `0`
  disables, else ≥ 1h) — checked at startup and by the existing 5-minute sweeper; a `KEY_ALG`
  change also rotates at startup. The previous key retires with
  `not_after = now + ACCESS_TOKEN_TTL + 2×CLOCK_SKEW`; sweeping removes it from the manifest
  **before** deleting its file (crash-safe order). New tokens sign only with the active key.
- **ES256 shipped (decision resolved):** fosite v0.49 natively signs/verifies
  `*ecdsa.PrivateKey` (ES256), so both `KEY_ALG=RS256` (RSA-2048) and `ES256` (P-256) are
  supported — no follow-up needed.
- **Multi-key verification end to end (§2.3.3):** the key insight was that fosite's
  introspection validates JWTs through its `jwt.Signer` — a multi-key JWKS alone would have
  broken introspection after rotation. `keys.FositeSigner` implements fosite's `jwt.Signer`:
  signs with the active key (kid header injected **at signing time** — sessions are created at
  authorize time and cloned for refresh, so a session-borne kid could go stale), verifies via
  kid lookup against active + retiring with an alg-match guard (no algorithm confusion).
  `proxy.Config.PublicKey` (single RSA key) was replaced by a
  `VerificationKey func(kid) (pub, alg, ok)` hook backed by the manager; unknown/missing kid
  or alg mismatch → 401. `idp.Config.PrivKey` became `Keys *keys.Manager`.
- **JWKS (§1.8):** serves active + retiring keys (EC params per RFC 7518 §6.2.1, fixed-length
  coordinates) with `Cache-Control: max-age=300`.
- **Config (§3.2):** `KEY_ALG` / `KEY_ROTATION_INTERVAL` flags + env, fail-fast validated.
- **Cleanup:** key helpers moved out of `pkg/utils` (`LoadOrGeneratePrivateKey`,
  `SavePrivateKey`, `LoadPrivateKey`, `PrivateKeyFromPEM`, `GenerateKeyID` deleted; secret
  helpers stayed); `NewJWTSessionWithKey` became key-free `NewJWTSession`.

**Verification:** gofmt/vet clean, all 10 packages green. New tests: `pkg/keys` suite
(first-run init, ES256 init, legacy adoption, missing-key/kid-mismatch fail-fast, rotation
persistence, interval/alg-switch triggers, retiring sweep incl. file deletion, rotation
failure leaves manifest intact via read-only dir, static mode, ParseAlg); signer suite
(active-kid injection, validate-across-rotation, reject-after-sweep, ES256 round-trip, forged
alg/kid mismatch); idp integration (`TestKeyRotationKeepsOldTokensValid`: pre-rotation token
introspects active after rotation, JWKS serves both kids, new token carries new kid;
`TestES256TokenIssuance`); proxy multi-key matrix (RS/ES accept, unknown/missing kid,
alg-mismatch, wrong-key 401s); config validation + flag default/env tests. Live smoke test
with the built binary: legacy key adopted with identical kid, `KEY_ALG=ES256` restart rotated
at startup (JWKS = EC active + RSA retiring, correct `not_after`), full password+consent OAuth
flow issued an ES256 token that proxied upstream (200; 401 without token), fail-fast on bad
`KEY_ROTATION_INTERVAL`/`KEY_ALG`, static-mode warning + single-key JWKS + alg-mismatch
abort.

**Files changed:** new `pkg/keys/{keys,manager,manifest,signer}.go` +
`pkg/keys/{manager_test,signer_test}.go`; edited `main.go`, `main_test.go`, `pkg/idp/idp.go`,
`pkg/idp/idp_test.go`, `pkg/proxy/proxy.go`, `pkg/proxy/proxy_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `pkg/utils/{keys,rand}.go`,
`pkg/utils/keys_test.go`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005e1 — User model + passkey/WebAuthn — DONE 2026-07-06

Fifth substep of F-005; first half of the F-005e split (prep decision 2026-07-06: env config
stays the authoritative password source — **Variante A**, user-approved after a pros/cons
walkthrough; B (hash migrated into the user record) was rejected as an operator trap: env
rotation would silently stop working, and it needs a password-change UI that is out of scope).

**What was done** (SPEC references in parentheses):
- **Operator account (FR-4, §1.12):** single persisted `models.User`, bootstrapped on the
  first successful password login; generated 64-char ID doubles as JWT `sub` (§1.7) and
  WebAuthn user handle. The record stores identity, passkeys, and the
  `password_login_disabled` flag — **never a password hash** (Variante A).
- **Storage (§2.1):** `UserStorage` interface on the repository (Get/Create/UpdateUser +
  Add/List/Update/DeleteWebAuthnCredential) implemented for **both backends** (bbolt:
  `user-record` fixed key + `webauthn_credential-` prefix; SQLite: `user_records` +
  `webauthn_credential_records` via GORM auto-migration). Credentials store the marshaled
  go-webauthn credential as JSON so models stays agnostic of the library type.
- **Passkey/WebAuthn (§1.12):** `github.com/go-webauthn/webauthn` v0.17.4 (BSD-3) as the
  vetted ceremony library (SR-1). Public assertion endpoints
  `/.auth/webauthn/login/begin|finish`; session-gated attestation endpoints
  `/.auth/webauthn/register/begin|finish` (existing credentials excluded). RP ID/origin
  derived from the normalized issuer. Ceremony state lives in the cookie session, consumed
  on finish (one finish per begin — replay tested). Fail-closed: clone warning (sign-count
  regression) and a failed sign-count persist both deny the login.
- **Settings page (§1.12):** `/.auth/settings` (+ `settings/password`,
  `settings/credentials/delete` form posts, `SameSite=Lax` CSRF mitigation) — passkey
  list/enroll/delete, password-fallback toggle. Feedback messages are fixed server-side
  texts selected by `?msg=` code (no reflected input). Settings/enrollment additionally
  require the session to belong to the persisted user — OIDC-provider sessions get 403.
- **Fallback rule (§1.12):** disabling the password requires ≥1 passkey; the flag is only
  honoured while a passkey exists — deleting the last one re-activates the password login
  (lockout rescue). Disabled-password logins answer exactly like wrong-password ones
  (uniform body, bcrypt always runs first — no state enumeration, SR-6).
- **Startup check (§3.1):** fail-fast when neither password, OIDC, nor an enrolled passkey
  can log the operator in.
- **Security bug found by test, fixed:** the session-gate middleware (`RequireAuth`)
  redirected unauthenticated requests **without aborting the handler chain** — on bodyless
  (POST) redirects gin's deferred WriteHeader let the downstream handler run and even
  override the 302. Inherited from upstream; now aborts (fail-closed, SR-3).
- **Enabling refactor:** `auth.NewAuthRouter` takes a `Config` struct (CODING-STANDARDS §3);
  templates gained `settings.html` + a shared `webauthn_script.html` (base64url/ArrayBuffer
  helpers + ceremony JS in `login.html`/`settings.html`).
- **Deps:** `go-webauthn/webauthn` v0.17.4 (BSD-3) + transitives (BSD/MIT/Apache-2.0, all
  permissive, verified); test-only `descope/virtualwebauthn` v1.0.5 (MIT).

**Verification:** gofmt/vet clean, all 10 packages green. New tests: full enrollment+login
round-trip with a **virtual authenticator** (bootstrap → enroll → fresh-browser passkey
login → settings reachable → LastUsedAt stamped → replay denied); fallback semantics
(disable refused without passkey, uniform disabled-vs-wrong response, passkey-only login,
auto re-enable after deleting the last passkey); unavailable-before-enrollment; session
gating (anonymous → redirect; foreign/OIDC session → 403); user+credential lifecycle on
both storage backends; auth-backend fail-fast. Live smoke test with the built binary:
fail-fast without backend, bootstrap on first login ("Signed in as admin", no second
bootstrap after restart), settings gated, register/begin returns correct RP options, OAuth
flow issues `sub` = 64-char user ID (not `password_user`), proxied request 200.

**Files changed:** new `pkg/auth/{webauthn,settings}.go`, `pkg/auth/webauthn_test.go`,
`pkg/auth/templates/{settings,webauthn_script}.html`, `pkg/repository/users_test.go`;
edited `pkg/auth/auth.go`, `pkg/auth/auth_test.go`, `pkg/auth/templates/login.html`,
`pkg/models/models.go`, `pkg/repository/{interface,kvs,sql}.go`, `pkg/mcp-proxy/main.go`,
`pkg/mcp-proxy/main_test.go`, `pkg/idp/idp_test.go`, `pkg/utils/rand.go`, `go.mod`,
`go.sum`, `SPEC.md` (+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005e2 — Rate limits, lockout & auth events — DONE 2026-07-06

Sixth and final substep of F-005; second half of the F-005e split.

**What was done** (SPEC references in parentheses):
- **New `pkg/ratelimit` (SR-5/SR-6, §3.2):** `ParseLimit` for `N/s|m|h` expressions (`0`
  disables, fail-fast otherwise); keyed per-client-IP token buckets on
  `golang.org/x/time/rate` (burst = full window); a gin `Middleware` answering `429` +
  `temporarily_unavailable` and emitting the `rate_limited` event; and a per-account
  `Lockout` (consecutive-failure counter, lock for `LOGIN_LOCKOUT_DURATION`, reset on
  success). Disabled limits/lockouts are typed nils — call sites need no special-casing.
  All state in-memory by design (GR-3, single-instance).
- **New `pkg/authevent` (SR-8, §3.3):** one fixed `"auth event"` log message with a generic
  `event` field (GR-4) + non-secret context. Events wired: `login_ok`/`login_fail`
  (password + passkey, `method` field) in `pkg/auth`; `token_issued` (client_id,
  grant_types) and `register` (client_id) in `pkg/idp`; `revoked` per accepted revocation
  request (RFC 7009 hides token existence, so the event does too); `rate_limited`
  (endpoint) in the middleware.
- **Login hardening (§1.12):** rate limit applied to the password login **and** the passkey
  ceremony endpoints; lockout counts consecutive failed password logins only (passkey
  assertions are cryptographic, not guessable — exempt, documented). A locked account
  rejects even the correct password with a **byte-identical** response to a wrong password
  (SR-6, no lockout oracle); bcrypt always runs first (timing uniformity). The
  disabled-fallback rejection does not count toward the lockout (correct password, not a
  guessing signal).
- **Endpoint wiring:** `TokenRateLimit`/`RegisterRateLimit` handler hooks in `idp.Config`,
  `LoginRateLimit`/`Lockout` in `auth.Config` — routers stay decoupled from the limiter
  types. The 5-minute sweeper also prunes idle rate-limit buckets and expired lockout
  entries.
- **Config (§3.2):** `RATE_LIMIT_REGISTER`/`_TOKEN`/`_LOGIN` (defaults `10/m`/`60/m`/`10/m`),
  `LOGIN_LOCKOUT_THRESHOLD` (default 10; `0` disables) / `LOGIN_LOCKOUT_DURATION` (default
  15m; 1m–24h) — flags + env, fail-fast validated.
- **Dep:** `golang.org/x/time` (BSD-3).

**Verification:** gofmt/vet clean, all 11 packages green. New tests: ParseLimit matrix;
limiter burst/deny/per-key/sweep; lockout threshold/expiry/reset/sweep; middleware 429 +
`rate_limited` event + **TRUSTED_PROXIES client-IP keying** (X-Forwarded-For buckets);
lockout byte-identical uniform response, unlock after duration, streak reset on success;
login rate limit covering the passkey ceremony; register/token 429 matrix with per-endpoint
events; `token_issued`/`register`/`revoked` events; log assertions that no entry carries
passwords, tokens, or client secrets. Live smoke test with the built binary: fail-fast on a
malformed rate limit, `/register` 429 after the bucket, lockout rejects the correct password
uniformly, 429 on the login surface, structured `auth event` JSON lines with correct fields,
no passwords in the log, lockout expiry re-admits, `login_ok` emitted.

**Files changed:** new `pkg/ratelimit/{ratelimit,lockout,middleware,ratelimit_test}.go`,
`pkg/authevent/authevent.go`, `pkg/auth/abuse_test.go`; edited `main.go`, `main_test.go`,
`pkg/auth/{auth,webauthn}.go`, `pkg/idp/idp.go`, `pkg/idp/idp_test.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/main_test.go`, `go.mod`, `go.sum`, `SPEC.md`
(+ `PROGRESS.md` / `PROGRESS-ARCHIVE.md` bookkeeping).

### F-005 — Implement on the chosen base (sigbit fork) — DONE 2026-07-06 (parent task)

Completed via six substeps (full detail in their sections above): **F-005a** discovery & 401
surface, **F-005b** token binding & lifecycle, **F-005c** CIMD + DCR hardening, **F-005d**
key management, **F-005e1** user model + passkey/WebAuthn, **F-005e2** rate limits, lockout
& auth events.

**Original gap list (from the F-001 code review) — all closed:**
- RFC 8707 audience-binding → F-005b
- CIMD client-registration → F-005c
- `WWW-Authenticate` on the `/mcp` 401 → F-005a
- `/revoke` route (RFC 7009) → F-005b (incl. upstream revoke-no-op bugfix)
- Complete PRM/AS-metadata → F-005a/b
- RFC 9207 `iss` → F-005a
- Key management (rotation + ES256) → F-005d
- Self-contained auth (passkey/WebAuthn + user model) → F-005e1, hardened by F-005e2

**Prep decisions (user-approved), all honoured:** passkey bootstrap via password + session-
gated settings page; ES256 shipped (fosite supports it natively); in-memory rate-limit
state; deps `go-webauthn/webauthn` (BSD-3) + `golang.org/x/time` (BSD-3). Two inherited
security bugs found and fixed along the way: revoke-by-signature no-op (F-005b) and the
RequireAuth chain-continuation after redirect (F-005e1). Next: F-006 (verify against Claude
+ security review).
