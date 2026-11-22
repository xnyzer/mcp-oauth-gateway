---
id: F-012
title: Audit low-severity follow-ups (from F-006b)
type: feature
status: DONE
size:
created: 2026-07-07
done: 2026-07-09
depends-on:
superseded-by:
---

# F-012 — Audit low-severity follow-ups (from F-006b)

## History

### F-012a — Fail-fast & crypto/proxy guards — DONE 2026-07-08

First F-012 substep (audit low-severity follow-ups): five independent validation guards from
the F-006b audit lows.

- **Malformed boolean envs abort startup** (`main.go`): `getEnvBoolWithDefault` now accepts
  exactly `true|1|false|0` (words case-insensitive) and panics with a clear message otherwise,
  matching the sibling duration/int parsers — a typo in a security toggle (`DCR_ENABLED`, …)
  can no longer silently disable it. This brings the code in line with the already-normative
  SPEC §3 wording, so no SPEC change was needed.
- **RSA keys below 2048 bits are refused** (`pkg/keys`): `algForKey` checks `N.BitLen()`,
  which covers every ingress path centrally — `JWT_PRIVATE_KEY`, legacy-key adoption, and
  manifest loads all route through `ParsePrivateKeyPEM`/`NewStaticManager`. SPEC §2.2 delta
  noted. **Deployment note (for the F-012e CHANGELOG):** a pre-existing sub-2048 key now
  fails startup (operator-controlled; generated keys were always 2048).
- **`jwt.WithExpirationRequired()`** (`pkg/proxy`): a signed token that omits `exp` no longer
  validates as never-expiring — defence-in-depth; every issued token carries `exp` (§1.7).
- **Redirect-replay body buffering capped at 4 MiB** (`pkg/backend`): named constant
  `maxRedirectReplayBody`; a body over the cap streams through unbuffered via `stitchedBody`
  (buffered prefix + unread remainder, original `Close` preserved) and a 307/308 for it passes
  to the client instead of being followed. **Decision:** fixed constant over a new env var —
  MCP JSON-RPC payloads are orders of magnitude smaller, and the cap only bounds the
  redirect-replay convenience, never the proxy path itself. SPEC §1.11 delta noted.
- **CIMD grant/response-type whitelist** (`pkg/cimd` + `pkg/idp`): new shared
  `IsSupportedGrantType`/`IsSupportedResponseType` (the §1.2 sets) — CIMD documents are now
  validated exactly like DCR registrations (attacker-declared `implicit`/
  `client_credentials`/`token` → `invalid_client`); the duplicate maps in `pkg/idp` were
  replaced by the shared functions (same pattern as `ValidateRedirectURI`). SPEC §1.3 delta
  noted.

Verification: five negative regression tests (bool typos panic; 1024-bit key refused on the
parse and static-manager paths; token without `exp` → 401 without upstream contact; oversized
body → 307 passed through **and** streamed untruncated; CIMD unsupported types →
`invalid_client`); full suite + `-race` green; golangci-lint v2.12.2 (the CI-pinned version)
0 issues; gitleaks over the working tree clean.

**Files:** `main.go` (+tests), `pkg/keys/keys.go` (+new `keys_test.go`), `pkg/proxy/proxy.go`
(+tests), `pkg/backend/transparent.go` (+tests), `pkg/cimd/resolver.go` (+tests),
`pkg/idp/idp.go`, `SPEC.md` (§1.3/§1.11/§2.2 deltas).

### F-012b — Auth-flow hardening — DONE 2026-07-09

Second F-012 substep: six login-path hardening items from the F-006b audit lows, all on
surfaces Claude web/iOS + passkey use live, so the e2e harness had to stay green.

- **`EnforcePKCE: true`** (`pkg/idp`): PKCE is now enforced for **every** client, not only
  public/CIMD ones — confidential DCR clients must send `code_challenge` too. Closes the
  long-standing SPEC §1.5 open delta (the metadata already advertised S256-only). Claude uses
  CIMD/public clients, which were already covered; only confidential DCR clients change.
- **Uniform empty-password** (`pkg/auth`): the empty-password branch that returned a distinct
  "Password is required" body before bcrypt is gone — an empty password now runs the same
  bcrypt comparison and returns the byte-identical uniform "Invalid password" as a wrong one
  (SR-6, no pre-bcrypt oracle), and consequently counts toward the lockout.
- **Constant bcrypt timing** (`pkg/auth`): the comparison loop dropped its early `break`, so
  for a multi-hash `PasswordHashes` config the bcrypt count no longer depends on the match
  index (the in-code uniformity claim now holds; single-hash was already uniform).
- **Dead-branch removal** (`pkg/auth`): the unreachable `if method == "POST"` branch in the
  GET-only `handleLogin` was deleted (POST is wired straight to `handleLoginPost` in
  `SetupRoutes`).
- **Full logout clear** (`pkg/auth`): logout now `session.Clear()` + `Options{MaxAge:-1}`
  instead of deleting only the `authorized` flag — identity, user info, WebAuthn ceremony
  blobs and pending redirect targets are all dropped and the cookie is expired client-side.
- **`redirect_url` same-origin guard** (`pkg/auth`): new pure `safeRedirectTarget` (must start
  with a single `/`, never `//` or `/\`, both scheme-relative in browsers) applied via the
  shared `takeRedirectTarget` at all three login consumers — password login, passkey finish
  (`webauthn.go`), and the OIDC callback. A latent open-redirect invariant closed even though
  only `RequireAuth` writes the value today. SPEC §1.5/§1.12 deltas noted.

**Behaviour-change handling:** `EnforcePKCE: true` broke every confidential-client test that
drove the flow without PKCE. Rather than exempt them, the shared `testAuthFlowWithURL` helper
now appends a shared S256 challenge and the token exchanges send the verifier (idp_test.go);
the four confidential e2e flows (`e2e_test.go`) were threaded through `pkcePair` + a
`code_verifier`, keeping the Claude-representative harness green. A new
`TestConfidentialClientRequiresPKCE` asserts the negative (no `code_challenge` → error, no
code).

Verification: new negatives — confidential-without-PKCE rejected, empty-password response
byte-identical to wrong-password, logout makes the protected route redirect to login again and
expires the cookie, `safeRedirectTarget` table (`//evil`, `/\evil`, `https://evil`, … → `/`);
full suite + `-race` green; golangci-lint v2.12.2 0 issues.

**Files:** `pkg/auth/auth.go`, `pkg/auth/webauthn.go`, `pkg/idp/idp.go`, `SPEC.md` (§1.5/§1.12
deltas); tests `pkg/idp/idp_test.go`, `e2e_test.go`, new `pkg/auth/hardening_test.go`.

### F-012c — Login surface: CSRF tokens + discoverable passkey login — DONE 2026-07-09

Third F-012 substep. Two audit lows deliberately bundled because they touch the same login
templates/JS and the live Claude web/iOS + passkey flows — concentrating the behaviour-change
risk in one verify step.

#### What was done

**① Per-session anti-CSRF token (defence-in-depth on top of `SameSite=Lax`, SPEC §1.12):**
- New `pkg/utils.GenerateCSRFToken()` — 32 bytes `crypto/rand`, hex (stdlib, no new dep).
- New `pkg/auth/csrf.go` (extracted so `auth.go` stays cohesive): `SessionKeyCSRF` lives with
  the other session keys; `CSRFFieldName`/`CSRFHeaderName` consts; `EnsureCSRFToken` (get-or-
  create, stored in the HMAC-signed session); constant-time `validCSRF` (`crypto/subtle`,
  fail-closed — a missing/empty stored token never matches); `RequireCSRF()` gin middleware
  that checks the `X-CSRF-Token` header **first** (so the JSON WebAuthn fetches never trigger
  form-body parsing, which would consume the ceremony request body) and falls back to the
  hidden `csrf_token` form field.
- Middleware wired onto every state-changing POST on the surface: password login, both
  WebAuthn login ceremonies, both WebAuthn register ceremonies, both settings POSTs
  (`auth.go`), and the consent POST `/.idp/auth/:ar_id` (`idp.go`, on top of its existing
  `ar_id` session binding).
- Token minted + persisted in the GET handlers that render forms: `renderLogin` (`auth.go`),
  `handleSettings` (`settings.go`), `handleAuthorizationReturnForm` (`idp.go`).
- Templates deliver it: a `<meta name="csrf-token">` tag + hidden `csrf_token` fields in
  `login.html`/`settings.html` and the consent form (inline template in `idp.go`); a shared
  `csrfHeader()` JS helper in `webauthn_script.html` adds `X-CSRF-Token` to every WebAuthn
  `fetch()`.

**② Discoverable (usernameless) passkey login (SPEC §1.12, `webauthn.go`):**
- `handleWebAuthnLoginBegin` now calls `BeginDiscoverableLogin()` (empty allow-list), so the
  begin response no longer enumerates the operator's credential IDs to an anonymous caller.
- `handleWebAuthnLoginFinish` uses `FinishDiscoverableLogin` with a single-operator
  `DiscoverableUserHandler` that resolves the sole operator account and validates the asserted
  user handle against its ID (go-webauthn additionally enforces credential ownership + a
  non-blank handle — fail-closed). Clone-warning / sign-count-persist denials unchanged.
- Registration raised from `ResidentKeyRequirementPreferred` to `…Required`, so every newly
  enrolled passkey is guaranteed discoverable.

#### Tests

- New `pkg/auth/csrf_test.go` (negatives, acceptance a/b): login POST missing/wrong token →
  `403` (correct token → `302`); session-gated settings POST missing token → `403`; WebAuthn
  login begin missing header → `403`; discoverable begin response omits credential descriptors
  (`allowCredentials`).
- New `TestConsentPostRejectsMissingOrWrongCSRF` in `pkg/idp/idp_test.go`.
- Existing harness threaded through token extraction (acceptance c): `pkg/auth` helpers
  (`passwordLogin`/`enrollPasskey`/`passkeyLogin`/`postLogin`) fetch the token and send it via
  field or header; body-comparison uniformity tests (empty-vs-wrong password, lockout oracle)
  reuse one session so the embedded token is identical; the two discoverable-login tests set
  the virtual authenticator's `Options.UserHandle`; `idp` `testAuthFlowWithURL` + a new
  `postConsent` helper extract the consent token; the root e2e `driveAuthCode`
  (`e2e_harness_test.go`) fetches the login token and the consent token so all five e2e flows
  stay green.

#### Decisions / deviations

- **CSRF applied to the public passkey-login ceremony too** (not only the audit-named
  password/consent/settings/register POSTs): the token is minted on the login-page GET and the
  fetch sends it, so it is free defence-in-depth and keeps every state-changing POST uniform.
- **Handler over library user-lookup:** the discoverable handler loads the single operator
  regardless of the raw credential ID (go-webauthn verifies ownership + signature), matching
  the single-operator model.
- **Live/deploy note (rescue path, captured in the SPEC §1.12 delta; CHANGELOG draft belongs
  to F-012e):** a **non-resident** passkey enrolled before F-012c can no longer complete the
  empty-allow-list login. Synced-keychain (iCloud) passkeys are resident → the live setup is
  expected fine. Rescue (unchanged §1.12 lockout-rescue rule): delete the passkey records in
  the data dir → the password fallback re-activates. No real paths/hosts recorded.
- **No new deps, endpoints, or env vars.** `crypto/rand`, `crypto/subtle` are stdlib.

#### Verification

Full suite + `go test -race ./...` green; `gofmt`/`go vet` clean; golangci-lint v2.12.2 →
0 issues. The assembled-gateway e2e harness (real login + consent + proxied upstream) exercises
the CSRF-guarded flow end to end; the virtual-authenticator round-trip exercises the
discoverable ceremony.

**Files:** `pkg/utils/rand.go`, new `pkg/auth/csrf.go`, `pkg/auth/auth.go`,
`pkg/auth/settings.go`, `pkg/auth/webauthn.go`, `pkg/auth/templates/{login,settings,
webauthn_script}.html`, `pkg/idp/idp.go`, `SPEC.md` (§1.5/§1.12 deltas); tests
`new pkg/auth/csrf_test.go`, `pkg/auth/{webauthn,abuse,hardening}_test.go`,
`pkg/idp/idp_test.go`, `e2e_harness_test.go`.

### F-012d — Persistence hardening — DONE 2026-07-09

Fourth F-012 substep: three persistence-layer audit lows — a TOCTOU-prone DCR cap, missing
SQLite concurrency/durability pragmas, and a session cookie that was only signed (not
encrypted) and shared the raw token secret.

#### What was done

**① DCR registration cap enforced inside the write transaction (SR-5, no TOCTOU):**
- `DynamicClientStorage.RegisterClient` gained a `maxClients int` parameter and a new sentinel
  `repository.ErrClientCapReached` (`interface.go`). `maxClients <= 0` means unlimited.
- bbolt (`kvs.go`): count + insert now run in a single `db.Update` transaction; bbolt allows
  one writer at a time, so the cap check cannot race. New `countNonExpiredClients(bucket, now)`
  helper (also used by `CountClients`, DRY). A re-registration of an existing key replaces in
  place and does not count against the cap.
- GORM/SQLite (`sql.go`): count + insert wrapped in `db.Transaction`; new
  `countNonExpiredClientRecords(db, now)` helper (also used by `CountClients`). Same
  re-registration semantics.
- `idp.go handleRegister`: the pre-flight `CountClients` check (the TOCTOU window) is gone; the
  cap is passed to `RegisterClient` and `ErrClientCapReached` maps to `503`
  `temporarily_unavailable`.
- `CountClients` is **kept** on the interface (still used by the maintenance tests as a read
  query) — a deliberate deviation from the plan's "drop if unused" (it is still used).

**② SQLite concurrency/durability (`sql.go`):** new `configureSQLite(db)` runs right after
`gorm.Open`: `SetMaxOpenConns(1)` (single-writer → serialises the cap transaction) plus
`PRAGMA busy_timeout=5000`, `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`. DSN
guidance added to the README config reference (persistent, non-shared, lock-capable path).

**③ Session-cookie key separation (`pkg/mcp-proxy/cookie.go` + `main.go`):** new
`deriveCookieKeys(secret)` expands the 32-byte secret via `crypto/hkdf` (SHA-256, two distinct
context labels) into independent 32-byte auth + AES-256 encryption subkeys; `cookie.NewStore`
now takes both, so the operator session cookie is signed **and** encrypted. Fosite keeps the
**raw** secret as its `GlobalSecret`, so issued/refresh tokens are unaffected — only the
short-lived (`MaxAge` 600 s) operator session cookie changes format and forces a one-time
re-login after upgrade.

#### Tests

- New `pkg/repository/cap_test.go`: `TestRegisterClientCapIsAtomicUnderConcurrency` (both
  backends, 40 goroutines vs cap 5 → exactly 5 succeed, 35 `ErrClientCapReached`, final count
  == 5; run under `-race`) and `TestRegisterClientCapAllowsReRegistration` (same ID re-registers
  in place, a new ID is capped).
- New `pkg/mcp-proxy/cookie_test.go`: `TestDeriveCookieKeys` (distinct, 32-byte, deterministic,
  secret-dependent) and `TestSessionCookieIsEncrypted` (a marker stored in the session is not
  present in plaintext in the emitted cookie).
- `maintenance_test.go` updated for the new `RegisterClient` arity (cap `0`).

#### Decisions / deviations

- **Cap moved into the storage layer, not a DB unique-constraint:** the count is over
  non-expired records (expiry is inside the JSON blob), so it needs a scan; doing it in the
  same transaction as the insert is the atomic point. `SetMaxOpenConns(1)` makes the SQLite
  case genuinely serial.
- **`CountClients` retained** (plan said drop if unused) — still used by tests as a read query.
- **HKDF for cookie keys, raw secret for fosite:** one configured secret, two purposes, kept
  cryptographically independent — avoids a second env var while giving the cookie its own
  signed+encrypted keys.
- **No new dependencies** (`crypto/hkdf`, `crypto/sha256` are stdlib; bbolt/GORM already present).

#### Verification

Full suite + `go test -race ./...` green (incl. the concurrency cap on both backends);
`gofmt`/`go vet` clean; golangci-lint v2.12.2 → 0 issues (one G117 on the kvs client-marshal
carries the same documented nolint as the SQL backend — persisting the DCR secret server-side
is the repository's purpose, SPEC §2.1).

**Files:** `pkg/repository/interface.go`, `pkg/repository/kvs.go`, `pkg/repository/sql.go`,
`pkg/idp/idp.go`, `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/cookie.go`, `README.md`,
`SPEC.md` (§1.12/§2.2 deltas); tests new `pkg/repository/cap_test.go`, new
`pkg/mcp-proxy/cookie_test.go`, `pkg/repository/maintenance_test.go`.

### F-012 — Audit low-severity follow-ups — DONE 2026-07-09

Umbrella task closing out the 16 actionable low-severity findings from the F-006b adversarial
audit (the remaining lows after 2 were pulled into F-007b, 2 landed with F-007, and M3/XFF was
fixed in F-006b). Two further notes — introspection accepts any valid access token as auth, and
`handleAuth` persists an authorize request pre-auth — are closed as **accepted, no code change**
(both informational, mitigated by the M4 fixes). Worked in five independently-committed substeps,
each with regression tests incl. negatives, full suite + `-race` + golangci-lint v2.12.2 green,
and its SPEC/README delta in the same commit. Per-substep detail in the F-012a–e sections above.

- **F-012a** (guards, 2026-07-08): bool-parse fail-fast · RSA < 2048 refused ·
  `jwt.WithExpirationRequired()` · redirect-replay body cap (4 MiB) · CIMD grant/response-type
  whitelist shared with DCR.
- **F-012b** (auth flow, 2026-07-09): `EnforcePKCE:true` for all clients · uniform
  empty-password · constant multi-hash bcrypt timing · dead `handleLogin` branch removed ·
  full logout `Clear` + cookie expiry · `safeRedirectTarget` same-origin guard.
- **F-012c** (login surface, 2026-07-09): per-session anti-CSRF token on login/consent/settings/
  WebAuthn POSTs (constant-time, new `pkg/auth/csrf.go`) · discoverable passkey login
  (`BeginDiscoverableLogin`, empty allow-list) + resident-key required.
- **F-012d** (persistence, 2026-07-09): atomic DCR-cap transaction (`ErrClientCapReached` → 503,
  no TOCTOU) · SQLite `SetMaxOpenConns(1)` + WAL/busy_timeout/synchronous/foreign_keys pragmas ·
  HKDF-separated signed+encrypted session cookie (fosite keeps the raw `GlobalSecret`).
- **F-012e** (docs & release, 2026-07-09): `CHANGELOG.md` `[0.1.1]` entry (every behaviour change
  + upgrade notes: one-time operator re-login, stricter startup, resident-passkey rescue);
  `AUDIT-RESULTS.md` (local) findings marked resolved; release-gate `govulncheck` clean
  (0 reachable). **v0.1.1 released:** git tag `v0.1.1` → release workflow green → multi-arch
  (amd64+arm64) image on GHCR as `0.1.1`/`0.1` (metadata-action strips the `v`, as with v0.1.0),
  verified by anonymous `docker manifest inspect`. Operator bumps the live deployment separately.

**Known follow-up (pre-existing) → intaked as F-013, fixed 2026-07-09:**
`.github/workflows/ci.yml` failed to load on every push since v0.1.0 (0 jobs created, GitHub
"No jobs were run") — so the build/test/lint/license CI gate was not actually running. Isolated
to `ci.yml` (the `vulncheck` and `release` workflows run fine). **Root cause (verified with
actionlint), correcting an earlier wrong guess in this note:** it was **not** the
`golangci/golangci-lint-action@v9.3.0` reference (that tag exists and resolves, as do
`actions/checkout@v7` / `actions/setup-go@v6`). The actual bug was a **YAML syntax error** on the
`license-check` job's `run:` line — the value began with a double quote
(`run: "$(go env GOPATH)/bin/go-licenses" check …`), so YAML parsed the quoted scalar and the
trailing ` check …` was invalid, invalidating the whole file. Local checks (`go test ./...`,
`-race`, golangci-lint v2.12.2) were run by hand for every F-012 substep in lieu of the gate.
Fixed in F-013 (block-scalar `run:` + a pinned `actionlint` CI job so a malformed workflow fails
loudly in future).

**Files (umbrella):** see the per-substep sections. **Docs:** `CHANGELOG.md`, `SPEC.md`,
`README.md`, `AUDIT-RESULTS.md` (local), `PROGRESS.md`, `PROGRESS-ARCHIVE.md`; git tag `v0.1.1`.
