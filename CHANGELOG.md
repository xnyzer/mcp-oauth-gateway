# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html). **Schema migrations and config changes are
called out explicitly** (SPEC §2.5) — read them before upgrading. Downgrades are unsupported.

## [0.1.1] — 2026-07-09

Security-hardening patch: the low-severity follow-ups from the F-006b adversarial audit
(none a vulnerability on their own — defence-in-depth, fail-fast, and hygiene). Delivered as
F-012a–d; see `PROGRESS-ARCHIVE.md` for the per-finding rationale.

### Added

- **Per-session anti-CSRF token** on every state-changing operator POST (login, consent, both
  settings POSTs, and all WebAuthn ceremonies): a 32-byte `crypto/rand` token in the signed
  session, checked in constant time — defence-in-depth on top of `SameSite=Lax`.

### Changed

- **PKCE is now enforced for _every_ client**, including confidential DCR clients (previously
  public/CIMD clients only) — closes the SPEC §1.5 delta; metadata already advertised S256-only.
- **Passkey login is now discoverable** (`BeginDiscoverableLogin`, empty allow-list), so the
  public `login/begin` response no longer enumerates the operator's credential IDs to anonymous
  callers; new passkey registrations require a **resident** key.
- **Operator session cookie is signed _and_ encrypted** with HKDF-derived auth+AES-256 subkeys,
  separate from the Fosite token secret (which is unchanged).
- **DCR registration cap is enforced atomically** inside the write transaction (no
  count-then-insert TOCTOU); an over-cap registration returns `503 temporarily_unavailable`.
- **Startup fails fast** on malformed boolean env vars and on RSA signing keys smaller than
  **2048 bits** (`JWT_PRIVATE_KEY`, adopted legacy keys, and manifest keys alike).
- Login-flow uniformity/robustness: an empty password takes the same bcrypt path and
  byte-identical error as a wrong one; the multi-hash bcrypt comparison runs in constant time
  (no early break); logout clears the whole session and expires the cookie; the stored
  post-login redirect target is validated same-origin.
- SQLite backend opens with `SetMaxOpenConns(1)` and `busy_timeout`/WAL/`synchronous=NORMAL`/
  `foreign_keys=ON` pragmas (serialised writes, fewer "database is locked" errors).

### Security

- Proxy JWT verification now requires `exp` to be present (`WithExpirationRequired`).
- Redirect-following on the proxy path caps buffered bodies at 4 MiB (larger bodies stream;
  a redirect is passed through untouched).
- CIMD documents are held to the same grant/response-type whitelist as DCR registrations.

### Upgrade notes

- **One-time operator re-login.** The session-cookie format changed (now encrypted); existing
  operator sessions are invalidated once. Issued access/refresh tokens are **unaffected** (Fosite
  keeps the raw secret).
- **Startup is now stricter.** Fix any malformed boolean env vars and replace RSA signing keys
  below 2048 bits **before** upgrading, or the gateway will refuse to start.
- **Passkeys must be resident (discoverable).** Passkeys stored in a synced keychain
  (e.g. iCloud Keychain) are resident and keep working. A **non-resident** passkey enrolled
  before v0.1.1 can no longer complete login; rescue by deleting the passkey records in
  `DATA_PATH`, which re-activates the password fallback (SPEC §1.12 lockout-rescue), then
  re-enrol.

## [0.1.0] — 2026-07-08

Initial public release. `mcp-oauth-gateway` is a hard fork of
[`sigbit/mcp-auth-proxy`](https://github.com/sigbit/mcp-auth-proxy) (see [`FORK.md`](FORK.md));
everything below is relative to that base.

### Added

- **CIMD client identification** (MCP spec 2025-11-25, primary mechanism) with dial-time
  SSRF guards, size/time limits and caching; DCR kept as the deprecated fallback with
  TTL/cap/validation and a `DCR_ENABLED` switch.
- **Complete discovery/401 surface:** RFC 9728 PRM, full RFC 8414 AS metadata,
  `WWW-Authenticate` challenge, RFC 9207 `iss`, optional OIDC-discovery mirror.
- **Token binding & lifecycle:** RFC 8707 `resource`→`aud` binding, `jti`/`client_id`/`scope`
  claims, revocation endpoint (RFC 7009) with a fail-closed proxy-side revocation check,
  configurable TTLs, storage sweeper.
- **Key management:** key directory with atomic manifest, RS256/ES256, automatic interval
  rotation with a retiring window (outstanding tokens stay verifiable), multi-key JWKS,
  manual `rotate-key` ops command.
- **Passkey/WebAuthn operator login** with a session-gated settings page; the password
  fallback can be disabled (env hash stays as break-glass rescue).
- **Abuse protection:** per-IP rate limits on register/token/login/authorize, account
  lockout, structured auth events (`login_ok`, `login_fail`, `token_issued`, `register`,
  `rate_limited`, `revoked`).
- **Consent screen** showing the requesting client's identity and scopes.
- **Packaging:** digest-pinned non-root distroless image with a built-in healthcheck
  (`healthcheck` subcommand), multi-arch (amd64/arm64) GHCR releases, `.env.example`,
  health-gated Compose example, `setup.sh` quickstart.

### Changed (relative to the forked base)

- Rebranded to `mcp-oauth-gateway`; bundled Google/GitHub login providers removed (generic
  OIDC stays, off by default).
- Hardened against the findings of an adversarial security audit (0 critical / 1 high /
  9 medium — all fixed; see `PROGRESS-ARCHIVE.md` F-006b/F-007a/F-007b): consent client
  identity, CIMD SSRF denylist, fail-closed `/revoke`, `X-Forwarded-*` spoof protection,
  CIMD cache bound + authorize rate limit, lockout re-arm DoS, no internal-error disclosure,
  bare-IP `TRUSTED_PROXIES` normalisation, http-issuer startup warning, TLS-aware cookie
  `Secure` flag, Slowloris `ReadHeaderTimeout`, `0700` data dir.
- Container image runs as non-root **without interpreters** — stdio upstreams that need
  `npx`/`uvx` now run as a separate service or custom image.
- Image default ports are non-privileged: `LISTEN=:8080`, `TLS_LISTEN=:8443` (publish host
  80/443 onto them).

### Security

- Release-gate `govulncheck` run: bumped `golang.org/x/net` to v0.55.0 (GO-2026-5026),
  `quic-go` to v0.59.1 (GO-2026-5676) and the Go toolchain to 1.26.5 (GO-2026-5856) — all
  three were reachable; zero reachable vulnerabilities at release.
- Verified against the MCP **2026-07-28 specification release candidate**: all six
  authorization-hardening SEPs are satisfied (RFC 9207 `iss` supplied on success+error;
  DCR accepts native/localhost redirect URIs per RFC 8252 and tolerates `application_type`;
  refresh tokens issued independent of an `offline_access` scope; issuer-bound tokens;
  no-path issuer makes the `.well-known` suffix forms equivalent). Re-check planned when
  the final spec publishes on 2026-07-28.

### Upgrade notes

- **No compatibility with `sigbit/mcp-auth-proxy` data directories** (hard fork; the
  storage namespace changed). Start with a fresh `DATA_PATH`.
- First start generates signing keys and the HMAC secret into `DATA_PATH`; a pre-F-005d
  single `private_key.pem` is adopted automatically (kid preserved).
