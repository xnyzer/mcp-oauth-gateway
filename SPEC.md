# SPEC — mcp-oauth-gateway (implementable contracts)

> Precise, RFC-conformant contracts for the FR/GR/SR requirement register (**§5**). Normative
> keywords (**MUST**, **SHOULD**, **MAY**) per RFC 2119. Baseline: the **final MCP authorization
> spec 2026-07-28**; the requirement-by-requirement conformance record is
> [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md) (§4).

**This document is binding for changes to the gateway.** It says *what must hold*. Two documents
sit beside it and are equally binding: `CODING-STANDARDS.md` (how the code is written) and
`THREAT-MODEL.md` (what it defends against). Everything else in the repository — README, the
`docs/` records, PROGRESS — is description, not rule.

## 0. Conventions

- **Base URL / issuer:** every absolute URL below is relative to the configured public base URL
  (`EXTERNAL_URL`). The OAuth **issuer is `EXTERNAL_URL` normalized without a trailing slash**;
  the same normalized value MUST be used in AS metadata (`issuer`), token `iss` claims, and the
  RFC 9207 `iss` authorization-response parameter. `EXTERNAL_URL` is validated at startup as an
  absolute http(s) URL without path, query or fragment.
- **Endpoint paths:** OAuth and login endpoints live under the `/.idp/*` and `/.auth/*`
  prefixes: clients discover endpoint paths via RFC 8414/9728 metadata, and the prefixes
  cannot collide with paths proxied to the upstream MCP server. The FR-2/FR-3 path examples
  (`/register`, `/authorize`) in §5.2 are to be read as "the paths advertised in discovery
  metadata".
- **Error format:** OAuth endpoints return RFC 6749 §5.2-style JSON errors
  (`{"error": "...", "error_description": "..."}`) with the appropriate HTTP status. Error
  responses MUST NOT leak internals (no stack traces, no file paths, no upstream details)
  (CODING-STANDARDS §6). The protected proxy surface uses RFC 6750 (§1.11).
- **Security headers:** token and authorization responses carry `Cache-Control: no-store`
  (SR-9). All endpoints assume TLS termination (SR-2), either built-in (ACME) or by the
  fronting reverse proxy (GR-1).
- **Origin validation (SR-9, `ORIGIN_CHECK_ENABLED`, default on):** a request whose `Origin`
  header names anything other than the `EXTERNAL_URL` origin is answered `403`. A request
  **without** an `Origin` header passes — server-side MCP clients send none, so treating
  absence as a violation would reject every real client. `Origin: null` (sandboxed iframes,
  `file://`, some redirect chains) counts as present and invalid. Comparison is on
  scheme + host + port with the host lower-cased and default ports elided. `GET /healthz`
  is registered ahead of the check and stays reachable regardless.
- **Fail-closed:** any validation or storage error on an auth path results in denial
  (400/401/403), never in an authenticated default (SR-3).

### Endpoint overview

| # | Method + path | Purpose | RFC | Req. |
|---|---|---|---|---|
| 1.1 | `GET /.well-known/oauth-protected-resource` | PRM discovery | 9728 | FR-1 |
| 1.2 | `GET /.well-known/oauth-authorization-server` | AS metadata | 8414 | FR-1 |
| 1.2 | `GET /.well-known/openid-configuration` | OIDC Discovery mirror (optional) | OIDC Disc. | FR-1 |
| 1.3 | — (no endpoint; URL client IDs) | CIMD client identification | MCP 2025-11-25 | FR-2 |
| 1.4 | `POST /.idp/register` | DCR (deprecated fallback) | 7591 | FR-2 |
| 1.5 | `GET /.idp/auth` | Authorization endpoint | 6749, 7636, 9207, 8707 | FR-3 |
| 1.5 | `GET/POST /.idp/auth/:ar_id` | Login-gated consent step | — | FR-4 |
| 1.6 | `POST /.idp/token` | Token endpoint | 6749, 7636, 8707 | FR-3/5 |
| 1.8 | `GET /.well-known/jwks.json` | JWKS | 7517 | FR-7 |
| 1.9 | `POST /.idp/revoke` | Token revocation | 7009 | FR-9 |
| 1.10 | `POST /.idp/introspect` | Token introspection | 7662 | FR-9 |
| 1.11 | `ANY <any non-public path>` | Authenticated proxy to upstream | 6750 | FR-6/8 |
| 1.12 | `/.auth/login`, `/.auth/logout`, `/.auth/oidc*` | Operator login (password / passkey / optional OIDC) | — | FR-4 |
| 1.13 | `GET /healthz` | Health | — | GR-4 |

**Public (unauthenticated) paths** are exactly: the three `/.well-known/*` documents,
`/.idp/auth`, `/.idp/auth/:ar_id`, `/.idp/token`, `/.idp/register`, `/.idp/revoke`,
`/.idp/introspect`, `/.auth/*`, and `/healthz`. Every other path is the protected proxy
surface (§1.11). This list is normative for SR-7/SR-10 (minimal public surface).
The `/.idp/`, `/.auth/`, and `/.well-known/` namespaces are **reserved**: unmatched paths
inside them (e.g. config-disabled endpoints) return `404` and are **never proxied upstream** —
a disabled endpoint MUST NOT fall through to the proxy.

---

## 1. API contracts

### 1.1 Protected Resource Metadata — `GET /.well-known/oauth-protected-resource`

RFC 9728. Response `200`, `Content-Type: application/json`:

| Field | Value | Notes |
|---|---|---|
| `resource` | issuer | The gateway is the MCP resource. |
| `authorization_servers` | `[issuer]` | The gateway is its own AS. |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` | advertised per RFC 9728 §2 |
| `bearer_methods_supported` | `["header"]` | only `Authorization: Bearer` |
| `scopes_supported` | `[]` (until scopes are defined) | keep consistent with §1.2 |
| `resource_name` | `"mcp-oauth-gateway"` | optional, cosmetic |

The PRM URL is the one the `WWW-Authenticate` challenge points at (§1.11).

### 1.2 AS metadata — `GET /.well-known/oauth-authorization-server`

RFC 8414. Response `200 application/json`:

| Field | Value |
|---|---|
| `issuer` | issuer (no trailing slash, §0) |
| `authorization_endpoint` | `<issuer>/.idp/auth` |
| `token_endpoint` | `<issuer>/.idp/token` |
| `registration_endpoint` | `<issuer>/.idp/register` (present while DCR fallback is enabled) |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` |
| `revocation_endpoint` | `<issuer>/.idp/revoke` |
| `introspection_endpoint` | `<issuer>/.idp/introspect` |
| `response_types_supported` | `["code"]` |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `["authorization_code", "refresh_token"]`; `refresh_token` is omitted when the refresh grant is disabled (`REFRESH_TOKEN_TTL=0`) |
| `token_endpoint_auth_methods_supported` | `["client_secret_basic", "client_secret_post", "none"]` |
| `code_challenge_methods_supported` | `["S256"]` (plain MUST NOT be offered) |
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207) |
| `client_id_metadata_document_supported` | `true` while CIMD is enabled (§1.3), else `false` — always present |
| `scopes_supported` | `[]` (until scopes are defined) |

**OIDC Discovery mirror (optional):** `GET /.well-known/openid-configuration` MAY serve
the same document for clients that only probe that path (the gateway issues no ID tokens; this
is a discovery convenience, not OIDC conformance). Off by default; config flag in §3.

`client_id_metadata_document_supported` MUST always be present, as a boolean, driven by whether
a CIMD resolver is configured. Clients pick CIMD only when the metadata advertises it *and*
offers `none` client authentication; omitting the field pushes every client onto the deprecated
DCR path (§1.4), which is why it is emitted either way rather than only when true.

### 1.3 Client identification — CIMD (primary mechanism)

Per MCP authorization spec 2025-11-25, clients SHOULD identify with a **Client ID Metadata
Document**: `client_id` is an **HTTPS URL** that resolves to a JSON document describing the
client. No registration endpoint is involved; nothing is persisted beyond a cache.

**Recognition:** a `client_id` beginning with `https://` presented at `/.idp/auth` or
`/.idp/token` is treated as a CIMD client ID. All other client IDs are looked up in the DCR
store (§1.4).

**Resolution contract** (all limits configurable, §3; defaults here):
1. `GET client_id` with `Accept: application/json`; **timeout 5 s**, response **size cap
   64 KiB**, **no redirects followed**, TLS verification mandatory.
2. **SSRF guard:** the URL MUST be `https://` with a non-empty host; resolution MUST reject
   loopback, link-local, RFC 1918/ULA, and metadata-service addresses (fail-closed on DNS
   returning such addresses). The check MUST happen at dial time, so that DNS rebinding cannot
   bypass it. No userinfo, no non-default ports unless explicitly allowed by config.
3. The document MUST contain `client_id` exactly equal to the fetched URL, and
   `redirect_uris` (non-empty). Accepted redirect URI schemes: `https://` and
   custom/native schemes; `http://` only for loopback literals (RFC 8252 §7.3).
   **Port tolerance:** a registered loopback URI matches a request that differs from it
   in **nothing but the port** — the part a native client cannot pre-register, because the OS
   assigns it per session. RFC 8252 §7.3 requires this for the IP literals `127.0.0.1`/`[::1]`
   (fosite implements it); the gateway extends it to the hostname `localhost`, which §8.3
   discourages but real native clients use. Scheme, host, path and query must be identical, and
   the tolerance covers `localhost` exactly — not `*.localhost`. It applies at the authorize
   endpoint only; the token endpoint compares against the authorize request, not the registered
   list.
4. Relevant fields: `client_id`, `client_name`, `redirect_uris`, `grant_types` (default
   `["authorization_code"]`), `response_types` (default `["code"]`),
   `token_endpoint_auth_method` — MUST be `none` (CIMD clients are **public**; PKCE is their
   proof of possession); an **absent** value is read as `none`, which is common in real CIMD
   documents, while an explicit non-`none` value is rejected. Unknown fields are ignored.
5. **Cache:** successful resolutions cached (default TTL 1 h, honouring shorter
   `Cache-Control: max-age`); failures negative-cached (default 60 s). Cache is
   in-store/in-memory, not a client registration.
6. Any resolution/validation failure → the OAuth request fails with `invalid_client`
   (fail-closed); the resolution error detail goes to structured logs (SR-8), not the client.

Resolution is effective at the authorize and token endpoints alike.

**Narrowing, not rejecting.** Declared `grant_types`/`response_types` are **narrowed** to the
§1.2 sets rather than rejected for naming something outside them: a CIMD document is published
once and presented to every authorization server, so it declares the union of the client's
abilities — Claude's names `urn:ietf:params:oauth:grant-type:jwt-bearer` beside
`authorization_code` and `refresh_token`. A document that leaves *no* supported grant or
response type is still rejected, since no flow remains to run. Narrowing is fail-closed: the
resolved client only ever ends up with a subset of what the document asked for, and the
endpoints refuse an unsupported flow if one is attempted anyway. **DCR stays strict** (§1.4) —
a registration request is addressed to this server alone, so declaring something it does not
support is a client error there.

### 1.4 Dynamic Client Registration — `POST /.idp/register` (deprecated fallback)

RFC 7591. Kept for backward compatibility; MAY be disabled by config.

**Request** (`application/json`): `redirect_uris` (REQUIRED, non-empty, schemes as in §1.3.3),
`token_endpoint_auth_method` (`none` | `client_secret_basic` | `client_secret_post`; default
`client_secret_basic`), `grant_types` (subset of §1.2; default `["authorization_code"]`),
`response_types` (subset; default `["code"]`), `client_name`, `scope` (space-separated).

**Response `201`:** `client_id` (generated), `client_secret` (confidential clients only),
`client_id_issued_at`, `client_secret_expires_at` (epoch seconds = issued_at + registration
TTL; `0` only if expiry is disabled), echo of the accepted metadata,
`registration_client_uri` (reserved; management API is out of scope).

**SR-5 hardening:**
- **Registration TTL:** registrations expire (default 30 days) and are garbage-collected;
  expiry is refreshed on successful token issuance (active clients never expire mid-use). An
  expired registration is treated as absent on lookup.
- **Cap:** at most N stored DCR clients (default 100); at the cap, registration returns
  `503` + `{"error":"temporarily_unavailable"}` (never silent eviction of active clients). The
  count and the insert MUST run in one write transaction, so the cap cannot be exceeded by
  concurrent registrations (no TOCTOU).
- **Rate limit:** per-IP limit on `/.idp/register` (default 10/min, §3).
- **Validation:** redirect URIs validated as in §1.3.3; grant/response types restricted to the
  §1.2 sets; unknown `token_endpoint_auth_method` → `invalid_client_metadata` (400).

### 1.5 Authorization endpoint — `GET /.idp/auth`

RFC 6749 §4.1 + PKCE (RFC 7636) + RFC 9207 + RFC 8707.

**Parameters:** `client_id` (CIMD URL or DCR ID), `redirect_uri` (MUST exactly match a
registered/resolved URI), `response_type=code` (only), `state` (RECOMMENDED, echoed verbatim),
`code_challenge` (**REQUIRED** for **every** client, confidential DCR clients included —
requests without PKCE are rejected), `code_challenge_method=S256`
(only; `plain` rejected), `scope` (optional), `resource` (RFC 8707, optional — see below).

**`resource` handling:** the gateway fronts exactly one MCP resource: itself. If present,
`resource` MUST equal the issuer (after §0 normalization); any other value →
`invalid_target`. If absent, it defaults to the issuer. The granted resource becomes the
token's `aud` (§1.7).

**Flow:** valid request → login (§1.12) if no session → consent form
(`GET /.idp/auth/:ar_id`, login-gated) → user approval (`POST /.idp/auth/:ar_id`).
Consent MUST show the client identity (CIMD `client_name` + the client_id URL, or DCR
`client_name` + ID) and requested scopes; both mechanisms therefore MUST retain the declared
`client_name` rather than parsing and discarding it. The approval POST carries the §1.12
per-session anti-CSRF token on top of its `ar_id` session binding. Approval is
per-authorization (no silent long-lived blanket grants in v1).

**Naming a connection.** The consent form additionally offers an optional
`connection_name`, prefilled with the `client_name` the client declares about itself. What the
operator submits is stored with the authorization and identifies it in the client list (§1.12); it
is display text and decides nothing. The value is sanitized where it enters — control characters
dropped, trimmed, capped at 64 runes — because it is repeated into the auth log, where
`html/template` escaping does not reach. The client's declared name is **prefill only**: the
verified `client_id`, redirect URI and scopes stay the identity the page is judged on.

**Success response:** `302` to `redirect_uri` with `code` (single-use, short-lived: default
10 min, consumed on first token exchange), `state`, and **`iss`** (RFC 9207).

**Loopback warning:** when *every* registered redirect URI of the requesting client is a
loopback address, the consent page adds an explicit warning that the application runs on the
operator's own device and that any local program could have claimed the port. A Client ID Metadata
Document proves who published it, never which process is listening.

**Errors:** per RFC 6749 §4.1.2.1 — redirectable errors (`access_denied`,
`invalid_scope`, `invalid_target`, `server_error`) go to the redirect URI with `state` and
`iss`; non-redirectable ones (unknown client, invalid/missing `redirect_uri`) render an HTML
error page (§1.12 template) with `400` and MUST NOT redirect.

### 1.6 Token endpoint — `POST /.idp/token`

RFC 6749 §4.1.3/§6 + PKCE + RFC 8707. `Content-Type: application/x-www-form-urlencoded`.

**Client authentication:** `client_secret_basic` or `client_secret_post` for confidential DCR
clients; **`none` + PKCE** for public clients (all CIMD clients). `code_verifier` REQUIRED for
`authorization_code` grants.

**Grants:**
- `authorization_code`: `code`, `redirect_uri` (must match), `code_verifier`, optional
  `resource` (same rule as §1.5; must match the authorized resource).
- `refresh_token`: `refresh_token`; issues a new access token and **rotates the refresh
  token** (Fosite default; old refresh token invalidated — reuse of a rotated token revokes
  the grant chain, Fosite behaviour, keep enabled).

**Response `200`** (`Cache-Control: no-store`, `Pragma: no-cache`):
`access_token` (JWT, §1.7), `token_type: "bearer"`, `expires_in` (default 3600 s,
configurable), `refresh_token` (when granted), `scope`.

**Errors (`400`/`401`):** `invalid_request`, `invalid_client` (401 with
`WWW-Authenticate: Basic` when Basic auth failed), `invalid_grant` (bad/expired/replayed code,
PKCE mismatch, rotated refresh token), `unauthorized_client`, `unsupported_grant_type`,
`invalid_target`.

### 1.7 Access token claims (JWT) — FR-5, SR-4

Signed JWS, `alg` RS256 (default) or ES256 (`KEY_ALG`, §2.2), header `kid` = active signing
key (§1.8), set at signing time.

| Claim | Value | Verified on `/mcp` (§1.11) |
|---|---|---|
| `iss` | issuer (§0) | MUST equal issuer |
| `sub` | stable user ID (the persisted operator account's ID; OIDC logins keep their provider identity) | present |
| `aud` | granted resource (§1.5/§1.6) — the issuer, as array | MUST contain issuer |
| `exp` | issue time + access-token TTL (default 3600 s) | MUST be in the future |
| `iat`, `nbf` | issue time | `nbf` MUST NOT be in the future |
| `jti` | unique token ID, regenerated per issued token including on refresh (§2.4) | — |
| `client_id` | requesting client's ID (CIMD URL or DCR ID) | — |
| `scope` | granted scopes (space-separated), when scopes exist | — |
| `userinfo` | user attributes for header mapping (existing `Extra`) | — |

Refresh tokens and authorization codes are **opaque Fosite HMAC tokens** (not JWTs), stored
server-side (§2), revocable.

### 1.8 JWKS — `GET /.well-known/jwks.json`

RFC 7517. Response `200 application/json`: `{"keys": [...]}` — public keys only, each with
`kty`, `use: "sig"`, `kid`, `alg`, and the key parameters (`n`/`e` for RSA; `crv`/`x`/`y` for
EC when ES256 is enabled).

**Rotation contract (detail in §2.3):** during a rotation window the set contains
the **new active key and the previous key(s)** until every token signed with them has
expired (window ≥ access-token TTL + clock skew). The active key is served first, then every
retiring key (EC keys with `crv`/`x`/`y` per RFC 7518 §6.2.1). Verifiers select by `kid`. The
endpoint sends `Cache-Control: max-age=300` so rotations propagate quickly.

### 1.9 Token revocation — `POST /.idp/revoke` (new)

RFC 7009. Form-encoded: `token` (REQUIRED), `token_type_hint`
(`access_token` | `refresh_token`, optional). Client authentication as at the token endpoint;
a client MAY only revoke its own tokens (mismatch → treat as unknown token).

**Response:** `200` with empty body for valid client requests — **also when the token is
unknown or already revoked/expired** (RFC 7009 §2.2; no token-existence oracle). `401
invalid_client` for failed client auth; `503` if the store is unavailable (revocation MUST NOT
silently no-op).

Revoking a refresh token revokes the whole grant; its access tokens are then rejected by the
§2.4 record-presence check.

### 1.10 Token introspection — `POST /.idp/introspect`

RFC 7662 (optional per FR-9; exists today). Form-encoded `token`, `token_type_hint`.
**Client authentication REQUIRED** (confidential clients or gateway-internal use; anonymous
introspection MUST be rejected — no token oracle). Response `200`:
`{"active": false}` or `{"active": true, iss, sub, aud, exp, iat, client_id, scope, ...}`.

### 1.11 Protected proxy surface (every non-public path)

FR-6/FR-8/SR-3/SR-7. All requests to paths outside the §0 public list:

1. **Bearer required:** `Authorization: Bearer <jwt>`. Validation: JWS signature against the
   JWKS key set (`kid`; RS256/ES256, unknown `kid` or alg mismatch → 401), `iss`, `aud`
   contains issuer, `exp` (**MUST be present**) and `nbf` (small skew tolerance, default 30 s),
   and the §2.4 record-presence check. Any failure → `401`.
2. **401 contract (RFC 6750 + RFC 9728 §5 — target):**
   `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"`,
   plus `error="invalid_token", error_description="..."` when a (malformed/invalid/expired)
   token was presented; the bare challenge when none was. Body: RFC 6750-style JSON. This
   header is how MCP clients bootstrap discovery — it is the single most important delta for
   client compatibility.
3. **Upstream forwarding on success:** request streamed to the upstream MCP server
   (streamable HTTP; SSE passthrough unless `HTTP_STREAMING_ONLY` rejects GET-SSE with `405`).
   No buffering of streaming bodies; hop-by-hop headers stripped per RFC 9110. Request-body
   buffering for an upstream 307/308 replay is capped at **4 MiB**: a larger body streams
   through unbuffered, and a redirect for it is passed to the client instead of followed.
4. **Credential injection (FR-6):** configured upstream credential attached
   (`Authorization: Bearer <PROXY_BEARER_TOKEN>` / custom headers / none). The client's
   token is **not** forwarded unless `PROXY_FORWARD_AUTHORIZATION=true`. The upstream
   credential MUST never appear in responses or logs (SR-8). Every configured
   `PROXY_HEADERS` name is stripped from the inbound request before the configured value
   is attached — the same anti-spoofing rule as §1.11.5. Without it a client could send
   the same header name and, because appended values keep their order, sit in front of the
   injected one where an upstream reading only the first value would find it.
5. **Identity headers:** configured `HEADER_MAPPING` maps token claims (base
   `HEADER_MAPPING_BASE`, default `/userinfo`) to request headers; inbound copies of those
   headers are stripped first (anti-spoofing).

### 1.12 User authentication & consent — `/.auth/*`

FR-4/SR-6. Session-cookie based (`Secure`, `HttpOnly`, `SameSite=Lax`; keys from
`AUTH_HMAC_SECRET` or generated, §2/§3). The cookie is **signed and encrypted** with
HKDF-derived auth+encryption subkeys distinct from the Fosite token secret (§2.2);
upgrading forces a one-time operator re-login. A per-session anti-CSRF token (32 random bytes,
crypto/rand) is stored in the HMAC-signed session and embedded in the login/consent/settings
forms; every state-changing POST on this surface is checked against it in constant time —
defence-in-depth on top of `SameSite=Lax`. Form POSTs carry it in a hidden
`csrf_token` field; the WebAuthn `fetch()` calls send it as the `X-CSRF-Token` request header.

- `GET /.auth/login` — login page. Backends: **passkey/WebAuthn** (preferred, offered once a
  credential is enrolled), **password** (bcrypt hash(es) from the env config — see below),
  and **generic OIDC** (off by default, active only when configured).
- `POST /.auth/login` — password verification. **Rate limiting / lockout (SR-6):** per-IP token
  bucket on the login surfaces (password + passkey ceremony) and a
  per-account lockout after `LOGIN_LOCKOUT_THRESHOLD` consecutive failed password logins
  (passkey assertions are exempt — cryptographic, not guessable). Uniform error message and
  timing (no user/state enumeration): a locked account and a disabled password fallback both
  answer exactly like a wrong password, and the bcrypt comparison always runs first. The
  disabled-fallback rejection does not count toward the lockout (it is a correct password,
  not a guessing signal). An **empty** password runs the same bcrypt path and returns the same
  uniform error as a wrong one — no distinct pre-bcrypt rejection (SR-6).
- `GET /.auth/logout` — session invalidation: the whole session is cleared and the cookie
  expired (`MaxAge -1`), not merely the authorized flag.
- `/.auth/oidc`, `/.auth/oidc/callback` — generic OIDC login backend (unchanged contract,
  off by default).
- Consent (`/.idp/auth/:ar_id`, §1.5) requires an authenticated session; it MUST re-verify
  the pending authorize request server-side (`ar_id` session mechanism).
- A stored post-login redirect target MUST be normalised to a local path (it MUST start with
  `/` and MUST NOT start with `//` or `/\`) at every login consumer — password, passkey and
  OIDC callback alike.

**Operator account & bootstrap:** the gateway has exactly **one** persisted user
(FR-4), created on the first successful password login. Its generated 64-character ID is the
JWT `sub` (§1.7) and the WebAuthn user handle. **The env config stays the authoritative
password source:** the record never stores a password hash — only identity, passkeys, and the
password-disabled flag.

**Passkey/WebAuthn:** RP ID = the issuer's host, allowed origin = the issuer
(§0). Ceremony state lives in the cookie session, one `finish` per `begin`.

| Endpoint | Access | Purpose |
|---|---|---|
| `POST /.auth/webauthn/login/begin` / `finish` | public (CSRF-checked) | **discoverable** (usernameless) assertion ceremony — empty allow-list, so the begin response never enumerates the operator's credential IDs to an anonymous caller; `400`/`401` with a uniform error when unavailable or failed; a sign-count regression (clone warning) or a failed sign-count persist denies the login (fail-closed) |
| `POST /.auth/webauthn/register/begin` / `finish` | session-gated (CSRF-checked) | enrollment (attestation) ceremony; existing credentials are excluded; a resident (discoverable) key is **required** so every new passkey supports discoverable login |
| `GET /.auth/settings` | session-gated | passkey list/enroll/delete + password-fallback toggle + **the client list**; the page footer names the running build version — the only place the gateway shows it over HTTP (§1.13) |
| `POST /.auth/settings/password`, `POST /.auth/settings/credentials/delete` | session-gated (CSRF-checked) | form posts (per-session CSRF token + `SameSite=Lax`) |
| `POST /.auth/settings/clients/revoke`, `.../clients/grants/revoke`, `.../clients/revoke-all` | session-gated (CSRF-checked) | operator revocation: one client, one authorization, or everything |

Settings and enrollment additionally require the session to belong to the persisted operator
account (OIDC-provider sessions get `403`). **Password-fallback rule:** disabling requires ≥ 1
passkey; the stored flag is only honoured while a passkey exists — deleting the last passkey
re-activates the password login (lockout rescue). At startup, at least one usable backend
(password, OIDC, or an enrolled passkey) MUST exist, otherwise fail-fast (§3.1).

**Client list and operator revocation.** The settings page lists every client that holds
access, with its authorizations, token-record counts and activity times, and revokes per client,
per authorization, or all at once. It closes a gap `/.idp/revoke` cannot: RFC 7009 is
**client-authenticated**, so it lets a client drop its *own* token and never lets the operator drop
someone else's. Three properties define the contract:

- **The listing is built from token records, not registrations.** A CIMD client has no stored
  registration — it is re-resolved from its URL on every lookup (§1.3) — so enumerating client
  records would miss exactly the clients that hold access. Non-expired registrations join as a
  second source, so a registration without tokens still shows.
- **Rows are identified by the operator's own name** where one was given at consent time
  (§1.5); the `client_id` stays visible beneath it, because the name is a label and the id is the
  verifiable identity. The name lives in the authorization's session record, so it needs no store of
  its own and is deleted with the authorization.
- **Granularity is per client and per authorization, never per device.** Token records carry no IP
  and no user agent, and every device signed into the same client shares one client ID. The page
  says so rather than implying device identity.
- **A revoke ends access at once and bans nobody.** Deleting the token records is what stops
  `/mcp`, because access is decided by record presence (§2.4) rather than by the token's remaining
  lifetime. A revoked client may authorize again, which requires an authenticated operator session
  and the consent step (§1.5). Revoking sweeps access tokens, refresh tokens, authorization codes,
  PKCE sessions and pending authorize requests together, plus the DCR registration where one
  exists — a refresh token left behind would mint a new access token immediately. The operator's
  own account, passkeys and session are never touched, including by the "revoke everything" action.

Every revoke emits the SR-8 `revoked` auth event with actor, scope and record count, so an operator
kill is distinguishable in the log from the client-initiated RFC 7009 revocations that share the
event name.

HTML pages (login/consent/error/unauthorized/settings) are the §1.5 "non-redirectable error"
and login surfaces; they MUST NOT reflect unvalidated request input (XSS — settings messages
are fixed server-side texts selected by code) and MUST NOT reveal whether a user exists
(SR-6).

### 1.13 Health — `GET /healthz`

`200 {"status":"ok"}` once the process is serving; no auth, no version/internals disclosure
(SR-10) — the endpoint is public, and a version string tells an anonymous caller which
advisories apply. The operator reads the running version behind their session instead, in the
settings page footer (§1.12). Not proxied to the upstream. Served on every listener: in TLS
modes the plain-HTTP listener answers `/healthz` directly (everything else redirects to
https), so the container health probe (`mcp-oauth-gateway healthcheck`) always targets
`LISTEN`.

---

## 2. Data model, persistence & key management

Persistence goes through the existing `pkg/repository.Repository` interface —
**bbolt (default,** single bucket `mcp-oauth-gateway`, prefixed keys**) or SQLite (GORM)**.
Every entity below extends that interface; none bypass it. All times are
stored UTC. A periodic **expiry sweeper** (default every 5 min, §3) garbage-collects every
entity with a passed expiry; lookups MUST treat expired-but-not-yet-swept records as absent
(fail-closed, no reliance on the sweeper).

### 2.1 Entities

| Entity | Key fields | Lifetime / expiry | Store mapping (SQLite table / bbolt key prefix) |
|---|---|---|---|
| **DCR client** | `client_id`; hashed secret, redirect URIs, grant/response types, scopes, public flag, `client_name`, `created_at`, **`expires_at`** | `DCR_CLIENT_TTL` (default 30 d), refreshed on token issuance; hard cap `DCR_MAX_CLIENTS` (§1.4) | `client_records` / `client:` |
| **CIMD cache entry** | `client_id` URL; resolved metadata JSON, `fetched_at`, `expires_at`, `negative` flag | positive: `CIMD_CACHE_TTL` (default 1 h, capped by upstream `max-age`); negative: 60 s | in-memory (MAY persist as `cimd_cache` / `cimd:`) — loss on restart is acceptable (re-resolve) |
| **Authorize request** | `ar_id`; serialized Fosite authorize request | 10 min (= auth-code TTL); consumed on completion | `authorize_request_records` / `authorize_request:` |
| **Authorization code session** | code signature; request + session data | `AUTH_CODE_TTL` (default 10 min), single-use | `authorize_code_sessions` / `authorize_code:` |
| **Access token record** | token signature (JWT signature segment) + **request ID** (grant); request + session data | `ACCESS_TOKEN_TTL` (default 1 h) | `access_token_sessions` / `access_token-` |
| **Refresh token record** | token signature + **request ID** (grant); request + session data, rotation state | `REFRESH_TOKEN_TTL` (default 30 d); rotated on use (§1.6) | `refresh_token_sessions` / `refresh_token-` |
| **PKCE session** | request signature; challenge + method | tied to auth-code lifetime | `pkce_request_sessions` / `pkce_request-` |
| **User** | `user_id`; `username`, `password_login_disabled`, `created_at` — **no password hash** (the env config stays authoritative, §1.12) | permanent (single record, FR-4) | `user_records` / `user-` |
| **Passkey credential** | WebAuthn credential ID (base64url); `user_id`, name, marshaled credential (COSE public key, sign count, transports, flags), `created_at`, `last_used_at` | permanent, user-revocable | `webauthn_credential_records` / `webauthn_credential-` |

"Last active" for a client is derived from its token records, not stored on the registration — a
second timestamp there would be a competing source of truth. The operator's own name for an
authorization is not an entity either: it rides the grant's session record (`SessionData`), which
is why it is deleted with the authorization.

The operator's client list (§1.12) adds **no entity**: it aggregates the access- and
refresh-token records above by the client snapshot each one carries, and joins the stored DCR
registrations. `SchemaVersion` is therefore unchanged, and a store written before the client list reads
without migration.

Access tokens are JWTs (§1.7) **and** have a server-side record: `/mcp` validation stays
stateless-first (signature/claims), then requires the token's **record to still exist**
(§2.4). Refresh tokens and authorization codes are opaque Fosite HMAC tokens, server-side
only. Revocation is decided by **record presence** rather than by a revoked-`jti` deny-list:
same guarantee, no extra entity, and the RFC 7009 cascade falls out of deleting the grant's
records. The `jti` claim serves introspection and logging, and is regenerated per issued
token, including on refresh.

### 2.2 Signing keys & secrets

Keys live in the **data directory** (not the DB), permissions `0600`, directory `0700`
(backup/restore = back up the data directory, §5.5):

- `keys/<kid>.pem` — PKCS#8 private key (RSA-2048 default; P-256 when `KEY_ALG=ES256`).
- `keys/manifest.json` —
  `{ "active": "<kid>", "active_since": ts, "retiring": [{"kid": "...", "not_after": ts}] }`
  (`active_since` drives the §2.3.1 interval check; timestamps are RFC 3339 UTC).
- `kid` = hex-encoded first 8 bytes of the SHA-256 fingerprint of the PKIX public key. The
  scheme is fixed: outstanding tokens carry the `kid` in their header, so the legacy migration
  below MUST preserve it.
- **First run:** no manifest → generate a key, write manifest atomically (temp file + fsync +
  rename). Startup MUST fail (fail-fast) if the manifest references a missing/unreadable key
  file or a file whose fingerprint does not match its `kid`.
- Legacy single-key file (`data/private_key.pem`): migrated on first start by
  adopting it as the active key (kid preserved) and writing a manifest — existing deployments
  keep their key; the original file is left in place.
- `JWT_PRIVATE_KEY` (env, existing behaviour): the key is used as a **static** single key —
  no key directory, automatic rotation disabled (startup WARNING when
  `KEY_ROTATION_INTERVAL` > 0); `KEY_ALG` must match the key type (fail-fast). RSA keys below
  **2048 bits** are refused (fail-fast) — this applies to supplied and adopted legacy
  keys alike.
- `AUTH_HMAC_SECRET` (session cookies + Fosite HMAC): from env (base64) or generated secret
  file in the data directory (existing behaviour). The operator **session cookie** no longer
  uses the raw secret directly: two independent subkeys (authentication + AES-256 encryption)
  are HKDF-derived (`crypto/hkdf`, SHA-256, distinct context labels) so the cookie is signed
  **and** encrypted. Fosite keeps the **raw** secret as its `GlobalSecret`,
  so issued tokens are unaffected; only the short-lived (`MaxAge` 600 s) operator session
  cookie changes format and is re-issued on the next login — a one-time re-login after upgrade.

### 2.3 Key rotation (SR-4, §5.5 "no abrupt invalidation")

1. Rotation trigger: `KEY_ROTATION_INTERVAL` elapsed since active-key creation (default 90 d;
   `0` disables) — checked at startup and periodically by the sweeper. Additionally, the
   `rotate-key` ops command forces one rotation on the data directory (offline — restart the
   gateway afterwards to sign with the new key).
2. On rotation: generate new key → new key becomes `active`; previous key moves to `retiring`
   with `not_after = now + ACCESS_TOKEN_TTL + 2×CLOCK_SKEW` (every outstanding token signed by
   it stays verifiable until it has expired).
3. JWKS (§1.8) serves `active` + all `retiring` keys; `/mcp` verification accepts any key in
   that set, selected by `kid`. New tokens are signed only with `active`.
4. Keys past `not_after` are removed from the manifest and their files deleted by the sweeper.
5. Rotation MUST be atomic (manifest rewrite via temp file + rename); a crash mid-rotation
   leaves the old manifest intact.

Rotation is checked at startup and by a 5-minute sweeper; changing `KEY_ALG` also triggers a
rotation at startup (§3.2). Verification is multi-key end to end: the proxy resolves `kid`
against active + retiring keys, and fosite validates through the same key set, so introspection
keeps working across rotations. Sweep order MUST be crash-safe — the manifest is rewritten
before key files are deleted.

### 2.4 Revocation semantics (completes §1.9)

- Token records carry their grant's **request ID**; revocation deletes **all records of the
  grant** (refresh revocation therefore cascades to its access tokens).
- `/mcp` checks **record presence** (lookup by the JWT's signature segment) after stateless
  validation; missing record → `401 invalid_token`; a store error during the check → `503`
  (fail-closed, SR-3 — never "assume not revoked").
- Introspection (§1.10) reports `active: false` for anything deleted.

### 2.5 Migrations & versioning

- A `schema_version` marker (SQLite: table; bbolt: `meta:schema_version` key) is written on
  first run and checked at startup; an unknown newer version → fail-fast with a clear error.
- SQLite schema changes ship as GORM auto-migrations **plus** a documented entry in the
  release notes; bbolt value-format changes bump the schema version and provide an
  in-place upgrade path. Downgrades are unsupported (documented).
- The SQLite backend sets `busy_timeout`, WAL, `synchronous=NORMAL` and `foreign_keys=ON` on
  open; writes are serialised (bbolt single-writer, SQLite `SetMaxOpenConns(1)`) so the §1.4
  cap check and insert stay atomic.

---

## 3. Configuration & deployment

12-factor (GR-3): every option is an env var with a CLI-flag twin (flag wins). **Fail-fast
validation at startup** (CODING-STANDARDS §7): invalid values abort with a clear message —
never silent defaults for malformed input. Booleans accept `true|1`/`false|0`.

### 3.1 Server, storage and login options

The option reference — every variable, its default and its description — is `README.md`
("Configuration reference") together with `.env.example`. Duplicating it here would create a
second source of truth; this section states only what is **normative** about these options.

- **`EXTERNAL_URL`** is the issuer (§0): absolute http(s), no path/query/fragment. An `http`
  scheme on a non-loopback host MUST log a startup WARNING.
- **At least one login backend MUST exist at startup** — a password, a configured OIDC provider,
  or an already-enrolled passkey. Otherwise the gateway MUST refuse to start (§1.12): a silently
  missing auth backend is worse than a process that will not boot.
- **TLS** is either terminated by the gateway (built-in ACME or a supplied cert+key, which MUST
  be set together) or by a fronting reverse proxy (GR-1, SR-2).
- **`TRUSTED_PROXIES`** accepts bare IPs and CIDR ranges; bare IPs are normalised to `/32`
  (IPv4) and `/128` (IPv6). Empty means **nothing is trusted**, so `X-Forwarded-*` is ignored
  (GR-1).
- **`REPOSITORY_DSN`** is REQUIRED iff the backend is `sqlite`, and MUST point at a persistent,
  non-shared path (§2.5 serialises writes and enables WAL).
- Exactly **one** upstream target is configured, as a positional argument: an `http(s)://` URL
  or a stdio command. The upstream credential to inject is configured alongside it and never
  reaches the client (FR-6, §1.11.4).

### 3.2 Protocol, abuse-protection and key options

Reference as in §3.1; the normative part:

- **Token lifetimes** are validated at startup and MUST stay inside their ranges:
  `ACCESS_TOKEN_TTL` 1 m–24 h, `AUTH_CODE_TTL` 30 s–1 h, `REFRESH_TOKEN_TTL` 1 h–8760 h,
  `CLOCK_SKEW` 0–5 m, `KEY_ROTATION_INTERVAL` ≥ 1 h. A value outside its range is a startup
  failure, never a silent default.
- **`REFRESH_TOKEN_TTL=0`** disables the refresh grant entirely, which also removes
  `refresh_token` from `grant_types_supported` (§1.2).
- **`KEY_ALG`** is `RS256` or `ES256` (§2.2); changing it triggers a key rotation at startup
  (§2.3).
- **Rate limits** are per-client-IP token buckets written `N/s|m|h`; `0` disables a limit.
  Over-limit responses are `429` + `temporarily_unavailable` (SR-5/SR-6). Client-IP extraction
  honours `TRUSTED_PROXIES`; the state is in-memory (GR-3). `RATE_LIMIT_AUTHORIZE` also bounds
  unauthenticated CIMD resolutions driven by unique client IDs (§1.3).
- **`LOGIN_LOCKOUT_THRESHOLD`/`_DURATION`** gate the per-account lockout (§1.12); the error
  stays uniform either way (SR-6). Threshold `0` disables it.
- **`CIMD_ENABLED`/`DCR_ENABLED`:** at least one MUST stay enabled, otherwise the gateway
  refuses to start. Disabling either also removes it from the AS metadata (§1.2). The DCR
  registration TTL and client cap are the SR-5 abuse mitigations (§1.4).
- **`ORIGIN_CHECK_ENABLED=false`** accepts any origin — a rescue switch (SR-9), and it MUST be
  logged at startup (§0).

### 3.3 Deployment artefacts & compatibility

- **`docker-compose.example.yml`** (repo root): gateway + example upstream, placeholder env
  values only (GR-5) — see file.
- **`Dockerfile`**: digest-pinned `golang:1.26-bookworm`
  builder and `gcr.io/distroless/static-debian12:nonroot` runtime — non-root (uid 65532), no
  shell/package manager/interpreters (stdio upstreams needing `npx`/`uvx` run as a separate
  service or custom image). In-image defaults `LISTEN=:8080` / `TLS_LISTEN=:8443` (a non-root
  container cannot bind :80/:443 — publish host ports onto them); `/data` owned by nonroot so
  fresh named volumes inherit ownership; `HEALTHCHECK` runs the binary's own `healthcheck`
  subcommand against `/healthz`; `VERSION` build arg is wired to `pkg/version` (reported by
  `--version` and the MCP ClientInfo).
- **Backward compatibility (§5.5):** existing env keys keep working; renames ship with the old
  key still honoured for ≥1 minor release plus a startup deprecation warning.
- **Health/observability:** `/healthz` (§1.13); structured JSON logs to stdout with
  `login_ok`, `login_fail`, `token_issued`, `register`, `rate_limited`, `revoked` events
  (SR-8): one fixed `"auth event"` message with a generic `event` field
  (GR-4) plus non-secret context (`method`, `endpoint`, `client_id`, `client_ip`); `revoked`
  fires per accepted revocation request (RFC 7009 hides token existence, so the event does
  too).

---

## 4. MCP 2026-07-28 conformance

The requirement-by-requirement conformance record moved out of this document: it is a
**verification result**, not a contract, and it is kept in
[`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md). Its §4.1/§4.2/§4.3 are that file's §1/§2/§3.

At the last check against the **final MCP authorization specification 2026-07-28** the gateway
satisfied every requirement addressed to it; the two deliberate limitations (the scope-less design
and the stdio backend's protocol version) are recorded there.

---

## 5. Requirement register

The intent-level requirements this document turns into contracts. They are stable identifiers,
cited from code comments and tests throughout the repository: a requirement is in force or
repealed, never "done". The contracts above say *how* each one is met; this register says *what*
must hold.

### 5.1 Scope

**In scope:** a gateway process that terminates MCP-spec OAuth toward the client and forwards
authenticated MCP traffic to a single configured upstream MCP server (streamable HTTP). What the
gateway deliberately is *not* is stated in `README.md` ("Why").

### 5.2 Functional requirements (FR)

- **FR-1 Discovery:** serve `GET /.well-known/oauth-protected-resource` (RFC 9728) and
  `GET /.well-known/oauth-authorization-server` (RFC 8414); optionally mirror the latter as
  **OIDC Discovery** (`GET /.well-known/openid-configuration`) for clients that only probe
  that path.
- **FR-2 Client registration — CIMD-first:** accept **CIMD** client IDs (HTTPS-URL client IDs
  resolving to a Client ID Metadata Document) as the primary mechanism; keep **DCR**
  (`POST /register`, RFC 7591) as a **deprecated fallback** for backward compatibility.
  CIMD avoids persisting registrations; DCR registrations remain subject to
  the SR-5 abuse mitigations.
- **FR-3 Authorization Code + PKCE/S256:** `GET /authorize`, `POST /token`. No implicit grant.
  Include the **RFC 9207 `iss`** parameter in the authorization response.
- **FR-4 User authentication:** single configured user. **Passkey/WebAuthn preferred**; strong
  password fallback. Explicit consent step. Auth backend pluggable (self-contained now; external
  self-hosted OIDC later).
- **FR-5 Token issuance & validation:** short-lived signed JWT access tokens (optional refresh).
  Validate signature, `exp`, `aud`, `iss` on every proxied request.
- **FR-6 Upstream auth injection:** on a valid token, forward to the upstream MCP server and
  attach the configured upstream credential — **static bearer / custom header / none**
  (configurable). The client never sees the upstream credential.
- **FR-7 JWKS:** serve `GET /.well-known/jwks.json`.
- **FR-8 Streaming passthrough:** proxy MCP streamable-HTTP/SSE transparently (no buffering;
  correct headers).
- **FR-9 Token lifecycle:** support **token revocation (RFC 7009)** (`POST /revoke`); optionally
  **token introspection (RFC 7662)** (`POST /introspect`).

### 5.3 Generic / portability requirements (GR)

- **GR-1 Reverse-proxy-agnostic:** work behind any reverse proxy **or** optionally terminate TLS
  itself (built-in ACME). Correctly honor `Forwarded` / `X-Forwarded-Proto/Host`. A
  **configurable public base URL** drives all OAuth metadata and redirect URIs.
- **GR-2 Upstream-agnostic:** configurable upstream URL + auth mode (FR-6). Not tied to any
  specific MCP server.
- **GR-3 12-factor config:** env-based config, sane defaults, example compose; runs on any
  Docker host. Single container preferred.
- **GR-4 Portable observability:** structured logs to stdout (JSON), a health endpoint; no
  dependency on a specific logging/metrics backend.
- **GR-5 No-leak by default:** ship no personal/deployment specifics; secrets via env/file/volume,
  generated on first run if absent.

### 5.4 Security requirements (SR)

- **SR-1 No hand-rolled crypto.** OAuth/PKCE/JWT/JWKS primitives via a vetted library; project
  code is glue only (DCR policy, PRM, login, upstream injection).
- **SR-2 TLS everywhere;** tokens never traverse cleartext.
- **SR-3 Fail-closed.** Any failed/absent token check → 401/403; never forward unauthenticated.
- **SR-4 Token hardening.** Short-lived; `aud` bound to the MCP resource (replay protection);
  `iss` checked; asymmetric signing (RS256/ES256); private key stored securely, rotatable.
- **SR-5 DCR abuse mitigation.** `/register` is open by spec; the real gate is the user login.
  Add rate-limiting on `/register` and `/token`, auto-expiring client registrations, and a cap
  on stored clients.
- **SR-6 Brute-force protection** on login (rate-limit/lockout; generic errors, no enumeration).
- **SR-7 Defense-in-depth.** Keep upstream auth (e.g. its bearer) in place; expose only `/mcp`
  plus OAuth/discovery endpoints.
- **SR-8 No secrets in logs** (redact tokens/codes/keys). Auth events emitted as structured
  fields for alerting (`login_ok`, `login_fail`, `token_issued`, `register`).
- **SR-9 Tight CORS/headers;** `Cache-Control: no-store` on token responses; HSTS when serving TLS.
- **SR-10 Minimal attack surface;** lean image; only required endpoints public.
- **SR-11 Maintained dependencies;** documented update path; **permissive-licensed deps only
  (avoid GPL/AGPL)** to keep the project freely usable under Apache-2.0.

### 5.5 Non-functional requirements (NFR)

- Actively maintainable; pinned base image; SemVer; data/schema migrations if persistence is
  used (§2.5); **backward-compatible config changes** — old env keys keep working or have a
  deprecation path (contract: §3.3).
- **Key rotation** without invalidating in-flight sessions abruptly (contract: §2.3).
- Backup/restore of signing keys + client registrations (contract: §2.2; operator guide in
  `README.md`, Operations).
- Tests/CI (OAuth + MCP conformance) so others can trust it.
- End-user docs: how to front an MCP server and add it as a client connector.
