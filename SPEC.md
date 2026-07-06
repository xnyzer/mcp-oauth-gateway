# SPEC — mcp-oauth-gateway (implementable contracts)

> **Status: draft (F-004).** Contract-level companion to `REQUIREMENTS.md` (intent-level source
> of truth). This document turns the FR/GR/SR requirements into precise, RFC-conformant
> contracts that F-005 implements and F-006 verifies. Normative keywords (**MUST**, **SHOULD**,
> **MAY**) per RFC 2119. Baseline: MCP authorization spec **2025-11-25**; **re-verify against
> the 2026-07-28 release candidate before any release** (watch item, see REQUIREMENTS §0).
>
> Each section notes the **Delta** between the fork's current behaviour and the target
> contract, so F-005 can be implemented and reviewed section by section.

## 0. Conventions

- **Base URL / issuer:** every absolute URL below is relative to the configured public base URL
  (`EXTERNAL_URL`). The OAuth **issuer is `EXTERNAL_URL` normalized without a trailing slash**;
  the same normalized value MUST be used in AS metadata (`issuer`), token `iss` claims, and the
  RFC 9207 `iss` authorization-response parameter. (Delta: **done, F-005a** — the external URL
  is validated as absolute http(s) without path/query/fragment and normalized without a
  trailing slash at startup.)
- **Endpoint paths:** the fork's `/.idp/*` and `/.auth/*` prefixes are **kept** (decision,
  F-004 prep): clients discover endpoint paths via RFC 8414/9728 metadata, and the prefixes
  cannot collide with paths proxied to the upstream MCP server. `REQUIREMENTS.md` FR-2/FR-3
  path examples (`/register`, `/authorize`) are to be read as "the paths advertised in
  discovery metadata".
- **Error format:** OAuth endpoints return RFC 6749 §5.2-style JSON errors
  (`{"error": "...", "error_description": "..."}`) with the appropriate HTTP status. Error
  responses MUST NOT leak internals (no stack traces, no file paths, no upstream details)
  (CODING-STANDARDS §6). The protected proxy surface uses RFC 6750 (§1.11).
- **Security headers:** token and authorization responses carry `Cache-Control: no-store`
  (SR-9). All endpoints assume TLS termination (SR-2), either built-in (ACME) or by the
  fronting reverse proxy (GR-1).
- **Fail-closed:** any validation or storage error on an auth path results in denial
  (400/401/403), never in an authenticated default (SR-3).

### Endpoint overview

| # | Method + path | Purpose | RFC | Req. | Status |
|---|---|---|---|---|---|
| 1.1 | `GET /.well-known/oauth-protected-resource` | PRM discovery | 9728 | FR-1 | exists, **thin** |
| 1.2 | `GET /.well-known/oauth-authorization-server` | AS metadata | 8414 | FR-1 | exists, **incomplete** |
| 1.2 | `GET /.well-known/openid-configuration` | OIDC Discovery mirror | OIDC Disc. | FR-1 | **new (optional)** |
| 1.3 | — (no endpoint; URL client IDs) | CIMD client identification | MCP 2025-11-25 | FR-2 | **new** |
| 1.4 | `POST /.idp/register` | DCR (deprecated fallback) | 7591 | FR-2 | exists, needs SR-5 |
| 1.5 | `GET /.idp/auth` | Authorization endpoint | 6749, 7636, 9207, 8707 | FR-3 | exists, needs `iss`+`resource` |
| 1.5 | `GET/POST /.idp/auth/:ar_id` | Login-gated consent step | — | FR-4 | exists |
| 1.6 | `POST /.idp/token` | Token endpoint | 6749, 7636, 8707 | FR-3/5 | exists, needs `aud` binding |
| 1.8 | `GET /.well-known/jwks.json` | JWKS | 7517 | FR-7 | exists, single static key |
| 1.9 | `POST /.idp/revoke` | Token revocation | 7009 | FR-9 | **new** (storage exists) |
| 1.10 | `POST /.idp/introspect` | Token introspection | 7662 | FR-9 | exists |
| 1.11 | `ANY <any non-public path>` | Authenticated proxy to upstream | 6750 | FR-6/8 | exists, 401 needs `WWW-Authenticate` |
| 1.12 | `/.auth/login`, `/.auth/logout`, `/.auth/oidc*` | User login (password / optional OIDC) | — | FR-4 | exists, F-005 reworks |
| 1.13 | `GET /healthz` | Health | — | GR-4 | exists |

**Public (unauthenticated) paths** are exactly: the three `/.well-known/*` documents,
`/.idp/auth`, `/.idp/auth/:ar_id`, `/.idp/token`, `/.idp/register`, `/.idp/revoke`,
`/.idp/introspect`, `/.auth/*`, and `/healthz`. Every other path is the protected proxy
surface (§1.11). This list is normative for SR-7/SR-10 (minimal public surface).
The `/.idp/`, `/.auth/`, and `/.well-known/` namespaces are **reserved**: unmatched paths
inside them (e.g. config-disabled endpoints) return `404` and are **never proxied upstream**
*(added in F-005c after the DCR_ENABLED=false smoke test showed the disabled endpoint falling
through to the proxy)*.

---

## 1. API contracts

### 1.1 Protected Resource Metadata — `GET /.well-known/oauth-protected-resource`

RFC 9728. Response `200`, `Content-Type: application/json`:

| Field | Value | Notes |
|---|---|---|
| `resource` | issuer | The gateway is the MCP resource. |
| `authorization_servers` | `[issuer]` | The gateway is its own AS. |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` | **target** (advertise; RFC 9728 §2) |
| `bearer_methods_supported` | `["header"]` | **target** — only `Authorization: Bearer`. |
| `scopes_supported` | `[]` (until scopes are defined) | keep consistent with §1.2 |
| `resource_name` | `"mcp-oauth-gateway"` | **target**, optional cosmetic |

**Delta:** **done, F-005a** — all fields above are served. The PRM URL is referenced by the
`WWW-Authenticate` challenge (§1.11).

### 1.2 AS metadata — `GET /.well-known/oauth-authorization-server`

RFC 8414. Response `200 application/json`:

| Field | Value |
|---|---|
| `issuer` | issuer (no trailing slash, §0) |
| `authorization_endpoint` | `<issuer>/.idp/auth` |
| `token_endpoint` | `<issuer>/.idp/token` |
| `registration_endpoint` | `<issuer>/.idp/register` (present while DCR fallback is enabled) |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` — **target** |
| `revocation_endpoint` | `<issuer>/.idp/revoke` — **target** |
| `introspection_endpoint` | `<issuer>/.idp/introspect` — **target** |
| `response_types_supported` | `["code"]` |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `["authorization_code", "refresh_token"]` |
| `token_endpoint_auth_methods_supported` | `["client_secret_basic", "client_secret_post", "none"]` |
| `code_challenge_methods_supported` | `["S256"]` (plain MUST NOT be offered) |
| `authorization_response_iss_parameter_supported` | `true` — **target** (RFC 9207) |
| `scopes_supported` | `[]` (until scopes are defined) |

**OIDC Discovery mirror (optional, F-009):** `GET /.well-known/openid-configuration` MAY serve
the same document for clients that only probe that path (the gateway issues no ID tokens; this
is a discovery convenience, not OIDC conformance). Off by default; config flag in part 3.

**Delta:** **done, F-005a/b** — all fields including `revocation_endpoint` are served;
`grant_types_supported` reflects a disabled refresh grant (`REFRESH_TOKEN_TTL=0`).

### 1.3 Client identification — CIMD (primary mechanism)

Per MCP authorization spec 2025-11-25, clients SHOULD identify with a **Client ID Metadata
Document**: `client_id` is an **HTTPS URL** that resolves to a JSON document describing the
client. No registration endpoint is involved; nothing is persisted beyond a cache.

**Recognition:** a `client_id` beginning with `https://` presented at `/.idp/auth` or
`/.idp/token` is treated as a CIMD client ID. All other client IDs are looked up in the DCR
store (§1.4).

**Resolution contract** (all limits configurable, part 3; defaults here):
1. `GET client_id` with `Accept: application/json`; **timeout 5 s**, response **size cap
   64 KiB**, **no redirects followed**, TLS verification mandatory.
2. **SSRF guard:** the URL MUST be `https://` with a non-empty host; resolution MUST reject
   loopback, link-local, RFC 1918/ULA, and metadata-service addresses (fail-closed on DNS
   returning such addresses). No userinfo, no non-default ports unless explicitly allowed by
   config.
3. The document MUST contain `client_id` exactly equal to the fetched URL, and
   `redirect_uris` (non-empty). Accepted redirect URI schemes: `https://` and
   custom/native schemes; `http://` only for loopback literals (RFC 8252 §7.3).
4. Relevant fields: `client_id`, `client_name`, `redirect_uris`, `grant_types` (default
   `["authorization_code"]`), `response_types` (default `["code"]`),
   `token_endpoint_auth_method` — MUST be `none` (CIMD clients are **public**; PKCE is their
   proof of possession). Unknown fields are ignored.
5. **Cache:** successful resolutions cached (default TTL 1 h, honouring shorter
   `Cache-Control: max-age`); failures negative-cached (default 60 s). Cache is
   in-store/in-memory, not a client registration.
6. Any resolution/validation failure → the OAuth request fails with `invalid_client`
   (fail-closed); the resolution error detail goes to structured logs (SR-8), not the client.

**Delta:** **done, F-005c** — implemented in `pkg/cimd` (dial-time SSRF checks, so DNS
rebinding cannot bypass them) and integrated as the fosite client source, effective at the
authorize and token endpoints alike. An absent `token_endpoint_auth_method` is treated as
`none` (decision: common in CIMD documents; explicit non-`none` values are rejected).

### 1.4 Dynamic Client Registration — `POST /.idp/register` (deprecated fallback)

RFC 7591. Kept for backward compatibility (decision F-003); MAY be disabled by config.

**Request** (`application/json`): `redirect_uris` (REQUIRED, non-empty, schemes as in §1.3.3),
`token_endpoint_auth_method` (`none` | `client_secret_basic` | `client_secret_post`; default
`client_secret_basic`), `grant_types` (subset of §1.2; default `["authorization_code"]`),
`response_types` (subset; default `["code"]`), `client_name`, `scope` (space-separated).

**Response `201`:** `client_id` (generated), `client_secret` (confidential clients only),
`client_id_issued_at`, `client_secret_expires_at` (**target:** epoch seconds =
issued_at + registration TTL; `0` only if expiry is disabled), echo of the accepted metadata,
`registration_client_uri` (reserved; management API is out of scope).

**SR-5 hardening (target):**
- **Registration TTL:** registrations expire (default 30 days) and are garbage-collected;
  expiry is refreshed on successful token issuance (active clients never expire mid-use).
- **Cap:** at most N stored DCR clients (default 100); at the cap, registration returns
  `503` + `{"error":"temporarily_unavailable"}` (never silent eviction of active clients).
- **Rate limit:** per-IP limit on `/.idp/register` (default 10/min, part 3).
- **Validation:** redirect URIs validated as in §1.3.3; grant/response types restricted to the
  §1.2 sets; unknown `token_endpoint_auth_method` → `invalid_client_metadata` (400).

**Delta:** **done, F-005c** — except the per-IP rate limit (F-005e). TTL (refreshed on token
issuance), cap (503, no eviction), redirect-URI scheme validation, grant/response-type
whitelist, `client_secret_expires_at`, and `DCR_ENABLED` (endpoint + metadata entry removed
when off) are implemented; expired registrations are treated as absent on lookup.

### 1.5 Authorization endpoint — `GET /.idp/auth`

RFC 6749 §4.1 + PKCE (RFC 7636) + RFC 9207 + RFC 8707.

**Parameters:** `client_id` (CIMD URL or DCR ID), `redirect_uri` (MUST exactly match a
registered/resolved URI), `response_type=code` (only), `state` (RECOMMENDED, echoed verbatim),
`code_challenge` (**REQUIRED** — requests without PKCE are rejected), `code_challenge_method=S256`
(only; `plain` rejected), `scope` (optional), `resource` (RFC 8707, optional — see below).

**`resource` handling:** the gateway fronts exactly one MCP resource: itself. If present,
`resource` MUST equal the issuer (after §0 normalization); any other value →
`invalid_target`. If absent, it defaults to the issuer. The granted resource becomes the
token's `aud` (§1.7).

**Flow:** valid request → login (§1.12) if no session → consent form
(`GET /.idp/auth/:ar_id`, login-gated) → user approval (`POST /.idp/auth/:ar_id`).
Consent MUST show the client identity (CIMD `client_name` + the client_id URL, or DCR
`client_name` + ID) and requested scopes. Approval is per-authorization (no silent long-lived
blanket grants in v1).

**Success response:** `302` to `redirect_uri` with `code` (single-use, short-lived: default
10 min, consumed on first token exchange), `state`, and **`iss`** (RFC 9207, **target**).

**Errors:** per RFC 6749 §4.1.2.1 — redirectable errors (`access_denied`,
`invalid_scope`, `invalid_target`, `server_error`) go to the redirect URI with `state` and
`iss`; non-redirectable ones (unknown client, invalid/missing `redirect_uri`) render an HTML
error page (§1.12 template) with `400` and MUST NOT redirect.

**Delta:** flow exists (Fosite); `iss` parameter **done (F-005a)**; `resource` validation
**done (F-005b)**; CIMD client support **done (F-005c)**. PKCE presence is enforced by Fosite
config for public clients (which covers every CIMD client) — enforcing it for confidential
DCR clients too remains open (F-005e picks this up with the auth rework).

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

**Delta:** `resource`→`aud` binding and TTL configuration **done (F-005b)**; CIMD client
resolution at the token endpoint **done (F-005c**, via the shared client source**)**. Still
missing: rate limiting (F-005e).

### 1.7 Access token claims (JWT) — FR-5, SR-4

Signed JWS, `alg` RS256 (ES256 optional, part 2), header `kid` = active signing key (§1.8).

| Claim | Value | Verified on `/mcp` (§1.11) |
|---|---|---|
| `iss` | issuer (§0) | MUST equal issuer |
| `sub` | stable user ID (`password_user` today; real user ID after F-005) | present |
| `aud` | granted resource (§1.5/§1.6) — the issuer, as array | MUST contain issuer |
| `exp` | issue time + access-token TTL (default 3600 s) | MUST be in the future |
| `iat`, `nbf` | issue time | `nbf` MUST NOT be in the future |
| `jti` | unique token ID — **target** (enables revocation checks, part 2) | — |
| `client_id` | requesting client's ID (CIMD URL or DCR ID) — **target** | — |
| `scope` | granted scopes (space-separated) — **target** when scopes exist | — |
| `userinfo` | user attributes for header mapping (existing `Extra`) | — |

Refresh tokens and authorization codes are **opaque Fosite HMAC tokens** (not JWTs), stored
server-side (part 2), revocable.

**Delta:** **done, F-005b** — `aud` carries the granted resource, `jti` is unique per issued
token (regenerated on refresh), `client_id` and space-separated `scope` claims are emitted;
`exp` follows `ACCESS_TOKEN_TTL`.

### 1.8 JWKS — `GET /.well-known/jwks.json`

RFC 7517. Response `200 application/json`: `{"keys": [...]}` — public keys only, each with
`kty`, `use: "sig"`, `kid`, `alg`, and the key parameters (`n`/`e` for RSA; `crv`/`x`/`y` for
EC when ES256 is enabled).

**Rotation contract (target, detail in part 2):** during a rotation window the set contains
the **new active key and the previous key(s)** until every token signed with them has
expired (window ≥ access-token TTL + clock skew). Verifiers select by `kid`. The endpoint MAY
send `Cache-Control: max-age` ≤ 300 s so rotations propagate quickly.

**Delta:** today a single static RS256 key, `kid` derived from the public key; no rotation.

### 1.9 Token revocation — `POST /.idp/revoke` (new)

RFC 7009. Form-encoded: `token` (REQUIRED), `token_type_hint`
(`access_token` | `refresh_token`, optional). Client authentication as at the token endpoint;
a client MAY only revoke its own tokens (mismatch → treat as unknown token).

**Response:** `200` with empty body for valid client requests — **also when the token is
unknown or already revoked/expired** (RFC 7009 §2.2; no token-existence oracle). `401
invalid_client` for failed client auth; `503` if the store is unavailable (revocation MUST NOT
silently no-op).

Revoking a refresh token revokes the grant (its access tokens are rejected via store lookup /
`jti`, part 2). The Fosite `TokenRevocationStorage` interface is already implemented by the
repository — this endpoint wires it up.

**Delta:** **done, F-005b** — endpoint wired via fosite's revocation handler; the storage
`Revoke*` implementations were fixed to delete by grant request ID (upstream no-op bug).

### 1.10 Token introspection — `POST /.idp/introspect`

RFC 7662 (optional per FR-9; exists today). Form-encoded `token`, `token_type_hint`.
**Client authentication REQUIRED** (confidential clients or gateway-internal use; anonymous
introspection MUST be rejected — no token oracle). Response `200`:
`{"active": false}` or `{"active": true, iss, sub, aud, exp, iat, client_id, scope, ...}`.

**Delta:** **done, F-005b** — client-auth enforcement verified by test (anonymous
introspection rejected); revoked tokens introspect `active: false`.

### 1.11 Protected proxy surface (every non-public path)

FR-6/FR-8/SR-3/SR-7. All requests to paths outside the §0 public list:

1. **Bearer required:** `Authorization: Bearer <jwt>`. Validation: JWS signature against the
   JWKS key set (`kid`), `iss`, `aud` contains issuer, `exp`/`nbf` (small skew tolerance,
   default 30 s), revocation state (once `jti` lands, part 2). Any failure → `401`.
2. **401 contract (RFC 6750 + RFC 9728 §5 — target):**
   `WWW-Authenticate: Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource"`,
   plus `error="invalid_token", error_description="..."` when a (malformed/invalid/expired)
   token was presented; the bare challenge when none was. Body: RFC 6750-style JSON. This
   header is how MCP clients bootstrap discovery — it is the single most important delta for
   client compatibility.
3. **Upstream forwarding on success:** request streamed to the upstream MCP server
   (streamable HTTP; SSE passthrough unless `HTTP_STREAMING_ONLY` rejects GET-SSE with `405`).
   No buffering of streaming bodies; hop-by-hop headers stripped per RFC 9110.
4. **Credential injection (FR-6):** configured upstream credential attached
   (`Authorization: Bearer <PROXY_BEARER_TOKEN>` / custom headers / none). The client's
   token is **not** forwarded unless `PROXY_FORWARD_AUTHORIZATION=true`. The upstream
   credential MUST never appear in responses or logs (SR-8).
5. **Identity headers:** configured `HEADER_MAPPING` maps token claims (base
   `HEADER_MAPPING_BASE`, default `/userinfo`) to request headers; inbound copies of those
   headers are stripped first (anti-spoofing).

**Delta:** enforcement, streaming, injection, and header mapping exist; the
`WWW-Authenticate` challenge and clock-skew leeway are **done (F-005a)**; the fail-closed
revocation check is **done (F-005b**, §2.4 record-presence lookup**)**.

### 1.12 User authentication & consent — `/.auth/*`

FR-4/SR-6. Session-cookie based (`Secure`, `HttpOnly`, `SameSite=Lax`; HMAC key from
`AUTH_HMAC_SECRET` or generated, part 2/3).

- `GET /.auth/login` — login page. Backends: **password** (bcrypt hash(es); the self-contained
  default) and **generic OIDC** (off by default, active only when configured — decision
  F-011). **Target (F-005):** passkey/WebAuthn as preferred method + a real user model
  (REQUIREMENTS FR-4); this spec section will be extended in F-005's prep, not here.
- `POST /.auth/login` — password verification. **Rate limiting / lockout (SR-6, target):**
  per-IP and per-account limits (defaults in part 3); uniform error message and timing (no
  user enumeration).
- `GET /.auth/logout` — session invalidation.
- `/.auth/oidc`, `/.auth/oidc/callback` — generic OIDC login backend (unchanged contract,
  off by default).
- Consent (`/.idp/auth/:ar_id`, §1.5) requires an authenticated session; it MUST re-verify
  the pending authorize request server-side (existing `ar_id` session mechanism).

HTML pages (login/consent/error/unauthorized) are the §1.5 "non-redirectable error" and login
surfaces; they MUST NOT reflect unvalidated request input (XSS) and MUST NOT reveal whether a
user exists (SR-6).

### 1.13 Health — `GET /healthz`

`200 {"status":"ok"}` once the process is serving; no auth, no version/internals disclosure
(SR-10). Not proxied to the upstream.

---

## 2. Data model, persistence & key management

Persistence goes through the existing `pkg/repository.Repository` interface —
**bbolt (default,** single bucket `mcp-oauth-gateway`, prefixed keys**) or SQLite (GORM)** —
decided in F-008c. New entities below extend that interface; none bypass it. All times are
stored UTC. A periodic **expiry sweeper** (default every 5 min, part 3) garbage-collects every
entity with a passed expiry; lookups MUST treat expired-but-not-yet-swept records as absent
(fail-closed, no reliance on the sweeper).

### 2.1 Entities

| Entity | Key fields | Lifetime / expiry | Store mapping (SQLite table / bbolt key prefix) |
|---|---|---|---|
| **DCR client** | `client_id`; hashed secret, redirect URIs, grant/response types, scopes, public flag, `client_name`, `created_at`, **`expires_at`**, **`last_used_at`** | `DCR_CLIENT_TTL` (default 30 d), refreshed on token issuance; hard cap `DCR_MAX_CLIENTS` (§1.4) | `client_records` / `client:` |
| **CIMD cache entry** | `client_id` URL; resolved metadata JSON, `fetched_at`, `expires_at`, `negative` flag | positive: `CIMD_CACHE_TTL` (default 1 h, capped by upstream `max-age`); negative: 60 s | in-memory (MAY persist as `cimd_cache` / `cimd:`) — loss on restart is acceptable (re-resolve) |
| **Authorize request** | `ar_id`; serialized Fosite authorize request | 10 min (= auth-code TTL); consumed on completion | `authorize_request_records` / `authorize_request:` |
| **Authorization code session** | code signature; request + session data | `AUTH_CODE_TTL` (default 10 min), single-use | `authorize_code_sessions` / `authorize_code:` |
| **Access token record** | token signature (JWT signature segment) + **request ID** (grant); request + session data | `ACCESS_TOKEN_TTL` (default 1 h) | `access_token_sessions` / `access_token-` |
| **Refresh token record** | token signature + **request ID** (grant); request + session data, rotation state | `REFRESH_TOKEN_TTL` (default 30 d); rotated on use (§1.6) | `refresh_token_sessions` / `refresh_token-` |
| **PKCE session** | request signature; challenge + method | tied to auth-code lifetime | `pkce_request_sessions` / `pkce_request-` |
| **User** (new, implemented in F-005) | `user_id`; `username`, optional `password_hash` (bcrypt), `created_at` | permanent | `users` / `user:` |
| **Passkey credential** (new, F-005) | WebAuthn credential ID; `user_id`, COSE public key, sign count, transports, `created_at`, `last_used_at` | permanent, user-revocable | `webauthn_credentials` / `webauthn_credential:` |

Access tokens are JWTs (§1.7) **and** have a server-side record: `/mcp` validation stays
stateless-first (signature/claims), then requires the token's **record to still exist**
(§2.4). Refresh tokens and authorization codes are opaque Fosite HMAC tokens, server-side
only. *(Design change during F-005b: the originally specified revoked-`jti` deny-list was
replaced by this record-presence check — same guarantees, no extra entity, and the RFC 7009
cascade falls out of deleting the grant's records. The `jti` claim is kept for introspection
and logging and is regenerated per issued token, including on refresh.)*

### 2.2 Signing keys & secrets

Keys live in the **data directory** (not the DB), permissions `0600`, directory `0700`
(backup/restore = back up the data directory, NFR):

- `keys/<kid>.pem` — PKCS#8 private key (RSA-2048 default; P-256 when `KEY_ALG=ES256`).
- `keys/manifest.json` — `{ "active": "<kid>", "retiring": [{"kid": "...", "not_after": ts}] }`.
- `kid` = base64url SHA-256 fingerprint of the public key (existing scheme).
- **First run:** no manifest → generate a key, write manifest atomically (temp file + rename).
  Startup MUST fail (fail-fast) if the manifest references a missing/unreadable key file.
- Legacy single-key file (current `LoadOrGeneratePrivateKey` path): migrated on first start by
  adopting it as the active key and writing a manifest — existing deployments keep their key.
- `AUTH_HMAC_SECRET` (session cookies + Fosite HMAC): from env (base64) or generated secret
  file in the data directory (existing behaviour).

### 2.3 Key rotation (SR-4, NFR "no abrupt invalidation")

1. Rotation trigger: `KEY_ROTATION_INTERVAL` elapsed since active-key creation (default 90 d;
   `0` disables) — checked at startup and periodically by the sweeper. A manual-rotation ops
   command is deferred to F-007; v1 rotates on interval only.
2. On rotation: generate new key → new key becomes `active`; previous key moves to `retiring`
   with `not_after = now + ACCESS_TOKEN_TTL + 2×CLOCK_SKEW` (every outstanding token signed by
   it stays verifiable until it has expired).
3. JWKS (§1.8) serves `active` + all `retiring` keys; `/mcp` verification accepts any key in
   that set, selected by `kid`. New tokens are signed only with `active`.
4. Keys past `not_after` are removed from the manifest and their files deleted by the sweeper.
5. Rotation MUST be atomic (manifest rewrite via temp file + rename); a crash mid-rotation
   leaves the old manifest intact.

### 2.4 Revocation semantics (completes §1.9) — **done, F-005b**

- Token records carry their grant's **request ID**; revocation deletes **all records of the
  grant** (refresh revocation therefore cascades to its access tokens). This fixed a latent
  upstream bug where the store deleted by request ID as if it were a signature (a no-op).
- `/mcp` checks **record presence** (lookup by the JWT's signature segment) after stateless
  validation; missing record → `401 invalid_token`; a store error during the check → `503`
  (fail-closed, SR-3 — never "assume not revoked").
- Introspection (§1.10) reports `active: false` for anything deleted.

### 2.5 Migrations & versioning

- A `schema_version` marker (SQLite: table; bbolt: `meta:schema_version` key) is written on
  first run and checked at startup; an unknown newer version → fail-fast with a clear error.
- SQLite schema changes ship as GORM auto-migrations **plus** a documented entry in the
  release notes (F-007); bbolt value-format changes bump the schema version and provide an
  in-place upgrade path. Downgrades are unsupported (documented).

---

## 3. Configuration & deployment

12-factor (GR-3): every option is an env var with a CLI-flag twin (flag wins). **Fail-fast
validation at startup** (CODING-STANDARDS §7): invalid values abort with a clear message —
never silent defaults for malformed input. Booleans accept `true|1`/`false|0`.

### 3.1 Existing options (post-F-011 state — unchanged contracts)

| Env (flag) | Default | Notes / validation |
|---|---|---|
| `EXTERNAL_URL` (`-e`) | `http://localhost` | Public base URL = issuer (§0). MUST be absolute, no path/query/fragment. `http://` only sensible behind TLS-terminating proxy — startup WARNING when scheme is http and host is non-loopback. |
| `LISTEN` | `:80` | HTTP listen address. |
| `TLS_LISTEN` | `:443` | TLS listen address (when TLS enabled). |
| `NO_AUTO_TLS`, `TLS_HOST` (`-H`), `TLS_DIRECTORY_URL`, `TLS_ACCEPT_TOS`, `TLS_CERT_FILE`, `TLS_KEY_FILE` | — | Built-in ACME / manual cert options (GR-1). Cert+key must be set together; `TLS_HOST` conflicts with manual certs (existing checks). |
| `DATA_PATH` (`-d`) | `./data` (image: `/data`) | Data directory (§2.2). Created if absent. |
| `REPOSITORY_BACKEND` | `local` | `local` (bbolt) or `sqlite`. |
| `REPOSITORY_DSN` | — | Required iff backend is `sqlite`. |
| `PASSWORD` / `PASSWORD_HASH` | — | Self-contained login (§1.12). At least one auth backend MUST be configured (password, or OIDC, or — after F-005 — passkey); otherwise startup fails. `PASSWORD` is bcrypt-hashed at startup; prefer `PASSWORD_HASH`. |
| `OIDC_CONFIGURATION_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPES`, `OIDC_USER_ID_FIELD`, `OIDC_PROVIDER_NAME`, `OIDC_ALLOWED_USERS`, `OIDC_ALLOWED_USERS_GLOB`, `OIDC_ALLOWED_ATTRIBUTES`, `OIDC_ALLOWED_ATTRIBUTES_GLOB` | off | Generic OIDC login backend — **off by default**, active only when URL + ID + secret are all set (decision F-011). |
| `NO_PROVIDER_AUTO_SELECT` | `false` | Disable auto-redirect to a sole login provider. |
| `PROXY_BEARER_TOKEN` | — | Upstream credential injection (FR-6). |
| `PROXY_HEADERS` | — | Static upstream headers `H1:V1,H2:V2`. |
| `PROXY_FORWARD_AUTHORIZATION` | `false` | Forward the validated client bearer upstream. |
| `HEADER_MAPPING`, `HEADER_MAPPING_BASE` | — / `/userinfo` | Claim→header mapping (§1.11.5). |
| `TRUSTED_PROXIES` | — | IPs/CIDRs allowed to set `X-Forwarded-*` (GR-1). Empty = none trusted. |
| `HTTP_STREAMING_ONLY` | `false` | Reject GET-SSE with 405 (§1.11.3). |
| `AUTH_HMAC_SECRET` | generated | Base64; session/HMAC secret (§2.2). |
| positional args | — | Upstream MCP target: `http(s)://…` URL or a stdio command. Exactly one target in v1. |

### 3.2 New options (targets specified in parts 1–2; implemented in F-005)

| Env | Default | Contract |
|---|---|---|
| `ACCESS_TOKEN_TTL` | `1h` | §1.7 `exp`. Go duration; 1 m–24 h. **Done (F-005b).** |
| `AUTH_CODE_TTL` | `10m` | §1.5. 30 s–1 h. **Done (F-005b).** |
| `REFRESH_TOKEN_TTL` | `720h` (30 d) | §2.1. `0` disables the refresh grant (also removed from metadata). **Done (F-005b).** |
| `CIMD_ENABLED` | `true` | §1.3. Disabling leaves DCR-only (not recommended). **Done (F-005c).** |
| `CIMD_FETCH_TIMEOUT` / `CIMD_MAX_SIZE` / `CIMD_CACHE_TTL` | `5s` / `65536` / `1h` | §1.3 resolution limits (1s–1m / 1KiB–1MiB / 1m–24h). **Done (F-005c).** |
| `DCR_ENABLED` | `true` | §1.4. `false` removes `registration_endpoint` from metadata and 404s `/.idp/register`. At least one of CIMD/DCR must stay enabled. **Done (F-005c).** |
| `DCR_CLIENT_TTL` | `720h` (30 d) | §1.4/§2.1. `0` disables expiry. **Done (F-005c).** |
| `DCR_MAX_CLIENTS` | `100` | §1.4 cap; `0` = unlimited (not recommended). **Done (F-005c).** |
| `RATE_LIMIT_REGISTER` / `RATE_LIMIT_TOKEN` / `RATE_LIMIT_LOGIN` | `10/m` / `60/m` / `10/m` | Per-client-IP token buckets (SR-5/SR-6). `0` disables (not recommended). Honour `TRUSTED_PROXIES` for client-IP extraction. |
| `LOGIN_LOCKOUT_THRESHOLD` / `LOGIN_LOCKOUT_DURATION` | `10` / `15m` | Per-account lockout after N consecutive failures (SR-6); uniform error either way. |
| `KEY_ALG` | `RS256` | `RS256` or `ES256` (§2.2); switching triggers a rotation (§2.3). |
| `KEY_ROTATION_INTERVAL` | `2160h` (90 d) | §2.3; `0` disables automatic rotation. |
| `CLOCK_SKEW` | `30s` | §1.11.1 validation tolerance. |
| `OIDC_DISCOVERY_MIRROR` | `false` | §1.2 `openid-configuration` mirror. |

### 3.3 Deployment artefacts & compatibility

- **`docker-compose.example.yml`** (repo root): gateway + example upstream, placeholder env
  values only (GR-5) — see file.
- **`Dockerfile`**: existing (pinned `golang:1.26-bookworm` builder, distroless-ish runtime,
  entrypoint `mcp-oauth-gateway`), unchanged by this spec.
- **Backward compatibility (NFR):** existing env keys keep working; renames ship with the old
  key still honoured for ≥1 minor release plus a startup deprecation warning. Config removed
  in F-011 (`GOOGLE_*`, `GITHUB_*`) is gone pre-release (no compatibility obligation).
- **Health/observability:** `/healthz` (§1.13); structured JSON logs to stdout with
  `login_ok`, `login_fail`, `token_issued`, `register`, `rate_limited`, `revoked` events
  (SR-8) — field names fixed in F-005 to stay generic (GR-4).

