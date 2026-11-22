---
id: F-004
title: Complete the spec (make it implementable)
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-07-03
depends-on:
superseded-by:
---

# F-004 — Complete the spec (make it implementable)

## History

### F-004 — Complete the spec (make it implementable) — DONE 2026-07-03

**Problem:** The requirements described intent but not the implementable contract (exact
endpoints, schemas, data model, config).

**Idea:** Turn the requirements into precise, RFC-conformant contracts.

**Dependencies:** F-002, F-003, F-009 (all DONE).

**Prep decisions (user-approved):** contracts live in a new root-level **`SPEC.md`**
(REQUIREMENTS stays intent-level); the fork's **`/.idp/*` endpoint paths are kept** (clients
discover paths via RFC 8414/9728 metadata; the prefix avoids collisions with proxied upstream
paths).

#### F-004a — API contracts (SPEC.md §0–§1)
- §0 conventions: issuer = `EXTERNAL_URL` **normalized without trailing slash** everywhere
  (code currently ambiguous — pinned for F-005); RFC 6749 error format; normative
  **public-path list** (SR-7); endpoint overview table (RFC + FR mapping + status).
- Contracts with per-section **Delta notes** (current fork behaviour vs target): complete PRM
  (RFC 9728) and AS metadata (RFC 8414 incl. `jwks_uri`/`revocation_endpoint`/
  `introspection_endpoint`/`authorization_response_iss_parameter_supported`; optional OIDC
  Discovery mirror), **CIMD resolution contract** (HTTPS-URL client IDs, 5 s/64 KiB/no-redirect
  fetch limits, SSRF guards rejecting private/link-local/metadata ranges, mandatory public
  client + PKCE, positive/negative caching), DCR fallback with SR-5 hardening (TTL 30 d
  refreshed on use, cap 100, rate limit, redirect-URI validation), authorize/token with PKCE
  S256 for **all** clients + RFC 9207 `iss` + RFC 8707 `resource`→`aud` (gateway = sole
  resource; other values → `invalid_target`), refresh-token rotation, JWKS with rotation
  window, **`/revoke`** (RFC 7009, no token-existence oracle), introspection (client-auth
  required), **`WWW-Authenticate` contract on the proxy 401** (flagged as the key
  client-compatibility delta), auth pages incl. SR-6 targets, `/healthz`.
- Token-claims table (FR-5/SR-4): `iss`/`sub`/`aud`/`exp`/`iat`/`nbf` + target
  `jti`/`client_id`/`scope`; verification rules on the proxy path.

#### F-004b — Data model & key management (SPEC.md §2)
- Entity table (10 entities) with key fields, lifetimes, and bbolt/SQLite mapping onto the
  existing `Repository` interface — including new: **CIMD cache** (in-memory acceptable),
  **revoked-`jti` set** (TTL-bounded), **user** and **passkey credential** schemas (implemented
  in F-005). Expiry sweeper contract: lookups treat expired records as absent (fail-closed).
- Signing keys in the data directory (`keys/<kid>.pem` PKCS#8 0600 + atomic `manifest.json`);
  legacy single-key migration path; `AUTH_HMAC_SECRET` unchanged.
- **Rotation:** interval-triggered (default 90 d), new key active, old key retiring with
  `not_after = ACCESS_TOKEN_TTL + 2×CLOCK_SKEW` (no abrupt session invalidation — NFR);
  JWKS serves active + retiring; atomic manifest rewrite.
- **Revocation semantics:** stateless JWT validation first, then deny-list check; store error
  during check → 503 fail-closed; refresh-token revocation cascades to the grant's access
  tokens.
- Schema-version marker + migration/downgrade policy.

#### F-004c — Config schema & deployment (SPEC.md §3 + examples)
- Full env/flag tables: existing options (post-F-011) with validation notes, plus 16 new
  target options (`ACCESS_TOKEN_TTL`, `AUTH_CODE_TTL`, `REFRESH_TOKEN_TTL`, `CIMD_*`, `DCR_*`,
  `RATE_LIMIT_*`, `LOGIN_LOCKOUT_*`, `KEY_ALG`, `KEY_ROTATION_INTERVAL`, `CLOCK_SKEW`,
  `OIDC_DISCOVERY_MIRROR`) with defaults and fail-fast validation.
- **`docker-compose.example.yml`** (placeholders only, GR-5; reverse-proxy TLS assumed,
  built-in ACME noted); Dockerfile unchanged; backward-compatibility policy (old env keys ≥1
  minor release + deprecation warning); structured-log event names fixed.
- `REQUIREMENTS.md` header now marks itself intent-level and points to SPEC.md; `README.md`
  docs list and `CLAUDE.md` key documents updated.

**Verification:** compose YAML parses; all referenced files exist; FR-1–FR-9 coverage and all
10 F-001 gap-list items grep-verified in SPEC.md; secrets scan clean (placeholders only).

**Files changed:** new `SPEC.md` (~480 lines), new `docker-compose.example.yml`; edited
`REQUIREMENTS.md` (header), `README.md` (docs list), `CLAUDE.md` (+ `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` bookkeeping).
