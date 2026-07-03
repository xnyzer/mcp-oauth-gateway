# Requirements — mcp-oauth-gateway

> Status: draft. This is the **intent-level** source of truth; the implementable contracts
> (endpoints, schemas, data model, config) live in **`SPEC.md`** (F-004). The implementation
> base is a fork of `sigbit/mcp-auth-proxy` (see PROGRESS F-008). Generic by design:
> **no deployment-specific or personal details.**

## 0. Verified background (mid-2026; re-verify, fast-moving area)
- OAuth-requiring MCP clients (notably Claude's apps) mandate **OAuth 2.1 + PKCE/S256**. A
  **static bearer token is not accepted**.
- The MCP authorization spec **2025-11-25** makes **CIMD** (Client ID Metadata Document) the
  **recommended** client-registration mechanism (SHOULD) and **deprecates DCR** (RFC 7591 —
  MAY, fallback only). Claude supports both and prefers CIMD → this gateway is **CIMD-first
  with DCR as a deprecated fallback** (decision F-003, see `PROGRESS-ARCHIVE.md`).
- The same spec revision recommends **RFC 9207** (`iss` parameter in the authorization
  response, SHOULD) and allows **OIDC Discovery** as an alternative to RFC 8414 server
  metadata; **RFC 8707** audience-binding remains a MUST.
- Claude connects to remote/custom connectors **from the vendor's cloud**, not the end-user
  device → the server must be reachable over the **public internet** with a **publicly-trusted
  TLS certificate**, and must publish **RFC 9728 Protected Resource Metadata** and **RFC 8414
  Authorization Server Metadata** (or OIDC Discovery).
- No maintained, self-hosted, no-third-party, lightweight gateway covers this gap today — hence
  this project (build-vs-fork decision: see PROGRESS F-001).
- **Watch item:** the next MCP spec release candidate is dated **2026-07-28** — re-verify these
  requirements against it before any release.

## 1. Scope
**In scope:** a gateway process that terminates MCP-spec OAuth toward the client and forwards
authenticated MCP traffic to a single configured upstream MCP server (streamable HTTP).

**Out of scope (initially):** modifying the upstream MCP server; acting as a general-purpose
IdP; multi-tenant SaaS. (Multi-user must not be architecturally precluded.)

## 2. Functional requirements (FR)
- **FR-1 Discovery:** serve `GET /.well-known/oauth-protected-resource` (RFC 9728) and
  `GET /.well-known/oauth-authorization-server` (RFC 8414); optionally mirror the latter as
  **OIDC Discovery** (`GET /.well-known/openid-configuration`) for clients that only probe
  that path.
- **FR-2 Client registration — CIMD-first:** accept **CIMD** client IDs (HTTPS-URL client IDs
  resolving to a Client ID Metadata Document) as the primary mechanism; keep **DCR**
  (`POST /register`, RFC 7591) as a **deprecated fallback** for backward compatibility
  (decision F-003). CIMD avoids persisting registrations; DCR registrations remain subject to
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

## 3. Generic / portability requirements (GR)
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

## 4. Security requirements (SR)
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

## 5. Non-functional requirements
- Actively maintainable; pinned base image; SemVer; data/schema migrations if persistence is used;
  **backward-compatible config changes** (old env keys keep working or have a deprecation path).
- **Key rotation** without invalidating in-flight sessions abruptly.
- Backup/restore of signing keys + client registrations.
- Tests/CI (OAuth + MCP conformance) so others can trust it.
- End-user docs: how to front an MCP server and add it as a client connector.

## 6. Decisions (rationale in PROGRESS-ARCHIVE.md)
- **Build vs fork** → hard fork of `sigbit/mcp-auth-proxy` (F-001).
- **Language + OAuth library** → Go + Ory Fosite (F-002).
- **Client registration** → CIMD-first, DCR as deprecated fallback (F-003).
- **Persistence** → bbolt (default) / SQLite (F-008c).
- Still open: multi-user evolution (single user now; must not be architecturally precluded, §1).
