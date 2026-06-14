# Threat Model — mcp-oauth-gateway

> STRIDE-oriented, kept concise. Refine alongside the implementation. The gateway sits on a
> **public trust boundary** (it is internet-reachable so vendor clouds can reach it), so the
> auth code is security-critical.

## Trust boundaries
1. Public internet → gateway (OAuth + discovery + `/mcp`). **Hostile.**
2. Gateway → upstream MCP server (internal). Trusted-ish; still authenticated (defense-in-depth).
3. Operator/admin (single user) login.

## Assets
- Upstream MCP server and the data behind it.
- Access/refresh tokens and the signing key (JWKS private key).
- The upstream credential (e.g. static bearer) injected by the gateway.
- The single user's login credential (passkey/password).

## Threats & mitigations (STRIDE)
| Threat | Vector | Mitigation (req.) |
|---|---|---|
| **Spoofing** | Forged/replayed tokens | OAuth 2.1, JWT signature + `aud`/`iss`/`exp` checks (SR-4); fail-closed (SR-3) |
| **Tampering** | Modified requests/tokens | TLS (SR-2); signed tokens; integrity checks |
| **Repudiation** | No audit trail | Structured auth-event logging (SR-8) |
| **Info disclosure** | Token/secret leak | TLS; no secrets in logs (SR-8); upstream credential never exposed to client (FR-6); no third-party TLS termination |
| **DoS** | `/register`,`/token`,login flooding | Rate-limiting, auto-expiry + cap on DCR clients (SR-5), login lockout (SR-6); lean surface (SR-10) |
| **Elevation** | Auth bypass via gateway bug | Vetted OAuth lib (SR-1); fail-closed (SR-3); defense-in-depth — upstream auth still required, internal services not exposed (SR-7) |

## Accepted risks (by design)
- **Open `/register` endpoint** (DCR is open per spec) — gated by the user-login step; abuse
  bounded by SR-5.
- **Public reachability of `/mcp`** — required for cloud-originated clients; protected by OAuth +
  defense-in-depth.

## Notable caveats
- End-to-end behavior against specific clients (e.g. Claude iOS) is **not yet verified** — treat
  as integration risk; iterative live testing required (web client first, then mobile).
- Spec is fast-moving (DCR vs CIMD; client behaviors) — re-verify requirements before release.
- A self-written gateway owns auth-server security; mandatory pre-release **security review** and
  vetted-library use (SR-1) are non-negotiable.
