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
- End-to-end behavior against real clients is **verified** (F-006c): Claude web **and** iOS both
  connect via live CIMD, and passkey enrol+login works in Safari (desktop) + iOS (iCloud
  Keychain). Residual integration risk remains for untested clients and future client/spec
  changes — re-verify on each.
- Spec is fast-moving (DCR vs CIMD; client behaviors). v0.1.x is verified against the MCP
  **2026-07-28 authorization spec release candidate** (all six authorization SEPs satisfied,
  F-007e); the **final spec (due 2026-07-28) has not published yet** — a re-check against it is a
  standing open item (`PROGRESS.md`).
- A self-written gateway owns auth-server security; the mandatory pre-release **security review**
  was completed (F-006b: 0 crit / 1 high / 9 med / 19 low — all fixed across F-006b/F-007/F-012)
  and vetted-library use (SR-1, Ory Fosite) is non-negotiable. The review was an **internal**
  adversarial audit, not an external third-party pentest; security is maintained continuously
  (Dependabot + weekly `govulncheck`), not "finished".
