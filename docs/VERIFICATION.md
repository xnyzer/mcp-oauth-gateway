# Live verification runbook (F-006c)

End-to-end verification of a deployed gateway against real clients. Server-side checks are
scripted; the client checks (passkey in real browsers, Claude web/iOS) are manual. Replace every
`<placeholder>` with your own values — **keep real hostnames, IPs and tokens out of the repo**
(operational specifics belong in `private/`, which is gitignored).

Topology assumed here (the common one): a TLS-terminating reverse proxy in front of the gateway,
which runs plain HTTP internally and forwards to a single upstream MCP server.

```
Internet → reverse proxy (public TLS for <mcp.example.com>) → gateway :<port> → upstream MCP
```

## 1. Prerequisites

- A publicly reachable host with a **publicly-trusted TLS certificate** terminated by your reverse
  proxy (Caddy, nginx, Traefik, zoraxy, …). Claude connects from Anthropic's cloud
  (egress **160.79.104.0/21**), so a geo/IP firewall that blocks it fails **silently** — allow it.
- The upstream MCP server's URL, transport (SSE / streamable-HTTP) and bearer token, if any.
- An operator **bcrypt** password hash (`$2a$`/`$2b$`/`$2y$`, cost 10–12). Generate without
  putting the plaintext in your shell history:
  ```bash
  htpasswd -nBC 12 "" | tr -d ':\n'; echo                 # apache2-utils
  docker run --rm -it httpd:2.4-alpine htpasswd -nBC 12 "" | tr -d ':\n'; echo   # no local tools
  ```

## 2. Configuration (behind a TLS-terminating proxy)

| Env | Value | Why |
|---|---|---|
| `EXTERNAL_URL` | `https://<mcp.example.com>` | Public base URL = OAuth issuer. `https` even though the gateway serves HTTP internally (the proxy does TLS). |
| `NO_AUTO_TLS` | `true` | **Required.** With an `https` non-loopback `EXTERNAL_URL` the gateway otherwise auto-enables ACME and refuses to start (`TLS host is auto-detected …`). The proxy already terminates TLS. |
| `LISTEN` | `:<port>` (e.g. `:8080`) | Plain-HTTP listen address. Use a non-privileged port if the container runs non-root. |
| `TRUSTED_PROXIES` | `<proxy-ip-or-cidr>` | Bare IPs and CIDR ranges both work (bare IPs are normalised to `/32`·`/128` since F-007a; builds before that abort on a bare IP — use CIDR there). Set it so the real client IP / `X-Forwarded-Proto` from the proxy are honoured (and the session cookie gets `Secure`). |
| `PROXY_TARGET` (positional arg) | `http://<upstream-host>:<port>` | **Host-only** when the upstream MCP path mirrors the client path (e.g. both `/mcp`): the gateway joins the inbound path onto the target, so a target ending in `/mcp` + an inbound `/mcp` would double to `/mcp/mcp`. |
| `PROXY_BEARER_TOKEN` | `<upstream-token>` | Injected toward the upstream; the client never sees it. Omit if the upstream is unauthenticated. |
| `PASSWORD_HASH` | `<bcrypt-hash>` | Operator login. See the Compose pitfall below. |
| `DATA_PATH` | `/data` | Keys + token store (volume). Back this up. |

The client's **connector URL** is `https://<mcp.example.com>/<mcp-path>` (e.g. `/mcp`) — the path
your upstream serves MCP on.

### Common pitfalls (learned the hard way)

- **Docker Compose interpolates `env_file` values**, so a bcrypt hash's `$` gets eaten
  (`"…" variable is not set`). Escape every `$` as `$$` in the env file, or verify the value inside
  the container: `docker compose exec -T <svc> printenv PASSWORD_HASH | wc -c` should be 60.
- **Non-root + a named volume**: a root-owned named volume isn't writable by a non-root UID. Use a
  **bind mount** to a host dir owned by the run user and set `user: "<uid>:<gid>"`, or `chown` the
  volume.
- **Bare-IP `TRUSTED_PROXIES`** aborts startup on builds before F-007a — use CIDR (`/32`,
  `/128`) there; current builds accept both forms.

## 3. Deploy

Any method works (single static binary, systemd, container). A minimal non-root container:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY gateway /usr/local/bin/mcp-oauth-gateway
ENTRYPOINT ["/usr/local/bin/mcp-oauth-gateway"]
```
```yaml
services:
  mcp-oauth-gateway:
    build: .
    restart: unless-stopped
    user: "<uid>:<gid>"
    ports: ["<port>:<port>"]        # bind all interfaces if the proxy is on another host
    env_file: [gateway.env]
    command: ["http://<upstream-host>:<port>"]
    volumes: ["./data:/data"]
```
Point the reverse proxy at `<gateway-host>:<port>` and **enable streaming / disable response
buffering** for the MCP route (MCP uses SSE / streamable-HTTP), forwarding `Host` and
`X-Forwarded-Proto`.

## 4. Server-side verification (scripted)

From anywhere that can reach the public URL:

- **Discovery** (all `200`, self-consistent):
  ```bash
  for p in /.well-known/oauth-protected-resource /.well-known/oauth-authorization-server /.well-known/jwks.json; do
    curl -s -o /dev/null -w "$p -> %{http_code}\n" https://<mcp.example.com>$p; done
  ```
  PRM `resource` must equal the issuer; AS metadata `code_challenge_methods_supported` = `["S256"]`,
  `authorization_response_iss_parameter_supported` = `true`.
- **Fail-closed:** `POST /<mcp-path>` with no token → `401` + `WWW-Authenticate: Bearer
  resource_metadata="…"`.
- **Full round-trip:** DCR-register a client → `/.idp/auth` (login + consent) → `/.idp/token` →
  `POST /<mcp-path>` with the bearer + an MCP `initialize` → the upstream's `serverInfo` comes back
  (proves credential injection + streaming through the proxy). A cookie-jar curl script or the
  Claude connector (below) both exercise this.
- **Rate-limit / revocation:** exceed `RATE_LIMIT_*` → `429` + `temporarily_unavailable`; `POST
  /.idp/revoke` a token (client-authenticated) → the proxy then denies it (`401`).

## 5. Client verification (manual)

Record each row pass/fail with evidence in `private/`.

**Passkey / WebAuthn** (bootstrap with the password first, then enrol in `/.auth/settings`):
- [ ] Enrol + login in **Safari** (desktop)
- [ ] Enrol + login in **Chrome** (desktop)
- [ ] Enrol + login on **iOS** (Safari / platform authenticator)
- [ ] (Optional, after passkey is confirmed) disable the password fallback in settings — the env
  `PASSWORD_HASH` stays as a rescue; deleting all passkeys auto-reactivates the password.

**Claude — web connector first (easier to debug), then iOS:**
- [ ] Add `https://<mcp.example.com>/<mcp-path>` as a **custom connector** in Claude web. Complete
  the OAuth flow (this exercises **real CIMD**): operator login → consent → connected.
- [ ] Claude lists and successfully calls an upstream tool.
- [ ] Repeat on **Claude iOS**.

**Negative checks against the live endpoint:**
- [ ] No token → `401`. Tampered token → `401`. A revoked token → `401`. (Replay of a consumed
  auth code → `invalid_grant`.)

## 6. Close-out

- [ ] All rows recorded in `private/`.
- [ ] Re-verify against the MCP authorization spec **2026-07-28 RC** if released — otherwise this
  stays on the F-007 release gate (REQUIREMENTS §0).
