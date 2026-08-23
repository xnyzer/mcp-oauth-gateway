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

This is install mode A; both modes and the full option reference live in the
[README](../README.md#install-modes) and [`.env.example`](../.env.example). The rows below
are the verification-relevant subset.

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

**Client list and kill switch (F-024)** — session-gated, so this is a browser check:
- [ ] `/.auth/settings` lists every client that holds access. A **CIMD client appears even though
  it has no stored registration** — the case an implementation built on client records gets wrong.
- [ ] Rotation history is aggregated: a long-lived connection shows **one row with a refresh
  count**, not one row per rotation.
- [ ] A registration with no tokens is listed too, with `0 authorizations` and *never*.
- [ ] **Revoke client** → the client's next request answers `401` within seconds, not after
  `ACCESS_TOKEN_TTL`. Visible in the log: the `revoked` event carries the record count, and the
  `/mcp` line right after it carries the client's user agent and `401`.
- [ ] Re-connecting succeeds and goes through the consent page. It asks for the passkey when no
  operator session is open; with a live session the consent step alone stands between the client
  and a new token, by design (SPEC §1.5).
- [ ] After a revoke the operator is **still logged in** and the passkey list is untouched —
  including after *Revoke everything*.

## 6. Close-out

- [ ] All rows recorded in `private/`.
- [x] Re-verify against the **final MCP authorization spec 2026-07-28**: walk
  [`MCP-CONFORMANCE.md`](MCP-CONFORMANCE.md) and confirm each row still holds. The watch item that
  used to live here closed with F-017; keeping the row means the table gets re-walked on every
  deployment rather than trusted indefinitely.
  *Done 2026-08-21 for v0.2.0/v0.2.1 — every authorization and transport row held except the one
  already recorded as unmet (`Origin`, F-021).*

### Force a fresh authorization (learned in F-017d, mechanised in F-024)

Verifying that clients pick CIMD needs a **new** authorization, and an already-connected client
will not produce one. None of the obvious routes work:

- Claude refuses a second connector for a URL it already has.
- Removing and re-adding the connector reuses the stored credentials — the gateway sees no
  authorization request at all.
- Waiting for `DCR_CLIENT_TTL` never fires: the registration is refreshed on every token issuance
  (SPEC §2.1), so one in active use never expires.

**What works: revoke the client in `/.auth/settings`.** Open the settings page, find the client
under *Connected clients*, and press **Revoke client**. Its registration and every token it holds
are deleted in one transaction, so the next request the client makes is rejected and the one after
that starts a fresh authorization. Nothing has to be stopped, edited or restarted.

> Until F-024 the only way was to stop the gateway and edit its data store by hand with a
> purpose-built tool. That procedure has been removed from this runbook: the button replaces it,
> and hand-editing a live auth store is not something to keep on file as a routine step.

This matters because a verification that only exercises an **already-connected** client passes
even when the gateway is broken for every new one — which is exactly what F-023 turned out to be.
