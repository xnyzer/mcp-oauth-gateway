# mcp-oauth-gateway

A self-hosted **OAuth 2.1 gateway** that puts spec-compliant **MCP authorization** in front
of *any* MCP server — including servers that only support a static bearer token, or no auth
at all — so that **OAuth-only MCP clients** (e.g. Claude's web/desktop/mobile apps) can
connect, **without depending on a third-party identity provider**.

> **Status:** feature-complete against [`SPEC.md`](SPEC.md), hardened by an adversarial
> security audit (all critical/high/medium findings fixed), and verified live end to end
> against **Claude web and iOS**. Verified against the **final MCP authorization spec
> 2026-07-28** (conformance recorded in [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md));
> pre-1.0 while the project
> settles.

## Why

The MCP authorization spec requires remote MCP servers to be OAuth 2.1 Authorization Servers
that support client registration — **CIMD** (Client ID Metadata Documents; recommended since
spec 2025-11-25) with **Dynamic Client Registration** as a deprecated fallback — plus
discovery metadata (RFC 9728 / RFC 8414). Most self-hosted MCP servers only offer a static
bearer token — which OAuth-only clients reject. Existing OAuth gateways either mandate a
hosted identity provider, are unmaintained, or bundle a heavy stack. This project fills the
gap: **maintained, self-hosted, no mandatory third party, lightweight, reverse-proxy- and
upstream-agnostic.**

**What it is not.** It does not modify the MCP server it fronts, and it is not a
general-purpose identity provider or a multi-tenant SaaS. It authenticates a **single
operator**; multi-user is not supported today, and the design deliberately does not preclude
it later.

## Features

- **Full OAuth 2.1 AS surface:** discovery (RFC 9728 PRM + RFC 8414 AS metadata), CIMD-first
  client identification with DCR fallback, authorize + token with **PKCE S256 only**,
  RFC 9207 `iss`, RFC 8707 `resource` binding, refresh tokens, revocation (RFC 7009) and
  introspection.
- **Self-contained operator login:** password (bcrypt) to bootstrap, **passkey/WebAuthn**
  preferred (password fallback can be disabled); optional generic OIDC backend.
- **Fail-closed proxy:** every non-public path requires a valid, unrevoked, audience-bound
  JWT; upstream credentials are injected server-side and never reach the client.
- **Key management:** RS256/ES256, automatic interval rotation with a retiring window
  (outstanding tokens stay valid), multi-key JWKS, manual `rotate-key` command.
- **Abuse protection:** per-IP rate limits on all public endpoints, login lockout,
  structured auth events (JSON logs, no secrets).
- **Single non-root container** (distroless, digest-pinned), 12-factor env config,
  `/healthz` + built-in Docker healthcheck.

## Quickstart (Docker Compose)

Prerequisites: a host with Docker, a public DNS name for the gateway, and the MCP server you
want to front (the "upstream").

```bash
git clone https://github.com/xnyzer/mcp-oauth-gateway.git && cd mcp-oauth-gateway
./setup.sh                                  # asks for public URL + operator password, writes .env
cp docker-compose.example.yml docker-compose.yml
# edit docker-compose.yml: image version, your upstream service
# edit .env: pick install mode A or B (below), set PROXY_BEARER_TOKEN if your upstream needs it
docker compose up -d
```

Verify: `curl https://<your-host>/.well-known/oauth-authorization-server` returns metadata,
and `curl -X POST https://<your-host>/<mcp-path>` without a token returns `401` with a
`WWW-Authenticate` challenge (fail-closed works).

Every configuration option is documented in [`.env.example`](.env.example) and the
[reference below](#configuration-reference).

## Install modes

TLS is required (Claude only connects to `https`). Choose one:

### Mode A — behind your own TLS-terminating reverse proxy

Your proxy (Caddy, nginx, Traefik, …) owns the certificate and forwards plain HTTP to the
gateway.

```dotenv
EXTERNAL_URL=https://mcp.example.com   # the public URL, https even though the gateway serves http
NO_AUTO_TLS=true                       # required: stops the gateway from trying ACME itself
TRUSTED_PROXIES=<proxy-ip-or-cidr>     # so the real client IP / X-Forwarded-Proto are honoured
```

Point the proxy at the published port (`127.0.0.1:8080` in the example compose) and make sure it

- forwards `Host` and `X-Forwarded-Proto`, and
- **disables response buffering / enables streaming** for the MCP route (MCP uses SSE /
  streamable HTTP — a buffering proxy breaks it).

### Mode B — standalone with built-in ACME (no reverse proxy)

The gateway terminates TLS itself with Let's Encrypt certificates:

```dotenv
EXTERNAL_URL=https://mcp.example.com
TLS_HOST=mcp.example.com
TLS_ACCEPT_TOS=true
```

Publish ports `80` and `443` onto the container's non-privileged listeners in
`docker-compose.yml` (port 80 must stay reachable for the ACME HTTP-01 challenge):

```yaml
    ports:
      - "80:8080"
      - "443:8443"
```

Bring-your-own-certificate (`TLS_CERT_FILE`/`TLS_KEY_FILE`) works too — see
[`.env.example`](.env.example).

### Firewall note (read this — failures are silent)

Claude's cloud connects from Anthropic's egress range **`160.79.104.0/21`**. A firewall or
geo/IP block that drops this range makes the Claude connector fail **silently** — the OAuth
flow completes in your browser, but Claude's backend can never reach the MCP endpoint. Allow
that range inbound to your public URL.

### CIMD note for datacenter deployments (also a silent failure)

To identify a client by CIMD, the gateway fetches that client's metadata document **outbound**
from your host. Claude's document
(`https://claude.ai/oauth/mcp-oauth-client-metadata`) is reported to answer server-side fetches
from **datacenter IP ranges** with a Cloudflare challenge (HTTP 403) instead of the document
([anthropics/claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650)). Nothing
a server-side OAuth implementation can work around — passing the check requires running
JavaScript.

The symptom is an error page reading `invalid_client … The requested OAuth 2.0 Client does not
exist.` after you click connect. Check your gateway's log: a line `CIMD resolution failed` names
the actual cause. If it is the fetch, set **`CIMD_ENABLED=false`** and restart — the gateway then
stops advertising CIMD, clients fall back to Dynamic Client Registration, and the connector works
again. That is a workaround, not a destination: the MCP spec deprecates DCR.

Home and office connections are typically unaffected; this bites VPS and cloud hosts.

### Origin validation and `EXTERNAL_URL`

The gateway refuses a request whose `Origin` header names anything other than the `EXTERNAL_URL`
origin, which is what stops a page loaded elsewhere from driving your gateway through the victim's
browser (DNS rebinding). A request **without** an `Origin` header always passes — server-side MCP
clients send none, so Claude and friends are unaffected by design.

**Browsers do send it, including on same-origin POSTs.** That is the point — but it also means
`EXTERNAL_URL` has to match what your browser address bar actually shows. If you reach the gateway
under a second hostname, by IP, or on a different port, the login and consent POSTs on `/.auth/*`
are refused with `403` and you cannot log in.

The gateway logs every rejection at WARN with both the offending and the expected origin, so one
look at `docker logs` names the cause. `ORIGIN_CHECK_ENABLED=false` turns the check off as a rescue;
the disabled state is logged at startup so it does not stay off by accident.

## Connect Claude

1. In Claude (web → *Settings → Connectors*, or the mobile apps), add a **custom connector**
   with the URL `https://<your-host>/<mcp-path>` — the path your upstream serves MCP on
   (commonly `/mcp`).
2. Claude starts the OAuth flow (via CIMD): log in with your operator password, review the
   consent screen (it shows the client's identity and requested scopes), optionally **give the
   connection a name** — the field is prefilled with the name the client gives itself — and
   authorize.
3. Claude lists the upstream's tools and can call them through the gateway.

Recommended hardening after the first login: open `https://<your-host>/.auth/settings`,
**enrol a passkey**, then disable the password fallback there (the `PASSWORD_HASH` env stays
as a break-glass rescue; deleting all passkeys re-activates password login).

The same page lists **connected clients** — by the name you gave them when authorizing, with the
client id beneath — showing how many authorizations each holds and when it was last active, and
revokes it: one client, one authorization, or everything at once. A revoke
takes effect on the client's next request rather than after the token's remaining lifetime. It does
not ban anyone: a revoked client can authorize again, which needs your login. Entries are per
client and per authorization, **not per device** — every device signed into the same client shares
one client id, and the gateway stores no device identity.

## Fronting an MCP server

The upstream target is the container command (a positional argument, not an env var):

```yaml
    command:
      - "http://mcp-upstream:3000/mcp"
```

- **Bearer-protected upstream:** set `PROXY_BEARER_TOKEN` — the gateway injects it toward
  the upstream; connecting clients never see it.
- **Unauthenticated upstream:** just omit `PROXY_BEARER_TOKEN`.
- **Path gotcha:** the gateway joins the *inbound* path onto the target. If your upstream
  serves MCP on the same path clients use (e.g. both `/mcp`), configure the target
  **host-only** (`http://mcp-upstream:3000`), otherwise the path doubles (`/mcp/mcp`).
- **stdio upstreams** (a command instead of a URL) are supported by the binary, but the
  container image ships **no interpreters** (no python/node). Run such servers as a separate
  HTTP service, or build a custom image on top of this one.

## Configuration reference

Every option is an env var with a CLI-flag twin (flag wins); malformed values abort startup.
Booleans accept `true|1` / `false|0`. See [`SPEC.md`](SPEC.md) §3 for the normative contracts.

### Core

| Env | Default | Description |
|---|---|---|
| `EXTERNAL_URL` | `http://localhost` | Public base URL = OAuth issuer. Absolute, no path/query/fragment. `http` on a non-loopback host logs a startup WARNING. |
| `LISTEN` | `:80` (image: `:8080`) | Plain-HTTP listen address. |
| `TLS_LISTEN` | `:443` (image: `:8443`) | TLS listen address (when TLS is enabled). |
| `DATA_PATH` | `./data` (image: `/data`) | Data directory: signing keys, token store, auto-generated secrets. **Back this up.** |
| `REPOSITORY_BACKEND` | `local` | `local` (embedded bbolt) or `sqlite`. |
| `REPOSITORY_DSN` | — | SQL DSN; required iff backend is `sqlite`. For a file DB use e.g. `file:/data/gateway.sqlite`. The gateway serialises writes (single connection) and enables WAL + a 5 s busy timeout, so point the DSN at a **persistent, non-shared** path on a filesystem that supports SQLite locking (a local volume, not a network share). |

### TLS

| Env | Default | Description |
|---|---|---|
| `NO_AUTO_TLS` | `false` | Disable built-in ACME. **Required in mode A** (https `EXTERNAL_URL` behind a proxy). |
| `TLS_HOST` | — | Hostname for ACME certificate provisioning (mode B). |
| `TLS_ACCEPT_TOS` | `false` | Accept the ACME terms of service (required with `TLS_HOST`). |
| `TLS_DIRECTORY_URL` | Let's Encrypt | Alternative ACME directory. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | Bring-your-own certificate (PEM); mutually exclusive with `TLS_HOST`. |

### Operator login

| Env | Default | Description |
|---|---|---|
| `PASSWORD_HASH` | — | bcrypt hash of the operator password (preferred; generate via `./setup.sh` or `htpasswd -nBC 12 "" \| tr -d ':\n'`). In a Compose `env_file`, escape `$` as `$$`. |
| `PASSWORD` | — | Plain-text alternative (hashed at startup). Prefer `PASSWORD_HASH`. |
| `NO_PROVIDER_AUTO_SELECT` | `false` | Don't auto-redirect to a sole login provider. |
| `OIDC_CONFIGURATION_URL` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | — | Optional OIDC login backend — active only when all three are set, and it **requires an allow-list** (below). |
| `OIDC_SCOPES` / `OIDC_USER_ID_FIELD` / `OIDC_PROVIDER_NAME` | `openid,profile,email` / `/email` / `OIDC` | OIDC details. |
| `OIDC_ALLOWED_USERS[_GLOB]`, `OIDC_ALLOWED_ATTRIBUTES[_GLOB]` | — | Who may log in through OIDC — see [OIDC allow-lists](#oidc-allow-lists). |

At least one login backend must exist at startup: a password, OIDC, or an already-enrolled
passkey — otherwise the gateway refuses to start. Passkeys are enrolled at `/.auth/settings`
after the first login.

#### OIDC allow-lists

Four settings decide which accounts of your OIDC provider may log in. **A login is allowed as
soon as one rule matches** — the rules are alternatives, so adding one widens access and never
narrows it.

| Setting | A rule matches … | Example |
|---|---|---|
| `OIDC_ALLOWED_USERS` | the user ID exactly | `alice@example.com,bob@example.com` |
| `OIDC_ALLOWED_USERS_GLOB` | the user ID against a pattern | `*@example.com` |
| `OIDC_ALLOWED_ATTRIBUTES` | a userinfo attribute exactly | `/groups=admins,/department=it` |
| `OIDC_ALLOWED_ATTRIBUTES_GLOB` | a userinfo attribute against a pattern | `/groups=team-*` |

The user ID is the userinfo field `OIDC_USER_ID_FIELD` points to. An attribute is named by a
JSON pointer (`/groups`, `/org/team`); if its value is a list, one matching entry is enough.

**OIDC needs at least one rule — without one the gateway refuses to start.** With no rule,
every account your provider authenticates would be the operator; with a provider anyone can sign
up to, that is everyone. So "everyone" is never the result of leaving the settings out or of an
empty variable. If it is really what you want, say so:

```
OIDC_ALLOWED_USERS_GLOB=*
```

**Pattern syntax.** A pattern describes the whole value, and matching is case-sensitive.

| Pattern | Matches |
|---|---|
| `*` | any run of characters, including none — **across `@`, `.` and `/` too** |
| `?` | exactly one character |
| `[abc]`, `[a-z]` | one character from the set or range |
| `[!a-z]` | one character **not** in the set or range |
| `{alice,bob}` | one of the alternatives; `{-eu,}` makes a part optional |
| `\*`, `\?` | the character itself |

So `*@example.com` allows every address of that domain — and nothing at `example.com.evil.example`,
because the pattern is anchored at both ends. Note what `*` does **not** promise: it has no
notion of a "local part", so a pattern is only as trustworthy as the claim it is matched
against. Use a claim your provider verifies.

**Commas separate entries**, so a comma inside a pattern is written `\,`:

```
OIDC_ALLOWED_USERS_GLOB={alice\,bob}@example.com,*@example.org
```

**An entry the gateway cannot read stops it at start-up**, with a message naming the setting
and the entry: an attribute rule that is not `/pointer=value`, a pattern that does not parse,
or a setting that is set but empty. A rule that was silently dropped would be a hole in an
authorization decision.

### Upstream / proxy

| Env | Default | Description |
|---|---|---|
| positional arg | — | The upstream MCP target: `http(s)://…` URL or a stdio command. Exactly one. |
| `PROXY_BEARER_TOKEN` | — | Bearer injected toward the upstream (omit for unauthenticated upstreams). |
| `PROXY_HEADERS` | — | Static upstream headers, `H1:V1,H2:V2`. |
| `PROXY_FORWARD_AUTHORIZATION` | `false` | Forward the validated client bearer upstream. |
| `HEADER_MAPPING` / `HEADER_MAPPING_BASE` | — / `/userinfo` | Claim→header mapping toward the upstream. |
| `TRUSTED_PROXIES` | — | IPs/CIDRs allowed to set `X-Forwarded-*` (bare IPs are normalised to `/32`·`/128`). Empty = none trusted. |
| `HTTP_STREAMING_ONLY` | `false` | Reject GET-SSE with 405 (streamable-HTTP-only upstreams). |

### Tokens, clients & keys

| Env | Default | Description |
|---|---|---|
| `ACCESS_TOKEN_TTL` | `1h` | Access-token lifetime (1m–24h). |
| `AUTH_CODE_TTL` | `10m` | Authorization-code lifetime (30s–1h). |
| `REFRESH_TOKEN_TTL` | `720h` | Refresh-token lifetime (1h–8760h); `0` disables the refresh grant. |
| `CLOCK_SKEW` | `30s` | Token time-claim validation leeway (0–5m). |
| `ORIGIN_CHECK_ENABLED` | `true` | Reject requests whose `Origin` header names a foreign origin (DNS rebinding, see the [note](#origin-validation-and-external_url)). A request **without** an `Origin` header always passes. |
| `CIMD_ENABLED` | `true` | Accept CIMD client IDs (HTTPS URLs). Setting `false` also removes it from the AS metadata, so clients fall back to DCR — the escape hatch when the metadata document cannot be fetched (see the [CIMD note](#cimd-note-for-datacenter-deployments-also-a-silent-failure)). |
| `CIMD_FETCH_TIMEOUT` / `CIMD_MAX_SIZE` / `CIMD_CACHE_TTL` | `5s` / `65536` / `1h` | CIMD resolution limits. |
| `DCR_ENABLED` | `true` | Serve the deprecated RFC 7591 registration endpoint. Turning it off shrinks the public surface — see [below](#should-you-turn-dcr-off). |
| `DCR_CLIENT_TTL` / `DCR_MAX_CLIENTS` | `720h` / `100` | DCR registration expiry / cap. |
| `KEY_ALG` | `RS256` | `RS256` or `ES256`; switching triggers a key rotation. |
| `KEY_ROTATION_INTERVAL` | `2160h` (90 d) | Automatic rotation interval (≥1h); `0` disables. |
| `JWT_PRIVATE_KEY` | — | Advanced: fixed external signing key (PEM) — disables the managed key directory and rotation. |
| `AUTH_HMAC_SECRET` | generated | Base64 session/HMAC secret; auto-generated into `DATA_PATH` on first start. |
| `OIDC_DISCOVERY_MIRROR` | `false` | Also serve the AS metadata as `/.well-known/openid-configuration`. |

### Abuse protection

| Env | Default | Description |
|---|---|---|
| `RATE_LIMIT_REGISTER` / `RATE_LIMIT_TOKEN` / `RATE_LIMIT_LOGIN` / `RATE_LIMIT_AUTHORIZE` | `10/m` / `60/m` / `10/m` / `60/m` | Per-client-IP token buckets, format `N/s\|m\|h`; `0` disables (not recommended). Over-limit → `429`. |
| `LOGIN_LOCKOUT_THRESHOLD` / `LOGIN_LOCKOUT_DURATION` | `10` / `15m` | Account lockout after N consecutive failed password logins; threshold `0` disables. |

### Should you turn DCR off?

Clients identify themselves either by **CIMD** (an HTTPS URL pointing at a metadata document) or
by **Dynamic Client Registration**, which the MCP spec deprecates but keeps for authorization
servers that cannot do CIMD. This gateway does both, CIMD first.

`DCR_ENABLED=false` removes `POST /.idp/register` from the routing table and drops
`registration_endpoint` from the AS metadata, so the public surface gets smaller by one open
endpoint. If every client you serve speaks CIMD — and Claude does — that is a reasonable trade for
your deployment.

Two things to know before you do it:

- **Never combine it with `CIMD_ENABLED=false`.** With both mechanisms disabled the gateway refuses
  to start, by design. In particular, DCR is the fallback recommended in the
  [CIMD note above](#cimd-note-for-datacenter-deployments-also-a-silent-failure) when a client's
  metadata document cannot be fetched — turning DCR off removes that rescue.
- **Any client that cannot do CIMD stops working**, with no partial degradation: it has no way to
  obtain a `client_id` at all.

The default stays `true` because this gateway targets any OAuth-only MCP client, not one vendor's.
The narrowing is yours to make, deployment by deployment.

## Operations

- **Health:** `GET /healthz` (no auth, no internals). The image ships a `HEALTHCHECK` that
  runs `mcp-oauth-gateway healthcheck` — no curl needed; works in every TLS mode.
- **Key rotation:** automatic per `KEY_ROTATION_INTERVAL`; rotated-out keys keep verifying
  outstanding tokens until they expire. Force one manually (run against the data directory
  while the gateway is stopped, or restart right after):
  ```bash
  docker compose run --rm mcp-oauth-gateway rotate-key
  docker compose restart mcp-oauth-gateway
  ```
- **Backup:** everything lives in `DATA_PATH` (keys, token store, secrets) — back up that
  volume. Restoring it restores all sessions and keys.
- **Logs:** structured JSON on stdout, including auth events (`login_ok`, `login_fail`,
  `token_issued`, `register`, `rate_limited`, `revoked`) without secrets.
- **Version:** shown in the footer of `/.auth/settings` once you are logged in, and by
  `mcp-oauth-gateway --version`; release images report their git tag. No public endpoint
  discloses it — `/healthz` deliberately says only `{"status":"ok"}`.
- **Upgrades:** pin image versions; read the [release notes](CHANGELOG.md) — schema
  migrations and config changes are documented there. Downgrades are unsupported.

## Endpoints

| Path | Purpose |
|---|---|
| `/.well-known/oauth-protected-resource` · `/.well-known/oauth-authorization-server` · `/.well-known/jwks.json` | Discovery (public). |
| `/.idp/auth` · `/.idp/token` · `/.idp/register` · `/.idp/revoke` · `/.idp/introspect` | OAuth endpoints. |
| `/.auth/login` · `/.auth/settings` | Operator login, passkey/settings UI, and the connected-clients list with its revoke actions. |
| `/healthz` | Liveness (public). |
| everything else | Proxied to the upstream — **bearer required, fail-closed**. |

## Security

Security posture: fail-closed on every auth path, vetted crypto only (Ory Fosite,
golang-jwt, x/crypto), PKCE S256-only, audience-bound short-lived JWTs with server-side
revocation, SSRF-guarded CIMD resolution, rate limits + lockout, non-root distroless
container. Details: [`THREAT-MODEL.md`](THREAT-MODEL.md) and [`SPEC.md`](SPEC.md). The
codebase went through an adversarial security audit before its first release; findings and
fixes are documented in [`PROGRESS-ARCHIVE.md`](PROGRESS-ARCHIVE.md) (F-006b).

**Reporting vulnerabilities:** please use GitHub private vulnerability reporting — see
[`SECURITY.md`](SECURITY.md).

## Documentation

**The rules** — binding for anyone changing the gateway:

- [`SPEC.md`](SPEC.md) — implementable contracts: endpoints, schemas, data model, config, plus
  the functional, security, and non-functional requirement register (§5). *What must hold.*
- [`CODING-STANDARDS.md`](CODING-STANDARDS.md) — binding coding rules. *How it is written.*
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — assets, threats, mitigations. *What it defends against.*

**The records** — what was checked, when, and why:

- [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md) — requirement-by-requirement result of the
  last check against the MCP spec. Walk it when a new spec revision lands.
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) — runbook for verifying a *deployed* gateway
  end to end against real clients. Walk it after deploying or before a release.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes (incl. migrations).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute, commit conventions, secrets hygiene.
- [`PROGRESS.md`](PROGRESS.md) / [`PROGRESS-ARCHIVE.md`](PROGRESS-ARCHIVE.md) — roadmap and
  finished work with rationale.
- [`HOW-TO-CODE-WITH-CLAUDE.md`](HOW-TO-CODE-WITH-CLAUDE.md) / [`AI-DISCLOSURE.md`](AI-DISCLOSURE.md)
  — how this project is built.

## License

Apache-2.0 © xnyzer. See [`LICENSE`](LICENSE).

This project is a hard fork of [`sigbit/mcp-auth-proxy`](https://github.com/sigbit/mcp-auth-proxy)
(MIT). The upstream attribution is retained in [`NOTICE`](NOTICE); fork provenance is in
[`FORK.md`](FORK.md). Dependencies are permissive (MIT/BSD/Apache-2.0) apart from a few
weak-copyleft **MPL-2.0** modules (transitive via Ory Fosite); **no GPL/AGPL/LGPL** —
enforced by a CI license check.
