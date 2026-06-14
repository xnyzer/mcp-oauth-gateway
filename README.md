# mcp-oauth-gateway

A self-hosted **OAuth 2.1 + Dynamic Client Registration (DCR) gateway** that puts
spec-compliant **MCP authorization** in front of *any* MCP server — including servers that
only support a static bearer token, or no auth at all — so that **OAuth-only MCP clients**
(e.g. Claude's web/desktop/mobile apps) can connect, **without depending on a third-party
identity provider**.

> **Status: specification phase — no code yet.** This repository currently contains the
> requirements, threat model, and open decisions. See [`PROGRESS.md`](PROGRESS.md) and
> [`STARTPROMPT.md`](STARTPROMPT.md) to continue the work from scratch.

## Why
The MCP authorization spec requires remote MCP servers to be OAuth 2.1 Authorization Servers
that support **Dynamic Client Registration** (clients register themselves) plus discovery
metadata (RFC 9728 / RFC 8414). Most self-hosted MCP servers only offer a static bearer token
— which OAuth-only clients reject. Existing OAuth gateways either mandate a hosted identity
provider (e.g. GitHub), are unmaintained, or bundle a heavy stack. This project aims to fill
the gap: **maintained, self-hosted, no mandatory third party, lightweight, reverse-proxy- and
upstream-agnostic.**

## Design goals
- **Upstream-agnostic:** front any MCP server; configurable upstream auth (static bearer /
  custom header / none).
- **Reverse-proxy-agnostic:** run behind any reverse proxy (Nginx, Caddy, Traefik, …) or
  optionally terminate TLS itself. Honors `Forwarded` / `X-Forwarded-*`; configurable public
  base URL.
- **No mandatory third-party IdP:** self-contained single-user auth (passkey/WebAuthn preferred);
  pluggable to a self-hosted OIDC provider later; multi-user not precluded.
- **Security-first:** build on a vetted OAuth library (no hand-rolled crypto), fail-closed,
  defense-in-depth.
- **Single container, 12-factor config, portable observability** (structured logs to stdout).

## Documentation
- [`REQUIREMENTS.md`](REQUIREMENTS.md) — functional, security, and non-functional requirements.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — assets, threats, mitigations.
- [`PROGRESS.md`](PROGRESS.md) — open decisions and roadmap as F-numbers (start at F-001).
- [`STARTPROMPT.md`](STARTPROMPT.md) — resume the project with a fresh context.

## License
Apache-2.0 © xnyzer. See [`LICENSE`](LICENSE).
