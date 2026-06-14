# Start prompt — resume work on mcp-oauth-gateway

Paste into a fresh session to continue this project from zero context.

```
We are building `mcp-oauth-gateway`: a self-hosted OAuth 2.1 + Dynamic Client Registration
gateway that fronts ANY MCP server (bearer-only or unauthenticated) so that OAuth-only MCP
clients (e.g. Claude's web/desktop/mobile apps) can connect, WITHOUT a third-party identity
provider. It is meant to be generic, maintained, lightweight, reverse-proxy- and
upstream-agnostic, and is intended to later become a module of a larger self-hosting suite.

READ FIRST (in this repo): README.md, REQUIREMENTS.md, THREAT-MODEL.md, PROGRESS.md.

PROJECT STATE: specification phase, no code yet. The repo contains requirements, threat model,
and open decisions. LICENSE is Apache-2.0. Keep the repo generic — NO personal or
deployment-specific details.

VERIFIED FACTS (mid-2026; re-verify, fast-moving):
- Claude clients need OAuth 2.1 + PKCE/S256; a static bearer token is NOT accepted.
- Clients register via DCR (RFC 7591) or CIMD; the server must publish RFC 9728 Protected
  Resource Metadata and RFC 8414 Authorization Server Metadata.
- Claude connects from the vendor cloud, so the server must be publicly reachable with a
  publicly-trusted TLS certificate.
- No maintained, self-hosted, no-third-party, lightweight gateway covers this gap today.

DECISIONS ALREADY MADE:
- Approach: a custom gateway built on a VETTED OAuth library (no hand-rolled crypto) — BUT
  first evaluate forking an existing project (PROGRESS F-001) to avoid duplication.
- License: Apache-2.0. Dependencies must be permissive (no GPL/AGPL).
- Security-first: fail-closed, aud-bound short-lived tokens, defense-in-depth, DCR abuse
  mitigation, mandatory security review before any public exposure.

START HERE (this session's job): **PROGRESS F-001 — build-vs-fork evaluation.**
Evaluate existing MCP-OAuth gateways AT THE CODE LEVEL as a possible fork base instead of
greenfield — primarily `atrawog/mcp-oauth-gateway` (can the mandatory GitHub login be replaced
with self-contained/self-hosted login? can Traefik+Redis be dropped? is it maintainable?), plus
a quick skim of IBM `mcp-context-forge`, `tigrisdata/mcp-oidc-provider`, Pomerium MCP support.
Deliver a clear recommendation: **fork a specific project** (with what changes) **or build
greenfield**, with rationale. Do NOT start the language/library deep-dive until Task 1 is decided
(a fork may decide the language for us).

AFTER Task 1: (2) choose language/OAuth library (lean: Go + Ory Fosite; alt: Python + authlib),
(3) decide DCR vs CIMD, then complete the spec (PROGRESS F-004) before building.

CONVENTIONS: git author `xnyzer <12890660+xnyzer@users.noreply.github.com>`, Conventional
Commits, add a `Co-Authored-By: Claude <noreply@anthropic.com>` trailer. Repo language: English.

Ask clarifying questions instead of guessing. Begin by confirming the Task 1 evaluation plan.
```
