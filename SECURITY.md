# Security Policy

mcp-oauth-gateway is an **authentication gateway** — an OAuth 2.1 + DCR boundary placed in front of
an MCP server. A vulnerability here can expose the upstream server or leak credentials, so security
reports are taken seriously. Thank you for helping keep it and its users safe.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private reporting feature:

1. Go to the **[Security tab](https://github.com/xnyzer/mcp-oauth-gateway/security)** of this repository
2. Click **"Report a vulnerability"**
3. Fill in the form and submit

Only the maintainer and you will see the report. You can attach proof-of-concept code or logs
without them becoming public.

## What to include

- A description of the issue and its impact
- Steps to reproduce (as minimal as you can make them)
- The affected version or commit SHA
- The threat scenario (e.g. unauthenticated attacker, malicious client via DCR, token replay,
  PKCE downgrade, exposed reverse proxy)
- Any suggested mitigation or patch idea, if you have one

## What happens next

mcp-oauth-gateway is maintained by a single person in their spare time, so response times vary —
please be patient.

- **Initial response:** within a few days where possible, but it can take two to three weeks.
- **Triage:** confirmation whether it is a vulnerability and a rough severity.
- **Fix timeline:** because this is an auth boundary, vulnerabilities that allow authentication
  bypass, token leakage/forgery, or upstream exposure are treated as the highest priority; lower-
  severity fixes depend on scope and available time.
- **Disclosure:** when a fix is released, the advisory is published and you are credited unless you
  prefer to stay anonymous.

## Scope

In scope:

- The OAuth/MCP gateway code: discovery (PRM/AS metadata), DCR, authorize+token (PKCE), JWKS and
  key management, login/consent, the upstream proxy, rate-limiting.
- Build, deployment, and CI configuration (`Dockerfile`, compose, `.github/workflows/`).
- The threat model and spec where a documented design choice is itself a vulnerability.

Out of scope (please report upstream):

- Vulnerabilities in the **upstream MCP server** fronted by this proxy — report to that project.
- Vulnerabilities in third-party dependencies or the chosen OAuth library — report to the
  respective upstream project (but do tell us so we can pin/patch).
- Vulnerabilities in the reverse proxy, TLS terminator, or the underlying OS/runtime — report to
  their maintainers.
- Issues that require privileged local/physical access beyond what a normal network attacker has.

## Supported versions

| Version | Supported |
|---------|-----------|
| pre-release (no tagged release yet) | latest `main` only |

This table will be updated once the project has tagged releases and a SemVer policy.

## Safe harbor

I will not take legal action against researchers who report vulnerabilities in good faith, follow
this policy, give reasonable time to fix the issue before public disclosure, and do not exfiltrate
user data or pivot into upstream systems beyond what is needed to demonstrate the issue. Testing
must be limited to your own deployment — do not attack other people's instances.
