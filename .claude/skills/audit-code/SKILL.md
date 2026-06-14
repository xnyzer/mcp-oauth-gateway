---
name: audit-code
description: Full audit of the project/stack. Code, architecture, security, secrets, dependencies, deployment config. Produces AUDIT-RESULTS.md, fixes nothing. Optionally scope to an area.
disable-model-invocation: true
---

# Code & stack audit

Systematic full check of the project. **Document only, fix nothing.**

Argument (optional): scope to an area — e.g. "auth", "proxy", "config", "security", "deps" or a concrete path. Without argument: check everything.

**Guiding principle:** Surface problems that could lead to security holes, token/credential leakage, fail-open behaviour, instability, or unmaintainability. Every finding concrete, reproducible, with a clear recommendation.

**How to work:** Read thoroughly, skip nothing. Subagents for parallel analysis where useful. For library/SDK questions use current docs (context7 if available, otherwise web). Check against the actually pinned versions. Note: the language/stack may not be decided yet (see F-002) — until then, audit the spec and meta files.

## Phase 0: Get permissions
Before you start, ask the user for all permissions you need for the whole audit.

## Phase 1: Preparation & context
1. Read `CODING-STANDARDS.md` — reference for style and architecture.
2. Read `REQUIREMENTS.md` and `THREAT-MODEL.md` — the security model and FRs are the contract.
3. Determine versions: lockfiles / manifests once a stack exists; pinned image tags.
4. Read deployment-relevant files once they exist: `Dockerfile*`, `docker-compose*.yml`, reverse-proxy config, config schema / example env.
5. `git log --oneline -20` for the current state.

## Phase 2: Code audit (against CODING-STANDARDS.md)
Area by area: discovery/metadata, DCR, authorize+token (PKCE), JWKS/key management, login/consent, upstream proxy, rate-limiting. Apply each rule per file, note violations.

**Additionally — check the security posture (see THREAT-MODEL.md), violations are severity: high:**
1. **No hand-rolled crypto:** Is token signing/verification, PKCE, or JWKS built on a vetted library, not custom code?
2. **Fail-closed:** Does any error path leave a request authenticated/authorized by default? Expired/invalid/missing token must yield 401.
3. **Token hygiene:** Audience-bound, short-lived access tokens? No tokens/keys in logs or images? PKCE (S256) enforced?
4. **DCR abuse:** Registration capped/expiring? Rate-limited? No unbounded client growth?
5. **Discovery correctness:** RFC 9728 PRM and RFC 8414 AS metadata accurate and consistent with actual endpoints?

## Phase 3: Security & secrets audit
- **Secrets:** Tokens/passwords/private keys/private emails/deployment IPs/hostnames in code or git history? Content that belongs in `private/` in the public tree?
- **Dependency security:** known CVEs; still maintained? Runtime within its support window? **All dependencies permissive-licensed (no GPL/AGPL)?**
- **Input validation:** Do all endpoints validate input (body/query/params)? Config validated at startup?
- **Credentials:** No secrets in logs/images; bearers/keys masked.

## Phase 4: Deployment & infrastructure
- **Dockerfiles:** Multi-stage? Non-root? current base image? Healthcheck? no secrets? ports/config via env?
- **Compose:** Health checks + `depends_on: condition: service_healthy`? Restart policies? Volumes for persistent data (keys/clients/sessions store)? All ports/secrets via env? Example env complete?
- **TLS / reverse proxy:** Publicly-trusted TLS terminated correctly? No unprotected routes to internal services?

## Phase 5: Architecture & robustness
- **Error handling:** Unhandled rejections/panics? empty `catch`? internal error details leaked to clients? Graceful degradation when the upstream MCP server is down?
- **Reliability:** Key rotation handled without breaking live sessions? Backoff/retry on upstream calls where appropriate?
- **Config:** All config documented? All ports configurable (no conflicts)?
- **Concurrency:** Shared state without coordination (key cache, session store, rate-limit counters)? In-flight operations without dedup?

## Phase 6: Compile results

**Don't fix! Document only.** In `AUDIT-RESULTS.md` (project root, gitignored, each run overwrites):

```markdown
# Audit results — [Date]

## Summary
- Critical / High / Medium / Low findings: X / X / X / X
- Recommended immediate actions: [Top 3]

## 1. Code audit
### [File] (path)
| # | Category | Rule | Line(s) | Violation | Severity |
|---|----------|------|---------|-----------|----------|

## 2. Security & secrets
## 3. Deployment & infrastructure
## 4. Architecture & robustness
## 5. Upgrade recommendations
| Priority | Package/Image | From | To | Reason | Breaking changes |

## 6. Summary by severity
```

**Severities:** critical (active hole / token leak / fail-open / CVE without fix) · high (security best-practice or threat-model violation, missing validation, hand-rolled crypto) · medium (structural violation, missing types, suboptimal config) · low (style, imports).

Don't list files without violations. After finishing, show a short summary.
