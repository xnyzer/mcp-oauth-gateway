# mcp-oauth-gateway — Coding Standards

Binding rules for every code change. This document is the working instruction — whoever writes or
reviews code follows these rules.

> **Stack note:** The language and stack are **not yet decided** (a build-vs-fork and Go-vs-Python
> decision is pending). The rules below are language-agnostic and always apply. **Language-specific
> rules (Go or Python) will be added once the stack is chosen (see PROGRESS F-002).**

---

## 1. Mindset

- **No workarounds.** Always fix the root cause. No `// HACK`, no `// TODO: fix later`.
- **Fix errors immediately.** Don't defer, don't ignore, don't dismiss as "pre-existing". Linter/diagnostic warnings count as errors.
- **Use established patterns.** Don't invent your own when a proven one exists. For anything security-critical (crypto, token handling, PKCE, JWKS), use a vetted library — never hand-roll.
- **Code must be production-ready when first written.** No "good enough for now".
- **Dead code is deleted.** No commented-out blocks, no unused imports, no unreachable paths.

---

## 2. Files & structure

### File names
- Use the casing convention of the chosen language (to be specified in F-002). Until then: descriptive, consistent names.
- **Tests** live next to or mirror the code they test, following the language's test convention.
- **Config/deploy**: descriptive names — `Dockerfile`, `docker-compose.yml`, reverse-proxy config, example env file.

### File length
- **Target: under 300 lines.** At 300, check whether it can be split.
- **Hard limit: 500 lines.** Above that, split. Exception: clearly delimited modules with section comments.

### Section comments
Structure large files with ASCII rules:
```
// -- Discovery / metadata -------------------------------------
// -- Token issuance -------------------------------------------
// -- JWKS / key management ------------------------------------
```
Short, descriptive, visually set apart. No rambling block comments.

---

## 3. Functions & methods

- **Target: under 30 lines** — a function does one thing. **Hard limit: 50 lines.** Exception: sequential orchestration functions up to ~80 lines.
- **Naming:** verb first — `issueToken`, `parsePkceChallenge`, `verifyJwks`. Follow the language's casing convention.
- **Booleans:** `is`/`has`/`can`/`should` — `isExpired`, `hasValidPkce`.
- **Exported functions:** explicit return type where the language supports it.
- **Maximum 3 parameters** — beyond that, an options object/struct.

---

## 4. Naming & imports

- **Descriptive names**, no single letters except trivial loop indices. Names reveal intent.
- **No magic values** — named constants for timeouts, token lifetimes, limits.
- **Imports grouped and ordered**: standard library, third-party, local. No unused imports. No wildcard imports where the language allows specificity.

---

## 5. Control flow

- **Early returns / guard clauses** over deep nesting. Handle the error/edge case first, keep the happy path unindented.
- **No deeply nested conditionals** (target max 2-3 levels).
- **Exhaustive handling** of enums/variants — no silent fall-through on auth decisions.

---

## 6. Error handling & resilience

- **Custom error types** with clear names (e.g. `InvalidTokenError`, `PkceMismatchError`, `UpstreamUnavailableError`). Throw/return in the core, handle centrally.
- **Fail-closed:** any error on an auth path results in denial (401/403), never in an authenticated/authorized default. This is the single most important rule for this project.
- **No empty `catch`/error-swallowing.** Never leak internal error details to clients (no stack traces, no internal paths in responses).
- **Graceful degradation:** if the upstream MCP server is down, fail clearly — never serve a degraded but "open" auth path.
- **No unhandled rejections/panics** on request paths.

---

## 7. Security & secrets

- **No hand-rolled crypto.** Token signing/verification, PKCE (S256), and JWKS are built on a vetted OAuth/crypto library. See `THREAT-MODEL.md`.
- **Never commit secrets** — no tokens, passwords, private keys (PEM/JWK), private emails, or deployment IPs/hostnames/key names. Operational internals belong in `private/` (gitignored).
- **All secrets via config/env**; the example env file contains only placeholders and is always complete.
- **Config validation at startup** — missing/invalid values fail fast with a clear message, never silent misbehaviour.
- **Tokens:** audience-bound, short-lived access tokens; PKCE (S256) enforced.
- **No secrets in logs** (mask keys, tokens, bearers). Structured auth logging without leaking credentials.
- **Pinned versions** instead of `latest` for images, tags, and dependencies. **All dependencies permissive-licensed (no GPL/AGPL).**

---

## 8. Configuration & observability

- **Everything configurable, nothing hardcoded:** endpoints, token lifetimes, limits, upstream URL, ports — via config/env.
- **Structured logging** (JSON where sensible) with log level via env; relevant security events (failed auth, DCR registrations, rate-limit hits) explicitly measurable — without leaking secrets.

---

## 9. Testing

- **Business logic** (token issuance, PKCE verification, DCR caps, fail-closed paths) has unit tests, using the chosen language's standard test framework (to be specified in F-002).
- **Negative tests are mandatory** for an auth boundary: missing token, tampered token, replay, expired token, PKCE downgrade — each must be denied.
- **Never commit with red tests.** Fix pre-existing red tests anyway, or report them explicitly.

---

## 10. Commits & git

- **Commit messages in English**, **Conventional Commits**, imperative mood; justify trade-offs briefly in the body (`Decision: X over Y because …`).
- **`Co-Authored-By: Claude <noreply@anthropic.com>`** trailer.
- **Commit email = GitHub noreply** (`12890660+xnyzer@users.noreply.github.com`) — never the private address. Verify before each commit (see `step-done` skill / `CONTRIBUTING.md`).
- **Never auto-commit** — always wait for the user's explicit "yes".
- **Focused commits** — one concern per commit.
