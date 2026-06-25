# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks / backlog** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

Everything top-down: nothing here is built yet; this is the path from spec → working gateway. **F-001 (build-vs-fork) is the first work item.**

---

## Done

| Step | Description | Completed |
|------|-------------|-----------|
| — | _(nothing implemented yet)_ | — |

---

## Open tasks

### F-001 — Build vs fork evaluation (do first)

**Problem:** Before any code, decide whether to fork an existing MCP-OAuth gateway or build greenfield, to avoid duplicating work.

**Idea:** Evaluate existing projects at the code level as a possible fork base instead of greenfield.

**Possible implementation:**
- Primary candidate: `atrawog/mcp-oauth-gateway` (Apache-2.0): genuine OAuth 2.1 + DCR, but **mandates GitHub login**, bundles **Traefik + Redis**, and looked **stale**. Can GitHub be swapped for self-hosted/self-contained login? Can Traefik/Redis be dropped? Is it maintainable?
- Also skim: IBM `mcp-context-forge` (only outbound DCR), `tigrisdata/mcp-oidc-provider` (DCR shim — check no phone-home / local token storage), Pomerium MCP support.
- HyprMCP `mcp-gateway` is **archived** → excluded.
- **Decide:** maintained fork vs greenfield on a vetted library. Record the rationale.

**Dependencies:** none (first item).

**Evaluation result (2026-06-24) — code-level review done; final decision deferred to a local PoC.**

Candidates reviewed (atrawog + sigbit at the code level; others skimmed):
- **`atrawog/mcp-oauth-gateway`** — ❌ not a fork base. Python/authlib but ~10 months stale; **GitHub login hardcoded** into the authorize/callback flow (no auth-backend abstraction); enforcement *is* Traefik ForwardAuth (no in-process gate); **Redis** threaded through every call site (no DAO); **RFC 9728 PRM referenced but never served**; 1-year auth-code TTL; no unit tests for the auth package; "divine" cosmetic styling. Useful only as a reference.
- **`sigbit/mcp-auth-proxy`** — ✅ **leading candidate / likely base.** Go 1.26, **MIT**, single binary, built on **Ory Fosite** (= our F-002 lean). Already provides: in-process **fail-closed** bearer enforcement, upstream credential injection + hiding, SSE/streaming passthrough, stdio→HTTP MCP bridge, **embedded persistence (bbolt default / GORM SQLite·Postgres·MySQL)** behind a clean storage interface, **built-in password login with NO third-party IdP required**, built-in ACME, X-Forwarded trust gating, decent unit tests, active (v2.10.2, 2026-05). Verified by upstream against Claude/ChatGPT/Copilot/Cursor.
- Skimmed: IBM `mcp-context-forge` (downstream OAuth + heavy Postgres/Redis stack — wrong layer), `tigrisdata/mcp-oidc-provider` (DCR shim but **mandates** a third-party IdP, DCR-only), Pomerium MCP (acts as MCP-client AS, Apache-2.0, but heavy platform and leans on an upstream IdP for user login). `hyprmcp/mcp-gateway` archived → excluded.

**Spec change found (re-verification): MCP spec 2025-11-25 makes _CIMD_ the recommended client-registration mechanism (SHOULD) and _deprecates DCR_ (MAY, fallback only).** Claude supports CIMD/DCR/Anthropic-creds, prefers CIMD. Also new: RFC 9207 `iss` (SHOULD), OIDC Discovery as an RFC 8414 alternative; RFC 8707 audience-binding stays MUST. → Design should be **CIMD-first, DCR fallback** (affects F-003/F-004; REQUIREMENTS §0 needs an update).

**Recommendation — DECIDED (PoC validated 2026-06-25): build on a hard fork of `sigbit/mcp-auth-proxy`** rather than greenfield. A live PoC (sigbit in Docker on a self-hosted VM, plain HTTP behind a Zoraxy reverse proxy doing public TLS, fronting `@modelcontextprotocol/server-filesystem`) **completed a full Claude custom-connector round-trip**: OAuth 2.1 discovery → built-in password login → consent → token → proxied MCP tool call (list/read `/tmp`). Confirms sigbit is a viable base toward Claude. (Note: Claude's cloud connects from egress `160.79.104.0/21`; the public endpoint must allow it — geo/IP firewalls that block US sources will silently fail before any request reaches the gateway.) Gaps to close after adoption (the parts we'd want to own/audit anyway): **RFC 8707 audience-binding** (currently hardcoded to `externalURL`), **CIMD** + **RFC 9207 `iss`**, complete PRM/AS-metadata (advertise jwks_uri/introspection; add `/revoke` route), **passkey/WebAuthn + real user model** (currently bcrypt single-shared-secret), **key rotation** + optional ES256. Risks: single maintainer (treat as our own fork from day one), hand-rolled metadata/DCR structs drift, transitive dep bloat (ory/x, OTel, mongo) to prune. License: MIT→Apache-2.0 is compatible (retain MIT NOTICE).

**Implications:** F-002 likely resolved (**Go + Ory Fosite**); F-003 trends **CIMD-first, DCR fallback**; F-004 inherits a real codebase.

**PoC done (2026-06-25): SUCCESS** — local smoke-test + public Claude custom-connector round-trip both worked. F-001 resolved in favor of forking `sigbit/mcp-auth-proxy`. **Next:** confirm F-002 (Go + Ory Fosite), F-003 (CIMD-first), then create the hard fork and open F-numbers for the gap-closing work (RFC 8707/9207, CIMD, complete PRM + `WWW-Authenticate` on the `/mcp` 401, `/revoke`, passkey/WebAuthn + user model, key rotation). Update REQUIREMENTS §0 for the CIMD/DCR spec change.

---

### F-002 — Choose language + OAuth library

**Problem:** The implementation language and OAuth library are undecided; everything downstream depends on this.

**Idea:** Decide between Go + Ory Fosite and Python + authlib (lean: Go + Fosite for a tool others self-host). A fork (F-001) may dictate the language.

**Possible implementation:**
- Decision criteria: distribution size (tiny static binary vs runtime deps), security pedigree (Fosite powers Ory Hydra; authlib widely used), contributor reach, streaming-proxy support.
- Once chosen, add the language-specific section to `CODING-STANDARDS.md`.

**Dependencies:** F-001 (a fork may decide the language).

---

### F-003 — DCR vs CIMD decision

**Problem:** A Dynamic Client Registration endpoint may be unnecessary if target clients honor CIMD, which would simplify the gateway.

**Idea:** Verify current client support; decide whether to support CIMD, DCR, or both.

**Possible implementation:**
- Check the current OAuth client behaviour of the target apps (re-verify; fast-moving).
- Decide the registration model and record the rationale.

**Dependencies:** F-001 (the chosen base may already implement one model).

---

### F-004 — Complete the spec (make it implementable)

**Problem:** The requirements describe intent but not the implementable contract (exact endpoints, schemas, data model, config).

**Idea:** Turn the requirements into precise, RFC-conformant contracts.

**Possible implementation:**
- API contracts: exact endpoint paths, request/response schemas, token claims, error formats (RFC-conformant) for all FRs.
- Data model & persistence (clients, keys, sessions) — choose a store (e.g. SQLite/file).
- Config schema (env vars), defaults, example `docker-compose.yml`, `Dockerfile`.
- Key management: generation on first run, storage, **rotation** strategy.

**Dependencies:** F-002, F-003.

---

### F-005 — Implement on the vetted library

**Problem:** The gateway does not exist yet.

**Idea:** Build the gateway on the chosen vetted library — glue only, no hand-rolled crypto (see `THREAT-MODEL.md`).

**Possible implementation:**
- Discovery (PRM/AS metadata), DCR, authorize+token (PKCE), JWKS, login (passkey), consent.
- Upstream proxy with streaming passthrough + configurable upstream auth injection.
- Rate-limiting, DCR-client expiry/caps, structured auth logging.

**Dependencies:** F-004.

---

### F-006 — Verify against Claude + security review

**Problem:** Nothing ships without verification against real clients and a security review.

**Idea:** End-to-end verify, then a mandatory security review before any public exposure.

**Possible implementation:**
- Local/tooling: discovery valid; DCR works; authorize+token+PKCE round-trip; JWKS; expired/invalid token → 401 (fail-closed); rate-limits fire.
- **Claude web custom connector first** (easier to debug), then **Claude iOS**.
- Negative tests (no token / tampered token / replay).
- **Security review** before any public exposure.

**Dependencies:** F-005.

---

### F-007 — Release hygiene

**Problem:** A public release needs usage docs, SemVer, and license/NOTICE hygiene.

**Idea:** Finalise documentation and release artifacts.

**Possible implementation:**
- README usage docs (front an MCP server; add as a connector), SECURITY.md, SemVer, NOTICE.
- CI with OAuth/MCP conformance tests.
- Verify all dependencies are permissive-licensed (no GPL/AGPL).

**Dependencies:** F-006.

---

## Feature ideas (backlog)

_New ideas beyond the path above are intaked via `/add-feature` and get the next F-number._

---

<!-- FEATURE-INDEX
next-feature: F-008
F-001 Build vs fork evaluation (do first)
F-002 Choose language + OAuth library
F-003 DCR vs CIMD decision
F-004 Complete the spec (make it implementable)
F-005 Implement on the vetted library
F-006 Verify against Claude + security review
F-007 Release hygiene
-->
