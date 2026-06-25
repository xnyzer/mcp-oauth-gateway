# mcp-oauth-gateway — Progress

Living task list. **Done table** at the top, **open tasks / backlog** below, **feature index** at the very end.

How it works: `/add-feature` intakes new tasks (F-number), `/prep-step` prepares and decomposes, `/step-done` finishes (review, docs, Graphiti, commit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`.

Everything top-down: nothing here is built yet; this is the path from spec → working gateway. **F-001 (build-vs-fork) is the first work item.**

---

## Done

| Step | Description | Completed |
|------|-------------|-----------|
| F-001 | Build vs fork evaluation → **decided: hard-fork `sigbit/mcp-auth-proxy`** (Go + Ory Fosite), validated by a live Claude PoC. Detail in `PROGRESS-ARCHIVE.md`. | 2026-06-25 |

---

## Open tasks

### F-002 — Choose language + OAuth library

**Problem:** The implementation language and OAuth library are undecided; everything downstream depends on this.

**Idea:** Decide between Go + Ory Fosite and Python + authlib (lean: Go + Fosite for a tool others self-host). A fork (F-001) may dictate the language.

**Possible implementation:**
- Decision criteria: distribution size (tiny static binary vs runtime deps), security pedigree (Fosite powers Ory Hydra; authlib widely used), contributor reach, streaming-proxy support.
- Once chosen, add the language-specific section to `CODING-STANDARDS.md`.

**Dependencies:** F-001 (a fork may decide the language).
**F-001 outcome:** the chosen base `sigbit/mcp-auth-proxy` is **Go + Ory Fosite** → this task is now mostly a formal confirmation.

---

### F-003 — DCR vs CIMD decision

**Problem:** A Dynamic Client Registration endpoint may be unnecessary if target clients honor CIMD, which would simplify the gateway.

**Idea:** Verify current client support; decide whether to support CIMD, DCR, or both.

**Possible implementation:**
- Check the current OAuth client behaviour of the target apps (re-verify; fast-moving).
- Decide the registration model and record the rationale.

**Dependencies:** F-001 (the chosen base may already implement one model).
**F-001 outcome:** spec 2025-11-25 makes **CIMD** recommended (SHOULD) and **deprecates DCR** (MAY). The base implements DCR only (open `/register`, no CIMD) → decide **CIMD-first, DCR fallback** and plan CIMD as new work.

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

### F-005 — Implement on the chosen base (sigbit fork)

**Problem:** The gateway does not exist yet. F-001 chose to hard-fork `sigbit/mcp-auth-proxy`; the base already provides much of this, so the work is **closing the gaps** to our spec/security bar — glue only, no hand-rolled crypto (see `THREAT-MODEL.md`).

**Idea:** Build on the fork (F-008). Keep/verify what sigbit already does (in-process fail-closed enforcement, streaming proxy, embedded persistence, ACME); add and harden the missing pieces below.

**Possible implementation:**
- Discovery (PRM/AS metadata), DCR, authorize+token (PKCE), JWKS, login (passkey), consent.
- Upstream proxy with streaming passthrough + configurable upstream auth injection.
- Rate-limiting, DCR-client expiry/caps, structured auth logging.

**Gap list vs the sigbit fork base (from F-001 code review):**
- **RFC 8707 audience-binding** — sigbit hardcodes `aud` to `externalURL`; bind tokens to the actual MCP resource.
- **CIMD client-registration** — absent; add Client ID Metadata Document resolution (CIMD-first per spec 2025-11-25, see F-003/F-009).
- **`WWW-Authenticate` on the `/mcp` 401** — sigbit returns a bare 401 JSON; emit `Bearer resource_metadata="…"` so clients can discover the PRM.
- **`/revoke` route (RFC 7009)** — storage supports it but no HTTP endpoint is wired.
- **Complete PRM/AS-metadata** — advertise `jwks_uri`/introspection/revocation; PRM is currently thin.
- **RFC 9207 `iss`** in the authorize response.
- **Key management** — rotation + optional ES256 (sigbit ships a single static RS256 key).
- **Self-contained auth** — replace the bcrypt single-shared-secret with passkey/WebAuthn + a real user model.

**Dependencies:** F-004, F-008.

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

### F-008 — Create the hard fork of `sigbit/mcp-auth-proxy`

**Problem:** F-001 chose `sigbit/mcp-auth-proxy` (Go + Ory Fosite, MIT) as the base, but no project repo exists yet; all gap-closing work (F-005) needs a clean fork to build on.

**Idea:** Stand up our own hard fork as the project's codebase — owned and maintained by us from day one (not tracking upstream), licence-clean and lean.

**Possible implementation:**
- Import the source into our repo; retain the upstream **MIT LICENSE/NOTICE** alongside our Apache-2.0 (`NOTICE` file) — both permissive, no GPL/AGPL.
- Prune unused transitive dependency trees (ory/x, OpenTelemetry, mongo-driver) to shrink the audit/supply-chain surface.
- Establish project layout + CI (build/test); baseline must compile and pass the existing unit tests.
- Record provenance (the upstream commit forked from) for future security tracking.

**Dependencies:** F-002, F-003.

---

### F-009 — Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)

**Problem:** `REQUIREMENTS.md` §0/FR-2 still frame **DCR** as the registration mechanism, but the MCP authorization spec **2025-11-25** makes **CIMD** the recommended path (SHOULD) and **deprecates DCR** (MAY, fallback). RFC 9207 `iss` and OIDC Discovery (as an RFC 8414 alternative) are newly relevant too.

**Idea:** Bring the source-of-truth docs in line with the current spec so F-003/F-004/F-005 build to the right contract.

**Possible implementation:**
- REQUIREMENTS §0: note CIMD-first / DCR-deprecated; add RFC 9207 `iss` and OIDC-Discovery-as-alternative.
- FR-2: reframe as CIMD primary, DCR fallback; cross-reference F-003.
- Note the 2026-07-28 release candidate as a watch item (re-verify before release).

**Dependencies:** none (documentation).

---

<!-- FEATURE-INDEX
next-feature: F-010
F-001 Build vs fork evaluation (do first) (DONE)
F-002 Choose language + OAuth library
F-003 DCR vs CIMD decision
F-004 Complete the spec (make it implementable)
F-005 Implement on the chosen base (sigbit fork)
F-006 Verify against Claude + security review
F-007 Release hygiene
F-008 Create the hard fork of sigbit/mcp-auth-proxy
F-009 Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)
-->
