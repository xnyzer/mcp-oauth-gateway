# mcp-oauth-gateway — Progress Archive

Full documentation of all finished tasks. Filled by `/step-done`: per completed (sub)step, the complete section from `PROGRESS.md` plus the files actually created/changed, what was concretely implemented, and any notable decisions/deviations from the plan.

---

## F-001 — Build vs fork evaluation — DONE 2026-06-25

**Problem:** Before any code, decide whether to fork an existing MCP-OAuth gateway or build greenfield, to avoid duplicating work.

**Idea:** Evaluate existing projects at the code level as a possible fork base instead of greenfield.

**Dependencies:** none (first item).

### What was done
Code-level evaluation of two primary candidates (cloned and read, including the relevant
submodules), plus an architecture skim of the secondary field, plus a re-verification of the
current Claude/MCP OAuth requirements, plus a **live end-to-end PoC against Claude**.

**Candidates:**
- **`atrawog/mcp-oauth-gateway`** — ❌ not a fork base. Python/authlib but ~10 months stale;
  GitHub login hardcoded into the authorize/callback flow (no auth-backend abstraction);
  enforcement *is* Traefik ForwardAuth (no in-process gate); Redis threaded through every call
  site (no DAO); RFC 9728 PRM referenced but never served; 1-year auth-code TTL; no unit tests
  for the auth package. Reference only.
- **`sigbit/mcp-auth-proxy`** — ✅ **chosen base.** Go 1.26, MIT, single binary, built on
  **Ory Fosite**. Provides in-process fail-closed bearer enforcement, upstream credential
  injection + hiding, SSE/streaming passthrough, stdio→HTTP MCP bridge, embedded persistence
  (bbolt default / GORM SQLite·Postgres·MySQL) behind a clean storage interface, built-in
  password login with **no third-party IdP**, built-in ACME, X-Forwarded trust gating, decent
  unit tests, active (v2.10.2, 2026-05; single maintainer).
- Skimmed: IBM `mcp-context-forge` (downstream OAuth + heavy stack — wrong layer),
  `tigrisdata/mcp-oidc-provider` (DCR shim but mandates a third-party IdP, DCR-only), Pomerium
  MCP (MCP-client AS, Apache-2.0, but heavy platform leaning on an upstream IdP). `hyprmcp/mcp-gateway`
  archived → excluded.

**PoC (2026-06-25):** sigbit ran in Docker on a self-hosted VM, plain HTTP behind a reverse
proxy doing public TLS (Let's Encrypt wildcard via DNS-01), fronting
`@modelcontextprotocol/server-filesystem`. A full Claude custom-connector round-trip succeeded:
OAuth 2.1 discovery (RFC 8414 + RFC 9728) → built-in password login → consent → token issuance →
proxied MCP tool call (list/read `/tmp`). Local smoke-test confirmed the discovery/DCR/JWKS
endpoints and the fail-closed 401 beforehand.

### Decision
**Build on a hard fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite); not greenfield, not atrawog.**
Rationale: it already nails the security-sensitive plumbing we'd otherwise build from scratch,
under a permissive license, and it works with Claude today. We own and maintain it as our own
fork from day one.

### Spec change found (re-verification)
MCP spec **2025-11-25** makes **CIMD** the recommended client-registration mechanism (SHOULD) and
**deprecates DCR** (MAY, fallback only). Also newly relevant: RFC 9207 `iss` (SHOULD), OIDC
Discovery as an RFC 8414 alternative; RFC 8707 audience-binding stays MUST. → Design should be
**CIMD-first, DCR fallback**. Affects F-003/F-004; **REQUIREMENTS §0 needs updating**.

### Gaps to close after adopting the fork
RFC 8707 audience-binding (sigbit hardcodes `aud` to `externalURL`); CIMD support; RFC 9207 `iss`;
complete PRM/AS-metadata (advertise `jwks_uri`/introspection) and emit `WWW-Authenticate` with
`resource_metadata` on the `/mcp` 401 (sigbit returns a bare 401 JSON with no `WWW-Authenticate`);
add a `/revoke` route; passkey/WebAuthn + a real multi-user model (sigbit is bcrypt
single-shared-secret); key rotation + optional ES256. Risks: single maintainer, hand-rolled
metadata/DCR structs drift, transitive dependency bloat (ory/x, OTel, mongo) to prune. License
MIT→Apache-2.0 is compatible (retain MIT NOTICE).

### Deployment learning (generic)
Claude's cloud connects to remote MCP servers from Anthropic egress range **160.79.104.0/21**
(IPv4, documented). Geo/IP firewalls that block US sources make the connection fail **silently
before any request reaches the gateway** (nothing in gateway logs). A Let's Encrypt wildcard cert
obtained via DNS-01 does **not** prove inbound reachability, and NAT hairpin from inside the LAN
can make a server look externally reachable when it is not.

### Files changed
- `PROGRESS.md` — F-001 marked done; recommendation/decision recorded.
- (Evaluation clones and the PoC ran in throwaway scratch/VM environments outside the repo; no
  gateway code committed yet — implementation starts after the fork is created.)
