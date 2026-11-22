---
id: F-002
title: Choose language + OAuth library
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-06-25
depends-on:
superseded-by:
---

# F-002 — Choose language + OAuth library

## History

### F-002 — Choose language + OAuth library — DONE 2026-06-25

**Problem:** The implementation language and OAuth library were undecided; everything downstream depends on this.

**Decision: Go + Ory Fosite.**

**Rationale:**
- F-001 chose to hard-fork `sigbit/mcp-auth-proxy`, which is built in **Go** on **Ory Fosite** — adopting it dictates the stack, and re-deciding would mean discarding a working base.
- **Ory Fosite** is a vetted OAuth2/OIDC library (powers Ory Hydra), Apache-2.0 (permissive, no GPL/AGPL), so token issuance/PKCE/JWT stay in library code — satisfies SR-1 (no hand-rolled crypto).
- **Go** yields a tiny static single binary (supports GR-3 single-container), strong streaming-proxy support (FR-8), and broad contributor reach.
- Alternative **Python + authlib** rejected: heavier runtime footprint and would imply greenfield rather than reusing the validated fork base.

**Follow-up:** add the Go-specific section to `CODING-STANDARDS.md` (handled as part of F-008).

**Files changed:** `PROGRESS.md` (moved to Done; F-005 already references the stack).
