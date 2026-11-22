---
id: F-009
title: Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)
type: feature
status: DONE
size:
created: 2026-06-25
done: 2026-07-03
depends-on:
superseded-by:
---

# F-009 — Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first)

## History

### F-009 — Update REQUIREMENTS/spec for MCP 2025-11-25 (CIMD-first) — DONE 2026-07-03

**Problem:** `REQUIREMENTS.md` §0/FR-2 still framed **DCR** as the registration mechanism, but
the MCP authorization spec **2025-11-25** makes **CIMD** the recommended path (SHOULD) and
**deprecates DCR** (MAY, fallback). RFC 9207 `iss` and OIDC Discovery (as an RFC 8414
alternative) were newly relevant too.

**Idea:** Bring the source-of-truth docs in line with the current spec so F-004/F-005 build to
the right contract.

**Dependencies:** none (documentation).

#### What was done
- **§0 Verified background:** CIMD documented as the recommended registration mechanism
  (SHOULD), DCR as deprecated fallback (MAY), cross-referencing the F-003 decision. Added
  **RFC 9207** `iss` (SHOULD), **OIDC Discovery** as an RFC 8414 alternative, RFC 8707
  audience-binding staying MUST, and a **watch item**: re-verify against the MCP spec release
  candidate dated **2026-07-28** before any release. Header note no longer flags a pending
  CIMD update.
- **FR-2** reframed from "DCR, optionally CIMD" to **CIMD-first with DCR as deprecated
  fallback** (HTTPS-URL client IDs resolving to a Client ID Metadata Document); SR-5 abuse
  mitigations still apply to DCR registrations.
- **FR-1** gained an optional OIDC Discovery mirror (`/.well-known/openid-configuration`);
  **FR-3** now requires the RFC 9207 `iss` parameter in the authorization response (matching
  the F-005 gap list).
- **§6** converted from "open decisions" to the decided state (F-001/F-002/F-003/F-008c), with
  multi-user evolution as the only remaining open point.
- **Consistency fixes beyond REQUIREMENTS:** `README.md` headline/Why no longer frame the
  project as a DCR gateway (now OAuth 2.1 gateway, CIMD-first with DCR fallback); `CLAUDE.md`
  status/entry pointer moved to F-010.

**Decisions/deviations:** the §6 cleanup and the README/CLAUDE.md alignment went slightly
beyond the task text (which named only §0/FR-2) — done for doc consistency per the approved
plan. Spec facts (SHOULD/MAY, RC date) taken from the F-001/F-003 verified research; live
re-verification is deferred to the pre-release watch item. Documentation only — no endpoints,
config, or dependencies changed.

**Files changed:** `REQUIREMENTS.md`, `README.md`, `CLAUDE.md` (+ `PROGRESS.md` /
`PROGRESS-ARCHIVE.md` bookkeeping).
