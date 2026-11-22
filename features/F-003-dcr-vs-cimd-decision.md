---
id: F-003
title: DCR vs CIMD decision
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-06-25
depends-on:
superseded-by:
---

# F-003 — DCR vs CIMD decision

## History

### F-003 — DCR vs CIMD decision — DONE 2026-06-25

**Problem:** Decide the client-registration model — DCR, CIMD, or both.

**Decision: support both — CIMD-first, with DCR retained as a deprecated fallback.**

**Rationale:**
- MCP authorization spec **2025-11-25** makes **CIMD** the recommended mechanism (SHOULD) and **deprecates DCR** (MAY, fallback only). Claude supports CIMD/DCR/Anthropic-creds and prefers CIMD.
- The fork base (sigbit) currently implements **DCR only** (open `/register`, no CIMD). So DCR comes for free as the backward-compat fallback; **CIMD must be added** (tracked as a gap in F-005).
- Not DCR-only (would ignore the now-recommended mechanism and cause registration bloat); not CIMD-only (would drop backward-compat with AS/clients that still rely on DCR).
- Regardless of model, apply **SR-5** DCR-abuse mitigations (rate-limit `/register`, auto-expiry, client cap).
- `REQUIREMENTS.md` §0/FR-2 must be updated to reflect CIMD-first — tracked as **F-009**.

**Files changed:** `PROGRESS.md` (moved to Done).
