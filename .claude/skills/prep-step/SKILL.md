---
name: prep-step
description: Prepare a task before implementation. Analyses scope, decomposes into substeps if needed, and writes the plan into PROGRESS.md.
disable-model-invocation: true
---

# Prepare a task

Before a task is implemented, analyse it thoroughly, decompose it if needed, and write the plan into PROGRESS.md.
Argument: number from PROGRESS.md — step number (e.g. "1.2") or F-number (e.g. "F-001"). If no argument: take the next open step.

## 1. Read & understand the task

- Read the task from `PROGRESS.md` — description, files, dependencies, acceptance criteria.
- Read `CODING-STANDARDS.md` (if not already in context).
- If there are dependencies: check whether they are done (Done table at the top + feature index at the end of PROGRESS.md).
- Check `REQUIREMENTS.md` and `THREAT-MODEL.md` for the full context of the task.

## 2. Analyse scope

- Which files/components must be created or changed?
- Is there existing code/config that can be reused?
- Which new config (env vars), endpoints, dependencies become necessary? New dependencies must be permissive-licensed (no GPL/AGPL).
- Check against the security posture (-> `THREAT-MODEL.md`): does the design stay fail-closed? Any hand-rolled crypto (forbidden — vetted library only)? Does it touch token issuance, PKCE, JWKS, DCR, or consent?
- Estimated scope: roughly how many lines of code/config?

## 3. Assess size & decompose if needed

**Small (< 200 lines, < 5 files):** Directly doable, no decomposition. List a short plan.

**Medium (200-500 lines, 5-15 files):** Decompose into 2-3 logical substeps. Each substep runnable/meaningful on its own.

**Large (> 500 lines, > 15 files):** Decompose into 3-5 substeps, each with its own acceptance criteria.

## 4. Present the plan to the user

```
### [Number] — [Name]

**Assessment:** Small / Medium / Large
**Estimated scope:** ~N lines, N files

**Substeps:** (only for Medium/Large)
1. [Number]a — [Name]: [what, which files, acceptance criteria]
2. ...

**New endpoints/config/dependencies:** [which?]

**Risks / open questions:**
- ...
```

Substeps inherit the parent task's numbering convention (F-001 -> F-001a, F-001b ...).

**Wait for OK — do NOT start implementing!**

## 5. Record substeps in PROGRESS.md

After approval:
- **If Small:** Change nothing — the existing task is enough.
- **If Medium/Large:** Insert substeps directly under the parent task, in the existing format (What / Files / Dependencies / acceptance criteria as checkboxes). Keep the parent task as heading/context.

## 6. Ask whether to start

- Ask: "Should I start with [Number]a?"
- **Only implement after explicit OK.**
