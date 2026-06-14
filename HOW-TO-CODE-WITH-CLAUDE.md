# How to Code with Claude

Guide for working with Claude Code in the mcp-oauth-gateway project.

---

## Overview: skills

| Skill | When to use | What happens |
|-------|-------------|--------------|
| `/add-feature` | Put a new task on the roadmap | Analysis → write-up → entry in PROGRESS.md |
| `/prep-step` | Before implementing a task | Analysis → decomposition → plan in PROGRESS.md → ask whether to start |
| `/step-done` | After finishing a task/substep | Code review → secrets scan → docs → Graphiti → commit question |
| `/audit-code` | One-off check of the whole code/stack | Check → results in AUDIT-RESULTS.md |

---

## Workflow 1: Intake a new task

**When:** You have an idea — a module, a feature, a refactoring, a docs task, anything.

```
You:    /add-feature DCR client expiry
Claude: Analysis... recommendation... open questions...
You:    yes, do that
Claude: Writes it out, shows you the text
You:    looks good
Claude: Records F-009 in PROGRESS.md, updates the feature index
```

**Important:** Everything gets an F-number. No distinction between "feature" and "task".

---

## Workflow 2: Prepare & implement a task

**When:** You want to implement a task from PROGRESS.md.

```
You:    /prep-step F-005
Claude: Analysis... assessment: Large... substeps:
        F-005a — discovery + JWKS endpoints
        F-005b — authorize + token (PKCE)
        F-005c — upstream proxy
You:    yes, write that in
Claude: Records substeps in PROGRESS.md
Claude: Should I start with F-005a?
You:    yes
Claude: Implements F-005a...
You:    /step-done
Claude: Code review, checks, PROGRESS-ARCHIVE, Graphiti, commit question
You:    yes, commit
Claude: Committed. Should I continue with F-005b?
```

**Size assessment:**
- **Small** (< 200 lines, < 5 files) → directly doable, no decomposition
- **Medium** (200–500 lines, 5–15 files) → 2–3 substeps
- **Large** (> 500 lines, > 15 files) → 3–5 substeps

**Note:** `/prep-step` without an argument automatically takes the next open step.

---

## What `/step-done` does in detail

After each finished (sub)step:

1. **Code review & checks** — Check changed files against CODING-STANDARDS.md, fix violations; run the project's typecheck/lint/test once a stack is chosen.
2. **Secrets scan** — Scan working tree + commit-message draft for secrets/tokens/keys/IPs/private emails. Remove findings immediately.
3. **PROGRESS.md / PROGRESS-ARCHIVE.md** — Update the Done table, move/remove the detail section.
4. **Graphiti** — Update the knowledge graph (`group_id: mcp-oauth-gateway`).
5. **Commit** — Ask whether to commit; propose a message (English, Conventional Commits, GitHub noreply email, Co-Authored-By).

---

## Extra: full audit with `/audit-code`

**When:** You want to check the **whole** stack once — code, deployment config, security, dependencies. Writes `AUDIT-RESULTS.md` (gitignored, each run overwrites). Difference from `/step-done`: the latter only checks the files just changed.

---

## Important files

| File | Purpose |
|------|---------|
| `PROGRESS.md` | Open tasks + Done table + feature index |
| `PROGRESS-ARCHIVE.md` | Full documentation of all finished tasks |
| `CODING-STANDARDS.md` | Binding coding rules |
| `REQUIREMENTS.md` | Source of truth for the spec |
| `THREAT-MODEL.md` | Security model — read before touching auth paths |
| `AUDIT-RESULTS.md` | Results of the last `/audit-code` run (temporary, gitignored) |
| `CLAUDE.md` | Project-specific Claude instructions (auto-loaded) |
| `.claude/skills/` | Skill definitions |

---

## Tips

- **Not everything at once.** Decompose large tasks into substeps via `/prep-step`.
- **`/step-done` after each substep.** Not everything at the end at once — otherwise details get lost in the docs.
- **Claude never commits automatically.** You are always asked.
- **Language:** You talk to Claude in German. Code, comments, commits, and variables are English.
- **Secrets:** Deployment internals (IPs, tokens, hostnames, key names) belong in `private/` (gitignored), never in the public tree.
- **Security-first:** This is a public auth boundary. No hand-rolled crypto, fail-closed, mandatory security review before public exposure. See `THREAT-MODEL.md`.
- **On errors:** Claude fixes diagnostic errors immediately. No workarounds, always the root cause.
