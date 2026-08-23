# How to Code with Claude

Guide for working with Claude Code in the mcp-oauth-gateway project.

The workflow skills live in the **coding-kit plugin**, not in this repository — every command
below is prefixed `coding-kit:`. The project itself ships no skills of its own, so there is
nothing here to keep in sync with the kit.

---

## Overview: skills

| Skill | When to use | What happens |
|-------|-------------|--------------|
| `/coding-kit:add-feature` | Put a new task on the roadmap | Analysis → write-up → entry in PROGRESS.md, marker **BACKLOG** |
| `/coding-kit:prep-step` | Before implementing a task | Challenges the sketch against the current code, decomposes into substeps → plan in PROGRESS.md, marker **PLANNED** |
| `/coding-kit:build-step` | To implement a prepared task | Works the plan substep by substep, verifying each one |
| `/coding-kit:step-done` | After finishing a task/substep | Code review → checks → secrets + privacy scan → docs → Graphiti → commit question |
| `/coding-kit:audit-code` | One-off check of the whole code/stack | Check → results in AUDIT-RESULTS.md |

---

## Workflow 1: Intake a new task

**When:** You have an idea — a module, a feature, a refactoring, a docs task, anything.

```
You:    /coding-kit:add-feature DCR client expiry
Claude: Analysis... recommendation... open questions...
You:    yes, do that
Claude: Writes it out, shows you the text
You:    looks good
Claude: Records F-009 in PROGRESS.md as BACKLOG, updates the feature index
```

**Important:** Everything gets an F-number. No distinction between "feature" and "task".

---

## Workflow 2: Prepare & implement a task

**When:** You want to implement a task from PROGRESS.md.

```
You:    /coding-kit:prep-step F-005
Claude: Analysis... assessment: Large... substeps:
        F-005a — discovery + JWKS endpoints
        F-005b — authorize + token (PKCE)
        F-005c — upstream proxy
You:    yes, write that in
Claude: Records substeps in PROGRESS.md as PLANNED
You:    /coding-kit:build-step F-005
Claude: Implements F-005a, verifies, recommends step-done
You:    /coding-kit:step-done
Claude: Code review, checks, PROGRESS-ARCHIVE, Graphiti, commit question
You:    yes, commit
Claude: Committed. Should I continue with F-005b?
```

**Size assessment:**
- **Small** (< 200 lines, < 5 files) → directly doable, no decomposition
- **Medium** (200–500 lines, 5–15 files) → 2–3 substeps
- **Large** (> 500 lines, > 15 files) → 3–5 substeps

**Note:** `/coding-kit:prep-step` without an argument automatically takes the next open step.

---

## What `/coding-kit:step-done` does in detail

After each finished (sub)step:

1. **Code review & checks** — Check changed files against CODING-STANDARDS.md, fix violations;
   run the project checks. This project has **no justfile**: the checks are `gofmt -l .`,
   `go vet ./...`, `go test -race ./...`, plus the pinned `golangci-lint`, `go-licenses` and
   `govulncheck` that CI runs.
2. **Secrets & privacy scan** — Scan working tree + commit-message draft for secrets, tokens,
   keys, IPs and private emails. Remove findings immediately.
3. **PROGRESS.md / PROGRESS-ARCHIVE.md** — Update the Done table, move/remove the detail section.
4. **Graphiti** — Update the knowledge graph (`group_id: mcp-oauth-gateway`).
5. **Commit** — Ask whether to commit; propose a message (English, Conventional Commits, GitHub
   noreply email, Co-Authored-By).

---

## Extra: full audit with `/coding-kit:audit-code`

**When:** You want to check the **whole** stack once — code, deployment config, security,
dependencies. Writes `AUDIT-RESULTS.md` (gitignored, each run overwrites). Difference from
`/coding-kit:step-done`: the latter only checks the files just changed.

---

## Files this workflow touches

The full document index is in [`README.md`](README.md) ("Documentation"); it is not repeated here.
These are the ones the workflow itself writes or reads every run:

| File | Role in the workflow |
|------|----------------------|
| `PROGRESS.md` | Open tasks + Done table + feature index — every step starts and ends here |
| `PROGRESS-ARCHIVE.md` | Where a finished task's detail moves at `step-done` |
| `AUDIT-RESULTS.md` | Output of the last `/coding-kit:audit-code` run (temporary, gitignored) |
| `CLAUDE.md` | Project-specific Claude instructions (auto-loaded every session) |

The **binding rules** a change is reviewed against — `SPEC.md`, `CODING-STANDARDS.md`,
`THREAT-MODEL.md` — are described in README.

---

## Tips

- **Not everything at once.** Decompose large tasks into substeps via `/coding-kit:prep-step`.
- **`/coding-kit:step-done` after each substep.** Not everything at the end at once — otherwise details get lost in the docs.
- **Claude never commits automatically.** You are always asked.
- **Language:** You talk to Claude in German. Code, comments, commits, and variables are English.
- **Secrets:** Deployment internals (IPs, tokens, hostnames, key names) belong in `private/` (gitignored), never in the public tree.
- **Security-first:** This is a public auth boundary. No hand-rolled crypto, fail-closed, mandatory security review before public exposure. See `THREAT-MODEL.md`.
- **On errors:** Claude fixes diagnostic errors immediately. No workarounds, always the root cause.
