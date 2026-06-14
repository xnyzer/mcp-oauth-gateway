---
name: step-done
description: Run after a task is finished. Code review against CODING-STANDARDS.md, secrets scan, PROGRESS docs, Graphiti update, and commit preparation.
disable-model-invocation: true
---

# Post-step checklist

A task or substep was just finished. Applies to steps (1.2) and F-numbers (F-001, F-001a) alike. Work through this checklist systematically and handle each point yourself — **except where an explicit question to the user is required**. Summarise at the end what you did.

## 1. Code review & checks

- Read `CODING-STANDARDS.md` (if not already in context).
- Go through **all files changed/created in this step** and check them against the rules.
- **Fix violations directly** — don't present them to the user as a question.
- Run the project's checks and fix red results immediately. The language/stack is not decided yet (see F-002); once it is, run the project's typecheck/lint/test. For documentation/spec-only changes, verify internal links and formatting.
- **Never commit with red tests/checks.** Fix pre-existing red tests anyway, or report them explicitly.

## 2. Secrets scan (CRITICAL)

mcp-oauth-gateway is public and is a security/auth tool. Before proposing a commit, scan the working-tree changes **and** the commit-message draft for:
- Real tokens/bearers/passwords/API keys/private keys (PEM/JWK), private email addresses.
- Deployment internals: concrete IPs, SSH key names, hostnames, domains, "password set" notes.
- Content that belongs in `private/` (gitignored) but ended up in the public tree.

**Remove/mask findings immediately** and re-check. **Do not propose a commit while anything is open.**

## 3. PROGRESS.md + PROGRESS-ARCHIVE.md

**PROGRESS-ARCHIVE.md:** Transfer the complete section of the finished task from `PROGRESS.md` and add: which files were actually created/changed, what was concretely implemented, any notable decisions/deviations.

**PROGRESS.md:** **Remove** the task's detail section and add one line to the **Done** table:

```
| F-001a | Discovery metadata endpoints | 2026-06-14 |
```

For a complete F-number: mark the entry as `(DONE)` in the `<!-- FEATURE-INDEX ... -->`. **Do this directly, without asking.**

## 4. Graphiti knowledge graph

- Call `add_memory` with `group_id: "mcp-oauth-gateway"`.
- Describe: what was finished, which files/components created/changed, which config/endpoints/dependencies, which architecture/security decisions.

## 5. Prepare the commit

- **Never auto-commit!** Ask the user whether to commit, and propose a meaningful Conventional Commits message in English.
- In the body, briefly justify **design decisions** (`Decision: X over Y because …`). If the user weighed options: "User chose X over Y because …".

### 5a. Check the commit email (CRITICAL)

Before any `git commit`, verify the email is a **GitHub noreply address**:

```bash
git config --get user.email
```

Expected format: `<numeric-id>+<github-username>@users.noreply.github.com`
For this repo the convention is `12890660+xnyzer@users.noreply.github.com`.

If it differs:

```bash
GH_ID=$(gh api user --jq '.id')
GH_LOGIN=$(gh api user --jq '.login')
git config --local user.email "${GH_ID}+${GH_LOGIN}@users.noreply.github.com"
```

Only then commit. Never use `--author="..."` with a real email. **Why:** in a public repo no private email may land in commits — that would be a permanent data leak; cleanup requires `git filter-repo` + force-push.

### 5b. Co-Authored-By

The commit body ends with:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```
