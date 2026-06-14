---
name: add-feature
description: Put a new task on the roadmap. Analyses the idea, checks for overlaps, fleshes it out, and adds it to PROGRESS.md after approval.
disable-model-invocation: true
---

# Intake a task

The user has an idea for a new task. It can be a module, a feature, a refactoring, an audit, a documentation task, or anything else — no distinction is made. Everything gets an F-number and lands in the PROGRESS.md backlog.

Argument: short description of the task (e.g. "DCR client expiry", "JWKS rotation", "rate-limit middleware").

## 1. Understand the idea

- What exactly should be done?
- If the description is unclear: **ask** — don't guess.

## 2. Analysis

- **Sensible for mcp-oauth-gateway?** Does it fit the scope (a generic, self-hosted OAuth 2.1 + DCR gateway in front of an MCP server)?
- **Does something similar already exist?** Read the `<!-- FEATURE-INDEX ... -->` comment at the end of `PROGRESS.md` — overlaps or dependencies? Only read the full description when there is a concrete suspicion.
- **Can an existing entry be extended** instead of creating a new one?
- **Technical feasibility:** constraints, given the language/stack are not yet decided (see F-002)?
- **Security implications:** This is a public auth boundary. New attack vectors? External services? Secrets? Anything that touches token issuance, PKCE, JWKS, DCR, or consent gets extra scrutiny — see `THREAT-MODEL.md`.

## 3. Present to the user

Present the analysis briefly:
- Recommendation: new entry or extension of an existing one?
- Dependencies on other entries
- Open questions or decisions

**Wait for OK before fleshing it out.**

## 4. Flesh out

After approval: write the task out in the PROGRESS.md schema.

**F-number:** At the end of `PROGRESS.md` there is a `<!-- FEATURE-INDEX ... -->` comment. Read the `next-feature:` line, use that number, then:
1. Increment `next-feature:` to N+1
2. Add a new line to the index (e.g. `F-009 New feature`)

**Base format (always):**

```markdown
### F-NNN — [Name]

**Problem:** [1-2 sentences — what is missing, why it matters]

**Idea:** [2-3 sentences, solution approach]

**Possible implementation:**
- [Technical details, architecture sketch]
- [New endpoints, config, dependencies]
- [Which patterns/libraries — must stay permissive-licensed, no GPL/AGPL]

**Dependencies:** [entries that must be done first]
```

**Optional extra sections (for complex tasks):** Technical approach, Flow (numbered), Configuration (env vars), Still to analyse.

Match the style and level of detail to existing entries in PROGRESS.md.

## 5. Record

- Show the drafted text to the user.
- **Only after explicit approval**, add it to `PROGRESS.md` under "Feature ideas (backlog)".
- **Before recording**, scan for secrets/internals (no real tokens, IPs, hostnames, key names — PROGRESS.md is public).
- Update the Graphiti knowledge graph (`add_memory` with `group_id: "mcp-oauth-gateway"`).
