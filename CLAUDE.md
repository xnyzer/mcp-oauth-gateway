# mcp-oauth-gateway — Claude Instructions

## Graphiti Memory (Knowledge Graph)
**group_id**: `mcp-oauth-gateway`

- **Query the graph first** before searching files:
  `search_memory_facts(query="…", group_ids=["mcp-oauth-gateway"])`,
  `search_nodes(query="…", group_ids=["mcp-oauth-gateway"])`.
- **After significant changes**, update via `add_memory` (`group_id: "mcp-oauth-gateway"`,
  `source: "text"`, descriptive `name`). Graphiti auto-invalidates contradictions.

## Overview
A self-hosted **OAuth 2.1 + DCR gateway** that fronts any MCP server (bearer-only or
unauthenticated) so OAuth-only MCP clients (e.g. Claude's apps) can connect — without a
third-party identity provider. Generic, lightweight, reverse-proxy- and upstream-agnostic;
intended to later become a module of the memstead suite. Full context: `README.md`.

## Status & where to start
**Specification phase — no code yet.** Read in order: `README.md`, `REQUIREMENTS.md`,
`THREAT-MODEL.md`, `PROGRESS.md`. To resume from empty context: `STARTPROMPT.md`.
First real work item = **PROGRESS F-001: build-vs-fork evaluation** (assess
`atrawog/mcp-oauth-gateway` et al. — don't duplicate).

## Conventions
- **Repo language: English** (public/international).
- Git: author `xnyzer <12890660+xnyzer@users.noreply.github.com>`, **Conventional Commits**,
  body ends with `Co-Authored-By: Claude <noreply@anthropic.com>`. **Never auto-commit** — ask first.
- License **Apache-2.0**; **dependencies must be permissive (no GPL/AGPL)**.
- **Security-first** (it's a public auth boundary): no hand-rolled crypto (vetted lib only),
  fail-closed, mandatory security review before any public exposure. See `THREAT-MODEL.md`.
- Ask instead of guessing. The user communicates in German (replies in German); the repo/docs stay English.

## Workflow & skills
Tasks are tracked in `PROGRESS.md` as F-numbers (no distinction between features, refactors,
audits, docs). Four skills in `.claude/skills/`: `/add-feature` (intake), `/prep-step` (plan +
decompose), `/step-done` (review + secrets-scan + docs + Graphiti + commit question),
`/audit-code` (full audit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`. Coding rules: `CODING-STANDARDS.md`.

## Key documents
`REQUIREMENTS.md` (source of truth), `THREAT-MODEL.md`, `PROGRESS.md` (roadmap, start at F-001),
`PROGRESS-ARCHIVE.md` (finished tasks), `STARTPROMPT.md` (resume prompt).
