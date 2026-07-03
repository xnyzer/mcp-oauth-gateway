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
The base gateway exists: a working **hard fork of `sigbit/mcp-auth-proxy`** (Go + Ory Fosite),
builds and tests green on `main`. Done so far — **F-001** (decided to fork sigbit; validated by a
live Claude PoC), **F-002** (Go + Ory Fosite), **F-003** (CIMD-first, DCR deprecated fallback),
**F-008** (fork imported, CI green), **F-009** (REQUIREMENTS updated to CIMD-first); rationale in
`PROGRESS-ARCHIVE.md`. The binary is still named `mcp-warp` until the rebrand (F-010).

Read in order: `README.md`, `REQUIREMENTS.md`, `THREAT-MODEL.md`, `PROGRESS.md`
(+ `PROGRESS-ARCHIVE.md` for past decisions). **To continue: open `PROGRESS.md`, take the first
open task (top of "Open tasks" — currently F-010), run `/prep-step <F-number>` to plan, then
`/step-done <F-number>` to finish.** Work the open tasks top-to-bottom.

## Conventions
- **Repo language: English** (public/international).
- Git: author `xnyzer <12890660+xnyzer@users.noreply.github.com>`, **Conventional Commits**,
  body ends with `Co-Authored-By: Claude <noreply@anthropic.com>`. **Never auto-commit** — ask first.
- License **Apache-2.0**; **dependencies must be permissive (no GPL/AGPL/LGPL)** — weak-copyleft
  MPL-2.0 accepted only where unavoidable (e.g. transitive via Ory Fosite).
- **Security-first** (it's a public auth boundary): no hand-rolled crypto (vetted lib only),
  fail-closed, mandatory security review before any public exposure. See `THREAT-MODEL.md`.
- Ask instead of guessing. The user communicates in German (replies in German); the repo/docs stay English.

## Workflow & skills
Tasks are tracked in `PROGRESS.md` as F-numbers (no distinction between features, refactors,
audits, docs). Four skills in `.claude/skills/`: `/add-feature` (intake), `/prep-step` (plan +
decompose), `/step-done` (review + secrets-scan + docs + Graphiti + commit question),
`/audit-code` (full audit). Details: `HOW-TO-CODE-WITH-CLAUDE.md`. Coding rules: `CODING-STANDARDS.md`.

## Key documents
`REQUIREMENTS.md` (source of truth), `THREAT-MODEL.md`, `PROGRESS.md` (roadmap — work
top-to-bottom), `PROGRESS-ARCHIVE.md` (finished tasks + their rationale).
