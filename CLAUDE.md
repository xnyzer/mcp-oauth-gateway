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
**Released: v0.1.0 is public** — repo public, GitHub release published, multi-arch image on
GHCR (`ghcr.io/xnyzer/mcp-oauth-gateway`). The gateway (hard fork of `sigbit/mcp-auth-proxy`,
Go + Ory Fosite) is feature-complete against `SPEC.md`, security-audited (F-006b, all
crit/high/med findings fixed), live-verified against Claude web + iOS (F-006c) and verified
against the MCP **2026-07-28 spec RC** (F-007e). All roadmap tasks **F-001–F-011 are done**;
rationale in `PROGRESS-ARCHIVE.md`. Open: the **F-012 backlog** (audit low-severity
follow-ups) and the watch item to re-check the final MCP spec after 2026-07-28.

Read in order: `README.md`, `REQUIREMENTS.md`, `SPEC.md`, `THREAT-MODEL.md`, `PROGRESS.md`
(+ `PROGRESS-ARCHIVE.md` for past decisions). **To continue: open `PROGRESS.md`** — new work
is intaked via `/add-feature`, planned with `/prep-step <F-number>`, finished with
`/step-done <F-number>`. Work the open tasks top-to-bottom. Security fixes ship as patch
releases (tag → release workflow); Dependabot + weekly govulncheck watch the dependencies.

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
`REQUIREMENTS.md` (intent-level source of truth), `SPEC.md` (implementable contracts),
`THREAT-MODEL.md`, `PROGRESS.md` (roadmap — work top-to-bottom), `PROGRESS-ARCHIVE.md`
(finished tasks + their rationale).
