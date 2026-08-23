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
**The current release and deployment state lives in `PROGRESS.md`** (its "State" paragraph at the
top) — it is not repeated here, because a second copy drifts. What is stable: the gateway is a hard
fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite), public on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`), feature-complete against `SPEC.md`, security-audited (F-006b)
and live-verified against Claude web + iOS (F-006c). It is verified against the **final MCP spec
2026-07-28** (F-017; conformance table in `docs/MCP-CONFORMANCE.md`) and the standing spec watch
item is **closed**. Rationale for finished work is in `PROGRESS-ARCHIVE.md`.

**The binding rules are three documents:** `SPEC.md` (what must hold — contracts + the FR/GR/SR
register in §5), `CODING-STANDARDS.md` (how code is written), `THREAT-MODEL.md` (what it defends
against). Everything else is description or record.

Read in order: `README.md`, `SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`, `PROGRESS.md`
(+ `PROGRESS-ARCHIVE.md` for past decisions). **To continue: open `PROGRESS.md`** — new work
is intaked via `/coding-kit:add-feature`, planned with `/coding-kit:prep-step <F-number>`, built
with `/coding-kit:build-step <F-number>` and finished with `/coding-kit:step-done <F-number>`. Work the open tasks top-to-bottom. Security fixes ship as patch
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
audits, docs). The workflow skills come from the **coding-kit plugin** (this project keeps no
skills of its own): `/coding-kit:add-feature` (intake), `/coding-kit:prep-step` (plan + decompose),
`/coding-kit:build-step` (implement), `/coding-kit:step-done` (review + secrets-scan + docs +
Graphiti + commit question), `/coding-kit:audit-code` (full audit). Details:
`HOW-TO-CODE-WITH-CLAUDE.md`. Coding rules: `CODING-STANDARDS.md`.

## Key documents
**Rules (binding):** `SPEC.md` (implementable contracts, incl. the FR/GR/SR requirement register
in §5), `CODING-STANDARDS.md`, `THREAT-MODEL.md`.
**Work:** `PROGRESS.md` (roadmap — work top-to-bottom), `PROGRESS-ARCHIVE.md` (finished tasks +
their rationale).
**Records:** `docs/MCP-CONFORMANCE.md` (MCP spec conformance), `docs/VERIFICATION.md` (live
deployment runbook), `CHANGELOG.md`.
