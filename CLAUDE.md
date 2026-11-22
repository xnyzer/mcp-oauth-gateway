# mcp-oauth-gateway — Claude Instructions

<!-- section:claude-graphiti -->
## Graphiti Memory (Knowledge Graph)
**group_id**: `mcp-oauth-gateway`

- **Query the graph first** before searching files:
  `search_memory_facts(query="…", group_ids=["mcp-oauth-gateway"])`,
  `search_nodes(query="…", group_ids=["mcp-oauth-gateway"])`.
- **Write** via `add_memory` (`group_id: "mcp-oauth-gateway"`) following the Graphiti section
  of the coding-kit global rules: knowledge with no place in the repo, plus one short
  pointer per finished feature; details stay in the feature file.
- Requires a running Graphiti MCP server. Without one, reading is skipped silently;
  anything that should have been written is reported with its text, never redirected to
  `docs/notes.md`.
<!-- /section:claude-graphiti -->

## Overview
A self-hosted **OAuth 2.1 + DCR gateway** that fronts any MCP server (bearer-only or
unauthenticated) so OAuth-only MCP clients (e.g. Claude's apps) can connect — without a
third-party identity provider. Generic, lightweight, reverse-proxy- and upstream-agnostic;
intended to later become a module of the memstead suite. Full context: `README.md`.
Goals, non-goals and constraints are the FR/GR/SR requirement register in `SPEC.md` §5 —
not repeated here.

## Status & where to start
**State (2026-11-22): released and live.** **v0.5.0 is public** — multi-arch image on GHCR
(`ghcr.io/xnyzer/mcp-oauth-gateway`, tags `0.5.0`/`0.5`); the deployment runs `0.5.0` since
2026-10-13. The gateway is a hard fork of `sigbit/mcp-auth-proxy` (Go + Ory Fosite),
feature-complete against `SPEC.md`, security-audited (F-006b) and live-verified against Claude
web + iOS (F-006c), end to end again on 2026-08-21: Claude connects via **CIMD**, no longer via
the deprecated DCR fallback. It is verified against the **final MCP spec 2026-07-28** (F-017;
conformance table in `docs/MCP-CONFORMANCE.md`) and the standing spec watch item is
**closed**. Open work and the reasons behind finished work are in `features/`.

**The binding rules are three documents:** `SPEC.md` (what must hold — contracts + the FR/GR/SR
register in §5), `CODING-STANDARDS.md` (how code is written), `THREAT-MODEL.md` (what it defends
against). Everything else is description or record.

<!-- section:claude-startup -->
Read `README.md`, then `features/INDEX.md`: its recommended order and the table of all
features are the working context. Open a feature file (`features/F-NNN-*.md`) when you
work on that feature or need the reasons behind a finished one — not all of them at
startup. **To continue: take the first feature of the recommended order, run `/prep-step`
to specify and plan it, `/build-step` to implement it, then `/step-done` to finish each
substep.**

Project notes — knowledge with no other place in the repo: @docs/notes.md
<!-- /section:claude-startup -->

Before changing code, read the three binding documents above. Security fixes ship as
patch releases (tag → release workflow); Dependabot + weekly govulncheck watch the
dependencies.

<!-- section:claude-conventions -->
## Conventions

- **Languages** (chosen at instantiation, independent of repo visibility — identifiers,
  Conventional-Commit tokens, status tokens, and governance docs are always English):
  - Living docs (feature files and their index): **English**
  - CLAUDE.md prose (project parts of this file): **English**
  - Code comments & docstrings: **English**
  - Commit-message prose: **English**
  - README & public docs: **English**
- Git: **Conventional Commits** (tokens English), prose in English,
  imperative mood; body ends with
  `Co-Authored-By: Claude <noreply@anthropic.com>`. Commit email = **GitHub noreply**
  (verify `git config user.email`; fix via `gh api user`). **Never auto-commit — ask first.**
- License: **Apache-2.0**; dependencies must be permissive-licensed (no GPL, AGPL
  or LGPL; MPL is fine) — deviations only as a conscious decision, recorded with its
  reason in `license-policy.txt`.
- Toolchain: **mise + just + lefthook** are mandatory; all checks run via **`just check`**
  and it must be green before any commit.
- Secrets and private material never enter the tree; operational internals go to
  `private/` (gitignored). Living docs stay free of private info (names, customers, local
  paths, IPs) — the project must remain publishable at any time.
<!-- /section:claude-conventions -->
- Git author: `xnyzer <12890660+xnyzer@users.noreply.github.com>`.
- **MPL-2.0 is accepted only where unavoidable** (e.g. transitive via Ory Fosite) — stricter
  than the licence rule above.
- **Security-first** (it's a public auth boundary): no hand-rolled crypto (vetted lib only),
  fail-closed, mandatory security review before any public exposure. See `THREAT-MODEL.md`.
- Ask instead of guessing. The user communicates in German (replies in German); the
  repo/docs stay English.

<!-- section:claude-workflow -->
## Workflow & skills

Every task is an F-number with its own file in `features/` (`F-NNN-short-name.md`, from
`F-000-template.md`): intake, specification, plan and history in one place.
`features/INDEX.md` holds the recommended order and the table of all features, which
`just features-index` generates from the files. Skills come from the **coding-kit
plugin**: `/add-feature` (intake and advice), `/prep-step` (specify, size and plan),
`/build-step` (implement the plan), `/step-done` (review, secrets scan, history and
booking, commit question), `/audit-code` (full audit). Details:
`HOW-TO-CODE-WITH-CLAUDE.md`.
Decisions about one feature are recorded in its file; a decision that shapes the project
beyond one feature becomes an ADR in `docs/adr/`. Coding rules: `CODING-STANDARDS.md`.
Project-local deviations from template conventions are registered in
`.claude/convention-overrides.md`.
<!-- /section:claude-workflow -->

## Key documents
**Rules (binding):** `SPEC.md` (implementable contracts, incl. the FR/GR/SR requirement register
in §5), `CODING-STANDARDS.md`, `THREAT-MODEL.md`.
**Work:** `features/INDEX.md` (recommended order + table of all features), one file per task
in `features/` (intake, plan, history and rationale).
**Records:** `docs/MCP-CONFORMANCE.md` (MCP spec conformance), `docs/VERIFICATION.md` (live
deployment runbook), `CHANGELOG.md`.
