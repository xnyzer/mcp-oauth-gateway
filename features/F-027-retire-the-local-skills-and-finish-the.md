---
id: F-027
title: Retire the local skills and finish the documentation architecture
type: feature
status: DONE
size:
created: 2026-08-23
done: 2026-08-23
depends-on:
superseded-by:
---

# F-027 — Retire the local skills and finish the documentation architecture

## History

### F-027 — Retire the local skills and finish the documentation architecture — DONE 2026-08-23

**Intake note:** this task was not written by `/coding-kit:add-feature`. It came out of the
operator's review of the finished F-026 — three questions ("why were the local skills touched?",
"the spec is still long — rules or documentation?", "is anything duplicated or in the wrong
place?") — and was executed in the same session on their instruction. It is recorded as its own
F-number because the work is a separate concern from dissolving `REQUIREMENTS.md`, and finished
work without a home is worse than an out-of-band intake.

#### The local skills are gone

`.claude/skills/` held four skills (`add-feature`, `prep-step`, `step-done`, `audit-code`) that the
project no longer uses — the workflow runs on the **coding-kit plugin** instead. F-026b had dutifully
*edited* two of them because its plan named them; the plan never asked whether they were still alive.
All four are deleted.

Deleting them was the smaller half. Six documents pointed at them: `CLAUDE.md` (three places),
`HOW-TO-CODE-WITH-CLAUDE.md` (rewritten — most of the file was about these four skills),
`CODING-STANDARDS.md` and `CONTRIBUTING.md` (both cite "the `step-done` skill" for commit-email and
secrets hygiene), plus the live workflow sentences in `PROGRESS.md` and `PROGRESS-ARCHIVE.md`.
Historical mentions of past `/audit-code` and `/prep-step` runs in the archive were left alone.

Two facts the repository did not record and now does: the workflow has **four** stages, not three
(`add-feature` → `prep-step` → **`build-step`** → `step-done`), and the plugin's `step-done` runs
"checks via just" while this project has **no justfile** — so `HOW-TO-CODE-WITH-CLAUDE.md` now names
the real gate (`gofmt`, `go vet`, `go test -race`, plus pinned `golangci-lint`, `go-licenses`,
`govulncheck`).

#### SPEC is a rules document, and now says so

Measured rather than asserted: **325 citations from Go code against 46 from documentation**. Nobody
reads `SPEC.md` to *use* the gateway; it is read to *change* it. Two consequences:

- **§3 was a duplicate of README.** A first pass compared env-var *names* (52 of 56 shared) — too
  shallow a measurement to act on, so it was redone against content: README carries the validation
  ranges (1 m–24 h, `N/s|m|h`, `0` disables) **and** the three startup contracts the Go code cites
  from §3.1 (the plain-http WARNING, the auth-backend fail-fast, `TRUSTED_PROXIES` normalisation).
  The duplication was total. The tables are gone; §3 keeps only what is normative and points at
  README + `.env.example` for the reference — **−33 % characters** (6631 → 4415). Line count barely
  moved (73 → 76), which is why characters are the honest metric for a table-to-prose change.
- **§4 was a verification record, not a contract** (zero code citations). Moved to
  `docs/MCP-CONFORMANCE.md`. A 12-line stub stays at §4 so that the existing `SPEC.md §4` references
  in `CHANGELOG.md` and this archive — append-only records — keep resolving, and so no section is
  renumbered.

**A mistake worth recording:** qualifying the moved record's bare `§1.5`-style references (they meant
SPEC, but collided with the new file's own §1) was done with a blanket regex, which also rewrote
`RFC 8707 §2` and `CODING-STANDARDS §7`, and pointed the file's own §4.3 references at the stub.
Caught by inspection and repaired. A second slip — rewriting §3 dropped four requirement anchors
(FR-6, GR-1, SR-5, SR-9) — was caught by diffing the requirement-ID **multiset** against the previous
state, not by reading.

#### The tidy-up the operator asked for, audited rather than assumed

Four checks were run; **five** things failed them:

1. **`docs/README.md` was a dead stub** — unlinked from anywhere, listing three "planned" documents
   (fronting an MCP server, adding the Claude connector, the configuration reference) that have all
   existed as full README sections for months. Deleted.
2. **`CLAUDE.md` claimed `v0.1.0` while the latest tag is `v0.3.0`** — two releases stale, the cost
   of keeping the release state in three documents. Fixed at the cause: `CLAUDE.md` now points at
   `PROGRESS.md` for the live state and keeps only what does not change.
3. **Three live pointers at the moved `SPEC.md` §4** (`THREAT-MODEL.md`, the close-out checklist in
   `docs/VERIFICATION.md`, the `PROGRESS.md` state paragraph) — repointed. Historical mentions left.
4. **Three competing document indexes** (README 9 entries, `CLAUDE.md` 5, `HOW-TO` 7, overlapping).
   `HOW-TO` now lists only the four files the workflow itself writes and defers to README.
5. **README's index named neither `CODING-STANDARDS.md` nor `CONTRIBUTING.md`.** It now separates
   **the rules** (`SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`) from **the records**
   (`docs/MCP-CONFORMANCE.md`, `docs/VERIFICATION.md`, `CHANGELOG.md`, `CONTRIBUTING.md`), each with
   a line on when to reach for it.

`SPEC.md` states in its own header that it is binding and names the two documents beside it;
`CLAUDE.md` names the same three up front. After the fixes, all 15 tracked documents are reachable
from README or `CLAUDE.md`, and no live pointer aims at a moved or deleted target.

**Files:** `.claude/skills/` (4 files deleted), `docs/README.md` (deleted),
`docs/MCP-CONFORMANCE.md` (new), `SPEC.md`, `README.md`, `CLAUDE.md`,
`HOW-TO-CODE-WITH-CLAUDE.md`, `CODING-STANDARDS.md`, `CONTRIBUTING.md`, `THREAT-MODEL.md`,
`docs/VERIFICATION.md`, `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.
