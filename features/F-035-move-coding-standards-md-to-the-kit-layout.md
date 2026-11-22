---
id: F-035
title: Move CODING-STANDARDS.md to the kit layout
type: change
status: BACKLOG
size:
created: 2026-11-22
done:
depends-on:
superseded-by:
---

# F-035 — Move CODING-STANDARDS.md to the kit layout

## Intake

**Problem:** `CODING-STANDARDS.md` predates the coding-kit template: eleven sections, the Go
rules in §11, and no `module:coding-standards` slot. The template composes its stack rules from
standards fragments in its §13, so the kit's Go fragments (`go`, `go-lang`) cannot be placed,
the template's newer general rules (comments, allowlist validation, least privilege,
write-then-verify, …) do not reach the project, and every `/coding-kit:update-conventions` run
offers the file again as a two-way replacement that would drop the project's rules.

**Goal:** The file follows the template's layout, so template updates merge three-way, and it
keeps every rule only this project has. What must stay the same: no rule is lost or weakened —
fail-closed as the single most important rule, the auth-specific negative tests, "prove a new
assertion can fail" with its three patterns, the `idp.Session` `Clone` rule, the Go toolchain
and version rules, Fosite + `golang-jwt` + `x/crypto`, MPL only where unavoidable — and every
citation of a section still points at the rule it meant.

**Solution sketch:**
- The template version as the base, the project-only rules added where they belong — the way
  the conventions sync of 2026-11-22 handled `SECURITY.md`, `.golangci.yml` and the others.
- The section numbers shift (§6 → §7, §7 → §8, §9 → §10, §11 → §13, …). About 16 explicit
  `CODING-STANDARDS §N` citations and about 45 bare `§N` citations in Go comments point at the
  old numbers; `docs_refs_test.go` only checks that a cited section exists, not what it says,
  and skips bare citations by design.
- A safe order: first make every bare citation explicit, so the guard sees it; then renumber
  with one mapping table; then check each moved citation against the content of its new
  section.
- Fill the slot with the module fragments `go` and `go-lang`; decide on `api-design` and
  `docker`, which detection proposes.
- Afterwards `/coding-kit:update-conventions` sets the base snapshot for the file.

**Dependencies:** none.

**To be analysed:** whether history entries in `features/` that cite old numbers stay as
written (they are records, like the `REQUIREMENTS.md` mentions the reading note in
`features/INDEX.md` covers) or get a note of their own; whether the guard should learn to catch
a citation whose section changed meaning.
