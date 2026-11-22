# .claude/

Claude Code project configuration.

## settings.json (managed by the template)

Hardened permissions: a tight allow-list (`just`, `mise`, read-only git, hooks/scanner)
plus a deny-list for secret material (`.env*`, key files, `.ssh/`, `.aws/`, `secrets/`,
`credentials/`) and for `git push --force`.

**Auto memory is off** (`"autoMemoryEnabled": false`). Claude Code keeps its auto memory
in the home folder of one machine, so what it saved there would not travel with the
project. Knowledge with no other place in the repo goes to the Graphiti graph (when
`CLAUDE.md` has a Graphiti block) or to `docs/notes.md`. The project setting wins over a
user setting that turns auto memory on.

**Why the env deny rules look the way they do.** Deny beats allow and a deny rule cannot
carry an exception, so a broad `Read(**/.env*)` would shadow the `.env.example` allow entry
and make the tracked placeholder unusable. Narrowing the deny to a list of known names is
worse: whatever is not on the list (`.env.bak` — a literal copy of a real `.env` — `.env.prod`,
`.env.ci`) becomes readable *without a prompt*, because read-only tools need no approval inside
the working directory.

The rules therefore carve the exception out by hand, with positive character classes that
exclude one letter each, so `.env.example` is the only spelling that no deny rule matches.
Two properties of the matcher make this work, both measured rather than assumed:

- **There is no negation.** `[!e]` and `[^e]` are *not* negated classes — they are read as
  positive sets containing `e`, so such a rule blocks `.env.example` and allows everything
  else, the exact inverse of the intent. Never write one.
- **Matching is case-insensitive**, so the lowercase ranges also cover `.env.PROD`. Adding
  `A-Z` to a class breaks it: the uppercase range then swallows the lowercase letter the class
  was meant to exclude.

Known residual: a suffix starting with `exa` that is not `example` (`.env.exact`) and exact
truncations (`.env.exa`) are not matched. Neither is a real env filename; closing them would
cost one pattern per prefix letter.

## settings.local.json (never committed)

Machine-local settings and permission grants accumulate here; it is gitignored and must
never be committed or copied between machines — it tends to collect local paths and
project internals.

## convention-overrides.md

The registry of deliberate project-local deviations from template conventions: why a
managed file deviates (Files table, with a kind — `skip`, `keep`, `adapt` or none) and
which rules differ (Rules table). `/update-conventions` follows the kinds; `/step-done`
reports changed managed files that have no row.

## template-version

Stamped by `/new-project`; records the coding-kit version (template and skills share it)
this project was instantiated from or last synced to. `/update-conventions` shows the
template changes since then. Do not edit by hand.

## template-answers

The values this project was instantiated with (name, languages, license, stack module,
visibility, chosen optional blocks and fragments), one `KEY=value` per line. The skills
render the template from it; a skill that changes one of these values updates the file.

## template-base/

The base snapshot: the pure template version of every managed file at the last sync, as
`<file>.base` (the suffix keeps tools from picking the copies up). `/update-conventions`
merges three-way against it, so your own additions to managed files survive template
updates. Generated — never edit it by hand. To see what this project changed in a
managed file: `git diff --no-index .claude/template-base/<file>.base <file>`.

## skills/

**Project-specific skills only.** The generic workflow skills (`/add-feature`,
`/prep-step`, `/step-done`, `/audit-code`, …) come from the coding-kit plugin — do not
copy them here, or you'll shadow updates.
