---
id: F-026
title: Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC
type: feature
status: DONE
size:
created: 2026-08-23
done: 2026-08-23
depends-on:
superseded-by:
---

# F-026 — Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC

## History

### F-026 — Dissolve REQUIREMENTS.md into SPEC, and strip the history out of SPEC — DONE 2026-08-23

**Problem:** Two documents describe what must hold, and one of them also narrates how it came to
hold. `SPEC.md` carries three jobs at once — contracts, the MCP conformance record (§4), and
implementation history: **108 of its 763 lines name an F-number**, across **15 "Delta" paragraphs**.
That history already lives in `PROGRESS-ARCHIVE.md`, in more detail, so the same story is told
twice and the worse telling sits in the contract document. It is not cosmetic: whoever opens §1.12
reads mostly *what changed when* instead of *what must hold*, which is how the §1.5 client-identity
MUST sat unread from F-004 until F-025 tripped over it. Meanwhile `REQUIREMENTS.md` is a second
document for the same genre, still marked "Status: draft" while v0.3.0 is public.

**Idea:** One document for rules, one for finished work, one for open work. `REQUIREMENTS.md`
disappears: its requirement register moves into `SPEC.md`, the parts that are duplicated elsewhere
are deleted, and the one statement that exists nowhere else is moved rather than lost. `SPEC.md`
then loses its history, because the archive already holds it.

**Decided at `/prep-step` (2026-08-23), with the measurements behind each decision:**

- **The register goes to `SPEC.md` as a new §5 — appended, never inserted.** Code references are
  distributed **§0 (9×), §1 (156×), §2 (64×), §3 (22×)**; inserting requirements as §0 or
  renumbering anything would break up to **251** references. Nothing points at §4, which is why §4
  stays where it is rather than becoming its own file — moving it would cost doc references for no
  gain, and splitting documents is what this task undoes.
- **Rejected: pointing the references at `PROGRESS-ARCHIVE.md`.** It conflates *work* with *rules*.
  Work has a lifecycle (backlog → done → archive); a rule is in force or repealed — SR-3
  (fail-closed) is satisfied today and must stay satisfied tomorrow, so it is never "done". The
  mapping is not one-to-one either: **SR-8 is referenced from 11 files and was implemented across at
  least five F-numbers** (F-005e2, F-006b, F-012c, F-024b, F-025a), **SR-5 from 13 files**. There is
  no single entry to point at, and new code — tomorrow's log line — would have no rule to cite at
  all. The archive is also append-only: when a contract changes the old entry stays correct about
  the past and wrong about the present, so a "current truth" pointer into it rots by construction.
- **Delete what is genuinely duplicated, verified item by item, not assumed:** §0 background (the
  archive holds F-001/F-003/F-009/F-017 in more detail; the watch item closed with F-017), §6
  decisions (the archive holds each with full rationale — the section's own heading says so), and
  from §5 the backup statement (`README.md`, Operations) and the env-compatibility rule
  (`SPEC.md` §3.3).
- **Move what exists nowhere else.** The **out-of-scope statement** is unique: README and CLAUDE.md
  say what the project *is*, but nothing anywhere says what it is *not* — no general-purpose IdP, no
  multi-tenant SaaS, and the constraint that multi-user must not be architecturally precluded. A
  search for "multi-user"/"single user" across README, CLAUDE.md and SPEC returns nothing.
  Suggested home: README's "Why" section, beside the rest of the project's identity.
- **References are repointed, including in the archive — pointers only, never claims.** An archive
  entry saying "REQUIREMENTS §6 records the re-decision beside F-003" becomes a pointer to the new
  location or carries "(formerly REQUIREMENTS §6)". Rewriting what an entry *asserted* would
  falsify the record; git makes it traceable, but nobody reads git history to learn what a document
  originally said. Nine files reference `REQUIREMENTS.md` today, two of them project skills
  (`audit-code`, `prep-step`).
- **`last_used_at` in §2.1 is corrected, not built.** F-025b made `client_name` real, leaving
  `last_used_at` as the only field in that row nothing has ever written. F-024 settled that "last
  active" comes from the token records and §2.1 itself says the client list needs no new entity, so
  a second timestamp on the registration would be a competing source of truth.

**Substeps** — the order is the point: build the safety net, then move, then edit.

#### F-026a — The reference guard, before the surgery

**What:** A test in the repo (not a one-off script) that collects every `SPEC §…` and
`FR`/`GR`/`SR` reference from code and documentation and asserts each resolves. It runs in CI, so
the guarantee does not decay after this task. **Use the prefix rule:** a reference `§A.B.C` resolves
when any prefix of it is a real heading — `SPEC §1.11.3` means list item 3 inside §1.11, not a
heading `1.11.3`. A naive checker reports **36 false positives** on today's tree; with the prefix
rule the answer is **0**, and that zero is the baseline this task must preserve.

**Files:** one new `*_test.go` (placement to be decided — it checks repository documents, so the
root package is the natural home)

**Acceptance:**
- [ ] Green against today's tree, with the reference count reported so a silent drop to zero checks
      is visible (~251 `SPEC §…` + ~80 FR/GR/SR + ~30 in other docs)
- [ ] Red when a heading is renamed or a requirement ID removed — verified by doing it, not assumed
- [ ] Runs in CI with the normal `go test` invocation; no new tooling, no new dependency

#### F-026b — Dissolve REQUIREMENTS.md

**What:** FR/GR/SR/NFR move verbatim into `SPEC.md` as **§5**, identifiers unchanged. The
out-of-scope statement moves to README. The duplicated parts are deleted. Every pointer to
`REQUIREMENTS.md` is updated — README, CLAUDE.md, THREAT-MODEL.md, CHANGELOG.md, PROGRESS.md,
PROGRESS-ARCHIVE.md, `HOW-TO-CODE-WITH-CLAUDE.md`, and the two skills in `.claude/skills/`. Then the
file is deleted.

**Files:** `REQUIREMENTS.md` (deleted), `SPEC.md`, `README.md`, `CLAUDE.md`, `THREAT-MODEL.md`,
`CHANGELOG.md`, `PROGRESS.md`, `PROGRESS-ARCHIVE.md`, `HOW-TO-CODE-WITH-CLAUDE.md`,
`.claude/skills/audit-code/SKILL.md`, `.claude/skills/prep-step/SKILL.md`

**Acceptance:**
- [ ] The F-026a guard stays green; **no §0–§4 heading number changed**
- [ ] All 25 requirement IDs present in §5, wording unchanged
- [ ] No file references `REQUIREMENTS.md` any more, and no dead link anywhere
- [ ] The out-of-scope statement survives in README — checked by searching for it, not by memory
- [ ] Archive edits are pointer-only; a diff review confirms no claim was altered

#### F-026c — Strip the history out of SPEC

**What:** The 15 "Delta" paragraphs and the 108 lines naming F-numbers go, along with the
endpoint-overview status column ("exists, thin", "new") and the "Status: draft" marker. The
`last_used_at` row in §2.1 is corrected. **The editorial rule is the work:** where a Delta records a
*decision* rather than a date — why CIMD grant types are narrowed instead of rejected, why the
revoked-`jti` deny-list became a record-presence check — the statement stays and only the
bookkeeping goes. A regex that deletes every F-number line would take contract text with it.

**Files:** `SPEC.md`

**Acceptance:**
- [ ] The F-026a guard stays green
- [ ] No F-number and no "done," remains in `SPEC.md`
- [ ] Spot-checked: every removed Delta statement either survives in the contract text or is present
      in `PROGRESS-ARCHIVE.md` — listed explicitly in the step-done entry, not asserted
- [ ] `SPEC.md` reads as a contract from top to bottom: what must hold, not what changed when

**Dependencies:** none. F-022 touches Go files only, so the two can run in either order.

---

---

#### What was actually done

**F-026a — the reference guard.** New `docs_refs_test.go` (root package, no new dependency): three
tests over every **git-tracked** text file. `TestSectionReferencesResolve` (348 refs),
`TestRequirementReferencesResolve` (258 refs against 25 IDs), `TestDocumentLinksResolve` (35 links).

**The plan's prefix rule was too weak, and the mutation proved it.** The plan specified "a reference
resolves when any prefix of it is a real heading". Built that way, renaming `### 1.11` to `### 1.14`
left the suite **green**: every `1.x` resolves as long as §1 exists. The rule now **counts the
ordered list items** of the parent section, so `§1.11.3` resolves because §1.11 really has a third
item — and a renamed heading goes red. Seven mutations were verified red: heading renamed, list item
deleted, item 9 of 5 cited, requirement definition removed, register split across two documents,
document link broken, `SPEC.md` deleted.

**Two scope corrections found by measuring, not by reading the plan:**
- The guard first walked the filesystem, which read **gitignored** files (`AUDIT-RESULTS.md`, and it
  would have read `private/`). It now reads `git ls-files`.
- After the register moved, the guard skipped the register document — which silently left SPEC's own
  61 requirement citations unchecked. Removed the skip; the count went 224 → 251.

**F-026b — the dissolution.** `REQUIREMENTS.md` deleted; its register is `SPEC.md` §5 (appended, no
§0–§4 heading renumbered), all 25 IDs verbatim. The out-of-scope statement moved to README ("Why").
Nine files repointed. In `PROGRESS-ARCHIVE.md` a **single reading note** at the top replaced fifteen
inline edits — no archived claim was altered.

**One plan decision reversed on evidence.** The plan called the backup statement and the
env-compatibility rule duplicates to be deleted. They are *cited* — `SPEC.md` §2.2 and §3.3 point at
them. Deleting them would have aimed two pointers at nothing, so both stayed in §5.5 as
intent-level lines with the concrete contract in §2.2/§3.3.

**F-026c — the redaction.** All 15 Delta paragraphs, all 108 F-number lines, the endpoint-overview
status column, the 11 `**target**` markers and the "Status: draft" header are gone. The contract text
went from 763 to 645 lines while gaining the 85-line register.

**Four statements existed only inside a Delta** and were lifted into the contract, or they would have
been lost: `exp` MUST be present (§1.11.1), the 4 MiB cap on redirect-replay body buffering (§1.11.3),
the post-login redirect normalisation (§1.12), and the SQLite pragmas plus cap atomicity (§2.5/§1.4).
An audit checked all 28 removed Delta statements: **28/28** survive in contract text, and the four
history-only claims (the upstream `Revoke*` no-op bug, the session-gate side fix, the non-resident
passkey upgrade note, the original base64url `kid` draft) are all present in this archive.

**Three editorial calls were put to the operator rather than decided here:** strip the `**target**`
markers (yes), strip the F-numbers from the conformance section too (yes), and the pre-F-012c
non-resident passkey note (delete — the lockout rescue it referenced was already stated in §1.12's
own prose).

Also corrected: the `last_used_at` field on the DCR client row in §2.1, which `models.Client` never
had and nothing ever wrote; and the §1.5 loopback warning, which sat **inside** the Errors sentence
(between "redirectable errors (`access_denied`," and "`invalid_scope`") and now precedes it.

**Files:** `docs_refs_test.go` (new), `SPEC.md`, `README.md`, `CLAUDE.md`, `CHANGELOG.md`,
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`, `HOW-TO-CODE-WITH-CLAUDE.md`, `REQUIREMENTS.md` (deleted),
`.claude/skills/audit-code/SKILL.md` and `.claude/skills/prep-step/SKILL.md` (edited, then deleted
outright in F-027).

**Deviation from the plan's file list:** it named `THREAT-MODEL.md` as carrying a `REQUIREMENTS.md`
reference. It does not — it only uses FR/GR/SR IDs, which kept working unchanged.
