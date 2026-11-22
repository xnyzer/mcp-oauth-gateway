# How to Code with Claude

Guide for working with Claude Code in the mcp-oauth-gateway project.

---

## Contributor setup

1. **Install Claude Code** — see the [official docs](https://code.claude.com/docs).
2. **Install the coding-kit plugin** (provides the workflow skills used below):
   ```
   /plugin marketplace add xnyzer/coding-kit
   /plugin install coding-kit@xnyzer
   ```
3. **Install the toolchain** — [mise](https://mise.jdx.dev) provides everything pinned in
   `mise.toml` (including `just`, `lefthook`, `gitleaks` and the stack toolchain).
   Activate mise once per machine, or the project's versions never reach Claude Code:
   Claude Code, the editor and the terminal take their `PATH` from your interactive
   shell, so `eval "$(mise activate zsh --shims)"` belongs at the very end of `~/.zshrc`,
   after nvm and other tool managers (bash: end of `~/.bashrc`, which `~/.bash_profile`
   must load on macOS). Then restart the terminal and the editor — a new Claude Code
   session alone keeps the old `PATH` — and check that `mise doctor` reports
   `shims_on_path: yes`. `/update-conventions global` checks this and offers the line.
   Outside a project a shim runs only a tool installed on the system or set globally in
   mise.
   ```
   mise install
   just setup     # dependencies + git hooks
   just check     # must be green
   ```
4. *(Optional)* **Graphiti memory** — if `CLAUDE.md` has a Graphiti block, knowledge
   with no place in the repo goes to the graph under the group id documented there;
   without the block it goes to `docs/notes.md`, which `CLAUDE.md` loads in every
   session. The project decides, not the machine: if the block is there but the Graphiti
   MCP server is not, the skills say what they could not write. Claude Code's auto
   memory is switched off for the project (`.claude/settings.json`) — it lives on one
   machine only.

---

## Overview: skills

None of these skills live in this repository — they come from the coding-kit plugin for
Claude Code (see *Contributor setup*). Each can be called with the plugin's namespace,
e.g. `/coding-kit:add-feature`; the short form `/add-feature` used below works as long as
no other command or skill has the same name. The skills automate a workflow you can also
follow by hand: the feature files in `features/` and the `just` recipes (`just check`
above all) work without the plugin.

**Daily development loop** — a feature moves `BACKLOG → PLANNED → IN-PROGRESS → DONE`
(statuses and their meaning: the head of `features/INDEX.md`):

| Skill | When to use | What happens |
|-------|-------------|--------------|
| `/add-feature` | Put a new task on the roadmap — you start it, or Claude does when a new task comes up while building | Advice first: the problem behind the idea, the strongest counter-argument, alternatives (including not building it) and one recommendation → write-up → your OK → a new file in `features/` (status **BACKLOG**) and its row in the index |
| `/prep-step` | Plan a task before building it | Sizes the feature (S, M or L) and specifies it to fit — acceptance criteria, edge cases, non-goals, tests, how it fits the project; may advise against it — then plans the substeps → specification and plan in the feature file (status **PLANNED**). If the task introduces a new framework, dependency, language or toolchain, checks the planned signals with the detection script against the fragment catalog and the stack modules — plus the catalog's characteristic triggers — and proposes appending missing catalog fragments, adding a missing module via `/choose-stack` (or keeping the language as a tool language), or, where the template has nothing for it (a tool without any module or fragment), building it by hand in the project — a project-local fragment or a hand-built toolchain — with an adoption proposal for the template, or declining the tool for good with a `tool:NAME` row. A fragment that also requires a change in the project itself brings that change into the plan |
| `/build-step` | Implement a planned task | Works the plan substep by substep, verifying each and reviewing its own diff (understandable, simple, secure, readable, no workaround) against `CODING-STANDARDS.md`; fixes bugs it finds in the code it touches (asks first when the fix is large); stops and offers ways forward instead of building a workaround; ends every substep with a `/step-done` recommendation |
| `/step-done` | After finishing a task/substep | Code review along five questions (understandable, simple, secure, readable, no workaround), fixing bugs it finds in the touched code → `just check` → independent review by a read-only reviewer agent with fresh context → detection backstop (a framework without its fragment, a language without its module or a tool the template has no convention for, new in this step) → managed-files backstop (a changed template file without a row in `.claude/convention-overrides.md` is reported, with the choice to register it, revert it or propose it for the template — never blocking) → secrets & privacy scan → preview of the booking (history entry, acceptance criteria with their proof, status, index) with the commit message → one approval → booking + commit |
| `/teach-step` | Implement it yourself, guided | Socratic guidance — you write all the code; Claude reads it, checks it along the same five questions as `/step-done`, points out bugs it finds as hints, gives graded hints, runs tests, writes nothing itself |
| `/audit-code` | One-off audit of existing code | Check (optionally scoped to an area or path) → results in AUDIT-RESULTS.md (gitignored) |

**Occasional project maintenance:**

| Skill | When to use |
|-------|-------------|
| `/choose-stack` | Add a stack module later, or switch modules — recommended from the project's signals, rendered from the template and merged three-way like an update, so your additions stay; the base snapshot follows. Composes the module's declared catalog fragments (append, idempotent per `fragment:NAME` marker) and can retrofit characteristic fragments after confirmation. Some fragments require more than the text in the slot — a file that has to exist before a framework first runs, say; that change is made in the same step and confirmed with it, and template files it changes are registered as `keep` |
| `/choose-license` | Pick or change the project license; in an existing project it also updates `.claude/template-answers` and the template files that depend on the license (e.g. `CONTRIBUTING.md`) |
| `/update-conventions` | Pull template updates into this project — downward only (template → project). Managed files are merged three-way against the base snapshot in `.claude/template-base/`: your additions stay, template changes arrive, only overlapping changes need a decision, and every result is confirmed per file; registered deviations follow their kind. Every run also detects what the project uses that the template now has a module or fragment for and offers it, and reports tools the template has no convention for, with an adoption proposal for the template (a copy-ready issue or prompt for the kit — nothing is sent); a permanent no becomes a `module:NAME`, `fragment:NAME` or `tool:NAME` row in the Rules table. Standards fragments and marked seed sections (`section:NAME`) are synced one by one; seed files are never replaced as a whole; project-local fragments are never touched, only reported with an adoption proposal for the template. Fragment requirements of that kind are re-checked even when the fragment text itself is unchanged — this is the only route that reaches a project which adopted a fragment before it carried the requirement. Without an argument it syncs this project; `status` only reports, `revise` reviews the deviation registry. `global` syncs the kit's global rules on this machine (`~/.claude/rules/coding-kit.md`: reply language, explanation level, house rules) section by section — every other run checks them once when they are set up — offers two Claude Code settings (auto memory off, transcripts kept 365 days) and checks that mise reaches every shell, offering the activation line for the end of the startup file otherwise. Each run also moves the project's auto memory on this machine into the graph or `docs/notes.md` after your approval and then deletes it, and offers new seed files such as `docs/notes.md` for creation |
| `/go-public` | Take a private or local-only project public, guided and fail-closed: blocking preflight audit (secrets across the full git history, privacy incl. commit metadata, license, `private/` hygiene), file catch-up **before** the switch (public-only files arrive while still private), then visibility change or repo creation + initial push only after explicit per-run approval |
| `/define-requirements` | Elicit requirements (M1 interview → goals, non-goals and constraints in the overview of `CLAUDE.md`, one feature file per core feature). The interview also asks the fragment catalog's characteristic triggers (e.g. audit-logging: "Are there user/admin actions that mutate data?") |
| `/refine-requirements` | Go back to the spec when something fundamental changed |

---

## Workflow 1: Intake a new task

```
You:    /add-feature <idea>
Claude: Analysis… recommendation… open questions…
You:    yes, do that
Claude: Writes it out, shows you the text
You:    looks good
Claude: Creates features/F-NNN-short-name.md, regenerates the index table and
        proposes a place in the recommended order
```

**Important:** Everything gets an F-number and its own file. No distinction between
"feature" and "task" — the `type` field only says whether it adds behaviour (`feature`),
fixes it (`fix`) or reworks something (`change`).
Claude may also start `/add-feature` itself — for an idea that comes up during
`/build-step`, say — but the entry is still written only after your OK.

---

## Workflow 2: Prepare, implement & finish a task

```
You:    /prep-step F-002
Claude: Size… questions… specification… substeps if needed (F-002a, F-002b, …)
You:    yes, write that in
Claude: Records specification and plan in the feature file (status PLANNED)
You:    /build-step F-002
Claude: Implements F-002a, verifies it, recommends /step-done
You:    /step-done
Claude: Review, checks, scans — then the booking and commit message as a preview
You:    book and commit
Claude: Booked and committed. Continue with F-002b?
```

Three skills, one per phase: `/prep-step` plans (→ `PLANNED`), `/build-step` implements the
plan substep by substep, `/step-done` reviews and finishes each substep. Prefer to write the
code yourself? Use `/teach-step` instead of `/build-step` — it guides you and writes nothing.

**Size:** three signals, the highest counts — effort (S under 5 files and 200 lines, M up
to 15 and 500, L above), uncertainty and reach. S gets a mini specification and no
substeps, M a short interview and 2–3 substeps, L the full interview and 3–5 substeps.
`/prep-step` without an argument takes the first feature of the recommended order.

---

## What `/step-done` does in detail

1. **Code review & checks** — changed files against `CODING-STANDARDS.md` (without it:
   the Mindset, Control flow and Secure coding sections of the kit's template), along five
   questions: understandable, simple, secure, readable (never minified), no workaround.
   Findings are fixed; a bug that was already in the touched code is fixed too, with a
   test, and noted in the history (large fixes only after asking). `just check` must be
   green. Then a **read-only reviewer agent** checks the diff with fresh context — it gets
   only the F-number, the diff, the new files and the coding standards, never a summary
   of the build — against the feature file (acceptance criteria, edge cases, non-goals)
   and the same five questions. Each finding is first checked against the code — does it
   hold there, and at comparable places too? — then fixed or rejected with a reason; the
   list, with what each decision rests on, is shown with the booking preview. One run per
   step, no second round after the fixes.
2. **Secrets & privacy scan** — working tree + commit draft for secrets/keys/IPs/private
   emails; living docs for private info (names, customers, local paths). Findings are
   fixed or moved to `private/` before any commit is proposed.
3. **Detection backstop** — the detection script reports only the signals this step
   adds (new dependencies, tools, signal files). A framework without its standards
   fragment comes with a proposal to append it, a language without its stack module with
   the choice of `/choose-stack` or a tool language, a tool the template has no convention
   for with an adoption proposal for the template; a permanent no becomes a Rules row in
   `.claude/convention-overrides.md`. Non-blocking — it never stops the finish.
4. **Booking, as a preview** — the history entry of the substep in the feature file, its
   acceptance criteria checked off with their proof, the status (`IN-PROGRESS`, `DONE`
   after the last substep), the regenerated index table and, if needed, a change to the
   recommended order are prepared, not yet written.
5. **One approval for booking and commit** — the preview comes with a proposed
   Conventional Commits message; you choose *book and commit*, *book only*, or *change
   the text*. Only then are the feature file and `features/INDEX.md` written, `just check`
   re-run and the commit made (commit email verified as a GitHub noreply address).
6. **Graphiti** — only when the booking sets the feature to `DONE`: one short pointer
   episode in the knowledge graph (if the project has a Graphiti block; if the server is
   unreachable, the summary says so and gives the text).

---

## Important files

| File | Purpose |
|------|---------|
| `features/INDEX.md` | Recommended order + the generated table of all features (`just features-index`) |
| `features/F-NNN-*.md` | One file per feature: intake, specification, plan, history |
| `features/F-000-template.md` | Template for a new feature file |
| `docs/adr/` | Decisions that shape the project beyond one feature |
| `CODING-STANDARDS.md` | Binding coding rules (incl. stack section) |
| `CLAUDE.md` | Project-specific Claude instructions (auto-loaded), incl. goals, non-goals and constraints in the overview |
| `.claude/convention-overrides.md` | Registered deviations from template conventions — why a managed file deviates and how updates treat it |
| `.claude/template-answers` | Values the template is rendered with for this project |
| `.claude/template-base/` | Base snapshot for template updates (generated — never edit) |
| `.claude/skills/` | Project-specific skills only (workflow skills come from the plugin) |

---

## Tips

- **Not everything at once.** Decompose large tasks via `/prep-step`.
- **`/step-done` after each substep** — otherwise details get lost in the docs.
- **Claude never commits automatically.** You are always asked — and no feature file or index
  change is written without your OK either.
- **Languages:** see the Languages block in `CLAUDE.md` — living docs in
  English, code comments in English, commit prose in
  English (Conventional-Commit tokens stay English); identifiers and
  governance docs are always English.
- **Secrets/private info** belong in `private/` (gitignored), never in the tree.
- **On errors:** fix diagnostics immediately — no workarounds, always the root cause.
