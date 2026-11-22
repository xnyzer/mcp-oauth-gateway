# Convention Overrides

<!-- section:overrides-head -->
Registry of deliberate, project-local deviations from the template conventions.
`/update-conventions` merges template updates into managed files three-way, so a project
addition survives without a row here. A row records **why** a file deviates and how
updates treat it — the Kind column:

- `skip` — the file is never created, changed or offered (e.g. no CI in a local-only
  project).
- `keep` — template changes still merge in; on a conflict the project side wins.
- `adapt` — the file carries spots concretised for this project (`template:adapt`).
- empty — merged normally; the row only documents the reason.

`/step-done` reports changes to managed files that have no row. Paths may be globs
(`.github/**`); several paths can share a row. Deviations that are not about one file go
to the Rules table. Inside a seed zone or a standards fragment, a line that holds nothing
but an HTML comment starting with `override:` and the reason protects just that part.

A Rules row with the Rule `module:NAME` or `fragment:NAME` declines a detection proposal
for good: the skills stop offering that stack module or standards fragment. The Deviation
column says what the project does instead — e.g. Python as a tool language with a
hand-built toolchain instead of the python module. `tool:NAME` does the same for a tool
the template has no convention for: the skills stop proposing it to the template.

Since is the date a row was added (`YYYY-MM-DD`).

A deviation needs a reason — "we never got around to it" is drift, not a deviation.
<!-- /section:overrides-head -->

## Files

| Path | Kind | Reason | Since |
|------|------|--------|-------|
| `renovate.json` | skip | Dependabot keeps dependencies current (`.github/dependabot.yml`); a switch to Renovate is decided in F-032 | 2026-11-22 |
| `.github/workflows/codeql.yml` | skip | F-032 weighs CodeQL (signal versus noise) before adopting it | 2026-11-22 |
| `.github/workflows/ci.yml` |  | project jobs after the template job: workflow-lint (actionlint, F-013) and image-build (image runs and turns healthy, F-018) | 2026-11-22 |
| `mise.toml` |  | `go` pinned to the exact release of the go.mod toolchain line, so CI tests the Go that ships; both are bumped together | 2026-11-22 |
| `.golangci.yml` |  | gosec and misspell on top of the standard set — a public auth boundary; errcheck/gosec exclusions for tests | 2026-11-22 |
| `.gitignore` |  | project block: key material (`*.pem`, `*.key`, `*.jwks`), runtime data (`data/`: signing keys, token store), Go build and test output | 2026-11-22 |
| `license-policy.txt` |  | `except` for the Thrift sources vendored by the frozen Jaeger exporter (FSF all-permissive, F-033) | 2026-11-22 |
| `SECURITY.md` | adapt | intro and scope concretised for an auth gateway; threat scenarios, fix priority, supported versions and safe harbor specific to it | 2026-11-22 |
| `CODE_OF_CONDUCT.md` | adapt | reporting channel confirmed: the Security tab, as the template proposes | 2026-11-22 |
| `.github/ISSUE_TEMPLATE/bug_report.yml` |  | gateway fields (MCP client, upstream MCP server) and a redaction hint for logs | 2026-11-22 |
| `AI-DISCLOSURE.md` |  | an added section on why this matters for a security tool | 2026-11-22 |
| `scripts/privacy-lint.sh` |  | exact allowlist for values the docs must name: SSRF denylist ranges, Anthropic's published egress range, placeholders, an RFC section number, the reserved `.example` domain; deployment-shaped ranges stay blocked | 2026-11-22 |

## Rules

| Rule | Deviation | Reason | Since |
|------|-----------|--------|-------|
| _(none)_ | | | |
