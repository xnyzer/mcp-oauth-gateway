---
id: F-013
title: Fix the CI workflow (ci.yml never runs)
type: feature
status: DONE
size:
created: 2026-07-09
done: 2026-07-09
depends-on:
superseded-by:
---

# F-013 — Fix the CI workflow (ci.yml never runs)

## History

### F-013 — Fix the CI workflow (`ci.yml` never runs) — DONE 2026-07-09

**Problem:** `.github/workflows/ci.yml` had failed to load on every push since v0.1.0 — GitHub
reported "No jobs were run" and created **0 jobs**, so the build/test/`gofmt`/`vet` +
`golangci-lint` + `go-licenses` gate had never actually run (only `vulncheck.yml` and
`release.yml` ran). Surfaced by the operator's repeated GitHub failure emails while closing F-012.

**Root cause (verified with `actionlint`):** the `license-check` job's shell step was
`run: "$(go env GOPATH)/bin/go-licenses" check ./… --disallowed_types=forbidden,restricted`. The
value **begins with a double quote**, so the YAML parser read `"$(go env GOPATH)/bin/go-licenses"`
as a complete double-quoted scalar and the trailing ` check …` was a syntax error ("did not find
expected key"), which invalidates the **entire** workflow file → 0 jobs. An earlier close-out
note had wrongly guessed the `golangci/golangci-lint-action@v9.3.0` reference; that tag resolves
fine (as do `actions/checkout@v7` / `actions/setup-go@v6`) — corrected in the F-012 archive note.

**What was done:**
- Fixed the `run:` step to a block scalar (`run: |` on its own line), so the quoting is preserved
  without the leading-quote parse error.
- Added a new pinned `workflow-lint` job that `go install`s `actionlint@v1.7.12` and lints all
  workflow files (`-shellcheck=` to avoid a shellcheck dependency), so a future malformed workflow
  **fails loudly** instead of being silently dropped by GitHub.
- Ran `actionlint` over all three workflow files locally (clean) before pushing.
- Corrected the inaccurate root-cause note in the F-012 umbrella archive section (and Graphiti).

**Verification:** after the push, the CI run created **4 jobs** (was 0) — `build-test`, `lint`,
`license-check`, `workflow-lint` — and completed **`success`** (all green), confirmed via
`gh api …/actions/runs/<id>/jobs`. So the gate runs and passes again, not merely parses.

**Files:** `.github/workflows/ci.yml`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code
change, no new runtime dependencies.
