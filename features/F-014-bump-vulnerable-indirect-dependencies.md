---
id: F-014
title: Bump vulnerable indirect dependencies
type: feature
status: DONE
size:
created: 2026-08-20
done: 2026-08-20
depends-on:
superseded-by:
---

# F-014 — Bump vulnerable indirect dependencies

## History

### F-014 — Bump vulnerable indirect dependencies — DONE 2026-08-20

**Problem:** The weekly `vulncheck` workflow had failed on every run since 2026-07-27, mailing a
failure notice each Monday. Two advisories were reachable from our code, both in indirect
dependencies: GO-2026-6061 (`google.golang.org/grpc` 1.80.0, fixed 1.82.1) and GO-2026-5970 — an
infinite loop on invalid input — (`golang.org/x/text` 0.37.0, fixed 0.39.0).

**Idea:** Bump both modules past their fixed versions, confirm `govulncheck` reports zero
reachable vulnerabilities, and close the gap that let them go stale.

**Scope revision during `/prep-step`:** a dry-run bump plus a local `govulncheck` showed the two
module advisories cleared — but surfaced **six standard-library advisories**, all fixed in
**go1.26.6**, against our pinned **go1.26.5**. They had not appeared in the 2026-08-17 CI run
because they published after it, so the next scheduled run would have failed regardless of the
module bump. Several sit directly on the auth boundary: `html/template` (GO-2026-6091,
login/consent rendering), `encoding/asn1` (GO-2026-5972, signing-key parsing), `net/url`
(GO-2026-6218, redirect following on the proxy path), plus `crypto/tls` (GO-2026-6090),
`net/http` (GO-2026-6089) and `x/net/idna` via `net/http` (GO-2026-5026). The task therefore
grew to cover the Go toolchain in both places it is pinned.

**What was done:**
- Bumped the modules to pinned versions: `golang.org/x/text` 0.41.0, `google.golang.org/grpc`
  1.83.1, and `golang.org/x/crypto` 0.55.0 — the last one deliberately, because the other two
  drag it along transitively and an incidental 0.54.0 would have been worse than an intentional
  0.55.0. `go mod tidy` clean; **no new modules**, only version replacements, so the license set
  is unchanged.
- Raised the Go toolchain to **1.26.7** (latest 1.26.x, above the 1.26.6 fix level) in `go.mod`,
  which drives every CI job via `go-version-file: go.mod`.
- Re-pinned the `Dockerfile` builder image to the current `golang:1.26-bookworm` digest
  `sha256:6ef6e30f…`, verified against the registry as carrying `GOLANG_VERSION=1.26.7` (the
  image also sets `GOTOOLCHAIN=local`, so image and `go.mod` must agree — they now do).
- Extended `.github/dependabot.yml` for the gomod ecosystem with `allow: dependency-type: all`
  plus a `groups` block collapsing all Go updates into one weekly PR.
- Added a `[Unreleased]` → `Security` section to `CHANGELOG.md`.

**Verification:** `go version` inside the module resolves to `go1.26.7`; `go build ./...` and
`go vet ./...` clean; `gofmt -l .` empty; `go test -race ./...` green across all 16 packages
(11 with tests `ok`, 5 without test files, 0 failures); **`govulncheck ./...` reports
"No vulnerabilities found" — 0 reachable, down from 2 module + 6 standard-library advisories.**
The `dependabot.yml` change was parsed as YAML to confirm `allow`/`groups` land where intended.

**Decisions / deviations:**
- The intake text suggested `go get …@latest`; replaced with explicit pinned versions, because
  `CODING-STANDARDS.md` §7 requires pinned versions over `latest`.
- The intake text called both bumps `// indirect`. True for the two named modules, but the bump
  drags `golang.org/x/crypto` — a **direct** dependency — along, which the entry had missed.
- Dependabot: the operator chose the grouped variant (`allow` + `groups`) over bare `allow`,
  because one PR per transitive module would bury the direct ones under
  `open-pull-requests-limit: 5`.
- Supersedes two open Dependabot PRs: #12 (x/crypto → 0.55.0, now included) and #1 (golang
  builder digest, whose target `18aedc1…` was itself already stale — resolved fresh instead).

**Known gap (not closed here):** `ci.yml` does not build the container image; only `release.yml`
does, on a tag push. The new builder digest is therefore first exercised at the next release
rather than on push, and the local Docker daemon was unavailable to smoke it. Adding an
image-build job to CI is a candidate for its own task.

**Files:** `go.mod`, `go.sum`, `Dockerfile`, `.github/dependabot.yml`, `CHANGELOG.md`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code change, no new runtime dependencies.
