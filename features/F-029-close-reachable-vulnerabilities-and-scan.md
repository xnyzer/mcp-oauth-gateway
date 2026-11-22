---
id: F-029
title: Close reachable vulnerabilities and scan the toolchain we ship
type: feature
status: DONE
size:
created: 2026-10-12
done: 2026-10-12
depends-on:
superseded-by:
---

# F-029 — Close reachable vulnerabilities and scan the toolchain we ship

## History

### F-029 — Close reachable vulnerabilities and scan the toolchain we ship — DONE 2026-10-12

**Origin:** came out of a failed CI run, not from `/add-feature`, and was applied directly —
without `/prep-step` or `/build-step`, so there was no plan and no per-substep verification; the
full check set ran once at the end, under `/step-done`. That is also why the standard-library
finding below surfaced as a scope revision during `/step-done` rather than in planning.

**Problem:** The weekly `vulncheck` run of 2026-10-12 failed on five reachable advisories in
`golang.org/x/net` 0.58.0 — GO-2026-6603, -6610, -6611, -6612 and -6617, all HTTP/2, fixed in
0.60.0. The open grouped Dependabot PR (#23) only went to 0.59.0 and would not have cleared them.
Dependabot alert #2 (GO-2026-6443, `google.golang.org/grpc` 1.83.1, fixed 1.83.2) was open beside
it — not reachable, since the gateway runs no gRPC server.

**Scope revision during `/step-done`:** a re-check of `govulncheck` with the toolchain the image is
actually built with (`GOTOOLCHAIN=go1.26.7`) reported **11 reachable standard-library advisories**,
all fixed in **go1.26.9**: GO-2026-6617, -6613, -6612, -6611, -6610, -6605, -6603 (`net/http`,
HTTP/1 and HTTP/2, both server and the transport on the proxy path), -6608 (`net/textproto`),
-6607 (`crypto/tls`), and -6600 and -6599 (`html/template`, login/consent rendering). No CI
run had reported any of them. The cause sits in `vulncheck.yml`: `golang/govulncheck-action`
defaults `go-version-input` to `stable`, and when both inputs are set `setup-go` uses
`go-version` and ignores `go-version-file` — every run logged the warning *"Both go-version and
go-version-file inputs are specified, only go-version will be used"*. With `GOTOOLCHAIN=local`,
the scan therefore checked the standard library of the latest Go release (1.27.2), not the one we
ship. While the latest release and our pin coincided this was harmless; once they drifted, the
weekly scan stopped covering the standard library altogether.

**What was done:**
- `golang.org/x/net` 0.58.0 → **0.61.0** (latest, above the 0.60.0 fix level). It drags
  `x/crypto` 0.58.0 (direct), `x/sys` 0.49.0, `x/text` 0.43.0, `x/sync` 0.24.0, `x/mod` 0.41.0
  and `x/tools` 0.51.0 along. No new modules.
- `google.golang.org/grpc` 1.83.1 → **1.83.2**; nothing else moved.
- Go toolchain **1.26.7 → 1.26.9** in `go.mod`, and the `Dockerfile` builder re-pinned to the
  current `golang:1.26-bookworm` digest `sha256:d9c68c2c…`, verified to run `go1.26.9` (image and
  `go.mod` must agree, the image sets `GOTOOLCHAIN=local`).
- `vulncheck.yml`: `go-version-input: ""`, so `go-version-file: go.mod` decides — with a comment
  saying why, because the empty value looks like a mistake otherwise.
- `CHANGELOG.md`: `[Unreleased]` → `Security`.

**Verification** (all with `GOTOOLCHAIN=go1.26.9`): `govulncheck ./...` — **0 reachable**, down from
5 module + 11 standard-library advisories; `go vet` clean; `go test -race -count=1 ./...` green;
gofmt from the 1.26.9 toolchain empty; golangci-lint v2.12.2 0 issues; go-licenses v2.0.1 check
passes; actionlint v1.7.12 clean; local `docker build` → `--version` → container polled to
`healthy`, as in the `image-build` job.

**Decisions / deviations:**
- Applied on `main`, not via Dependabot's PR #23 (standing practice). #23 stays open: its other
  updates are maintenance, not security, and do not belong in a security patch.
- Separate commits per concern (`x/net`, `grpc`, toolchain, CI), at the operator's request.
- The remaining unreached module advisory, GO-2026-5932 (`x/crypto/openpgp` unmaintained), has no
  fix and the package is not imported — nothing to do.

**Known gaps:**
- Whether the action's bundled `setup-go` honours the `toolchain` directive (rather than the
  `go 1.26.2` line) is only provable by the first CI run after the push. Should it pick 1.26.2,
  the scan fails loudly with more advisories, not fewer — fail-safe, but to be checked.
- `gofmt` from Go 1.27 realigns a struct literal in `pkg/idp/metadata.go`; 1.26 does not. It
  belongs to the toolchain move to 1.27 (Dependabot PR #17), not here.

**Files:** `go.mod`, `go.sum`, `Dockerfile`, `.github/workflows/vulncheck.yml`, `CHANGELOG.md`;
docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code change.
