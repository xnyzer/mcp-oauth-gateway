---
id: F-018
title: Build the container image in CI
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-21
depends-on:
superseded-by:
---

# F-018 — Build the container image in CI

## History

### F-018 — Build the container image in CI — DONE 2026-08-21

**Problem:** `ci.yml` ran four jobs — `build-test`, `lint`, `license-check`, `workflow-lint` — and
none built the container image. Only `release.yml` did, on a SemVer tag push, so a broken
`Dockerfile` surfaced as a failed *release* rather than a failed push. F-014 made it concrete: it
re-pinned the builder digest, and nothing exercised that digest until the next tag. The pending
Dependabot bump of the distroless runtime digest was equally untested.

**Idea:** A CI job that builds the image with buildx (no push) and smoke-tests the result, so
base-image and `Dockerfile` changes fail on the pull request instead of at release time.

**What was done:** one new `image-build` job in `.github/workflows/ci.yml` (41 lines):
`docker/setup-buildx-action@v4`, then `docker/build-push-action@v7` with `push: false`,
`load: true`, `platforms: linux/amd64`, `build-args: VERSION=ci`; then `docker run --rm IMAGE
--version`; then a container start that polls `docker inspect --format
'{{.State.Health.Status}}'` until `healthy`, dumping `docker logs` and failing on `unhealthy` or
timeout. Actions pinned by major version like the sibling jobs; the workflow keeps
`permissions: contents: read`, so the job cannot push.

**Correction the plan needed:** the intake sketched the smoke as `docker run --rm IMAGE
healthcheck`, which cannot work — `probeHealth` GETs `/healthz` on the *local listener*, so
without a running server it fails with a refused connection. The sketch also ruled out starting a
container, contradicting itself. Starting one won, because it tests strictly more: it exercises
the image's `HEALTHCHECK` directive from F-007b/M9 and proves the non-root distroless runtime
brings the listener up at all.

**Decisions:**
- **The smoke container's password is generated inside the step** (`openssl rand -hex 16`) rather
  than written into the workflow. The gateway refuses to start without an auth backend, and a
  literal would leave a credential-shaped string in a public repository forever.
- **linux/amd64 only.** `release.yml` still builds both architectures; arm64 here would mean QEMU
  emulation for a gate whose breakage is not architecture-specific.
- **No build cache** (`cache-from/to: type=gha`) for now — roughly 2–3 minutes per push is
  acceptable, and a stale cache is another way for a broken build to slip through.
- **Loop variable renamed `status` → `health`** after local verification: `status` is read-only in
  zsh. CI runs bash, where it never mattered, but anyone reproducing the step by hand would have
  hit a pointless error.

**Verification (the job was proven, not just linted):** `actionlint` v1.7.12 — the version CI
pins — clean. `bash -n` on the extracted step clean; the polling logic was dry-run against a stub
`docker` for all three outcomes: healthy → rc=0, unhealthy → rc=1 with logs, timeout → rc=1 with
logs. Then the real thing, locally with Docker: `docker buildx build --platform linux/amd64`
succeeded against the current `Dockerfile`, `docker run --rm IMAGE --version` printed
`mcp-oauth-gateway version ci` (so the `VERSION` build-arg reaches the binary through ldflags),
and the started container reported **healthy**. All of that ran under amd64 emulation on an arm64
host — harder conditions than CI, which runs amd64 natively. Container and image were removed
afterwards. Go suite unaffected and still green (`gofmt` 0, `vet` rc=0, `go test -race` rc=0).

**Incidental finding:** the builder stage sets `ENV GOTOOLCHAIN=auto`, overriding the base image's
`GOTOOLCHAIN=local`. Had the image and `go.mod` disagreed on the Go patch version, the build would
have downloaded the required toolchain rather than failing — so F-014's alignment saves a download
rather than preventing a break.

**Files:** `.github/workflows/ci.yml`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No product-code
change, no new dependencies, no new config.
