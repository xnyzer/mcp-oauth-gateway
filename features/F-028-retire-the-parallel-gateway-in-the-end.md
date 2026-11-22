---
id: F-028
title: Retire the parallel gateway in the end-to-end harness
type: feature
status: DONE
size:
created: 2026-08-24
done: 2026-08-24
depends-on:
superseded-by:
---

# F-028 — Retire the parallel gateway in the end-to-end harness

## History

### F-028a — Move the end-to-end tests into the package — DONE 2026-08-24

**What:** Relocate `e2e_harness_test.go` and `e2e_test.go` (794 lines) to `pkg/mcp-proxy`, otherwise
unchanged — they keep building the gateway themselves for now. One change is forced: the harness's
`tokenActiveChecker` collides with the production copy in `router.go`, so **the compiler proves the
duplication** the moment they share a package.

**Files:** `e2e_harness_test.go`, `e2e_test.go` (both moved)

**Acceptance:**
- [x] `go test -list '.*'` returns the same test set across the repository as before the move
- [x] `go test -race ./...` green; the root package keeps its other tests
- [x] The collision is resolved by renaming the harness copy, not by keeping two implementations

#### What was actually done

`e2e_harness_test.go` (460 lines) and `e2e_test.go` (334) moved from the repository root to
`pkg/mcp-proxy`, by `git mv` so the history follows them. The package clause changed; nothing else
about the tests did.

**The compiler proved the duplication, exactly as the plan predicted.** The move produced one error
and only one: `tokenActiveChecker redeclared in this block`. The two implementations turned out to
be identical line for line — one reads `repo`, the other `deps.repo` — and the harness copy carried
a comment saying so itself: "copied from Run".

**Deviation from the plan, and it is an improvement.** The substep called for *renaming* the harness
copy and deleting it in F-028b. Renaming would have left two identical functions under two names,
which is the drift this whole task exists to end. Since the production function needs nothing but
`deps.repo`, the harness now calls it directly:

    TokenActive: tokenActiveChecker(&dependencies{repo: repo}),

The acceptance criterion — "not by keeping two implementations" — is therefore met literally in this
substep rather than deferred. `tokenActiveChecker` now exists exactly **once** in the repository.

**Verified:** `go test -list '.*'` returns the identical set of **240 tests** across the whole
repository before and after; `go test -race ./...`, gofmt, vet and golangci-lint are green; the root
package keeps its six other test files (`docs_refs_test.go`, `env_test.go`, `healthcheck_test.go`,
`main_test.go`, `parse_test.go`, `rotatekey_test.go`).

The harness header now says why the file sits in this package. The claim it still makes — that it
assembles the gateway "the way `Run()` mounts it" — stays untrue until F-028b, and the header says
that too rather than leaving a reader to discover it.

**Files:** `e2e_harness_test.go` → `pkg/mcp-proxy/e2e_harness_test.go`,
`e2e_test.go` → `pkg/mcp-proxy/e2e_test.go`.

### F-028 — Retire the parallel gateway in the end-to-end harness — DONE 2026-08-24

**Problem:** `e2e_harness_test.go` builds the gateway a second time instead of using the one `Run`
builds, and the two have already drifted apart. Three findings, all measured during F-022e. The
harness creates the operator session cookie with `cookie.NewStore(secret[:])` and never calls
`store.Options`, so it runs **without encryption, `HttpOnly`, `Secure` or `SameSite`** — the
end-to-end suite therefore cannot catch a regression in any of those SPEC §1.12 properties, which
makes this a testing gap with a security edge rather than tidiness. The revocation check
`tokenActiveChecker` exists there a **third** time, beside the production copy. And although F-022e
turned the wiring into a callable function, the harness still cannot call it: it lives in package
`main` while the parameter types are package-private. This is the same gap F-021 found once and
closed by hand — by hand does not hold.

**Idee:** Let the end-to-end tests drive the real wiring through `httptest` and delete the parallel
construction rather than keep it in sync. The suite then exercises what the binary runs by
construction instead of by vigilance.

**Decided at `/coding-kit:prep-step` (2026-08-24), with the measurements behind each decision:**

- **The move is feasible and cycle-free.** The two test files import only packages `pkg/mcp-proxy`
  already imports (`auth`, `cimd`, `idp`, `keys`, `proxy`, `ratelimit`, `repository`), and they
  reference nothing from package `main`.
- **The intake sketch overstated the seams.** Of the four options the harness injects, **three map
  onto real configuration fields** — `oidcMirror` → `OIDCDiscoveryMirror`, `registerLimit` /
  `tokenLimit` → `RateLimitRegister` / `RateLimitToken`. Only the CIMD stub genuinely needs one.
- **Drive the real startup path, not a hand-assembled one.** `resolveConfig` → `openDependencies` →
  `BuildRouter` covers everything except `serve`. The mock upstream is an `http.Handler`, so putting
  it behind `httptest.NewServer` and passing that URL as `ProxyTargets` runs it through the **real
  transparent backend** — more faithful, not more complicated.
- **The logger is the second seam.** Without `MODE=debug`, `openDependencies` builds a production
  logger that floods the test output. The three direct `os.Getenv` reads in the startup path
  (`AUTH_HMAC_SECRET`, `MODE`, `JWT_PRIVATE_KEY`) are safe to set per test, because no end-to-end
  test uses `t.Parallel()`.
- **Move first, rewire second — the reverse does not compile clean.** A package-private seam with no
  caller is removed by the `unused` linter on sight. That happened in this project during F-022d,
  when `servesTLS()` was written one substep ahead of its user.

**Substeps**

#### F-028b — Drive the real wiring and delete the second gateway

**What:** Add the two package-internal seams (CIMD resolver, logger), rewire `newE2EGateway` to run
`resolveConfig` → `openDependencies` → `BuildRouter`, serve the mock upstream through `httptest` as
a real `ProxyTargets` URL, and delete the parallel construction along with the duplicate revocation
check. **Retrofit from F-022e:** `BuildRouter` goes back to unexported, because its caller now lives
in the same package — it was exported for a caller that could never exist, its parameter types being
package-private.

**Files:** `pkg/mcp-proxy/e2e_harness_test.go`, `pkg/mcp-proxy/router.go`, `pkg/mcp-proxy/deps.go`

**Acceptance:**
- [x] No second gateway construction remains — verified by searching, not by memory
- [x] The harness session cookie comes from `newSessionStore`, so the tests run **with** encryption,
      `HttpOnly`, `Secure` and `SameSite` — the gap that motivated this task
- [x] `tokenActiveChecker` exists exactly once in the repository
- [x] `BuildRouter` is unexported and nothing outside the package references it
- [x] Same test set, `go test -race ./...` green, and the seams are package-internal — the public
      API is unchanged

**Abhängigkeiten:** F-022e (done — it produced the callable wiring this task builds on).

---

#### F-028b — what was actually done

`newE2EGateway` now runs the binary's own startup path — `resolveConfig` →
`openDependenciesWithLogger` → `buildRouter` — and serves the resulting engine through
`httptest`. It assembles **nothing**: no `gin.New()`, no `cookie.NewStore`, no `NewAuthRouter`,
`NewIDPRouter` or `NewProxyRouter`, verified by searching rather than by memory. The mock upstream
runs as a real HTTP server whose URL is passed as `ProxyTargets`, so the tests additionally exercise
the transparent backend, and the assertion that the upstream sees `/mcp` proves the path join works.

**Two package-internal seams, and one of them is a structural improvement rather than a
concession.** The CIMD resolver moved from `router.go` into `deps.go`: it is a collaborator like the
repository and the key manager, so it belongs where those are built. A test overrides the field
afterwards. The second is `openDependenciesWithLogger`, so the suite can run the real startup path
without a production logger writing JSON across its output. Neither widens the public API.

**The gap that motivated the whole task is closed, and it was checked empirically rather than
argued.** A throwaway probe drove the real login and printed what the harness now receives:

    Set-Cookie: session=…; Path=/; Max-Age=600; HttpOnly; SameSite=Lax

with the value in securecookie's signed-and-encrypted form. Before, the harness called
`cookie.NewStore(secret[:])` and never called `store.Options`, so none of those attributes existed
and the value was signed only. The probe was deleted after the reading; it existed to answer the
question, not to stay. (`Secure` is correctly absent: the issuer is `http://localhost`, and
`sessionCookieSecure` decides exactly as it does in production.)

**A decision beyond the plan: `OriginCheckEnabled: true`.** Production defaults it on. Leaving it
off in the harness would have introduced a *fresh* divergence in the very task that exists to end
divergence. The tests send no `Origin`, and an absent one passes by design (SPEC §0), so fidelity
cost nothing.

**The retrofit from F-022e is done.** `BuildRouter` no longer exists — it is `buildRouter` again.
The exported form was never callable from outside the package, its parameter types being
package-private, so the export bought nothing and implied something false. `pkg/mcp-proxy` exports
`Run`, `Config` and `ServerShutdownTimeout` again: exactly its surface before F-022e.

**Also removed:** `limiterMiddleware`, the helper whose own comment said it "mirrors Run's
construction" — with nothing left to mirror, it went.

**Verified:** identical set of **240 tests** across the repository; `go test -race ./...`, gofmt,
`go vet` and golangci-lint green; `tokenActiveChecker` exists once.

**Files:** `pkg/mcp-proxy/e2e_harness_test.go`, `pkg/mcp-proxy/deps.go`, `pkg/mcp-proxy/router.go`,
`pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/server.go`.

#### F-028 as a whole

The end-to-end suite tested a gateway it built itself, and the two had drifted where it mattered
most: the session cookie. Two substeps ended that — a proven move into the package, then the rewire
onto the real startup path. What the suite exercises is now what the binary runs, by construction
rather than by vigilance, which is the difference F-021 could not achieve by fixing the symptom
once by hand.

The task also carried a correction of its predecessor, at the operator's instruction: work that
leaves a loose end should name the task that will pick it up, and that task should actually pick it
up. F-022e exported a function for a caller that could not exist; F-028 removed the export.

### F-028b (2026-08-24)

Harness onto the real startup path → `newE2EGateway` runs `resolveConfig` → `openDependenciesWithLogger` → `buildRouter` and **assembles nothing itself**; the mock upstream runs as a real HTTP server behind `ProxyTargets`, so the transparent backend is exercised too. **The gap that motivated the task is closed and was measured, not argued:** a throwaway probe against the real login printed `Path=/; Max-Age=600; HttpOnly; SameSite=Lax` with a signed-and-encrypted value, where the old harness had none of it. Two package-internal seams, one of them a structural fix — the CIMD resolver moved to `deps.go`, where collaborators are built. **Retrofit from F-022e done:** `BuildRouter` is unexported again, so `pkg/mcp-proxy` exports exactly what it did before F-022e. Beyond the plan: `OriginCheckEnabled: true`, because leaving it off would have created a fresh divergence in the task that exists to end divergence. Detail in `PROGRESS-ARCHIVE.md`.
