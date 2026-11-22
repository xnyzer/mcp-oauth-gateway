---
id: F-022
title: Bring the remaining oversized files under the §2 limits
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-24
depends-on:
superseded-by:
---

# F-022 — Bring the remaining oversized files under the §2 limits

## History

### F-022a — The persistence and auth glue — DONE 2026-08-24

**What:** Cut `pkg/repository/sql.go` along its entity seams (token sessions, schema version,
clients, PKCE, authorize requests, user, WebAuthn, marshal helpers) and `pkg/auth/auth.go` along
its three concerns (router + setup, login flow, template rendering). Pure move, no behaviour change.

**Files:** `pkg/repository/sql.go` → several `sql_*.go`; `pkg/auth/auth.go` → several `*.go`

**Acceptance:**
- [x] Every touched file ≤ 500 lines; no new file above the 300-line target
- [x] **Identical declaration set** before/after (compared, not assumed) and identical body-line
      counts per declaration
- [x] `go test -race ./...` green with the test files untouched

#### What was actually done

`pkg/repository/sql.go` (712) became four files, following the `sql_*.go` convention the package
already used for `sql_inventory.go`:

| File | Lines | Holds |
|---|---|---|
| `sql.go` | 173 | connection, `configureSQLite`, schema version, marshal helpers |
| `sql_sessions.go` | 275 | authorization codes, access/refresh tokens, PKCE, authorize requests |
| `sql_clients.go` | 197 | DCR registrations including the atomic cap check |
| `sql_users.go` | 106 | the operator account and passkey credentials |

`pkg/auth/auth.go` (558) became four files with concern names, as `pkg/idp` got them in F-020:

| File | Lines | Holds |
|---|---|---|
| `auth.go` | 176 | `AuthRouter`, `Config`, constructor, template constants |
| `routes.go` | 98 | `SetupRoutes`, `withRateLimit` |
| `login.go` | 206 | login/logout, lockout, redirect normalisation, `RequireAuth` |
| `render.go` | 105 | template data types and the three render functions |

**The cut was mechanical, not hand-edited.** A script assigned whole declaration segments — each
declaration extended upward over its contiguous doc comment — so every line after the import block
landed in exactly one output file. `goimports` then fixed the per-file import sets. Hand-editing
730 lines of seams is where a "pure move" quietly stops being one.

**The plan's invariant was proven with an AST parser, not with text patterns.** A throwaway tool
(`go/parser`) printed `kind name bodyLines` per top-level declaration, sorted, for the whole
package including its tests. `pkg/repository`: **215 declarations identical**. `pkg/auth`: **197
identical**. Body-line counts come from the AST, so comments and formatting cannot shift them.

**One check beyond the plan.** The declaration invariant cannot see a comment stranded between the
import block and the first declaration — it would simply vanish with no declaration changing. A
multiset comparison of every content line, original against the union of the new files, reported
**0 lost and 0 gained** for both files. Worth keeping for F-022b and F-022c: the AST invariant
proves declarations moved intact, the line multiset proves nothing fell out between them.

**A first attempt failed and was reverted before it could mislead.** The assignment patterns were
written against the tool's `Type.Method` output form while the source reads `) Method(`, so almost
nothing matched and `sql.go` stayed at 496 lines with three near-empty siblings. `git checkout` on
the original, corrected patterns, re-run.

**Not fixed here, deliberately: import grouping.** CODING-STANDARDS §4 asks for stdlib →
third-party → local, and the new files put the local imports in the third-party group. That is not
a regression — measured, **46 of 46** files in the repository carrying a local import do the same,
including the originals of both split files and files this task never touched. Fixing it here would
break the pure move and leave four files unlike the other ninety. Worth its own task; noted rather
than silently built.

**Files:** `pkg/repository/sql.go`, `pkg/repository/sql_sessions.go` (new),
`pkg/repository/sql_clients.go` (new), `pkg/repository/sql_users.go` (new), `pkg/auth/auth.go`,
`pkg/auth/routes.go` (new), `pkg/auth/login.go` (new), `pkg/auth/render.go` (new). No test file was
touched, which is what makes the green suite evidence rather than decoration.

### F-022b — The CLI surface — DONE 2026-08-24

**What:** `main.go` (env helpers vs. the three Cobra commands) and `main_test.go` (parsing tests vs.
command tests) are one surface and get one cut, so the test layout mirrors the production layout.

**Files:** `main.go`, `main_test.go` → `env.go`/`env_test.go` + command files

**Acceptance:**
- [x] Both files ≤ 500 lines
- [x] Identical declaration sets and body-line counts
- [x] **`go test -list '.*'` returns the identical test set** before/after

#### What was actually done

`main.go` (568) and `main_test.go` (776) were cut together into **five pairs**, each production file
carrying a test file of the same name:

| Production | Lines | Test | Lines | Holds |
|---|---|---|---|---|
| `main.go` | 248 | `main_test.go` | 204 | `main`, `newRootCommand`, flag wiring |
| `env.go` | 73 | `env_test.go` | 154 | the five `getEnv*WithDefault` readers |
| `parse.go` | 106 | `parse_test.go` | 260 | `splitCSV`, `splitWithEscapes`, attribute and header mapping |
| `healthcheck.go` | 73 | `healthcheck_test.go` | 88 | the `healthcheck` command, `probeHealth`, `healthURL` |
| `rotatekey.go` | 96 | `rotatekey_test.go` | 96 | the `rotate-key` command and its options |

**Deviation from the plan: five pairs instead of the planned two or three files.** The plan said
"env helpers vs. the three Cobra commands". Reading environment variables and splitting strings are
different jobs, and separating them is what keeps `parse_test.go` at 260 lines instead of ~415 —
otherwise one file would have stayed above the 300-line target while still satisfying the ≤ 500
criterion. The exact mirroring is the second reason: five names, five twins, so the test for a
function is always in the file named after the file that holds it.

**All three invariants held, each compared rather than asserted:** the AST declaration set including
body-line counts (**94 declarations**, unchanged), `go test -list '.*'` (**29 tests**, identical
set), and the line multiset (**0 lost, 0 gained** for both files). The multiset check earns its
place here more than in F-022a: this substep *does* touch test files, so a green suite no longer
proves on its own that nothing was dropped.

**One check specific to splitting a Go file by name.** A file whose name ends in something Go reads
as a build constraint is silently excluded from the build rather than rejected. `go list` confirms
all five production files land in `GoFiles`, all five test files in `TestGoFiles`, and
`IgnoredGoFiles` is empty.

**Two pre-existing test fixtures tripped the secrets scan and were deliberately left alone:**
`user@domain.com` (a placeholder in a string-splitting table) and `10.0.0.5:8080` (an example of a
wildcard listen address in `healthURL`'s doc comment). Both are in `HEAD` unchanged — generic
examples, not deployment internals or a real address. Rewriting them would have broken the pure
move for no gain; if the project ever wants RFC 5737 placeholders throughout, that is its own task.

**Files:** `main.go`, `main_test.go`, `env.go` (new), `env_test.go` (new), `parse.go` (new),
`parse_test.go` (new), `healthcheck.go` (new), `healthcheck_test.go` (new), `rotatekey.go` (new),
`rotatekey_test.go` (new).

### F-022c — The proxy test file — DONE 2026-08-24

**What:** Split `pkg/proxy/proxy_test.go` (1035) by theme — token validation, header mapping,
discovery/PRM, reserved namespaces and streaming — with the shared helpers (lines 26–64) kept in
one place.

**Files:** `pkg/proxy/proxy_test.go` → several `proxy_*_test.go`

**Acceptance:**
- [x] Every file ≤ 500 lines
- [x] `go test -list '.*'` identical before/after; no helper duplicated

#### What was actually done

`pkg/proxy/proxy_test.go` (1035) became four files. Mirroring production, as F-022b did, was not
available here: `pkg/proxy` has a **single** production file (`proxy.go`, 251 lines, already inside
the limit). So the cut is thematic, along the seams `proxy.go` itself forms, and the names follow the
package's existing convention — `transport_test.go` carries no `proxy_` prefix, so neither do these:

| File | Lines | Covers |
|---|---|---|
| `token_test.go` | 343 | bearer validation: signature, `iss`/`aud`, missing `exp`, clock skew, multi-key JWKS, record presence |
| `upstream_test.go` | 414 | what leaves toward the upstream: claim-to-header mapping, anti-spoofing, credential policy |
| `metadata_test.go` | 116 | protected-resource metadata and the 401 challenge that points at it |
| `proxy_test.go` | 203 | the shared helpers, reserved namespaces, SSE gating |

**Deviation from F-022a and F-022b: two files stay above the 300-line target.** `token_test.go` (343)
and `upstream_test.go` (414) are under the 500-line hard limit, which is the acceptance criterion,
but not under the target that a and b both reached. §2 asks to *check* whether a file above 300 can
be split, and the check was made: the finer cuts are artificial. Separating "is the token valid"
from "is the token still active", or claim mapping from credential policy, tears apart tests that
exercise the same contract line. Four coherent themes under the hard limit beat six invented ones
under the target.

**One line that is not a move, and is in scope precisely because of that.**
`pkg/proxy/transport_test.go` opened with "They live apart from proxy_test.go because that file is
already far past the 500-line hard limit in CODING-STANDARDS §2 (F-022 tracks the split)". This
substep is that split, so the sentence became false the moment it landed. It now states what the
file is delimited *against* — the ordinary proxy path's mapping and credential tests in
`upstream_test.go` — instead of citing a limit that no longer applies.

**All invariants held:** 35 AST declarations with identical body-line counts, `go test -list`
identical at 17 tests, line multiset **0 lost / 0 gained** across 885 content lines, and each of the
five shared helpers (`testKid`, `testKeyLookup`, `generateRSAKeyPair`, `createJWT`,
`createDummyBackendServer`) has exactly **one** definition in the package — the criterion that
matters most when a test file is split, because duplicating a helper compiles and then silently
drifts. `go list` confirms every new file is in `TestGoFiles` and `IgnoredGoFiles` is empty.

**Files:** `pkg/proxy/proxy_test.go`, `pkg/proxy/token_test.go` (new), `pkg/proxy/metadata_test.go`
(new), `pkg/proxy/upstream_test.go` (new), `pkg/proxy/transport_test.go` (comment only).

**One file remains past the hard limit:** `pkg/mcp-proxy/main.go` (949), for F-022d and F-022e — the
part where these invariants stop applying, because `Run` is decomposed rather than relocated.

### F-022d — `Run`, part 1: configuration and dependencies — DONE 2026-08-24

**What:** Extract phases 1–4 of `Run` (lines 218–485) into named functions that take configuration
and return values: issuer normalisation, TTL and proxy validation, data directory and logger,
repository open plus schema check, key manager, abuse-protection limiters and the expiry sweeper.
New files follow the package's existing concern-file convention (`cookie.go`, `origin.go`).

**Files:** `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/config.go` and `pkg/mcp-proxy/deps.go`,
new/extended `pkg/mcp-proxy/*_test.go`

**Acceptance:**
- [x] `Run` no longer performs configuration normalisation, validation, data-directory, logger,
      repository, key-manager, limiter or sweeper setup inline
- [x] The one genuinely uncovered fail-fast branch gets a test: **CIMD and DCR both disabled**
      (`main.go:167.41,169.3`, execution count 0 today)
- [x] The 13 existing `Run`-level fail-fast cases stay green **unchanged** — they are the
      regression net for this refactor, not something to be replaced by finer tests
- [x] Coverage of `pkg/mcp-proxy` **recorded before and after** (46.9 % today). No target number is
      promised: most uncovered statements are the router and server code that F-022e moves, so a
      large rise here would be surprising rather than good
- [x] `go test -race ./...` green

#### What was actually done

`Run` went from **645 to 415 lines**, `pkg/mcp-proxy/main.go` from 949 to 716. Not under the limit
yet — phases 5–7 are F-022e's ~380 lines.

| File | Lines | Holds |
|---|---|---|
| `config.go` | 124 | `resolveConfig`: issuer normalisation, TTL defaults, `validateTTLs`, `TRUSTED_PROXIES`, TLS flag combinations |
| `deps.go` | 249 | `openDependencies`: data directory, session secret, logger, upstream backend, proxy headers, repository + schema check, key manager |
| `sweeper.go` | 78 | `limiters`, `newLimiters`, `startSweeper`, `sweep` |
| `config_test.go` | 119 | the new tests |

**The order of the checks is contract, and it was preserved deliberately.** A misconfigured
deployment sees the *first* problem found, and the 13 existing fail-fast cases assert on those
messages. `resolveConfig` reproduces the original sequence exactly; all 13 stayed green without a
single test being touched, which is what makes them evidence here rather than decoration.

**Three deviations from the plan, each for a reason:**

- **Three new files, not two.** `deps.go` came out at 324 lines, above the 300-line target. The
  sweeper is a background maintenance loop rather than startup work, so it moved to `sweeper.go`;
  both are now comfortably under.
- **`servesTLS()` was written and then deleted.** It was speculative, for F-022e. `golangci-lint`
  flagged it as unused and was right — it returns when it has a caller.
- **`sweep` had four parameters, against §3's maximum of three.** Caught in review, not by a tool:
  `golangci-lint` does not check that. Fixed by moving the refresh-window fallback onto
  `resolvedConfig` as `refreshSweepTTL()`, which is where it belongs anyway — it is a property of
  the configuration, not an argument to a sweep.

**Coverage 46.9 % → 48.1 %, measured.** The modest rise was predicted in the plan: most uncovered
statements are the router and server code F-022e moves. The one branch this substep was supposed to
close — CIMD and DCR both disabled — now shows execution count **1** in the profile where it showed
0.

**Three new assertions, each proven able to fail** (CODING-STANDARDS §9): removing the
both-disabled check makes the new test fail; removing `issuerURL.Path = ""` makes the issuer test
report the trailing slash; forcing the TLS-combination branch to `false` makes the table fail.

**One behaviour that changed shape without changing outcome.** `Run` used to register
`defer repo.Close()` immediately after opening the store, so any later failure closed it. Now
`openRepository` closes it on a schema-version failure and `openDependencies` closes it when the key
manager fails; the caller only takes ownership on success. Same guarantee, stated explicitly
instead of relying on the defer frame — and documented on the `dependencies` type, because a
half-built gateway leaving an open store is exactly the kind of thing that is invisible until it
is not.

**Files:** `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/config.go` (new), `pkg/mcp-proxy/deps.go` (new),
`pkg/mcp-proxy/sweeper.go` (new), `pkg/mcp-proxy/config_test.go` (new). No existing test touched.

### F-022 — Bring the remaining oversized files under the §2 limits — DONE 2026-08-24

**Problem:** CODING-STANDARDS §2 sets a 300-line target and a **500-line hard limit**. F-020 brought
`pkg/idp` under it, but nothing ever surveyed the rest of the tree: **six files are still past the
hard limit**, the largest at 1035 lines, and fourteen more sit above the 300-line target. F-017b ran
straight into this — its new tests could not go into `pkg/proxy/proxy_test.go` without pushing a
1035-line file to 1180, so they went into a new file and the underlying violation stayed untouched.

| File | Lines | Kind | State |
|---|---|---|---|
| `pkg/proxy/proxy_test.go` | 1035 | tests | **done (F-022c)** |
| `pkg/mcp-proxy/main.go` | 949 | production — assembly and config wiring | F-022d/e |
| `main_test.go` | 776 | tests | **done (F-022b)** |
| `pkg/repository/sql.go` | 712 | production — SQL persistence | **done (F-022a)** |
| `main.go` | 568 | production — CLI surface | **done (F-022b)** |
| `pkg/auth/auth.go` | 558 | production — password/session/WebAuthn glue | **done (F-022a)** |

Same origin as F-020's two files: they came over with the F-008 fork and grew through F-005 and
everything after it. Size is not cosmetic in this repo — these are the files a reviewer has to hold
in their head to reason about the auth boundary.

**Idea:** Repeat the F-020 method. Cut each file along the seams its declarations already form, as a
**pure move** with no behaviour change, so the existing tests are the proof rather than something
that also changed.

**Decided at `/prep-step` (2026-08-23), with the measurements behind each decision:**

- **Five of the six files are pure moves. One is not, and that governs the shape of this task.**
  `pkg/mcp-proxy/main.go` holds a **single 650-line function**, `Run` (lines 217–866). Moving out
  everything else — the `Config` struct with its validation (~170 lines) and the small helpers
  below `Run` (~83 lines) — still leaves ~690 lines around one 650-line function. The file cannot
  reach the limit by relocation; `Run` has to be decomposed, which is restructuring, not moving.
- **The invariant proof does not transfer to `Run`.** F-020's method rests on identical declaration
  sets and identical body-line counts, which only prove anything while nothing changes. `Run` is
  called from exactly one place (`main.go:189`) and the e2e suite does **not** exercise it —
  `e2e_harness_test.go` says so itself ("builds the gateway exactly as `Run()` mounts it"), i.e. it
  is a parallel implementation. This is the same gap F-021 found, so the proof for the wiring has
  to be the running binary.
- **Correction, re-planned 2026-08-24: the fail-fast paths are *not* untested.** The first plan
  claimed they were and made "tests for the paths that had none" the point of F-022d. Measured
  instead of inferred: `TestRun_ValidatesTTLs` (11 cases), `TestRun_RequiresAuthBackend` and
  `TestRun_NormalizesTrustedProxies` already cover three of the four, all through `Run` itself.
  Exactly one branch is genuinely uncovered — **both CIMD and DCR disabled**, `main.go:167.41,169.3`
  with execution count 0, and no test sets both flags to `false`. Two of the checks do not even sit
  in `Run`'s body but in `validateTTLs`, which is already extracted. The claim came from reading
  `Run`'s **35.0 % statement coverage** as if it described its branches: the figure is low because
  the tests return at the fail-fast and never reach the ~500 lines of router construction and server
  start — the fail-fast paths are the part that *is* covered. `CODING-STANDARDS.md` §9 lists that
  trap first: "Reading an aggregate where one record was meant."
- **Splitting `Run` is still two substeps, not one** — that decision rested on size and risk, which
  are unchanged — cut at the seam its own phases already form: configuration and dependencies
  (218–485) against wiring and server lifecycle (486–861).
- **The real testing gain is retiring the parallel implementation, and it has already drifted.**
  `newE2EGateway` (76 lines) rebuilds what `Run` mounts, and a helper beside it says it "mirrors
  Run's construction". The two have diverged where it matters: `Run` builds the operator session
  cookie with HKDF-derived subkeys so it is signed **and** encrypted and sets `HttpOnly`, `Secure`,
  `SameSite=Lax` and `MaxAge 600`; the harness calls `cookie.NewStore(secret[:])` and never calls
  `store.Options` at all. The e2e suite therefore cannot catch a regression in any of those §1.12
  properties. Once the wiring is a named function the harness can call it, which closes this by
  construction rather than by vigilance.
- **§3 violations stay out of scope.** `handleRegister` (109 lines), `newRootCommand` (232) and
  `handleProxy` (118) are function-length problems, not file-length ones. `Run` is the sole
  exception, because §2 is unreachable there without §3.
- **The fourteen files between 300 and 500 stay out of scope** unless a cut makes them fall out
  naturally; §2 only asks to "check whether it can be split" at 300, and the hard limit is the
  actual violation. `pkg/repository/kvs.go` (487) mirrors `sql.go` and would be worth the same cut
  afterwards for package symmetry — as its own task, not here.

**Substeps** — the pure moves first, so the invariant harness is established before the one change
it cannot prove. **F-022a–d are done.** `pkg/mcp-proxy/main.go` is down from 949 to 716 lines;
F-022e's phases 5–7 are the remaining ~380 that bring it under the limit.

The verification harness F-022a established, to be reused by b and c: an AST parser prints
`kind name bodyLines` per top-level declaration for the whole package (tests included) — identical
before and after proves the declarations moved intact — plus a **line multiset** comparison, which
catches what the declaration invariant cannot: a comment stranded between the import block and the
first declaration would vanish without any declaration changing.

#### F-022e — `Run`, part 2: wiring and lifecycle

**What:** Extract phases 5–7 (lines 486–861): auth/IDP/proxy router construction, the gin assembly
(trusted proxies, `/healthz`, logging, origin check, session store) and the server lifecycle
(listeners, TLS/ACME, shutdown). The extraction must yield a function that builds and returns the
`*gin.Engine` **without** starting a listener — otherwise `e2e_harness_test.go`, which needs
`httptest`, still cannot call it. That is the design decision of this substep.

**Files:** `pkg/mcp-proxy/main.go`, new `pkg/mcp-proxy/router.go` and `pkg/mcp-proxy/server.go`,
`e2e_harness_test.go`

**Acceptance:**
- [x] `pkg/mcp-proxy/main.go` ≤ 500 lines and `Run` within the §3 orchestration exception (~80)
- [x] `e2e_harness_test.go` calls the extracted wiring instead of rebuilding it — **or** the reason
      it cannot is recorded in the step-done entry, in which case the drift below is raised as its
      own task rather than left implicit
- [x] The known divergence is closed or explicitly recorded: the harness builds the session cookie
      with `cookie.NewStore(secret[:])` and never calls `store.Options`, so it runs without
      encryption, `HttpOnly`, `Secure` or `SameSite` — unlike `Run`
- [x] **Verified against the running binary**, not only the suite: the gateway starts against a
      deployment-like configuration, serves the three discovery documents, and answers `/mcp`
      without a token with `401` plus the `WWW-Authenticate` challenge
- [x] Each fail-fast path still aborts startup with its message, checked against the built binary
- [x] `go test -race ./...` green

**Dependencies:** none — but like F-020 it must not land between F-017's verification and the v0.2.0
tag, or the release would ship code the verification never saw.

---

#### F-022e — what was actually done

`Run` went from 415 to **27 lines** and `pkg/mcp-proxy/main.go` from 716 to **312**. Counting the
whole task: `main.go` 949 → 312, `Run` 645 → 27. **No file in the repository exceeds the 500-line
hard limit any more** — the goal F-022 was raised for.

| File | Lines | Holds |
|---|---|---|
| `router.go` | 265 | `BuildRouter` plus the auth/IDP/proxy constructors, the session store and the revocation check |
| `server.go` | 223 | `serverGroup`, `gateway`, the three TLS modes, `acmeHost` |
| `main.go` | 312 | `Run` and the small helpers |

**The server phase was three near-identical blocks.** Each TLS mode carried its own copy of the
listen goroutine plus the shutdown goroutine — roughly 150 lines of duplication. They collapse into
`serverGroup.serve`, which decides TLS from the server's own `TLSConfig`. One consequence worth
naming: the plain-HTTP branch previously logged no "server closed" debug line where the other two
did; unifying them gives it one.

**The design constraint was met.** `BuildRouter` returns the assembled `*gin.Engine` **without
listening**, which is what the plan required so the end-to-end tests could drive the real wiring.

**But the harness still cannot call it, and that was not foreseen.** `resolvedConfig` and
`*dependencies` are package-private while `e2e_harness_test.go` lives in package `main`. The
package boundary, not the listener, is the blocker. Per the acceptance criterion's own escape
clause this was recorded rather than solved here, and the operator chose a separate F-number:
**F-028** carries the relocation, the cookie divergence, the third `tokenActiveChecker` copy — and
explicitly the retrofit of what this substep left behind. Concretely, `BuildRouter` was exported in
anticipation of a caller that cannot exist: **its parameter types are package-private, so nothing
outside the package can call it at all**, and its only caller is `Run`. F-028 owns that correction.

**Verified against the running binary, not only the suite** — the point of this substep, because
the e2e suite provably does not exercise this path. All five fail-fast paths abort with their
message (no auth backend, CIMD and DCR both disabled, malformed TTL, invalid `TRUSTED_PROXIES`, no
upstream). Running against a mock upstream: the three discovery documents answer `200` and are
self-consistent (PRM `resource` equals AS `issuer`), `code_challenge_methods_supported` is
`["S256"]`, CIMD is advertised, `POST /mcp` without a token answers `401` with
`WWW-Authenticate: Bearer resource_metadata="…"`, a foreign `Origin` gets `403` and the gateway's
own gets `200`.

**One documented linter exception.** gosec G118 wants the shutdown context derived from `ctx`. That
would be **wrong**: `ctx` is already cancelled when the shutdown goroutine runs — that is why it
runs — and a cancelled parent makes `Shutdown` return at once instead of draining in-flight
requests. `//nolint:gosec` with that reason, in the form the repository already uses in nine places.

Coverage of `pkg/mcp-proxy` rose 46.9 % → **52.7 %** across F-022d and F-022e, without a single
existing test being modified in either.

**Files:** `pkg/mcp-proxy/main.go`, `pkg/mcp-proxy/router.go` (new), `pkg/mcp-proxy/server.go` (new).

#### F-022 as a whole

Six files were past the hard limit, the largest at 1035 lines. Four substeps were **pure moves**,
proven by invariants — identical AST declaration sets with per-declaration body-line counts,
identical `go test -list` output, and a line multiset showing nothing lost or gained. The fifth was
not a move and could not use those invariants, which is why it was split off and verified
behaviourally instead.

Two lessons the task produced beyond the file sizes. **The planned safety net was too weak, and
only a mutation showed it:** built to the specified prefix rule, renaming a heading left the suite
green, because every `1.x` resolves while `§1` exists. **And a plan built on an inferred fact had to
be re-planned mid-task:** F-022d's stated purpose rested on reading `Run`'s 35 % statement coverage
as if it described its branches, when three of the four fail-fast paths were already covered. Both
are recorded where they happened rather than smoothed over.

### F-022e (2026-08-24)

`Run` part 2 → phases 5–7 into `router.go` and `server.go`; **`Run` 645 → 27 lines**, `main.go` 949 → 312, and **no file in the repository is past the 500-line hard limit any more**. The server phase was three near-identical blocks — ~150 lines of listen/shutdown goroutine duplication — now one `serverGroup.serve` that decides TLS from the server's own `TLSConfig`. **Verified against the running binary, not the suite**, which provably does not exercise this path: five fail-fast paths abort with their message; live, the three discovery documents answer 200 and are self-consistent, `/mcp` without a token gives 401 with `WWW-Authenticate`, a foreign `Origin` gets 403. The design constraint was met — the wiring returns the engine without listening — but the harness still cannot call it, because the parameter types are package-private and it lives in package `main`. Recorded as **F-028**, which also owns the retrofit: `BuildRouter` was exported for a caller that cannot exist. Detail in `PROGRESS-ARCHIVE.md`.
