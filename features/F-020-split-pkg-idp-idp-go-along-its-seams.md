---
id: F-020
title: Split pkg/idp/idp.go along its seams
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-21
depends-on:
superseded-by:
---

# F-020 — Split pkg/idp/idp.go along its seams

## History

### F-020a — Split `idp.go` — DONE 2026-08-21

First substep of F-020. `pkg/idp/idp.go` went from **1072 to 216 lines**, distributed over eight
files that follow the clusters the declarations already formed. Code only — no test file was
touched, which is what makes the green suite mean anything.

| File | Contents | Lines |
|---|---|---|
| `idp.go` | `IDPRouter`, `Config`, `NewIDPRouter`, `customCompose`, `withRateLimit`, endpoint constants, `SetupRoutes` | 216 |
| `register.go` | DCR request/response types, `validateRegistration`, `handleRegister` | 182 |
| `consent.go` | `consentTemplate`/`consentTemplateData`, both consent handlers | 165 |
| `authorize.go` | `handleAuth`, `issRedirectWriter`, `errInvalidTarget`, `validateResource`, `ar_id` session helpers | 165 |
| `metadata.go` | `authorizationServerResponse` + handler, `jwks` | 120 |
| `token.go` | `handleToken`, `handleIntrospect`, `handleRevoke` | 108 |
| `client_source.go` | `CIMDResolver`, `clientSource`, the redirect-URI context stash, `GetClient`, `lookupClient` | 97 |
| `session.go` | `NewJWTSession`, `Session` | 96 |

`loopback.go` (111 lines, from F-016) was already separate and stayed as it is. Every file is now
under the 300-line target, so the 500-line hard limit is comfortably met.

**How it was done:** a script sliced the file at declaration boundaries, walking backwards over
each declaration's doc comment so no comment was orphaned, then `goimports` reduced each new
file's copy of the original import block to what it actually uses.

**One acceptance criterion could not be met, and it was a bad criterion.** The plan asked for
`git diff -M` to report moves rather than rewrites. Git cannot do that here: rename and copy
detection works on whole-file similarity, and a file that splits into eight while the source
survives fits no such pair. Even `--find-copies-harder` reports seven plain `create mode` entries.
Two stronger checks replaced it:

- **Declaration sets are byte-identical:** 47 top-level declarations before, 47 after, `diff` on
  the sorted lists empty — nothing lost, nothing duplicated.
- **Body content is byte-identical:** 954 non-blank lines below the import block before, 954
  after, sorted `diff` empty — not one character of content changed, only its file.
- The net **+77** lines reconcile exactly: **+87** for seven new package/import headers, **−10**
  because `goimports` dropped imports that `idp.go` no longer uses.

**Verification:** no `_test.go` in `git status`; `go test -race ./...` rc=0 across 11 packages with
the tests unchanged; `gofmt -l` empty; `go vet` clean. Import grouping still follows §4 (stdlib,
blank line, then third-party and local alphabetically) — `goimports` preserved the repo's style.

**Left for F-020c, deliberately not fixed here:** ten exported identifiers carry no doc comment
(`IDPRouter`, `NewIDPRouter`, `SetupRoutes`, `GetClient`, `WriteHeader`, `NewJWTSession`,
`Session`, `GetJWTClaims`, `GetJWTHeader`, `Clone`), a §11 violation. Verified as **pre-existing**:
the same ten were undocumented before the split. Adding them here would have added content to a
move-only substep and destroyed the byte-identical proof above.

**Files:** `pkg/idp/idp.go` (shrunk); new `authorize.go`, `client_source.go`, `consent.go`,
`metadata.go`, `register.go`, `session.go`, `token.go`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.
No behaviour, signature, dependency or config change.

### F-020b — Split `idp_test.go` to match — DONE 2026-08-21

Second substep of F-020. `pkg/idp/idp_test.go` (1684 lines, 48 top-level declarations) was
distributed over **ten** files, each sitting next to the code it exercises. Test files only — no
production file was touched.

| File | Lines | | File | Lines |
|---|---|---|---|---|
| `authorize_test.go` | 296 | | `session_test.go` | 147 |
| `helpers_test.go` | 290 | | `register_test.go` | 134 |
| `token_test.go` | 286 | | `ratelimit_test.go` | 119 |
| `metadata_test.go` | 184 | | `consent_test.go` | 97 |
| `revocation_test.go` | 176 | | `client_source_test.go` | 81 |

`loopback_test.go` (187 lines, from F-016) was already separate and stayed.

**Deviation from the plan: ten files instead of nine.** `token_test.go` would have reached ~439
lines once `TestPrivateClient` (148 lines, a full confidential-client flow) joined the audience,
introspection and identity tests — over the 300-line target the substep was meant to enforce. The
revocation tests were split off into `revocation_test.go`; they are self-contained anyway
(RFC 7009), and `token_test.go` lands at 286.

**Two placement decisions worth recording:**
- `stubResolver` went to `helpers_test.go`, not `client_source_test.go`, because `loopback_test.go`
  uses it too. A stub with two consumers belongs with the helpers.
- `failingRevokeRepo` stayed with `revocation_test.go` — only that one test uses it.

**Verification, using the approach F-020a established rather than git's rename detection:**
- **Test set identical:** `go test -list '.*'` returns 34 before and 34 after, `diff` on the sorted
  lists empty. This is the check that matters for a test split — a test function lost in the move
  would leave the suite green and nobody the wiser.
- **Bodies identical:** 1399 non-blank lines below the import block before, 1399 after, sorted
  `diff` empty — no test body changed, only its file.
- No production file in `git status`; `go test -race ./...` rc=0 across 11 packages with 34
  top-level tests executed; `gofmt -l` empty; `go vet` clean.
- Every file under the 300-line target (largest: 296).

**Files:** `pkg/idp/idp_test.go` (removed); new `authorize_test.go`, `client_source_test.go`,
`consent_test.go`, `helpers_test.go`, `metadata_test.go`, `ratelimit_test.go`, `register_test.go`,
`revocation_test.go`, `session_test.go`, `token_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No production code, dependency or config change.

### F-020c — Section comments and final standards pass — DONE 2026-08-21

Third and final substep of F-020, and the one that put content back after two move-only steps.

**Ten doc comments** on the exported identifiers that had none — `IDPRouter`, `NewIDPRouter`,
`SetupRoutes`, `GetClient`, `WriteHeader`, `NewJWTSession`, `Session`, `GetJWTClaims`,
`GetJWTHeader`, `Clone` (§11). They were written to explain *why* something exists rather than
restate the signature. `Clone` now records that fosite clones sessions between the authorize and
token steps, so a shallow copy would let two requests share one claims map — the route by which one
client's identity ends up in another's token. `NewJWTSession` records that the `jti` is generated
there and not at signing time, because revocation is keyed on it (SPEC §1.9). `WriteHeader` records
that fosite's own error writer knows nothing about RFC 9207, so without the wrapper a client could
not tell which authorization server rejected it.

**Ten section rules** in the three files that still group more than one concern:
`authorize.go` (RFC 8707 resource validation · RFC 9207 `iss` on redirects · authorize endpoint ·
authorize-request session binding), `idp.go` (router/config/construction · endpoints and route
registration), and `helpers_test.go` (test server setup · PKCE and flow drivers · small assertion
helpers · stubs and decoding). The other seventeen files hold exactly one concern each after
F-020a/b and need none.

**Deviation from the expectation stated when the substep was queued:** the section comments looked
likely to be redundant, since every file already sits under the 300-line target. Reading the files
showed the opposite — `authorize.go` bundles four clearly separate concerns in 165 lines. The §2
rule is about structure, not length, and applying it by line count would have missed the point.

**Verification:** zero undocumented exported identifiers remain (checked by the same scan that
found the ten); `gofmt -l` empty; `go vet` clean; `go test -race ./...` rc=0 across 11 packages;
the test set is still the identical 34 from before the whole refactor.

**Noted for later, no action needed:** `helpers_test.go` now sits at 298 lines. It satisfies the
criterion — and carries section comments either way — but the next helper added there will cross
the target and call for a further split.

**Files:** `pkg/idp/idp.go`, `authorize.go`, `client_source.go`, `session.go`, `helpers_test.go`;
docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No behaviour, signature, dependency or config change.

### F-020 — Split `pkg/idp/idp.go` along its seams — DONE 2026-08-21

Complete (a/b/c). `pkg/idp/` went from two oversized files — `idp.go` at 1072 lines and
`idp_test.go` at 1684, both far past the 500-line hard limit — to twenty files, the largest 298.
Every file now holds one concern, sits under the 300-line target, and carries section rules where
it still groups several.

The refactor was run as a **pure move first, content second**: F-020a and F-020b relocated code and
tests without changing a character of either, and only F-020c added the doc and section comments.
That order is what made the verification meaningful. Because git cannot recognise a one-into-eight
split as a move — rename detection needs whole-file similarity — the proof came from invariants
instead: identical declaration sets (47/47), identical body lines (954/954 for the code, 1399/1399
for the tests), and an identical test set (34/34 via `go test -list`), the last of which is the one
that matters for a test split, since a test lost in a move leaves the suite green and the loss
invisible.

**Sequencing:** run before F-017 by the operator's decision, so the spec re-check and its
verification pass see the split code rather than the pre-split code.

**Still open, deliberately:** `handleRegister` is 103 lines, over the 50-line hard limit and over
the ~80-line orchestration exception. Splitting it restructures the DCR endpoint instead of
relocating a file, so it never belonged in a move task and still needs its own F-number.
