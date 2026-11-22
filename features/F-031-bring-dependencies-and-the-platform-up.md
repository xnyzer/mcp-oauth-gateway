---
id: F-031
title: Bring dependencies and the platform up to date
type: feature
status: DONE
size:
created: 2026-10-12
done: 2026-10-13
depends-on:
superseded-by:
---

# F-031 — Bring dependencies and the platform up to date

## History

### F-031a — Routine bumps — DONE 2026-10-12

First substep of F-031 (*Bring dependencies and the platform up to date*); the parent entry,
with the dry-run findings and the operator's decisions, stays in `PROGRESS.md` until its last
substep is done.

**What:** The 35 minor and patch updates of the group that change neither API nor documented
behaviour (OpenTelemetry 1.47, gin-contrib, quic-go, sqlite3, grpc 1.84, `x/oauth2`, `x/time`
and the rest). No product code. One new indirect module appears, `go.opentelemetry.io/otel/log`.

**Files:** `go.mod`, `go.sum`.

**Acceptance criteria:**
- [x] `go mod tidy` clean; the only new module is the one named above, and it is permissively
      licensed (`go-licenses` green).
- [x] Full check set green with the pinned toolchain; `govulncheck` 0 reachable.

#### F-031a — what was actually done

**Applied with explicit pinned versions** (`go get module@version` for each of the 35, then
`go mod tidy`), from a script rather than `@latest` — CODING-STANDARDS §7. **37 modules moved:**
the 35, plus the two `google.golang.org/genproto` modules, which follow transitively. With the
three updates held back for their own substeps — `gobwas/glob`, `go-webauthn/webauthn`,
`mark3labs/mcp-go`, all verified unchanged afterwards — that is exactly the forty of Dependabot's
grouped PR #24. The `go` line and the toolchain did not move.

**One module added, none removed:** `go.opentelemetry.io/otel/log` v1.47.0, an indirect
dependency compiled into the build (two packages) through `ory/fosite` → `ory/x/otelx` →
`otel`. Apache-2.0, with a BSD-3-Clause part; `go-licenses check` passes.

**The result matched the `/prep-step` dry run line for line** — same 37 modules, same single
addition, same diff size (118 insertions, 115 deletions). That is the dry run doing its job:
this substep held no surprise because the surprises had been measured beforehand.

**Verified** (all with `GOTOOLCHAIN=go1.26.9`): `go mod tidy -diff` empty; `go mod verify` —
all modules verified; gofmt from that toolchain empty; `go vet` clean; `go test -race -count=1
./...` green in all 11 packages with tests; golangci-lint v2.12.2 0 issues; go-licenses v2.0.1
passes; actionlint clean; `govulncheck` — no vulnerabilities found. The `image-build` job
replicated locally: image builds, `--version` runs, the container reports `healthy`, no
error-level log line.

**Found on the way, not built here:** `go get` printed that
`go.opentelemetry.io/otel/exporters/zipkin` is deprecated and will be removed in early 2027.
Tracing it showed two unused trace exporters in the binary, both through `ory/x`: Zipkin, and
Jaeger, which has been frozen at v1.17.0 since its own removal. Taken in as **F-033**, a dated
watch item (re-check 2027-01-15), instead of being acted on inside a routine bump.

**Deviations from the plan:** none.

**No CHANGELOG entry:** nothing here is visible to an operator; the release notes for v0.5.0
will name the dependency refresh once, for F-031 as a whole.

### F-031b — `gobwas/glob` 1.0, and the OIDC allow-list hardened — DONE 2026-10-13

Second substep of F-031. **Its scope grew twice, both times on the operator's instruction**,
after the glob work had surfaced two further faults in the same allow-list; the planned part is
recorded first, the extensions after it.

**What (as planned):** Adapt the OIDC allow-list to `*glob.Pattern`. Before the bump, write a
table test that pins what the allow-list matches — wildcards, character classes, alternates,
escapes, non-ASCII, and above all what must **not** match — and run it against 0.2.3; then bump
and run it again. Compile errors stay fail-fast at start-up.

**Acceptance criteria:**
- [x] The table passes against 0.2.3 as written, or every row that does not is recorded as a
      known defect of the old engine.
- [x] Every row whose result differs under 1.0 is explained and named in the CHANGELOG for
      operators using `OIDC_ALLOWED_*_GLOB`.
- [x] The negative rows have been seen to fail once (CODING-STANDARDS §9).
- [x] Full check set green.

#### Part 1 — the glob engine

**The move itself was one word**: `glob.Glob` (an interface) became `*glob.Pattern`. Before it,
the two duplicated compile loops in `NewOIDCProvider` became one helper, `compileGlobs`, so a
test exercises the exact call production makes — compiled **without separators** — instead of
compiling patterns of its own. Its error now names the pattern and wraps the sentinel
`ErrInvalidGlobPattern`.

**The table** (`pkg/auth/oidc_glob_test.go`, 49 rows, 23 of them negative) was run against
0.2.3 first. **Exactly the eight rows marked "0.2.3 got this wrong" failed there, and no
other**: five wrong matches, two malformed patterns it accepted, one crash. Under 1.0 all pass.

**The differences were measured, not looked up.** A throwaway probe in the scratchpad, built once
against each version, ran 9,512 generated patterns against 1,555 values each — about 15 million
comparisons per engine. 72.6 % of the patterns behaved identically on every value; every one of
the 23,195 differing pairs among patterns both engines compile traced back to a named cause, and
so did all 1,446 patterns only 1.0 rejects. Six causes, all in the CHANGELOG:
1. **Overlapping literals** — `admin*n@corp.example` matched `admin@corp.example` (over-permissive).
2. **`?` and negated classes matched the empty value** (over-permissive).
3. **Malformed patterns** — unclosed `{`, trailing backslash — were accepted; now a start-up error.
4. **Non-ASCII** — `?` and classes failed on a multi-byte character.
5. **Empty braces** — `a{}` panicked inside `Match`, at login time.
6. **Empty alternatives** next to `*` or another brace group were lost — found by the probe
   after the first CHANGELOG draft had named only five causes.

Of 54 hand-written realistic patterns, 50 behaved identically; the four that did not are rows
of the table.

#### Part 2 — strict parsing of the four settings (operator's instruction)

**The fault:** `parseAttributeMap` dropped an entry without `=`, with an empty key or with an
empty value, and every list kept or dropped blank entries depending on how it was split. An
allow-list emptied that way read as "no restriction", so a typo in the only rule admitted every
account of the provider. **Now** (`parse.go`): blank entries (a trailing comma, stray spaces)
are dropped; anything else that is not a rule — no `=`, no value, a key that is not a JSON
pointer starting with `/`, a setting that is set but holds no entry — stops start-up with a
message naming the setting and the entry. Parsing moved out of `RunE` into
`oidcAllowListSettings.parse`.

**Found on the way: the comma trap.** The glob settings are split at commas before a pattern is
read, so `{alice,bob}@example.com` arrives as `{alice` and `bob}@example.com` unless the comma is
escaped as `\,`. 0.2.3 accepted both halves silently; 1.0 rejects the first with "unclosed `{`",
which would send an operator looking for a typo. `buildOIDCProviders` recognises
`ErrInvalidGlobPattern` and adds the escape rule to the message.

#### Part 3 — OIDC requires an allow-list (operator's decision)

**The root:** with OIDC enabled and none of the four settings set, `Authorization` returned
"allowed" for every account the provider authenticated — with a provider anyone can sign up to,
everyone, as the single operator. Part 2 closed the typo route to that state, not the state:
leaving the settings out, or an empty variable, still led there. **User chose refusing to start
over a start-up warning**, because a warning leaves the trap open for everyone who does not read
logs, and v0.5.0 already changes start-up conditions. Now `NewOIDCProvider` refuses a provider
without a rule (`ErrNoAllowList`) **before it fetches anything**, so the refusal does not depend
on the provider being reachable; "everyone" is a rule that has to be written,
`OIDC_ALLOWED_USERS_GLOB=*`. The allow-all branch in `Authorization` is gone: a provider without
a rule — which the constructor never builds — denies. `buildOIDCProviders` names the four
settings and the `*` form in the start-up message.

**Rule evaluation was extracted** into `oidcProvider.isAllowed` during `/step-done`:
`Authorization` had stood at 67 lines, past the §3 hard limit; it is now under 30.
`NewOIDCProvider` (67) is an orchestration function within the §3 exception.

#### Verification

**21 mutations, each seen red**, run from bash scripts with byte-for-byte restore checks: seven
on the glob path (substring matching, match-everything, a dropped malformed pattern, an error
not naming the pattern, empty patterns compiled, a separator configured, list values ignored),
nine on the parsing (each drop-instead-of-error path restored, escapes ignored, the parse error
ignored at start-up, the comma hint removed), five on the requirement (no check, allow-all
restored, the check moved after the fetch, an attribute key without values counted as a rule,
the start-up message stripped). Under "every pattern matches every value", all 23 negative rows
failed. **A process slip, caught:** after the `isAllowed` extraction, two glob mutations whose
anchor text had changed were not applied — the script's assertion failed but did not abort, and
the run reported "nothing failed". Re-run with the anchors fixed; both went red. The mutation
memory now says the assertion must abort the run.

**On the built binary:** OIDC without an allow-list stops with the message naming the four
settings and `OIDC_ALLOWED_USERS_GLOB=*`; with `*` the check passes and start-up fails only on the
unreachable test provider; an unescaped `{alice,bob}` stops with the escape rule; a malformed
attribute rule names setting and entry.

**Check set** (`GOTOOLCHAIN=go1.26.9`): gofmt empty; `go mod tidy -diff` empty; `go vet` clean;
`go test -race -count=1 ./...` green in all 11 packages; golangci-lint v2.12.2 0 issues;
go-licenses passes (`gobwas/glob` is MIT); `govulncheck` 0 reachable.

#### Deviations from the plan

- **Scope extended twice on the operator's instruction** (Parts 2 and 3); Part 3's design was the
  operator's choice between two options.
- **`compileGlobs` extracted** instead of a bare type swap — otherwise the table would have tested
  its own compile call, not production's.
- **New test files** `pkg/auth/oidc_glob_test.go` and `pkg/mcp-proxy/router_test.go`:
  `oidc_test.go` stood at 483 lines and would have crossed the 500-line limit.
- **Existing tests that built providers with empty lists** now pass `*`. Three of them — the
  constructor's error paths — would otherwise have failed for the new reason instead of the one
  their names state.
- **Test data uses reserved domains only** (`*.example`, `example.com` subdomains); two real
  domains in the first draft were replaced.
- **One commit instead of the two announced:** the three parts interleave in `oidc.go` and the
  test files; splitting them by hand risked an intermediate commit that does not build.

**Files:** `go.mod`, `go.sum`, `pkg/auth/oidc.go`, `pkg/auth/oidc_test.go`,
`pkg/auth/oidc_glob_test.go` (new), `parse.go`, `parse_test.go`, `main.go`, `main_test.go`,
`pkg/mcp-proxy/router.go`, `pkg/mcp-proxy/router_test.go` (new), `README.md`, `SPEC.md` (§1.12,
§3.1), `CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

### F-031c — `mark3labs/mcp-go` 1.x — DONE 2026-10-13

Third substep of F-031.

**What:** Bump to 1.2.1 and establish what the stdio backend now speaks: which protocol
version it requests, and that it still initializes against an upstream that only knows an
older one. Bring `docs/MCP-CONFORMANCE.md` and SPEC in line — the conformance record still
says the stable line implements 2025-11-25 only.

**Acceptance criteria:**
- [x] A test names the protocol version the stdio path negotiates, against a current and
      against an older upstream.
- [x] The conformance record states that version, with the test as its evidence.
- [x] Full check set green.

#### F-031c — what was actually done

**The bump is one line in `go.mod`** and compiles untouched, as the dry run had shown. What it
changes is the protocol: 2026-07-28 replaced the `initialize` handshake with a stateless core —
`server/discover`, the version carried in every request's `_meta`, no sessions. `mcp-go` 1.x
therefore probes `server/discover` first and falls back to the handshake when the other side
does not have it.

**The stdio backend terminates MCP on both sides, so it holds two versions**, negotiated
independently. Established by test, not read off the changelog:

| Side | Case | Version in effect |
|---|---|---|
| upstream | has `server/discover` | 2026-07-28 |
| upstream | answers "method not found" → handshake, asking for 2025-11-25 | the upstream's: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 |
| upstream | answers a version nobody knows | refused at start-up |
| client | current | 2026-07-28 |
| client | still performs the handshake | the one it asks for, back to 2025-03-26 |

The sides need not match: a client on 2026-07-28 lists and calls a tool on an upstream that
answers 2025-06-18.

**The one behavioural cost, found in the library source rather than in its release notes:** an
older upstream that *ignores* an unknown method answers the probe with nothing, and on stdio
nothing means waiting. The client bounds the probe — at five seconds by default. That default
is now the gateway's own named value, `MCPDiscoverProbeTimeout`, passed in with
`client.WithDiscoverTimeout`: the start-up delay such an upstream costs should not be a number
nobody in this repository can see, and a test for it should not take five seconds.

**Tests** (`pkg/backend/proxy_protocol_test.go`, new): a real `mcp-go` server over in-memory pipes
as the current upstream; a hand-written JSON-RPC responder as the older one, configurable to
reject or ignore the probe, to answer any version, and to offer a tool. Each version is a
literal in the assertions, so a library update that moves one fails a test before the
conformance record can be wrong.

**`TestSetupProxy` removed, on the operator's instruction at `/step-done`.** Its first half
checked that `setupProxy` returns a client and a handler; its second half opened a second client
on the *upstream's* transport and asserted the upstream's own name — it never touched the
gateway's handler, and stayed green with the identity pass-through broken. The new tests cover
both halves through the handler; its one assertion nothing else made, the upstream's version
being passed through, moved there and was seen red.

**Eight mutations, each seen red**, from a script that now aborts when an anchor is missing
(the lesson of F-031b): the client kept on the handshake; an old version requested; the probe
bound left to the library default; the bound removed; the named value changed; tools not
offered; the upstream's name not passed through; its version not passed through.

**Verified** (`GOTOOLCHAIN=go1.26.9`): gofmt empty; `go mod tidy -diff` empty; `go vet` clean;
`go test -race -count=1 ./...` green in all 11 packages; golangci-lint v2.12.2 0 issues;
go-licenses passes (`mcp-go` is MIT); `govulncheck` 0 reachable. The built binary was started
with a real stdio upstream: `/healthz` answers, `/mcp` without a token is `401`, no error-level
log line.

#### Deviations from the plan

- **`SPEC.md` did not change.** Its one sentence on the matter says the stdio backend's protocol
  version is recorded in the conformance document, which is still true.
- **Production code changed after all** — three lines for the named probe timeout. The plan
  allowed code "only if negotiation needs it"; negotiation works without it, but the delay it
  introduces would otherwise be an invisible default.
- **Both sides tested, and the bridge**, where the plan asked for the upstream side. The old
  record's claim covered the whole path, so the new one had to as well.
- `setupProxy` stands at 70 lines; it is a sequential orchestration function within the §3
  exception, and its three registration blocks were left as they are.

**Not affected:** the transparent backend forwards bytes and holds no protocol opinion — and the
live deployment uses it.

**Files:** `go.mod`, `go.sum`, `pkg/backend/proxy.go`, `pkg/backend/proxy_test.go`,
`pkg/backend/proxy_protocol_test.go` (new), `docs/MCP-CONFORMANCE.md`, `CHANGELOG.md`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

### F-031d — Go 1.27 and the images — DONE 2026-10-13

Fourth substep of F-031.

**What:** Toolchain 1.27 in `go.mod`, the builder on digest-pinned `golang:1.27-bookworm`,
the runtime on digest-pinned `distroless/static-debian13:nonroot`, golangci-lint on a version
that supports 1.27, and the `gofmt` realignment in `pkg/idp/metadata.go`. The rules that name
1.26 follow.

**Dependencies:** F-031a–c, so the toolchain moves under a settled dependency set.

**Acceptance criteria:**
- [x] All five CI jobs replicated locally and green, `lint` with the new pinned version.
- [x] Image builds; `--version` runs; the container reports `healthy`; it still runs as
      non-root and can write its data directory.
- [x] `govulncheck` against the 1.27 toolchain: 0 reachable.
- [x] No reference to Go 1.26 or `static-debian12` is left in the rules or the README.

#### F-031d — what was actually done

**Versions were looked up, not remembered:** Go 1.27.2 is the current release; the
`golang:1.27-bookworm` image carries exactly it (digest `sha256:5cf287a7…`);
`distroless/static-debian13:nonroot` is at `sha256:e2e927ec…`; golangci-lint v2.14.0 is current.

- **`go.mod`:** `toolchain go1.27.2`, and `go 1.27.0`.
- **`Dockerfile`:** both `FROM` lines re-pinned. The builder already sets `GOTOOLCHAIN=auto`, and
  image and `go.mod` name the same release, so nothing is downloaded during the build.
- **`ci.yml`:** golangci-lint v2.12.2 → v2.14.0. The old version fails its typecheck under Go
  1.27 ("could not import fmt"), so the toolchain cannot move without it — which is also why
  Dependabot's PR #17, touching the `Dockerfile` only, would have turned `lint` red.
- **`pkg/idp/metadata.go`:** reformatted by the 1.27 `gofmt`; `git diff -w` is empty, so the
  change is whitespace only.
- **Rules:** CODING-STANDARDS §11 and SPEC §3.3 name 1.27 and `static-debian13`.

**The `go` line moved too, which the plan had not asked for.** With only the toolchain raised,
the gateway would have been built by 1.27 with 1.26's behaviour defaults — and CODING-STANDARDS
could not truthfully have said "pinned to 1.27". What the line switches on was read from the
1.27 `godebug.md` before raising it: a single default, `tracebacklabels`, which puts goroutine
labels into tracebacks; the others are removals of settings long since at their final value.
Every package in the build (434 directories) was searched for code that sets goroutine labels:
one hit, gRPC's server, which the gateway does not run. No effect, and no path by which a label
could carry something into a log.

**The runtime image** changes its Debian base and nothing the gateway relies on: the user is
still `nonroot`, uid 65532, so existing named volumes and bind mounts keep their ownership.

#### Verification

**All five CI jobs replicated locally under `GOTOOLCHAIN=go1.27.2`:**
- `build-test`: gofmt (the 1.27 binary) empty, `go vet`, `go build`, `go test ./...` — and
  `-race`, green in all 11 packages.
- `lint`: golangci-lint v2.14.0, 0 issues; `config verify` clean.
- `license-check`: go-licenses v2.0.1 builds under 1.27 and passes.
- `workflow-lint`: actionlint v1.7.12 clean.
- `image-build`: built for `linux/amd64` as CI does; `--version` runs; container `healthy`.

**The image at run time:** `healthy` with no volume, with a fresh named volume, and with a
read-only root filesystem. In the named volume the gateway's files belong to 65532:65532 with
modes 0600/0700. The binary inside reports `go1.27.2`.

`govulncheck` against 1.27.2: no vulnerabilities found. `go mod tidy -diff` empty.

**No new tests and no mutation pass:** the substep adds no logic. Its evidence is the replicated
jobs and the run-time checks of the image.

#### Deviations and open ends

- **`go` line raised**, see above.
- **`docs/VERIFICATION.md` unchanged:** its `debian:bookworm-slim` example is a hand-built
  container for a hand-built binary, not a reference to this image.
- **The question the plan left to this substep is not settled.** The deprecated tag does not
  fully explain why Dependabot proposed no runtime digest: `static-debian12` moved once more
  after the pinned digest, and no PR came. Unproven suspicion — its digest PRs for both base
  images were closed rather than merged in August (#1, #7), and it may not propose a digest for
  the same tag again. With both tags changed now, it has new ones to track; whether it does is
  proposed as a check for F-032.
- **Dependabot PR #17** (Go 1.27 builder) is superseded and has to be closed by hand; docker PRs
  do not close themselves.

**Files:** `go.mod`, `Dockerfile`, `.github/workflows/ci.yml`, `pkg/idp/metadata.go`,
`CODING-STANDARDS.md`, `SPEC.md`, `CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

### F-031e — `go-webauthn` 0.18 — DONE 2026-10-13

Fifth and last substep of F-031. Its code was complete and released as part of v0.5.0 before its
last criterion — the operator's own passkey on the live deployment — could be met; the two are
recorded in that order.

**What:** Last, so the real-device check runs on the final combination. Bump to 0.18.2; turn
the library's relying-party-ID error into a start-up message that names `EXTERNAL_URL` and
says what to use instead; prove that a passkey stored under 0.17 still logs in under 0.18;
cover the stricter response checks.

**Files:** `go.mod`, `go.sum`, `pkg/auth/webauthn.go`, `pkg/auth/webauthn_test.go`,
`pkg/mcp-proxy/` (start-up path test), `README.md`, `SPEC.md` (§1.12, §3.1), `CHANGELOG.md`.

**Dependencies:** F-031d.

**Acceptance criteria:**
- [x] A credential record written by 0.17.4 completes a login under 0.18.2 (fixture test).
- [x] An IP address as `EXTERNAL_URL` host stops the gateway at start-up with a message naming
      the setting and the remedy; a domain and `localhost` start. Seen red once.
- [x] An unsolicited extension output fails the ceremony, pinned by a test, so the strict
      policy is a decision and not an accident of the default.
- [x] CHANGELOG carries a prominent upgrade note for the `EXTERNAL_URL` change.
- [x] Full check set green.
- [x] **On the live deployment:** password login re-enabled first, update applied with a
      backup, the operator's passkey login succeeds, password login disabled again.

**What was built:**
- `go-webauthn` 0.17.4 → 0.18.2, and with it — at the operator's request — the two patch updates
  that had appeared since F-031a, `fxamacker/cbor` 2.9.6 and `x/mod` 0.42.0. No new module.
- `newWebAuthn` refuses an IP address itself, in terms of the setting, and wraps the library's
  refusal of any other unusable host the same way (`ErrInvalidRelyingPartyHost`). The strict
  extension policy is set explicitly instead of inherited as a default.
- **Fixtures written by 0.17.4** (`pkg/auth/testdata/`), generated before the bump: a synced
  passkey (backup-eligible, backed up, user-verified) and a device-bound key without user
  verification. Both log in under 0.18.2 and round-trip through it to the same document. A
  fixture cannot carry its private key (CODING-STANDARDS §7), so the test enrolls a fresh key
  and rewrites the stored record into the 0.17.4 one with that key's id and public key — the
  field set, flags and authenticator data are 0.17.4's. That its values count was shown by
  mutation: a fixture whose backup flags contradict the authenticator fails the login.
- Tests for the start-up path (`startE2EGateway`, a small harness extension that returns a
  refused start-up as an error), the unsolicited extension output at login and at enrollment,
  and the `id`/`rawId` check. Eight mutations, each seen red.
- All five CI jobs replicated under Go 1.27.2; `govulncheck` 0 reachable; gitleaks clean.

#### F-031e — the live deployment

**What no test could tell** was whether the operator's own browser or password manager returns
an extension output unasked — under the strict policy that fails the login, and the operator
had the password login switched off. Passkeys are bound to the production domain, so there was
no staging host to try them on. The agreed safety net: the operator re-enabled the password
login before the update.

**A rehearsal that needed no private key was found on the way.** Beginning a passkey login
makes the gateway decode every stored credential record; it needs no assertion, only a CSRF
token. So before the switch, v0.5.0 was started **beside** the running gateway — a separate
Compose project, bound to the host's loopback only, on a **copy** of the data directory and with
the real environment file — and asked to begin a passkey login. It answered `200` with a
challenge for the production relying-party ID and logged neither warning nor error: v0.5.0 reads
the stored passkeys, and the production `EXTERNAL_URL` passes the new host validation. The
rehearsal and its data copy were removed again; the running gateway was never touched by it.

**The switch:** backup of the Compose file and the data directory, image tag to `0.5.0`, pull,
`up -d`; `healthy` after six seconds, no error or warning in the log. From outside: both
metadata documents, the JWKS and the login page answer `200`, `/mcp` without a token answers
`401` with its challenge, no public page names the version, and **the signing key is the one in
the backup**, so connected clients kept their tokens.

**The operator's check:** the passkey login succeeded under the stricter checks; the password
login was switched off again; Claude connects. The strict extension policy therefore stays.

**Seen by the operator on that login, not part of this task:** after a direct visit to the login
page the gateway redirects to `/`, which is the protected proxy surface and answers
`{"error":"unauthorized"}`. Inherited behaviour — the post-login target defaults to `/` when no
protected page was visited first. Proposed as a task of its own.

**Deviations from the plan:**
- The end-to-end harness gained `startE2EGateway`, which returns a refused start-up as an error.
- The two patch updates were carried along at the operator's request.
- The rehearsal on a data copy was not in the plan; it turned the riskiest step from "switch and
  see" into "switch what has already been seen to work".
- `handleWebAuthnLoginFinish` stands at 62 lines; it is a sequential handler within the §3
  exception and was deliberately left alone on the eve of a release that changes the library
  beneath it.

**Files:** `go.mod`, `go.sum`, `pkg/auth/webauthn.go`, `pkg/auth/webauthn_upgrade_test.go` (new),
`pkg/auth/testdata/` (new), `pkg/mcp-proxy/e2e_harness_test.go`, `pkg/mcp-proxy/router_test.go`,
`README.md`, `SPEC.md` (§1.12, §3.1), `CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

### F-031 — Bring dependencies and the platform up to date — DONE 2026-10-13

**Problem:** About forty dependency updates are pending, and Dependabot's grouped PR cannot
land them: it fails to compile. None closes a known vulnerability — `govulncheck` reports zero
reachable and no alert is open — but the longer the gap grows, the larger and riskier the next
security bump becomes; F-029 showed how a routine fix turns into a toolchain move when the
baseline has drifted.

**Idea:** Take the updates in on `main` in separately verified pieces instead of as one
grouped PR: the routine bumps first, then each update that changes behaviour on its own, then
the Go toolchain. Ship the result as minor release **v0.5.0**.

**What `/prep-step` measured (2026-10-12, dry run in a throwaway worktree):**
- **Only one update breaks the build.** `gobwas/glob` 1.0 turns the `glob.Glob` interface into
  `*glob.Pattern` — a one-word change in `pkg/auth/oidc.go`. `go-webauthn` 0.18.2 and `mcp-go`
  1.2.1 compile untouched, and with all forty updates applied the full suite, lint, licences
  and `govulncheck` are green. The intake's "three API-changing updates" was wrong.
- **The risk is in behaviour, which no compiler reports and our tests do not cover:**
  - `glob` 1.0 is a rewrite of the matching engine closing 23 issues, two of them crashes in
    `Match`. It decides the OIDC allow-list — an authorization decision — and the only test
    for it has two patterns.
  - `go-webauthn` 0.18 validates the relying-party ID as a domain: an IP address as the
    `EXTERNAL_URL` host passed `webauthn.New` under 0.17.4 and fails it under 0.18.2, so such a
    gateway **no longer starts**. Single-label hosts (`http://gateway:8080`) were already
    refused under 0.17.4.
  - `go-webauthn` 0.18 fails a ceremony when the client returns an extension output nobody
    requested. An operator who has disabled the password login is locked out if their
    authenticator does that.
  - `mcp-go` 1.x makes `LATEST_PROTOCOL_VERSION` 2026-07-28; the stdio backend requests it.
    The transparent backend forwards bytes and is unaffected.
- **Go 1.27 needs more than the builder image.** golangci-lint v2.12.2 fails its typecheck
  under Go 1.27, so the pinned linter moves too (v2.14.0 is current). `gofmt` 1.27 realigns
  one struct literal in `pkg/idp/metadata.go`; suite and `govulncheck` are green under 1.27.2.
  Dependabot's PR #17 touches the `Dockerfile` only and would have gone red in `lint`.
- **`distroless/static-debian12` is no longer updated.** The distroless README lists only
  Debian 13 as published and updated and calls every other tag deprecated — which is the
  likely reason Dependabot proposed no new runtime digest.

**Decisions (operator, 2026-10-12):**
- **IP address in `EXTERNAL_URL`: fail fast with a clear message**, over starting without
  passkeys — single-label hosts are already refused the same way, a passkey never could work
  on an IP, and degrading would mean uncoupling the settings page from WebAuthn on the login
  surface. It gets a prominent upgrade note in the CHANGELOG.
- **Unsolicited extension outputs: keep the library's strict default**, verified against the
  operator's real authenticators before the deployment switches.
- **Deployment safety net:** passkeys are bound to the production domain and cannot be tried
  on a staging host, so the operator re-enables the password login before the update, tests a
  passkey login after it, and disables the password again.
- **Runtime image: move to `distroless/static-debian13`**, over re-pinning the deprecated
  `debian12` tag.
- **One minor release, v0.5.0,** after all five substeps — the changed start-up condition and
  the `mcp-go` major are not patch material.

**Analysed in F-031d, not settled:** the deprecated tag does not fully explain the missing
runtime-digest PR — `static-debian12` did move once more after the pinned digest, and Dependabot
never proposed it. Unproven suspicion: its digest PRs for both base images were closed rather
than merged in August, and it may not propose a digest for the same tag again. Now a check in
F-032.

**Dependencies:** none. Supersedes Dependabot PRs #24 and #17.

#### F-031 as a whole

Forty updates, five substeps (a–e, each with its own entry above), one minor release:
**v0.5.0**. The dependency set is current, the toolchain is Go 1.27, the runtime image is one
that is still maintained, and the stdio backend speaks the current MCP protocol.

**What carried the task was measuring before deciding.** The dry run before planning showed that
one update breaks the build, not three — and that the risk was in behaviour. Each substep then
measured its own: two glob engines side by side over fifteen million comparisons; the protocol
version on both sides of the stdio backend; what the `go` line switches on; records written by
the old WebAuthn library; and, last, the new version on a copy of the live data before the
live switch.

**It found more than it was sent for.** Three faults in the OIDC allow-list, each able to admit
an account the operator never meant to: an over-permissive glob engine, entries dropped instead
of refused, and — the root — OIDC without any allow-list admitting everyone. All three are fixed;
the third on the operator's decision to refuse start-up rather than warn. The live deployment
uses no OIDC and was never exposed to them.

**It left two things to others:** F-033, a dated watch on two frozen OpenTelemetry exporters
compiled in through `ory/x`; and a check in F-032 on whether Dependabot still proposes
base-image digests.

**Two process lessons, both now in the mutation practice:** a mutation run goes through a script
with a verified restore, and a mutation whose anchor is missing aborts the run instead of
reporting "nothing failed".

**Superseded Dependabot PRs:** #24 (rebuilt by Dependabot as the updates landed), #17 (closed by
hand).
