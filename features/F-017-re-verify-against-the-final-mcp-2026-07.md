---
id: F-017
title: Re-verify against the final MCP 2026-07-28 authorization spec
type: feature
status: DONE
size:
created: 2026-08-20
done: 2026-08-21
depends-on:
superseded-by:
---

# F-017 — Re-verify against the final MCP 2026-07-28 authorization spec

## History

### F-017 — Re-verify against the final MCP 2026-07-28 authorization spec — DONE 2026-08-21

Complete (a/b/c/d). The standing watch item, open since F-007e checked the release candidate, is
closed — and deliberately without a successor: the specification will keep moving, and re-checking
it is ordinary maintenance rather than a standing exception.

| Substep | Outcome |
|---|---|
| **F-017a** | mcp-go 0.50 → 0.58 with the stdio backend migrated to `log/slog`; unblocked a red Dependabot PR that turned out to be a real API migration, not a bot error |
| **F-017b** | closed a spoofing path on credential injection — a client could shadow a configured `PROXY_HEADERS` value — plus tests pinning the MCP transport-header pass-through |
| **F-017c** | seven RC caveats became final-spec statements; new `SPEC.md` §4 records conformance requirement by requirement, including one **unmet** MUST |
| **F-017d** | released `v0.2.0`, deployed, verified live — and surfaced F-023, which required `v0.2.1` |

**The authorization surface needed no change.** All six SEPs remained satisfied, and CIMD-first with
a DCR fallback still matches a spec that now formally deprecates DCR. Everything this task actually
fixed lay elsewhere: on the proxy surface (F-017b), in the CIMD resolver (F-023), and in
documentation that claimed conformance without evidence (F-017c).

**What the task is really worth, in hindsight.** A re-check that had only compared the specification
against the code would have concluded "conformant, no action" — and been wrong in two places. The
`PROXY_HEADERS` gap needed reading the code against a *new* spec feature (`Mcp-Param-*`) to become
visible; the CIMD defect needed a live client pushed through a fresh registration, which took
deleting production state. Both were invisible to the test suite, and one of them had been sitting
in the code since F-012a.

**Recorded as unmet rather than glossed over:** `Origin` validation, a MUST since protocol
2025-03-26 that this gateway never implemented and the F-006b audit missed. It sits in `SPEC.md`
§4.2 with a ✘, in the CHANGELOG under "Known limitations", and in `THREAT-MODEL.md`, tracked as
**F-021**.

**Spawned:** F-021 (`Origin`), F-022 (six files past the §2 hard limit), F-023 (done, the CIMD fix),
F-024 (operator client list with a kill switch — the manual store surgery this task required is the
argument for it).

### F-017a — Migrate `mcp-go` to `log/slog` and unblock Dependabot PR #13 — DONE 2026-08-21

First substep of F-017. Dependabot PR #13 ("Bump the go-modules group with 45 updates") was red on
`build-test` and `lint`, and the cause was not a Dependabot error but a real API migration:
`mark3labs/mcp-go` dropped its own `Infof`/`Errorf` logger interface in favour of `log/slog`
between 0.50 and 0.58, and the Streamable-HTTP logger option changed **type** as well as parameter.
Three compiler errors across two call sites, all in `pkg/backend/proxy.go` — the stdio backend is
the only place the gateway drives mcp-go as a library.

**What was done:**

| Before | After |
|---|---|
| `transport.WithCommandLogger(&zapLogger{p.logger})` | `transport.WithCommandLogger(newSlogLogger(p.logger))` |
| `server.WithLogger(&zapLogger{logger})` (a `ServerOption`, rejected by `NewStreamableHTTPServer`) | `server.WithStreamableHTTPLogger(newSlogLogger(logger))` (a `StreamableHTTPOption`) |
| `zapLogger` adapter type + two methods | deleted — dead code (§1) |

The bridge is a single line over a vetted library: `slog.New(zapslog.NewHandler(logger.Core()))`.
Wrapping the **existing** core matters — it keeps the stdio backend's output in the same structured
stream as the rest of the gateway instead of opening a second sink.

**Dependencies:** `go.mod`/`go.sum` were taken from the Dependabot branch verbatim rather than
re-derived, so the local state matches what CI would have tested. Direct bumps:
`mcp-go` 0.50.0 → **0.58.0**, `testify` 1.11.1 → 1.12.1, `bbolt` 1.4.3 → 1.5.0, `gorm` 1.31.1 →
1.31.2, plus 41 indirect. Added `go.uber.org/zap/exp` **v0.3.0** (MIT, by the zap authors).
`go mod tidy` is a no-op afterwards.

**Decision: `go.uber.org/zap/exp` over a hand-written `slog.Handler`.** CODING-STANDARDS §1 prefers
an established pattern over an invented one, and the cost argument that would normally favour
hand-rolling does not apply here: every module `zap/exp` requires (`zap`, `multierr`, `testify`,
`go-spew`, `go-difflib`, `yaml.v3`) is **already in the build at an equal or higher version**, so it
adds no transitive dependency at all. A hand-written handler would have meant owning
`Handle`/`WithAttrs`/`WithGroup` semantics for no gain.

**Decision: mcp-go 0.58.x over v1.0.0-beta.1.** v1.0.0-beta.1 already implements protocol
**2026-07-28** (`server/discover`, `_meta` protocol version, header validation) while 0.58.0 is
still `LATEST_PROTOCOL_VERSION = "2025-11-25"`. Taking the beta would have made the stdio path
spec-current, but CODING-STANDARDS §7 pins stable versions and this is a public auth boundary.
**Consequence, to be documented in F-017c:** the stdio backend speaks 2025-11-25 until mcp-go v1.x
is final. The transparent backend — the documented primary mode — is unaffected, because it
proxies transparently and holds no protocol opinion.

**Tests:** one added, `TestNewSlogLoggerWritesToZap`. The existing `TestSetupProxy` and
`TestProxyBackendRun` do traverse both migrated call sites (the latter against a real subprocess),
but both pass `zap.NewNop()` — a green run there proves type compatibility and nothing more, and
would stay green if the bridge were wired to a discarding core. The new test asserts through
`zaptest/observer` that the record, its level and its slog attributes actually reach the zap core.
**Verified non-vacuous:** repointing the bridge at `zapcore.NewNopCore()` turned it red
(`expected: 1, actual: 0`), and restoring it turned it green again.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages,
0 FAIL; `govulncheck` **0 reachable** (one module-level finding remains, `GO-2026-5932`
`x/crypto/openpgp` — unmaintained, not called, pre-existing); `go-licenses v2.0.1 check
--disallowed_types=forbidden,restricted` rc=0; `golangci-lint v2.12.2` **0 issues**;
`actionlint v1.7.12` rc=0; gitleaks over the working tree: no leaks. All **five** CI jobs were
replicated locally rather than deferred to CI — including `image-build`, which built the amd64
image, ran `--version`, and polled the container's own `HEALTHCHECK` to `healthy` (the F-018 job,
exercised here against a 45-module bump for exactly the reason it was written).

**PR #13 stays open and red on GitHub.** What landed here is the "equivalent commit" the acceptance
criterion allows; Dependabot normally closes the PR itself once the versions reach the default
branch — worth confirming after the push rather than assuming.

**Files:** `pkg/backend/proxy.go`, `pkg/backend/proxy_test.go`, `go.mod`, `go.sum`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No behaviour, config, endpoint or signature change on the
authorization surface.

### F-017b — Transport conformance: prove header pass-through, harden credential injection — DONE 2026-08-21

Second substep of F-017. Two halves: pin the pass-through confirmations down with tests, and close
the one real defect the final-spec re-check turned up.

**The defect (finding 3 of the re-check).** `pkg/proxy/proxy.go` attached each configured
`PROXY_HEADERS` entry with `Header.Add` and, unlike the `HEADER_MAPPING` loop two lines above it,
never deleted an inbound copy first. Appended values keep their order, so a client sending the same
header name landed **in front of** the injected one — and an upstream reading `Header.Get`, which
returns the first value, would read the client's instead of the configured upstream credential
(FR-6, SR-7). Only `Authorization` was special-cased.

The fix is one line, `c.Request.Header.Del(key)` before the add. It replaces the
`strings.EqualFold(key, "Authorization")` branch rather than joining it, because the generic delete
subsumes that case entirely — so closing the gap made the function **shorter**, not longer.

**Why this surfaced now, when the code is unchanged since the fork.** The gap was always reachable
in principle — HTTP clients have always been able to set arbitrary headers. What changed is that
MCP 2026-07-28 makes client-set headers *routine*: SEP-2243 mirrors annotated tool parameters into
`Mcp-Param-{Name}` headers and obliges intermediaries to forward the ones they do not recognise.
A latent gap became one that normal, spec-conformant traffic walks past.

**Tests, and why they assert what they do:**

| Test | File | Guards |
|---|---|---|
| `TestProxyRouter_ProxyHeadersStripClientHeaders` | `pkg/proxy/transport_test.go` | four cases: single-value shadowing, multi-value replacement, `Authorization` via `PROXY_HEADERS`, and **unconfigured headers passing through untouched** |
| `TestProxyRouter_ProxiesServerDiscover` | `pkg/proxy/transport_test.go` | the new `server/discover` RPC reaches the upstream with body and `Mcp-Method` intact |
| `TestTransparentBackendForwardsMCPTransportHeaders` | `pkg/backend/transparent_test.go` | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` arrive unchanged and exactly once, Base64-sentinel value included |

The security assertions compare the **full value slice**, never `Header.Get`. `Get` returns the
first value and would have reported `"upstream-secret"` just the same while the attacker's copy sat
behind it — it cannot tell a fixed gateway from a broken one. The fourth case exists so the strip
stays limited to configured names: an over-broad delete would eat the very transport headers the
gateway is required to forward.

**Both verified non-vacuous**, which is what makes them worth having:
- Reverting the fix turned the security test red with `actual: ["attacker-supplied",
  "upstream-secret"]` — the client's value first, exactly the ordering the vulnerability depends on.
- Deleting `Mcp-Method` inside the transparent backend's `Rewrite` turned the pass-through test red
  with `actual: []string(nil)`.

**No production change in `pkg/backend/transparent.go`.** Nothing was broken there: `ReverseProxy`
clones the inbound request and this backend rewrites only `X-Forwarded-*`. That is a property of
the current implementation rather than a guarantee, so the test records it — the confirmation the
intake asked for, in a form that cannot silently expire.

**`server/discover` cannot collide with the reserved-namespace guard**, confirmed by reading and now
by test: the guard matches URL *path* prefixes (`/.idp/`, `/.auth/`, `/.well-known/`) while
`server/discover` is a JSON-RPC method in the request *body*. The test exists against a future guard
rewritten in terms of method names.

**Deviation from the plan, found during review.** The plan put the new tests in
`pkg/proxy/proxy_test.go`. That file was already **1035 lines**, twice the 500-line hard limit in
CODING-STANDARDS §2, and the addition would have pushed it to 1180 — making a pre-existing violation
worse. The tests went into a new `pkg/proxy/transport_test.go` (163 lines) instead, and
`proxy_test.go` is left **byte-identical to HEAD**. Splitting the 1035-line file is real work of the
F-020 kind and is **reported as open**, not silently carried: it needs its own F-number.

**Files:** `pkg/proxy/proxy.go` (one line + comment), new `pkg/proxy/transport_test.go`,
`pkg/backend/transparent_test.go` (+54), `SPEC.md` (§1.11.4 now states the strip for both
mechanisms, plus an F-017b delta line); docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No config,
endpoint or signature change.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues; gitleaks no leaks. **Behaviour change worth an upgrade note:** a
deployment that (unwisely) relied on clients supplying a header also listed in `PROXY_HEADERS` will
see that client value dropped from now on.

### F-017c — Documentation sweep and conformance record — DONE 2026-08-21

Third substep of F-017. The sweep itself was mechanical; the part worth keeping is what replaced
the prose.

**Seven live "release candidate" caveats became statements about the final revision** — `README.md`
(status blurb), `REQUIREMENTS.md` §0 (the watch item), the `SPEC.md` header, `THREAT-MODEL.md`,
`CLAUDE.md`, the `PROGRESS.md` state line, and the `docs/VERIFICATION.md` close-out. What remains
is either inside F-017's own task text (archived with this entry) or explicitly historical, in the
v0.1.0 CHANGELOG entry.

**The watch item was closed, not re-dated.** REQUIREMENTS §0 now records that the final spec
published, that the authorization surface needed no change, and — deliberately — that there is **no
successor watch item**: the specification will keep moving, and re-checking it is ordinary
maintenance rather than a standing exception. A watch item that renews itself forever is a reminder
nobody reads.

**New `SPEC.md` §4 — the conformance record.** Three tables replacing the claim "we are conformant"
with something a reader can walk:

- **§4.1 Authorization**, 16 requirement rows. Every server-side MUST and SHOULD of the
  authorization spec, each with its status and the section that implements it. Client-side
  obligations are omitted with the reason stated: the gateway is an AS and a resource server,
  never an MCP client.
- **§4.2 Streamable HTTP**, 10 rows, each attributed to **gateway** or **upstream**. The
  attribution is the point: "the upstream owns it" is only an answer while the gateway provably
  forwards enough for the upstream to comply — which F-017b's tests now assert.
- **§4.3 Recorded limitations**, the two deliberate gaps: the scope-less design behind the two
  "not applicable" rows, and the stdio backend's 2025-11-25 ceiling from F-017a.

**§4.2 carries a ✘.** `Origin` validation is a MUST the gateway does not satisfy — unchanged since
protocol 2025-03-26 and missed by the F-006b audit. The table records it as unmet with its
mitigation (bearer-protected `/mcp`, CSRF plus `SameSite=Lax` on `/.auth/*`, loopback the exposed
case) and points at F-021, rather than quietly omitting the row. The same limitation appears in
`CHANGELOG.md` under "Known limitations" and in `THREAT-MODEL.md`, so a reader meets it wherever
they look.

**Two normative rows were missing on the first pass** and were caught by self-auditing §4.1 against
the specification instead of trusting the draft: the error-status table (401/403/400, MUST) and
scope-hierarchy handling (MUST). Without them the acceptance criterion "covers every MUST and
SHOULD" would have been ticked while being false — the exact failure mode a conformance table is
supposed to prevent.

**`CHANGELOG.md` v0.2.0**, with Added / Security / Changed / Known limitations / Upgrade notes. The
upgrade note names the F-017b behaviour change: a deployment relying on *clients* supplying a header
also listed in `PROXY_HEADERS` now sees that value dropped. Intended setups get stricter and are
otherwise unaffected. Recorded as **minor, not patch**, because F-015, F-016 and F-017b each change
behaviour rather than only repairing a defect.

**Deliberate decision to revisit in F-017d:** `## [Unreleased]` was renamed to `## [0.2.0] —
2026-08-21` here rather than at tag time, so the acceptance criterion could be met. If the tag slips
past that date, F-017d must correct it.

**Verification:** all relative links in the changed files resolve; every `SPEC.md` section
referenced from §4 exists; the §4 tables are column-consistent (5 and 6); gitleaks clean; GR-5 scan
found no paths, IPs, e-mail addresses or hostnames. No Go file was touched, so the suite was not
re-run — `git status` showing no `.go` entry is the evidence.

**Files:** `README.md`, `REQUIREMENTS.md`, `SPEC.md` (+62, new §4), `THREAT-MODEL.md`, `CLAUDE.md`,
`PROGRESS.md`, `docs/VERIFICATION.md`, `CHANGELOG.md`; plus `PROGRESS-ARCHIVE.md`. No code, config
or behaviour change.

### F-017d — Live verification and release — DONE 2026-08-21

Fourth substep of F-017, and the one that justified the whole task: it found a defect that no test
and no amount of reading would have caught.

**Two releases, not one.** `v0.2.0` shipped F-014/F-015/F-016/F-017a–c. The live verification then
broke, and `v0.2.1` shipped the fix (F-023) forty minutes later.

**Phase 0 — publish.** Tag `v0.2.0` → `release.yml` → multi-arch GHCR image, verified the way any
user would get it: logged out of ghcr.io, anonymous pull, `--version` → `v0.2.0`, amd64 + arm64,
tags `0.2.0` and `0.2` present, `latest` correctly absent, GitHub release published.

**Phase 1–2 — deploy.** A fresh `data/` backup first (the newest on the host was six weeks old and
predated the 0.1.1 switch), compose image tag bumped, `down && up -d` → healthy in ~8 s. Total
downtime seconds.

**Phase 3 — server-side, all green.** Discovery, JWKS, `/healthz` 200; **JWKS `kid` unchanged**, so
signing keys survived and issued tokens stayed valid; PRM self-consistent; `POST /mcp` without a
token → 401 with the bare `WWW-Authenticate` challenge; garbage bearer → `401 invalid_token`;
reserved namespaces not proxied. And the one that mattered: **`client_id_metadata_document_supported`
was absent before the switch and `true` after** — F-015 demonstrated in the field rather than in a
commit.

**The correction that made this substep honest.** The plan assumed the deployment ran `0.1.0` and
warned at length about crossing v0.1.1's breaking changes (encrypted session cookie, resident-passkey
requirement) with the password fallback disabled. The operator said otherwise and the host confirmed
it: **`0.1.1` was live**, so those changes had shipped weeks earlier and carried no risk at all. The
cause was drift — `private/mcp-gateway/docker-compose.yml` still pinned `0.1.0` because the 0.1.1
deployment was never mirrored back. Assumption replaced by an SSH-verified inventory; the local copy
is now a verbatim mirror and the plan says to re-sync after every deployment.

**Phase 3, client side — where it went wrong, and why that was worth it.** Claude web, iOS and
passkey login all worked immediately. But the acceptance criterion asked for proof that clients now
pick **CIMD**, and getting it defeated three approaches in a row:

1. A second connector on the same URL — Claude refuses; it de-duplicates by URL.
2. Removing and re-adding the connector — **no OAuth flow at all**. MCP traffic arrived, but no
   `register`, no `token_issued`, no `login_ok`: Claude kept its stored credentials for that URL.
3. Waiting for `DCR_CLIENT_TTL` — never fires, because the registration is refreshed on every token
   issuance (SPEC §2.1), so one in active use never expires.

The log did establish the starting point: web and iOS both issued tokens against **one** opaque DCR
client id, registered before the switch under metadata that never advertised CIMD.

With operator approval, the active DCR record was deleted from the store (second backup first;
gateway stopped for the bbolt lock; a purpose-built helper printing key names and sizes only, never
record contents). Inventory **before: 2 client records** — the store *had* been growing, which is
itself the evidence F-019 wanted — **after: 1**, the older orphan left in place so a new DCR record
would be unmistakable. Deleting the client does not invalidate live tokens (revocation checks the
token record), so the access and refresh records went too: **58 refresh-token records** for that one
client, a rotation history nobody had looked at before.

**Then Claude switched to CIMD and the gateway refused it** —
`invalid CIMD client ID: unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"`.
That became **F-023** and `v0.2.1`. After deploying it:

```
20:22:41  login_ok
20:22:57  token_issued   client_id = https://claude.ai/oauth/mcp-oauth-client-metadata
```

A URL, so CIMD; **zero `register` events**, so no DCR registration was created; and the operator
confirmed tool calls against the upstream succeed. F-015, F-023 and F-019's evidence, all settled at
once.

**The lesson, written into `docs/VERIFICATION.md` rather than left in a chat.** The runbook gained
"Force a fresh client registration": the three routes that do not work, the one that does, and the
reason it matters — *a verification that only exercises an already-connected client passes even
while the gateway is broken for every new one.* That is precisely what happened here, and it is the
part most likely to be repeated wrongly next time.

**Files:** `docs/VERIFICATION.md` (final-spec checkbox ticked with the §4 walk recorded, plus the
new section); evidence and the full run log in `private/UPDATE-PLAN-v0.2.0.md` (gitignored). Host
cleanup: the one-off helper removed, and the v0.1.0-era leftovers (35 MB cross-compiled binary,
`Dockerfile`, stale compose backup, superseded `0.1.0` image) deleted afterwards at the operator's
request.

**Left open on purpose:** Dependabot `#9` and `#6` — the latter bumps `action-gh-release`, the step
that publishes releases, so it was held back until after both tags landed.
