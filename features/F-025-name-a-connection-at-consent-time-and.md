---
id: F-025
title: Name a connection at consent time, and show the client's own name
type: feature
status: DONE
size:
created: 2026-08-22
done: 2026-08-23
depends-on:
superseded-by:
---

# F-025 — Name a connection at consent time, and show the client's own name

## History

### F-025a — The label, end to end — DONE 2026-08-23

First substep of F-025. A connection can now be given a name at consent time; the name is stored
with the authorization, shown wherever that authorization appears, and deleted with it.

#### What was done

The name rides the gateway's **own session type** (`pkg/idp/session.go`), which fosite already
persists as `SessionData` with every record of the grant. That location decides three properties at
once, which is why it was chosen over the request `Form` the first sketch proposed: the session is
**server-built**, so no client can plant a label; it is written with every token record, so the name
travels; and it is deleted with those records, so there is **no cleanup path to forget**.
`models.Request` gains a `Label` lifted out of the session through a new `models.Labeled` interface,
so the repository and F-024's client list read it directly instead of decoding session JSON.

The consent page gains an optional text field. Its value is sanitized **once, where it enters**:
control characters dropped, trimmed, capped at 64 runes. One write point means one place to get it
right — and the log needs it as much as the page does, because `html/template` escaping does not
reach a structured log field. The list shows the name as the row's primary identifier with the
client id beneath it, and both `token_issued` and `revoked` carry it, so the auth log reads in the
operator's words.

#### The mutations found two of my own test defects

The suite was green, and **two of its assertions did not test what they claimed.**

**First: the acceptance criterion itself was wrong.** It read "the label survives the token exchange
and every refresh — `Session.Clone` copies it, and the test goes red when that one line is removed."
Removing the line left everything green. The reason is worth recording, because it contradicts the
plan's mental model: at the authorize→token exchange the session is restored **from its stored
JSON**, so `Clone` is not on that path at all. `Clone` carries the name only on the **refresh**
grant, where fosite clones the loaded session in memory and persists the clone. The code comment
now states that, measured rather than assumed.

**Second: the refresh test could not see the difference.** It read the name through
`ListClientGrants`, which aggregates every record of a grant — so the *first* token's record, which
still had the name, answered for the refreshed one that had lost it. Both tests now look up the
record of **that specific token** by its signature. With that fix the mutation behaves correctly:
dropping the `Clone` line leaves the token exchange green and turns the refresh red.

A third assertion had the same shape: "the name identifies the row" was checked with a loose
`Contains`, which also matched the name in the per-authorization table below. Removing the row's
rendering left it green. It now asserts the row's own markup and fails as it should.

**Four mutations in total, each red after the fixes:** the `Clone` line, the label lift in
`models.FromFositeReq`, the row rendering in the template, and the `label` field on the `revoked`
event.

#### Decisions and deviations

- **The label is set after `NewJWTSession`, not passed to it.** The constructor already takes four
  parameters where §3 allows three; the value comes from the consent form, so the assignment belongs
  at the call site rather than in a fifth parameter.
- **`logRevoke` now takes a `revokeEvent` struct** instead of four parameters — the label would have
  been a fifth. This removes a §3 violation that existed before this substep rather than growing it.
- **`handleToken` was already past the 50-line limit** and would have grown to 59; the event context
  moved into `tokenIssuedFields`, leaving the handler shorter than it was.
- The label is deliberately **not a JWT claim**: only `JWTClaims` reaches the token, and the
  operator's private note about a connection has no business travelling to the client.

#### Verification

- 22 passing (sub)tests across `pkg/idp`, `pkg/repository` and `pkg/auth`, covering the flow, both
  storage backends and the rendered page.
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**. No dependency change.

**Noted for F-025b, not fixed here:** `pkg/auth/clients_test.go` reached 426 lines (§2 target 300,
hard limit 500) and F-025b adds prefill tests to it — the split belongs there.
`handleAuthorizationReturn` is at 71 lines, inside §3's orchestration exception, and the plan
already earmarks its split for F-025b.

**Files:** `pkg/idp/session.go`, `pkg/idp/consent.go`, `pkg/idp/token.go`, `pkg/models/models.go`,
`pkg/repository/inventory.go`, `pkg/auth/clients.go`, `pkg/auth/templates/settings.html`; new
`pkg/idp/label_test.go`; extended `pkg/repository/inventory_test.go`, `pkg/auth/clients_test.go`;
docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new endpoint, config, dependency or schema change.

### F-025b — The prefill, and the documentation — DONE 2026-08-23

Second and final substep of F-025. The consent field is now prefilled with the name the client
declares about itself, which also closes the `SPEC.md` §1.5 client-identity requirement that had
been unmet since F-004 wrote it.

#### What was done

- **DCR:** `models.Client` gained `Name`, and `RegisterClient` now takes a `ClientRegistration`
  struct instead of four positional parameters — the fifth would have pushed it further past the
  three §3 allows, so the fix **removes** a violation rather than growing it. Seven call sites
  updated.
- **CIMD:** `IDPRouter` keeps the resolver it already hands to fosite, so the consent page reads the
  document's `client_name` through the **same** resolver — and therefore from the same cache.
- **New repository method `GetClientName`**, which the plan did not anticipate but the code
  demanded: fosite's client type has nowhere to carry a name, so `GetClient` can never return one.
  Kept deliberately narrow rather than a `GetClientRecord`, which would have handed callers the
  hashed client secret.
- Documentation: `SPEC.md` §1.5 (the requirement, now recorded as satisfied, plus the naming
  contract), §1.12 (rows identified by the operator's name), §2.1 (`client_name` is stored since
  this substep; the operator's own name rides the session and is no entity); `README.md`;
  `CHANGELOG.md` under `[Unreleased]`.

#### The review caught a defect the tests could not

`step-done`'s file-by-file review found that **the SQL backend never stored the name**: the bbolt
implementation set `client.Name`, the SQLite one did not. Neither the suite nor the live
verification could have caught it —

- the `pkg/idp` prefill test drives a test server that is **always bbolt** (`setupTestServerWith`),
  so the DCR prefill was only ever exercised on one backend;
- the deployment runs bbolt too (no `REPOSITORY_BACKEND` set), so the live check passed for the
  same reason rather than despite it.

A SQLite deployment would have shown an empty prefill for every DCR client, silently. Fixed, and
covered by `TestClientNameRoundTrip` plus the unknown- and expired-registration cases, all running
against **both** backends through `testRepos`. Verified by re-removing the fixed line: the `sql`
subtest goes red, `kvs` stays green — which is precisely the shape the defect had.

The general lesson, and the reason it is recorded here rather than only fixed: **a contract that
both backends implement needs a test that runs against both.** The two-backend helper existed; the
new method simply had no test using it.

#### The cache criterion, split honestly

The acceptance criterion read "resolving the CIMD name issues no additional outbound request". That
cannot be proven end to end at the `pkg/idp` layer: the real resolver's SSRF guard blocks a test
server, and the hook that works around it is package-internal to `pkg/cimd`. So the claim was split
into the two halves that *can* be proven, and both are:

- `TestConsentUsesTheConfiguredCIMDResolver` shows the consent page goes through the resolver the
  router was configured with — not a second one, not a direct fetch. Measured: **two consultations**
  per authorization, one from fosite's client lookup and one from the render.
- `pkg/cimd`'s existing `TestResolverHappyPathAndCache` shows that resolver serves a repeat
  resolution from cache without fetching.

Together: one document fetch per authorization. Recorded as two halves rather than asserted as one.

#### Live verification

Deployed to the running gateway and exercised with the operator's real Claude connector. The
prefill arrived as **"Claude"** — the `client_name` in Claude's published CIMD document, which no
local test could have known, since the tests supply their own stub. The operator overrode it with
their own wording, and the log then read
`token_issued client_id=https://claude.ai/oauth/… label=claude.ai`. The omit-when-empty branch
verified itself in the same run: the `revoked` event for the *older* grant, authorized before this
feature existed, carried no label field at all.

#### Cleanups this substep carried, both noted by F-025a

- `handleAuthorizationReturn` (71 lines) split into `approvedSession` and `grantRequested`; the
  latter now carries a statement that had been implicit — approval is all-or-nothing, not scope by
  scope (SPEC §1.5). The handler is at 48 lines.
- `pkg/auth/clients_test.go` (429 lines) split along its section rules into 230 + 220
  (`clients_revoke_test.go`). Verified as a pure move the way F-020 established: **19 declarations
  before, 19 after**, nothing lost — a green suite proves nothing about a move.

**Files:** `pkg/idp/idp.go`, `pkg/idp/consent.go`, `pkg/idp/register.go`, `pkg/models/models.go`,
`pkg/repository/interface.go`, `kvs.go`, `sql.go`; new `pkg/idp/prefill_test.go`,
`pkg/auth/clients_revoke_test.go`; tests in `pkg/repository/inventory_test.go`, `cap_test.go`,
`maintenance_test.go`, `pkg/auth/clients_test.go`; docs `SPEC.md`, `README.md`, `CHANGELOG.md`,
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new endpoint, config or dependency; no schema change.

### F-025 — Name a connection at consent time, and show the client's own name — DONE 2026-08-23

**Problem:** Three different names meet on this surface and are easy to confuse, so this entry names
them first: the **`client_id`** is fixed and verifiable (a URL for CIMD, a random string for DCR);
the **`client_name`** is what the client declares about *itself*; and there is **no third name** —
nowhere for the operator to write down what a connection actually is. F-024's list therefore
identifies a connection by its `client_id`, which for a DCR client is unreadable. Separately and
pre-existing: both mechanisms **parse** `client_name` and both throw it away — `registrationRequest`
in `pkg/idp/register.go` echoes it back and never stores it, `cimd.Client` never reads it — although
`SPEC.md` §1.5 says the consent page MUST show it. That is a literal gap in the gateway's own
contract; it sits outside the §4 conformance table, which tracks the MCP spec rather than our own.

**Idea:** Add **one field**. At consent time — the moment the operator is already looking at the
connection they started — a text box takes a short name, prefilled with the client's declared name
where there is one. It is stored with the authorization and shown wherever that authorization
appears. Everything already on the consent page stays exactly as it is.

**Solution (decided at `/prep-step`, 2026-08-23 — this replaces the intake sketch):**
- The label lives on the gateway's **own session type** (`pkg/idp/session.go`), which is already
  persisted as `SessionData` with every token record and deleted with the grant. **No new entity,
  no new table, no schema change** — and it is deliberately *not* the request `Form`, which is
  filled from the client's query parameters and would let a client plant its own label.
- `models.Request` gains a `Label` field, filled in `FromFositeReq`, so F-024's list and the
  repository layer read it directly instead of decoding session JSON.
- Prefill: CIMD through the resolver (cached, no extra outbound request), DCR from the
  `client_name` the registration already parses but has never stored.
- **Presentation stays plain** — a normal prefilled field, no claim marking. Operator decision, and
  it holds: the flow is operator-initiated and login-gated, the verified `client_id`, redirect URI
  and scopes stay visible below, and the page already warns to approve only self-started requests.
  The prefill only matters on a first connection; after that the field holds the operator's own text.
- The label travels into the auth events, so the log reads in the operator's words.
- **Renaming later is out of scope**: re-authorizing asks again, and the field is right there.

**Dependencies:** F-024 (done) — its list is where the name pays off.

#### Complete (a/b)

A connection can be given a name where the operator is already looking at it, and that name follows
the authorization everywhere it appears — the client list, the auth log — and is deleted with it.

**The design came out of the operator's own pushback.** The first plan was three substeps with a new
entity keyed by client id, renaming in the list, and a claim-marked presentation of the client's
declared name. The operator asked why it was that complicated, and the question was fair: their
framing — "a new data field, not a new storage structure" — pointed at a place the plan had missed.
The name rides the gateway's **own session**, which fosite already persists with every record of a
grant. That single choice settled three properties at once: server-built, so no client can plant a
label; written with every token record, so it travels; deleted with those records, so no cleanup
path exists. Two of the three substeps fell away with it, and the renaming UI was never needed —
re-authorizing asks again.

**Presentation stayed plain**, also the operator's call, and the reasoning holds: the flow is
operator-initiated and login-gated, the verified client id and redirect URI stay visible beneath,
and the page already warns to approve only self-started requests. The prefill only matters on a
first connection; afterwards the field holds the operator's own words.

**It closed a spec violation nobody had noticed.** `SPEC.md` §1.5 required consent to show the
client's declared name; both registration mechanisms parsed `client_name` and discarded it, so the
page had shown the bare client id since F-004. The gap surfaced only because this task went looking
at the same code — and it prompted **F-026**, since the reason it stayed hidden is that §1.12 and
§1.5 read as changelogs rather than contracts.

**Three defects found, none by the suite being red.**

| Found by | What |
|---|---|
| Mutation (F-025a) | The acceptance criterion was wrong: `Session.Clone` does **not** carry the label through the token exchange — the session is restored from stored JSON there. `Clone` matters only on **refresh**. |
| Mutation (F-025a) | Two assertions could never fail: one read an aggregate where a specific record was meant, one used a loose `Contains` that matched elsewhere on the page. |
| Review (F-025b) | The **SQL backend never stored the declared name**. Invisible to both the suite (the idp tests are bbolt-only) and the live check (the deployment is bbolt too). |

The first two are now rules in `CODING-STANDARDS.md` §9 and §11; the third has its two-backend
contract test.

**Live-verified** with the real Claude connector: the prefill arrived as **"Claude"** from Claude's
published CIMD document, the operator's override reached the store, the list and the
`token_issued` event, and the older unnamed grant's `revoked` event correctly carried no label.
