---
id: F-024
title: Operator view of connected clients, with a kill switch
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-23
depends-on:
superseded-by:
---

# F-024 — Operator view of connected clients, with a kill switch

## History

### F-024a — Enumerate and revoke in the repository layer — DONE 2026-08-22

First substep of F-024. The repository layer had **no enumeration at all** — no `List`, no `All`, on
either backend — which is why deleting a single client record in F-017d needed a purpose-built bbolt
tool. It now has `InventoryStorage`, implemented for bbolt and SQLite, with no UI attached.

#### What was done

| Method | Purpose |
|---|---|
| `ListClientGrants` | One row per client: origin, registration state and expiry, redirect URIs, scope union, per-grant breakdown, access/refresh record counts, first and last activity — newest activity first |
| `RevokeClient` | Every record of one client, registration included |
| `RevokeGrant` | One authorization, client and registration untouched |
| `RevokeAll` | The panic button, in one transaction |

**The listing is built from token records, not client records.** That is the finding the whole task
turns on and it survived contact with the code: since v0.3.0 Claude connects via CIMD, and a CIMD
client has **no stored registration** — `clientSource.lookupClient` re-resolves it from its URL on
every lookup. Enumerating `client-*` would have listed precisely the clients the operator cares
about least. Rows are therefore grouped from `access_token-*` / `refresh_token-*` by the client
snapshot each record carries, with stored registrations joined as a second source so a registration
without tokens still shows. `TestListClientGrantsFindsCIMDClientWithoutRegistration` is the guard.

**One aggregator, two backends.** `inventory.go` holds the grouping logic and both backends feed it:
bbolt walks key prefixes, SQL decodes request blobs. The two listings cannot drift apart, because
there is only one of them.

**Recognisability needed no new field**, as the prep predicted: a CIMD client's ID is its URL, and
every token record carries a client snapshot with the redirect URIs, so a DCR client with a random
ID is still identifiable. A stored registration outranks the snapshot — it is the live record.

#### Decisions and deviations from the plan

- **`RevokeAll` added** — a fourth method where the plan named three. The approved panic button
  looped over `RevokeClient` would be N transactions, and a failure in the middle would leave
  clients with access while the UI reported a kill. One transaction per backend instead.
- **bbolt does not reuse `deleteMatching`**, which the plan assumed it would: that helper sweeps one
  prefix per transaction and returns no count, while the kill needs five prefixes plus the
  registration in **one**. New `staleRecords` + `revoke`; `deleteMatching` stays untouched for the
  RFC 7009 path it was written for.
- **SQL deletes uniformly by primary key**, not over the indexed `request_id` as the plan sketched.
  `RevokeClient` has to decode the request blobs regardless — no column holds the client — so a
  second, index-based path for two of the five tables would be a second chance to disagree. The
  index still serves fosite's own revocation.
- **An unreadable record is an error, not a skip.** This departs from the sweeper's precedent
  (`kvs.go`: "undecodable records are reclaimed by the sweeper, not revocation") and does so
  deliberately: for a kill switch, skipping a record means reporting a revoke that did not happen,
  and for the listing it means hiding a client that holds access. Both now fail loudly, and the
  transaction rolls back whole.
- **No schema change.** `SchemaVersion` stays 1 and a downgrade stays possible; SQL filters in Go
  rather than gaining an indexed `client_id` column, which is affordable because the tables are
  bounded by the DCR cap and the token TTLs.
- **The panic button spares the operator.** `RevokeAll` sweeps clients only — the user record, the
  passkeys and the schema marker survive. Answering a compromise by locking out the only person who
  can respond to it would be the wrong reflex, so a test guards it.

#### Verification

- **30 subtests green** — 15 tests against both backends through the existing `testRepos` helper.
- **The green suite was not taken on trust.** Two deliberate mutations: dropping the
  authorization-code sweep from the revoke turned `TestRevokeClientRemovesEveryRecordKindAndSparesOthers`
  red on **both** backends, and making an undecodable record a skip instead of an error turned both
  fail-closed tests red. Restored, green again.
- Rotation history aggregates: **58 refresh records → one row, one grant** (the number F-017d found
  in the field).
- Revoking one client leaves another's records untouched, asserted **per record kind** rather than
  on tokens alone.
- `TestInventoryNeedsNoMigration` writes, closes and reopens each store, then lists — proof that a
  store written before this change needs no migration.
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**; `govulncheck` 0 vulnerabilities. No dependency change
  (`go.mod`/`go.sum` untouched), so licensing is unaffected.

**Standards work done alongside:** three functions came in over the §3 hard limit of 50 lines (55,
63 and 45) and were split into named helpers rather than parked under the ~80-line orchestration
exception; the longest is now 42. The test file crossed the §2 300-line target at 470 and was split
along its own section rules into `inventory_test.go` (listing, 249) and `inventory_revoke_test.go`
(revocation, 235) — F-022 should not inherit a fresh violation from the task queued ahead of it. Two
**pre-existing** §11 gaps in the file being edited were closed at the same time: `Repository` and
`AuthorizeRequestStorage` had no doc comment.

**Noted for F-022, not fixed here:** the bbolt key prefixes now exist as constants in
`kvs_inventory.go` while `kvs.go` still builds its keys from the same literals. Consolidating them
means editing `kvs.go`, which F-022 will split anyway.

**Files:** `pkg/repository/interface.go` (extended); new `pkg/repository/inventory.go`,
`kvs_inventory.go`, `sql_inventory.go`, `inventory_test.go`, `inventory_revoke_test.go`; docs
`PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No config, endpoint, dependency or schema change; no UI —
nothing calls the new methods yet, which is F-024b.

### F-024b — The settings surface and its wiring — DONE 2026-08-23

Second substep of F-024. `/.auth/settings` gained a **Connected clients** section: who holds
access, what they hold, and the actions that take it away — per client, per authorization, and the
panic button for everything at once. It sits behind the page's existing gates (`RequireAuth` +
`RequireCSRF` + `requireOwnUser`) and follows the "delete passkey" POST as the working template for
a destructive per-row action.

#### What was done

- **`pkg/auth/clients.go`** — the view model and three handlers. `clientView` is a projection *by
  construction*: the stored records carry the client's hashed secret and the type has nowhere to put
  it, so no later template change can leak one. Redirect URIs are reduced to their distinct hosts —
  the recognisable part for a DCR client, whose ID is random — and a URI that does not parse
  contributes nothing rather than being rendered raw.
- **The template** shows one row per client (identity, CIMD or registration, redirect hosts,
  registration expiry, counts, last activity) with the authorizations behind a `<details>`. The
  wording says what an entry actually is: **per client and per authorization, not per device**, and
  a revoke ends access without banning the client.
- **Auth events (SR-8):** every revoke logs `revoked` with actor, scope, record count and client IP —
  an operator kill is now visible in the log beside the client-initiated RFC 7009 revocations that
  share the event name. Only non-secret context travels.
- **Wiring:** one line in `pkg/mcp-proxy/main.go`.

#### The mutation that mattered

The suite was green on the first run, and one of its security tests was green **for the wrong
reason**. Removing `requireOwnUser` from the client-revoke handler left
`TestSettingsRevokeRejectsForeignSession` passing: the test used a bare `&http.Client{}`, which
*follows redirects*, so the handler's `302` was chased to the settings page — and that page's own
`403` satisfied the assertion. The test could never have failed when the gate it names was deleted.
Fixed by using the non-following client the package already has; the mutation then turns it red as
it should. The pattern came from the existing `TestSettingsRejectForeignSession`, where it is
harmless because the WebAuthn endpoint answers `403` directly instead of redirecting.

Two further mutations behaved correctly: dropping `RequireCSRF` from the revoke route turned the
CSRF test red, and swallowing the enumeration error turned the fail-closed test red.

#### Decisions and deviations from the plan

- **`Config.Clients` is required when `Users` is set**, not optional with a nil check. A nil check
  in the handler would have been exactly the second visibility rule the acceptance criterion rules
  out; requiring it removes the nil case, mirrors the `ExternalURL` contract already documented in
  the same struct, and fails at construction rather than at the operator's first visit (§7). Cost:
  five construction sites updated — one production, four test files.
- **`pkg/auth/settings.go` was touched** although the plan did not list it: `handleSettings` renders
  the page, so that is where the list has to be loaded. `credentialViews` was extracted while there
  to keep the handler under the §3 limit (47 lines).
- **The confirmation is a server-rendered two-step** (`?confirm=revoke_all` renders a panel that
  carries the POST), not a JavaScript dialog — it works without JS and is genuinely two deliberate
  actions. The code records what it is: a guard against a slip, **not** against an attacker. The
  CSRF token and the session are what make the POST authentic; a direct POST by the logged-in
  operator still works, and that is the correct boundary.
- **The panic button only appears when something can be revoked**, and its panel states that the
  operator's own login, passkeys and settings are untouched and that no client is banned.
- **An unknown client ID answers exactly like a successful revoke** — same status, same `Location`.
  The operator's own page gains nothing from an existence oracle, and a typo should not read
  differently from a kill.

#### Verification

- 15 tests in `pkg/auth` covering the surface, including every negative case the plan demanded:
  missing and wrong CSRF token (403, **and the record survives**), an OIDC-provider session on all
  three endpoints, and the unknown-client oracle check.
- The no-secret assertion was made non-vacuous: the test first proves the **store** holds the secret
  (a token record keeps a full client snapshot), then proves the rendered body does not.
- The fail-closed test asserts `500`, the absence of "No client currently holds access", **and** that
  the cause stays in the log rather than reaching the page (§6).
- `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
  `golangci-lint` 2.12.2 **0 issues**. No dependency change.

**Recorded rather than glossed over:** `pkg/auth/auth.go` grew by 24 lines to **558**, past the §2
hard limit it was already over before this change — the config field and the routes belong there,
and F-022 owns the split. `clients_test.go` sits at 347, over the 300 target and under the hard
limit, with section rules. And a doc comment on `handleSettings` that no longer described the page
was corrected.

**What this substep does *not* prove:** that the surface is reachable in the running binary. The e2e
harness builds its own gin router, so route registration and middleware in `pkg/mcp-proxy/main.go`
go unexercised — the same blind spot F-021 ran into. Only inspection backs it here
(`authRouter.SetupRoutes` is called, `Clients: repo` is set). F-024c supplies the proof.

**Files:** new `pkg/auth/clients.go`, `pkg/auth/clients_test.go`; changed `pkg/auth/auth.go`,
`pkg/auth/settings.go`, `pkg/auth/templates/settings.html`, `pkg/mcp-proxy/main.go`, and the four
construction sites in `e2e_harness_test.go`, `pkg/auth/abuse_test.go`,
`pkg/auth/hardening_test.go`, `pkg/auth/webauthn_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. Three new endpoints under `/.auth/settings/clients/`; no new config, no new
dependency, no schema change. `SPEC.md` and `README.md` are deliberately untouched — documentation
is F-024c.

### F-024c — Verify against the running binary, then document — DONE 2026-08-23

Third and final substep of F-024, and the one that had to answer a question no test suite in this
repo can: **is the surface actually reachable in the running process?** `e2e_harness_test.go` builds
its own gin router, so a green suite says nothing about route registration or middleware in
`pkg/mcp-proxy/main.go` — the blind spot F-021 ran into and recorded.

#### Verified twice, deliberately

**First against a locally built binary**, the way F-021 did, before anything reached a deployment:
a real OAuth + PKCE flow (DCR registration → authorize → consent → token) produced a genuine access
token; `POST /mcp` with it was proxied; the settings page listed the client with its grant; the
page's own revoke POST returned `302 …?msg=revoked`; and the **same token was refused `401`
immediately afterwards**. The guards were exercised against the production router rather than the
test one: a revoke POST without a CSRF token and with a wrong one both got `403`, and without a
session cookie the surface redirected to the login. The panic button proved two-step — the list
offers only a link, the confirmation panel carries the POST — and after *Revoke everything* the
operator was still logged in.

**Then against the deployment**, with the operator's real Claude connector. The evidence came from
the auth-event log and the access log, and it lines up to the second:

| Time | Event |
|---|---|
| 11:55:12 | `revoked actor=operator scope=client` **records=7** — matching the page's "1 access / 6 refresh" |
| **11:55:56 / 11:55:58** | `POST /mcp` → **401**, user agent `Claude-User` |
| 11:56:17 | `POST /mcp` → `401` from the second client |
| 11:57:53 | `revoked scope=client` **records=1** — the leftover DCR registration, exactly one record |
| 11:58:17 | `login_ok method=passkey` |
| 11:58:34 | `token_issued` with a **CIMD** client id |
| from 11:58:35 | `/mcp` → `200`/`202` — the client works again |

**The decisive number is 44 seconds.** `ACCESS_TOKEN_TTL` is one hour, so without the
record-presence rule (SPEC §2.4) the revoked client would have kept working for up to sixty
minutes. It was refused on its next request.

**Two things only the live run could show.** The real client's row read **1 access / 6 refresh** as
a *single* row — rotation history aggregated on real data, the case F-017d met as 58 records. And a
**DCR registration left over from before the CIMD switch** appeared with `0 authorizations` and
*never*: the "a registration without tokens must still be listed" branch, seen for the first time
against something real rather than a fixture.

#### What the verification found

**The two revoke buttons read as duplicates.** The operator asked what the difference was — a fair
question, because a client with exactly one authorization makes "Revoke" and "Revoke this one" do
the same thing, and a CIMD client has no registration for the client-level action to additionally
remove. Only the wording distinguishes them, and the wording did not. Relabelled to **"Revoke
client"** and **"Revoke this authorization"**, with a sentence in the expanded view stating what the
client-level action additionally takes. A test pins the distinction; renaming both back to the same
word turns it red. Fixed inside this substep rather than deferred, by the operator's decision and
following F-023's precedent that a defect found by live verification is fixed, not filed.

**One acceptance criterion was written too strongly by its own author.** "Re-authorization requires
the passkey" holds only when no operator session is open. With a live session the **consent page**
is what stands between a revoked client and a new token — which is the design (SPEC §1.5), and the
anti-phishing property is the consent step, shown in both cases. The operator noticed this
unprompted while testing and checked both paths. `SPEC.md` §1.12 and the runbook now state the
actual contract instead of the overstated one.

#### Documentation

- **`docs/VERIFICATION.md`** — the F-017d manual store-editing procedure is **gone**, not annotated:
  the steps are replaced by "press Revoke client", with one sentence recording that hand-editing a
  live auth store used to be the only way and is not a routine step to keep on file. A new
  checklist group in §5 covers the client list, placed with the other manual checks rather than
  after the close-out.
- **`SPEC.md`** — §1.12 gains the three endpoints in the table and a contract paragraph (built from
  token records, not registrations; per client and per authorization, never per device; a revoke
  ends access at once and bans nobody); §2.1 records that the listing adds **no entity** and needs
  no migration.
- **`README.md`** — the settings paragraph and the endpoint table.
- **`CHANGELOG.md`** — an `[Unreleased]` entry with the two properties an operator has to know
  before using it, and the measured 44 seconds.

**Verification of the docs themselves:** every relative link in the four changed files resolves;
`gofmt`/`go vet`/`go test -race` green across 11 packages; `golangci-lint` 0 issues; GR-5 scan
clean — no hostname, IP, path or personal detail from the live run reached the repository.

**Operational state, recorded because it is easy to forget:** the deployment runs a **locally built,
unreleased image** carrying this work, by the operator's decision, and the data directory and
compose file were backed up before the swap. It is not reproducible from the registry until a
release replaces it — and the operator has chosen to do **F-025 and F-022 first**, so that state
persists for now.

**Files:** `SPEC.md`, `README.md`, `CHANGELOG.md`, `docs/VERIFICATION.md`,
`pkg/auth/templates/settings.html`, `pkg/auth/clients_test.go`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No behaviour change beyond the two button labels.

### F-024 — Operator view of connected clients, with a kill switch — DONE 2026-08-23

**Problem:** The operator cannot see which clients hold access, and cannot take it away. If a
device or a session is compromised, the only remedy today is stopping the gateway and editing the
bbolt store by hand — which is literally what F-017d had to do, with a purpose-built tool, to
delete one client record. `/.idp/revoke` does not help: it is RFC 7009 and **client-authenticated**,
so it lets a client drop its *own* token, never the operator drop someone else's.

**Idea:** Extend `/.auth/settings` with a list of clients and their active authorizations, with
timestamps, plus a per-entry action that deletes the client's registration and every token issued
to it. Access dies at once; a CIMD client can only return through a fresh authorization, which
needs the operator's passkey.

**Possible implementation:**
- The real work is **enumeration**, which the repository layer does not have — there is no `List`
  or `All` on either backend. It has to be added for client records and token records, for bbolt
  (cursor over the `client-` / `access_token-` / `refresh_token-` prefixes) and for SQL.
- The UI slot already exists: `/.auth/settings` runs behind `RequireAuth` + `RequireCSRF`, and the
  "delete passkey" POST is a working template for a destructive per-row action.
- **Granularity is per client and per grant, never per device.** A token record carries
  `RequestedAt`, `Client`, scopes and `RotatedAt` — no IP, no user agent. In the field Claude web
  and iOS shared a single client id, so "log out my old phone" is not expressible. The UI should
  say what it actually shows instead of implying device identity.
- **CIMD and DCR revoke differently.** A DCR client has a stored registration to delete; a CIMD
  client has none, because it is re-resolved from its URL on every use. Revoking it means
  destroying its tokens, after which it may re-authorize — the right property for a compromised
  device, since re-authorization requires the passkey, but the UI must not suggest a permanent
  ban. A denylist was weighed at intake and deliberately left out of scope.
- Revoking must cover **access and refresh tokens together**: a refresh token left behind mints a
  new access token immediately. F-017d found **58** refresh-token records for one client, so
  enumeration has to cope with rotation history rather than assuming a single row per client.
- Emit an auth event (SR-8) when the operator revokes, so a kill is visible in the log next to the
  existing `revoked` event.

**Dependencies:** none. Would retire the manual store-editing procedure that F-017d had to write
into `docs/VERIFICATION.md`.

**Substeps (`/prep-step`, 2026-08-22) — Large: ~950 lines across ~11 files, of which ~380 are
tests.** Reading the code moved three things the intake could not have known, and each one changes
the design rather than merely detailing it:

| # | Finding | Consequence |
|---|---|---|
| 1 | Since v0.3.0 Claude connects via **CIMD**, and a CIMD client has **no stored record at all** — `clientSource.lookupClient` re-resolves it from its URL on every lookup. An enumeration over `client-*` would therefore list precisely the clients the operator cares about **least**. | The list is built from **token records** grouped by `Request.Client.ID`; stored DCR registrations join as a second source, so a registration without tokens still shows. |
| 2 | Recognisability needs **no new field**. A CIMD client's `client_id` *is* its URL (`https://claude.ai/oauth/mcp-oauth-client-metadata`, the one F-023 recorded live), and a DCR registration stores its `redirect_uris`, whose host names the client just as well. | Identity in the list = `client_id` + redirect-URI hosts. No client-supplied free text enters the operator UI here; the naming idea became **F-025** instead. |
| 3 | "Last active" falls out of `RequestedAt`/`RotatedAt` on the token records. | The `last_used_at` that `SPEC.md` §2.1 lists for the DCR client entity, and that was never implemented, is not needed for this task. |

Decisions taken at prep time: **the panic button is in** (operator-approved) — a "revoke
everything" action with a confirmation step, cheap once enumeration exists and the thing the title
promises. **No schema change**: SQL filtering decodes the request blobs in Go rather than gaining an
indexed `client_id` column, so `SchemaVersion` stays 1 and a downgrade stays possible. **All new
code lands in new files** — `kvs.go` (470) and `sql.go` (694) and `auth.go` (534) are already at or
past the §2 limits that F-022 exists to fix, and this task must not make that worse.

#### Complete (a/b/c)

The operator can now see who holds access and take it away — a capability the gateway simply did
not have. `/.idp/revoke` never provided it: RFC 7009 is **client-authenticated**, so it lets a
client drop its *own* token and never lets the operator drop someone else's. Before this, the
remedy was to stop the gateway and edit the bbolt store by hand, which is literally what F-017d had
to do with a purpose-built tool to delete a single record. That procedure has been removed from
`docs/VERIFICATION.md`; a button replaces it.

| Substep | Delivered |
|---|---|
| **F-024a** | `InventoryStorage` on the repository interface — `ListClientGrants`, `RevokeClient`, `RevokeGrant`, `RevokeAll` — for bbolt and SQLite, fed by one shared aggregator |
| **F-024b** | The *Connected clients* section in `/.auth/settings`, behind the page's existing gates, with per-client, per-authorization and panic actions |
| **F-024c** | Verification against a local binary **and** the live deployment, then the documentation |

**The finding that shaped everything** came from reading the code at prep time and held up in the
field: since v0.3.0 Claude connects via **CIMD**, and a CIMD client has **no stored registration**.
The obvious implementation — enumerate the client records — would have listed precisely the clients
the operator cares about least. The listing is therefore built from **token records**, with
registrations joined as a second source. The live run confirmed both halves at once: the real
Claude client appeared with no registration behind it, and a leftover DCR registration from before
the CIMD switch appeared with zero authorizations.

**What the design refuses to promise, deliberately:** granularity is per client and per
authorization, **never per device** — token records carry no IP or user agent, and every device
signed into the same client shares one client id, so "log out my old phone" is not expressible and
the page says so. And a revoke **bans nobody**: a CIMD client keeps no server-side registration, so
destroying its tokens is the whole of the action and it may authorize again. A denylist was weighed
at intake and left out of scope.

**Proof rather than assertion.** Three deliberate mutations were run against the finished code, and
one of them earned its keep: a security test in F-024b was passing **for the wrong reason** — a bare
`http.Client` follows redirects, so the handler's `302` was chased to the settings page and that
page's own `403` satisfied the assertion. The own-user gate could have been deleted unnoticed. The
generalisable lesson is recorded in F-024b: on this surface, any test asserting a status code
against a handler that can redirect must use a non-following client. Live, the decisive measurement
was **44 seconds** — the time between the operator's revoke and the real client's `401`, against an
`ACCESS_TOKEN_TTL` of one hour.

**Spawned:** **F-025** (naming a connection at consent time, which also closes a `SPEC.md` §1.5
identity requirement that has been unmet since it was written — DCR and CIMD both parse
`client_name` today and both discard it).

**Left for F-022:** `pkg/auth/auth.go` grew to 558 lines, past a §2 hard limit it already exceeded.
The config field and the routes belong there; the split does not belong in this task.

**Not yet released.** The deployment runs a locally built image carrying this work, by the
operator's decision, with the data directory and compose file backed up beforehand. The operator
chose to complete **F-025 and F-022 before the next release**, so that state persists until then.
