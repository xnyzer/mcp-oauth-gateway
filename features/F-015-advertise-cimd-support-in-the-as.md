---
id: F-015
title: Advertise CIMD support in the AS metadata
type: feature
status: DONE
size:
created: 2026-08-20
done: 2026-08-21
depends-on:
superseded-by:
---

# F-015 — Advertise CIMD support in the AS metadata

## History

### F-015 — Advertise CIMD support in the AS metadata — DONE 2026-08-21

**Problem:** `SPEC.md` §1.3 declared Client ID Metadata Documents the primary
client-identification mechanism, but the §1.2 AS metadata table never announced it — and the
implementation faithfully mirrored that omission: `client_id_metadata_document_supported`
appeared nowhere in the repository. Clients could not discover a capability that is implemented
(`pkg/cimd`) and enabled by default (`CIMD_ENABLED=true`), and fell back to the deprecated DCR
path instead. Surfaced while diagnosing an unrelated outage: the live deployment's metadata was
missing the field entirely.

**Idea:** Add the field to SPEC §1.2 and emit it from `authorizationServerResponse`, driven by
the CIMD configuration so the advertisement always matches actual behaviour.

**What was done:**
- `pkg/idp/idp.go`: new `cimdEnabled` field on `IDPRouter`, set from `cfg.CIMDResolver != nil`;
  new `ClientIDMetadataDocumentSupported` field on `authorizationServerResponse`, populated from
  it in `handleOauthAuthorizationServer`.
- `SPEC.md` §1.2: added the field row and a delta note recording why the omission mattered.
- `CHANGELOG.md`: `[Unreleased]` → `Added`.
- Tests: a presence assertion in `TestOAuthServerMetadata` plus a new
  `TestASMetadataAdvertisesCIMD` with three subtests — advertised with a resolver (asserting the
  `none` auth method alongside, since clients require both halves), not advertised without one,
  and mirrored onto the OIDC discovery path.

**Decisions / deviations:**
- **Wired from the resolver, not from a second flag.** `IDPRouter` had no `cimdEnabled` field;
  CIMD hangs off `cfg.CIMDResolver` (nil disables it). Deriving the advertisement from the
  resolver's presence means the metadata and the behaviour cannot drift apart.
- **Always emitted as a boolean**, `true` or `false`, rather than omitted when false — consistent
  with the neighbouring `authorization_response_iss_parameter_supported`.
- **The plan's consent concern was imprecise and needed no work.** The consent screen sources
  identity from `ar.GetClient().GetID()`, which for a CIMD client *is* the document URL — a
  verifiable identifier, better than a self-declared `client_name`. Nothing to change.
- **The test pair came out sharper than planned.** The plan assumed the field would be `true` by
  default in the existing metadata test; in fact `setupTestServerWith` configures no resolver, so
  the honest default there is `false`. The existing test now pins presence *and* `false`, which
  also makes it non-vacuous: were the field absent, the presence assertion fails.
- **Added an OIDC-mirror subtest** that was not in the plan, pinning the claim (made during
  `/prep-step`) that the mirror is covered automatically because it routes to the same handler.

**Verification:** `gofmt -l .` empty, `go vet ./...` clean, `go test -race ./...` green across all
packages; the three new subtests pass. Compared against the live deployment for contrast, whose
metadata still omits the field entirely.

**Expected live effect:** clients that previously used DCR will switch to CIMD once this ships.
That path is already exercised end to end by `TestE2EPublicClientPKCE` (authorize → consent →
token → proxied call, including `iss` and a PKCE negative). Existing DCR registrations stay in
the store until their TTL expires and are simply no longer used.

**Files:** `pkg/idp/idp.go`, `pkg/idp/idp_test.go`, `SPEC.md`, `CHANGELOG.md`; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. No new dependencies, no new config, no new endpoints.
