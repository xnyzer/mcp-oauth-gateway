---
id: F-023
title: CIMD documents rejected over a foreign grant type
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-21
depends-on:
superseded-by:
---

# F-023 — CIMD documents rejected over a foreign grant type

## History

### F-023 — CIMD documents rejected over a foreign grant type — DONE 2026-08-21

Found during the F-017d live verification, minutes after v0.2.0 went live. It is the defect that
made the whole F-015/F-017d exercise worth running.

**Symptom.** The operator clicked "connect" in Claude and got an error page:
`invalid_client … The requested OAuth 2.0 Client does not exist.` The gateway logged:

```
CIMD resolution failed
client_id: https://claude.ai/oauth/mcp-oauth-client-metadata
error: invalid CIMD client ID: unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"
```

**Cause.** `pkg/cimd/resolver.go` validated a document's declared `grant_types` against the §1.2
supported set and rejected the **entire client** if any entry fell outside it. Claude's published
document is perfectly valid and declares three grants — `authorization_code`, `refresh_token` and
`urn:ietf:params:oauth:grant-type:jwt-bearer`. Two are exactly what this gateway offers; the third
is a capability Claude uses at other authorization servers.

That is the conceptual error: **a CIMD document is published once and presented to every
authorization server**, so it necessarily declares the union of the client's abilities. A server
that refuses the client because that union names something it does not offer makes CIMD unusable
with any real client. DCR is different — a registration request is addressed to one server, so
rejecting an unsupported declaration there is correct, and it stays strict.

**Why it stayed hidden until now.** Before F-015 the AS metadata never advertised CIMD, so clients
took the deprecated DCR path and no real document ever reached this code. F-015 fixed the
advertisement, clients switched to CIMD — and walked straight into the rejection. The shared
whitelist came from F-012a, where sharing it between DCR and CIMD looked like consistency rather
than a category error.

**Fix.** Narrow instead of reject: `grant_types` and `response_types` are intersected with the
supported sets, order preserved, via a small `intersect` helper. A document that leaves *nothing*
supported is still rejected — no flow would remain to run. Narrowing is strictly fail-closed: the
resolved client only ever ends up with a subset of what it asked for, and fosite refuses an
unsupported flow at the endpoints if one is attempted anyway.

**Tests.** New `TestResolverNarrowsUnsupportedFlows`, table-driven over Claude's real document,
a mixed `client_credentials` case (order preservation) and a mixed response-type case.
**Verified non-vacuous:** restoring the old validation turns it red with
`unsupported grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer"` — byte-identical to the
message from the live log.

Two existing cases in `TestResolverDocumentValidation` encoded the old behaviour and were
**deliberately changed**: `["authorization_code", "client_credentials"]` must now resolve rather
than fail, so it moved into the narrowing test. The two remaining rejection cases were renamed to
`no supported grant_type` / `no supported response_type`, which is what they actually assert.

**Known limitation recorded alongside** (`CHANGELOG.md`), from
[anthropics/claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650), surfaced by
the operator: fetching Claude's CIMD document from **datacenter IP ranges** can return a Cloudflare
challenge (403) instead of the document. Nothing a server-side OAuth implementation can solve;
`CIMD_ENABLED=false` is the escape hatch for deployments hit by it. This gateway's host is
unaffected — the document fetches with HTTP 200.

**Files:** `pkg/cimd/resolver.go`, `pkg/cimd/resolver_test.go`, `SPEC.md` §1.3, `CHANGELOG.md`
(v0.2.1); docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues.
