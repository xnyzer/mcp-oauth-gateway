---
id: F-016
title: Port-agnostic loopback matching for localhost redirect URIs
type: feature
status: DONE
size:
created: 2026-08-20
done: 2026-08-21
depends-on:
superseded-by:
---

# F-016 — Port-agnostic loopback matching for localhost redirect URIs

## History

### F-016 — Port-agnostic loopback matching for `localhost` redirect URIs — DONE 2026-08-21

**Problem:** Native clients that use the hostname `localhost` for their loopback redirect could
not complete authorization. Fosite ignores the port only for IP literals — `isLoopbackAddress()`
tests `net.ParseIP(hostname).IsLoopback()` — so a client registering `http://localhost/callback`
and requesting `http://localhost:PORT/callback` was rejected, while the `127.0.0.1` form of the
same request was accepted. Claude Code publishes exactly that shape, so it could not connect.

**Idea:** Extend the RFC 8252 §7.3 port-agnostic rule to the exact hostname `localhost`, keeping
every other component an exact match.

**What the research turned up (it shaped the whole design):**
1. **Only the authorize step needed the fix.** `MatchRedirectURIWithClientRedirectURIs` is a
   package-level function called at two sites, both in the authorize path. The token endpoint only
   string-compares against the authorize request — no re-matching against registered URIs.
2. **An expansion survives the consent round-trip by itself,** because the authorize request is
   serialised including the client and its redirect URIs, then re-hydrated for the consent POST.
3. **No wrapper client type is possible:** `models.FromFositeClient` type-asserts
   `client.(*fosite.DefaultClient)` unchecked, so a foreign type would panic on that round-trip.
4. **Pre-processing was already established** in `handleAuth`, which rewrites the query to inject a
   generated `state`; its request context reaches `clientSource.GetClient`.

**What was done:**
- New `pkg/idp/loopback.go`: `matchesLoopbackHostPort` (the predicate, mirroring fosite's
  `isMatchingAsLoopback` but for the `localhost` hostname), `expandLoopbackRedirects` (returns a
  fresh slice, never aliases the caller's), plus `isLoopbackRedirect`/`allRedirectsLoopback` for
  the consent warning.
- `pkg/idp/idp.go`: `handleAuth` stashes the raw `redirect_uri` on the request context via a
  private key type; `clientSource.GetClient` was split into a lookup plus an expansion step that
  clones the `*fosite.DefaultClient` before extending its redirect list. The client lookup itself
  moved unchanged into `lookupClient`.
- Consent: `consentTemplateData` gained `LoopbackOnly`, and the template shows an explicit warning
  that the application runs on the operator's own device and any local program could have claimed
  the port (recommended by the MCP authorization spec).
- `SPEC.md` §1.3 (port tolerance) and §1.5 (loopback warning); `CHANGELOG.md` `[Unreleased]`.

**Verification:** `gofmt` clean, `go vet` clean, `go test -race ./...` green across all packages.
New tests: 16 predicate table cases, 5 expansion cases, 7 authorize-flow subtests through the real
endpoint, and a consent-template check. **The positive test was proven non-vacuous** by disabling
the context stash and re-running it: `400` instead of a redirect, test red; restored, green.

**Decisions / deviations:**
- **The tests came out at 187 lines against a planned handful.** Not trimmed: this is the
  open-redirect boundary, and each negative is a distinct way the rule could go slack —
  `evil.localhost`, path prefix, appended query, scheme downgrade, and bridging `localhost` to an
  IP literal.
- **No bridge between `localhost` and `127.0.0.1`.** A registered `localhost` does not authorise a
  `127.0.0.1` redirect or vice versa. Both forms work, each on its own.
- **The consent warning keys on "all redirect URIs are loopback", not "any".** A web client that
  also offers a local callback is not a native client, and warning there would train the operator
  to click through the warning that matters.
- **`isLoopbackRedirect`/`allRedirectsLoopback` were moved out of `idp.go`** into `loopback.go`
  during review — they are loopback logic, and `idp.go` is already far over the file-length limit.
- **Rejected alternative:** rewriting `localhost` → `127.0.0.1` in the query would have let
  fosite's existing IP-literal rule do the work, but it sends the user to a different host than
  requested and can break clients that compare the callback URL against what they sent.

**Pre-existing issue found, not fixed here:** `pkg/idp/idp.go` is 1073 lines against a 500-line
hard limit in `CODING-STANDARDS.md`, with no section comments, so the documented exception does not
apply. It was already 1010 lines before this task; splitting it is a refactor of an auth-critical
file and belongs in its own task, not smuggled into a redirect-matching change.

**Files:** new `pkg/idp/loopback.go`, `pkg/idp/loopback_test.go`; changed `pkg/idp/idp.go`,
`SPEC.md`, `CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`. No new dependencies, no new
config, no new endpoints.
