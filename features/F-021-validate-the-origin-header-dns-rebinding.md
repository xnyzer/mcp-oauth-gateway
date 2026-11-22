---
id: F-021
title: Validate the Origin header (DNS rebinding, SR-9)
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-22
depends-on:
superseded-by:
---

# F-021 — Validate the Origin header (DNS rebinding, SR-9)

## History

### F-021 — Validate the `Origin` header (DNS rebinding, SR-9) — DONE 2026-08-22

Closes the one **unmet MUST** the F-017 spec re-check turned up. `SPEC.md` §4.2 carried a ✘ from
v0.2.0 until now; the row reads ✔.

**What it does.** A request whose `Origin` header names anything other than the `EXTERNAL_URL`
origin is answered `403`. A request **without** an `Origin` header passes — deliberately, and as the
specification intends: server-side MCP clients send none, so treating absence as a violation would
reject every real client and turn a hardening measure into an outage. `Origin: null` counts as
present and invalid. Comparison is on scheme + host + port, host lower-cased, default ports elided.

**Two intake questions decided at prep time, one third found during it:**

- **No `ALLOWED_ORIGINS` list**, only `ORIGIN_CHECK_ENABLED` (default `true`). The gateway emits no
  CORS headers, so every cross-origin browser request already fails in the browser; a list would
  widen a door that is bricked up, and it belongs with CORS if CORS ever arrives. The boolean also
  matches the eight existing `*_ENABLED` variables.
- **Global check.** `GET /healthz` falls outside it for free, being registered before any
  `router.Use`. `.well-known` stays inside — a cross-origin fetch cannot work without CORS headers
  anyway, so a 403 there breaks nothing that functions.
- **`Origin: null`** was missing from the intake entirely. Browsers send it from sandboxed iframes,
  `file://` documents and some redirect chains. Naming it up front is what kept the implementation
  from getting it wrong.

**The bug the test caught — worth recording, because the code was wrong and the comment was
confident.** The first implementation compared `normalizeOrigin(origin) == expected`. Since
`normalizeOrigin` returns `""` for anything unusable, an expected origin that itself normalized to
`""` would have matched `Origin: null`, and the guard would have degraded into a wildcard while its
doc comment claimed "fail-closed". `TestNormalizeOriginRejectsUnusableAsExpectedValue` — written
for exactly that suspicion — went red. Fixed by requiring a **non-empty** match. Unreachable in
practice, since `EXTERNAL_URL` is validated at startup, which is precisely why it would have
survived review.

**Second deviation: IPv6.** `url.Hostname()` strips the brackets from a literal, so the first
re-assembly turned `[::1]:8080` into the unparseable `::1:8080`. Fixed and covered by two rows in
`TestNormalizeOrigin`.

**Third, and the one that generalises beyond this task: the e2e suite does not prove the wiring.**
`e2e_harness_test.go` builds its **own** `gin.New()` router, so a green suite says nothing about
whether middleware added in `pkg/mcp-proxy/main.go` is actually mounted. Verified instead against
the **running binary**, the way F-007a did:

| Request | Result |
|---|---|
| `GET /healthz` with a foreign Origin | `200` — outside the check, as designed |
| `POST /mcp` foreign Origin | `403` |
| `POST /mcp` `Origin: null` | `403` |
| `POST /mcp` no Origin | `401` — passed the check, then hit auth |
| `POST /mcp` own Origin | `401` — same |
| `GET /.auth/login` own Origin | `200` |
| WARN log line | carries the offending **and** the expected origin |
| `ORIGIN_CHECK_ENABLED=false` | `401` instead of `403`, plus the startup warning |

**Tests:** 13 middleware cases and 15 normalization rows, plus the fail-closed guard.
**Verified non-vacuous:** removing the comparison turns seven rejection cases red at once.

**Standards note:** `pkg/mcp-proxy/main.go` grew 934 → 948 lines and `main.go` 565 → 568, both
already past the §2 hard limit. Unavoidable here, unlike F-017b where the tests could move: a global
middleware must be wired where the router is assembled, and a flag where the other flags live. The
*logic* lives in a new `origin.go`, so only the wiring touches the oversized files. **F-022** tracks
the split.

**Files:** new `pkg/mcp-proxy/origin.go` (96 lines) and `pkg/mcp-proxy/origin_test.go` (110);
`pkg/mcp-proxy/main.go` and `main.go` (wiring + flag); `SPEC.md` (§0 contract, §3 config table,
§4.2 row now ✔), `README.md` (an "Origin validation and `EXTERNAL_URL`" note beside the firewall and
CIMD ones), `.env.example`, `CHANGELOG.md` (Unreleased, with an upgrade note).

**Verification:** `gofmt -l` empty; `go vet` clean; `go test -race ./...` green across 11 packages;
`golangci-lint v2.12.2` 0 issues; gitleaks clean over the tree **and** the untracked new files.

**The risk this ships with, stated plainly in README and CHANGELOG rather than buried:** browsers
send `Origin` on same-origin POSTs, so the operator's own login and consent POSTs now carry it. An
`EXTERNAL_URL` that does not match the browser's address bar locks the operator out. The WARN log
names both origins so the cause is one line, and `ORIGIN_CHECK_ENABLED=false` is the rescue.
