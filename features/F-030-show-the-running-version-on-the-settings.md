---
id: F-030
title: Show the running version on the settings page
type: feature
status: DONE
size:
created: 2026-10-12
done: 2026-10-12
depends-on:
superseded-by:
---

# F-030 — Show the running version on the settings page

## History

### F-030 — Show the running version on the settings page — DONE 2026-10-12

**Problem:** The operator cannot see in the browser which version is running — only via
`--version` inside the container on the host. After an update there is no quick way to
confirm the new image is actually live.

**Idea:** Show the build version (`pkg/version.Version`) on the session-gated
`/.auth/settings` page, so only the logged-in operator sees it. `/healthz` stays
unchanged: SPEC §1.13 forbids version disclosure there, because it is unauthenticated and
publicly reachable, and a version string tells an attacker which advisories apply.

**Solution sketch** (as planned in `/prep-step`, 2026-10-12 — small, no substeps):
- The version reaches the page through the auth router's construction options (a `Version`
  field on `auth.Config`, wired from `version.Version` where the router is built) rather than
  the handler reading the package global. It is still the one build-time value `--version`
  reports — nothing an operator sets, so the two cannot drift. The indirection exists for the
  test: it can set a distinctive value and assert that exact rendering, where the global would
  only ever say `dev`.
- Rendered as a small footer on the settings page; an empty value renders nothing.
- Extend SPEC §1.12 (the `GET /.auth/settings` row) by the version display; §1.13 stays as it
  is and gains a sentence on why. README's "Version" line and the CHANGELOG follow.
- No new endpoint, no new config, no new dependency, no outbound call — an "update available"
  check against GitHub is deliberately out of scope (egress from an auth boundary, new failure
  mode); the operator compares against the releases page.

**Acceptance criteria:**
- [x] A logged-in operator sees the version in the settings footer, asserted on the specific
      rendering, not a loose `Contains`.
- [x] Without a session the version is nowhere: not on the login page, not in the redirect
      that `GET /.auth/settings` answers with (client must not follow redirects).
- [x] `/healthz` still answers exactly `{"status":"ok"}`.
- [x] Each new assertion has been seen to fail once (CODING-STANDARDS §9).
- [x] Full check set green with the pinned toolchain.

**Release:** on its own as patch release **v0.4.2** — the operator's decision: worth shipping,
not worth a minor bump.

**Dependencies:** none.

#### F-030 — what was actually done

**Product code, 20 lines in four files.** `auth.Config` gained `Version`, `AuthRouter` carries
it, `handleSettings` puts it into the template data, and `settings.html` renders
`mcp-oauth-gateway <version>` beneath the existing logout footer — with the page's existing
`muted small` classes, so no new CSS. `buildRouter`'s auth wiring passes `version.Version`.
`html/template` escapes the value, and it is a build constant, never request input.

**Tests.**
- `pkg/auth/settings_test.go` (new, mirrors `settings.go`): the footer element is matched as an
  element by a regexp on a deliberately odd version (`v9.9.9-test`); an empty version renders
  no footer; an anonymous caller finds the version neither on the login page nor in the
  redirect `GET /.auth/settings` answers with.
- `pkg/mcp-proxy/e2e_version_test.go` (new): on the gateway assembled by the real startup
  path, with the build version swapped as the linker flag would set it — `/healthz` answers
  exactly `{"status":"ok"}`, the login page, both metadata documents, the OIDC mirror and the
  JWKS do not name the build, an anonymous settings request is turned away with an empty
  redirect, and the logged-in operator sees the footer.

**Each assertion seen red — eight mutations.** Footer removed; wiring line removed (only the
end-to-end test can catch that one, which is why it exists); version added to the `/healthz`
body; version leaked onto the login page; the empty-value guard dropped; the redirect made to
carry the version; `Abort` removed from `RequireAuth`; the session gate removed from the route.
After every mutation the tree was restored and compared byte for byte against the baseline.

**Deviations from the plan:**
- **An end-to-end test the plan did not have.** The plan's tests lived in `pkg/auth`, where the
  version is set directly on `auth.Config` — they would stay green with the wiring line in
  `buildRouter` deleted. The mutation showed exactly that, so the test is not optional.
- **`/healthz` on the real router had no exact-body assertion before**; only the plain-HTTP
  fallback handler did. The new end-to-end test covers it.
- **The first version of that end-to-end test had a hole, found by mutating the gate:** it
  never requested the settings page anonymously, so it stayed green with the session gate
  removed. Extended in the same step and seen red afterwards.
- No new CSS — the page already had a footer.

**A process failure worth recording.** The first mutation pass ran from an interactive zsh,
where an unquoted list of file names is not split into words: the backup and every restore
silently failed, and the mutations piled up in the working tree. Nothing was committed. The
tree was rebuilt from `HEAD` plus the intended edits and verified against the earlier diff
stat, and the pass was repeated from a `bash` script with an array, a `cmp` after every
restore, and a before/after diff comparison of the whole tree. **Mutation runs go through a
script with a verified restore, not through ad-hoc shell.**

**Verified** (all with `GOTOOLCHAIN=go1.26.9`): gofmt from that toolchain empty; `go vet` clean;
`go test -race -count=1 ./...` green in all 11 packages with tests; golangci-lint v2.12.2
0 issues; go-licenses v2.0.1 passes; actionlint clean; `govulncheck` 0 reachable; `go mod tidy`
without diff. **And on a built image** (`VERSION=v0.4.2-rc`): `/healthz` → `{"status":"ok"}`,
login page without the version, password login `302`, settings footer
`mcp-oauth-gateway v0.4.2-rc`, settings without a session `302`.

**Not verified:** how the footer looks in a browser — the HTML was fetched, not rendered.

**Files:** `pkg/auth/auth.go`, `pkg/auth/settings.go`, `pkg/auth/templates/settings.html`,
`pkg/mcp-proxy/router.go`, `pkg/auth/settings_test.go` (new),
`pkg/mcp-proxy/e2e_version_test.go` (new), `SPEC.md` (§1.12, §1.13), `README.md`,
`CHANGELOG.md`; docs `PROGRESS.md`, `PROGRESS-ARCHIVE.md`.
