---
id: F-007
title: Release hygiene
type: feature
status: DONE
size:
created: 2026-06-14
done: 2026-07-08
depends-on:
superseded-by:
---

# F-007 — Release hygiene

## History

### F-007a — Code fixes: M7 + M8 + manual key-rotation command — DONE 2026-07-08

First F-007 substep (release hygiene): the two remaining code-level audit fixes plus the
SPEC §2.3 ops command deferred from F-005d.

- **M8 — bare-IP `TRUSTED_PROXIES` no longer crashes startup:** new
  `backend.ParseTrustedProxies` / `backend.NormalizeTrustedProxies` accept both documented
  entry forms — CIDR as-is, bare IPs normalised to `/32`·`/128` (4-in-6 unmapped first,
  matching gin); anything else fails fast with a clear message. `Run()` normalises once so
  gin and the transparent backend see the same list; gin's previously ignored
  `SetTrustedProxies` error is now checked.
- **M7 — SPEC §3.1 startup WARNING + cookie `Secure`:** `warnPlainHTTPIssuer` warns on an
  `http` issuer with a non-loopback host (localhost / `*.localhost` / 127.0.0.0/8 / ::1 stay
  silent); the session cookie's `Secure` flag is now "https issuer **or** the gateway itself
  serves TLS" instead of the URL scheme alone.
- **`rotate-key` ops command (SPEC §2.3):** offline cobra subcommand on the data directory —
  same env twins (`DATA_PATH`, `KEY_ALG`, `ACCESS_TOKEN_TTL`, `CLOCK_SKEW`), same retiring
  window as the server, refuses `JWT_PRIVATE_KEY` static mode, prints kid continuity and a
  restart reminder. **Decision:** offline subcommand over signal/admin-endpoint because the
  running manager keeps the key set in memory (it would neither pick up nor reliably preserve
  an on-disk rotation) and an offline command adds no attack surface; the restart requirement
  is documented in the command help and SPEC §2.3.
- **Cobra gotcha:** adding the first subcommand made cobra treat the positional upstream
  target as an "unknown command" — the root command now sets `Args: cobra.ArbitraryArgs`
  (regression caught by the existing root-command tests).

Verification: 13 new test cases (parse/normalise tables, bare-IP constructor + Run-level,
Secure-flag matrix, loopback table, WARNING via zap observer, rotation continuity, static-mode
refusal, flag validation); full suite + `-race` green; live smoke on the built binary (bare-IP
start, WARNING in the JSON log, `/healthz` 200, no-token `/mcp` 401, two `rotate-key` runs with
a correct manifest).

**Files:** `pkg/backend/transparent.go` (+tests), `pkg/mcp-proxy/main.go` (+tests), `main.go`
(+tests), `pkg/keys/manager.go` (comment), `SPEC.md` §2.3, `docs/VERIFICATION.md` (M8 gotcha
scoped to pre-F-007a builds).

### F-007b — Container & CI hardening (M9 + M10) — DONE 2026-07-08

Second F-007 substep: the published container image and the CI quality gates.

#### M9 — hardened runtime image
- **Runtime switched to `gcr.io/distroless/static-debian12:nonroot`** (digest-pinned, as is the
  `golang:1.26-bookworm` builder): non-root uid 65532, no shell, no package manager, and the
  python/pip/node/npm/curl interpreter surface inherited from sigbit is gone. **Trade-off
  (documented):** stdio upstreams that need `npx`/`uvx` now run as a separate service or a
  custom image — the gateway image stays minimal.
- **Non-privileged in-image defaults** `LISTEN=:8080` / `TLS_LISTEN=:8443` (a non-root container
  cannot bind :80/:443; hosts publish onto them). `/data` is created in-image owned by nonroot,
  so a fresh named volume inherits writable ownership (verified by running `rotate-key` on one).
- **`HEALTHCHECK` without curl:** new `healthcheck` subcommand probes `/healthz` on `LISTEN`
  (redirects count as unhealthy, fail-closed). To make that mode-independent, the plain-HTTP
  listener in both TLS modes now serves `/healthz` directly and redirects everything else
  (`httpFallbackHandler`, deduplicating the two previously copy-pasted redirect handlers).
- **Version wiring:** new `pkg/version` injected via `-ldflags -X` (`VERSION` build arg);
  reported by `--version` and the MCP ClientInfo (was hardcoded `"dev"`).

#### M10 — CI quality gates
- **golangci-lint v2.12.2** (pinned; action `golangci/golangci-lint-action@v9.3.0`) with a
  curated `.golangci.yml`: standard linters + `gosec` + `misspell`; `errcheck`/`gosec` off in
  `_test.go` (documented: cleanup-error noise, taint findings against local stubs).
- **First lint run: 76 findings, all triaged.** Real fixes: `ReadHeaderTimeout` on all five
  listeners (Slowloris, SSE-safe), data dir `0700` (SPEC §2.2, pulled from F-012), unchecked
  `json.Unmarshal` of session user info now logged, deprecated `ecdsa.PublicKey.X/.Y` swapped
  for `PublicKey.Bytes()` (JWKS output byte-identical, verified by the suite), best-effort
  cleanup errors made explicit (`_ =`), `Clone()` embedded-selector cleanup. Deliberate
  exceptions carry inline `//nolint:<linter> // reason` (operator-configured stdio exec/OIDC
  fetch/key paths, same-host https upgrade, DCR-secret persistence, endpoint-path G101s).
- **`go-licenses` pinned** to `github.com/google/go-licenses/v2@v2.0.1` (verified locally:
  dependency tree passes).
- **Pulled forward from F-012** (adjacent, tiny): data-dir `0700`; startup errors now exit via
  cobra `RunE` + `os.Exit(1)` instead of `panic()` (root command `SilenceUsage`). F-012 list
  updated.

Verification: gofmt/vet/lint clean, full suite + `-race` green; container smoke — `--version`
reports the injected version, `Config.User=nonroot`, Docker health turns `healthy` via the
in-binary probe, `/healthz` 200 through a published port, `/mcp` without token 401, fresh named
volume writable as nonroot.

**Files:** `Dockerfile`, `.github/workflows/ci.yml`, `.golangci.yml` (new), `pkg/version/` (new),
`main.go` (+tests: healthcheck command, healthURL), `pkg/mcp-proxy/main.go` (+tests:
`httpFallbackHandler`), `pkg/backend/proxy.go`, and lint-driven fixes across `pkg/auth`,
`pkg/cimd`, `pkg/idp`, `pkg/keys`, `pkg/repository`, `pkg/utils`; `SPEC.md` §1.13/§3.3;
`docker-compose.example.yml` (port mapping matches the new image default).

### F-007c — Release workflow + install artefacts — DONE 2026-07-08

Third F-007 substep: everything needed to install the gateway from a tag.

- **`.github/workflows/release.yml`** (new): a SemVer tag (`v*.*.*`) builds the multi-arch
  image (linux/amd64 + linux/arm64, QEMU+buildx) and pushes `ghcr.io/<repo>:<version>` +
  `<major>.<minor>` — deliberately **no floating `latest`** (deployments pin versions, SPEC
  §3.3). The tag is injected as the build `VERSION` (→ `pkg/version`). Action majors verified
  current at runtime (docker/setup-qemu@v4, setup-buildx@v4, login@v4, metadata@v6,
  build-push@v7); actionlint clean. The "image pullable after a tag push" acceptance can only
  run with the first real tag → moved to F-007e.
- **`.env.example`** (new): every SPEC §3.1+§3.2 env var, grouped (required / install mode A
  behind a TLS proxy / mode B built-in ACME / listeners+storage / upstream / lifetimes / keys /
  abuse protection / OIDC), defaults documented, placeholders only (GR-5; TEST-NET IPs). The
  Compose `env_file` `$`→`$$` bcrypt pitfall is documented prominently, incl. the 60-char
  in-container check. Also covers `JWT_PRIVATE_KEY`/`AUTH_HMAC_SECRET` as advanced options.
- **`docker-compose.example.yml`**: switched from inline `environment:` to `env_file: .env`;
  gateway relies on the image's built-in `HEALTHCHECK`; upstream gets a placeholder
  `healthcheck` + `depends_on: condition: service_healthy` (with a documented fallback to
  `service_started` for upstreams without a probe).
- **`setup.sh`** (new, universal parts only — no firewall scripting): prompts for the public
  URL + operator password (stdin, hidden, never in argv/history), generates the bcrypt hash
  via `docker run httpd:2.4-alpine htpasswd -niBC 12`, applies the `$`→`$$` escaping, writes
  `.env` (0600) from `.env.example`, refuses to overwrite an existing `.env`, and prints next
  steps incl. the Anthropic-egress (160.79.104.0/21) silent-failure reminder.

**Verified end to end** (scratchpad): piped `setup.sh` run → `.env` correct (0600, escaped
hash); `docker compose up -d --wait` with the F-007b image + env_file + health gating →
upstream healthy → gateway healthy; in-container `PASSWORD_HASH` is the un-escaped 60-char
bcrypt; **login with the real password → 302, wrong password → 400** — proving the whole
escaping chain; workflows actionlint-clean (also fixed the pre-existing SC2046 quoting in
ci.yml's go-licenses step).

**Files:** `.github/workflows/release.yml` (new), `.env.example` (new), `setup.sh` (new),
`docker-compose.example.yml`, `.github/workflows/ci.yml` (quoting).

### F-007d — Docs — DONE 2026-07-08

Fourth F-007 substep: the public-facing documentation.

- **`README.md` rewritten as full usage docs** (replacing the "early development / not yet
  released" banner with the audited/live-verified status): quickstart via `setup.sh` +
  compose; **install modes A** (behind a TLS-terminating reverse proxy — `NO_AUTO_TLS`,
  `TRUSTED_PROXIES`, streaming/no-buffering proxy note) **and B** (standalone built-in ACME —
  `TLS_HOST`/`TLS_ACCEPT_TOS`, host 80/443 published onto the non-privileged container
  ports); the **Anthropic-egress firewall note** (160.79.104.0/21 — blocking fails
  *silently*); a step-by-step **Claude custom-connector guide** incl. passkey enrolment and
  disabling the password fallback; upstream fronting (bearer optional, host-only-target path
  gotcha, stdio-needs-own-image note); a **complete §3 config reference** (six grouped
  tables); operations (health, manual + automatic key rotation, backup, auth-event logs,
  version, upgrade policy); endpoint map; security posture.
- **`CHANGELOG.md`** (new, Keep-a-Changelog): `[Unreleased]` section ready to become v0.1.0 —
  everything relative to the forked base (CIMD, discovery, token lifecycle, keys, passkeys,
  abuse protection, packaging), the audit-hardening list, and **upgrade notes** (no
  data-directory compatibility with sigbit/mcp-auth-proxy; legacy single-key adoption).
- **`SECURITY.md`**: scope no longer "once implemented" (it is); supported-versions table
  stays "pre-release" until the F-007e tag flips it.
- **`NOTICE`**: stale `go-sql-driver/mysql` entry removed (dependency dropped long ago),
  license-scan reference updated to the CI job. Attribution (sigbit MIT block) verified.
- **`docs/VERIFICATION.md`**: cross-linked to the README install modes + `.env.example`.

Verified by script: all relative links in README/CHANGELOG resolve; every SPEC §3.1+§3.2 env
var appears in both README and `.env.example`; GR-5 scan clean (only documented public
ranges/TEST-NET addresses).

**Files:** `README.md`, `CHANGELOG.md` (new), `SECURITY.md`, `NOTICE`, `docs/VERIFICATION.md`.

### F-007e — Release gate + publish — DONE 2026-07-08

Final F-007 substep — every gate ran, then the operator-gated publish.

#### Release gates (all green)
- **MCP 2026-07-28 RC check:** the RC turned out to be **already published** (locked
  2026-05-21; final spec lands 2026-07-28). All six authorization-hardening SEPs verified
  against the gateway: RFC 9207 `iss` supplied on success+error (SEP-2468); DCR tolerates
  `application_type` and accepts RFC 8252 native/localhost redirect URIs (SEP-837);
  issuer-bound tokens (SEP-2352); refresh tokens issued independent of an `offline_access`
  scope, requested scopes granted (SEP-2207/2350); no-path issuer makes both `.well-known`
  suffix forms equivalent (SEP-2351). CIMD-first + DCR fallback unchanged in the RC.
  REQUIREMENTS §0 watch item **resolved**; re-check scheduled at the final spec.
- **govulncheck (new gate):** found **3 reachable vulnerabilities** — fixed by bumping
  `golang.org/x/net` → v0.55.0 (GO-2026-5026), `quic-go` → v0.59.1 (GO-2026-5676), Go
  toolchain → 1.26.5 (GO-2026-5856). Re-scan: 0 reachable; full suite + `-race` green.
- **gitleaks over the entire history** (32 commits): no leaks — cleared the public flip.
- **License sweep:** go-licenses clean; **license decision re-examined with the operator**
  and re-confirmed: **Apache-2.0** over MIT (no patent grant/NOTICE/contribution clause),
  MPL-2.0 (file-copyleft cost without SaaS protection — that would need AGPL) and AGPL
  (adoption cost); memstead-module future favours permissive.
- **Update automation added:** `.github/dependabot.yml` (gomod/docker/actions, weekly) +
  weekly `govulncheck` workflow — dependency vulnerabilities surface automatically
  post-release (documented in SECURITY.md).

#### Publish
`chore(release): prepare v0.1.0` pushed together with the 8 pending commits; tag **v0.1.0**
→ release workflow built and pushed the multi-arch image
(`ghcr.io/xnyzer/mcp-oauth-gateway:0.1.0` + `:0.1`, digest `bb5b1216…`). **Operator go/no-go:
repo flipped public** (`gh repo edit`), operator set the GHCR package public + Actions access
"Write" (least privilege); private vulnerability reporting + Dependabot alerts enabled;
GitHub release v0.1.0 published with CHANGELOG notes. Verified as an anonymous user:
`docker pull` works, amd64+arm64 manifests present, `--version` reports `v0.1.0`, container
healthy, discovery 200, tokenless `/mcp` 401.

### F-007 — Release hygiene — DONE 2026-07-08 (parent task)

Completed via **F-007a** (M7/M8 fixes + `rotate-key`), **F-007b** (distroless non-root image,
golangci-lint + go-licenses CI), **F-007c** (release workflow, `.env.example`, health-gated
compose, `setup.sh`), **F-007d** (README usage docs, CHANGELOG, SECURITY/NOTICE) and
**F-007e** (gates + publish). **v0.1.0 is publicly released**: repo public, GHCR image
pullable, all four deployment audit findings (M7–M10) fixed, RC-verified, zero reachable
vulnerabilities, docs complete. Remaining: the F-012 backlog and the final-spec re-check
after 2026-07-28.
