# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/spec/v2.0.0.html). **Schema migrations and config changes are
called out explicitly** (SPEC §2.5) — read them before upgrading. Downgrades are unsupported.

## [Unreleased]

### Security

- **OIDC allow-list patterns no longer match more than they say.** `OIDC_ALLOWED_USERS_GLOB` and
  `OIDC_ALLOWED_ATTRIBUTES_GLOB` are matched by `gobwas/glob` 1.0, whose engine is a rewrite. The
  old one (0.2.3) was over-permissive in two ways, both of which could admit an identity the
  pattern does not describe:
  - **Literals on both sides of a `*` could share characters.** `admin*n@corp.example` matched
    `admin@corp.example`, and `admin*admin` matched a single `admin`.
  - **`?` and negated classes matched the empty value**, although each stands for exactly one
    character.

  Only deployments that log in through OIDC **and** use a glob allow-list are affected; OIDC is
  off by default. If you use such patterns, read the upgrade note below.

- **OIDC login now requires an allow-list.** With OIDC enabled and none of the four
  `OIDC_ALLOWED_*` settings set, **every account the provider authenticates could log in as the
  operator** — with a provider anyone can sign up to, everyone. Leaving the settings out was
  enough, and so was an empty variable (`OIDC_ALLOWED_USERS=${UNSET}`). The gateway now refuses
  to start in that state. Admitting every account remains possible, but has to be written down:
  `OIDC_ALLOWED_USERS_GLOB=*`. A provider that somehow holds no rule denies instead of admitting.

- **A misread OIDC allow-list no longer turns into "no restriction".** The four
  `OIDC_ALLOWED_*` settings used to drop whatever they could not read: an attribute rule without
  `=`, one without a value, a list that held only commas. With no rule left, the allow-list was
  empty — and an empty allow-list lets **every** account of the provider log in. A typo in the
  only rule was therefore enough to open the gateway to the whole provider. Such an entry now
  stops start-up, with a message naming the setting and the entry.

### Changed

- **Breaking, if you log in through OIDC: set an allow-list before you upgrade.** A gateway
  with `OIDC_CONFIGURATION_URL`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` set and no
  `OIDC_ALLOWED_*` rule **no longer starts**; the message names the four settings. Decide who
  should get in and set a rule — or, to keep exactly what you had, `OIDC_ALLOWED_USERS_GLOB=*`.
  Deployments without OIDC (the default) are not affected.

- **Upgrade note for OIDC glob patterns — check them before you upgrade.** Beyond the two matching
  fixes under *Security*, 1.0 differs from 0.2.3 in four more ways:
  - **A malformed pattern now stops the gateway at start-up.** An unclosed `{` (as in
    `{alice,bob`) or a trailing backslash used to be accepted and read as if it had been
    well-formed; it is now an error, and the message names the pattern. That is deliberate — a
    rule in an authorization decision should not be guessed at — but it means a typo that went
    unnoticed until now keeps the new version from starting.
  - **A non-ASCII character counts as one character.** `user?@example.com` now matches
    `userü@example.com`; before, `?` and character classes failed on anything outside ASCII. A
    pattern can therefore match values it used to miss.
  - **Empty braces no longer crash a login.** A pattern such as `a{}` made the match panic at
    login time; it now matches as if the braces were absent.
  - **An empty alternative is honoured everywhere.** `{dev,}{ops,}-lead` now matches `-lead`
    and `*{a,}` the empty value; before, the empty choice was lost when it stood next to a `*`
    or to another brace group. Again a pattern can match values it used to miss.

  Everything else in glob matching behaves as before: a pattern is matched against the whole
  value, matching is case-sensitive, and `*` has no separator — it spans every character, `@`,
  `.` and `/` included. Measured, not assumed: the two engines were run side by side over 9,512
  generated patterns and 1,555 values each, and every difference traces back to one of the six
  points named here.

- **Built with Go 1.27, on a new runtime base image.** The toolchain moves from 1.26.9 to 1.27.2
  and the runtime image from `distroless/static-debian12` to **`distroless/static-debian13`** —
  the Debian 12 flavour is no longer updated by the distroless project, so staying on it would
  have meant a base image that stops receiving fixes. Nothing to do when upgrading: the image
  still runs as non-root uid 65532, so existing named volumes and bind mounts keep their
  ownership, and it still has no shell, package manager or interpreter.

- **The stdio backend speaks MCP 2026-07-28 (`mcp-go` 1.x).** Only deployments whose upstream is a
  *command* rather than a URL are affected; the transparent backend forwards bytes and is
  unchanged. Towards the upstream the gateway now tries the stateless protocol first
  (`server/discover`) and falls back to the `initialize` handshake for an upstream that predates
  it, down to 2024-11-05. Towards clients it serves 2026-07-28 and, for clients that still perform
  the handshake, the earlier revisions back to 2025-03-26. The two sides are independent, so a
  current client reaches the tools of an older upstream.

  **One thing to expect:** an older stdio upstream that *ignores* unknown methods, instead of
  rejecting them, makes the gateway wait five seconds at start-up before it falls back. A
  well-behaved one costs nothing. What the backend speaks in each case is recorded in
  [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md).

- **Upgrade note for all four `OIDC_ALLOWED_*` settings.** The gateway refuses to start when
  - an entry of `OIDC_ALLOWED_ATTRIBUTES` or `OIDC_ALLOWED_ATTRIBUTES_GLOB` is not
    `/pointer=value` — no `=`, no value, or a key that does not start with `/`;
  - a setting is set but holds no entry (only commas or spaces);
  - a pattern does not parse. If that pattern contains `{` or `}`, the cause is usually the list
    syntax rather than a typo: **commas separate entries, so a comma inside a pattern is written
    `\,`** — `{alice\,bob}@example.com`. Unescaped, the pattern arrives in two halves; 0.2.3
    silently accepted each half as a pattern of its own.

  A trailing comma and stray spaces are still fine. The syntax is now documented in the README
  under *OIDC allow-lists*.

## [0.4.2] — 2026-10-12

### Added

- **The settings page shows which version is running (F-030).** The footer of `/.auth/settings`
  names the build, so after an update you can confirm in the browser that the new image is
  live instead of running `--version` inside the container. It is visible only behind your
  login: `/healthz` and every other public endpoint still disclose no version, because that
  would tell an anonymous caller which advisories apply. No schema or config change.

## [0.4.1] — 2026-10-12

### Security

- **Built with Go 1.26.9 (was 1.26.7).** The 0.4.0 image carries 11 standard-library advisories
  reachable from the gateway, fixed in 1.26.9: `net/http` over HTTP/1 and HTTP/2, on the server
  and on the transport to the upstream (GO-2026-6617, -6613, -6612, -6611, -6610, -6605, -6603),
  `net/textproto` (GO-2026-6608), `crypto/tls` (GO-2026-6607) and `html/template`, which renders
  the login and consent pages (GO-2026-6600, -6599). **Upgrade recommended.** No schema or config
  change.
- **`golang.org/x/net` 0.61.0** (was 0.58.0): five reachable HTTP/2 advisories (GO-2026-6603,
  -6610, -6611, -6612, -6617).
- **`google.golang.org/grpc` 1.83.2** (was 1.83.1): GO-2026-6443. Not reachable — the gateway runs
  no gRPC server — but bumped so the alert closes.
- **The weekly vulnerability scan now covers the toolchain that is shipped.** It had been checking
  the standard library of the latest Go release instead of the pinned one, which is how the
  advisories above went unreported.

## [0.4.0] — 2026-08-24

### Added

- **Name a connection when you authorize it (F-025).** The consent page now offers an optional
  name for the connection, prefilled with the `client_name` the client declares about itself. What
  you type identifies that connection in the client list and appears in the `token_issued` and
  `revoked` auth events, so the log reads in your words instead of in client ids.

  The name is stored with the authorization itself, not in a list of its own — so it is deleted
  when you revoke, and re-authorizing asks again. **No schema change**, and no client can set it:
  the value rides the session the gateway builds server-side.

  This also closes a requirement the gateway's own `SPEC.md` §1.5 had carried unmet since it was
  written: consent had to show the client's declared name, and both registration mechanisms parsed
  that name and threw it away. It is shown as prefill, while the verified client id, redirect URI
  and scopes remain the identity the page is judged on.

- **Operator view of connected clients, with a kill switch (F-024).** `/.auth/settings` now lists
  every client that holds access — its authorizations, token-record counts, redirect hosts and
  activity times — and revokes it: one client, one authorization, or everything at once behind a
  confirmation. This closes a gap `/.idp/revoke` cannot: RFC 7009 is client-authenticated, so it
  lets a client drop its *own* token and never lets you drop someone else's. Before this, taking
  access away meant stopping the gateway and editing its data store by hand.

  **A revoke takes effect on the client's next request**, not after the access token's remaining
  lifetime, because access is decided by the token record still existing (SPEC §2.4). Verified
  live: a client whose access was revoked was refused **44 seconds later**, with
  `ACCESS_TOKEN_TTL` at one hour.

  Two properties worth knowing before you use it. **Entries are per client and per authorization,
  never per device** — every device signed into the same client shares one client id, and token
  records carry no IP or user agent, so "log out my old phone" is not expressible. And **a revoke
  bans nobody**: a client identified by a metadata document (CIMD) keeps no server-side
  registration, so revoking destroys its tokens and it may authorize again — which requires your
  login. The operator's own account, passkeys and session are never touched, including by "revoke
  everything".

  New: `POST /.auth/settings/clients/revoke`, `.../clients/grants/revoke`,
  `.../clients/revoke-all` (session-gated, CSRF-checked). Every revoke emits the `revoked` auth
  event with actor, scope and record count, so an operator kill is distinguishable in the log from
  the client-initiated ones. **No schema change** — the listing aggregates existing token records,
  so a store from an earlier version needs no migration.

### Changed

- **Documentation restructured (F-026, F-027) — no behaviour change.** `REQUIREMENTS.md` is gone:
  its FR/GR/SR requirement register now lives in [`SPEC.md`](SPEC.md) §5, with every identifier
  unchanged. `SPEC.md` lost the implementation history it had accumulated (15 "Delta" paragraphs,
  108 lines naming internal task numbers) and reads as a contract throughout; its option tables in
  §3 were a duplicate of the README configuration reference and now state only what is normative.

  The MCP conformance record moved out of `SPEC.md` §4 into
  [`docs/MCP-CONFORMANCE.md`](docs/MCP-CONFORMANCE.md) — it is a verification result, not a
  contract. A short §4 stays behind and points there, so existing references keep working.

  `README.md` now separates the **rules** (`SPEC.md`, `CODING-STANDARDS.md`, `THREAT-MODEL.md`)
  from the **records**, and names `CODING-STANDARDS.md` and `CONTRIBUTING.md`, which its index had
  omitted.

- **Internal restructuring, no behaviour change (F-022, F-028).** Six files were past the
  project's 500-line limit, the largest at 1035; none is now. `pkg/mcp-proxy/main.go` went from
  949 lines to 312 and its `Run` from 645 to 27, split into configuration, dependencies, wiring
  and server lifecycle. The end-to-end suite no longer assembles a second gateway of its own — it
  drives the binary's startup path, so it now covers the session cookie's encryption, `HttpOnly`
  and `SameSite` (SPEC §1.12), which the parallel construction had silently stopped matching. A
  diff between this tag and the last shows a large amount of moved code for that reason;
  the moves were verified by comparing declaration sets and test sets rather than by review alone.

- **A reference guard runs in CI.** `docs_refs_test.go` resolves every `SPEC §…` /
  `CODING-STANDARDS §…` pointer, every FR/GR/SR identifier and every relative documentation link
  in the repository, so a renamed section or a deleted document fails the build instead of leaving
  dead references behind. No new dependency.

### Removed

- `REQUIREMENTS.md` (dissolved into `SPEC.md` §5, see above) and `docs/README.md` (an unwritten
  stub whose three planned pages have long existed as README sections). If you linked to either,
  link to [`SPEC.md`](SPEC.md) or [`README.md`](README.md) instead.

## [0.3.0] — 2026-08-22

### Added

- **`Origin` validation (SR-9).** A request whose `Origin` header names anything other than the
  `EXTERNAL_URL` origin is now answered `403`, which is what stops a page loaded elsewhere from
  driving the gateway through a victim's browser (DNS rebinding). The Streamable HTTP transport has
  required this since protocol version **2025-03-26**; the gateway never implemented it, and the
  F-006b audit missed it. Recorded as an unmet MUST in `SPEC.md` §4.2 since v0.2.0 — now satisfied.

  A request **without** an `Origin` header passes, deliberately and as the specification intends:
  server-side MCP clients send none, so treating absence as a violation would reject every real
  client. `Origin: null` — sandboxed iframes, `file://`, some redirect chains — counts as present
  and invalid. Comparison is on scheme, host and port, with the host lower-cased and default ports
  elided. `GET /healthz` is registered ahead of the check and stays reachable regardless.

  New `ORIGIN_CHECK_ENABLED` (default `true`) turns it off for deployments it breaks; the disabled
  state is logged at startup.

### Documentation

- **`DCR_ENABLED` re-confirmed as `true` by default**, and the README now says when *you* might
  want to change that. Dynamic Client Registration was reconsidered once clients actually started
  choosing CIMD: turning it off shrinks the public surface by one open endpoint and suits a
  deployment that serves only CIMD-capable clients. It stays on by default because it is the
  documented rescue when a client's metadata document cannot be fetched — and because disabling
  both mechanisms makes the gateway refuse to start, a `false` default would turn that rescue into
  an outage. New README section "Should you turn DCR off?"; the decision was recorded beside the
  original one in the decision list of the then-separate `REQUIREMENTS.md` (dissolved in F-026;
  the rationale lives in `PROGRESS-ARCHIVE.md`).
- `SPEC.md` §4 now records **no unmet requirement**: the `Origin` row that carried a ✘ since v0.2.0
  reads satisfied.

### Changed

- Dependencies: `jaeger-idl` 0.11.1. CI actions: `actions/setup-go` v7 and
  `softprops/action-gh-release` v3 — the latter is the step that publishes this release, so it runs
  here for the first time.

### Upgrade notes

- **Check that `EXTERNAL_URL` matches what your browser address bar shows before upgrading.**
  Browsers send `Origin` on same-origin POSTs too, so the operator login and consent POSTs on
  `/.auth/*` now carry it. If you reach the gateway under a second hostname, by IP, or on a
  different port, those POSTs are refused with `403` and you cannot log in. Every rejection is
  logged at WARN with the offending *and* the expected origin, so the cause is one log line;
  `ORIGIN_CHECK_ENABLED=false` is the rescue. MCP clients are unaffected — they send no `Origin`.

## [0.2.1] — 2026-08-21

Hotfix for a defect that v0.2.0 made reachable: with CIMD finally advertised, real clients chose
it — and the gateway then refused them.

### Fixed

- **CIMD client documents are no longer rejected for declaring a grant type this server does not
  offer.** A Client ID Metadata Document is published once and presented to *every* authorization
  server, so it names the union of the client's abilities: Claude's lists
  `urn:ietf:params:oauth:grant-type:jwt-bearer` beside `authorization_code` and `refresh_token`.
  The gateway validated that list against its own supported set and rejected the whole client
  (`invalid CIMD client ID: unsupported grant_type …`), so the authorization request failed with
  `invalid_client` and the connector could not complete. Declared `grant_types` and
  `response_types` are now **narrowed** to what this server supports; a document leaving nothing
  supported is still rejected. Narrowing is fail-closed — a client only ever ends up with a subset
  of what it asked for. **DCR stays strict**, because a registration request is addressed to this
  server alone.

  The gap was latent until v0.2.0: before F-015 the metadata never advertised CIMD, so clients
  used the deprecated DCR path and never exercised this code with a real document.

### Known limitations

- **Fetching a CIMD document can fail from datacenter IPs.** `https://claude.ai/oauth/mcp-oauth-client-metadata`
  is reported to answer server-side fetches from datacenter ranges with a Cloudflare challenge
  (HTTP 403) rather than the document
  ([anthropics/claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650)). Nothing
  a server-side OAuth implementation can solve. Deployments affected by it can set
  `CIMD_ENABLED=false` to fall back to DCR.

## [0.2.0] — 2026-08-21

Closes the standing MCP-spec watch item and ships the fixes for two real connection problems.
Minor rather than patch: F-015, F-016 and the `PROXY_HEADERS` change below each alter behaviour
rather than only repairing a defect.

### Added

- **Loopback redirect URIs now match port-agnostically for the `localhost` hostname**, not only
  for the IP literals `127.0.0.1`/`[::1]`. RFC 8252 §7.3 requires an authorization server to
  accept any port on a loopback redirect, because a native client gets its port from the OS per
  session; §8.3 discourages the hostname form, but native clients use it — so a client
  registering `http://localhost/callback` and redirecting to `http://localhost:54321/callback`
  was rejected while the `127.0.0.1` form of the same request succeeded. Scheme, host, path and
  query must still match exactly, and the tolerance covers `localhost` alone, not `*.localhost`.
- **The consent page warns when a client's redirect URIs are all loopback addresses** — the
  application runs on the operator's own device, and any local program could have claimed that
  port. Recommended by the MCP authorization spec.
- **The AS metadata now advertises `client_id_metadata_document_supported`** (SPEC §1.2), driven
  by whether a CIMD resolver is configured. §1.3 has declared CIMD the primary
  client-identification mechanism since F-005c, but the metadata never announced it — and
  clients select CIMD only when the metadata advertises it *and* offers `none` in
  `token_endpoint_auth_methods_supported`. Without the flag, every client fell back to the
  deprecated DCR path, which registers a fresh client per connection and eventually meets
  `DCR_MAX_CLIENTS`. Served on the OIDC discovery mirror alike.

### Security

- **Client-supplied copies of configured `PROXY_HEADERS` are now dropped before the gateway
  injects its own value.** Previously each configured header was appended without deleting an
  inbound copy first — and because appended values keep their order, a client sending the same
  header name landed *in front of* the injected one, where an upstream reading the first value
  would find the client's instead of the configured upstream credential. Only `Authorization`
  was special-cased. Always reachable in principle; the 2026-07-28 transport makes it routine by
  mirroring tool parameters into client-set `Mcp-Param-*` headers, so the gap moved from
  theoretical to something ordinary traffic walks past. `HEADER_MAPPING` was never affected.
- **Go toolchain raised to 1.26.7** — in `go.mod` and in the digest-pinned builder image alike —
  clearing six standard-library advisories reachable from our code: `html/template`
  (GO-2026-6091, login/consent rendering), `crypto/tls` (GO-2026-6090), `net/http`
  (GO-2026-6089), `net/url` (GO-2026-6218, redirect following on the proxy path),
  `encoding/asn1` (GO-2026-5972, signing-key parsing), and `x/net/idna` via `net/http`
  (GO-2026-5026).
- **Vulnerable indirect modules bumped:** `golang.org/x/text` 0.37.0 → 0.41.0 (GO-2026-5970,
  infinite loop on invalid input) and `google.golang.org/grpc` 1.80.0 → 1.83.1 (GO-2026-6061);
  `golang.org/x/crypto` moves 0.52.0 → 0.55.0 in the same step. `govulncheck` reports **zero
  reachable vulnerabilities** afterwards.
- **Dependabot now covers indirect Go modules** (`allow: dependency-type: all`), grouped into a
  single weekly PR. Version updates previously tracked only dependencies declared explicitly in
  `go.mod` — which is why both module advisories above went unnoticed until the weekly
  `govulncheck` run started failing on 2026-07-27.

### Changed

- **Verified against the final MCP authorization spec 2026-07-28**, closing the watch item that
  had stood since the release candidate. The authorization surface needed no change — all six
  authorization SEPs remain satisfied and CIMD-first with a DCR fallback still matches the spec,
  which now formally deprecates DCR. Conformance is recorded requirement by requirement in
  **`SPEC.md` §4**, including what belongs to the upstream and what does not apply.
- **`mark3labs/mcp-go` 0.50 → 0.58**, which required migrating the stdio backend's logging to
  `log/slog` (the library dropped its own logger interface). Adds `go.uber.org/zap/exp` for the
  bridge; it pulls in no new transitive dependency.

### Known limitations

- **`Origin` is not validated.** The Streamable HTTP transport has required this since protocol
  2025-03-26 and the gateway never implemented it. Mitigated but not closed: `/mcp` is
  bearer-protected and the operator surface carries CSRF tokens plus `SameSite=Lax`, so a
  **loopback deployment** is the exposed case. See `SPEC.md` §4.2.
- **The stdio backend speaks protocol 2025-11-25**, because `mcp-go`'s stable line does; only its
  v1.0.0 pre-release implements 2026-07-28. The transparent backend, the documented primary mode,
  is unaffected.

### Upgrade notes

- **Check `PROXY_HEADERS` before upgrading.** If any deployment relies on *clients* supplying a
  header whose name is also listed in `PROXY_HEADERS`, that client value is now dropped rather
  than forwarded alongside the configured one. Intended setups — where the gateway injects an
  upstream credential the client never sees — are unaffected and get stricter.
- **No schema or config migration.** No env var changed name, meaning or default.

## [0.1.1] — 2026-07-09

Security-hardening patch: the low-severity follow-ups from the F-006b adversarial audit
(none a vulnerability on their own — defence-in-depth, fail-fast, and hygiene). Delivered as
F-012a–d; see `PROGRESS-ARCHIVE.md` for the per-finding rationale.

### Added

- **Per-session anti-CSRF token** on every state-changing operator POST (login, consent, both
  settings POSTs, and all WebAuthn ceremonies): a 32-byte `crypto/rand` token in the signed
  session, checked in constant time — defence-in-depth on top of `SameSite=Lax`.

### Changed

- **PKCE is now enforced for _every_ client**, including confidential DCR clients (previously
  public/CIMD clients only) — closes the SPEC §1.5 delta; metadata already advertised S256-only.
- **Passkey login is now discoverable** (`BeginDiscoverableLogin`, empty allow-list), so the
  public `login/begin` response no longer enumerates the operator's credential IDs to anonymous
  callers; new passkey registrations require a **resident** key.
- **Operator session cookie is signed _and_ encrypted** with HKDF-derived auth+AES-256 subkeys,
  separate from the Fosite token secret (which is unchanged).
- **DCR registration cap is enforced atomically** inside the write transaction (no
  count-then-insert TOCTOU); an over-cap registration returns `503 temporarily_unavailable`.
- **Startup fails fast** on malformed boolean env vars and on RSA signing keys smaller than
  **2048 bits** (`JWT_PRIVATE_KEY`, adopted legacy keys, and manifest keys alike).
- Login-flow uniformity/robustness: an empty password takes the same bcrypt path and
  byte-identical error as a wrong one; the multi-hash bcrypt comparison runs in constant time
  (no early break); logout clears the whole session and expires the cookie; the stored
  post-login redirect target is validated same-origin.
- SQLite backend opens with `SetMaxOpenConns(1)` and `busy_timeout`/WAL/`synchronous=NORMAL`/
  `foreign_keys=ON` pragmas (serialised writes, fewer "database is locked" errors).

### Security

- Proxy JWT verification now requires `exp` to be present (`WithExpirationRequired`).
- Redirect-following on the proxy path caps buffered bodies at 4 MiB (larger bodies stream;
  a redirect is passed through untouched).
- CIMD documents are held to the same grant/response-type whitelist as DCR registrations.

### Upgrade notes

- **One-time operator re-login.** The session-cookie format changed (now encrypted); existing
  operator sessions are invalidated once. Issued access/refresh tokens are **unaffected** (Fosite
  keeps the raw secret).
- **Startup is now stricter.** Fix any malformed boolean env vars and replace RSA signing keys
  below 2048 bits **before** upgrading, or the gateway will refuse to start.
- **Passkeys must be resident (discoverable).** Passkeys stored in a synced keychain
  (e.g. iCloud Keychain) are resident and keep working. A **non-resident** passkey enrolled
  before v0.1.1 can no longer complete login; rescue by deleting the passkey records in
  `DATA_PATH`, which re-activates the password fallback (SPEC §1.12 lockout-rescue), then
  re-enrol.

## [0.1.0] — 2026-07-08

Initial public release. `mcp-oauth-gateway` is a hard fork of
[`sigbit/mcp-auth-proxy`](https://github.com/sigbit/mcp-auth-proxy) (see [`FORK.md`](FORK.md));
everything below is relative to that base.

### Added

- **CIMD client identification** (MCP spec 2025-11-25, primary mechanism) with dial-time
  SSRF guards, size/time limits and caching; DCR kept as the deprecated fallback with
  TTL/cap/validation and a `DCR_ENABLED` switch.
- **Complete discovery/401 surface:** RFC 9728 PRM, full RFC 8414 AS metadata,
  `WWW-Authenticate` challenge, RFC 9207 `iss`, optional OIDC-discovery mirror.
- **Token binding & lifecycle:** RFC 8707 `resource`→`aud` binding, `jti`/`client_id`/`scope`
  claims, revocation endpoint (RFC 7009) with a fail-closed proxy-side revocation check,
  configurable TTLs, storage sweeper.
- **Key management:** key directory with atomic manifest, RS256/ES256, automatic interval
  rotation with a retiring window (outstanding tokens stay verifiable), multi-key JWKS,
  manual `rotate-key` ops command.
- **Passkey/WebAuthn operator login** with a session-gated settings page; the password
  fallback can be disabled (env hash stays as break-glass rescue).
- **Abuse protection:** per-IP rate limits on register/token/login/authorize, account
  lockout, structured auth events (`login_ok`, `login_fail`, `token_issued`, `register`,
  `rate_limited`, `revoked`).
- **Consent screen** showing the requesting client's identity and scopes.
- **Packaging:** digest-pinned non-root distroless image with a built-in healthcheck
  (`healthcheck` subcommand), multi-arch (amd64/arm64) GHCR releases, `.env.example`,
  health-gated Compose example, `setup.sh` quickstart.

### Changed (relative to the forked base)

- Rebranded to `mcp-oauth-gateway`; bundled Google/GitHub login providers removed (generic
  OIDC stays, off by default).
- Hardened against the findings of an adversarial security audit (0 critical / 1 high /
  9 medium — all fixed; see `PROGRESS-ARCHIVE.md` F-006b/F-007a/F-007b): consent client
  identity, CIMD SSRF denylist, fail-closed `/revoke`, `X-Forwarded-*` spoof protection,
  CIMD cache bound + authorize rate limit, lockout re-arm DoS, no internal-error disclosure,
  bare-IP `TRUSTED_PROXIES` normalisation, http-issuer startup warning, TLS-aware cookie
  `Secure` flag, Slowloris `ReadHeaderTimeout`, `0700` data dir.
- Container image runs as non-root **without interpreters** — stdio upstreams that need
  `npx`/`uvx` now run as a separate service or custom image.
- Image default ports are non-privileged: `LISTEN=:8080`, `TLS_LISTEN=:8443` (publish host
  80/443 onto them).

### Security

- Release-gate `govulncheck` run: bumped `golang.org/x/net` to v0.55.0 (GO-2026-5026),
  `quic-go` to v0.59.1 (GO-2026-5676) and the Go toolchain to 1.26.5 (GO-2026-5856) — all
  three were reachable; zero reachable vulnerabilities at release.
- Verified against the MCP **2026-07-28 specification release candidate**: all six
  authorization-hardening SEPs are satisfied (RFC 9207 `iss` supplied on success+error;
  DCR accepts native/localhost redirect URIs per RFC 8252 and tolerates `application_type`;
  refresh tokens issued independent of an `offline_access` scope; issuer-bound tokens;
  no-path issuer makes the `.well-known` suffix forms equivalent). Re-check planned when
  the final spec publishes on 2026-07-28.

### Upgrade notes

- **No compatibility with `sigbit/mcp-auth-proxy` data directories** (hard fork; the
  storage namespace changed). Start with a fresh `DATA_PATH`.
- First start generates signing keys and the HMAC secret into `DATA_PATH`; a pre-F-005d
  single `private_key.pem` is adopted automatically (kid preserved).
