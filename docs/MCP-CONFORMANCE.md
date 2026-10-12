# MCP 2026-07-28 conformance record

Requirement-by-requirement result of checking the gateway against the **final MCP authorization
specification 2026-07-28**. This is a **verification record, not a contract** — the contracts it
was checked against live in [`../SPEC.md`](../SPEC.md). Re-checking against a newer revision means
walking these tables rather than re-deriving conformance from prose.

> Recorded requirement by requirement so the **next** revision can be walked against a table
> instead of re-derived from prose. Client-side obligations are omitted: this gateway is an
> authorization server and a resource server, never an MCP client.

## 1. Authorization

| Requirement | Level | Status |
|---|---|---|
| AS implements OAuth 2.1 for confidential **and** public clients | MUST | ✔ Ory Fosite; PKCE/S256 enforced for every client (SPEC §1.5) |
| AS supports Client ID Metadata Documents | SHOULD | ✔ `pkg/cimd` (SPEC §1.3), advertised as `client_id_metadata_document_supported` (SPEC §1.2) |
| DCR kept only for backwards compatibility | MAY | ✔ optional, disableable via `DCR_ENABLED` (SPEC §1.4). The default stays `true`: DCR is the documented rescue when a client's CIMD document cannot be fetched, so defaulting it off would break that path. An individual deployment serving only CIMD-capable clients may still disable it |
| Resource server implements PRM (RFC 9728) | MUST | ✔ SPEC §1.1 |
| AS provides RFC 8414 **or** OIDC Discovery | MUST | ✔ both (SPEC §1.2) |
| `iss` in the authorization response (RFC 9207) | SHOULD | ✔ SPEC §1.5 |
| An AS that emits `iss` advertises `authorization_response_iss_parameter_supported` | MUST | ✔ `true` (SPEC §1.2) — conditional on emitting `iss`, which this AS does |
| Access tokens validated per OAuth 2.1 §5.2 | MUST | ✔ SPEC §1.11.1 |
| Audience validated per RFC 8707 §2 | MUST | ✔ `aud` bound to the granted resource (SPEC §1.7), checked on every proxied request |
| Invalid or expired token → HTTP 401 | MUST | ✔ SPEC §1.11.2, fail-closed (SR-3) |
| Only tokens valid for the server's own resources accepted; no others transited | MUST | ✔ `iss` and `aud` both pinned to `EXTERNAL_URL`; the client's bearer is not forwarded unless `PROXY_FORWARD_AUTHORIZATION=true` |
| Appropriate HTTP status codes for authorization errors (401 / 403 / 400) | MUST | ✔ 401 per SPEC §1.11.2; 400 on a malformed authorization request (Fosite); the 403 case is scope-only here and cannot arise (§3) |
| Scope hierarchies accounted for when judging a token sufficient | MUST | **Not applicable by design** (§3) — no scopes exist to form a hierarchy |
| `offline_access` absent from PRM `scopes_supported` | SHOULD NOT | ✔ absent (§3) |
| `scope` in the `WWW-Authenticate` challenge | SHOULD | **Not applicable by design** (§3) |
| 403 + `insufficient_scope` on runtime scope errors | SHOULD | **Not applicable by design** (§3) |

## 2. Streamable HTTP transport

The gateway proxies transparently and never parses a JSON-RPC body, so most transport
requirements land on the upstream. These rows say which is which — the distinction is the point,
because "the upstream owns it" is only an answer while the gateway provably forwards enough for
the upstream to comply.

| Requirement | Level | Owner | Status |
|---|---|---|---|
| Intermediaries forward unrecognised `Mcp-Param-{Name}` headers and otherwise ignore them | MUST | **gateway** | ✔ `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` reach the upstream unchanged and exactly once, asserted by test |
| A client must not be able to shadow an injected upstream credential | SR-7 | **gateway** | ✔ SPEC §1.11.4 |
| `Origin` validated; 403 when present and invalid | MUST | **gateway** | ✔ a foreign or `null` origin is refused with 403; an absent header passes, as the specification intends (SPEC §0). Disableable via `ORIGIN_CHECK_ENABLED` for deployments the check breaks |
| Authentication on all connections | SHOULD | **gateway** | ✔ the gateway's entire purpose |
| Server implements `server/discover` | MUST | upstream | n/a — a JSON-RPC method, not a path. The reserved-namespace guard matches URL path prefixes only and cannot swallow it (asserted by test). With a stdio upstream the gateway is the server and answers it itself (see below) |
| Header values validated against the body (`HeaderMismatch`, `-32020`) | MUST | upstream | n/a — the gateway does not parse bodies |
| GET/DELETE on the MCP endpoint → 405 | SHOULD | upstream | n/a; with `HTTP_STREAMING_ONLY=true` the gateway answers GET-SSE with 405 itself (SPEC §1.11.3) |
| `Mcp-Session-Id` ignored, no session minted or echoed | — | upstream | n/a — the gateway never minted one |
| `Last-Event-ID` ignored, streams not resumable | — | upstream | n/a |
| `X-Accel-Buffering: no` on SSE responses | SHOULD | upstream | passed through; the gateway adds no buffering of its own (`FlushInterval: -1`, SPEC §1.11.3) |

## 3. Recorded limitations

**The gateway is scope-less by design.** It issues no scopes, `scopes_supported` is `[]`, and no
operation it guards is gated on one. The `scope` challenge and the `insufficient_scope` flow
therefore have nothing to express: a challenge naming required scopes would name none, and every
valid token is already sufficient for everything the gateway itself decides. Authorization *inside*
the upstream stays the upstream's business — that is the defence-in-depth split of SR-7. Should
per-operation authorization ever be wanted here, the two "not applicable" rows in §1 become work
rather than notes.

**The stdio backend speaks protocol 2026-07-28, and bridges to what came before it.** A
`PROXY_TARGET` given as a command (SPEC §3.1) drives the upstream through `mark3labs/mcp-go` 1.x,
which implements the stateless protocol core — `server/discover`, the protocol version carried in
every request's `_meta`, no `initialize` handshake. Unlike the transparent backend, this path
terminates MCP on both sides, so it holds two protocol versions, negotiated independently:

| Side | What happens | Version in effect |
|---|---|---|
| towards the upstream | `server/discover` first; an upstream that has it | **2026-07-28** |
| | an upstream without it — falls back to `initialize`, asking for 2025-11-25 | whatever the upstream answers: **2025-11-25, 2025-06-18, 2025-03-26 or 2024-11-05** |
| | an upstream answering a version nobody knows | refused at start-up |
| towards the client | a client on the current protocol | **2026-07-28** |
| | a client that still performs the handshake | the version it asks for, back to **2025-03-26** |

The two sides do not have to match: a client on 2026-07-28 reaches the tools of an upstream that
only speaks 2025-06-18, with the backend translating.

**One start-up cost.** An older upstream should reject `server/discover` with "method not found",
and then the fallback is immediate. One that ignores unknown methods answers nothing; the probe is
bounded at five seconds, after which the backend falls back. Such an upstream therefore starts
five seconds later than it did before, once.

Evidence: `pkg/backend/proxy_protocol_test.go` names each of these versions as a literal and fails
if a library update moves one — against a real current server and a hand-written older one, in
both directions, including a tool call across the bridge.

**The transparent backend — the documented primary mode — is unaffected**, because it
forwards bytes and holds no protocol opinion.
