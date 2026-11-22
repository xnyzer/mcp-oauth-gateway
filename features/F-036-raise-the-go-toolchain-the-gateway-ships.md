---
id: F-036
title: Raise the Go toolchain the gateway ships with
type: fix
status: BACKLOG
size:
created: 2026-11-22
done:
depends-on:
superseded-by:
---

# F-036 — Raise the Go toolchain the gateway ships with

## Intake

**Problem:** The released binary is built with the toolchain go1.27.2, and govulncheck reports two
standard-library vulnerabilities the code reaches: **GO-2026-6859**, an HTTP/1 server crash from a
`MaxBytesReader` header race in `net/http` — reachable through the gateway's own server, so a remote
crash of a public auth boundary — and **GO-2026-6809**, compromised intermediate certificates not
distrusted in `crypto/x509`, reachable through every outbound TLS call (CIMD fetch, OIDC, upstream).
The `vulncheck` workflow has been red since its scheduled run on 2026-11-16.

**Goal:**
- *Is:* v0.5.0 and `main` build with go1.27.2; govulncheck finds 2 reachable vulnerabilities (fixed
  in go1.27.3 and go1.27.4); the deployment runs 0.5.0.
- *Should:* the toolchain that builds, tests and ships the gateway is at least go1.27.4,
  govulncheck reports nothing reachable, a patch release is out and deployed.
- *Reproduce:* the `vulncheck` workflow, or govulncheck locally under the toolchain of `go.mod`.

**Solution sketch:**
- Move the three pins together, as the project rule requires: the `toolchain` line of `go.mod`,
  the exact `go` pin in `mise.toml`, and the digest-pinned `golang:1.27` builder image (a digest
  that carries the new release). The `go` line stays.
- Prove it on the shipped artefact, not only on the source: govulncheck under the new toolchain,
  and the Go version embedded in the binary of the built image — the lesson of F-029.
- A patch release through the tag → release workflow, the two advisories in the changelog, then
  the proven deployment routine; the signing key carries over, so clients keep their tokens.

**Dependencies:** none.

**To be analysed:** the three vulnerabilities in imported packages and the one in a required module
that govulncheck reports as not called — which modules, whether they are F-033's frozen exporters,
and whether a module bump closes them as well. Whether F-034 joins the same patch release — only if
it does not delay this fix.
