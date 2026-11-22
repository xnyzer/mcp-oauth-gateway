---
id: F-019
title: Evaluate whether DCR can be switched off
type: feature
status: DONE
size:
created: 2026-08-21
done: 2026-08-22
depends-on:
superseded-by:
---

# F-019 — Evaluate whether DCR can be switched off

## History

### F-019 — Evaluate whether DCR can be switched off — DONE 2026-08-22

A decision task, and it produced exactly that: **`DCR_ENABLED` stays `true` by default.** No code,
no config default, no behaviour change — `git status` showing only `.md` files is the evidence.

**Why the question was open.** F-003 chose "CIMD-first, DCR as deprecated fallback" at a time when
the AS metadata did not advertise CIMD at all — the gap F-015 closed. Once clients could actually
choose CIMD, whether this gateway still needed DCR became a live question rather than a settled one.

**The evidence asked for exists, and answers a narrower question than the one posed.** F-017d proved
live on 2026-08-21 that Claude switches to CIMD and the DCR store stops growing. That shows *Claude*
does not need DCR. It cannot show that *no* client needs it, and the README promises any OAuth-only
MCP client, not one vendor's.

**The decisive argument post-dates the entry entirely.** F-023, the evening before, made DCR the
**documented escape hatch**: `README.md` and `CHANGELOG.md` now tell deployments hit by the
Cloudflare challenge on datacenter IPs ([claude-ai-mcp#650](https://github.com/anthropics/claude-ai-mcp/issues/650))
to set `CIMD_ENABLED=false` and fall back to DCR. With DCR defaulting to `false`, that instruction
would not merely be clumsier — it would be **broken**: an operator flipping only `CIMD_ENABLED=false`
hits the both-disabled fail-fast and their gateway refuses to start. A workaround would become an
outage.

**The original motivation was also already gone.** The DCR store grew *because* the missing
advertisement forced clients onto DCR; F-015 fixed that. Disabling DCR would have solved a problem
that no longer existed, at the cost of the rescue path.

**The deliverable is guidance, not a bare verdict.** "No change" would have wasted the analysis, so
the outcome is written where an operator will meet it:

- `README.md` gained **"Should you turn DCR off?"** — what `false` actually removes (`POST
  /.idp/register` unrouted, `registration_endpoint` gone from the metadata), when the trade is
  reasonable (only CIMD-capable clients, smaller public surface per SR-10), and two warnings: never
  combine it with `CIMD_ENABLED=false`, and any client that cannot do CIMD stops working outright
  with no partial degradation.
- `REQUIREMENTS.md` §6 records the re-decision with its date and reason **beside** F-003 rather
  than rewriting it, so the history stays readable.

**Deviation from the plan: a fourth file.** The plan named two or three; `SPEC.md` §4.1 still read
"F-019 asks whether it should default to off". Leaving that would have left the conformance table
carrying an open question this very task answered — precisely the staleness F-017c built the table
to prevent.

**Counter-argument, recorded rather than dismissed:** `/.idp/register` is an open endpoint by spec,
and removing it would shrink the public surface (SR-10). It is bounded by SR-5 — TTL, a cap enforced
atomically inside the write transaction (F-012d), rate limiting — and the F-006b audit left nothing
open there. The escape hatch outweighs it for the *default*; for a single-client deployment the
trade goes the other way, which is what the README section is for.

**Files:** `README.md`, `REQUIREMENTS.md` §6, `SPEC.md` §4.1; docs `PROGRESS.md`,
`PROGRESS-ARCHIVE.md`. The operator confirmed they are leaving their own deployment on the default.

**Verification:** only `.md` files touched; `DCR_ENABLED` unchanged in `main.go` and `.env.example`;
all relative links and every README anchor resolve; gitleaks clean.
