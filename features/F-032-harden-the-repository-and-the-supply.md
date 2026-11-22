---
id: F-032
title: Harden the repository and the supply chain
type: feature
status: BACKLOG
size:
created: 2026-10-12
done:
depends-on:
superseded-by:
---

# F-032 — Harden the repository and the supply chain

## Intake

**Problem:** GitHub's free security features for public repositories are switched off here:
secret scanning, push protection and Dependabot security updates. The actions are pinned by
major tag rather than by commit, and nothing scans the built image — `govulncheck` covers the
Go code and standard library, not the runtime base image. F-029 was a reminder that a check
which does not look at the shipped artefact reports green regardless.

**Idea:** Switch on what costs nothing, and close the two gaps in what CI verifies. Mostly
settings and workflow changes, no product code.

**Solution sketch:**
- Enable secret scanning with push protection and Dependabot security updates in the
  repository settings (operator action, or via the API with the operator's go).
- Pin third-party actions to commit SHAs, with the version as a comment so Dependabot keeps
  them current (CODING-STANDARDS §7: pinned versions).
- Scan the built container image for known vulnerabilities in CI and on a schedule, with a
  permissively licensed scanner — the image-level counterpart to `vulncheck.yml`.
- Consider CodeQL code scanning; decide on signal versus noise before adopting it.
- **Check that Dependabot still proposes base-image digests** (from F-031d). The runtime image
  sat on a stale digest for weeks without a PR, although its tag had moved. Suspicion, unproven:
  the digest PRs for both base images (#1, #7) were closed rather than merged in August — the
  project applies bumps on `main` instead of merging — and Dependabot may not propose a digest
  for the same tag again after that. Both tags changed in F-031d (`golang:1.27-bookworm`,
  `static-debian13`), so it has new ones to track: watch whether a digest PR appears when one of
  them moves, and read Dependabot's update log if none does. If the suspicion holds, the working
  practice needs a counterpart — a scheduled check of the pinned digests, or letting Dependabot
  record a superseded PR (`@dependabot close` / `ignore`) in a way that does not silence the next.

**To be analysed:** which image scanner (licence, maintenance, false-positive rate on a
distroless static image); whether CodeQL adds anything over golangci-lint + `govulncheck`;
what exactly makes Dependabot stop proposing a digest.

**Dependencies:** none.
