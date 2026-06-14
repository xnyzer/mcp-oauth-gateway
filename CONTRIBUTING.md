# Contributing to mcp-oauth-gateway

Thanks for your interest in contributing!

## Project status

mcp-oauth-gateway is in an early specification/scaffolding phase. The language and stack are not yet
decided (a build-vs-fork and Go-vs-Python decision is pending — see `PROGRESS.md` F-001/F-002), so
contributions at this stage are mostly about the spec, threat model, and decisions.

## License of contributions

This project is licensed under **Apache-2.0** (see `LICENSE`). By submitting a contribution you agree
that it is licensed under the same terms. For trivial changes no separate sign-off is required;
Apache-2.0's inbound = outbound model applies.

## Commit email policy

This repository's history is public. Commit emails must use the GitHub noreply address format:

```
<numeric-id>+<github-username>@users.noreply.github.com
```

For the maintainer this is `12890660+xnyzer@users.noreply.github.com`. Do not use a private or
corporate email address. See the `step-done` skill for verifying and correcting this before each
commit. If a real email slips into history, it has to be scrubbed with `git filter-repo` and
force-pushed — preventing is far cheaper than cleaning.

## Commit messages

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, …), imperative mood.
- Where a commit involves a design choice, describe the *why* briefly in the body
  (`Decision: X over Y because …`).
- End the body with `Co-Authored-By: Claude <noreply@anthropic.com>` when applicable.

Example:

```
feat: enforce S256 PKCE on the authorize endpoint

Reject plain code_challenge_method to remove a downgrade vector. Decision: S256-only over
allowing plain because all target clients support S256 and plain weakens the flow.

Co-Authored-By: Claude <noreply@anthropic.com>
```

## Secrets policy

Never commit secrets, tokens, passwords, private keys, private email addresses, or deployment
internals (IPs, hostnames, SSH key names, etc.). Operational internals belong in the gitignored
`private/` directory, never in the public tree. The `step-done` skill runs a secrets scan before
every commit.

## Code style

- Follow `CODING-STANDARDS.md` — it is the binding reference.
- This is a public auth boundary: no hand-rolled crypto (vetted library only), fail-closed.
- Dependencies must be permissive-licensed (no GPL/AGPL).
- Run the relevant checks for the module you touched before committing (once a stack is chosen,
  the project's typecheck/lint/test).

## Pull requests

- Target the `main` branch.
- Describe the change and the reasoning. Keep changes focused — one concern per PR.
- Security-relevant changes (token issuance, PKCE, JWKS, DCR, consent) get extra scrutiny — call them
  out explicitly in the PR description.
