---
id: F-034
title: Land on the settings page after a direct login
type: feature
status: BACKLOG
size:
created: 2026-10-13
done:
depends-on:
superseded-by:
---

# F-034 — Land on the settings page after a direct login

## Intake

**Problem:** An operator who opens `/.auth/login` directly and logs in is redirected to `/` —
which belongs to the protected proxy surface and answers `{"error":"unauthorized"}`. The login
worked; the landing page is wrong, and the operator has to type the settings address by hand.
The post-login target is the page that sent the browser to the login, and it falls back to `/`
when there was none. Inherited behaviour, noticed by the operator on the passkey check after the
v0.5.0 deployment.

**Idea:** Without a stored target, land where an operator has something to do: the settings
page. The fallback is a constant in the code, never taken from the request, so this opens no
redirect an attacker could steer.

**Solution sketch:**
- One default target for all three login paths (password, passkey, OIDC callback) and for a
  stored target that fails normalisation (SPEC §1.12) — today each of those ends at `/`.
- A visit to `/.auth/login` with a session that is already logged in goes to that target as
  well, instead of showing the form again.
- State the default in SPEC §1.12, which so far only says how a stored target is normalised.
- No new endpoint, config or dependency. A patch release.

**To be analysed:** where an **OIDC** login lands. The settings page is reserved for the
gateway's own account — an OIDC-provider session is answered `403` there (SPEC §1.12) — so
sending it to the settings page would trade one error page for another. Candidates: a minimal
"signed in" page for sessions without settings access, or leaving OIDC at `/`. Likewise what the
default is when the settings page does not exist at all (no user store configured).

**Dependencies:** none.
