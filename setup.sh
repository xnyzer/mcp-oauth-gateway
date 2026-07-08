#!/usr/bin/env bash
# Quickstart for mcp-oauth-gateway: generates the operator bcrypt hash and
# writes .env from .env.example. Universal steps only — firewalling and
# reverse-proxy wiring are documented in the README, not scripted.
set -euo pipefail

cd "$(dirname "$0")"

if [[ -e .env ]]; then
  echo "ERROR: .env already exists — refusing to overwrite it." >&2
  echo "Remove or rename it first, then re-run ./setup.sh" >&2
  exit 1
fi
if [[ ! -f .env.example ]]; then
  echo "ERROR: .env.example not found (run from the checkout/release directory)." >&2
  exit 1
fi
if ! command -v docker > /dev/null; then
  echo "ERROR: docker is required (used to generate the bcrypt hash and to run the gateway)." >&2
  exit 1
fi

# ── Public base URL ────────────────────────────────────────────────────────
read -r -p "Public base URL (OAuth issuer, e.g. https://mcp.example.com): " external_url
case "$external_url" in
  https://*) ;;
  http://*) echo "WARNING: an http issuer is only safe strictly behind a TLS-terminating proxy." ;;
  *)
    echo "ERROR: the URL must start with https:// (or http:// behind a TLS proxy)." >&2
    exit 1
    ;;
esac

# ── Operator password → bcrypt hash (never stored in plain text) ──────────
read -r -s -p "Operator password (input hidden): " password
echo
read -r -s -p "Repeat password: " password2
echo
if [[ "$password" != "$password2" ]]; then
  echo "ERROR: passwords do not match." >&2
  exit 1
fi
if [[ ${#password} -lt 12 ]]; then
  echo "ERROR: use at least 12 characters." >&2
  exit 1
fi

echo "Generating bcrypt hash (cost 12) ..."
# htpasswd -i reads the password from stdin (keeps it out of argv); the
# output is ":<hash>" with a trailing newline.
hash="$(printf '%s' "$password" | docker run --rm -i httpd:2.4-alpine htpasswd -niBC 12 "" | tr -d ':\n')"
if [[ "$hash" != \$2* ]]; then
  echo "ERROR: hash generation failed (got: ${hash:0:8}...)." >&2
  exit 1
fi

# Compose interpolates env_file values: escape $ as $$ (see .env.example).
escaped_hash="${hash//$/\$\$}"

# ── Write .env ─────────────────────────────────────────────────────────────
cp .env.example .env
chmod 600 .env
# Replace the two required placeholders; everything else keeps its
# documented default and can be edited in .env afterwards.
awk -v url="$external_url" -v hash="$escaped_hash" '
  sub(/^EXTERNAL_URL=.*/,   "EXTERNAL_URL=" url)  { print; next }
  sub(/^PASSWORD_HASH=.*/,  "PASSWORD_HASH=" hash) { print; next }
  { print }
' .env.example > .env

echo
echo "Wrote .env (mode 600). Next steps:"
echo "  1. Review .env — pick install mode A (reverse proxy) or B (built-in ACME)"
echo "     and set PROXY_BEARER_TOKEN (or remove it for an unauthenticated upstream)."
echo "  2. Copy docker-compose.example.yml to docker-compose.yml and replace the"
echo "     <placeholders> (image version, upstream service)."
echo "  3. docker compose up -d"
echo
echo "Reminder: Claude connects from Anthropic's egress range 160.79.104.0/21 —"
echo "a firewall or geo-block that drops it makes the connector fail silently."
