#!/usr/bin/env bash
# POST $CF_STS_URL/token with Bearer $JWT.
# Success: 200 (rule matched) or 403 no_matching_rule (JWT verified, rule TBD).
# Soft-skip (exit 0): set ACCEPT_UNKNOWN_ISSUER=1 to treat 401 unknown_issuer as
# "prod not yet on this build" (avoids chicken-and-egg with CD).
# Fail: other 401 / transport errors.
set -euo pipefail

: "${JWT:?JWT required}"
: "${CF_STS_URL:?CF_STS_URL required}"

url="${CF_STS_URL%/}/token"
tmp=$(mktemp)
code=$(curl -sS -o "$tmp" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${JWT}" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":60}' \
  "$url" || true)

body=$(cat "$tmp")
rm -f "$tmp"

# Never log minted secrets (.token). Status + non-secret fields only.
err=$(echo "$body" | jq -r '.error // empty' 2>/dev/null || true)
rule=$(echo "$body" | jq -r '.rule // empty' 2>/dev/null || true)
tid=$(echo "$body" | jq -r '.id // empty' 2>/dev/null || true)
echo "cf-sts HTTP ${code} error=${err:-none} rule=${rule:--} id=${tid:--}"

case "$code" in
  200)
    echo "mint ok rule=${rule}"
    exit 0
    ;;
  403)
    if [ "$err" = "no_matching_rule" ]; then
      echo "JWT accepted by cf-sts; no policy rule for this principal yet (expected until grants are added)."
      exit 0
    fi
    echo "::error::unexpected 403: ${err:-unknown}"
    exit 1
    ;;
  401)
    if [ "${ACCEPT_UNKNOWN_ISSUER:-}" = "1" ] && [ "$err" = "unknown_issuer" ]; then
      echo "::warning::cf-sts returned unknown_issuer (production may not have this issuer yet). Soft-skip."
      exit 0
    fi
    echo "::error::cf-sts rejected the JWT (${err:-unknown})"
    exit 1
    ;;
  *)
    echo "::error::unexpected HTTP ${code} error=${err:-unknown}"
    exit 1
    ;;
esac
