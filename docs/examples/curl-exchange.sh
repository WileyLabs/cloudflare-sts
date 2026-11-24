#!/usr/bin/env bash
# Exchange any OIDC JWT for a short-lived Cloudflare token.
set -euo pipefail
: "${JWT:?set JWT to a bearer token for aud=cf-sts.example.com}"
CF_STS_URL="${CF_STS_URL:-https://cf-sts.example.com}"
curl -fsS -X POST \
  -H "Authorization: Bearer ${JWT}" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":300}' \
  "${CF_STS_URL%/}/token" | jq .
