#!/usr/bin/env bash
# Print a fresh Google ID token for cf-sts (stdout only).
# Same final hop as google-github-actions/auth token_format=id_token:
#   Bearer (WIF auth_token) → iamcredentials generateIdToken.
# Expects GCP_AUTH_TOKEN in the env (from steps.auth.outputs.auth_token).
set -euo pipefail
AUDIENCE="${AUDIENCE:-cf-sts.example.com}"
SA_EMAIL="${SA_EMAIL:-sa-ci@example-project.iam.gserviceaccount.com}"
ACCESS="${GCP_AUTH_TOKEN:?GCP_AUTH_TOKEN required (export steps.auth.outputs.auth_token from google-github-actions/auth)}"

RESP=$(curl -fsS -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SA_EMAIL}:generateIdToken" \
  -H "Authorization: Bearer ${ACCESS}" \
  -H 'Content-Type: application/json' \
  -d "{\"audience\":\"${AUDIENCE}\",\"includeEmail\":true}")
TOKEN=$(echo "$RESP" | jq -r '.token // empty')
if [ -z "$TOKEN" ] || [[ "$TOKEN" != eyJ* ]]; then
  echo "generateIdToken failed: $RESP" >&2
  exit 1
fi
printf '%s' "$TOKEN"
