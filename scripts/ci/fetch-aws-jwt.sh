#!/usr/bin/env bash
# Print a fresh AWS web identity JWT for cf-sts (stdout only).
# Uses IAM outbound identity federation: sts:GetWebIdentityToken as the current AWS role
# (assumed earlier in the job, e.g. aws-actions/configure-aws-credentials). The call is regional.
set -euo pipefail
AUDIENCE="${AUDIENCE:-cf-sts.example.com}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

TOKEN=$(aws sts get-web-identity-token \
  --region "$REGION" \
  --audience "$AUDIENCE" \
  --signing-algorithm RS256 \
  --duration-seconds 60 \
  --query WebIdentityToken --output text)
if [ -z "$TOKEN" ] || [[ "$TOKEN" != eyJ* ]]; then
  echo "get-web-identity-token failed (no JWT returned)" >&2
  exit 1
fi
printf '%s' "$TOKEN"
