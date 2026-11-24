#!/usr/bin/env bash
# Prove a minted CLOUDFLARE_API_TOKEN works: list DNS for cf-sts under example.com.
set -euo pipefail

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN required}"
ZONE_NAME="${ZONE_NAME:-example.com}"
RECORD_NAME="${RECORD_NAME:-cf-sts.example.com}"
API="${CF_API:-https://api.cloudflare.com/client/v4}"

auth() { curl -fsS -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H 'Content-Type: application/json' "$@"; }

zone_json=$(auth "${API}/zones?name=${ZONE_NAME}&status=active")
zone_id=$(echo "$zone_json" | jq -r '.result[0].id // empty')
if [ -z "$zone_id" ]; then
  echo "::error::zone ${ZONE_NAME} not found (or token lacks DNS Read)"
  echo "$zone_json" | jq '{success,errors}'
  exit 1
fi
echo "zone ${ZONE_NAME} id=${zone_id}"

recs=$(auth "${API}/zones/${zone_id}/dns_records?name=${RECORD_NAME}")
count=$(echo "$recs" | jq '.result | length')
if [ "$count" -lt 1 ]; then
  echo "::error::no DNS records named ${RECORD_NAME}"
  echo "$recs" | jq '{success,errors,result}'
  exit 1
fi

echo "$recs" | jq -r '.result[] | "\(.type)\t\(.name)\t\(.content)\tproxied=\(.proxied)"'
echo "dns-read ok (${count} record(s) for ${RECORD_NAME})"
