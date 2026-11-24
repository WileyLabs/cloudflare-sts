#!/usr/bin/env bash
# Print one SPIRE JWT-SVID for cf-sts audience (stdout only). Retries while the agent syncs entries.
set -euo pipefail
AUDIENCE="${AUDIENCE:-cf-sts.example.com}"
SPIRE_SOCKET="${SPIRE_SOCKET:-/spiffe-workload-api/spire-agent.sock}"

if [ ! -S "$SPIRE_SOCKET" ]; then
  echo "no SPIRE socket at $SPIRE_SOCKET" >&2
  exit 1
fi
if ! command -v spire-agent >/dev/null 2>&1; then
  echo "spire-agent not on PATH" >&2
  exit 1
fi

fetch() {
  spire-agent api fetch jwt -audience "$AUDIENCE" -socketPath "$SPIRE_SOCKET" 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./) { print $i; exit } }'
}

for _ in 1 2 3 4 5 6 7 8; do
  jwt=$(fetch || true)
  if [ -n "${jwt:-}" ]; then
    printf '%s' "$jwt"
    exit 0
  fi
  sleep 2
done
echo "spire-agent returned no JWT for aud=$AUDIENCE" >&2
exit 1
