#!/usr/bin/env bash
# Decode a JWT segment (base64url) from stdin to stdout.
set -euo pipefail
s=$(tr '_-' '/+' | tr -d '[:space:]')
case $(( ${#s} % 4 )) in
  0) ;;
  2) s="${s}==" ;;
  3) s="${s}=" ;;
  *) echo "invalid base64url length" >&2; exit 1 ;;
esac
printf '%s' "$s" | base64 -d
