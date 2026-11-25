#!/usr/bin/env bash
# Example only: register a workload so its JWT-SVID sub is the SPIFFE ID used in cf-sts policy.
set -euo pipefail

spire-server entry create \
  -parentID spiffe://example.com/spire/agent/join_token/example \
  -spiffeID spiffe://example.com/ci/deployer \
  -selector unix:uid:1001 \
  -jwtSVIDTTL 300
