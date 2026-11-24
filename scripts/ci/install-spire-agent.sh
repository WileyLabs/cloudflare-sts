#!/usr/bin/env bash
# Install spire-agent CLI if missing (socket may be CSI-mounted; binary is not always on the image).
set -euo pipefail
SPIRE_VERSION="${SPIRE_VERSION:-1.13.0}"

if command -v spire-agent >/dev/null 2>&1; then
  spire-agent --version
  exit 0
fi

curl -fsSL -o /tmp/spire.tar.gz \
  "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz"
tar -xzf /tmp/spire.tar.gz -C /tmp
sudo cp "/tmp/spire-${SPIRE_VERSION}/bin/spire-agent" /usr/local/bin/
sudo chmod +x /usr/local/bin/spire-agent
spire-agent --version
