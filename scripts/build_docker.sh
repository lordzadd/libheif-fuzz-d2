#!/usr/bin/env bash
# Build the pinned image used by the D3 sustained campaign.
# (Dockerfile.d3 is the campaign image; Dockerfile is the team's D2/D3 image.)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker build --platform linux/amd64 -f "$ROOT/Dockerfile.d3" -t libheif-fuzz:1.23.4 "$ROOT"
