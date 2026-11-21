#!/usr/bin/env bash
# Build the pinned research image. Run once (or after Dockerfile changes).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker build --platform linux/amd64 -t libheif-fuzz:1.23.4 "$ROOT"
