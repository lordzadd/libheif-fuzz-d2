#!/usr/bin/env bash
# Post-campaign analysis for one run: coverage tables, crash triage, replay.
#
#   scripts/analyze_run.sh baseline            # analyse + triage
#   scripts/analyze_run.sh baseline build      # also replay against a build dir
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${1:-baseline}"
BUILD_DIR="${2:-}"
UID_GID="$(id -u):$(id -g)"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc "python3 harness/d3/analyze.py --run $RUN && python3 harness/d3/triage.py --run $RUN"

if [ -n "$BUILD_DIR" ]; then
  docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
    -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
    bash -lc "python3 harness/d3/replay.py --run $RUN --build /repo/$BUILD_DIR/fuzzing --label $RUN"
fi
