#!/usr/bin/env bash
# D3 baseline campaign: build the fuzzers, build the seed corpora, then fuzz
# for $1 seconds (default 10800 = 3 h) with 10 workers.
#
#   scripts/run_campaign.sh 10800 baseline
#
# The campaign writes results/<run>/ and is safe to re-run: seed corpora are
# rebuilt from the pinned upstream seed files and the run directory is reused.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECONDS_TO_RUN="${1:-10800}"
RUN="${2:-baseline}"
UID_GID="$(id -u):$(id -g)"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc "./scripts/build.sh && python3 harness/prepare_corpus.py"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc "python3 harness/campaign.py --seconds $SECONDS_TO_RUN --run $RUN --checkpoint 900"
