#!/usr/bin/env bash
# D3 campaign runner: build the fuzzers, build the seed corpora, then fuzz.
#
#   scripts/run_campaign.sh 7200 baseline
#   scripts/run_campaign.sh 21600 long2 --alloc file_fuzzer=4,api_fuzzer=4,box_fuzzer=2
#
# Extra arguments are passed to harness/d3/campaign.py. Useful knobs:
#   --alloc file_fuzzer=4,api_fuzzer=4   worker split (12 workers fit this VM)
#   --rss-limit 1200                     raise when corpora get large
#   --max-len 65536                      allow larger inputs
#   --extra-flags "-entropic=1"          any libFuzzer flag
#   --chunk-seconds 900                  longer chunks = less reload overhead
#
# The run writes results/<run>/ and corpora/run-<run>/. Existing runs are never
# modified: pick a new label for a new campaign.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECONDS_TO_RUN="${1:-10800}"
RUN="${2:-baseline}"
shift 2 || true
EXTRA="$*"
UID_GID="$(id -u):$(id -g)"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc "./scripts/build_d3.sh && python3 harness/d3/prepare_corpus.py --reuse"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc "python3 harness/d3/campaign.py --seconds $SECONDS_TO_RUN --run $RUN --checkpoint 900 $EXTRA"
