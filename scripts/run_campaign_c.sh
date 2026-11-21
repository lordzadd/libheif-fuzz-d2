#!/usr/bin/env bash
# Campaign C (D3 extended campaign), exactly as run on the 4-vCPU cloud runner.
#
#   bash scripts/run_campaign_c.sh distill      # Campaign B corpus -> corpora/run-long2a, run-long2c/box
#   bash scripts/run_campaign_c.sh seeds        # generated seeds (both batches) into corpora/seed/
#   bash scripts/run_campaign_c.sh long2a       # one 5400 s phase, then analyze/triage/pack
#   bash scripts/run_campaign_c.sh long2b
#   bash scripts/run_campaign_c.sh long2c
#   bash scripts/run_campaign_c.sh measure      # seed gain, replays on both builds, line coverage
#
# Prerequisite: bash scripts/cloud_setup.sh (builds ./build from this tree,
# i.e. the d3-final source with M1+M2). `measure` also builds the pinned
# d3-baseline source into build-baseline/ from a git worktree.
# Each step was run in this order; the results are in results/long2{a,b,c}/,
# results/long2/coverage/ and results/replay/long2-*.csv.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export ASAN_OPTIONS=detect_leaks=0
STEP="${1:?usage: run_campaign_c.sh distill|seeds|long2a|long2b|long2c|measure}"
TMP="${TMPDIR:-/tmp}/campaign-c"

unpack_b() {  # unpack Campaign B's final corpus for target $1 into $TMP/b/$1
  mkdir -p "$TMP/b"
  tar -xzf "results/baseline/corpus_final_tar/$1.tar.gz" -C "$TMP/b" 2>/dev/null
  # The tarballs were made on macOS: drop the AppleDouble '._*' entries.
  find "$TMP/b/$1" -name '._*' -delete
}

distill() {  # $1 target, $2 destination corpus, $3 log
  unpack_b "$1"
  mkdir -p "$2" "$(dirname "$3")"
  "build/fuzzing/$1" -merge=1 -timeout=30 -rss_limit_mb=2048 -max_len=65536 \
    "$2" "corpora/seed/$1" "$TMP/b/$1" > "$3" 2>&1
}

phase() {  # $1 run label, $2 allocation
  python3 harness/d3/campaign.py --seconds 5400 --run "$1" --alloc "$2" \
    --rss-limit 1200 --max-len 65536 --chunk-seconds 900
  python3 harness/d3/analyze.py --run "$1"
  python3 harness/d3/triage.py --run "$1"
  bash scripts/pack_corpus.sh "$1"
}

carry() {  # copy live corpus of targets $3.. from run $1 to run $2
  local from="$1" to="$2"; shift 2
  for t in "$@"; do
    mkdir -p "corpora/run-$to/$t"
    cp --update=none "corpora/run-$from/$t/"* "corpora/run-$to/$t/"
  done
}

case "$STEP" in
  distill)
    for t in file_fuzzer api_fuzzer tile_fuzzer sequence_fuzzer; do
      distill "$t" "corpora/run-long2a/$t" "results/long2a/corpus_distill/merge-$t.log"
    done
    distill box_fuzzer corpora/run-long2c/box_fuzzer results/long2c/corpus_distill/merge-box_fuzzer.log
    ;;
  seeds)
    python3 harness/d3/gen_seeds.py --count 400 --seed 428 \
      --manifest results/long2a/gen_seed_manifest.csv
    python3 harness/d3/gen_seeds.py --count 300 --seed 529 --features unc,regions,meta \
      --manifest results/long2b/gen_seed_manifest.csv
    ;;
  long2a)
    phase long2a file_fuzzer=1,api_fuzzer=1,tile_fuzzer=1
    ;;
  long2b)
    carry long2a long2b file_fuzzer api_fuzzer sequence_fuzzer tile_fuzzer
    phase long2b file_fuzzer=1,api_fuzzer=1,sequence_fuzzer=1
    ;;
  long2c)
    carry long2b long2c file_fuzzer tile_fuzzer
    phase long2c tile_fuzzer=1,file_fuzzer=1,box_fuzzer=1
    ;;
  measure)
    python3 harness/d3/seed_gain.py --manifest results/long2a/gen_seed_manifest.csv \
      --out results/long2a/seed_gain.csv
    python3 harness/d3/seed_gain.py --manifest results/long2a/gen_seed_manifest.csv \
      --manifest results/long2b/gen_seed_manifest.csv --out results/long2b/seed_gain.csv
    # Final Campaign C corpora: the last phase that ran each target.
    rm -rf "$TMP/c" "$TMP/gen"
    mkdir -p "$TMP/c" "$TMP/gen"
    for t in api_fuzzer sequence_fuzzer; do cp -r "results/long2b/corpus_final/$t" "$TMP/c/"; done
    for t in file_fuzzer tile_fuzzer box_fuzzer; do cp -r "results/long2c/corpus_final/$t" "$TMP/c/"; done
    for t in file_fuzzer api_fuzzer tile_fuzzer; do
      mkdir -p "$TMP/gen/$t"; cp corpora/seed/$t/gen-* "$TMP/gen/$t/"
    done
    if [ ! -x build-baseline/fuzzing/file_fuzzer ]; then
      git worktree add --detach "$TMP/wt-baseline" d3-baseline
      (cd "$TMP/wt-baseline" && BUILD_DIR="$ROOT/build-baseline" bash scripts/build_d3.sh)
    fi
    # Run the two corpus replays one after the other on an idle machine
    # (in the recorded run they shared the cores; see results/long2c/tile_repeat.txt).
    python3 harness/d3/replay.py --run long2c --build "$ROOT/build-baseline/fuzzing" \
      --label long2-baseline --corpus-root "$TMP/c"
    python3 harness/d3/replay.py --run long2c --build "$ROOT/build/fuzzing" \
      --label long2-patched --corpus-root "$TMP/c"
    python3 harness/d3/replay.py --run long2c --build "$ROOT/build-baseline/fuzzing" \
      --label long2-genseeds-baseline --corpus-root "$TMP/gen"
    for t in api_fuzzer box_fuzzer color_conversion_fuzzer file_fuzzer sequence_fuzzer tile_fuzzer; do
      unpack_b "$t"
    done
    bash scripts/coverage_report_native.sh long2 "$TMP/b" "$TMP/c"
    python3 harness/d3/cov_areas.py results/long2/coverage/cov-report-file_fuzzer.txt \
      --csv results/long2/coverage/areas.csv
    python3 harness/d3/cov_areas.py results/baseline/coverage/cov-report-file_fuzzer.txt \
      --csv results/long2/coverage/areas_campaignB.csv
    python3 harness/d3/tables_d3.py
    ;;
  *)
    echo "unknown step $STEP" >&2; exit 1 ;;
esac
