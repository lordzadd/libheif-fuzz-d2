#!/usr/bin/env bash
# Docker-less variant of scripts/coverage_report.sh for the cloud runner.
#
#   bash scripts/coverage_report_native.sh <out-label> <corpus-root> [<corpus-root> ...]
#
# Builds a coverage-instrumented copy of the fuzzers into build-cov/ (same flags
# as coverage_report.sh: -fsanitize=fuzzer -fprofile-instr-generate
# -fcoverage-mapping -g -O1), replays every <corpus-root>/<target>/ directory
# once with -runs=0, merges the profiles and writes llvm-cov reports to
# results/<out-label>/coverage/. Several corpus roots are merged per target, so
# the union of Campaign B and Campaign C corpora can be measured in one call.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="${1:?usage: coverage_report_native.sh <out-label> <corpus-root>...}"
shift
[ "$#" -ge 1 ] || { echo "need at least one corpus root" >&2; exit 1; }
OUT="$ROOT/results/$LABEL/coverage"
PROFDATA="${LLVM_PROFDATA:-llvm-profdata-18}"
LLVMCOV="${LLVM_COV:-llvm-cov-18}"

if [ ! -x "$ROOT/build-cov/fuzzing/file_fuzzer" ]; then
  BUILD_DIR="$ROOT/build-cov" \
  FUZZING_COMPILE_OPTIONS='-fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -g -O1' \
    bash "$ROOT/scripts/build_d3.sh" >/dev/null
fi

mkdir -p "$OUT"
rm -f "$OUT"/*.profraw "$OUT"/*.profdata
for t in api_fuzzer box_fuzzer color_conversion_fuzzer file_fuzzer sequence_fuzzer tile_fuzzer; do
  dirs=()
  for r in "$@"; do
    [ -d "$r/$t" ] && dirs+=("$r/$t")
  done
  [ "${#dirs[@]}" -gt 0 ] || continue
  echo "measuring $t: ${dirs[*]}"
  LLVM_PROFILE_FILE="$OUT/$t.profraw" \
    timeout 3600 "$ROOT/build-cov/fuzzing/$t" "${dirs[@]}" -runs=0 -timeout=60 \
      -rss_limit_mb=4096 > "$OUT/$t.log" 2>&1 || true
done
"$PROFDATA" merge -sparse "$OUT"/*.profraw -o "$OUT/all.profdata"
# Same reporting as coverage_report.sh (Campaign B): one llvm-cov report per
# fuzzer binary against the merged profile; the headline number is the
# file_fuzzer binary's TOTAL row, which is what docs/D3.md quotes.
for f in "$ROOT"/build-cov/fuzzing/*_fuzzer; do
  name=$(basename "$f")
  "$LLVMCOV" report "$f" -instr-profile="$OUT/all.profdata" \
    -ignore-filename-regex='(fuzzing/|/usr/|build-cov)' > "$OUT/cov-report-$name.txt"
done
head -100 "$OUT/cov-report-file_fuzzer.txt" > "$OUT/llvm_cov_report.txt"
cp "$OUT/cov-report-file_fuzzer.txt" "$OUT/llvm_cov_report_full.txt"
rm -f "$OUT"/*.profraw
tail -n 1 "$OUT/cov-report-file_fuzzer.txt"
