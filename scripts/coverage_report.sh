#!/usr/bin/env bash
# Build a coverage-instrumented copy of the fuzzers and measure line and
# function coverage of the final corpora. Used to report which code the harness
# reached and which it never reached.
#
#   scripts/coverage_report.sh baseline
#
# Output: results/<run>/coverage/llvm_cov_report.txt and .csv
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${1:-baseline}"
UID_GID="$(id -u):$(id -g)"

docker run --rm --platform linux/amd64 -u "$UID_GID" -e HOME=/tmp \
  -v "$ROOT":/repo -w /repo libheif-fuzz:1.23.4 bash -lc "
    set -e
    BUILD_DIR=/repo/build-cov \
    FUZZING_COMPILE_OPTIONS='-fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping -g -O1' \
      ./scripts/build.sh >/dev/null
    mkdir -p /repo/results/$RUN/coverage
    cd /repo/results/$RUN/coverage
    rm -f *.profraw *.profdata
    for f in /repo/results/$RUN/corpus_final/*/; do
      name=\$(basename \$f)
      echo \"measuring \$name\"
      LLVM_PROFILE_FILE=/repo/results/$RUN/coverage/\$name.profraw \
        timeout 3600 /repo/build-cov/fuzzing/\$name \$f -runs=0 -timeout=60 \
        > \$name.log 2>&1 || true
    done
    llvm-profdata-18 merge -sparse *.profraw -o all.profdata
    for f in /repo/build-cov/fuzzing/*_fuzzer; do
      name=\$(basename \$f)
      llvm-cov-18 report \$f -instr-profile=all.profdata \
        -ignore-filename-regex='(fuzzing/|/usr/|build-cov)' \
        > cov-report-\$name.txt
    done
    head -100 cov-report-file_fuzzer.txt > llvm_cov_report.txt
    for f in cov-report-*.txt; do echo \"== \$f\"; cat \$f; done > all_reports.txt
  "
