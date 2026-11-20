#!/usr/bin/env bash
# Build the fuzz targets in a production-like configuration: libFuzzer only,
# no AddressSanitizer / UndefinedBehaviorSanitizer.  Used as evidence when
# classifying a sanitizer-only finding: the same input is replayed here to
# show whether it causes a real memory error in a normal build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

export BUILD_DIR="${BUILD_DIR:-$ROOT/build-release}"
export FUZZING_COMPILE_OPTIONS="${FUZZING_COMPILE_OPTIONS:--fsanitize=fuzzer -O2 -g}"

exec bash "$ROOT/scripts/build.sh"
