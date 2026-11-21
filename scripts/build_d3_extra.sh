#!/usr/bin/env bash
# Build the extra D3 fuzz targets in harness/d3/fuzzers/ against an already
# built, instrumented libheif (scripts/build_d3.sh). The library is not changed.
#
#   BUILD_DIR=build bash scripts/build_d3_extra.sh            # patched tree
#   BUILD_DIR=build-baseline bash scripts/build_d3_extra.sh   # pinned tree
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
CXX="${CXX:-clang++-18}"
INC="${LIBHEIF_SRC:-$ROOT/libheif}/libheif/api"
for src in "$ROOT"/harness/d3/fuzzers/*.cc; do
  name="$(basename "$src" .cc)"
  $CXX -std=c++20 -fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer \
    -I"$INC" -I"$BUILD/libheif" "$src" "$BUILD/libheif/libheif.a" \
    $(pkg-config --libs libde265 aom zlib libbrotlidec libbrotlienc) -lx265 -lpthread \
    -o "$BUILD/fuzzing/$name"
  echo "built $BUILD/fuzzing/$name"
done
