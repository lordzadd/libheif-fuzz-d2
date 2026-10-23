#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/libheif"
BUILD="$ROOT/build"

if [ -z "${SDKROOT:-}" ]; then
  for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk; do
    if [ -d "$sdk" ]; then export SDKROOT="$sdk"; break; fi
  done
fi
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

FUZZING_COMPILE_OPTIONS="${FUZZING_COMPILE_OPTIONS:--fsanitize=fuzzer,address,shift,integer -fno-sanitize-recover=shift,integer}"
FUZZING_LINKER_OPTIONS="${FUZZING_LINKER_OPTIONS:-}"

cmake -S "$SRC" -B "$BUILD" \
  ${SDKROOT:+-DCMAKE_OSX_SYSROOT="$SDKROOT"} \
  -DWITH_FUZZERS=ON \
  -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DFUZZING_C_COMPILER="$CC" \
  -DFUZZING_CXX_COMPILER="$CXX" \
  -DFUZZING_COMPILE_OPTIONS="$FUZZING_COMPILE_OPTIONS" \
  -DFUZZING_LINKER_OPTIONS="$FUZZING_LINKER_OPTIONS"

cmake --build "$BUILD" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
echo "Build complete: $BUILD"
