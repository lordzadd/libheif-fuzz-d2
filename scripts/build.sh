#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/libheif"
BUILD="${BUILD_DIR:-$ROOT/build}"

supports_fuzzer() {
  local cxx="$1"
  local tmp
  tmp="$(mktemp -d)"
  cat > "$tmp/probe.cc" <<'CC'
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }
CC
  if "$cxx" -x c++ -fsanitize=fuzzer "$tmp/probe.cc" -o "$tmp/probe" >/dev/null 2>&1; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

if [[ -z "${CXX:-}" ]]; then
  for candidate in clang++ clang++-19 clang++-18 clang++-17 clang++-16 clang++-15; do
    if command -v "$candidate" >/dev/null 2>&1 && supports_fuzzer "$candidate"; then
      export CXX="$candidate"
      break
    fi
  done
fi
if [[ -z "${CXX:-}" ]]; then
  echo "error: no C++ compiler with libFuzzer found; set CXX to a compatible clang++." >&2
  exit 1
fi
if [[ -z "${CC:-}" ]]; then
  export CC="${CXX%++}"
fi
command -v "$CC" >/dev/null 2>&1 || {
  echo "error: C compiler '$CC' was not found; set CC to the matching clang." >&2
  exit 1
}

FUZZING_COMPILE_OPTIONS="${FUZZING_COMPILE_OPTIONS:--fsanitize=fuzzer,address,undefined,shift,integer -fno-sanitize-recover=undefined,shift,integer}"
FUZZING_LINKER_OPTIONS="${FUZZING_LINKER_OPTIONS:-}"

cmake -S "$SRC" -B "$BUILD" \
  -DWITH_FUZZERS=ON \
  -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=OFF \
  -DWITH_GDK_PIXBUF=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_X265=OFF \
  -DWITH_DAV1D=OFF \
  -DWITH_AOM_DECODER=OFF \
  -DWITH_AOM_ENCODER=OFF \
  -DWITH_RAV1E=OFF \
  -DWITH_JPEG_DECODER=OFF \
  -DWITH_JPEG_ENCODER=OFF \
  -DWITH_OpenJPEG_DECODER=OFF \
  -DWITH_OpenJPEG_ENCODER=OFF \
  -DWITH_UNCOMPRESSED_CODEC=ON \
  -DWITH_HEADER_COMPRESSION=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DFUZZING_C_COMPILER="$CC" \
  -DFUZZING_CXX_COMPILER="$CXX" \
  -DFUZZING_COMPILE_OPTIONS="$FUZZING_COMPILE_OPTIONS" \
  -DFUZZING_LINKER_OPTIONS="$FUZZING_LINKER_OPTIONS"

if command -v nproc >/dev/null 2>&1; then
  jobs="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
  jobs="$(sysctl -n hw.ncpu)"
else
  jobs=2
fi
cmake --build "$BUILD" --parallel "$jobs"
echo "Build complete: $BUILD"
