#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/libheif"
BUILD="$ROOT/build"

# Pick an SDK that links on this host. Linux ignores this block.
if [ "$(uname -s)" = "Darwin" ] && [ -z "${SDKROOT:-}" ]; then
  for sdk in \
    /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
    /Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk \
    /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk; do
    if [ -d "$sdk" ]; then export SDKROOT="$sdk"; break; fi
  done
fi

supports_fuzzer() {
  local cxx="$1"
  local tmp
  tmp="$(mktemp -d)"
  cat > "$tmp/t.cc" <<'CC'
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }
CC
  local sysroot_flag=""
  if [ "$(uname -s)" = "Darwin" ] && [ -n "${SDKROOT:-}" ]; then
    sysroot_flag="-isysroot $SDKROOT"
  fi
  if $cxx $sysroot_flag -x c++ -fsanitize=fuzzer "$tmp/t.cc" -o "$tmp/t" >/dev/null 2>&1; then
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

if [ -z "${CXX:-}" ]; then
  candidates=()
  if [ "$(uname -s)" = "Darwin" ]; then
    candidates+=(
      /opt/homebrew/opt/llvm/bin/clang++
      /usr/local/opt/llvm/bin/clang++
      /Library/Developer/Toolchains/swift-6.2.4-RELEASE.xctoolchain/usr/bin/clang++
      /Library/Developer/Toolchains/swift-6.2-RELEASE.xctoolchain/usr/bin/clang++
      /usr/bin/clang++
    )
  else
    candidates+=(
      clang++
      clang++-19
      clang++-18
      clang++-17
      clang++-16
      clang++-15
    )
  fi
  for c in "${candidates[@]}"; do
    if command -v "$c" >/dev/null 2>&1 && supports_fuzzer "$c"; then
      export CXX="$c"
      break
    fi
  done
fi

if [ -z "${CXX:-}" ]; then
  echo "error: no C++ compiler with libFuzzer support found." >&2
  echo "Set CXX to a clang++ that provides -fsanitize=fuzzer." >&2
  exit 1
fi

if [ -z "${CC:-}" ]; then
  export CC="${CXX%++}"
  if ! command -v "$CC" >/dev/null 2>&1; then
    export CC="$CXX"
  fi
fi

FUZZING_COMPILE_OPTIONS="${FUZZING_COMPILE_OPTIONS:--fsanitize=fuzzer,address,shift,integer -fno-sanitize-recover=shift,integer}"
FUZZING_LINKER_OPTIONS="${FUZZING_LINKER_OPTIONS:-}"

cmake -S "$SRC" -B "$BUILD" \
  ${SDKROOT:+-DCMAKE_OSX_SYSROOT="$SDKROOT"} \
  -DWITH_FUZZERS=ON \
  -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=OFF \
  -DWITH_GDK_PIXBUF=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DFUZZING_C_COMPILER="$CC" \
  -DFUZZING_CXX_COMPILER="$CXX" \
  -DFUZZING_COMPILE_OPTIONS="$FUZZING_COMPILE_OPTIONS" \
  -DFUZZING_LINKER_OPTIONS="$FUZZING_LINKER_OPTIONS"

cmake --build "$BUILD" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
echo "Build complete: $BUILD"
