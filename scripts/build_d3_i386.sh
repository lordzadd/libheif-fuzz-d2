#!/usr/bin/env bash
# 32-bit (i386) ASan + libFuzzer build of a libheif tree, for size/pointer
# arithmetic that only wraps on 32-bit targets. No 32-bit codec libraries are
# installed, so external codecs, zlib, brotli and sharpyuv are off; the
# uncompressed codec and libheif's own parsing and conversion code are in.
#
#   LIBHEIF_SRC=/path/to/libheif BUILD_DIR=build-master-i386 bash scripts/build_d3_i386.sh
# Needs: libc6-dev-i386 lib32stdc++-13-dev lib32gcc-13-dev
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${LIBHEIF_SRC:-$ROOT/libheif}"
BUILD="${BUILD_DIR:-$ROOT/build-i386}"
# The i386 libc headers include <asm/...>, which only the x86_64 multiarch
# directory provides (gcc-multilib normally links it); the asm headers are the
# same for both x86 ABIs, so expose just that directory.
mkdir -p "$BUILD.asm-include"
ln -sfn /usr/include/x86_64-linux-gnu/asm "$BUILD.asm-include/asm"
FLAGS="-m32 -isystem $BUILD.asm-include -fsanitize=fuzzer-no-link,address -g -O1 -fno-omit-frame-pointer"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="-m32" -DCMAKE_SHARED_LINKER_FLAGS="-m32" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DWITH_EXAMPLES=OFF -DWITH_GDK_PIXBUF=OFF \
  -DWITH_FUZZERS=OFF -DWITH_UNCOMPRESSED_CODEC=ON -DWITH_LIBSHARPYUV=OFF \
  -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_AOM_DECODER=OFF -DWITH_AOM_ENCODER=OFF \
  -DWITH_DAV1D=OFF -DWITH_RAV1E=OFF -DWITH_SvtEnc=OFF -DWITH_JPEG_DECODER=OFF \
  -DWITH_JPEG_ENCODER=OFF -DWITH_OpenJPEG_DECODER=OFF -DWITH_OpenJPEG_ENCODER=OFF \
  -DWITH_FFMPEG_DECODER=OFF -DWITH_OPENJPH_ENCODER=OFF -DWITH_UVG266=OFF -DWITH_VVDEC=OFF \
  -DWITH_VVENC=OFF -DWITH_KVAZAAR=OFF -DWITH_OpenH264_DECODER=OFF -DWITH_X264=OFF \
  -DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=ON -DCMAKE_DISABLE_FIND_PACKAGE_Brotli=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON -DENABLE_PLUGIN_LOADING=OFF > "$BUILD.cmake.log"
cmake --build "$BUILD" -j"$(nproc)" --target heif > "$BUILD.build.log"
mkdir -p "$BUILD/fuzzing" "$BUILD/libheif/libheif"
cp "$BUILD/libheif/heif_version.h" "$BUILD/libheif/libheif/"
for t in "$ROOT"/harness/d3/fuzzers/*.cc "$SRC"/fuzzing/file_fuzzer.cc "$SRC"/fuzzing/api_fuzzer.cc; do
  n="$(basename "$t" .cc)"
  clang++-18 -m32 -isystem "$BUILD.asm-include" -std=c++20 -fsanitize=fuzzer,address -g -O1 -I"$SRC/libheif/api" \
    -I"$BUILD/libheif" "$t" "$BUILD/libheif/libheif.a" -lpthread -o "$BUILD/fuzzing/$n"
  echo "built $BUILD/fuzzing/$n"
done
