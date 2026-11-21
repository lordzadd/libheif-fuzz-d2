#!/usr/bin/env bash
# Prepare a plain Linux VM (no Docker) to run the D3 campaign.
#
#   bash scripts/cloud_setup.sh
#
# Installs clang 18 with libFuzzer/ASan, CMake, and the codec libraries, then
# builds the fuzz targets into ./build. Use this when the runner is a bare VM
# or a container without a Docker daemon. With Docker, use scripts/build_docker.sh
# and scripts/run_campaign.sh instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    clang-18 libclang-rt-18-dev llvm-18 cmake make pkg-config python3 \
    libde265-dev libx265-dev libaom-dev zlib1g-dev libbrotli-dev
  export CC=clang-18
  export CXX=clang++-18
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y clang lld compiler-rt cmake make pkgconf-pkg-config python3 \
    libde265-devel x265-devel libaom-devel zlib-devel brotli-devel
else
  echo "error: install clang 18+, cmake, and the libde265/x265/aom/zlib/brotli" >&2
  echo "development packages by hand, then set CC and CXX." >&2
  exit 1
fi

bash "$ROOT/scripts/build_d3.sh"
python3 "$ROOT/harness/d3/prepare_corpus.py" --reuse
echo "ready: build/fuzzing/*_fuzzer"
