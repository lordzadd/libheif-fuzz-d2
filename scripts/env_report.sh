#!/usr/bin/env bash
# Record the exact toolchain and library versions used for the campaign.
# Output: results/env.txt (committed as evidence for the "Setup" section).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/results/env.txt"
mkdir -p "$ROOT/results"
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -srm)"
  echo "docker_server: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  echo "image: libheif-fuzz:1.23.4"
  echo "image_id: $(docker image inspect libheif-fuzz:1.23.4 --format '{{.Id}}')"
  echo "image_platform: linux/amd64"
  docker run --rm --platform linux/amd64 libheif-fuzz:1.23.4 bash -lc '
    echo "container_arch: $(uname -m)"
    echo "kernel: $(uname -r)"
    echo "clang: $(clang-18 --version | head -1)"
    echo "cmake: $(cmake --version | head -1)"
    echo "libde265: $(dpkg-query -W -f="\${Version}" libde265-dev)"
    echo "libx265: $(dpkg-query -W -f="\${Version}" libx265-dev)"
    echo "libaom: $(dpkg-query -W -f="\${Version}" libaom-dev)"
    echo "zlib: $(dpkg-query -W -f="\${Version}" zlib1g-dev)"
    echo "brotli: $(dpkg-query -W -f="\${Version}" libbrotli-dev)"
    echo "ubuntu: $(. /etc/os-release; echo $PRETTY_NAME)"
  '
  echo "libheif_version: $(grep -m1 'project(libheif' "$ROOT/libheif/CMakeLists.txt")"
  echo "libheif_commit: 08075aebcc0d9bf7d35f900c36114b1b6e90ed7d"
  echo "sanitizer_flags: -fsanitize=fuzzer,address -g -fno-omit-frame-pointer"
  echo "build_type: RelWithDebInfo (-O2 -g)"
  echo "asan_options: detect_leaks=0:abort_on_error=0:symbolize=1"
} | tee "$OUT"
