# Pinned build/run environment for the D2 harness.
# Base image is pinned by digest; apt packages are pinned to a dated Ubuntu archive snapshot,
# so every build installs the same package versions.
FROM ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c

ARG UBUNTU_SNAPSHOT=20261001T000000Z
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update --snapshot "$UBUNTU_SNAPSHOT" \
 && apt-get install -y --no-install-recommends \
      clang-18 libclang-rt-18-dev llvm-18 cmake make pkg-config python3 \
      libde265-dev libx265-dev libaom-dev zlib1g-dev libbrotli-dev \
 && rm -rf /var/lib/apt/lists/*

# llvm-symbolizer gives sanitizer reports function names, which LSan suppressions match on.
ENV CC=clang-18 CXX=clang++-18 \
    PATH=/usr/lib/llvm-18/bin:$PATH \
    ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-18/bin/llvm-symbolizer

WORKDIR /repo
COPY . .
# Guard against CRLF line endings if the repo was checked out on Windows.
RUN sed -i 's/\r$//' scripts/build.sh harness/run.py && chmod +x scripts/build.sh \
 && rm -rf build corpora results \
 && scripts/build.sh

ENTRYPOINT ["python3", "harness/run.py"]
