# Pinned research environment for the libheif fuzzing campaign (D2/D3).
#
# Ubuntu 24.04 LTS ships clang 18 (libFuzzer + ASan + UBSan) and the codec
# libraries libheif uses for HEVC and AV1 decoding. The image is pinned by the
# digest below so that every team member and the grader builds the identical
# toolchain. Nothing in this image is fetched from the network at run time; all
# fuzzing inputs are read from local files.
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# clang/lld 18: libFuzzer, ASan, UBSan.
# libde265-dev: HEVC decoder used for HEIC images (the main iPhone path).
# libx265-dev:  HEVC encoder, needed only by encoder_fuzzer.
# libaom-dev:   AV1 decoder/encoder used for AVIF images.
# zlib1g-dev, libbrotli-dev: payload compression for the ISO 23001-17
#   uncompressed codec (WITH_UNCOMPRESSED_CODEC=ON in scripts/build.sh).
# No network access is required after the image is built.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-18 \
        lld-18 \
        libclang-rt-18-dev \
        llvm-18 \
        cmake \
        make \
        ninja-build \
        pkg-config \
        python3 \
        ca-certificates \
        libde265-dev \
        libx265-dev \
        libaom-dev \
        zlib1g-dev \
        libbrotli-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang-18
ENV CXX=clang++-18

WORKDIR /repo
