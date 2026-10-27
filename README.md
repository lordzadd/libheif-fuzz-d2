# libheif fuzzing campaign (D2)

Fuzzing harness for libheif at pinned commit `08075aebcc0d9bf7d35f900c36114b1b6e90ed7d` (libheif 1.23.4, vendored in `libheif/`).

## Run (recommended: Docker, pinned environment)

```sh
git clone https://github.com/lordzadd/libheif-fuzz-d2.git
cd libheif-fuzz-d2
docker build -t libheif-fuzz-d2 .
docker run --rm -v "$PWD/results:/repo/results" libheif-fuzz-d2
```

The image pins the Ubuntu 24.04 base by digest and installs clang 18, CMake, and the
codec libraries (libde265 for HEVC, x265, and aom for AV1) from a dated Ubuntu archive snapshot.

## Run (native, Linux or macOS)

Needs bash, clang with libFuzzer, CMake >= 3.16, make, Python 3, and ideally the codec
development packages above. Without the codecs, HEVC/AVIF pixel decoding is skipped.

```sh
python3 harness/run.py          # 5 s per fuzzer
python3 harness/run.py 60       # 60 s per fuzzer
```

## Output

The script builds libheif with fuzzers if needed, runs all 7 fuzzers from a fresh copy of
the seed corpus, prints a JSON summary (`total_crashes`), and writes
`results/fuzz_results.csv` (one row per fuzzer: exit code, time, crashes, timeouts/OOMs,
executions, edge coverage). Per-fuzzer logs and crash inputs are in `results/crashes/<fuzzer>/`.
