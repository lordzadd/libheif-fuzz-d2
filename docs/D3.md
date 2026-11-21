---
title: "D3 — Working Attack and Mitigation"
subtitle: "Track B: sustained fuzzing campaign against libheif 1.23.4"
author: "Team: not Claude — Ritvik Sharma (CPT_S 528), Jacob Kolk, Hoang Anh Khoa Ta (CPT_S 428)"
date: "Fall 2026"
---

# Repository

- Repository: https://github.com/lordzadd/libheif-fuzz-d2
- Baseline commit: `<baseline>`
- Final commit: `<final>`

The repository holds the harness, the pinned Docker image definition, the seed
corpora, the raw campaign output (one log per worker, one artifact per crash),
the triage records, and the replay results. Every number in this report is
produced by a script in `harness/` from files in `results/`.

# Setup

**Target.** libheif 1.23.4 at commit `08075aebcc0d9bf7d35f900c36114b1b6e90ed7d`
(upstream master, 9 September 2026). The commit is unchanged from D1 and D2.
The vendored source tree in `libheif/` is byte-identical to that commit:
`diff -rq` against `git archive 08075aeb` reports no differences.

**Harness targets.** Six upstream libFuzzer targets, unmodified:

| Target | Entry point | D2 row |
|---|---|---|
| `file_fuzzer` | `heif_context_read_from_memory`, then decode of the primary image, thumbnails and metadata | 1, 5, 8, 9 |
| `api_fuzzer` | item, region, depth, property and decode APIs | 3, 4, 6, 10 |
| `box_fuzzer` | single-box parser called directly | 2 |
| `tile_fuzzer` | grid/tile decode | 7 |
| `sequence_fuzzer` | sequence/track decode | 10 |
| `color_conversion_fuzzer` | colour conversion with planes built from the input bytes | 11 |

`encoder_fuzzer` is built but not fuzzed: the encoder path is outside the D1
decode scope.

**Toolchain.** Ubuntu 24.04 pinned by manifest digest
(`ubuntu@sha256:9c7f200c…`), clang 18.1.3, CMake, libFuzzer, AddressSanitizer.
Codec libraries: libde265 (HEVC decode), libaom (AV1 decode and encode), x265
(HEVC encode, needed only by `encoder_fuzzer`), zlib and brotli for the
ISO 23001-17 uncompressed codec, which this build enables
(`WITH_UNCOMPRESSED_CODEC=ON`). `scripts/env_report.sh` writes the resolved
versions to `results/env.txt`.

**Build.** `scripts/build.sh` configures the tree with
`-DCMAKE_BUILD_TYPE=RelWithDebInfo` (`-O2 -g`) and
`-fsanitize=fuzzer,address -fno-omit-frame-pointer`, which applies to libheif
itself as well as to the fuzz targets. ASan is the halt condition. D2 used
`-fsanitize=fuzzer,address,shift,integer -fno-sanitize-recover=shift,integer`;
that set was replaced for three reasons: `-fsanitize=integer` reports defined
unsigned wraparound, `shift` reports shifts that are defined for the operand
types in use, and with `-fno-sanitize-recover` the first seed in the corpus
aborts in `StreamReader::read()` on a zero-length `memcpy` from a null pointer
(`libheif/bitstream.cc`, `memcpy` with `size == 0`), which is undefined
behaviour but not memory corruption. ASan alone is the detector for the D1
property: out-of-bounds read or write, use-after-free, heap overflow.

**Agents and models.** Not applicable: D1 chose Track B, so there is no LLM
agent, no prompt and no model version to pin. The system under test is the
decoder library; the test driver is libFuzzer.

# Method

## Campaign harness

`harness/campaign.py` runs a fixed number of workers per target. Each worker is
one libFuzzer process with a shared corpus directory per target and
`-reload=1`, so workers exchange inputs. One worker runs in chunks of at most
600 s; a supervisor restarts it with a new mutation seed
(`-seed = t0 + worker*7919 + chunk*104729`) after any exit. The new seed is
important: with a fixed seed a restart replays the same mutation stream and
re-finds the same crash immediately.

Every line a worker prints is copied to `results/<run>/logs/<target>.w<k>.log`
with a wall-clock offset, so coverage over time can be rebuilt from raw logs
after the run. Crashes are copied to `results/<run>/crashes/<target>/` and
indexed in `crashes.csv`; the chunk log that holds the sanitizer report is
saved next to the artifact.

Flags common to every worker:

```
-timeout=30 -rss_limit_mb=800 -reload=1 -print_final_stats=1
-use_value_profile=1 -artifact_prefix=results/<run>/crashes/<target>/
-dict=libheif/fuzzing/data/dictionary.txt -seed=<varies per chunk>
```

`ASAN_OPTIONS=detect_leaks=0:symbolize=1`. Leak reports are disabled because a
leak is not the D1 property (memory corruption) and libheif has known
false-positive leaks in error paths that D2 already suppressed for one target.

## Corpus construction

`harness/prepare_corpus.py` builds one seed set per target from the upstream
seed files (133 HEIC/AVIF files in `libheif/fuzzing/data/corpus`, plus
`sequence_corpus`):

1. Every target starts from the upstream files.
2. `box_fuzzer`, which parses one box with no container, also receives every
   top-level and nested ISOBMFF box carved out of those files (recursive `meta`,
   `moov`, `trak`, … descent), so its first mutation starts inside a box body.
3. `sequence_fuzzer` also receives `sequence_corpus/seq_seed.heif`.
4. Seeds are de-duplicated by SHA-1 and reduced with libFuzzer `-merge=1`,
   which keeps only the seeds that add coverage.

| Target | Seeds after merge | Bytes |
|---|---|---|
| `file_fuzzer` | 81 | 179 610 |
| `api_fuzzer` | 87 | 200 530 |
| `box_fuzzer` | 181 | 57 815 |
| `tile_fuzzer` | 88 | 204 139 |
| `sequence_fuzzer` | 37 | 76 011 |
| `color_conversion_fuzzer` | 4 | 31 612 |

The full per-seed manifest is `results/corpus_manifest.csv`.

## Measurements

- **CPU time.** `getrusage(RUSAGE_CHILDREN)` around the whole run, in
  `campaign_summary.json` (`cpu_seconds`, `cpu_hours`).
- **Executions.** Sum of the final `stat::number_of_executed_units` over all
  chunks and workers (`campaign_summary.json`, `execs_from_logs`).
- **Coverage over time.** Two independent sources: the `cov:` value of every
  libFuzzer progress line, timestamped in the worker logs (rebuildable with
  `harness/analyze.py`), and a 15-minute checkpoint that replays the live
  corpus with `-runs=0` and records the union edge count
  (`coverage_checkpoints.csv`).
- **Coverage of untouched code.** `scripts/coverage_report.sh` builds a
  coverage-instrumented copy (`-fprofile-instr-generate -fcoverage-mapping`)
  and runs each final corpus through it once, then reports line and function
  coverage per source file with `llvm-cov`.

## Triage

`harness/triage.py` replays every artifact once, extracts a signature (sanitizer
class plus the first three non-interceptor frames), minimises it with
`-minimize_crash=1`, and requires the minimised input to reproduce the same
signature three times. Distinct signatures are counted once. The sanitizer
report, the minimised input, the minimisation log and a JSON record are kept
under `results/<run>/triage/<target>/<sha1>/`.

## Replay (before and after)

`harness/replay.py` executes (a) every unit of the saved final corpus with
`-runs=0` and (b) every crashing input with `-runs=1`, against a named build
directory. The command line, environment and inputs are identical for the
baseline build and the patched build; only `--build` and `--label` differ.

# Baseline results

`<baseline results>`

# Mitigation

`<mitigation>`

# Before and after

`<before and after>`

# Reproduction

`<reproduction>`
