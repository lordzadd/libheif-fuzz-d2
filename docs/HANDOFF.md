# Handoff: finish D3 (Track B, libheif)

This document is written for an agent that has no memory of the earlier work and
may run on a different machine, including a cloud runner without Docker. Read it
in full before you start. Part 1 is background, Part 2 is state, Part 3 is the
job, Part 4 is environment, Part 5 is the plan, Part 6 is rules.

## 1. Background

### 1.1 The course deliverable

CPT_S 428/528, Fall 2026. Team "not Claude": Ritvik Sharma (528), Jacob Kolk
(428), Hoang Anh Khoa Ta (428). The D3 assignment has two parts.

Part 1: measure a baseline. For Track B that means a sustained coverage-guided
fuzzing campaign on the D1 target. The report must give CPU-hours, coverage over
time, and how the corpus was built. Each crash must be reproducible, minimised,
root-caused at the line of code with the wrong assumption named, and classified
as exploitable or only a denial of service. A careful null result is acceptable
if it reports the coverage reached and the code the harness never reached.

Part 2: build a mitigation in code, then run the same evaluation again. Only the
system under test may change.

There is a hard reproducibility rule: every number needs the script that
produced it and the raw results in the repository, and a baseline commit tag
must exist before any mitigation code, containing the harness, raw results and
reproduce commands.

### 1.2 D1 and D2, in one paragraph each

D1 chose Track B and target libheif 1.23.4 at upstream commit
`08075aebcc0d9bf7d35f900c36114b1b6e90ed7d` (9 September 2026). The threat model
is a remote attacker who supplies one HEIC/AVIF file to a decoder. The security
property is memory safety: no out-of-bounds access, no use-after-free, no heap
overflow in the decode path. Encoding and denial of service were explicitly out
of the D1 claim.

D2 mapped the attack surface (ISOBMFF box parser, item/property tables, colour
profiles, EXIF/XMP, regions, grid/tile decode, codec bitstreams, uncompressed
codec, sequences) and built the harness: the upstream libFuzzer targets plus a
Docker image pinned by digest.

## 2. State

- Repository: https://github.com/lordzadd/libheif-fuzz-d2
- Branch to work on: `d3-review` (from `main` `f0ff42e`)
- `d3-baseline` -> `1f847a0`: pinned source, both harnesses, all raw results,
  reproduce commands. `git diff 4cb65ae d3-baseline -- libheif` is empty.
- `d3-final` -> `f0ff42e`: M1 + M2 patches, replay, report, PDF.
- Submission file: `D3-not Claude.pdf` (copy of `docs/D3.pdf`). Source:
  `docs/D3.md`.

Two campaigns exist, with different toolchains:

| Campaign | Where | Config | Cost | Findings |
|---|---|---|---|---|
| A | `results/d3/baseline-20261120T173225Z/` | host, Clang 21, codecs off, 5 rounds x 30 s | 0.357 CPU-h | C1, C2 |
| B | `results/baseline/` | Docker, Clang 18, codecs on, ASan, 12 workers, 2 h | 11.30 CPU-h, 88.2 M execs | R1 |

Findings:

- C1 `bitstream.cc:115`, 188 inputs. Zero-length `memcpy` with a null
  destination in `StreamReader_memory::read()`. Undefined behaviour only.
- C2 `heif_items.cc:170`, 31 inputs. Same mistake on an empty item's data.
- R1 `unc_boxes.cc:1365`, 3 artifacts. `Box_snuc::parse()` sizes two `float`
  vectors from header dimensions and reads past the payload. A 45-byte input
  costs 11.9 s and 2 048 MB peak RSS in a release build. Denial of service.

Mitigation:

- M1: zero-length copy guards in `bitstream.cc`, `heif_items.cc`,
  `heif_color.cc`, `hevc_boxes.cc`, `vvc_boxes.cc`, `context.cc`. Class fix.
- M2: payload-size checks before allocation in the three float-array parsers in
  `codecs/uncompressed/unc_boxes.cc` (`snuc`, `splz`, Bayer pattern). Class fix.

Verification already done: 22/22 artifacts abort on the baseline build, 0/22 on
the patched build; the two representatives reproduce the exact UBSan signature;
the release build shows the R1 cost above.

## 3. The gap and the goal

Campaign B found no sanitizer-detected memory-corruption error in 11.3
CPU-hours. That is the only real gap in the submission.

Goal: get one reproducible, minimised, ASan-detected memory-safety violation in
the decode path, with root cause, exploitability call, and a class-level patch.
If you cannot, extend the campaign and keep an honest null result with more
evidence. Never invent impact.

## 4. Cloud environment

You may have no Docker daemon, a different core count, and a wall-clock limit.

**No Docker.** Use the native path:

```sh
git clone https://github.com/lordzadd/libheif-fuzz-d2.git
cd libheif-fuzz-d2
git checkout d3-review
bash scripts/cloud_setup.sh          # apt deps + build into ./build
```

`cloud_setup.sh` installs clang 18, libFuzzer/ASan runtimes, CMake, and the
libde265/x265/aom/zlib/brotli development packages, then runs
`scripts/build_d3.sh` and reuses the committed seed corpora. On x86_64 no
`--platform` flag is needed anywhere.

**Sizing.** One worker uses about one core and 400-800 MB of RSS. Use
`workers = min(cores - 2, RAM_GB)` and set `--rss-limit 1200` when the corpus
grows. A native x86_64 VM runs roughly 2-5x faster than the Rosetta container
that produced the current numbers, so 2 h on 16 cores can exceed 30 CPU-hours.

**Time limits.** The runner may stop the job with SIGTERM. `campaign.py` now
catches SIGTERM, kills the workers, writes `campaign_summary.json` with
`"interrupted": true`, and snapshots the corpus. Results are kept. Still, prefer
phases of 60-90 minutes with distinct labels (`long2a`, `long2b`, ...) so one
timeout cannot lose the whole campaign. Each phase is self-contained.

**Repository size.** A full clone is about 220 MB because the raw results and
corpus tarballs are committed. Do not use `--depth 1` if you need the tags.
Pushing new raw results needs `git add -f` because `results/` and `corpora/` are
ignored.

**Do not touch.** `main`, the `d3-baseline` tag, the `d3-final` tag, and every
file under `results/` that already exists.

## 5. Plan

### 5.1 Run longer, from the committed seeds

```sh
# 90-minute phase, adjust --alloc to the core count
python3 harness/d3/campaign.py --seconds 5400 --run long2a \
  --alloc file_fuzzer=4,api_fuzzer=3,box_fuzzer=2,tile_fuzzer=2,sequence_fuzzer=1 \
  --rss-limit 1200 --max-len 65536 --chunk-seconds 900
```

With Docker, the same through `scripts/run_campaign.sh 5400 long2a ...`.
All tuning values are recorded in `campaign_summary.json`.

After each phase: `python3 harness/d3/analyze.py --run long2a`, then triage new
artifacts with `python3 harness/d3/triage.py --run long2a`. Pack the corpus with
`bash scripts/pack_corpus.sh long2a` before committing it.

### 5.2 Add structured seeds

`harness/d3/prepare_corpus.py` only carves boxes out of the upstream fixtures.
The highest-yield change is a generator that emits valid container skeletons
with randomised `meta`/`iloc`/`iinf`/`ipma`/`iref`/`ipco` tables, so mutations
start inside a valid file instead of repairing a broken one. Add
`harness/d3/gen_seeds.py`, write into `corpora/seed/<target>/`, and keep
`results/corpus_manifest.csv` current. Generated files only, or mutations of the
pinned corpus.

### 5.3 High-yield areas

These are the fixes upstream made after the pin. Use them to choose where to
seed and which target to weight. Do not transplant their test inputs.

| Area | Upstream fix | Target |
|---|---|---|
| `sequences/track.cc` `saiz` sample index | `ec23637e` | `sequence_fuzzer` |
| HEVC SPS validation (GHSA-86ch-j429-fpr2) | `9e2c938d` | `file_fuzzer` |
| AV1 UVLC and unsized OBUs (GHSA-fpr5-xpfr-vcq3, GHSA-jx54-6rm6-2cgj) | `e8e84bb0`, `bbf8e3ab` | `file_fuzzer` |
| Grid/tile bit-depth mismatch (GHSA-vv35-6hxg-95x8, GHSA-3gwx-cjv4-jr74) | `770b0d8d`, `858398f9` | `tile_fuzzer`, `api_fuzzer` |
| Missing grid tiles (GHSA-rcqc-842v-m26h) | `4b12fc8d` | `tile_fuzzer` |

Suggested split for a memory-safety hunt:
`file_fuzzer=4, api_fuzzer=3, tile_fuzzer=2, sequence_fuzzer=2, box_fuzzer=1`.

### 5.4 If you find a memory error

1. Reproduce and minimise with `harness/d3/triage.py`; it requires the same
   signature three times.
2. Root cause with `addr2line -f -C` on the report addresses, then read the code
   and name the wrong assumption, not the ASan message.
3. Classify: exploitable or DoS. Prove it by replaying in a release build
   (`scripts/build_release.sh`).
4. Patch as a class, at the invariant, and check sibling call sites.
5. Add the class to the crash table and to the before/after table in
   `docs/D3.md`, and replay the whole corpus and every artifact on the patch.

### 5.5 If you find nothing

Keep the null result. Update CPU-hours, coverage over time and the
never-reached section from the new run. State plainly that the larger campaign
still found no memory-safety error.

## 6. Rules and deliverables

Rules:

- Do not modify existing `results/` data.
- Do not move `d3-baseline` or `d3-final`. When done, add `d3-final-2`.
- Every number must come from a script in `harness/` and a file in `results/`.
  Regenerate with `python3 harness/d3/tables_d3.py`.
- Synthetic data only; localhost only; no third-party services.
- If a claim cannot be verified, remove it or label it unverified.

Deliverables:

1. New campaign under `results/<label>/` with `campaign_summary.json`,
   `crashes.csv`, logs, and corpus tarballs.
2. If a bug is found: a `C3` row in `docs/D3.md`, a patch commit, a replay table.
3. Updated `docs/D3.md`, `docs/D3.pdf`, `D3-not Claude.pdf`.
4. `docs/CHANGELOG-D3.md` with what changed and the new CPU-hours.
5. Tag `d3-final-2`.

Final checks:

- `git diff 4cb65ae d3-baseline -- libheif` is empty.
- `python3 harness/d3/tables_d3.py` matches the PDF tables.
- `cpu_hours` in the new `campaign_summary.json` matches the report.
- A fresh clone can run `python3 harness/d3/campaign.py --seconds 30 --run smoke`.
- The PDF keeps the seven required sections in order.
