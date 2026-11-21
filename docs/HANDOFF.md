# Handoff: D3 review (Track B, libheif)

You are reviewing a finished D3 submission for CPT_S 428/528. Your job is to find
what would lose points, not to rewrite the work. Produce a written review with
severity, evidence and a concrete fix for each item. Do not change `main`.

## 1. State

- Repository: https://github.com/lordzadd/libheif-fuzz-d2
- Branch to review: `d3-review` (identical to `main` at `f0ff42e`)
- Tag `d3-baseline` -> `1f847a0` (pinned source, both harnesses, all raw results)
- Tag `d3-final` -> `f0ff42e` (M1 + M2 patches, replay, report, PDF)
- Target: libheif 1.23.4, upstream commit `08075aebcc0d9bf7d35f900c36114b1b6e90ed7d`
- Submission file: `D3-not Claude.pdf` (copy of `docs/D3.pdf`)
- Report source: `docs/D3.md`

The team is "not Claude": Ritvik Sharma (528), Jacob Kolk (428),
Hoang Anh Khoa Ta (428).

## 2. What the submission claims

Two campaigns:

- Campaign A (Part 1, commit `4cb65ae`): 0.357 CPU-hours, 35 rounds, 226
  artifacts in two classes, C1 `bitstream.cc:115` (188 inputs) and C2
  `heif_items.cc:170` (31 inputs). Both are zero-length `memcpy` with a null
  pointer: undefined behaviour, not memory corruption.
- Campaign B (this line, `harness/d3/`): 11.30 CPU-hours, 12 workers, 2 h 3 min,
  88 173 327 executions, 164 907 corpus units. No ASan memory-safety finding
  (reported as a null result). One new class R1: `unc_boxes.cc:1365`
  (`Box_snuc::parse`) sizes two `float` vectors from header dimensions and reads
  past the payload. A 45-byte input costs 11.9 s and 2 048 MB peak RSS in a
  release build, 17.6 s and ~2.1 GB under ASan with a 4 GB limit. Classified as
  denial of service.

Mitigation: M1 guards zero-length copies in six files (class fix). M2 adds
`get_remaining_bytes()` checks to three float-array parsers in
`codecs/uncompressed/unc_boxes.cc` (class fix).

Before/after: 226/226 artifacts abort on baseline, 0/226 after M1; independent
replay 22/22 -> 0/22; R1 45 bytes 11.9 s / 2 048 MB -> 0.07 s / 47 MB.

## 3. Review checklist (in priority order)

1. **Numbers against raw data.** Pick at least ten numbers from the PDF and
   trace each to a file under `results/`. Start with the cost table, the
   coverage-over-time table, the crash counts, and the before/after table. Use
   `python3 harness/d3/tables_d3.py` and
   `harness/d3/analyze.py --run baseline`. Report every mismatch.
2. **Baseline tag integrity.** Confirm `git diff 4cb65ae d3-baseline -- libheif`
   is empty (pinned source) and that the tag contains harness, raw results and
   the reproduce commands. Confirm `d3-final` contains M1 and M2:
   `git diff 660f468 d3-final -- libheif` should show only the M2 hunk.
3. **R1 validity.** Decide whether R1 is a legitimate finding or a harness
   artifact. The counter-evidence is in `results/baseline/rss_measure.csv` (a
   release build with no sanitizer still costs 11.9 s / 2 048 MB). Check that
   the minimized input really is 45 bytes and that the patch rejects it:
   `results/baseline/repro_snuc_oom_min.bin`.
4. **Patch correctness.** Read the M2 hunk. Check the arithmetic
   (`get_remaining_bytes() / bytes_per_element < count`), the element sizes
   (8 bytes for `snuc`, 8 for `cmpd`, 4 for `splz`), and whether the loops can
   still over-read after the guard. Check whether the same pattern exists in
   other boxes that were not patched.
5. **Coverage claims.** Verify 44.9 % lines / 45.8 % functions / 42.2 % branches
   from `results/baseline/coverage/cov-report-file_fuzzer.txt`. Verify the
   "23 files never entered" list and the `region.cc` 0/441 claim.
6. **Reproducibility.** Run `scripts/run_campaign.sh 60 smoke` and confirm it
   produces `results/smoke/campaign_summary.json`. Check that a fresh clone can
   rebuild with `scripts/build_docker.sh` and `scripts/build_d3.sh`.
7. **Rubric coverage.** Map each required PDF section (Repository, Setup,
   Method, Baseline results, Mitigation, Before and after, Reproduction) to the
   text. Flag anything missing or unsupported.

## 4. Known weaknesses (do not spend time rediscovering)

- There is no sanitizer-detected memory-corruption finding. The assignment
  allows a null result; the report says so explicitly.
- R1 is a denial of service. It is outside the D1 disclosure commitment, which
  covers memory safety only.
- Two `slow-unit` artifacts and one 0-byte OOM artifact do not reproduce in
  isolation (0.33 s and 0.11 s) and are reported as load artifacts.
- The `tile_fuzzer` corpus replay first read 9 078 edges and read 9 184 on a
  repeat with a longer per-unit timeout. Both values are in the report.
- The PDF names `05d83e2` as the final commit and says the tag also includes the
  report. The tag now points at `f0ff42e`, two commits later. Check whether the
  wording is good enough.
- `results/d3/` (Campaign A) was produced by the teammate's harness on a
  different machine and toolchain. Do not expect byte-identical binaries.
- Build directories are not committed. `build/` and `build-patched/` are local
  only; a fresh clone must rebuild.

## 5. Commands

```sh
git clone https://github.com/lordzadd/libheif-fuzz-d2.git
cd libheif-fuzz-d2
git checkout d3-review
git tag -l

# Numbers
python3 harness/d3/tables_d3.py
cat results/D3_tables.md

# Fresh builds (needs Docker)
bash scripts/build_docker.sh
BUILD_DIR="$PWD/build-patched" bash scripts/build_d3.sh
docker run --rm --platform linux/amd64 -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/repo -w /repo libheif-fuzz:1.23.4 \
  bash -lc 'ASAN_OPTIONS=detect_leaks=0 ./build-patched/fuzzing/box_fuzzer \
  /repo/results/baseline/repro_snuc_oom_min.bin -runs=1 -rss_limit_mb=800'

# Baseline build for comparison (pinned source)
git worktree add /tmp/heif-base d3-baseline
# then run scripts/build_d3.sh inside /tmp/heif-base
```

## 6. Constraints

- Do not force-push, rewrite history, or move the tags.
- Do not modify `results/`. It is evidence.
- Do not run a new long campaign. A 60 s smoke run is enough.
- Cite file paths and line numbers in every finding.
- If a claim cannot be verified, say so and say what is missing.

## 7. Deliverable

A review document with:

1. a verdict per PDF section (pass / weak / fail) and the reason;
2. a defect list, each with severity, evidence path, and a one-line fix;
3. a short list of what a grader is likely to re-run, and whether it works;
4. a final recommendation: submit as is, or make specific changes first.
