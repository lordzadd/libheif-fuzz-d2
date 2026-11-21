# Handoff: finish D3 (Track B, libheif)

You are taking over a D3 submission that is complete and defensible, but has one
gap: no sanitizer-detected memory-corruption finding. Your job is to try to close
that gap with a stronger campaign, and to keep the submission correct while you
do it. If you cannot close it, the null result stands and must stay honest.

Work on branch `d3-review`. Do not rewrite history and do not move
`d3-baseline`. Add new commits and a new tag when you are done.

## 1. What exists

- Repository: https://github.com/lordzadd/libheif-fuzz-d2
- Branch: `d3-review` (from `main` `f0ff42e`)
- `d3-baseline` -> `1f847a0`: pinned libheif `08075aeb`, both harnesses, all raw
  results, reproduce commands.
- `d3-final` -> `f0ff42e`: M1 (zero-length copies, 6 files) + M2 (header-count
  bounds in `codecs/uncompressed/unc_boxes.cc`) + replay + report + PDF.
- Submission: `D3-not Claude.pdf`; source `docs/D3.md`.

Current results:

| Campaign | Config | Cost | Findings |
|---|---|---|---|
| A (Part 1, `4cb65ae`) | 5 rounds x 30 s, `-fork=2`, codecs off | 0.357 CPU-h | C1 `bitstream.cc:115` (188), C2 `heif_items.cc:170` (31), both UB only |
| B (`harness/d3/`) | 12 workers, 2 h, codecs on, ASan | 11.30 CPU-h, 88.2 M execs | R1 `unc_boxes.cc:1365` (DoS, 45-byte input) |

Campaign B found **no** ASan memory-safety error in 11.3 CPU-hours. That is the
gap you are trying to close.

## 2. Frozen: do not change

- `results/d3/` (Campaign A output) and `results/baseline/` (Campaign B output).
  These are evidence. Never edit, delete or overwrite them.
- `results/verification/verify.csv` and `results/replay/*.csv`.
- The C1/C2 analysis and the M1 patch. They were independently verified:
  22/22 artifacts abort on baseline, 0/22 after M1.
- The pinned target `08075aeb`. A different commit invalidates the D1 scope.

If you run a new campaign, use a **new run label** so it lands in
`results/<newlabel>/` and `corpora/run-<newlabel>/`. Then update the report to
say which campaign produced which number, and keep the old ones.

## 3. Goal and plan

Goal: one reproducible, minimised, ASan-detected memory-safety violation in the
decode path, with root cause (line + wrong assumption), exploitability call, and
a class-level patch. If you find none, extend the campaign and report a bigger
null result with the same rigour.

### 3.1 Run a longer campaign

The harness is now parameterised. Everything below is one command:

```sh
# 6 h wall clock, 12 workers, larger RSS budget, larger inputs
bash scripts/run_campaign.sh 21600 long2 \
  --alloc file_fuzzer=4,api_fuzzer=3,box_fuzzer=2,tile_fuzzer=2,sequence_fuzzer=1 \
  --rss-limit 1200 --max-len 65536 --chunk-seconds 900
```

Notes:

- 12 vCPU and 7.7 GB in the Docker VM. `rss_limit 1200` x 12 is at the RAM edge;
  watch `docker stats`. If the VM swaps, drop to 10 workers.
- Corpora grow to tens of thousands of units and slow worker startup. That is
  why `--rss-limit 1200` matters: the earlier runs produced `oom-*` artifacts at
  800 MB during corpus load, which are harness artifacts, not bugs.
- Longer runs get more value from `file_fuzzer` and `api_fuzzer` (deep decode)
  than from `color_conversion_fuzzer` (cheap, saturated).
- Expect roughly 0.9-1.0 CPU-hours per wall hour per worker under Rosetta.

### 3.2 Add structured seeds

The corpus builder (`harness/d3/prepare_corpus.py`) only carves boxes out of the
133 upstream fixtures. The highest-yield change is a *generator* that emits
valid container skeletons with randomised item/property tables, so mutations
start inside `meta`/`iloc`/`iinf`/`ipma`/`iref` instead of repairing a broken
file. Add `harness/d3/gen_seeds.py` and extend `prepare_corpus.py` to merge its
output. Rules:

- Generate structure from the format (ISO 14496-12 and 23008-12 box layouts).
- Do not copy upstream regression inputs or test-suite fixtures that were added
  after `08075aeb`. Generated files only, or mutations of the pinned corpus.
- Keep the manifest (`results/corpus_manifest.csv`) up to date.

### 3.3 High-yield areas (from upstream history after the pin)

These are the fixes upstream made after `08075aeb`. Use them to choose where to
aim the corpus and which target to weight. Do not transplant their test inputs.

| Area | Upstream fix | Target | Why it is interesting |
|---|---|---|---|
| `sequences/track.cc` `saiz` sample index | `ec23637e` | `sequence_fuzzer` | index runs past the aux-info chunk |
| HEVC SPS validation | `9e2c938d` (GHSA-86ch-j429-fpr2) | `file_fuzzer` | crafted SPS reaches libde265 |
| AV1 UVLC / unsized OBUs | `e8e84bb0`, `bbf8e3ab` | `file_fuzzer` | AV1 bitstream parse |
| Grid/tile bit depth, alpha >16 bit | `770b0d8d`, `858398f9` (GHSA-vv35-6hxg-95x8, GHSA-3gwx-cjv4-jr74) | `tile_fuzzer`, `api_fuzzer` | plane mismatch in composition |
| Missing grid tiles | `4b12fc8d` (GHSA-rcqc-842v-m26h) | `tile_fuzzer` | job scheduling on absent tiles |

A reasonable split for a memory-safety hunt:
`file_fuzzer=4, api_fuzzer=3, tile_fuzzer=2, sequence_fuzzer=2, box_fuzzer=1`.

### 3.4 If you find a memory error

1. Reproduce with `harness/d3/triage.py`; it minimises and checks the signature
   three times.
2. Root cause: `addr2line -f -C` on the report addresses, then read the code and
   name the wrong assumption, not the ASan message.
3. Classify: exploitable or DoS. Prove it: replay in a release build
   (`scripts/build_release.sh`) and say what still happens.
4. Patch it as a class, not a single line. Add the guard where the invariant
   belongs, and check the sibling call sites.
5. Add the new class to the report's crash table and to the before/after table.
6. Replay the whole corpus and every artifact on the patched build.

### 3.5 If you find nothing

Keep the null result. Update the CPU-hours, the coverage tables and the
never-reached section from the new run. Say plainly that the larger campaign
still found no memory-safety error. Do not invent impact.

## 4. Rules

- Do not edit or delete existing `results/` data.
- Do not move `d3-baseline` or `d3-final`. When done, add `d3-final-2` and say
  in the report which commit it points to.
- Every number in the report must come from a script in `harness/` and a file in
  `results/`. Regenerate with `python3 harness/d3/tables_d3.py`.
- No real user data, no third-party services, localhost only.
- If you cannot verify a claim, remove it or label it as unverified.

## 5. Deliverables

1. New campaign under `results/<label>/` with `campaign_summary.json`,
   `crashes.csv`, logs and corpus tarballs.
2. If a bug is found: `C3` row in `docs/D3.md`, a patch commit, a replay table.
3. Updated `docs/D3.md` and `docs/D3.pdf` plus `D3-not Claude.pdf`.
4. A short `docs/CHANGELOG-D3.md` stating what changed and the new CPU-hours.
5. Tag `d3-final-2`.

## 6. Check before you finish

- `git diff 4cb65ae d3-baseline -- libheif` is empty.
- `python3 harness/d3/tables_d3.py` matches the PDF tables.
- The new campaign's `campaign_summary.json` `cpu_hours` matches the report.
- A fresh clone can run `scripts/run_campaign.sh 60 smoke`.
- The PDF keeps the seven required sections in order.
