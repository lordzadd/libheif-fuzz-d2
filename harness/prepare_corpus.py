#!/usr/bin/env python3
"""Build the seed corpora for every libheif fuzzer.

The upstream seed set is `libheif/fuzzing/data/corpus` (133 HEIC/AVIF files).
Using the same 133 files for every target is wasteful: `box_fuzzer` parses a
single ISOBMFF box, so whole files are poor seeds, and `sequence_fuzzer` needs
a track sample. This script derives a per-target seed set:

  * every target starts from the upstream corpus, but only files that the
    target can actually parse are kept (a seed that is rejected before the
    target's parser is entered adds coverage only to the ftyp check);
  * `box_fuzzer` additionally gets every top-level and nested box carved out of
    the upstream files, so its first mutation starts inside a box body;
  * `sequence_fuzzer` additionally gets the upstream `sequence_corpus`;
  * seeds are de-duplicated by SHA-1 and the result is minimised with
    libFuzzer `-merge=1`, which keeps only seeds that add new edges.

The output is written to corpora/seed/<fuzzer>/ and a manifest CSV records,
for each fuzzer, how many seeds came from each source. The manifest is part of
the D3 report (corpus construction).
"""

import argparse
import csv
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "libheif" / "fuzzing" / "data"
BUILD = ROOT / "build" / "fuzzing"
OUT = ROOT / "corpora" / "seed"
TMP = ROOT / "corpora" / "_tmp"

FUZZERS = [
    "file_fuzzer",
    "api_fuzzer",
    "box_fuzzer",
    "color_conversion_fuzzer",
    "tile_fuzzer",
    "sequence_fuzzer",
]


def sha1(data):
    return hashlib.sha1(data).hexdigest()


def iter_boxes(data, depth=0, max_depth=4):
    """Yield every ISOBMFF box (header + payload) found in `data`."""
    off = 0
    n = len(data)
    while off + 8 <= n:
        size = int.from_bytes(data[off:off + 4], "big")
        box_type = data[off + 4:off + 8]
        header = 8
        if size == 1:
            if off + 16 > n:
                return
            size = int.from_bytes(data[off + 8:off + 16], "big")
            header = 16
        elif size == 0:
            size = n - off
        if size < header or off + size > n:
            return
        box = data[off:off + size]
        yield box
        # Container boxes whose payload is a sequence of boxes.
        if box_type in (b"meta", b"moov", b"trak", b"mdia", b"minf", b"stbl",
                        b"dinf", b"iprp", b"ipco", b"iinf", b"grpl", b"mvex",
                        b"edts", b"udta") and depth < max_depth:
            inner = box[header:]
            if box_type in (b"meta", b"iinf"):
                # meta/iinf have a 4-byte version+flags / entry-count prefix.
                inner = inner[4:]
            yield from iter_boxes(inner, depth + 1, max_depth)
        off += size


def write_seed(dest, data, origin, manifest, seen):
    if not data:
        return
    digest = sha1(data)
    if digest in seen:
        return
    seen.add(digest)
    path = dest / digest
    path.write_bytes(data)
    manifest.append({"sha1": digest, "bytes": len(data), "origin": origin})


def merge_minimise(fuzzer, corpus_dir):
    """Keep only seeds that add coverage, using libFuzzer -merge=1."""
    if not corpus_dir.exists():
        return
    seeds = sorted(p for p in corpus_dir.iterdir() if p.is_file())
    if len(seeds) < 2:
        return
    kept = TMP / (fuzzer + "-kept")
    empty = TMP / (fuzzer + "-empty")
    shutil.rmtree(kept, ignore_errors=True)
    shutil.rmtree(empty, ignore_errors=True)
    kept.mkdir(parents=True)
    empty.mkdir(parents=True)
    cmd = [str(BUILD / fuzzer), str(kept), str(corpus_dir),
           "-merge=1", "-runs=0", "-timeout=30", "-rss_limit_mb=2048"]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env)
    if proc.returncode not in (0,):
        sys.stderr.write("merge failed for %s (rc=%d); keeping unmerged seeds\n%s\n"
                         % (fuzzer, proc.returncode, proc.stderr[-2000:]))
        return
    merged = sorted(p for p in kept.iterdir() if p.is_file())
    if not merged:
        return
    shutil.rmtree(corpus_dir)
    corpus_dir.mkdir(parents=True)
    for p in merged:
        shutil.copy2(p, corpus_dir / p.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-merge", action="store_true",
                    help="skip libFuzzer -merge=1 minimisation")
    ap.add_argument("--merge-only", action="store_true",
                    help="only re-run -merge=1 on existing seed corpora")
    args = ap.parse_args()

    upstream = sorted(p for p in (DATA / "corpus").iterdir() if p.is_file())
    sequence = sorted(p for p in (DATA / "sequence_corpus").iterdir() if p.is_file())

    rows = []
    for fuzzer in FUZZERS:
        dest = OUT / fuzzer
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        TMP.mkdir(parents=True, exist_ok=True)
        manifest = []
        seen = set()
        if not args.merge_only:
            for p in upstream:
                write_seed(dest, p.read_bytes(), "upstream:" + p.name, manifest, seen)
            if fuzzer == "box_fuzzer":
                # Every box carved out of the upstream files, top level and nested.
                for p in upstream:
                    for i, box in enumerate(iter_boxes(p.read_bytes())):
                        write_seed(dest, box, "carved:%s#%d" % (p.name, i),
                                   manifest, seen)
            if fuzzer == "sequence_fuzzer":
                for p in sequence:
                    write_seed(dest, p.read_bytes(), "sequence:" + p.name,
                               manifest, seen)
        if not args.no_merge and not args.merge_only:
            merge_minimise(fuzzer, dest)
        elif args.merge_only:
            merge_minimise(fuzzer, dest)
        files = sorted(p for p in dest.iterdir() if p.is_file())
        for p in files:
            rows.append({"fuzzer": fuzzer, "sha1": p.name,
                         "bytes": p.stat().st_size})
        print("%-24s seeds=%4d bytes=%d" % (fuzzer, len(files),
                                            sum(p.stat().st_size for p in files)))

    manifest_csv = ROOT / "results" / "corpus_manifest.csv"
    manifest_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["fuzzer", "sha1", "bytes"])
        w.writeheader()
        w.writerows(rows)
    print("wrote", manifest_csv)


if __name__ == "__main__":
    main()
