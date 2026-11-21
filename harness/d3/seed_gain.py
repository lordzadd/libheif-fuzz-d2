#!/usr/bin/env python3
"""Measure the edge coverage that the generated seeds add (D3, Campaign C).

For each target, replay three input sets once with libFuzzer `-runs=0` and read
the `INITED cov: N ft: M` line, which is the union coverage of the set:

  B        Campaign B's final corpus (results/baseline/corpus_final_tar/<t>.tar.gz)
  gen      the generated seeds only (corpora/seed/<t>/gen-*, gen_seeds.py)
  B+gen    both together

The gain of B+gen over B is coverage that 11.3 CPU-hours of mutation from the
carved seeds had not reached. Same flags as the campaign checkpoints
(campaign.py coverage_checkpoints): no value profile; -timeout=60 (see replay()).

  python3 harness/d3/seed_gain.py --out results/long2a/seed_gain.csv
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "fuzzing"
INITED = re.compile(r"INITED cov: (\d+) ft: (\d+) corp: (\d+)/")
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:symbolize=0")


def replay(fuzzer, dirs):
    # -timeout=60: with 30 s, tile_fuzzer loses ~100 edges on a loaded machine
    # (results/replay/tile_repeat.txt); run on an idle machine for final numbers.
    cmd = [str(BUILD / fuzzer), "-runs=0", "-timeout=60", "-rss_limit_mb=2048",
           "-max_len=65536"] + [str(d) for d in dirs]
    p = subprocess.run(cmd, capture_output=True, text=True, env=ENV, timeout=7200)
    m = None
    for line in (p.stdout + p.stderr).splitlines():
        mm = INITED.search(line)
        if mm:
            m = mm
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="file_fuzzer,api_fuzzer,tile_fuzzer")
    ap.add_argument("--out", default=str(ROOT / "results" / "long2a" / "seed_gain.csv"))
    ap.add_argument("--manifest", action="append",
                    help="gen_seed_manifest.csv selecting which gen-* seeds form the "
                         "'gen' set (repeatable); default: every gen-* file")
    args = ap.parse_args()
    wanted = None
    if args.manifest:
        wanted = set()
        for m in args.manifest:
            with open(m) as fh:
                wanted |= {r["sha1"] for r in csv.DictReader(fh)}
    rows = []
    tmp = Path(tempfile.mkdtemp(prefix="seedgain-"))
    try:
        for t in args.targets.split(","):
            tb = ROOT / "results" / "baseline" / "corpus_final_tar" / (t + ".tar.gz")
            with tarfile.open(tb) as tf:
                tf.extractall(tmp, filter="data")
            bdir = tmp / t
            # Campaign B's tarballs were made on macOS and carry one AppleDouble
            # '._<name>' metadata file per unit. They are not fuzz inputs.
            for junk in bdir.glob("._*"):
                junk.unlink()
            gdir = tmp / (t + "-gen")
            gdir.mkdir()
            for p in (ROOT / "corpora" / "seed" / t).glob("gen-*"):
                if wanted is None or p.name[4:] in wanted:
                    shutil.copy2(p, gdir / p.name)
            for label, dirs in (("B", [bdir]), ("gen", [gdir]), ("B+gen", [bdir, gdir])):
                r = replay(t, dirs)
                row = {"fuzzer": t, "set": label,
                       "inputs": sum(len(list(d.iterdir())) for d in dirs),
                       "cov": r[0] if r else "", "ft": r[1] if r else "",
                       "inited_units": r[2] if r else ""}
                rows.append(row)
                print(row, flush=True)
            shutil.rmtree(bdir)
            shutil.rmtree(gdir)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", out)


if __name__ == "__main__":
    main()
