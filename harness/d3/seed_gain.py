#!/usr/bin/env python3
"""Measure the edge coverage that the generated seeds add (D3, Campaign C).

For each target, replay three input sets once with libFuzzer `-runs=0` and read
the `INITED cov: N ft: M` line, which is the union coverage of the set:

  B        Campaign B's final corpus (results/baseline/corpus_final_tar/<t>.tar.gz)
  gen      the generated seeds only (corpora/seed/<t>/gen-*, gen_seeds.py)
  B+gen    both together

The gain of B+gen over B is coverage that 11.3 CPU-hours of mutation from the
carved seeds had not reached. Same flags as the campaign checkpoints
(campaign.py coverage_checkpoints): no value profile, -timeout=30.

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
    cmd = [str(BUILD / fuzzer), "-runs=0", "-timeout=30", "-rss_limit_mb=2048",
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
    args = ap.parse_args()
    rows = []
    tmp = Path(tempfile.mkdtemp(prefix="seedgain-"))
    try:
        for t in args.targets.split(","):
            tb = ROOT / "results" / "baseline" / "corpus_final_tar" / (t + ".tar.gz")
            with tarfile.open(tb) as tf:
                tf.extractall(tmp, filter="data")
            bdir = tmp / t
            gdir = tmp / (t + "-gen")
            gdir.mkdir()
            for p in (ROOT / "corpora" / "seed" / t).glob("gen-*"):
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
