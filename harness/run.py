#!/usr/bin/env python3
"""D2 harness for the libheif fuzzing campaign.

Builds libheif (if needed), runs every fuzzer for a short time, and writes
one row per fuzzer with crashes found and execution counts.

Usage: python3 harness/run.py [seconds_per_fuzzer]   (default 5)
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
FUZZ_DIR = BUILD / "fuzzing"
RESULTS = ROOT / "results"
CORPUS_SRC = ROOT / "libheif" / "fuzzing" / "data" / "corpus"


def run_build():
    script = ROOT / "scripts" / "build.sh"
    print("Building libheif fuzzers...", flush=True)
    subprocess.run([str(script)], check=True, cwd=ROOT)


def ensure_build():
    fuzzers = sorted(FUZZ_DIR.glob("*_fuzzer")) if FUZZ_DIR.exists() else []
    if not fuzzers:
        run_build()
    fuzzers = sorted(FUZZ_DIR.glob("*_fuzzer"))
    if not fuzzers:
        raise RuntimeError("No fuzzers built in " + str(FUZZ_DIR))
    return fuzzers


def seed_corpus(dest):
    dest.mkdir(parents=True, exist_ok=True)
    if CORPUS_SRC.exists():
        for p in CORPUS_SRC.iterdir():
            if p.is_file():
                target = dest / p.name
                if not target.exists():
                    shutil.copy2(p, target)


def parse_stat(text, key):
    m = re.search(r"stat::" + re.escape(key) + r":\s*(\d+)", text)
    if m:
        return int(m.group(1))
    m = re.search(re.escape(key) + r"[:=]\s*(\d+)", text)
    return int(m.group(1)) if m else 0


def as_text(s):
    if isinstance(s, bytes):
        return s.decode("utf-8", "replace")
    return s or ""


def run_one(fuzzer, seconds):
    name = fuzzer.name
    corpus = ROOT / "corpora" / name
    crash_dir = RESULTS / "crashes" / name
    # Start every run from the same seed corpus and an empty crash dir,
    # so numbers from one run do not leak into the next.
    shutil.rmtree(corpus, ignore_errors=True)
    shutil.rmtree(crash_dir, ignore_errors=True)
    corpus.mkdir(parents=True, exist_ok=True)
    crash_dir.mkdir(parents=True, exist_ok=True)
    seed_corpus(corpus)

    cmd = [
        str(fuzzer),
        str(corpus),
        f"-max_total_time={seconds}",
        "-print_final_stats=1",
        "-artifact_prefix=" + str(crash_dir) + "/",
    ]
    env = dict(os.environ)
    # Upstream ships an LSan suppression for a known x265 leak in the encoder fuzzer.
    supp = fuzzer.parent / f"{name}_lsan_suppressions.txt"
    if supp.exists():
        env["LSAN_OPTIONS"] = f"suppressions={supp}"
    print(f"Running {name} for {seconds}s...", flush=True)
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60, env=env)
        rc = proc.returncode
        out = as_text(proc.stdout) + "\n" + as_text(proc.stderr)
    except subprocess.TimeoutExpired as e:
        rc = -1
        out = as_text(e.stdout) + "\n" + as_text(e.stderr)
    elapsed = round(time.time() - start, 2)
    (crash_dir / "log.txt").write_text(out)

    crashes = len(list(crash_dir.glob("crash-*"))) + len(list(crash_dir.glob("leak-*")))
    timeouts = len(list(crash_dir.glob("timeout-*"))) + len(list(crash_dir.glob("oom-*")))
    execs = parse_stat(out, "number_of_executed_units")
    # libFuzzer reports edge coverage as "cov: N" on each status line; keep the last one.
    cov = [int(c) for c in re.findall(r"\bcov: (\d+)", out)]
    coverage = cov[-1] if cov else 0
    # fallback for execs
    if execs == 0:
        m = re.search(r"(\d+)\s+execs", out)
        if m:
            execs = int(m.group(1))

    return {
        "fuzzer": name,
        "exit_code": rc,
        "elapsed_s": elapsed,
        "crashes_found": crashes,
        "timeouts_ooms": timeouts,
        "execs": execs,
        "coverage_edges": coverage,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seconds", nargs="?", type=int, default=5,
                    help="fuzzing time per fuzzer in seconds (default 5)")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    try:
        fuzzers = ensure_build()
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2))
        sys.exit(1)

    rows = []
    for f in fuzzers:
        rows.append(run_one(f, args.seconds))

    out_csv = RESULTS / "fuzz_results.csv"
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    total_crashes = sum(r["crashes_found"] for r in rows)
    summary = {
        "fuzzers_run": len(rows),
        "total_crashes": total_crashes,
        "crash_rate": round(total_crashes / len(rows), 4) if rows else 0.0,
        "output": str(out_csv),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
