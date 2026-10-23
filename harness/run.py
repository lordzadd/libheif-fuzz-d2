#!/usr/bin/env python3
"""D2 harness for the libheif fuzzing campaign.

Builds libheif (if needed), runs every fuzzer for a short time, and writes
one row per fuzzer with crashes found and execution counts.
"""

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


def run_one(fuzzer):
    name = fuzzer.name
    corpus = ROOT / "corpora" / name
    crash_dir = RESULTS / "crashes" / name
    corpus.mkdir(parents=True, exist_ok=True)
    crash_dir.mkdir(parents=True, exist_ok=True)
    seed_corpus(corpus)

    cmd = [
        str(fuzzer),
        str(corpus),
        "-max_total_time=5",
        "-print_final_stats=1",
        "-artifact_prefix=" + str(crash_dir) + "/",
    ]
    print(f"Running {name} for 5s...", flush=True)
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        rc = proc.returncode
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        rc = -1
        out = (e.stdout or "") + "\n" + (e.stderr or "")
    elapsed = round(time.time() - start, 2)

    crashes = len(list(crash_dir.glob("crash-*"))) + len(list(crash_dir.glob("oom-*"))) + len(list(crash_dir.glob("timeout-*")))
    execs = parse_stat(out, "number_of_executed_units")
    edges = parse_stat(out, "number_of_new_units_added") or parse_stat(out, "edges_found")
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
        "execs": execs,
        "edges": edges,
    }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    try:
        fuzzers = ensure_build()
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2))
        sys.exit(1)

    rows = []
    for f in fuzzers:
        rows.append(run_one(f))

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
