#!/usr/bin/env python3
"""Build and run the pinned libheif fuzz targets with fixed input counts."""

import csv
import datetime as dt
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
CORPUS_SRC = ROOT / "libheif" / "fuzzing" / "data" / "corpus"
FUZZER_NAMES = (
    "api_fuzzer", "box_fuzzer", "color_conversion_fuzzer", "encoder_fuzzer",
    "file_fuzzer", "sequence_fuzzer", "tile_fuzzer",
)


def ensure_build():
    print("Building all pinned libheif fuzz targets...", flush=True)
    subprocess.run([str(ROOT / "scripts" / "build.sh")], check=True, cwd=ROOT)
    missing = [name for name in FUZZER_NAMES if not (FUZZ_DIR / name).is_file()]
    if missing:
        raise RuntimeError("Build did not produce expected fuzzers: " + ", ".join(missing))
    return [FUZZ_DIR / name for name in FUZZER_NAMES]


def parse_stat(text, key):
    match = re.search(r"stat::" + re.escape(key) + r":\s*(\d+)", text)
    if match:
        return int(match.group(1))
    match = re.search(re.escape(key) + r"[:=]\s*(\d+)", text)
    return int(match.group(1)) if match else None


def seed_corpus(dest):
    dest.mkdir(parents=True, exist_ok=True)
    if not CORPUS_SRC.is_dir():
        return 0
    count = 0
    for source in CORPUS_SRC.rglob("*"):
        if source.is_file():
            target = dest / source.relative_to(CORPUS_SRC)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            count += 1
    return count


def decode_output(value):
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def run_one(fuzzer, corpus_root, output_dir, runs, timeout_s):
    name = fuzzer.name
    corpus = corpus_root / name
    artifacts = output_dir / "artifacts" / name
    logs = output_dir / "logs"
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    seed_count = seed_corpus(corpus)
    logs.mkdir(parents=True, exist_ok=True)
    command = [
        str(fuzzer), str(corpus), "-runs=" + str(runs), "-print_final_stats=1",
        "-artifact_prefix=" + str(artifacts) + "/",
    ]
    print("Running " + name + ": requested " + str(runs) + " executions", flush=True)
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=timeout_s, cwd=ROOT,
        )
        rc = proc.returncode
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as error:
        timed_out = True
        rc = None
        output = decode_output(error.stdout) + "\n" + decode_output(error.stderr)
    elapsed = round(time.monotonic() - started, 2)
    (logs / (name + ".log")).write_text(output, errors="replace")

    execs = parse_stat(output, "number_of_executed_units")
    if execs is None:
        match = re.search(r"(\d+)\s+execs", output)
        execs = int(match.group(1)) if match else None
    crashes = sum(
        1 for path in artifacts.iterdir()
        if path.is_file() and path.name.startswith(("crash-", "oom-", "timeout-"))
    )
    reasons = []
    if timed_out:
        reasons.append("timeout")
    if rc not in (0, None):
        reasons.append("nonzero_exit")
    if execs is None:
        reasons.append("missing_execution_stat")
    if crashes:
        reasons.append("crash_artifact")
    return {
        "fuzzer": name, "requested_runs": runs, "seed_files": seed_count,
        "execs": execs, "crashes_found": crashes, "exit_code": rc,
        "timed_out": timed_out, "elapsed_s": elapsed,
        "failure_reasons": ";".join(reasons),
    }


def main():
    try:
        runs = int(os.environ.get("FUZZ_RUNS", "1000"))
        timeout_s = int(os.environ.get("FUZZ_TIMEOUT_SECONDS", "300"))
        if runs < 1 or timeout_s < 1:
            raise ValueError("FUZZ_RUNS and FUZZ_TIMEOUT_SECONDS must be positive integers")
    except ValueError as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 2

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = ROOT / "results" / stamp
    suffix = 1
    while output_dir.exists():
        output_dir = ROOT / "results" / (stamp + "-" + str(suffix))
        suffix += 1
    corpus_root = output_dir / "corpora"
    output_dir.mkdir(parents=True)

    try:
        fuzzers = ensure_build()
    except Exception as error:
        summary = {
            "fuzzers_run": 0, "total_executed_inputs": 0, "total_crashes": 0,
            "failed_fuzzers": ["build"], "error": str(error),
            "output_dir": str(output_dir.relative_to(ROOT)),
        }
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
        return 1

    rows = [run_one(fuzzer, corpus_root, output_dir, runs, timeout_s) for fuzzer in fuzzers]
    csv_path = output_dir / "fuzz_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    total_inputs = sum(row["execs"] or 0 for row in rows)
    total_crashes = sum(row["crashes_found"] for row in rows)
    failed = [row["fuzzer"] for row in rows if row["failure_reasons"]]
    summary = {
        "fuzzers_run": len(rows), "requested_runs_per_fuzzer": runs,
        "total_executed_inputs": total_inputs, "total_crashes": total_crashes,
        "crash_rate_per_executed_input": round(total_crashes / total_inputs, 8) if total_inputs else 0.0,
        "failed_fuzzers": failed, "output_dir": str(output_dir.relative_to(ROOT)),
        "csv": str(csv_path.relative_to(ROOT)),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
