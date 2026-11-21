#!/usr/bin/env python3
"""Replay a fixed input set against a fixed build (used for before/after).

Two kinds of replay:
  corpus  a saved corpus directory is executed once per unit in a single
          process (`-runs=0`), which yields the union edge count for that
          corpus. A crash during the replay is recorded.
  crash   one input file is executed once (`-runs=1`) and the sanitizer
          signature is recorded.

The command line, environment and input files are identical for the baseline
build and the patched build; only --build and --label change.

Output: results/replay/<label>.csv with one row per replay case.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = dict(os.environ)
ENV["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1"
ENV["UBSAN_OPTIONS"] = "print_stacktrace=1"

ASAN_ERR = re.compile(r"ERROR: AddressSanitizer: ([a-z0-9\-]+)", re.I)
COV_RE = re.compile(r"cov: (\d+) ft: (\d+)")
FRAME_SRC = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+)")


def sig_of(out):
    m = ASAN_ERR.search(out)
    if not m:
        if "Assertion" in out:
            return "assert|" + out.split("Assertion")[1][:80]
        return ""
    frames = []
    for line in out.splitlines():
        fm = FRAME_SRC.search(line)
        if fm:
            frames.append("%s %s" % (fm.group(1), fm.group(2)))
        if len(frames) == 3:
            break
    return "%s|%s" % (m.group(1).lower(), " <- ".join(frames))


def run_cmd(cmd, timeout):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=ENV)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out, round(time.time() - t0, 2)
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or "") + (e.stderr or "")) if isinstance(e.stdout, str) else ""
        return -1, out, round(time.time() - t0, 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="baseline")
    ap.add_argument("--build", required=True, help="build/fuzzing directory to test")
    ap.add_argument("--label", required=True, help="baseline or patched")
    ap.add_argument("--corpus-root",
                    default=None,
                    help="defaults to results/<run>/corpus_final")
    ap.add_argument("--triage-csv", default=None,
                    help="defaults to results/<run>/triage/uniq.csv")
    ap.add_argument("--only", default=None,
                    help="comma-separated fuzzer names to replay")
    args = ap.parse_args()

    run = ROOT / "results" / args.run
    build = Path(args.build)
    corpus_root = Path(args.corpus_root) if args.corpus_root else run / "corpus_final"
    triage_csv = Path(args.triage_csv) if args.triage_csv else run / "triage" / "uniq.csv"
    only = set(args.only.split(",")) if args.only else None

    out_dir = ROOT / "results" / "replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []

    for corpus in sorted(p for p in corpus_root.iterdir() if p.is_dir()):
        fuzzer = corpus.name
        if only and fuzzer not in only:
            continue
        units = sorted(p for p in corpus.iterdir() if p.is_file())
        adir = out_dir / "_artifacts" / args.label / fuzzer
        adir.mkdir(parents=True, exist_ok=True)
        cmd = [str(build / fuzzer), str(corpus), "-runs=0", "-timeout=30",
               "-rss_limit_mb=2048", "-artifact_prefix=%s/" % adir]
        rc, out, secs = run_cmd(cmd, timeout=max(600, len(units) // 5))
        cov = ft = 0
        for line in out.splitlines():
            m = COV_RE.search(line)
            if m:
                cov, ft = int(m.group(1)), int(m.group(2))
        new_artifacts = [p.name for p in adir.iterdir()] if adir.exists() else []
        rows.append({"label": args.label, "kind": "corpus", "fuzzer": fuzzer,
                     "input": corpus.name, "units": len(units), "exit": rc,
                     "cov": cov, "ft": ft, "signature": sig_of(out),
                     "seconds": secs,
                     "artifacts": ";".join(sorted(new_artifacts))})
        print("corpus %-24s units=%-6d exit=%-3d cov=%-6d ft=%-7d %.1fs %s"
              % (fuzzer, len(units), rc, cov, ft, secs, sig_of(out)[:40]))

    if triage_csv.exists():
        with open(triage_csv) as fh:
            for t in csv.DictReader(fh):
                fuzzer = t["fuzzer"]
                if only and fuzzer not in only:
                    continue
                for variant in ("original.bin", "minimized"):
                    p = Path(t["path"]) / variant
                    if not p.exists() or p.stat().st_size == 0:
                        continue
                    rc, out, secs = run_cmd([str(build / fuzzer), str(p), "-runs=1",
                                         "-timeout=30"], timeout=300)
                    rows.append({"label": args.label, "kind": "crash",
                                 "fuzzer": fuzzer,
                                 "input": str(p.relative_to(ROOT)),
                                 "units": 1, "exit": rc, "cov": "", "ft": "",
                                 "signature": sig_of(out), "seconds": secs,
                                 "artifacts": ""})
                    print("crash  %-24s %-40s exit=%-3d %s"
                          % (fuzzer, p.name, rc, sig_of(out)[:60]))

    out_csv = out_dir / (args.label + ".csv")
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["label", "kind", "fuzzer", "input",
                                           "units", "exit", "cov", "ft",
                                           "signature", "seconds", "artifacts"])
        w.writeheader()
        w.writerows(rows)
    print("\nwrote", out_csv)


if __name__ == "__main__":
    main()
