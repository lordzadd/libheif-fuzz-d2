#!/usr/bin/env python3
"""Run every input in a directory through one fuzz target, one process each,
and record the sanitizer signature (D3, Campaign D).

  python3 harness/d3/sweep_run.py --bin build-master/fuzzing/decode_matrix_fuzzer \
      --inputs /tmp/sweep/matrix --out results/sweep/master.csv --jobs 2

Columns: input, exit, kind (ASan class or libFuzzer error), frame (first
non-interceptor frame with file:line), seconds.
"""

import argparse
import concurrent.futures as cf
import csv
import os
import re
import subprocess
import time
from pathlib import Path

ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:symbolize=1:abort_on_error=0")
ASAN = re.compile(r"ERROR: AddressSanitizer: ([a-z0-9\-]+)")
OTHER = re.compile(r"ERROR: libFuzzer: ([a-z\-]+)|runtime error: (.*)")
CONTRACT = re.compile(r"CONTRACT-VIOLATION (\S+) handle=(\S+) image=(\S+) item=\S+ \((\w+)\)")
FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.+?) (/\S+:\d+)")
SKIP = ("__asan", "__interceptor", "memcpy", "memmove", "memset")


def run(binary, path):
    t = time.time()
    try:
        p = subprocess.run([binary, str(path), "-runs=1", "-timeout=60", "-rss_limit_mb=4096"],
                           capture_output=True, text=True, env=ENV, timeout=300)
        out, rc = p.stdout + p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return {"input": path.name, "exit": "timeout", "kind": "timeout", "frame": "",
                "seconds": round(time.time() - t, 2)}
    kind, frame = "", ""
    c = CONTRACT.search(out)
    if c:
        return {"input": path.name, "exit": rc, "kind": "contract:" + c.group(1),
                "frame": "%s handle=%s image=%s" % (c.group(4), c.group(2), c.group(3)),
                "seconds": round(time.time() - t, 2)}
    m = ASAN.search(out)
    if m:
        kind = m.group(1)
    else:
        m = OTHER.search(out)
        if m:
            kind = m.group(1) or ("ubsan: " + m.group(2)[:80])
    if kind:
        for fm in FRAME.finditer(out):
            if not fm.group(1).startswith(SKIP):
                frame = fm.group(1).split("(")[0] + " " + fm.group(2).split("/libheif/libheif/")[-1]
                break
    return {"input": path.name, "exit": rc, "kind": kind, "frame": frame,
            "seconds": round(time.time() - t, 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=2)
    args = ap.parse_args()
    files = sorted(p for p in Path(args.inputs).iterdir() if p.is_file())
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        rows = list(ex.map(lambda p: run(args.bin, p), files))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["input", "exit", "kind", "frame", "seconds"])
        w.writeheader()
        w.writerows(rows)
    sig = {}
    for r in rows:
        if r["kind"]:
            sig.setdefault((r["kind"], r["frame"]), []).append(r["input"])
    print("%d inputs, %d with a finding, %d distinct signatures" %
          (len(rows), sum(len(v) for v in sig.values()), len(sig)))
    for (k, f), v in sorted(sig.items(), key=lambda kv: -len(kv[1])):
        print("%5d  %s  %s  e.g. %s" % (len(v), k, f, v[0]))


if __name__ == "__main__":
    main()
