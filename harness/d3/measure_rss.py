#!/usr/bin/env python3
"""Measure wall time and peak RSS of one input against a fuzzer binary.

The release build has no sanitizer, so this is the closest thing to what a photo
service would run. Peak RSS is read from /proc/<pid>/status VmHWM while the
process runs; the fuzzer exits by itself after the single input.

  python3 harness/d3/measure_rss.py --target build-release/fuzzing/box_fuzzer \
      --input results/baseline/repro_snuc_oom_min.bin

Prints one CSV row: target,input,exit,wall_s,peak_rss_mb
"""

import argparse
import subprocess
import time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--timeout", type=float, default=300)
    args = ap.parse_args()

    t0 = time.time()
    p = subprocess.Popen([args.target, args.input, "-runs=1", "-timeout=290",
                          "-rss_limit_mb=6000"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    peak_kb = 0
    status = Path("/proc/%d/status" % p.pid)
    while p.poll() is None:
        try:
            for line in status.read_text().splitlines():
                if line.startswith("VmHWM:"):
                    peak_kb = max(peak_kb, int(line.split()[1]))
                    break
        except (FileNotFoundError, ProcessLookupError):
            break
        if time.time() - t0 > args.timeout:
            p.kill()
            break
        time.sleep(0.01)
    out = p.communicate()[0]
    wall = time.time() - t0
    print("%s,%s,%d,%.2f,%.1f" % (Path(args.target).name, Path(args.input).name,
                                  p.returncode, wall, peak_kb / 1024.0))
    sys_out = out.strip().splitlines()[-1] if out.strip() else ""
    if sys_out:
        print("# " + sys_out[:160], file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
