#!/usr/bin/env python3
"""Delta-debug a crash/OOM artifact down to a smaller input.

libFuzzer's own minimiser only handles sanitizer crashes; it cannot minimise an
out-of-memory report. This script runs classic ddmin over byte ranges and keeps
an input as long as the same failure still happens.

  python3 harness/d3/minimize_oom.py --target build/fuzzing/box_fuzzer \
      --input results/baseline/crashes/box_fuzzer/oom-<sha> \
      --output results/baseline/repro_snuc_oom.bin \
      --match "out-of-memory"

The predicate is deliberately narrow: the process must print `--match` (or exit
with `--exit-code`). A timeout counts as "not reproduced".
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


def fails(binary, data, match, exit_code, timeout, fix_size=False):
    if fix_size and len(data) >= 8:
        # Keep the first box's size field consistent with the shortened input so
        # that removing trailing bytes still produces a parseable container.
        data = len(data).to_bytes(4, "big") + data[4:]
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        p = subprocess.run([binary, path, "-runs=1", "-rss_limit_mb=800"],
                           capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if match:
            return match in out
        return p.returncode == exit_code
    except subprocess.TimeoutExpired:
        return False
    finally:
        Path(path).unlink(missing_ok=True)


def ddmin(data, test):
    n = 2
    while len(data) >= 2:
        chunk = max(1, len(data) // n)
        reduced = False
        for start in range(0, len(data), chunk):
            candidate = data[:start] + data[start + chunk:]
            if candidate and test(candidate):
                data = candidate
                n = max(2, n - 1)
                reduced = True
                sys.stderr.write("reduced to %d bytes\n" % len(data))
                break
        if not reduced:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--match", default="out-of-memory")
    ap.add_argument("--exit-code", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--fix-container-size", action="store_true")
    args = ap.parse_args()

    data = Path(args.input).read_bytes()
    print("start %d bytes, reproduces: %s"
          % (len(data), fails(args.target, data, args.match, args.exit_code, args.timeout)))
    out = ddmin(data, lambda d: fails(args.target, d, args.match, args.exit_code,
                                      args.timeout, args.fix_container_size))
    if args.fix_container_size and len(out) >= 8:
        out = len(out).to_bytes(4, "big") + out[4:]
    Path(args.output).write_bytes(out)
    print("minimised to %d bytes -> %s" % (len(out), args.output))
    print(out.hex())


if __name__ == "__main__":
    main()
