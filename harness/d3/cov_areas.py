#!/usr/bin/env python3
"""Group an llvm-cov per-file report into the areas used in docs/D3.md.

  python3 harness/d3/cov_areas.py results/baseline/coverage/cov-report-file_fuzzer.txt
  python3 harness/d3/cov_areas.py results/long2/coverage/cov-report-file_fuzzer.txt \
      --csv results/long2/coverage/areas.csv

Input is the text table written by `llvm-cov report` (scripts/coverage_report.sh
or scripts/coverage_report_native.sh). Columns used: Lines, Missed Lines.
Also prints files with zero covered lines and the TOTAL row.
"""

import argparse
import csv
import re
import sys

AREAS = [
    # Paths are relative to libheif/libheif/, as llvm-cov prints them.
    ("box.cc (ISOBMFF box parser)", lambda f: f == "box.cc"),
    ("color-conversion/", lambda f: f.startswith("color-conversion/")),
    ("codecs/uncompressed/", lambda f: f.startswith("codecs/uncompressed/")),
    ("image-items/", lambda f: f.startswith("image-items/")),
    ("sequences/", lambda f: f.startswith("sequences/")),
    ("codecs/ (HEVC, AV1, JPEG, VVC)",
     lambda f: f.startswith("codecs/") and not f.startswith("codecs/uncompressed/")),
    ("mini.cc (mini-box format)", lambda f: f == "mini.cc"),
    ("context.cc", lambda f: f == "context.cc"),
    ("api/libheif/", lambda f: f.startswith("api/libheif/")),
    ("region.cc", lambda f: f == "region.cc"),
    ("compression*.cc", lambda f: re.fullmatch(r"compression[^/]*\.cc", f) is not None),
    ("brands.cc", lambda f: f == "brands.cc"),
]


def parse(path):
    files, total, headers = [], None, []
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 13:
                continue
            name = parts[0].split("libheif/libheif/")[-1]
            try:
                nums = [p for p in parts[1:]]
                lines, missed = int(nums[6]), int(nums[7])
            except (ValueError, IndexError):
                continue
            row = (name, lines, lines - missed)
            # Rule: an area is every file (.cc and .h) under its path. The
            # earlier hand-made table in docs/D3.md did not follow one rule
            # (some rows match .cc only, some all files), so Campaign B's
            # column is regenerated with this script for a like-for-like
            # comparison.
            if name == "TOTAL":
                total = row
            else:
                files.append(row)
    return files, total, headers


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--csv")
    args = ap.parse_args()
    files, total, headers = parse(args.report)
    rows = []
    for label, pred in AREAS:
        sel = [f for f in files if pred(f[0])]
        n = sum(f[1] for f in sel)
        c = sum(f[2] for f in sel)
        rows.append({"area": label, "covered": c, "lines": n,
                     "percent": round(100.0 * c / n, 1) if n else 0.0})
    w = csv.DictWriter(sys.stdout, fieldnames=["area", "covered", "lines", "percent"])
    w.writeheader()
    w.writerows(rows)
    if total:
        print("TOTAL lines covered %d of %d (%.1f%%)" % (total[2], total[1], 100.0 * total[2] / total[1]))
    zero = [f[0] for f in files + headers if f[2] == 0]
    print("files with 0 covered lines: %d" % len(zero))
    for z in zero:
        print("  " + z)
    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            ww = csv.DictWriter(fh, fieldnames=["area", "covered", "lines", "percent"])
            ww.writeheader()
            ww.writerows(rows)


if __name__ == "__main__":
    main()
