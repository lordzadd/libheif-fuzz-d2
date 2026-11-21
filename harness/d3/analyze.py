#!/usr/bin/env python3
"""Rebuild every reported number from the raw campaign logs.

Inputs (all produced by harness/campaign.py):
  results/<run>/logs/<fuzzer>.w<k>.log   timestamped libFuzzer output
  results/<run>/campaign_summary.json
  results/<run>/coverage_checkpoints.csv
  results/<run>/crashes.csv

Outputs:
  results/<run>/analysis/coverage_timeseries.csv  one row per coverage event
  results/<run>/analysis/coverage_summary.csv     per fuzzer, final numbers
  results/<run>/analysis/coverage_10min.csv       union-over-workers per bucket
  results/<run>/analysis/summary.md               human-readable tables
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COV_RE = re.compile(r"cov: (\d+) ft: (\d+) corp: (\d+)/(\d+)")
EXECS_RE = re.compile(r"^#(\d+)")
S_LOG = re.compile(r"^\[\s*([0-9.]+)\] (.*)$")


def parse_log(path):
    rows = []
    with open(path, errors="replace") as fh:
        for line in fh:
            m = S_LOG.match(line)
            if not m:
                continue
            t = float(m.group(1))
            body = m.group(2)
            c = COV_RE.search(body)
            e = EXECS_RE.match(body)
            if not c:
                continue
            rows.append({
                "t_s": round(t, 2),
                "cov": int(c.group(1)),
                "ft": int(c.group(2)),
                "corp_units": int(c.group(3)),
                "corp_bytes": int(c.group(4)),
                "execs": int(e.group(1)) if e else "",
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="baseline")
    args = ap.parse_args()

    run = ROOT / "results" / args.run
    out = run / "analysis"
    out.mkdir(parents=True, exist_ok=True)

    series = []
    for log in sorted((run / "logs").glob("*.log")):
        stem = log.stem  # fuzzer.wN
        fuzzer, w = stem.rsplit(".w", 1)
        for r in parse_log(log):
            r.update({"fuzzer": fuzzer, "worker": int(w)})
            series.append(r)

    fields = ["fuzzer", "worker", "t_s", "cov", "ft", "corp_units", "corp_bytes", "execs"]
    with open(out / "coverage_timeseries.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(sorted(series, key=lambda r: (r["fuzzer"], r["worker"], r["t_s"])))

    # Per fuzzer: max coverage reached by any single worker, last exec count,
    # worker count, and the last coverage event time.
    per = defaultdict(lambda: {"workers": set(), "cov": 0, "ft": 0,
                               "execs": 0, "last_t": 0.0,
                               "corp_units": 0, "corp_bytes": 0})
    for r in series:
        p = per[r["fuzzer"]]
        p["workers"].add(r["worker"])
        p["cov"] = max(p["cov"], r["cov"])
        p["ft"] = max(p["ft"], r["ft"])
        p["last_t"] = max(p["last_t"], r["t_s"])

    # Executions: the per-worker exec counter resets on every restart, so the
    # correct total is the sum of the final counters over all chunks. campaign.py
    # records that in campaign_summary.json under execs_from_logs; prefer it.
    summary_path = run / "campaign_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
    else:
        # Partial run: derive what we can from the logs only.
        last_t = max((r["t_s"] for r in series), default=0)
        summary = {"wall_seconds": last_t, "workers": len({(r["fuzzer"], r["worker"]) for r in series}),
                   "cpu_seconds": 0.0, "cpu_hours": 0.0, "fuzzers": {}}

    # Union over workers in 10 minute buckets.
    buckets = defaultdict(dict)
    for r in series:
        b = int(r["t_s"] // 600) * 600
        key = (r["fuzzer"], b)
        buckets[key]["cov"] = max(buckets[key].get("cov", 0), r["cov"])
        buckets[key]["ft"] = max(buckets[key].get("ft", 0), r["ft"])
    with open(out / "coverage_10min.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["fuzzer", "t_s", "max_worker_cov", "max_worker_ft"])
        for (fuzzer, b), v in sorted(buckets.items()):
            w.writerow([fuzzer, b, v["cov"], v["ft"]])

    rows = []
    for fuzzer in sorted(per):
        p = per[fuzzer]
        fs = summary["fuzzers"].get(fuzzer, {})
        rows.append({
            "fuzzer": fuzzer,
            "workers": len(p["workers"]),
            "max_worker_cov": p["cov"],
            "max_worker_ft": p["ft"],
            "execs": fs.get("execs_from_logs", ""),
            "final_corpus_units": fs.get("final_corpus_units", ""),
            "final_corpus_bytes": fs.get("final_corpus_bytes", ""),
            "crashes": fs.get("crashes", 0),
            "last_event_s": p["last_t"],
        })
    with open(out / "coverage_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    md = []
    md.append("# Campaign analysis: %s\n" % args.run)
    md.append("Wall clock: %.1f s (%.2f h). Workers: %d. CPU time: %.1f s = %.2f CPU-hours.\n"
              % (summary["wall_seconds"], summary["wall_seconds"] / 3600,
                 summary["workers"], summary["cpu_seconds"], summary["cpu_hours"]))
    md.append("| fuzzer | workers | execs | max worker edges | final corpus units | final corpus bytes | crashes |")
    md.append("|---|---|---|---|---|---|---|")
    for r in rows:
        md.append("| %(fuzzer)s | %(workers)d | %(execs)s | %(max_worker_cov)d | "
                  "%(final_corpus_units)s | %(final_corpus_bytes)s | %(crashes)d |" % r)
    total_execs = sum(r["execs"] for r in rows if r["execs"] != "")
    md.append("\nTotal executions: %s.\n" % (total_execs if total_execs else "pending"))
    (out / "summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
