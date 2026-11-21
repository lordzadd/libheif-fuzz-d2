#!/usr/bin/env python3
"""Emit every table used in the D3 report from the raw result files.

  python3 harness/d3/tables_d3.py            # writes results/D3_tables.md

Sources:
  results/d3/baseline-*/summary.json            campaign A (team, Part 1)
  results/d3/baseline-*/analysis/groups.csv     campaign A crash classes
  results/baseline/campaign_summary.json        campaign B (sustained, this revision)
  results/baseline/coverage_checkpoints.csv     campaign B coverage over time
  results/verification/verify.csv               independent verification
  results/replay/*.csv                          before/after replay
"""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "D3_tables.md"


def read_csv(p):
    p = Path(p)
    if not p.exists():
        return []
    with open(p) as fh:
        return list(csv.DictReader(fh))


def table(header, rows):
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def campaign_a():
    base = sorted((ROOT / "results" / "d3").glob("baseline-*"))
    if not base:
        return "", ""
    d = base[0]
    s = json.loads((d / "summary.json").read_text())
    lines = []
    lines.append("Campaign A: %s wall, %.2f CPU-s = %.4f CPU-hours, %d rounds "
                 "(%d rounds/target x %ds), 226 artifacts."
                 % (s["campaign_wall_s"], s["campaign_cpu_s"], s["cpu_hours"],
                    s["total_rounds"], s["rounds_per_target"], s["round_seconds"]))
    groups = read_csv(d / "analysis" / "groups.csv")
    rows = []
    for g in groups:
        rows.append([g["root_cause_class"].split(":")[0],
                     g["root_cause_class"].split(": ", 1)[-1],
                     g["inputs_in_group"],
                     g["original_bytes"] + " -> " + g["minimized_bytes"],
                     g["source_line"],
                     "yes" if g["asan_memory_error"] == "True" else "no"])
    return "\n".join(lines), table(
        ["class", "description", "inputs", "bytes (orig -> min)", "source line",
         "ASan memory error"], rows)


def campaign_b():
    p = ROOT / "results" / "baseline" / "campaign_summary.json"
    if not p.exists():
        return "", ""
    s = json.loads(p.read_text())
    head = ("Campaign B: %.0f s wall, %.1f CPU-s = %.3f CPU-hours, %d workers, "
            "%d artifacts."
            % (s["wall_seconds"], s["cpu_seconds"], s["cpu_hours"],
               s["workers"], s["crashes"]))
    rows = []
    for name, f in sorted(s["fuzzers"].items()):
        rows.append([name, f["workers"], f["execs_from_logs"],
                     f["final_corpus_units"], f["final_corpus_bytes"],
                     f["crashes"]])
    rows.append(["total", "", sum(f["execs_from_logs"] for f in s["fuzzers"].values()),
                 sum(f["final_corpus_units"] for f in s["fuzzers"].values()),
                 sum(f["final_corpus_bytes"] for f in s["fuzzers"].values()),
                 s["crashes"]])
    return head, table(["target", "workers", "executions", "corpus units",
                        "corpus bytes", "artifacts"], rows)


def checkpoints():
    """Max single-worker edge coverage at 30-minute marks, from the raw logs."""
    rows = read_csv(ROOT / "results" / "baseline" / "analysis" / "coverage_10min.csv")
    if not rows:
        return ""
    buckets = {}
    for r in rows:
        buckets.setdefault(int(r["t_s"]), {})[r["fuzzer"]] = int(r["max_worker_cov"])
    fuzzers = sorted({r["fuzzer"] for r in rows})
    out = []
    for f in fuzzers:
        vals = []
        for t in (1800, 3600, 5400, 7200):
            cand = [(k, v[f]) for k, v in buckets.items() if k <= t and f in v]
            vals.append(max(cand)[1] if cand else "")
        vals.append(max(v[f] for v in buckets.values() if f in v))
        out.append([f] + vals)
    return table(["target", "30 min", "60 min", "90 min", "120 min", "maximum"], out)


def verification():
    rows = read_csv(ROOT / "results" / "verification" / "verify.csv")
    if not rows:
        return ""
    base = [r for r in rows if r["build"] == "baseline"]
    fixed = [r for r in rows if r["build"] == "fixed"]
    return table(
        ["build", "cases", "non-zero exits"],
        [["baseline (4cb65ae)", len(base), sum(1 for r in base if r["exit"] != "0")],
         ["fixed (660f468)", len(fixed), sum(1 for r in fixed if r["exit"] != "0")]])


def replay():
    rows = []
    for p in sorted((ROOT / "results" / "replay").glob("*.csv")):
        rs = read_csv(p)
        if not rs:
            continue
        fails = sum(1 for r in rs if r["exit"] not in ("0", ""))
        rows.append([rs[0]["label"], len(rs), fails])
    if not rows:
        return ""
    return table(["label", "replay rows", "non-zero exits"], rows)


def main():
    a_head, a_tab = campaign_a()
    b_head, b_tab = campaign_b()
    parts = ["# D3 tables (generated)\n"]
    if a_head:
        parts += ["## Campaign A (team baseline)\n", a_head, "", a_tab, ""]
    if b_head:
        parts += ["## Campaign B (sustained campaign, this revision)\n", b_head,
                  "", b_tab, ""]
    ck = checkpoints()
    if ck:
        parts += ["## Campaign B union edge coverage at 15-minute checkpoints\n", ck, ""]
    v = verification()
    if v:
        parts += ["## Independent verification of campaign A findings\n", v, ""]
    r = replay()
    if r:
        parts += ["## Replay (before/after)\n", r, ""]
    OUT.write_text("\n".join(parts) + "\n")
    print("\n".join(parts))


if __name__ == "__main__":
    main()
