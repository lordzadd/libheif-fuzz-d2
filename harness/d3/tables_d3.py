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
  results/long2*/campaign_summary.json          campaign C phases
  results/long2*/coverage_checkpoints.csv       campaign C coverage
  results/long2a/seed_gain.csv                  coverage added by generated seeds
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


def campaign_c():
    """Campaign C: the phased runs results/long2*/ (cloud runner, no Docker).

    One row per phase from its campaign_summary.json, a total row, the union
    coverage per target at the first and last non-skipped checkpoint of each
    phase (coverage_checkpoints.csv), and the seed-gain table
    (results/long2a/seed_gain.csv, harness/d3/seed_gain.py)."""
    runs = sorted(p.parent for p in (ROOT / "results").glob("long2*/campaign_summary.json"))
    if not runs:
        return "", "", "", ""
    rows, total_cpu, total_execs, total_art, total_wall = [], 0.0, 0, 0, 0.0
    cov_rows = []
    for d in runs:
        s = json.loads((d / "campaign_summary.json").read_text())
        execs = sum(f["execs_from_logs"] for f in s["fuzzers"].values())
        alloc = ", ".join("%s=%d" % (k.replace("_fuzzer", ""), v)
                          for k, v in s["worker_allocation"].items())
        rows.append([s["run"], alloc, s["wall_seconds"], s["cpu_hours"], execs,
                     s["crashes"], "yes" if s.get("interrupted") else "no"])
        total_cpu += s["cpu_hours"]
        total_execs += execs
        total_art += s["crashes"]
        total_wall += s["wall_seconds"]
        ck = [r for r in read_csv(d / "coverage_checkpoints.csv") if r["skipped"] == "0"]
        for f in sorted({r["fuzzer"] for r in ck}):
            fr = [r for r in ck if r["fuzzer"] == f]
            cov_rows.append([s["run"], f, fr[0]["t_s"], fr[0]["cov"], fr[-1]["t_s"],
                             fr[-1]["cov"], fr[-1]["ft"], fr[-1]["corpus_units"]])
    rows.append(["total", "", round(total_wall, 1), round(total_cpu, 3), total_execs,
                 total_art, ""])
    b = ROOT / "results" / "baseline" / "campaign_summary.json"
    b_cpu = json.loads(b.read_text())["cpu_hours"] if b.exists() else 0.0
    head = ("Campaign C: %d phases, %.3f CPU-hours, %d executions, %d artifacts. "
            "Campaign B + C: %.3f CPU-hours."
            % (len(runs), total_cpu, total_execs, total_art, b_cpu + total_cpu))
    tab = table(["phase", "workers", "wall s", "CPU-hours", "executions", "artifacts",
                 "interrupted"], rows)
    cov = table(["phase", "target", "first t (s)", "first cov", "last t (s)", "last cov",
                 "last ft", "corpus units"], cov_rows) if cov_rows else ""
    gain_rows = read_csv(ROOT / "results" / "long2a" / "seed_gain.csv")
    gain = ""
    if gain_rows:
        by = {}
        for r in gain_rows:
            by.setdefault(r["fuzzer"], {})[r["set"]] = r
        g = []
        for f, v in sorted(by.items()):
            bcov, gcov, bg = (int(v[k]["cov"]) for k in ("B", "gen", "B+gen"))
            g.append([f, v["B"]["inputs"], bcov, v["gen"]["inputs"], gcov, bg,
                      "+%d (+%.1f%%)" % (bg - bcov, 100.0 * (bg - bcov) / bcov)])
        gain = table(["target", "B inputs", "B cov", "gen inputs", "gen cov",
                      "B+gen cov", "gain over B"], g)
    return head, tab, cov, gain


def main():
    a_head, a_tab = campaign_a()
    b_head, b_tab = campaign_b()
    c_head, c_tab, c_cov, c_gain = campaign_c()
    parts = ["# D3 tables (generated)\n"]
    if a_head:
        parts += ["## Campaign A (team baseline)\n", a_head, "", a_tab, ""]
    if b_head:
        parts += ["## Campaign B (sustained campaign, this revision)\n", b_head,
                  "", b_tab, ""]
    ck = checkpoints()
    if ck:
        parts += ["## Campaign B union edge coverage at 15-minute checkpoints\n", ck, ""]
    if c_head:
        parts += ["## Campaign C (phased cloud campaign, long2*)\n", c_head, "", c_tab, ""]
        if c_cov:
            parts += ["## Campaign C union edge coverage, first and last checkpoint per phase\n",
                      c_cov, ""]
        if c_gain:
            parts += ["## Coverage added by the generated seeds (seed_gain.py)\n", c_gain, ""]
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
