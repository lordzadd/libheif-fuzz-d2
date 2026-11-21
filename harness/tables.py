#!/usr/bin/env python3
"""Emit Markdown tables directly from D3 raw CSV/JSON results.

Running this script is the recommended way to populate the tables in docs/D3.md,
so every number in the report is traceable to a raw result file.

    python3 harness/tables.py results/d3/baseline-<UTC>
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_csv(path):
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def md(headers, rows):
    print("| " + " | ".join(str(h) for h in headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        print("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    print()


def main():
    if len(sys.argv) != 2:
        print("usage: harness/tables.py <campaign_dir>", file=sys.stderr)
        return 2
    camp = Path(sys.argv[1])
    if not camp.is_absolute():
        camp = ROOT / camp
    summary = json.loads((camp / "summary.json").read_text())
    print("## Campaign summary\n")
    print("- Wall clock: %s s; CPU time: %s s (%.4f CPU-hours); nominal cores: %s\n"
          % (summary["campaign_wall_s"], summary["campaign_cpu_s"],
             summary["cpu_hours"], summary["nominal_cores_busy"]))
    analysis_meta = camp / "analysis" / "summary.json"
    n_unique = (json.loads(analysis_meta.read_text())["unique_crash_inputs"]
                if analysis_meta.is_file() else summary["unique_crash_inputs"])
    print("- Crash artifact files: %s; unique crashing inputs (SHA-1): %s\n"
          % (summary["unique_crash_inputs"], n_unique))
    print("## Final edge coverage by target\n")
    md(["fuzzer", "max cov (edges)"],
       [{"fuzzer": k, "max cov (edges)": v}
        for k, v in sorted(summary["final_coverage_by_fuzzer"].items())])
    print("## Coverage over time: first and last sample per target\n")
    cov = load_csv(camp / "coverage_over_time.csv")
    trend = []
    for fuzzer in sorted({r["fuzzer"] for r in cov}):
        series = [r for r in cov if r["fuzzer"] == fuzzer]
        first, last = series[0], series[-1]
        trend.append({
            "fuzzer": fuzzer, "samples": len(series),
            "first_t_s": first["global_time_s"], "first_cov": first["cov_edges"],
            "last_t_s": last["global_time_s"], "last_cov": last["cov_edges"],
            "corp_first": first["corp"], "corp_last": last["corp"],
        })
    md(["fuzzer", "samples", "first_t_s", "first_cov", "last_t_s", "last_cov",
        "corp_first", "corp_last"], trend)
    print("## Function coverage on final corpora\n")
    md(["fuzzer", "covered_funcs", "uncovered_funcs", "corpus_files_replayed",
        "crash_units_filtered"],
       load_csv(camp / "coverage_functions.csv"))
    analysis = camp / "analysis" / "groups.csv"
    if analysis.is_file():
        meta = json.loads((camp / "analysis" / "summary.json").read_text())
        print("## Crash analysis: %d unique inputs, %d distinct root causes\n"
              % (meta["unique_crash_inputs"], meta["distinct_root_cause_classes"]))
        md(["root_cause_class", "inputs_in_group", "representative_sha1",
            "original_bytes", "minimized_bytes", "signature", "asan_memory_error",
            "minimized_repro_same_signature"],
           load_csv(analysis))
    for label in ("baseline", "fixed", "release"):
        rp = camp / "replay" / label
        if not (rp / "summary.json").is_file():
            continue
        s = json.loads((rp / "summary.json").read_text())
        print("## Replay: %s (build %s)\n" % (label, s["build_dir"]))
        print("- Unique crash inputs replayed: %s; crash replays: %s; replays that crashed: %s\n"
              % (s["crash_inputs_replayed"], s["crash_replays"],
                 s["crash_replays_that_crashed"]))
        print("- New crash artifacts from full-corpus replay: %s\n"
              % s["corpus_new_crash_artifacts"])
        md(["fuzzer", "corpus_files", "execs", "max_cov_edges", "new_crash_artifacts"],
           load_csv(rp / "replay_corpus.csv"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
