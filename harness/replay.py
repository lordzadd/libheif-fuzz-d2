#!/usr/bin/env python3
"""D3 Track B: replay crashing inputs and the final corpus against a build.

The harness, inputs, settings and success criteria are identical across builds;
only the build under test changes (D3_BUILD_DIR).

    D3_CAMPAIGN_DIR=results/d3/baseline-<stamp> D3_LABEL=baseline \
        python3 harness/replay.py
    D3_CAMPAIGN_DIR=results/d3/baseline-<stamp> D3_LABEL=fixed \
        D3_BUILD_DIR=build-fixed python3 harness/replay.py

Outputs (under the campaign dir / replay / <label>):
    replay_crashes.csv   one row per (unique crash, fuzzer that found it)
    replay_corpus.csv    one row per fuzzer for the full final corpus
    summary.json         aggregated before/after numbers
"""

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUZZERS = (
    "api_fuzzer", "box_fuzzer", "color_conversion_fuzzer", "encoder_fuzzer",
    "file_fuzzer", "sequence_fuzzer", "tile_fuzzer",
)
UBSAN_OPTIONS = "print_stacktrace=0:halt_on_error=1:print_summary=1"
ASAN_OPTIONS = "symbolize=1"


def env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def run(cmd, timeout, env_extra=None):
    env = os.environ.copy()
    env.update(env_extra or {})
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout, cwd=ROOT, env=env,
        )
        rc, text = proc.returncode, (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as error:
        out, err = error.stdout or b"", error.stderr or b""
        text = (out if isinstance(out, str) else out.decode("utf-8", "replace"))
        text += "\n" + (err if isinstance(err, str) else err.decode("utf-8", "replace"))
        rc = None
    return rc, text, round(time.monotonic() - started, 2)


def signature(text):
    m = re.search(r"runtime error: (.+)", text)
    if m:
        return "UBSan: " + m.group(1).strip()
    m = re.search(r"ERROR: (AddressSanitizer|LeakSanitizer): (.+)", text)
    if m:
        return m.group(1) + ": " + m.group(2).strip()
    return "" if "ERROR:" not in text and "runtime error:" not in text else "other"


def unique_artifacts(art_root):
    by_hash = {}
    for fuzzer_dir in sorted(art_root.iterdir()):
        if not fuzzer_dir.is_dir():
            continue
        for path in sorted(fuzzer_dir.iterdir()):
            if not path.is_file() or not path.name.startswith(("crash-", "oom-", "timeout-")):
                continue
            digest = hashlib.sha1(path.read_bytes()).hexdigest()
            by_hash.setdefault(digest, []).append((fuzzer_dir.name, path))
    return by_hash


def main():
    campaign = os.environ.get("D3_CAMPAIGN_DIR")
    if not campaign:
        print("error: set D3_CAMPAIGN_DIR", file=sys.stderr)
        return 2
    campaign = (ROOT / campaign).resolve() if not Path(campaign).is_absolute() else Path(campaign)
    build_dir = os.environ.get("D3_BUILD_DIR", "build")
    label = os.environ.get("D3_LABEL", "baseline")
    timeout = env_int("D3_REPLAY_TIMEOUT", 180)
    forks = env_int("D3_REPLAY_FORKS", 2)

    fuzz_root = (ROOT / build_dir / "fuzzing").resolve()
    missing = [n for n in FUZZERS if not (fuzz_root / n).is_file()]
    if missing:
        print("error: missing fuzzers in %s: %s" % (fuzz_root, ", ".join(missing)), file=sys.stderr)
        return 2

    out = campaign / "replay" / label
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)

    # --- 1. Exact replay of every unique crashing input, in every target that found it.
    crash_rows = []
    by_hash = unique_artifacts(campaign / "artifacts")
    for digest, entries in sorted(by_hash.items()):
        for fuzzer, path in sorted(entries):
            rc, text, elapsed = run(
                [str(fuzz_root / fuzzer), "-runs=1", str(path)], timeout,
                {"UBSAN_OPTIONS": UBSAN_OPTIONS, "ASAN_OPTIONS": ASAN_OPTIONS},
            )
            (logs / (digest + "-" + fuzzer + ".log")).write_text(text, errors="replace")
            crash_rows.append({
                "sha1": digest, "fuzzer": fuzzer,
                "input": str(path.relative_to(ROOT)),
                "exit_code": rc, "crashed": rc not in (0, None),
                "sanitizer_signature": signature(text),
                "elapsed_s": elapsed,
                "log": str((logs / (digest + "-" + fuzzer + ".log")).relative_to(ROOT)),
            })
            print("crash %s %-24s exit=%s %s" %
                  (digest[:10], fuzzer, rc, signature(text)[:60]), flush=True)

    with (out / "replay_crashes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(crash_rows[0]) if crash_rows else ["sha1"])
        w.writeheader()
        w.writerows(crash_rows)

    # --- 2. Full final-corpus replay (fork + ignore_crashes so the baseline
    # can replay every corpus unit, including the two crash units libFuzzer
    # retained in each corpus).
    corpus_rows = []
    for fuzzer in FUZZERS:
        src = campaign / "corpora" / fuzzer
        clean = out / ("corpus_" + fuzzer)
        if clean.exists():
            shutil.rmtree(clean)
        clean.mkdir(parents=True)
        kept = 0
        for p in sorted(src.rglob("*")):
            if p.is_file():
                shutil.copy2(p, clean / p.name)
                kept += 1
        art = out / ("art_" + fuzzer)
        art.mkdir(exist_ok=True)
        cmd = [
            str(fuzz_root / fuzzer), str(clean),
            "-fork=" + str(forks), "-runs=0", "-ignore_crashes=1",
            "-print_final_stats=1", "-artifact_prefix=" + str(art) + "/",
        ]
        rc, text, elapsed = run(cmd, timeout,
                                {"UBSAN_OPTIONS": UBSAN_OPTIONS, "ASAN_OPTIONS": ASAN_OPTIONS})
        (logs / (fuzzer + ".corpus.log")).write_text(text, errors="replace")
        cov = [int(x) for x in re.findall(r"cov:\s*(\d+)", text)]
        execs = re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)
        crashes = sum(
            1 for p in art.iterdir()
            if p.is_file() and p.name.startswith(("crash-", "oom-", "timeout-"))
        )
        corpus_rows.append({
            "fuzzer": fuzzer, "corpus_files": kept, "exit_code": rc,
            "execs": int(execs[-1]) if execs else "",
            "max_cov_edges": max(cov) if cov else "",
            "new_crash_artifacts": crashes,
            "elapsed_s": elapsed,
            "log": str((logs / (fuzzer + ".corpus.log")).relative_to(ROOT)),
        })
        print("corpus %-25s files=%d crashes=%d cov=%s" %
              (fuzzer, kept, crashes, corpus_rows[-1]["max_cov_edges"]), flush=True)

    with (out / "replay_corpus.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(corpus_rows[0]))
        w.writeheader()
        w.writerows(corpus_rows)

    summary = {
        "label": label,
        "build_dir": build_dir,
        "campaign": str(campaign.relative_to(ROOT)),
        "crash_inputs_replayed": len({r["sha1"] for r in crash_rows}),
        "crash_replays": len(crash_rows),
        "crash_replays_that_crashed": sum(1 for r in crash_rows if r["crashed"]),
        "unique_signatures": sorted({r["sanitizer_signature"] for r in crash_rows
                                     if r["sanitizer_signature"]}),
        "corpus_new_crash_artifacts": sum(r["new_crash_artifacts"] for r in corpus_rows),
        "corpus_execs": sum(r["execs"] for r in corpus_rows if isinstance(r["execs"], int)),
        "crash_csv": str((out / "replay_crashes.csv").relative_to(ROOT)),
        "corpus_csv": str((out / "replay_corpus.csv").relative_to(ROOT)),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
