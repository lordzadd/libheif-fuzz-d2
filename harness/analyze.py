#!/usr/bin/env python3
"""D3 Track B: reproduce, group, minimize, and root-cause every unique crash.

Reads the artifacts produced by ``harness/campaign.py``.  Every unique input is
reproduced with a symbolized UBSan stack trace (raw log kept).  Inputs are then
grouped by their root cause; one representative per group is minimized with
libFuzzer and re-run to confirm the same diagnostic.

Usage:
    D3_CAMPAIGN_DIR=results/d3/baseline-<stamp> python3 harness/analyze.py

Environment:
    D3_CAMPAIGN_DIR     campaign output directory (required)
    D3_MINIMIZE_SECONDS per-representative minimization budget (default: 30)
    D3_ANALYZE_PARALLEL crashes reproduced concurrently (default: 6)
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUZZ_DIR = ROOT / "build" / "fuzzing"

UBSAN_OPTIONS = "print_stacktrace=1:halt_on_error=1:print_summary=1"
ASAN_OPTIONS = "symbolize=1:abort_on_error=0"


def env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def unique_artifacts(art_root):
    """Return one entry per unique SHA-1, with all fuzzers that found it."""
    by_hash = {}
    for fuzzer_dir in sorted(art_root.iterdir()):
        if not fuzzer_dir.is_dir():
            continue
        for path in sorted(fuzzer_dir.iterdir()):
            if not path.is_file() or not path.name.startswith(("crash-", "oom-", "timeout-")):
                continue
            digest = hashlib.sha1(path.read_bytes()).hexdigest()
            by_hash.setdefault(digest, []).append((fuzzer_dir.name, path))
    result = []
    for digest, entries in by_hash.items():
        fuzzer, path = entries[0]
        result.append({
            "sha1": digest, "fuzzer": fuzzer, "path": str(path.relative_to(ROOT)),
            "bytes": path.stat().st_size,
            "also_found_by": sorted({f for f, _ in entries}),
        })
    return sorted(result, key=lambda e: (e["bytes"], e["sha1"]))


def run(cmd, env_extra=None, timeout=120):
    env = os.environ.copy()
    env.update(env_extra or {})
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout, cwd=ROOT, env=env,
        )
        return proc.returncode, (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as error:
        out, err = error.stdout or b"", error.stderr or b""
        text = (out if isinstance(out, str) else out.decode("utf-8", "replace"))
        text += "\n" + (err if isinstance(err, str) else err.decode("utf-8", "replace"))
        return None, text + "\n[ TIMEOUT ]\n"


def classify(log):
    """Classify a sanitizer log from its stack, not just its headline."""
    ub = re.search(r"runtime error: (.+)", log)
    signature = ub.group(1).strip() if ub else ""
    if not signature:
        m = re.search(r"ERROR: (AddressSanitizer|LeakSanitizer): (.+)", log)
        signature = (m.group(1) + ": " + m.group(2)) if m else "no sanitizer diagnostic"

    src = re.search(r"libheif/([^: ]+\.cc):(\d+):\d+: runtime error", log)
    src_line = (src.group(1) + ":" + src.group(2)) if src else ""
    frames = re.findall(r"^\s+#\d+ .*? in ([^\n]+?)\s+(?:\S+\.cc|\S+\.h):\d+", log, re.M)
    top = frames[0] if frames else ""
    asan = bool(re.search(r"ERROR: AddressSanitizer|ERROR: LeakSanitizer", log))

    if "null pointer" in signature and "nonnull" in log and src_line == "libheif/bitstream.cc:115":
        cls = "C1: zero-length read into empty vector (bitstream.cc:115)"
        root = (
            "StreamReader_memory::read() calls memcpy(data, &m_data[m_position], size) at "
            "bitstream.cc:115 with data == nullptr and size == 0. Box_av1C::parse() "
            "(codecs/avif_boxes.cc:77-80) sizes an empty vector with resize(0) and passes "
            "m_config_OBUs.data() to BitstreamRange::read(); data() may legally be nullptr "
            "for an empty vector. Wrong assumption: a container's data() is always a valid "
            "non-null memcpy destination, even for a zero-byte read."
        )
        exploit = (
            "Not exploitable. memcpy(..., 0) reads and writes no bytes: no OOB access, no "
            "attacker-controlled dereference, no type confusion. ASan reports no invalid "
            "memory access. Only the harness's -fno-sanitize-recover UBSan configuration "
            "aborts, i.e. a denial of service of the fuzzing process; a production build "
            "treats the call as a no-op (release replay)."
        )
    elif "null pointer" in signature and "nonnull" in log and src_line.endswith("heif_items.cc:170"):
        cls = "C2: zero-length item-data copy from empty vector (heif_items.cc:170)"
        root = (
            "heif_get_item_data() at api/libheif/heif_items.cc:170 calls "
            "memcpy(*out_data, dataResult->data(), dataResult->size()) when an item exists "
            "but carries zero bytes. dataResult->data() is nullptr for the empty result "
            "vector, so memcpy's src (argument 2, declared nonnull) is null with size 0. "
            "Wrong assumption: an empty item's data pointer is always non-null."
        )
        exploit = (
            "Not exploitable. size == 0 means no bytes are copied; no OOB read/write occurs "
            "and ASan reports no invalid access. The only effect is the UBSan abort in this "
            "strict harness; a production build performs no copy."
        )
    else:
        cls = "other: " + signature
        root = "Unclassified sanitizer finding; see raw stack trace."
        exploit = "Requires manual review."

    return {
        "signature": signature, "root_cause_class": cls, "source_line": src_line,
        "root_cause": root, "exploitability": exploit,
        "asan_memory_error": asan, "top_frame": top,
        "reached_Box_av1C_parse": "Box_av1C::parse" in log,
        "reached_mini_box": "Box_mini" in log or "mini.cc" in log,
    }


def main():
    campaign = os.environ.get("D3_CAMPAIGN_DIR")
    if not campaign:
        print("error: set D3_CAMPAIGN_DIR", file=sys.stderr)
        return 2
    campaign = (ROOT / campaign).resolve() if not Path(campaign).is_absolute() else Path(campaign)
    if not campaign.is_dir():
        print("error: campaign dir not found: " + str(campaign), file=sys.stderr)
        return 2
    minimize_s = env_int("D3_MINIMIZE_SECONDS", 30)
    parallel = env_int("D3_ANALYZE_PARALLEL", 6)
    out = campaign / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    (out / "inputs").mkdir(exist_ok=True)
    (out / "logs").mkdir(exist_ok=True)

    crashes = unique_artifacts(campaign / "artifacts")
    print("reproducing %d unique inputs" % len(crashes), flush=True)

    def reproduce(crash):
        digest = crash["sha1"]
        exe = FUZZ_DIR / crash["fuzzer"]
        orig = ROOT / crash["path"]
        rc, log = run([str(exe), "-runs=1", str(orig)],
                      {"UBSAN_OPTIONS": UBSAN_OPTIONS, "ASAN_OPTIONS": ASAN_OPTIONS})
        (out / "logs" / (digest + ".reproduce.log")).write_text(log, errors="replace")
        info = classify(log)
        row = dict(crash)
        row.update({
            "original_repro_rc": rc,
            "signature": info["signature"],
            "source_line": info["source_line"],
            "root_cause_class": info["root_cause_class"],
            "root_cause": info["root_cause"],
            "exploitability": info["exploitability"],
            "asan_memory_error": info["asan_memory_error"],
            "top_frame": info["top_frame"],
            "reached_Box_av1C_parse": info["reached_Box_av1C_parse"],
            "reached_mini_box": info["reached_mini_box"],
            "reproduce_log": str((out / "logs" / (digest + ".reproduce.log")).relative_to(ROOT)),
        })
        return row

    rows = []
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        for fut in as_completed([pool.submit(reproduce, c) for c in crashes]):
            rows.append(fut.result())
    rows.sort(key=lambda r: (r["root_cause_class"], r["bytes"], r["sha1"]))

    # Group by root cause and minimize the smallest original in each group.
    groups = {}
    for row in rows:
        groups.setdefault(row["root_cause_class"], []).append(row)

    group_rows = []
    for cls, members in sorted(groups.items()):
        rep = members[0]
        digest = rep["sha1"]
        exe = FUZZ_DIR / rep["fuzzer"]
        orig = ROOT / rep["path"]
        work = out / "inputs" / digest
        work.mkdir(exist_ok=True)
        shutil.copy2(orig, work / "original.bin")
        min_path = work / "minimized.bin"
        if min_path.exists():
            min_path.unlink()
        t0 = time.monotonic()
        mrc, min_log = run(
            [str(exe), "-minimize_crash=1", "-max_total_time=" + str(minimize_s),
             "-exact_artifact_path=" + str(min_path), str(orig)],
            {"UBSAN_OPTIONS": UBSAN_OPTIONS, "ASAN_OPTIONS": ASAN_OPTIONS},
            timeout=minimize_s + 60,
        )
        min_elapsed = round(time.monotonic() - t0, 2)
        (out / "logs" / (digest + ".minimize.log")).write_text(min_log, errors="replace")
        minimized = min_path if min_path.is_file() else None
        same = False
        if minimized:
            _, re_log = run([str(exe), "-runs=1", str(minimized)],
                            {"UBSAN_OPTIONS": UBSAN_OPTIONS, "ASAN_OPTIONS": ASAN_OPTIONS})
            (out / "logs" / (digest + ".minimized-reproduce.log")).write_text(
                re_log, errors="replace")
            same = classify(re_log)["signature"] == rep["signature"]
        group_rows.append({
            "root_cause_class": cls,
            "inputs_in_group": len(members),
            "representative_sha1": digest,
            "original_bytes": rep["bytes"],
            "minimized_bytes": minimized.stat().st_size if minimized else "",
            "minimize_rc": mrc,
            "minimize_s": min_elapsed,
            "minimized_repro_same_signature": same,
            "signature": rep["signature"],
            "source_line": rep["source_line"],
            "asan_memory_error": rep["asan_memory_error"],
            "root_cause": rep["root_cause"],
            "exploitability": rep["exploitability"],
            "original_path": str((work / "original.bin").relative_to(ROOT)),
            "minimized_path": str(minimized.relative_to(ROOT)) if minimized else "",
            "minimize_log": str((out / "logs" / (digest + ".minimize.log")).relative_to(ROOT)),
        })
        print("group %-60s inputs=%d %s -> %s bytes" %
              (cls, len(members), rep["bytes"], group_rows[-1]["minimized_bytes"]),
              flush=True)

    for row in rows:
        row["minimized_representative"] = next(
            (g["representative_sha1"] for g in group_rows
             if g["root_cause_class"] == row["root_cause_class"]), "")

    with (out / "crashes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with (out / "groups.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(group_rows[0]))
        w.writeheader()
        w.writerows(group_rows)
    summary = {
        "campaign": str(campaign.relative_to(ROOT)),
        "unique_crash_inputs": len(rows),
        "distinct_root_cause_classes": len(group_rows),
        "classes": sorted({r["root_cause_class"] for r in rows}),
        "exploitability": sorted({r["exploitability"] for r in rows}),
        "root_causes": sorted({r["root_cause"] for r in group_rows}),
        "crashes_csv": str((out / "crashes.csv").relative_to(ROOT)),
        "groups_csv": str((out / "groups.csv").relative_to(ROOT)),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
