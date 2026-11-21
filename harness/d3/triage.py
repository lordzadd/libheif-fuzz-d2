#!/usr/bin/env python3
"""Reproduce, classify, de-duplicate and minimise every crash artifact.

For each results/<run>/crashes/<fuzzer>/<artifact>:
  1. replay the input once to get a full sanitizer report;
  2. extract a signature (sanitizer class + first non-interceptor frame);
  3. minimise the input with libFuzzer -minimize_crash=1 while keeping the
     same signature (the minimiser only checks that *some* crash happens);
  4. replay the minimised input three times and require the same signature.

Outputs, all under results/<run>/triage/:
  index.csv          one row per artifact, with signature and status
  uniq.csv           one row per distinct signature (smallest reproducer)
  <fuzzer>/<sha1>/   original, minimised (if any), report.txt, meta.json

Nothing here trusts the artifact name: signatures come from the report text.
"""

import argparse
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

ROOT = Path(__file__).resolve().parents[2]
ENV = dict(os.environ)
ENV["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1"
ENV["UBSAN_OPTIONS"] = "print_stacktrace=1"

ASAN_ERR = re.compile(r"ERROR: AddressSanitizer: ([a-z0-9\-]+)", re.I)
SUMMARY = re.compile(r"SUMMARY: AddressSanitizer: ([a-z0-9\-]+) (.*)")
FRAME_SRC = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+)")
FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+)")
ASSERT = re.compile(r"Assertion `(.*)' failed")
LIBC_ABORT = re.compile(r"(terminate called after throwing|libFuzzer: deadly signal|"
                        r"ERROR: libFuzzer: (out-of-memory|timeout|fuzz target))")

INTERCEPTORS = {"__asan_memcpy", "__asan_memmove", "__asan_memset", "memcpy",
                "__interceptor_memcpy", "__interceptor_memmove",
                "strlen", "__interceptor_strlen"}


def run_single(fuzzer_bin, path, timeout=90, extra=None):
    cmd = [str(fuzzer_bin), str(path), "-runs=1", "-timeout=30"]
    if extra:
        cmd.extend(extra)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env=ENV)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out, round(time.time() - t0, 2)
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or "") + (e.stderr or "")) if isinstance(e.stdout, str) else ""
        return -1, out, round(time.time() - t0, 2)


def signature(rc, out):
    m = ASAN_ERR.search(out)
    if m:
        kind = m.group(1).lower()
        frames = []
        for line in out.splitlines():
            fm = FRAME_SRC.search(line)
            if fm and fm.group(1) not in INTERCEPTORS:
                frames.append("%s %s" % (fm.group(1), fm.group(2)))
            elif FRAME.search(line):
                fn = FRAME.search(line).group(1)
                if fn not in INTERCEPTORS:
                    frames.append(fn)
            if len(frames) == 3:
                break
        detail = ""
        for line in out.splitlines():
            if "SUMMARY: AddressSanitizer" in line:
                detail = line.split("AddressSanitizer:", 1)[1].strip()
                break
        return "%s|%s" % (kind, " <- ".join(frames) if frames else detail), kind, frames
    m = ASSERT.search(out)
    if m:
        return "assert|" + m.group(1)[:120], "assert", [m.group(1)[:120]]
    m = LIBC_ABORT.search(out)
    if m:
        return "abort|" + m.group(1)[:80], "abort", [m.group(1)[:80]]
    if "LeakSanitizer" in out:
        return "leak|LeakSanitizer", "leak", []
    if "UndefinedBehaviorSanitizer" in out:
        line = [l for l in out.splitlines() if "runtime error" in l][:1]
        return "ubsan|" + (line[0][:120] if line else ""), "ubsan", line
    if rc < 0:
        # Still running when the wall-clock guard fired: a slow input, not a crash.
        return "timeout|>%ds" % timeout, "timeout", []
    return None, None, []


def minimize(fuzzer_bin, path, outdir, max_time=600):
    out = outdir / "minimized"
    cmd = [str(fuzzer_bin), str(path), "-minimize_crash=1",
           "-max_total_time=%d" % max_time, "-timeout=30",
           "-artifact_prefix=%s/" % outdir, "-exact_artifact_path=%s" % out]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max_time + 180, env=ENV)
        text = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        text = "minimizer timed out\n"
    if out.exists():
        return out, text
    return None, text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="baseline")
    ap.add_argument("--build", default=str(ROOT / "build" / "fuzzing"))
    ap.add_argument("--no-minimize", action="store_true")
    ap.add_argument("--minimize-seconds", type=int, default=600)
    ap.add_argument("--slow-seconds", type=float, default=2.0,
                    help="an input that runs this long without a crash is reported as slow")
    args = ap.parse_args()

    run = ROOT / "results" / args.run
    triage = run / "triage"
    triage.mkdir(parents=True, exist_ok=True)
    build = Path(args.build)

    crash_csv = run / "crashes.csv"
    artifacts = []
    if crash_csv.exists():
        with open(crash_csv) as fh:
            artifacts = list(csv.DictReader(fh))
    else:
        for f in (run / "crashes").glob("*/*"):
            if f.is_file():
                artifacts.append({"fuzzer": f.parent.name, "artifact": f.name,
                                  "sha1": hashlib.sha1(f.read_bytes()).hexdigest(),
                                  "bytes": str(f.stat().st_size)})

    rows = []
    for a in artifacts:
        fuzzer = a["fuzzer"]
        src = run / "crashes" / fuzzer / a["artifact"]
        if not src.exists():
            continue
        data = src.read_bytes()
        digest = hashlib.sha1(data).hexdigest()
        d = triage / fuzzer / digest
        d.mkdir(parents=True, exist_ok=True)
        (d / "original.bin").write_bytes(data)

        rc, out, secs = run_single(build / fuzzer, src)
        if rc == 0 and secs >= args.slow_seconds:
            kind, sig, frames = "slow", "slow|%0.1fs" % secs, []
        else:
            sig, kind, frames = signature(rc, out)
        (d / "report.txt").write_text(out)
        meta = {
            "fuzzer": fuzzer, "artifact": a["artifact"], "sha1": digest,
            "bytes": len(data), "exit": rc, "signature": sig, "kind": kind,
            "frames": frames, "seconds": secs,
        }
        min_path = None
        if sig and not args.no_minimize and kind in ("heap-buffer-overflow",
                                                     "stack-buffer-overflow",
                                                     "global-buffer-overflow",
                                                     "use-after-free",
                                                     "heap-use-after-free",
                                                     "dynamic-stack-buffer-overflow",
                                                     "stack-overflow"):
            min_path, min_log = minimize(build / fuzzer, src, d, args.minimize_seconds)
            (d / "minimize.log").write_text(min_log[-20000:])
            if min_path and min_path.exists():
                ok = True
                for _ in range(3):
                    rc2, out2, _ = run_single(build / fuzzer, min_path)
                    sig2, _, _ = signature(rc2, out2)
                    if sig2 != sig:
                        ok = False
                        break
                meta["minimized_bytes"] = min_path.stat().st_size if ok else None
                meta["minimize_stable"] = ok
                if not ok:
                    min_path.unlink(missing_ok=True)
                    min_path = None
                else:
                    (d / "minimized_report.txt").write_text(out2)
        meta["path"] = str(d)
        (d / "meta.json").write_text(json.dumps(meta, indent=2))
        rows.append(meta)
        print("%-22s %-38s %6d -> %s  %s" % (
            fuzzer, a["artifact"][:38], len(data),
            meta.get("minimized_bytes"), (sig or "no crash on replay")[:70]))

    fields = ["fuzzer", "artifact", "sha1", "bytes", "exit", "kind", "signature",
              "minimized_bytes", "minimize_stable", "seconds", "path"]
    with open(triage / "index.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # One row per distinct signature: smallest stable minimised reproducer.
    uniq = {}
    for r in rows:
        key = r["signature"] or ("replay-failed|" + r["artifact"])
        cur = uniq.get(key)
        size = r.get("minimized_bytes") or r["bytes"]
        if cur is None or size < (cur.get("minimized_bytes") or cur["bytes"]):
            uniq[key] = r
    with open(triage / "uniq.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(uniq.values())
    print("\n%d artifacts, %d distinct signatures" % (len(rows), len(uniq)))
    for sig, r in uniq.items():
        print("  %-70s %s/%s" % (sig[:70], r["fuzzer"], r["sha1"][:12]))


if __name__ == "__main__":
    main()
