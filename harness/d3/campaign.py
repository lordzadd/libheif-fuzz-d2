#!/usr/bin/env python3
"""Sustained, restart-tolerant libFuzzer campaign for libheif (D3, Track B).

One worker = one libFuzzer process. Workers are pinned to a fuzzer and share
that fuzzer's corpus directory, so they exchange inputs through libFuzzer's
`-reload=1`. A supervisor thread restarts a worker after a crash, timeout or
OOM so that one finding does not end the campaign.

Every line a worker prints is copied to its log with a wall-clock offset, so
`coverage.csv` can be rebuilt from the raw logs later (see analyze.py). Crashes
are copied to results/<run>/crashes/<fuzzer>/ and indexed in crashes.csv; the
chunk log that contains the sanitizer report is saved next to the artifact.

CPU time is measured with getrusage(RUSAGE_CHILDREN) around the whole run and
is also reported as wall-seconds x workers for comparison.
"""

import argparse
import csv
import hashlib
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "fuzzing"
SEED = ROOT / "corpora" / "seed"

# CPU budget is shared out in this order; each entry is one worker.
DEFAULT_ALLOC = [
    ("file_fuzzer", 3),
    ("api_fuzzer", 2),
    ("box_fuzzer", 2),
    ("tile_fuzzer", 1),
    ("sequence_fuzzer", 1),
    ("color_conversion_fuzzer", 1),
]

ENV = dict(os.environ)
ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:symbolize=1"
ENV["UBSAN_OPTIONS"] = "print_stacktrace=1"
ENV["LLVM_PROFILE_FILE"] = "/dev/null"

lock = threading.Lock()


def now():
    return time.time()


def scan_artifacts(adir):
    if not adir.exists():
        return {}
    out = {}
    for p in adir.iterdir():
        if p.name.startswith(("crash-", "oom-", "timeout-", "leak-", "slow-unit-")):
            out[p.name] = p
    return out


class Campaign:
    def __init__(self, run_dir, seconds, checkpoint, dict_path, alloc=None,
                 rss_limit=800, timeout=30, max_len=None, extra_flags="",
                 chunk_seconds=600):
        self.run_dir = run_dir
        self.deadline = now() + seconds
        self.seconds = seconds
        self.checkpoint = checkpoint
        self.dict_path = dict_path
        self.t0 = now()
        self.crash_rows = []
        self.interrupted = False
        self.stop = threading.Event()
        self.alloc = []
        self.worker_stats = []
        self.allocation = alloc or DEFAULT_ALLOC
        self.rss_limit = rss_limit
        self.unit_timeout = timeout
        self.max_len = max_len
        self.extra_flags = extra_flags
        self.chunk_seconds = chunk_seconds
        # Each run keeps its own live corpus so that two campaigns (for example
        # the pinned amd64 build and a native build) can run side by side.
        suffix = "" if run_dir.name == "baseline" else "-" + run_dir.name
        self.corpus_root = ROOT / "corpora" / ("run" + suffix)

    def _on_signal(self, signum, _frame):
        # Cloud runners often stop a job with SIGTERM at a wall-clock limit.
        # Treat it as "budget reached": stop the workers and still write the
        # summary and the final corpus snapshot, so the run is not lost.
        print("signal %d received: stopping and writing results" % signum, flush=True)
        self.interrupted = True
        self.deadline = now()

    # ---------------------------------------------------------------- workers
    def run_chunk(self, fuzzer, worker, corpus, adir, chunk, chunk_index):
        artifact_names_before = set(scan_artifacts(adir))
        # A fresh seed per chunk: after a crash the same mutation stream would
        # otherwise re-find the same input immediately and spin.
        seed = int(self.t0) + worker * 7919 + chunk_index * 104729
        cmd = [
            str(BUILD / fuzzer), str(corpus),
            "-max_total_time=%d" % chunk,
            "-timeout=%d" % self.unit_timeout,
            "-rss_limit_mb=%d" % self.rss_limit,
            "-reload=1",
            "-print_final_stats=1",
            "-use_value_profile=1",
            "-artifact_prefix=%s/" % adir,
            "-seed=%d" % seed,
        ]
        if self.max_len:
            cmd.append("-max_len=%d" % self.max_len)
        if self.dict_path and Path(self.dict_path).exists():
            cmd.append("-dict=%s" % self.dict_path)
        if self.extra_flags:
            cmd.extend(self.extra_flags.split())
        log_path = self.run_dir / "logs" / ("%s.w%d.log" % (fuzzer, worker))
        chunk_lines = []
        execs = 0
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                bufsize=1, env=ENV)
        with open(log_path, "a") as log:
            for line in proc.stdout:
                t = now() - self.t0
                log.write("[%10.2f] %s" % (t, line if line.endswith("\n") else line + "\n"))
                log.flush()
                chunk_lines.append(line)
                if "stat::number_of_executed_units:" in line:
                    try:
                        execs = int(line.split(":")[1])
                    except ValueError:
                        pass
                elif line.startswith("#") and " exec/s:" in line:
                    try:
                        execs = int(line.split()[0][1:])
                    except ValueError:
                        pass
                if self.stop.is_set():
                    # Do not wait for the fuzzer's own time budget: a cloud
                    # runner that sent SIGTERM has a short grace period.
                    proc.kill()
                    break
        try:
            rc = proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = -9
        # Crash artifacts created by this chunk. Files land directly in
        # results/<run>/crashes/<fuzzer>/ because that directory is the
        # libFuzzer artifact_prefix, so no copy is needed (and a copy would be
        # a same-file operation). A failure here must never stop the campaign.
        for name, src in scan_artifacts(adir).items():
            if name in artifact_names_before:
                continue
            try:
                data = src.read_bytes()
                digest = hashlib.sha1(data).hexdigest()
                log_copy = self.run_dir / "crash_logs" / (fuzzer + "-" + name + ".log")
                log_copy.parent.mkdir(parents=True, exist_ok=True)
                log_copy.write_text("".join(chunk_lines[-4000:]))
                row = {
                    "fuzzer": fuzzer,
                    "worker": worker,
                    "artifact": name,
                    "sha1": digest,
                    "bytes": len(data),
                    "t_s": round(now() - self.t0, 2),
                    "chunk_log": str(log_copy.relative_to(self.run_dir)),
                }
                with lock:
                    self.crash_rows.append(row)
                    with open(self.run_dir / "crashes.csv", "a", newline="") as fh:
                        w = csv.DictWriter(fh, fieldnames=list(row.keys()))
                        if fh.tell() == 0:
                            w.writeheader()
                        w.writerow(row)
                print("[%7.0fs] ARTIFACT %s %s (%d bytes)"
                      % (now() - self.t0, fuzzer, name, len(data)), flush=True)
            except Exception as e:
                print("artifact record error %s %s: %r" % (fuzzer, name, e), flush=True)
        return rc, execs

    def worker_loop(self, fuzzer, worker, corpus, adir):
        chunks = 0
        total_execs = 0
        while not self.stop.is_set():
            remaining = self.deadline - now()
            if remaining < 20:
                break
            chunk = int(min(self.chunk_seconds, remaining))
            try:
                rc, execs = self.run_chunk(fuzzer, worker, corpus, adir, chunk, chunks)
            except Exception as e:  # keep the campaign alive
                print("worker error %s w%d: %r" % (fuzzer, worker, e), flush=True)
                time.sleep(5)
                continue
            chunks += 1
            total_execs += execs
            if rc not in (0,):
                # Restart, but back off briefly so a deterministic corpus crash
                # does not spin. Corpora never contain crashing units, so this
                # is only a safeguard.
                time.sleep(1)
        with lock:
            self.worker_stats.append({"fuzzer": fuzzer, "worker": worker,
                                      "chunks": chunks, "execs": total_execs})

    # ------------------------------------------------------------ checkpoints
    def coverage_checkpoints(self, fuzzers):
        """Measure union coverage of the live corpus at intervals.

        libFuzzer prints `INITED cov: N ft: M` after it has executed every seed
        once with `-runs=0`, which is exactly the union edge count for the
        corpus at that moment. The corpus directory is read in place: copying
        hundreds of thousands of small files through a bind mount is slower than
        decoding them. A checkpoint is skipped when the corpus is too large to
        replay inside the interval, and the per-worker `cov:` series in the logs
        still gives coverage over time in that case.
        """
        path = self.run_dir / "coverage_checkpoints.csv"
        header = ["t_s", "fuzzer", "cov", "ft", "corpus_units", "corpus_bytes", "skipped"]
        if not path.exists():
            with open(path, "w", newline="") as fh:
                csv.writer(fh).writerow(header)
        max_units = 30000
        while not self.stop.is_set():
            for fuzzer in fuzzers:
                if self.stop.is_set():
                    # Shutdown requested. There is no live process to kill
                    # here: each checkpoint is a finished subprocess.run().
                    # (An earlier version called proc.kill() on the
                    # CompletedProcess, which raised and killed this thread.)
                    break
                corpus = self.corpus_root / fuzzer
                files = sorted(p for p in corpus.iterdir() if p.is_file()) if corpus.exists() else []
                if not files:
                    continue
                units = len(files)
                # libFuzzer replaces units in place (REDUCE deletes the old file),
                # so a stat can race with a worker. Skip missing files.
                nbytes = 0
                for p in files:
                    try:
                        nbytes += p.stat().st_size
                    except FileNotFoundError:
                        pass
                if units > max_units:
                    with lock, open(path, "a", newline="") as fh:
                        csv.writer(fh).writerow([round(now() - self.t0, 2), fuzzer,
                                                 0, 0, units, nbytes, 1])
                    continue
                cmd = ["nice", "-n", "15", str(BUILD / fuzzer), str(corpus),
                       "-runs=0", "-timeout=30", "-rss_limit_mb=2048"]
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True,
                                          timeout=900, env=ENV)
                except subprocess.TimeoutExpired:
                    continue
                if proc.returncode != 0:
                    continue
                cov = ft = 0
                for line in (proc.stdout + proc.stderr).splitlines():
                    if "cov:" in line and "ft:" in line:
                        try:
                            cov = int(line.split("cov:")[1].strip().split()[0])
                            ft = int(line.split("ft:")[1].strip().split()[0])
                        except (IndexError, ValueError):
                            pass
                if cov:
                    with lock, open(path, "a", newline="") as fh:
                        csv.writer(fh).writerow([round(now() - self.t0, 2), fuzzer,
                                                 cov, ft, units, nbytes, 0])
            # Sleep until the next checkpoint, but wake up for shutdown.
            self.stop.wait(self.checkpoint)

    # -------------------------------------------------------------------- run
    def run(self):
        (self.run_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.run_dir / "crashes").mkdir(parents=True, exist_ok=True)
        (self.run_dir / "crash_logs").mkdir(parents=True, exist_ok=True)
        with open(self.run_dir / "crashes.csv", "w", newline="") as fh:
            csv.writer(fh).writerow(["fuzzer", "worker", "artifact", "sha1",
                                     "bytes", "t_s", "chunk_log"])

        fuzzers = []
        threads = []
        for fuzzer, n in self.allocation:
            if not (BUILD / fuzzer).exists():
                print("skip %s: not built" % fuzzer)
                continue
            corpus = self.corpus_root / fuzzer
            corpus.mkdir(parents=True, exist_ok=True)
            seed_dir = SEED / fuzzer
            if seed_dir.exists():
                for p in seed_dir.iterdir():
                    if p.is_file() and not (corpus / p.name).exists():
                        shutil.copy2(p, corpus / p.name)
            adir = self.run_dir / "crashes" / fuzzer
            adir.mkdir(parents=True, exist_ok=True)
            fuzzers.append(fuzzer)
            for w in range(n):
                self.alloc.append((fuzzer, w))
                t = threading.Thread(target=self.worker_loop,
                                     args=(fuzzer, w, corpus, adir), daemon=True)
                t.start()
                threads.append(t)
                time.sleep(0.4)

        ck = threading.Thread(target=self.coverage_checkpoints, args=(fuzzers,),
                              daemon=True)
        ck.start()

        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

        start_ru = resource.getrusage(resource.RUSAGE_CHILDREN)
        while now() < self.deadline:
            time.sleep(5)
        self.stop.set()
        for t in threads:
            t.join(timeout=45)
        ck.join(timeout=180)
        end_ru = resource.getrusage(resource.RUSAGE_CHILDREN)

        cpu = ((end_ru.ru_utime - start_ru.ru_utime) +
               (end_ru.ru_stime - start_ru.ru_stime))

        # Final corpus snapshot for the repository and for replay.
        final = self.run_dir / "corpus_final"
        shutil.rmtree(final, ignore_errors=True)
        corpus_rows = []
        for fuzzer in fuzzers:
            corpus = self.corpus_root / fuzzer
            dst = final / fuzzer
            dst.mkdir(parents=True, exist_ok=True)
            files = sorted(p for p in corpus.iterdir() if p.is_file())
            nbytes = 0
            for p in files:
                try:
                    shutil.copy2(p, dst / p.name)
                    nbytes += p.stat().st_size
                except FileNotFoundError:
                    pass
            corpus_rows.append({"fuzzer": fuzzer,
                                "units": len(list(dst.iterdir())),
                                "bytes": nbytes})

        per_worker = {}
        for s in self.worker_stats:
            per_worker.setdefault(s["fuzzer"], []).append(s)
        summary = {
            "run": self.run_dir.name,
            "started_unix": int(self.t0),
            "requested_seconds": self.seconds,
            "interrupted": self.interrupted,
            "wall_seconds": round(now() - self.t0, 1),
            "workers": len(self.alloc),
            "worker_allocation": {},
            "cpu_seconds": round(cpu, 1),
            "cpu_hours": round(cpu / 3600.0, 3),
            "wall_seconds_times_workers": round((now() - self.t0) * len(self.alloc), 1),
            "crashes": len(self.crash_rows),
            "build": str(BUILD),
            "asan_options": ENV["ASAN_OPTIONS"],
            "rss_limit_mb": self.rss_limit,
            "unit_timeout_s": self.unit_timeout,
            "max_len": self.max_len,
            "extra_flags": self.extra_flags,
            "chunk_seconds": self.chunk_seconds,
            "dict": self.dict_path,
            "fuzzers": {},
        }
        for fuzzer, n in self.allocation:
            if fuzzer in fuzzers:
                summary["worker_allocation"][fuzzer] = n
        for row in corpus_rows:
            ws = per_worker.get(row["fuzzer"], [])
            summary["fuzzers"][row["fuzzer"]] = {
                "workers": summary["worker_allocation"].get(row["fuzzer"], 0),
                "chunks": sum(s["chunks"] for s in ws),
                "execs_from_logs": sum(s["execs"] for s in ws),
                "final_corpus_units": row["units"],
                "final_corpus_bytes": row["bytes"],
                "crashes": len([c for c in self.crash_rows if c["fuzzer"] == row["fuzzer"]]),
            }
        with open(self.run_dir / "campaign_summary.json", "w") as fh:
            json.dump(summary, fh, indent=2)
        print(json.dumps(summary, indent=2))
        return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, required=True)
    ap.add_argument("--run", required=True,
                    help="output directory name under results/, e.g. baseline")
    ap.add_argument("--checkpoint", type=int, default=900)
    ap.add_argument("--alloc", default=None,
                    help="worker allocation, e.g. file_fuzzer=2,api_fuzzer=1")
    ap.add_argument("--rss-limit", type=int, default=800,
                    help="libFuzzer -rss_limit_mb per worker (default 800)")
    ap.add_argument("--unit-timeout", type=int, default=30,
                    help="libFuzzer -timeout per input (default 30)")
    ap.add_argument("--max-len", type=int, default=None,
                    help="libFuzzer -max_len; default is the largest seed")
    ap.add_argument("--extra-flags", default="",
                    help='extra libFuzzer flags, e.g. "-entropic=1 -len_control=0"')
    ap.add_argument("--chunk-seconds", type=int, default=600,
                    help="chunk length before a worker restart (default 600)")
    ap.add_argument("--dict", default=str(ROOT / "libheif" / "fuzzing" / "data" / "dictionary.txt"))
    args = ap.parse_args()
    run_dir = ROOT / "results" / args.run
    run_dir.mkdir(parents=True, exist_ok=True)
    alloc = None
    if args.alloc:
        alloc = []
        for part in args.alloc.split(","):
            name, n = part.split("=")
            alloc.append((name.strip(), int(n)))
    c = Campaign(run_dir, args.seconds, args.checkpoint, args.dict, alloc,
                 rss_limit=args.rss_limit, timeout=args.unit_timeout,
                 max_len=args.max_len, extra_flags=args.extra_flags,
                 chunk_seconds=args.chunk_seconds)
    c.run()


if __name__ == "__main__":
    main()
