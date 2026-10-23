# libheif fuzzing campaign (D2)

Fuzzing harness for libheif at pinned commit `08075aebcc0d9bf7d35f900c36114b1b6e90ed7d`.

## Run

```sh
git clone <repo>
cd <repo>
python3 harness/run.py
```

The script builds libheif with fuzzers if needed, runs all fuzzers for 5 seconds each,
and writes `results/fuzz_results.csv`.
EOF
