# libheif fuzzing campaign (D2)

This repository vendors libheif commit 08075aebcc0d9bf7d35f900c36114b1b6e90ed7d and provides a reproducible runner for its seven upstream fuzz targets.

## Run

    git clone https://github.com/lordzadd/libheif-fuzz-d2.git
    cd libheif-fuzz-d2
    python3 harness/run.py

The runner builds with Clang/libFuzzer and executes 1,000 inputs per target by default. Set FUZZ_RUNS to choose another fixed count. Outputs are written to a timestamped directory under results/. See docs/D2.md for the Track B analysis, prerequisites, and coverage limitations.
