#!/usr/bin/env python3
"""Build the seed corpus of decode_matrix_fuzzer (D3, Campaign D).

Every generated seed (corpora/seed/file_fuzzer/gen-*, gen_seeds.py) three times,
with option byte 0x00 (no alpha composition), 0x08 (solid colour) and 0x10
(checkerboard), plus 1 500 units sampled with random.Random(4281) from the
Campaign C file_fuzzer final corpus (results/long2c/corpus_final, unpacked from
corpus_final_tar), each with a random option byte. Files are named by SHA-1.

  python3 harness/d3/matrix_seeds.py [--out corpora/seed/decode_matrix_fuzzer]
"""
import argparse
import hashlib
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=str(ROOT / "corpora" / "seed" / "decode_matrix_fuzzer"))
args = ap.parse_args()
out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
src = sorted((ROOT / "corpora" / "seed" / "file_fuzzer").glob("gen-*"))
rng = random.Random(4281)
fc = sorted((ROOT / "results" / "long2c" / "corpus_final" / "file_fuzzer").iterdir())
src += rng.sample(fc, 1500)
n = 0
for p in src:
    data = p.read_bytes()
    for sel in (0x00, 0x08, 0x10) if p.name.startswith("gen-") else (rng.randrange(24),):
        b = bytes([sel]) + data
        (out / hashlib.sha1(b).hexdigest()).write_bytes(b)
        n += 1
print(n, "seeds in", out)
