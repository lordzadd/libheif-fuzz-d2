#!/usr/bin/env bash
# Pack a run's final corpus into tarballs for the repository.
#
#   bash scripts/pack_corpus.sh long2
#
# Writes results/<run>/corpus_final_tar/<target>.tar.gz. Loose corpus files are
# tens of thousands of tiny files and are not suitable for git; the tarballs are
# about 1/3 of the size and one file per target. The report's Reproduction
# section shows the matching unpack loop.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${1:?usage: pack_corpus.sh <run>}"
SRC="$ROOT/results/$RUN/corpus_final"
DST="$ROOT/results/$RUN/corpus_final_tar"
[ -d "$SRC" ] || { echo "error: $SRC does not exist" >&2; exit 1; }
mkdir -p "$DST"
for d in "$SRC"/*/; do
  name="$(basename "$d")"
  tar -czf "$DST/$name.tar.gz" -C "$SRC" "$name"
  printf "%-28s %s\n" "$name" "$(du -h "$DST/$name.tar.gz" | cut -f1)"
done
