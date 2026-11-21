#!/usr/bin/env bash
# Independent verification of the two crash classes reported in Part 1.
#
# Builds the pre-mitigation commit (4cb65ae) and the mitigation commit
# (660f468) in scratch worktrees, then replays the two minimised reproducers
# and 20 random artifacts from the committed campaign. The point is to check
# the report against the repository, not to trust either.
#
#   scripts/verify_team_findings.sh
#
# Output: results/verification/verify.csv and results/verification/*.log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_COMMIT="${BASE_COMMIT:-4cb65ae1efd3f924822f823aec4cd0481b779061}"
FIXED_COMMIT="${FIXED_COMMIT:-660f46878009df767927db14ba7805573c0695d7}"
CAMPAIGN="${CAMPAIGN:-results/d3/baseline-20261120T173225Z}"
TMPD="${TMPD:-$(mktemp -d)}"
OUT="$ROOT/results/verification"
mkdir -p "$OUT"

git -C "$ROOT" worktree add --detach "$TMPD/heif-base" "$BASE_COMMIT" >/dev/null
git -C "$ROOT" worktree add --detach "$TMPD/heif-fixed" "$FIXED_COMMIT" >/dev/null
chmod -R a+rwX "$TMPD"

docker run --rm --platform linux/amd64 -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT":/repo -v "$TMPD":/scratch -w /scratch/heif-base libheif-fuzz:1.23.4 \
  bash -lc 'bash scripts/build.sh' > "$OUT/build-baseline.log" 2>&1
docker run --rm --platform linux/amd64 -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT":/repo -v "$TMPD":/scratch -w /scratch/heif-fixed libheif-fuzz:1.23.4 \
  bash -lc 'bash scripts/build.sh' > "$OUT/build-fixed.log" 2>&1

cat > "$OUT/verify.py" <<'PY'
import csv, os, random, subprocess, sys
campaign = sys.argv[1]
fixed = sys.argv[2]
rows = list(csv.DictReader(open(os.path.join(campaign, "analysis", "crashes.csv"))))
reps = {r["sha1"]: r for r in rows}
targets = ["49608d53a10a2a91fb7f226b588123ac3c36470e",
           "bd0c452dae2b4971047a90c797f4e1998d42bf9b"]
random.seed(3)
sample = random.sample(rows, 20)
out = []
for sha in targets:
    r = reps[sha]
    p = os.path.join("/repo", campaign, "analysis", "inputs", sha, "minimized.bin")
    for label, build in (("baseline", "heif-base"), ("fixed", "heif-fixed")):
        rc = subprocess.run([f"/scratch/{build}/build/fuzzing/{r['fuzzer']}", p,
                             "-runs=1"], capture_output=True, text=True)
        text = (rc.stdout or "") + (rc.stderr or "")
        sig = ""
        for line in text.splitlines():
            if "runtime error" in line or "ERROR: AddressSanitizer" in line:
                sig = line.strip()[:160]
                break
        out.append({"input": sha, "fuzzer": r["fuzzer"], "build": label,
                    "bytes": os.path.getsize(p), "exit": rc.returncode,
                    "signature": sig})
for i, r in enumerate(sample):
    p = os.path.join("/repo", r["path"])
    for label, build in (("baseline", "heif-base"), ("fixed", "heif-fixed")):
        rc = subprocess.run([f"/scratch/{build}/build/fuzzing/{r['fuzzer']}", p,
                             "-runs=1"], capture_output=True, text=True)
        out.append({"input": r["sha1"][:16] + "(%d)" % i, "fuzzer": r["fuzzer"],
                    "build": label, "bytes": r["bytes"], "exit": rc.returncode,
                    "signature": ("runtime error" in ((rc.stdout or "") + (rc.stderr or "")))})
w = csv.DictWriter(open("/repo/results/verification/verify.csv", "w", newline=""),
                   fieldnames=["input", "fuzzer", "build", "bytes", "exit", "signature"])
w.writeheader(); w.writerows(out)
for row in out:
    print(row)
PY

docker run --rm --platform linux/amd64 -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT":/repo -v "$TMPD":/scratch -w /scratch \
  libheif-fuzz:1.23.4 python3 /repo/results/verification/verify.py "/repo/$CAMPAIGN" fixed \
  | tee "$OUT/verify.log"

git -C "$ROOT" worktree remove --force "$TMPD/heif-base" >/dev/null 2>&1 || true
git -C "$ROOT" worktree remove --force "$TMPD/heif-fixed" >/dev/null 2>&1 || true
