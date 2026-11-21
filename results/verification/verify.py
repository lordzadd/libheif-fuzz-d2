import csv, os, random, subprocess, sys
campaign = sys.argv[1]
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
        rc = subprocess.run([f"/scratch/{build}/build/fuzzing/{r['fuzzer']}", p, "-runs=1"],
                            capture_output=True, text=True)
        text = (rc.stdout or "") + (rc.stderr or "")
        sig = ""
        for line in text.splitlines():
            if "runtime error" in line or "ERROR: AddressSanitizer" in line:
                sig = line.strip()[:160]
                break
        out.append({"input": sha, "fuzzer": r["fuzzer"], "build": label,
                    "bytes": os.path.getsize(p), "exit": rc.returncode, "signature": sig})
for i, r in enumerate(sample):
    p = os.path.join("/repo", r["path"])
    for label, build in (("baseline", "heif-base"), ("fixed", "heif-fixed")):
        rc = subprocess.run([f"/scratch/{build}/build/fuzzing/{r['fuzzer']}", p, "-runs=1"],
                            capture_output=True, text=True)
        text = (rc.stdout or "") + (rc.stderr or "")
        sig = "runtime error" if "runtime error" in text else ""
        out.append({"input": r["sha1"][:16] + "(%d)" % i, "fuzzer": r["fuzzer"],
                    "build": label, "bytes": r["bytes"], "exit": rc.returncode,
                    "signature": sig})
w = csv.DictWriter(open("/repo/results/verification/verify.csv", "w", newline=""),
                   fieldnames=["input", "fuzzer", "build", "bytes", "exit", "signature"])
w.writeheader(); w.writerows(out)
print("baseline nonzero:", sum(1 for r in out if r["build"] == "baseline" and r["exit"] != 0),
      "fixed nonzero:", sum(1 for r in out if r["build"] == "fixed" and r["exit"] != 0))
