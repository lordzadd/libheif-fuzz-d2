# libFuzzer slow-unit files written to the working directory during the Campaign D sweeps
# (-runs=1 reports units slower than 10 s). Re-timed one at a time on an idle machine,
# master ASan build, decode_matrix_fuzzer (12 output formats per input):
slow-unit-14ac7f3fa204d1a334aa2dc3ff63773ecf5d8813  7860 bytes exit=0 8.4s source=
slow-unit-27cac513f9ef0984291fffefff1f430c3696a1d1  7860 bytes exit=0 8.5s source=
slow-unit-50a55b7aaf8a06aa9759f7c77f2635c5ac5ae343 10058 bytes exit=0 8.8s source=
slow-unit-57be1e89fc11919c29c95bb1a0c726dcd95274fc  7664 bytes exit=0 8.3s source=
slow-unit-9cf824b4344cfe8ce147baecaa07f1db33295578 10269 bytes exit=0 8.6s source=
slow-unit-a0a80c94b94f932947f2865646b57138928e6132  7860 bytes exit=0 8.6s source=
slow-unit-a2be9bb5850f5b0acf6a59bacffd5de1aebd359e  7664 bytes exit=0 8.2s source=
slow-unit-b3f86c37fde1d8c453724de523d6b2722a7e5ae7  7664 bytes exit=0 8.1s source=
slow-unit-d04fe8dcd5ddd4b6dae8c3900ba829187d92aa07 10269 bytes exit=0 8.7s source=
# Verdict: not a finding. Each input is decoded into 12 output formats; ~0.7 s per decode under ASan. They crossed 10 s only while the sweep ran 4 processes on 4 cores. (Source lookup by content hash did not match because libFuzzer names the file by the hash of the input it ran.)
