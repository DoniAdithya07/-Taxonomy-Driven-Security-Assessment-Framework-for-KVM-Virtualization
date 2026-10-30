# Definition of Done (per module)

Tick a box only once you have evidence it passes (a test, a log, a file), not because the code exists. "Done" means implemented, tested, documented and demonstrated — not that a script runs without crashing.

## M1 — Configuration auditor
- [x] Control inventory reconciled and documented (`vsec/taxonomy.yaml`, 31 controls, `README.md` status table)
- [x] Known-positive and known-negative configurations tested (50 generated fixtures, `tests/test_m1.py`)
- [x] Findings include evidence and correct status (PASS/FAIL/NA with evidence string, never PASS on missing input)
- [ ] External comparison completed where applicable — **not done**: needs a live `weak`/`hardened` host, Lynis and OpenSCAP installed, and a hand-made ground truth for those two hosts (`docs/YOUR_TASKS.md` Task I). This is a manual comparison step, not a parser: Lynis/OpenSCAP audit general host hardening and only partly overlap with libvirt-specific controls (clearest overlap: C09 KSM, C25 CPU vulnerabilities, C26 SMT, C17/C21 permissions, C19/C20 exposed services). Do not write a generic "Lynis output parser" before you have a real report to parse against — the format assumptions would be guesses.
- [x] Permission and missing-dependency failures tested (`tests/test_m1.py`, `tests/test_guards.py`: a missing/unreadable file gives NA, a crash gives NA with the error)

## M2 — Snapshot privacy scanner
- [x] All 12 test cells exercised (synthetic planted secrets: `tests/test_m2_m3.py`)
- [x] Negative cases and malformed inputs tested (clean dumps, high-entropy padding, manifest validation)
- [x] Recall and false positives measured (per cell, synthetic only; `vsec/score.py`)
- [ ] Real-dump limitations documented — **partially done**: README/FINAL_PROJECT_PLAN already say "synthetic only, real dumps never collected"; still needs the actual Task E real dumps (hardware/VM-dependent) before this can say anything beyond "untested on real memory."
- [x] Sensitive scan output handled safely (chunked redaction, dumps memory-mapped, `collect.py` restrictive permissions and symlink refusal)

## M3 — Offline memory forensics
- [x] Volatility version and image compatibility recorded (plugin names checked against installed release per README)
- [ ] Known image processed successfully — **not done**: needs Volatility 3 installed and a public memory image downloaded (Task H). Code is written and tested against synthetic/mocked Volatility calls only.
- [ ] Expected findings checked against ground truth — blocked on the same real run.
- [x] Missing symbols and unsupported inputs handled (mandatory symbols hash, sandbox fallback flags, Volatility errors raise instead of looking clean)
- [x] Results reproducible from documented steps (`--row-name`, `--truth-hidden`, `--append` flow in README and `docs/YOUR_TASKS.md`)

## M4 — Hypervisor detection
- [x] Benchmark validated in the target environment — **partially**: `bench.c` compiled and ran once in WSL2 as a functional check only (not E1, not a native-vs-VM comparison; see `FINAL_PROJECT_PLAN.md` Round 6).
- [ ] Protocol frozen before confirmatory collection — `prereg.md` is still an uncommitted/untagged DRAFT; must be committed and tagged before any real session (Task D).
- [x] Raw data and session metadata preserved (`session_meta.py`, `meta.json` per session, schedule in `plan_sessions.py`)
- [x] Evaluation prevents session/workload leakage (grouped CV by session, repeated with 3 seeds, inner CV for model/threshold selection)
- [x] Metrics, uncertainty and negative results reported honestly (paired session bootstrap, Holm correction, ceiling/untestable rules, "EXPLORATORY" label if session counts are short, explicit power/low-sample-size caveat in `prereg.md`)

## What this table means right now
M1 and M2's *code and synthetic-test* obligations are done. M3's code is done but unexercised against any real image. M4's analysis code is done but the pre-registration isn't locked and no real session exists. Every unchecked box above needs the owner's hardware (E1) or installed tools (Volatility, Lynis, OpenSCAP) — none of it is a coding gap Claude can close from here.
