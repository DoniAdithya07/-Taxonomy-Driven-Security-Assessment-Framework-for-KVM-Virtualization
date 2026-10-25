# Submission: vsec — Taxonomy-Driven Security Assessment Framework for KVM

## Scope and AI Assistance

This project was done by one student using an AI coding assistant (Claude). The assistant produced most of the code, tests, documentation and first drafts of the paper and slides under the student's direction. Code review was done by automated AI reviewers only; no person has independently reviewed or reproduced the work. The tests show internal consistency, not correctness against real systems. No real measurements exist: M4, M2, and M3 have not been run on real hardware. This submission presents a design, implementation, and test suite, not findings.

## What Is Included

- **`vsec/`** — Main framework: taxonomy, auditor, scanner, forensics wrapper, detector, reporting, secrets generator, guards, simulate.
- **`tests/`** — 1028 tests collected. Last full Windows run: 1009 passed, 19 skipped (Windows-only skips), about 4 minutes. The quick subset (`-m "not slow"`) takes about the same, 4 to 5 minutes, depending on machine load.
- **`scripts/`** — Setup, VM management, M2/M3/M4 data collection, safety gates, symbol building, session scheduling.
- **`vms/`** — VM XML definitions and network configuration.
- **`docs/`** — Demo script, tasks, checklists, data sources, and paper draft.
- **`docs/paper/paper.md`** — Paper draft (no results, placeholders marked [PENDING]).
- **`docs/slides/vsec_deck.pptx`** — Presentation deck (18 slides: 12 main, 6 backup; speaker notes on every slide). Rebuilt by `docs/slides/build_deck.py`.

## Quick Run (Windows, ~10 minutes)

```powershell
$env:TMP = "$PWD\.local\tmp"; $env:TEMP = "$PWD\.local\tmp"
$PY = ".local\venv\Scripts\python"

# Setup (if not done)
python -m venv .local/venv
.local\venv\Scripts\pip install -r requirements.txt

# Tests (quick subset, shows pipeline works on synthetic data; NOT a real result)
& $PY -m pytest -q -m "not slow"              # 4-5 min; expect about 1008 passed, 19 skipped, 1 deselected

# Demo (all simulated, not a result)
& $PY tests/make_fixtures.py .local/work/fx   # ~1 s, generates 50 test cases
& $PY -m vsec audit .local/work/fx/case00 --env E1  # ~1 s, shows M1 audit output
& $PY -m vsec run --fast --simulate --out .local/work/out  # ~1 min, produces report.html
start .local\work\out\report.html             # View simulated report (see banner: not real)
```

## Reading Order

1. **README.md** — Setup, commands, known limits.
2. **FINAL_PROJECT_PLAN.md** — Research question, design, timeline, what's done (Rounds 1–6), what's next (Section 13).
3. **prereg.md** — Pre-specified analysis plan (DRAFT, not yet committed; read Sections: Question, Design, Analysis, Hypotheses).
4. **docs/paper/paper.md** — Full paper (Sections 1–5 for context; Sections 7–10 for findings placeholders; Chapter 7 not yet written).
5. **docs/DEMO_SCRIPT.md** — What to demonstrate (Part 1 done; Part 2 awaits E1 hardware).
6. **docs/YOUR_TASKS.md** — Hardware hands-on steps (Tasks A–J for real measurement).

## Status: Done / Not Done

| | Status | Notes |
|---|---|---|
| **Framework (taxonomy, findings, report)** | ✓ | `taxonomy.yaml`, common JSON format, `report.py`. |
| **M1 auditor (28 controls, 50 fixtures)** | ✓ | Checks read files and live `/sys` state. Fixtures = self-consistency tests only. |
| **M2 scanner** | ✓ | Synthetic dumps only; real dumps never collected. |
| **M3 Volatility wrapper** | ✓ | Code written; never executed (no Volatility or real dumps). |
| **M4 bench.c, features, classify** | ✓ | Compiled; ran once in WSL2 (functional check only); no native vs VM comparison. |
| **Tests (1028, 1009 passed)** | ✓ | All pass on Windows; quick subset ~5 min. One Linux run: 985 passed, 2 fixed, not re-run. |
| **Paper draft (10 chapters)** | ✓ draft | No results; Chapter 7 is only `[PENDING REAL DATA]` placeholders; references and survey citation are TODO; Chapter 2 is an outline. |
| **Slides (18 slides)** | ✓ | Deck created with speaker notes on every slide; never rendered in PowerPoint (checked with python-pptx only); name and course line are placeholders. |
| **Demo script** | ✓ | Part 1 (simulated) ready; Part 2 (real data) awaits E1. |
| **Real M4 data (45 native vs VM boots, 4 workloads each)** | ✗ | E1 not available yet. |
| **Real M2 dumps (120 per 12 cells, n=5 then 10)** | ✗ | Target VM not set up; gates designed but not tested. |
| **Real M3 (Volatility on real/public dumps)** | ✗ | No dumps collected; integration written but untested. |
| **Lynis/OpenSCAP comparison for M1** | ✗ | Designed; never run. |
| **Pre-registration (prereg.md commit + tag)** | ✗ | `prereg.md` is DRAFT; will be committed before real M4 data collection. |

## What to Zip

Run: `.local\venv\Scripts\python scripts/make_submission_zip.py [--out dist/vsec_submission.zip] [--exclude-notes]`

Excludes: `.local/`, `out/`, `.claude/`, `tests/fixtures/`, `__pycache__/`, `.pytest_cache/`, `dist/`, virtual environments.

## Before You Hand In (Student Checklist)

- [ ] Check course policy: AI-assistance disclosure matches requirements.
- [ ] Replace `[STUDENT NAME]` in slides and paper title block with actual name.
- [ ] Paper: add survey citation or mark as TODO.
- [ ] Render presentation deck in PowerPoint; check fonts and layout; save as .pptx.
- [ ] Record the demo (Part 1 only until E1 is available).
- [ ] Remove any stray files or test data from the repo root.
- [ ] Verify `SUBMISSION.md`, `README.md`, and paper all include the AI-assistance statement.
- [ ] Run `find .local -type f | wc -l` to confirm scratch is minimal (should be test outputs only).
- [ ] Create the zip with `scripts/make_submission_zip.py` (or push to GitHub yourself); nothing in this project is committed or pushed automatically.

---

**Last Updated:** 2026-10-04. This submission is a design-and-implementation paper with a test suite, not a measurements paper.
