# Paper Submission Guide

This directory contains the draft paper (`paper.md`) and instructions for converting it to Word or PDF for submission.

## Overview

- **`paper.md`**: The main paper draft with 10 chapters, abstract, and references.
- **`references.md`**: Placeholder citations that only the student can complete.
- **`make_paper_tables.py`** (in `scripts/`): Script to generate result tables from `out/report.json`.

## Step 1: Fill the Placeholders

The paper has two types of placeholders:

### Type A: Real Data [PENDING REAL DATA: ...]

These are tables and numerical results that cannot be filled until real data collection is complete (W1+). The script `scripts/make_paper_tables.py` will generate them.

**How to fill:**

1. After collecting all M4, M2, and M3 data, run:
   ```bash
   python -m vsec run \
     --vm weak=cases/weak \
     --vm hardened=cases/hardened \
     --m2-dumps data/m2 \
     --m3-results data/m3/results.json \
     --m4-data data/m4 \
     --t-short <value-from-pilot> \
     --out out
   ```

2. Generate the tables:
   ```bash
   python scripts/make_paper_tables.py out/report.json > /tmp/tables.md
   ```

3. If data is simulated or not citable, use:
   ```bash
   python scripts/make_paper_tables.py out/report.json --allow-draft > /tmp/tables_draft.md
   ```
   Each table will be stamped **"DRAFT: NOT CITABLE"**.

4. Copy the relevant sections from `/tmp/tables.md` (or `/tmp/tables_draft.md`) and paste them into Chapter 7 (Results) and Chapter 8 (Discussion) where the `[PENDING REAL DATA: ...]` placeholders appear.

### Type B: References [CITE], [SURVEY-2020], TODO: ...

These are citations in the Literature Review (Chapter 2) and References section that need to be completed.

**How to fill:**

1. **The 2020 survey**: Find the full bibliographic details (author, year, title, venue) and fill the `[SURVEY-2020]` entries. Update `references.md` with the complete citation.

2. **Other cited tools**:
   - **QEMU**: https://www.qemu.org (provide link and version used)
   - **libvirt**: https://libvirt.org (provide link and version)
   - **Volatility 3**: https://github.com/volatilityfoundation/volatility3
   - **Lynis**: https://cisofy.com/lynis/
   - **OpenSCAP**: https://www.open-scap.org/
   - **Linux kernel**: https://kernel.org (document kernel version)

3. **Academic references**: For claims in Chapter 2 (Literature Review), provide full citations for papers or documentation you reference.

4. Edit `references.md`, replacing each `TODO: student to supply full citation` with the actual citation.

### Type C: Self-Checks [CHECK]

Some sentences are marked `[CHECK]` where the author is uncertain. Review these:

- For each `[CHECK]`, verify the claim against the code or test results.
- Remove the `[CHECK]` tag if confident, or rephrase the sentence.
- If the claim cannot be verified, mark it as uncertain or remove it.

**Example:**
```
[CHECK: Confirm tone is appropriate for the actual results once available.]
```
becomes:
```
This paper demonstrates that... [after seeing real results]
```

## Step 2: Verify the Paper Structure

Before submitting, check:

1. **All [PENDING REAL DATA: ...] placeholders are filled** with actual tables from step 1.
2. **All [SURVEY-2020] and citation references are resolved** in Chapters 2 and References.
3. **All [CHECK] markers are reviewed and addressed.**
4. **Solo authorship is clear**: Check Section 10.4 (Conclusion) states your name.
5. **Limitations are honest**: Chapter 9 explains what was and was not tested.

## Step 3: Convert to Word or PDF

### Option A: Using Pandoc (Recommended)

[Pandoc](https://pandoc.org) is a document converter that handles Markdown well.

**Install:**
```bash
# Ubuntu/Debian
sudo apt install pandoc

# macOS
brew install pandoc

# Windows (or download from https://pandoc.org/installing.html)
choco install pandoc
```

**Convert to Word (.docx):**
```bash
pandoc docs/paper/paper.md \
  -o docs/paper/paper.docx \
  --standalone \
  --reference-doc=docs/paper/template.docx  # optional: custom template
```

**Convert to PDF (requires LaTeX):**
```bash
pandoc docs/paper/paper.md \
  -o docs/paper/paper.pdf \
  --pdf-engine=pdflatex
```

If pdflatex is not installed:
```bash
# Ubuntu/Debian
sudo apt install texlive-xetex texlive-latex-base

# macOS
brew install --cask mactex

# Then try the pandoc command again
```

### Option B: Manual (Google Docs)

1. Go to [Google Docs](https://docs.google.com).
2. Create a new blank document.
3. Copy and paste the Markdown into the document (or use **File > Open** and upload `paper.md`).
4. Format the document (headings, spacing, citations) by hand.
5. Export: **File > Download > Microsoft Word** (.docx) or **File > Download > PDF Document** (.pdf).

### Option C: MS Word Import

1. On Windows, open Microsoft Word.
2. **File > Open** and select `docs/paper/paper.md`.
3. Word may prompt you to convert; choose **Yes**.
4. Review formatting and fix any issues.
5. **File > Save As > .docx** for Word or use **File > Print > Save as PDF**.

## Known Weak Spots to Rewrite Yourself

The following sections are outlines, placeholders, or contain claims that require verification once real data is collected:

### Outline-Only Chapters

**Chapter 2: Literature Review**
- The threat class descriptions are written but depend on confirming the full citation for [SURVEY-2020].
- You must provide the complete author(s), year, title, and venue for the 2020 survey before final submission.
- Cross-check that the threat classes listed (Guest-to-Host, Host-to-VMM, etc.) match the actual survey document.

### Data and Results Sections (All Pending Real Data)

**Chapter 7: Results** – All numerical results are marked [PENDING REAL DATA]:
- 7.1–7.6: Threat class matrices, per-VM status, M1/M2/M3/M4 evaluation tables.
- These must be filled with actual measurements from: M4 (45 sessions), M2 (≥120 dumps), M3 (public images or rootkit test), M1 (real-world configs ≥10 and Lynis/OpenSCAP comparison).

**Chapter 8: Discussion** – Sections 8.2–8.3 discuss hypothetical outcomes:
- Once M4 results exist, rewrite 8.2 and 8.3 to discuss **actual** H1–H4 outcomes, not conditional ones.
- Update interpretation of what results tell us about testability and generalizability.

### Claims Requiring Verification Once Real Data Exists

**H1–H4 Results and Holm Correction** (check against `vsec/m4_detect/classify.py`):
- H1: Session-level AUROC at T_short (one-sided paired bootstrap, p < 0.05).
- H2: FPR at TPR ≥ 0.90, Holm-adjusted p < 0.05. **Note:** Low-power; read with CIs.
- **H3: AUROC drop < 0.05 (PRIMARY metric, not F1 drop).** This was corrected in the paper; verify your results report AUROC drop.
- H4: Cost < 10s AND overhead < 5%, both with bootstrap CI.

**Pre-Registration** (Section 10.4):
- Confirm `prereg.md` is committed and tagged in git **before** starting real M4 data collection.
- Command: `git log --oneline prereg.md | head -1` should show a commit message before your first M4 session.

**M1 Evaluation**:
- Verify precision/recall/F1/FPR per control with 95% Wilson CIs match `vsec/score.py` calculations.
- Real-world configs (≥10) must be evaluated separately from the 50 synthetic fixtures.
- Lynis and OpenSCAP live comparison on `weak` and `hardened` hosts provides independent evidence of correctness.

**M2 Snapshot Privacy**:
- Recall per cell (12 cells, ≥10 dumps per cell) and false-positive rate per GB with 95% Wilson CIs.
- Redaction test: confirm VM resumes and service runs after redacted `virsh save` image is restored.

**M3 Memory Forensics**:
- Exact counts (e.g., 7/8 detected) per public image with 95% Clopper-Pearson CIs.
- If optional rootkit test is used, detection rates must be reported per kernel version.

**M4 Citable Status** (Section 6.3, 10.1):
- Results are "EXPLORATORY" (not citable) unless each class has **exactly** 15 sessions with **all 4 workloads**.
- Verify session count and workload completeness; if not met, update status flag in report.

### Fixed Issues (Do Not Revert)

The following issues were found and corrected during the 2026-10-04 audit:

1. **H3 definition:** Fixed from "F1 drop" to "AUROC drop" (primary).
2. **Code reviews claim:** Changed from "peers and supervisors" to "automated agents only" (solo project).
3. **Pre-registration status:** Changed from "is committed" to "will be committed and tagged before."
4. **Invented citations:** Removed fabricated author/title from [SURVEY-2020]; kept as TODO placeholder. Fixed OpenSCAP attribution.
5. **Hard-coded test counts:** Changed "954 tests (as of Round 5)" to "several hundred tests."
6. **Bench.c claims:** Clarified it has only a functional validation run in WSL2 (a VM), not on E1 (native hardware).
7. **Past tense errors:** Changed "evaluated," "measures," "we found" to "is designed to evaluate," "will measure," removing false claims of done work.
8. **Section 10.1:** Rewritten as "Summary of What This Work Builds and What Remains to Be Measured."
9. **Abstract:** Revised to clearly indicate the framework is designed for evaluation, not that evaluation is complete.
10. **References:** Added [VERIFY] notes to scikit-learn and NumPy; noted unverified citations.

## Student Checklist

Before final submission:

- [ ] **Real data collected**: M4 has 15 sessions per class (45 total), M2 has 120–240 dumps, M3 has results.
- [ ] **Report generated**: `python -m vsec run --out out` produces `out/report.json`.
- [ ] **Tables generated**: `python scripts/make_paper_tables.py out/report.json` outputs all tables.
- [ ] **Placeholders filled**: All `[PENDING REAL DATA: ...]` replaced with actual tables; no missing placeholders remain.
- [ ] **Citations completed**: `references.md` has full citations; `[SURVEY-2020]`, `[CITE]` markers resolved.
- [ ] **[CHECK] items reviewed**: Each `[CHECK]` is verified or removed.
- [ ] **Solo authorship stated**: Your name is in the paper (Section 1.5 and 10.4).
- [ ] **Honest limitations**: Chapter 9 explains what was/wasn't tested; no overclaiming.
- [ ] **PDF/Word generated**: Document is in the required submission format.
- [ ] **Formatting clean**: No Markdown symbols remain (headers are # not rendered).
- [ ] **No test failures**: `python -m pytest tests/test_paper_tables.py -q` passes.

## What the Script Cannot Do (Manual Work)

The `make_paper_tables.py` script generates **numerical tables only**. The following require manual work:

1. **Narrative sections** of Chapter 8 (Discussion): explaining what H1–H4 outcomes mean.
2. **Interpretation and insight** in Chapters 3–6: your reasoning about the framework.
3. **Figure design** (if required): diagrams, flowcharts, or visualizations.
4. **Prose around tables**: context and commentary linking tables to claims.
5. **Proofreading**: grammar, style, clarity.

The student is responsible for all narrative content and interpretation.

## Contact

If the student has questions:

1. Check the comments in `paper.md` (marked `[CHECK]` or `[PENDING ...]`).
2. Refer to `FINAL_PROJECT_PLAN.md` for the overall structure and goals.
3. Refer to code in `vsec/` and `scripts/` for implementation details.
4. Run `python -m vsec run --help` for command-line documentation.

## Submission

Once the paper is complete:

1. Name it `<student-name>-vsec-paper.pdf` or `.docx` (or your institution's naming).
2. Submit to your supervisor or institution as required.
3. Keep the Markdown source (`docs/paper/paper.md`) in the git repository for reproducibility.

---

**Note**: This paper is a draft and a research artifact. It demonstrates the framework and its results; it is not a polished journal submission. Adapt the tone, structure, and formatting to your institution's requirements.
