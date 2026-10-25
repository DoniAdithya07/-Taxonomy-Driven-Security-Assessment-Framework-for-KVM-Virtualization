# Slides

- `vsec_deck.pptx`: 18 slides, 16:9, speaker notes on every slide. Slides 1 to 12 are the main talk (about 10 minutes, ending at "How this was made, and questions"); slides 13 to 18 are backup, for questions only.
- `build_deck.py`: rebuilds the deck. From the project root:
  ```
  .local\venv\Scripts\python -m pip install -r requirements-dev.txt   # includes python-pptx
  .local\venv\Scripts\python docs\slides\build_deck.py
  ```
  Facts come from `FINAL_PROJECT_PLAN.md`, `README.md`, `prereg.md`, `docs/YOUR_TASKS.md` and `vsec/taxonomy.yaml` (control counts are read from the yaml at build time). The build prints a loud WARNING while the name or course line is still a placeholder, but it does not fail.
- `../DEMO_SCRIPT.md`: timed script for the demo recording.

## Before presenting
- Set your name and course line: at the top of `build_deck.py`, edit `STUDENT = "[STUDENT NAME]"` and `COURSE_LINE = "[COURSE / DATE]"`, then rebuild. The name appears on slide 1, in every footer, in the speaker notes and in the file properties (author).
- Open the deck in PowerPoint once and check every slide, especially the slides with tables (4, 8, 10, 11 and the backup tables) and the two diagrams (slide 3 pipeline, slide 7 three classes). Look for text that overflows its box.
- The first line of each main-slide note is "If short on time, say only: ...".
- The deck shows design and implementation only. Only fixture self-consistency figures (84/84) and test counts appear; no measurement or simulated result is shown.
- If you ever add output from `python -m vsec run --simulate`, every slide showing it must carry a visible banner: "SIMULATED DATA: pipeline demo only".
- Test counts on slide 10 and the backup: 1028 collected; Windows 1009 passed, 19 skipped (about 4 minutes); Linux once under WSL2 985 passed, 2 failed (fixed), 1 skipped, not re-run after the fixes. Update them if you re-run.
- `taxonomy.yaml` now labels Guest->Guest as "Config-proxy" (its PASS comes from the host-side network-definition check; the guest scan can only add a FAIL), and the deck says the same.
- Two facts to fill in: the full citation of the 2020 survey (slide 2 shows "[2020 survey: full citation to be supplied]"), and the commit and tag of `prereg.md` (the deck calls it a draft, not yet committed).

## Limits
- **The assistant cannot record video.** The demo video is yours to record; follow `docs/DEMO_SCRIPT.md`.
- The deck was checked only by reopening it with python-pptx (titles, notes, shapes inside the slide, no overlapping shapes, font sizes, at most 6 bullets). It was **never rendered** to images (no LibreOffice or PowerPoint was used), so text fit and table row heights are estimates until you open it in PowerPoint.
