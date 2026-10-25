"""Build docs/slides/vsec_deck.pptx.   Run from the repo root:
    .local/venv/Scripts/python docs/slides/build_deck.py
Content comes only from FINAL_PROJECT_PLAN.md, README.md, prereg.md, docs/YOUR_TASKS.md and vsec/taxonomy.yaml.
No measured result is shown anywhere. The only figures are fixture self-consistency (84/84) and test counts.
Main talk = slides up to "Questions"; everything after it is backup."""
from datetime import datetime
from pathlib import Path

import yaml
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).with_name("vsec_deck.pptx")

# ---- set these two before presenting, then rebuild -------------------------------------------
STUDENT = "[STUDENT NAME]"
COURSE_LINE = "[COURSE / DATE]"
# -----------------------------------------------------------------------------------------------

NAVY, TEAL, INK, MUTED = RGBColor(0x14, 0x2B, 0x3F), RGBColor(0x0B, 0x6B, 0x74), RGBColor(0x22, 0x2B, 0x33), RGBColor(0x5B, 0x67, 0x70)
PALE, WHITE, AMBER, RED = RGBColor(0xEA, 0xF3, 0xF4), RGBColor(255, 255, 255), RGBColor(0x8A, 0x50, 0x00), RGBColor(0xA6, 0x1E, 0x1E)
PINK, GREEN_T, AMBER_T = RGBColor(0xFD, 0xEE, 0xEE), RGBColor(0xE6, 0xF4, 0xEA), RGBColor(0xFF, 0xF1, 0xD6)
FONT = "Calibri"

AI_SHORT = ("Built with an AI coding assistant (Claude); AI-agent reviews only, no human review. "
            "Design and implementation, no measured results.")
AI_FULL = ("One student worked with an AI assistant (Claude) that produced most of the code, tests, documents and first drafts. "
           "The tests show internal consistency, not real-world correctness. There are no real measurements; simulated numbers are not results. "
           "The analysis plan (prereg.md) is a draft, not yet committed.")
REMAINING = "Remaining work, NOT part of this submission: E1 not built; no native-vs-VM, M2-dump or Volatility results."

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
TITLE_ONLY = prs.slide_layouts[5]
n_slides = 0


def txt(slide, x, y, w, h, text, size=16, bold=False, color=INK, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.05)
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size, r.font.bold, r.font.color.rgb, r.font.name = Pt(size), bold, color, FONT
    return tb


def bullets(slide, x, y, w, h, items, size=18):
    assert len(items) <= 6, "max 6 bullets per slide"
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(9)
        head, _, rest = it.partition("::")
        if rest:
            r = p.add_run(); r.text = head + " "
            r.font.bold, r.font.size, r.font.color.rgb, r.font.name = True, Pt(size), TEAL, FONT
            r = p.add_run(); r.text = rest.strip()
        else:
            r = p.add_run(); r.text = "- " + it
        r.font.size, r.font.color.rgb, r.font.name = Pt(size), INK, FONT
    return tb


def box(slide, x, y, w, h, fill=PALE, line=None):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    s.adjustments[0] = 0.06
    s.fill.solid(); s.fill.fore_color.rgb = fill
    if line: s.line.color.rgb = line; s.line.width = Pt(1.5)
    else: s.line.fill.background()
    s.shadow.inherit = False
    return s


def card(slide, x, y, w, h, head, body, size=14, fill=PALE):
    box(slide, x, y, w, h, fill)
    txt(slide, x + 0.15, y + 0.1, w - 0.3, 0.45, head, 16, True, TEAL)
    txt(slide, x + 0.15, y + 0.55, w - 0.3, h - 0.65, body, size)


def table(slide, x, y, w, rows, col_w, size=14, row_h=0.45, header_fill=NAVY):
    gs = slide.shapes.add_table(len(rows), len(rows[0]), Inches(x), Inches(y), Inches(w), Inches(row_h * len(rows)))
    t = gs.table
    for j, cw in enumerate(col_w):
        t.columns[j].width = Inches(cw)
    for i, row in enumerate(rows):
        t.rows[i].height = Inches(row_h)
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.fill.solid(); c.fill.fore_color.rgb = header_fill if i == 0 else (PALE if i % 2 else WHITE)
            c.margin_left = c.margin_right = Inches(0.08); c.margin_top = c.margin_bottom = Inches(0.03)
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            p = c.text_frame.paragraphs[0]; c.text_frame.word_wrap = True
            r = p.add_run(); r.text = str(val)
            r.font.size, r.font.name = Pt(size), FONT
            r.font.bold = i == 0
            r.font.color.rgb = WHITE if i == 0 else INK
    return t


def slide(title, notes, short=None):
    """Content slide with a real title placeholder (so every slide has a title) and speaker notes.
    Main-talk slides pass `short`, which becomes the first line of the notes."""
    global n_slides
    n_slides += 1
    s = prs.slides.add_slide(TITLE_ONLY)
    t = s.shapes.title
    t.left, t.top, t.width, t.height = Inches(0.6), Inches(0.35), Inches(12.1), Inches(0.9)
    t.text_frame.word_wrap = True
    t.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = t.text_frame.paragraphs[0]; p.alignment = PP_ALIGN.LEFT
    r = p.runs[0] if p.runs else p.add_run()
    r.text = title
    r.font.size, r.font.bold, r.font.color.rgb, r.font.name = Pt(32), True, NAVY, FONT
    txt(s, 0.6, 6.95, 9.5, 0.4, f"vsec | one student with an AI assistant | {STUDENT}", 12, False, MUTED)
    txt(s, 12.0, 6.95, 0.8, 0.4, str(n_slides), 12, False, MUTED, PP_ALIGN.RIGHT)
    s.notes_slide.notes_text_frame.text = (f"If short on time, say only: {short}\n" if short else "") + notes
    return s


def remaining_banner(s, y=1.4):
    box(s, 0.6, y, 12.1, 0.6, AMBER_T, AMBER)
    txt(s, 0.7, y + 0.05, 11.9, 0.5, REMAINING, 15, True, AMBER, anchor=MSO_ANCHOR.MIDDLE)


tax = yaml.safe_load((ROOT / "vsec" / "taxonomy.yaml").read_text(encoding="utf8"))
controls = tax["controls"]
labels = dict(tax["threat_classes"])
# Guest->Guest: its PASS comes from the host-side network-definition check, a guest scan can only add a FAIL.
# taxonomy.yaml still says "Tested"; the deck overrides it until the yaml is changed.
labels["Guest->Guest"] = "Config-proxy"
n_total = len(controls)
m1 = [c for c in controls if c["module"] == "M1"]
n_live = sum(c["type"] == "live" for c in m1)
n_cfg = sum(c["type"] == "config" for c in m1)
n_ver = sum(c["type"] == "version" for c in m1)
assert len(m1) == 28, len(m1)
assert n_total == 31, n_total

# ================================================================ MAIN TALK
# ---------------------------------------------------------------- 1 title
n_slides += 1
s = prs.slides.add_slide(TITLE_ONLY)
bg = s.background.fill; bg.solid(); bg.fore_color.rgb = NAVY
t = s.shapes.title
t.left, t.top, t.width, t.height = Inches(0.8), Inches(1.0), Inches(11.7), Inches(1.9)
t.text_frame.word_wrap = True
p = t.text_frame.paragraphs[0]; p.alignment = PP_ALIGN.LEFT
r = p.runs[0] if p.runs else p.add_run()
r.text = "Taxonomy-driven security assessment for KVM virtualization"
r.font.size, r.font.bold, r.font.color.rgb, r.font.name = Pt(44), True, WHITE, FONT
txt(s, 0.8, 3.0, 11.7, 0.5, COURSE_LINE, 20, False, RGBColor(0xFF, 0xD0, 0x80))
txt(s, 0.8, 3.6, 11.7, 0.9, "vsec: a framework that turns a survey's threat taxonomy into testable controls", 22, False, RGBColor(0xBF, 0xE3, 0xE6))
txt(s, 0.8, 4.55, 11.7, 0.7, AI_SHORT, 14, False, WHITE)
txt(s, 0.8, 5.35, 11.7, 0.5, f"{STUDENT}  |  one student, with an AI coding assistant (Claude)", 18, False, WHITE)
txt(s, 0.8, 5.95, 11.7, 0.8, REMAINING, 16, True, RGBColor(0xFF, 0xD0, 0x80))
s.notes_slide.notes_text_frame.text = (
    "If short on time, say only: this is a design and implementation project built with an AI assistant, and it has no measured results.\n"
    f"I am {STUDENT}. This is a one-student project, built with an AI coding assistant (Claude) that wrote most of the code, tests and first drafts. "
    "Reviews were done by AI agents only, in three waves; no human reviewed the work. "
    "Today I present the framework and the experiment design, plus an implementation that passes its own tests. "
    "I have no real measurements. The planned PC booted from an external SSD, called E1, was never built, so there are no native-versus-VM results, no memory-dump results and no Volatility results.")

# ---------------------------------------------------------------- 2 problem
s = slide("Problem and research question", (
    "A 2020 virtualization-security survey lists many threats and controls but does not say which can be tested on a modern KVM stack. Its full citation is still to be supplied. "
    "The 31 controls and 9 threat classes are this project's own mapping, not mapped to the survey's sections. "
    "Question: which hold, which fail, which cannot be tested; 'cannot be tested' is a valid answer, reported as N/A. "
    "Centrepiece, module M4: a VMBR is a hypervisor-based rootkit; our stand-in only hides static indicators and is not a real one."),
    short="a survey names threats but not what is testable; we turn them into testable controls and ask whether several behaviour signals beat one.")
card(s, 0.6, 1.5, 6.0, 2.7, "Research question",
     "Can the survey's threats and controls become testable controls on a modern KVM stack? Which hold, fail, or cannot be tested?", 17)
card(s, 6.8, 1.5, 5.9, 2.7, "Centrepiece (M4)",
     "Do several behaviour signals together detect a hypervisor that hides its static indicators better than the best single signal? (A stand-in for a VMBR, a hypervisor-based rootkit.)", 17)
bullets(s, 0.6, 4.5, 12.1, 2.2, [
    "Survey:: [2020 survey: full citation to be supplied]",
    "Mapping:: 31 controls, 9 classes: our own, not survey sections",
], 18)

# ---------------------------------------------------------------- 3 approach + pipeline + honesty rules
s = slide("From survey taxonomy to a result matrix", (
    "The taxonomy of 9 threat classes and 31 controls is split across 4 modules: M1 configuration auditor, M2 snapshot privacy, M3 offline forensics, M4 multi-signal hypervisor detection. "
    "Each writes the same finding format, and one report command builds the result matrix. "
    "Honesty rules: PASS means the control passed its defined test, never that the system is secure. NA is never PASS; on a seeded fault it counts as a miss. Simulated data is never a result."),
    short="one pipeline from taxonomy to matrix, and PASS only means 'passed its test'.")
steps = [("Survey taxonomy", "9 classes, 31 controls"), ("4 modules", "M1 to M4"), ("One finding format", "PASS, FAIL or NA"), ("Result matrix", "one row per VM")]
bw, gap = 2.55, (12.1 - 4 * 2.55) / 3
for i, (h, b) in enumerate(steps):
    x = 0.6 + i * (bw + gap)
    card(s, x, 1.5, bw, 1.4, h, b, 15)
    if i < 3:
        txt(s, x + bw, 1.85, gap, 0.6, "→", 30, True, TEAL, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE)
box(s, 0.6, 3.3, 12.1, 3.4, PINK, RED)
txt(s, 0.8, 3.4, 11.7, 0.5, "Honesty rules", 20, True, RED)
bullets(s, 0.8, 4.0, 11.7, 2.6, [
    "PASS:: passed its defined test; it does not mean 'secure'",
    "NA:: never counted as PASS; on a seeded fault it is a miss",
    "Simulated data:: never a result",
    "M1 fixtures:: self-consistency only",
], 18)

# ---------------------------------------------------------------- 4 taxonomy map
mod_of = {}
cnt = {}
for c in controls:
    mod_of.setdefault(c["threat"], set()).add(c["module"])
    cnt[c["threat"]] = cnt.get(c["threat"], 0) + 1
order = ["Guest->Host", "Host->VMM", "Guest->Guest", "VMM vulnerabilities", "Side channels", "DMA/IOMMU",
         "Snapshot privacy", "VMI / hidden processes", "Hypervisor/VMBR presence"]
assert set(order) == set(labels) == set(cnt)
assert [cnt[k] for k in order] == [12, 6, 3, 2, 3, 2, 1, 1, 1], cnt
rows = [["Threat class", "Label", "Module", "Controls"]]
for k in order:
    rows.append([k, labels[k], "/".join(sorted(mod_of[k])), cnt[k]])
s = slide("Taxonomy to modules: what is actually tested", (
    f"{n_total} controls in 9 threat classes, the project's own mapping. The label says how a class is tested, not the result. "
    "Config-proxy means only configuration or a version is checked, not an attack: Host->VMM, VMM vulnerabilities, side channels and Guest->Guest. "
    "Guest->Guest gets its PASS from a host-side check of the network definition; a guest scan can only add a FAIL. "
    "DMA/IOMMU needs E1, not built. C23 and C24 use a fixture CVE list; the real list gives NA."),
    short="nine threat classes, and only some are tested directly; the rest are Config-proxy, meaning configuration or version checks.")
table(s, 0.6, 1.4, 12.1, rows, [4.6, 2.6, 3.0, 1.9], size=14, row_h=0.46)
txt(s, 0.6, 6.15, 12.1, 0.7, "Label = how a class is tested, not a result. E1 = planned PC booted from an external SSD (not built).", 14, False, MUTED)

# ---------------------------------------------------------------- 5 M1
s = slide("M1: configuration auditor", (
    f"M1 has {len(m1)} controls: {n_cfg} config checks that read files, {n_live} live checks that prove a control is active (for example the Seccomp field, or sVirt, libvirt's per-VM security labels), and {n_ver} version checks. "
    "The 84/84: 50 fixtures with 84 seeded faults, 28 controls times 3, all found; 0 false alarms in 1,310 clean checks; 6 NA predictions. "
    "But the checker's author wrote the fixtures and the same AI wrote the tests, so this is self-consistency, not correctness. "
    "Lynis and OpenSCAP would give independent evidence; planned, never run."),
    short="84/84 on my own fixtures shows self-consistency, not real-world correctness.")
txt(s, 0.6, 1.4, 12.1, 0.5, "84/84 seeded faults found in 50 fixtures; 0 false alarms in 1,310 clean checks.", 20, True, NAVY)
txt(s, 0.6, 2.0, 12.1, 0.9,
    f"{len(m1)} checks: {n_cfg} config, {n_live} live (e.g. sVirt = per-VM security labels), {n_ver} version (fixture CVE list; the real list gives NA).", 16)
box(s, 0.6, 3.2, 5.6, 3.5, GREEN_T)
txt(s, 0.8, 3.3, 5.2, 0.45, "What 84/84 shows", 18, True, RGBColor(0x1E, 0x6B, 0x35))
bullets(s, 0.8, 3.9, 5.2, 2.7, ["Checker matches its own specification", "Missing input gives NA, never PASS"], 16)
box(s, 6.5, 3.2, 6.2, 3.5, PINK, RED)
txt(s, 6.7, 3.3, 5.8, 0.45, "What it does not show", 18, True, RED)
bullets(s, 6.7, 3.9, 5.8, 2.7, ["Real-world correctness", "Independent evidence: same author, tests written by the same AI"], 16)

# ---------------------------------------------------------------- 6 M1-M3 in brief
s = slide("M1 to M3 in brief", (
    "M1 audits a host's configuration: 28 checks, each PASS, FAIL or NA. "
    "M2 scans VM memory snapshots for planted fake secrets; tested on synthetic dumps only. "
    "M3 uses Volatility 3, a memory-forensics tool, offline. pslist walks the kernel's own process list, psscan scans raw memory for process structures; a process only the scan finds is a hidden candidate. "
    "Volatility has not run on real dumps. Details are in the backup."),
    short="three small modules; only M1 has been run on its own fixtures, M2 and M3 only on synthetic input.")
card(s, 0.6, 1.5, 3.9, 3.4, "M1 Config auditor", "28 checks on a host's configuration; each gives PASS, FAIL or NA.", 16)
card(s, 4.7, 1.5, 3.9, 3.4, "M2 Snapshot privacy", "Scans VM memory snapshots for planted fake secrets.", 16)
card(s, 8.8, 1.5, 3.9, 3.4, "M3 Offline forensics",
     "Compares pslist and psscan (two ways of listing processes in a memory dump) to find hidden ones.", 16)
txt(s, 0.6, 5.2, 12.1, 1.2, "M2 and M3: scanner and scoring code tested on synthetic input only. Volatility has not run on real dumps.", 18, True, AMBER)

# ---------------------------------------------------------------- 7 M4 design
s = slide("M4: multi-signal hypervisor detection (design)", (
    "M4 is the centrepiece, and it is a design with three machine classes: native (Ubuntu on the PC), kvm-plain (a QEMU/KVM guest, default settings) and kvm-masked (static indicators hidden with standard libvirt options; no time faking; not a real VMBR). "
    "It needs E1, the planned PC booted from an external SSD; not built. "
    "bench.c, the C benchmark, compiled with gcc 13.3 and zig. One functional run in WSL2 (a VM under Hyper-V) on 2026-10-04: the CSV loads, quality checks pass, no number is a finding. Never run natively or in a KVM guest."),
    short="three machine classes to compare; the experiment needs a PC I have not built.")
txt(s, 0.6, 1.4, 12.1, 0.4, "Same PC, same image, 15 boot sessions per class (planned)", 15, False, MUTED)
card(s, 0.6, 1.9, 3.9, 2.6, "native", "Ubuntu\nPC hardware", 16)
card(s, 4.7, 1.9, 3.9, 2.6, "kvm-plain", "Guest OS\nQEMU/KVM\nPC hardware", 16)
card(s, 8.8, 1.9, 3.9, 2.6, "kvm-masked", "Guest OS, static indicators hidden\nQEMU/KVM\nPC hardware\nNot a real VMBR", 16, AMBER_T)
bullets(s, 0.6, 4.75, 12.1, 2.1, [
    "E1:: the planned PC booted from an external SSD; not built",
    "Signals:: timing, memory, scheduler jitter",
    "bench.c:: one functional run in WSL2 (a VM), never native or in a guest",
], 16)

# ---------------------------------------------------------------- 8 analysis plan
s = slide("Pre-specified analysis plan: hypotheses H1 to H4", (
    "This is a pre-specified analysis plan: a draft in prereg.md, not yet committed or tagged, so it is not a registration. "
    "AUROC: how well a detector separates two classes; 0.5 is chance, 1 is perfect. Holm: a correction for testing several hypotheses at once. "
    "H1: combined signals beat the best single signal at the shortest useful time. H3: the drop in session AUROC on unseen workloads; upper 95% bootstrap bound under 0.05 and Holm p under 0.05; F1 drop is secondary. "
    "With 15 against 15 sessions a null result proves nothing."),
    short="four hypotheses with fixed pass rules, written down before any data; the plan is a draft.")
rows = [["Hypothesis", "Supported if"],
        ["H1  Combined signals beat best single signal", "AUROC higher at T_short; p < 0.05"],
        ["H2  Fewer false alarms on native", "FPR difference CI excludes 0; Holm p < 0.05"],
        ["H3  Robust to unseen workloads", "Upper 95% bootstrap bound of AUROC drop < 0.05; Holm p < 0.05"],
        ["H4  Practical cost", "Under 10 s per decision, under 5% overhead"]]
table(s, 0.6, 1.4, 12.1, rows, [5.4, 6.7], size=14, row_h=0.6)
bullets(s, 0.6, 4.7, 12.1, 2.1, [
    "AUROC:: 0.5 = chance, 1 = perfect",
    "Holm:: multiple-test correction",
    "Status:: draft plan, not yet committed",
], 16)

# ---------------------------------------------------------------- 9 safety
s = slide("Safety and lab rules", (
    "Defensive research on my own hardware. Before any dump, a preflight script checks that no other VM runs, the target is offline and the target was reverted; the revert marker is single-use and expires in 15 minutes. "
    "The target VM has no network and is reverted before every experiment. The optional rootkit test runs only inside the isolated target, never on the host. "
    "No real malware, no VMBR, no real credentials. For E1: BitLocker key on paper first, internal disk disconnected during install."),
    short="everything runs in an isolated, reverted target VM; no real malware or credentials.")
card(s, 0.6, 1.5, 6.0, 2.4, "Preflight gate", "No other VM running; target offline and reverted before any dump.", 16)
card(s, 6.8, 1.5, 5.9, 2.4, "Isolation", "Target VM has no network; snapshot revert before every run.", 16)
card(s, 0.6, 4.1, 6.0, 2.5, "Rootkit guard", "Optional test, only inside the isolated target. No real malware.", 16)
card(s, 6.8, 4.1, 5.9, 2.5, "Data safety", "Synthetic secrets only. All files stay in the project folder.", 16)

# ---------------------------------------------------------------- 10 status and limitations
s = slide("Status and limitations", (
    "Built and tested, but nothing is measured. Last full Windows run: 1028 tests collected, 1009 passed, 19 skipped, about 4 minutes. "
    "Linux once under WSL2: 985 passed, 2 failed, 1 skipped; the 2 failures were fixed but the suite was not re-run. Not tested on native Linux or a KVM host. The tests were written by the same AI as the code. "
    "Limits: one machine and CPU model; kvm-masked is full QEMU/KVM, not a real VMBR; M1 truth is self-written; four classes are Config-proxy. M4 code ran only on simulated data."),
    short="built and tested on Windows and once on WSL2, with no real measurements.")
rows = [["Part", "Built", "Real data"], ["Framework", "yes", "n/a"], ["M1", "yes", "fixtures only"], ["M2", "yes", "none"], ["M3", "yes", "none"], ["M4", "yes", "none"]]
table(s, 0.6, 1.4, 6.2, rows, [2.2, 1.6, 2.4], size=14, row_h=0.45)
bullets(s, 7.2, 1.4, 5.5, 3.0, [
    "One PC:: one CPU model",
    "Not a real VMBR:: kvm-masked is full QEMU/KVM",
    "M1 truth:: self-written fixtures",
    "Config-proxy:: four classes",
], 16)
box(s, 0.6, 4.4, 12.1, 2.3, PALE)
txt(s, 0.8, 4.5, 11.7, 2.1,
    "1028 tests: Windows 1009 passed, 19 skipped (about 4 min). Linux under WSL2 once: 985 passed, 2 failed (fixed), 1 skipped; not re-run. "
    "Not tested on native Linux or a KVM host.", 17)

# ---------------------------------------------------------------- 11 remaining work
s = slide("Remaining work, NOT part of this submission", (
    "Planned work, not done work. E1 is not built, so there are no native-versus-VM, M2-dump or Volatility results. "
    "The eight-week plan is a solo schedule and can be compressed. Before any real data, prereg.md must be committed and tagged. "
    "Lynis and OpenSCAP, two independent configuration scanners, are planned for M1 but never run. "
    "Never cut: plan committed before data, randomised sessions, the masked class, the result matrix, the preflight gate."),
    short="none of this is done; it is the plan for what comes after this submission.")
remaining_banner(s)
rows = [["Week", "Planned work"], ["W1-W2", "Build E1; pilot; commit and tag prereg.md"], ["W3-W5", "Collect 45 boots; M1 and M2 evaluation"],
        ["W6-W7", "Analyse H1 to H4; M3 clean dumps"], ["W8", "Paper, slides, demo video"]]
table(s, 0.6, 2.3, 7.8, rows, [1.5, 6.3], size=14, row_h=0.55)
card(s, 8.7, 2.3, 4.0, 2.75, "Also not done", "Lynis and OpenSCAP (independent config scanners): planned, never run.", 15)

# ---------------------------------------------------------------- 12 closing: AI statement + Q&A
s = slide("How this was made, and questions", (
    "Please state this plainly. " + AI_FULL + " Reviews were by AI agents only, in three waves, with no human review. "
    "If asked whether 84/84 is proof: no, it is self-consistency. Backup slides follow with the finding format, M2, M3, engineering detail, empty results tables and likely questions."),
    short="one student with an AI assistant, no real measurements, analysis plan still a draft.")
box(s, 0.6, 1.4, 12.1, 4.3, PALE)
bullets(s, 0.8, 1.55, 11.7, 4.1, [
    "Who:: one student with an AI assistant (Claude) that produced most code, tests, documents and first drafts",
    "Reviews:: AI agents only; no human review",
    "Tests:: show internal consistency, not correctness",
    "Results:: no real measurements; simulated numbers are not results",
    "Plan:: prereg.md is a draft, not yet committed",
], 18)
txt(s, 0.6, 5.95, 12.1, 0.7, "Thank you. Questions?", 28, True, TEAL)
MAIN_COUNT = n_slides

# ================================================================ BACKUP
# ---------------------------------------------------------------- B1 finding format + matrix
s = slide("Backup: finding format and result matrix", (
    "Every module emits the same JSON finding: id, module, taxonomy class, control, status PASS, FAIL or NA, severity 1 to 4, evidence, fix, env and vm. "
    "For M4, PASS means the detected environment equals the declared one. report.py turns findings into the matrix. "
    "Matrix rule: a class shows PASS only if every control in the class was tested and passed; otherwise PARTIAL (some tested) or NA (none tested); any FAIL gives FAIL. "
    "Counts are never summed across different VMs. The tables are layout only, with no values."))
box(s, 0.6, 1.4, 6.0, 3.3, RGBColor(0x1B, 0x26, 0x30))
code = ('{"id":"C07","module":"M1",\n "taxonomy":"Guest->Host",\n "control":"qemu_not_root",\n'
        ' "status":"PASS|FAIL|NA",\n "severity":1..4,\n "evidence":"...","fix":"...",\n "env":"E0|E1","vm":"weak"}')
txt(s, 0.8, 1.55, 5.6, 3.0, code, 15, False, RGBColor(0xBF, 0xE3, 0xE6))
txt(s, 0.6, 4.85, 6.0, 1.9, "Severity 1 to 4. M4 status: PASS if detected environment equals declared environment. "
    "Counts are never summed across different VMs.", 15)
txt(s, 6.9, 1.35, 5.8, 0.4, "Matrix 1: per threat class (layout only)", 15, True, TEAL)
table(s, 6.9, 1.8, 5.8, [["Threat class", "Label", "Controls", "Tested", "N/A"], ["...", "...", "n", "n", "n"]], [1.9, 1.2, 1.0, 0.9, 0.8], size=14)
txt(s, 6.9, 3.0, 5.8, 0.4, "Matrix 2: per VM (layout only)", 15, True, TEAL)
table(s, 6.9, 3.45, 5.8, [["VM", "Class 1", "Class 2", "..."], ["weak", "status", "...", "..."], ["hardened", "status", "...", "..."], ["real-world", "status", "...", "..."]],
      [1.7, 1.6, 1.3, 1.2], size=14)
txt(s, 6.9, 5.4, 5.8, 1.4, "Class status: PASS only if every control was tested and passed; otherwise PARTIAL (some tested) or NA (none tested). Any FAIL gives FAIL.", 14, False, MUTED)

# ---------------------------------------------------------------- B2 M2
s = slide("Backup: M2 snapshot privacy", (
    "Question: do VM memory snapshots leak secrets. Four synthetic secret types in three memory states give 12 cells, at least 10 dumps per cell planned. "
    "Held-out variants (secrets split across page boundaries, UTF-16, base64) are a separate column, and the scanner rules are written without seeing them. "
    "Ground truth: a secret counts as present only if an exact search of the dump finds the planted bytes. The guest writes its own manifest, which cannot be trusted, so a host-side generator exists. "
    "Negative controls: empty and random high-entropy dumps. Synthetic dumps cannot tell live, freed and exited memory apart; only real VM dumps can. There is no real M2 data."))
bullets(s, 0.6, 1.4, 6.4, 5.4, [
    "12 cells:: 4 secret types x 3 memory states",
    "Held-out variants:: page-split, UTF-16, base64 (rules written blind)",
    "Real programs:: ssh-agent and openssl s_server, throwaway keys",
    "Host-side manifest:: guest-written manifest is not trusted",
    "Negative controls:: empty and high-entropy-padded dumps",
    "Synthetic secrets only:: never real credentials",
], 17)
table(s, 7.3, 1.6, 5.4, [["", "live", "freed", "exited"], ["ssh_key", "cell", "cell", "cell"], ["aws", "cell", "cell", "cell"], ["jwt", "cell", "cell", "cell"], ["hex32", "cell", "cell", "cell"]],
      [1.5, 1.3, 1.3, 1.3], size=14, row_h=0.5)
txt(s, 7.3, 4.3, 5.4, 1.2, "Layout of the 12 cells. No real dumps; synthetic dumps cannot tell the three states apart.", 14, False, MUTED)

# ---------------------------------------------------------------- B3 M3
s = slide("Backup: M3 offline memory forensics", (
    "M3 runs Volatility 3 on virsh dump output, offline. It compares pslist (the kernel's own process list) against psscan (a raw-memory scan for process structures), and lsmod against a scan for kernel modules; an item in the scan but not in the list is 'unlinked'. "
    "The claim is limited to unlinked processes and modules at dump time; it is not live introspection. "
    "Symbols: one pinned guest kernel, symbol file built on the host with pinned sha256; unverified symbols give C30 = NA. Volatility runs in a sandbox script with no network and a memory cap. "
    "Ground truth would be public Linux forensic images with documented hidden processes. Scoring code is tested; Volatility has not run on real dumps and there is no M3 data."))
bullets(s, 0.6, 1.4, 6.5, 5.4, [
    "Compare:: pslist vs psscan, lsmod vs module scan",
    "Symbols:: one pinned kernel, sha256-pinned build, hash required",
    "Sandbox:: Volatility with no network, memory cap, unprivileged",
    "Truth:: public images with documented hidden processes",
    "False positives:: clean dumps under process churn",
    "Limit:: only unlinked processes and modules, only at dump time",
], 17)
card(s, 7.4, 1.5, 5.3, 1.7, "Process view", "pslist: kernel's own list\npsscan: raw memory scan\nin scan, not in list = hidden candidate", 14)
card(s, 7.4, 3.4, 5.3, 1.5, "Module view", "lsmod vs scan for kernel modules", 14)
card(s, 7.4, 5.1, 5.3, 1.6, "Reported as", "Exact counts (k of n) with Clopper-Pearson 95% CIs, plus a failure-case table", 14)

# ---------------------------------------------------------------- B4 engineering
s = slide("Backup: engineering detail", (
    "Be precise and claim no more. Windows: 1028 tests collected, 1009 passed, 19 skipped (symlinks, POSIX permissions, bash and sandbox tests), about 4 minutes. "
    "Linux once under WSL2: 985 passed, 2 failed (since fixed), 1 skipped; not re-run after the fixes. "
    "Reviews: AI agents only, 3 waves, no human review, and the tests were written by the same AI that wrote the code. "
    "bench.c compiled with gcc 13.3 and zig; one functional run in WSL2 (a VM) on 2026-10-04; never native or in a KVM guest. The shell scripts pass bash -n only. "
    "A contract test pins the bench.c CSV columns to the feature loader."))
bullets(s, 0.6, 1.4, 7.3, 5.4, [
    "Tests:: 1028 collected; Windows 1009 passed, 19 skipped",
    "Linux:: WSL2 once: 985 passed, 2 failed (fixed), 1 skipped; not re-run",
    "Reviews:: AI-agent reviews, 3 waves; no human review; tests written by the same AI",
    "bench.c:: gcc 13.3 and zig; one functional run in WSL2 (a VM)",
    "Shell scripts:: bash -n syntax check only",
    "Contract test:: bench.c columns vs feature loader",
], 16)
card(s, 8.2, 1.5, 4.5, 2.4, "Verified", "Python logic and scoring (unit tests), report and CLI on synthetic input.", 15, GREEN_T)
card(s, 8.2, 4.1, 4.5, 2.6, "NOT verified", "Native Linux, a KVM host, Volatility, libvirt, any real measurement.", 15, PINK)

# ---------------------------------------------------------------- B5 results tables (empty)
s = slide("Backup: results tables (empty by design)", (
    "These tables are intentionally empty. No real measurement exists, and nothing from the simulated runs is shown. Simulated numbers must never be copied here. "
    "The only entry with a number is M1 on its own fixtures, which is self-consistency. "
    "Left: the M4 H1 to H4 table with the thresholds from the draft analysis plan. Right: module evaluation tables with ground truth, metric and interval columns."))
remaining_banner(s)
rows = [["M4", "Result", "Threshold"], ["H1 (AUROC)", "not done", "p < 0.05"], ["H2 (FPR)", "not done", "CI excl. 0, Holm"],
        ["H3 (AUROC drop)", "not done", "< 0.05, Holm"], ["H4 (cost)", "not done", "< 10 s, < 5%"]]
table(s, 0.6, 2.3, 6.0, rows, [2.2, 1.5, 2.3], size=14, row_h=0.5)
rows = [["Module", "Ground truth", "Result"], ["M1 fixtures", "50 fixtures", "84/84 (self-check)"], ["M1 real", "~10 configs", "none"],
        ["M2", "12 cells", "none"], ["M3", "public images", "none"]]
table(s, 6.9, 2.3, 5.8, rows, [1.6, 1.8, 2.4], size=14, row_h=0.5)
txt(s, 0.6, 5.1, 12.1, 1.0, "Also not done: indicator-leak table, F1-vs-measurement-time curve, per-VM result matrix.", 16, False, MUTED)

# ---------------------------------------------------------------- B6 likely questions
s = slide("Backup: likely questions", (
    "Why is 84/84 not proof: the checker's author wrote the fixtures and the same AI wrote the tests; independent evidence needs Lynis, OpenSCAP and real configurations. "
    "Why E1 and not the laptop: Windows already runs on Hyper-V, so the laptop has no bare-metal setup. If E1 is impossible, M4 would compare 1 against 2 virtualization layers and the claim would be renamed. "
    "Why might H1 be untestable: timing alone may reach AUROC near 1.0, and then the ceiling rule reports untestable. "
    "Is kvm-masked a real stealth hypervisor: no. Does PASS mean secure: no. Where is the data: nothing real yet."))
bullets(s, 0.6, 1.4, 7.0, 5.4, [
    "Is 84/84 proof?:: no, self-consistency: the checker's author wrote the fixtures, tests by the same AI",
    "Why E1?:: the laptop's Windows already runs on Hyper-V",
    "If no E1?:: M4 compares 1 vs 2 virtualization layers (WSL)",
    "H1 untestable?:: ceiling rule: timing alone near AUROC 1.0",
    "Is kvm-masked a VMBR?:: no, a non-adaptive stand-in",
    "Where are the numbers?:: none yet; E1 not built",
], 16)
card(s, 7.9, 1.5, 4.8, 3.0, "Files", "FINAL_PROJECT_PLAN.md\nREADME.md\nprereg.md (draft)\ndocs/YOUR_TASKS.md\nvsec/taxonomy.yaml", 15)
txt(s, 7.9, 4.8, 4.8, 1.6, AI_SHORT, 14, False, MUTED)

# ---------------------------------------------------------------- file metadata and save
cp = prs.core_properties
now = datetime.now()
cp.author = cp.last_modified_by = STUDENT
cp.title = "vsec: taxonomy-driven security assessment for KVM virtualization"
cp.subject = "University talk, about 10 minutes"
cp.created = cp.modified = cp.last_printed = now
prs.save(OUT)
print(f"wrote {OUT} ({n_slides} slides: {MAIN_COUNT} main + {n_slides - MAIN_COUNT} backup)")
for placeholder, name in ((STUDENT, "STUDENT"), (COURSE_LINE, "COURSE_LINE")):
    if placeholder.startswith("["):
        print("=" * 78)
        print(f"WARNING: {name} is still the placeholder {placeholder!r}. Set it in build_deck.py and rebuild before presenting.")
        print("=" * 78)
