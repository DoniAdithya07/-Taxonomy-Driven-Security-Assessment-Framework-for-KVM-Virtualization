# M4 Pre-Registration (SOLO, DRAFT: commit before any W3 data is collected)

**This is a DRAFT analysis plan by one student (with an AI assistant). It is NOT yet a pre-registration: it has no commit or tag, and the project folder is not a git repository yet.** You fill the `PILOT` values from the W1 pilot (pilot data only), then commit **before collecting any real data**. After the commit, nothing below changes without a dated amendment at the end of this file.

**Date committed:** (to be filled on W2)
**Researcher:** (your name/email)
**Window size (PILOT, in ms):** (to be filled from Task C; bench window_ms parameter, e.g., 100)
**n_windows (PILOT):** (to be filled from Task C; number of measurement windows per session, e.g., 300)
**T_short (PILOT, seconds):** (to be filled from Task D: output of `python -m vsec pilot --data data/m4/pilot`)
**bench window_ms:** ___
**n_windows:** ___
**ISF sha256:** ___ (ISF = integrated symbol file from `scripts/build_symbols.sh`, filled in Task G)

## Question
Against a non-adaptive hypervisor that hides its static indicators (`kvm-masked`), does combining several
behaviour signals detect it faster or more reliably than the best single behaviour signal?

## Design
- Classes: `native`, `kvm-plain`, `kvm-masked`, all on E1 (one CPU model). Same disk image, kernel, services.
- Fixed frequency (`performance`, turbo off), vCPUs pinned, same clock source in all classes (`clocksource=tsc`).
  Same CPU count, SMT setting and online CPUs for native and VM. Any class that cannot use these is reported as a confound.
  Per-session gate: a session whose recorded `clocksource` is not `tsc` is listed; the analysis reports a sensitivity run without such sessions.
- Unit of analysis: one boot session. 15 sessions per class (45 boots). Each boot runs idle, cpu, mem, mixed in a
  random order per session (carry-over between workloads is a stated limitation). A thermal reading is taken before and after each workload.
- Session order: **blocked randomisation**. Every day/batch contains all three classes in random order (`scripts/plan_sessions.py`, seed 2025), spread over days. `day` and `batch` are logged in `meta.json`.
- **Measurement seconds are real.** bench.c writes the real wall time of each window (`elapsed_ms`). A (session, workload) row at measurement time T uses the first k windows whose cumulative `elapsed_ms` reaches T seconds. Rows with less data are excluded and counted.
- **Window rule (pre-specified).** `T_short` = the shortest T on the grid (0.1, 0.2, 0.5, 1, 2, 5, 10 s) at which the best single signal's session AUROC is **below 0.90**, computed on **pilot data only** (`classify.choose_t_short`). `PILOT` window size: `PILOT` ms.
- **Ceiling rule.** If the best single signal has AUROC >= 0.99 at every T on the grid, H1 is reported as **status "untestable"** (supported = none), not as a failed hypothesis.
- Signals in H1: timing (cpuid_tsc, rdtsc_tsc, syscall, page fault), memory (seq, stride, random, tlb ratio, which is derived from stride/seq and is not an independent signal), performance counters (if exposed), scheduler jitter. System indicators are NOT features; they go in the indicator-leak table.
- Performance counters: whether they are exposed is reported per class as a descriptive finding (it can itself separate classes). Columns that are NaN in any row are dropped from the models and listed (`signals_dropped`).
- Feature for one (session, workload) at time T: median over the first T seconds of windows of the natural log of each signal (a value <= 0 makes the signal NaN, never -inf).
  Secondary aggregation (primary pair only, reported separately): median plus MAD (median absolute deviation of the log values).
- One decision per session: mean classifier score over its workload rows. Positive class = the virtualised class of the pair. The single-workload decision (one workload's windows only) is reported next to it.

## Analysis
- Grouped CV by session: 5 outer folds, stratified, **repeated with 3 seeds; row scores are averaged over repeats before any test**. The best single signal, the logistic C and the Youden threshold are chosen by inner grouped CV (3 folds) on training sessions only. Per outer fold the chosen signal and C are recorded and counts are reported.
- Like-for-like: logistic regression (primary family) vs logistic regression; random forest vs random forest (secondary).
- Search budget: also reported, the best single signal with C fixed (1.0) and with C fixed to the combined arm's most often chosen C.
- Baselines: best single signal, a CPUID-threshold rule, and the combined model.
- Uncertainty: **paired session-level bootstrap** (2000 resamples, the same resampled sessions for both models, stratified by class). CIs and p-values are conditional on the CV scores: variability of the model selection is not resampled.
- Pre-registered tail: **one-sided** for H1 and for the secondary combined-vs-single tests (combined better); H2 uses the one-sided bootstrap p plus a two-sided 95% CI; H3 is one-sided non-inferiority.
- Metrics: session AUROC is primary. F1 at the fixed threshold 0.5 is secondary (a calibration artefact: logistic scores of 1-feature and 10-feature models differ in scale). F1 at a threshold chosen inside the training folds (Youden on inner out-of-fold scores) is also reported.
- Sensitivity analyses (reported, not in the Holm family): (a) **behaviour-only**: `cpuid_tsc` excluded, primary pair, next to H1; (b) median+MAD aggregation; (c) **leave-one-day-out** CV grouped by day (needs >= 3 days, otherwise status NA with the reason); (d) without sessions failing the clocksource gate.
- Balance: standardized mean differences between classes for temperature, hour, session order index and minutes since boot (if recorded); |SMD| > 0.5 is flagged.

## Hypotheses (falsifiable, thresholds fixed now)
| | Statement | Supported if |
|---|---|---|
| **H1 (primary, only one)** | On native vs kvm-masked, combined beats best single signal (logistic family) | Session-level AUROC at `T_short` is higher for combined AND the one-sided paired session bootstrap p < 0.05 (p = share of bootstrap differences <= 0). A tie is "not supported". If the ceiling rule applies: "untestable". Also reported: smallest T with session AUROC >= 0.95, per T the single and combined AUROC. |
| H2 | Combining lowers false alarms on native (estimation) | FPR at **TPR >= 0.90** (with 15 positives 0.95 would mean 15/15; 0.90 allows one miss): the 95% bootstrap CI of (single - combined) excludes 0 in favour of combined AND Holm-adjusted p < 0.05 |
| H3 | Robust to unseen workloads (non-inferiority) | One decision per session: mean score over the session's rows, in-distribution out-of-fold vs leave-one-workload-out out-of-fold (every workload held out in turn). Drop = F1(in) - F1(held) at 0.5; upper 95% session-bootstrap bound of the drop < **0.05** AND Holm-adjusted p < 0.05. A 0.05 margin is only reachable near the ceiling. |
| H4 | Practical cost | **One criterion:** cost of one session decision at T95 < **10 s** AND amortised CPU overhead < **5%**. T95 = the smallest T with combined session AUROC >= 0.95. Cost = sum over all workloads used of (1.0 s warm-up + 0.5 s load start + real measured seconds), about 4 x (T + 1.5) s. Overhead = 100 * cost / 300 (a detector run every 300 s), so the 10 s limit is the binding one (3.3%). Both numbers are reported, with a bootstrap CI for T95 over sessions. |

Holm family: H2, H3 and the combined-vs-single tests of the two secondary pairs (native vs kvm-plain, kvm-plain vs kvm-masked) at `T_short`. H1 is the single primary endpoint outside the family. `supported` for H2/H3 = raw criterion AND Holm-adjusted p < 0.05; a test that cannot run is reported as `supported = none`, never false.
If timing alone wins H1, that is reported as the answer.

## Power and limits
- With 15 vs 15 sessions and AUROC about 0.8, the AUROC standard error is about 0.08; the minimum detectable AUROC difference between two models is roughly 0.15 to 0.2. p-values and CIs from 15 sessions per class are low-power: **a null result is not evidence of no difference.** H2 and H3 are therefore read as estimates with CIs when underpowered.
- If the analysis cannot run (a class of the primary pair has fewer than 5 sessions, or an AUROC is NaN) the result is `status NA` with the reason; nothing is reported as failed.
- One CPU model, one machine, a non-adaptive hypervisor; workload carry-over within a session is not removed.

## Comparisons
native vs kvm-plain (sanity), **native vs kvm-masked (primary)**, kvm-plain vs kvm-masked (secondary).
Also reported: indicator-leak table, AUROC/F1-vs-measurement-time curve (with the number of sessions at each point; points whose session set differs are flagged), session balance check, confound table (clocksource, governor, kernel, cmdline, no_turbo per class).

## Out of scope
A hypervisor that fakes time (TSC offsetting, VM-exit latency masking); other CPU models; proving that a VMBR exists.

## Draft History
Pre-commit revisions (before first commit; not time-stamped; dated 2026-10-03):
1. **H4 redefined.** Old text used an invented 60 s re-check interval. Now: one criterion, cost < 10 s AND overhead < 5% with overhead = 100 * seconds / 300, so the 10 s limit binds (3.3%); both numbers reported.
2. **H2 operating point** changed from TPR 0.95 to TPR >= 0.90 (15 positives: 0.95 means 15/15). Low-power statement added.
3. **Holm applied** to H2, H3 and the two secondary combined-vs-single tests; `supported` = raw criterion AND adjusted p < 0.05.
4. **H3 at session level** (one decision per session, in-distribution vs leave-one-workload-out).
5. **Window rule, ceiling rule ("untestable") and behaviour-only analysis** added for H1.
6. **Test replaced:** the paired permutation test of raw scores (scale dependent) is replaced by a paired session-level bootstrap, one-sided for H1.
7. **Time-to-detect** is now the smallest T with session AUROC >= 0.95 (F1 at 0.5 is secondary; Youden-threshold F1 added); real elapsed seconds replace window counts; decision cost includes warm-up and load start; bootstrap CI for T95.
8. **Confounding:** day/batch logged, blocked randomisation, leave-one-day-out sensitivity, clocksource gate, SMD balance check replaces Kruskal-Wallis.
9. **Repeated grouped CV** (3 seeds), selection counts, fixed-C single arms, natural-log features, MAD secondary aggregation, performance-counter exposure reported per class.

Post-collection revisions (after W8 analysis):
(To be filled if any amendments are made after real data collection starts; each must be dated.)
