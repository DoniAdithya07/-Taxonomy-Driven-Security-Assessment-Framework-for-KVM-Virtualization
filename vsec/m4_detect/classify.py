"""M4 classification and the pre-registered analysis (see prereg.md).

Everything that is tuned (the best single signal, the logistic C, the Youden threshold) is chosen inside nested
CV on the training sessions only. CV is grouped by boot session and repeated with several seeds; row scores are
averaged over repeats before any test. Positive class = the second class of a pair.

All CIs and p-values are conditional on those CV scores: the variability of the model selection itself is not
resampled (see `ci_note` in the result).
"""
import warnings
from collections import Counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import features as F
from . import stats as S

PRIMARY_FAMILY = "logreg"
PRIMARY_PAIR = ("native", "kvm-masked")
PAIRS = (("native", "kvm-plain"), PRIMARY_PAIR, ("kvm-plain", "kvm-masked"))
GRID = {"logreg": [0.1, 1.0, 10.0], "rf": [None]}
MODES = ("single", "combined", "rule")
TS = (0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0)  # measurement seconds per workload for the AUROC/F1-vs-time curve
REPEATS = 3               # grouped-CV repeats (different fold seeds); row scores are averaged
MIN_SESSIONS = 5          # per class of the primary pair, else the analysis is NA
TPR_TARGET = 0.90         # H2 operating point (with 15 positives 0.95 would mean 15/15)
AUROC_TARGET = 0.95       # time-to-detect: smallest T whose session AUROC reaches this
T_SHORT_AUROC = 0.90      # window rule: T_short = shortest T whose best-single AUROC (pilot data) is below this
CEILING_AUROC = 0.99      # H1 is 'untestable' if best-single AUROC >= this at every T on the grid
# H4 cost model. Cost of one session decision = sum over the workloads used of
#   (WARMUP_S + LOAD_START_S + real measured seconds of that workload).
WARMUP_S = 1.0            # assumed bench start-up / warm-up per workload run
LOAD_START_S = 0.5        # assumed time to start the workload's load
H4_SECONDS = 10.0         # H4: decision cost must be below this ...
H4_CPU_PCT = 5.0          # ... and amortised CPU overhead below this
H4_INTERVAL_S = 300.0     # a detector run every 300 s: overhead % = 100 * seconds / 300 (10 s -> 3.3%)
ALPHA = 0.05
EXPECTED_PER_CLASS = 15   # sessions per class of the primary pair for a citable (non-EXPLORATORY) result
H1_NESTED_NOTE = ("the nested single arm pays a selection cost (the signal is chosen inside the CV on training "
                  "sessions only); best_single_non_nested does not, so it is optimistic")
CI_NOTE = ("CIs and p-values are conditional on the repeated-CV session scores; variability of the model "
           "selection (best single signal, C, threshold) is not resampled.")


MAX_DROPPED_FRAC = 0.20   # a bootstrap with more NaN replicates than this gives no CI / p-value


class Insufficient(ValueError):
    """The data cannot support this analysis (too few sessions in a class, no usable signal, no inner-CV fit,
    too few days...): an EXPECTED data shortage, reported as NA. .counts = per-class session counts (or None),
    .min_sessions = the per-class minimum that applied. Any other ValueError is a bug and propagates."""

    def __init__(self, msg, counts=None, min_sessions=None):
        super().__init__(msg)
        self.counts = counts
        self.min_sessions = MIN_SESSIONS if min_sessions is None else min_sessions


def make(fam, p):
    if fam == "logreg":
        return make_pipeline(StandardScaler(), LogisticRegression(C=p, max_iter=2000))
    return RandomForestClassifier(60, min_samples_leaf=2, random_state=0)


def impute(Xtr, Xte):
    """Fill NaN (a row may lack a kept signal, see features.MAX_NAN_FRAC) with the TRAINING fold's column median
    (0 for a column that is all NaN there). Same fill for train and test, so nothing leaks from the test fold."""
    if not (np.isnan(Xtr).any() or np.isnan(Xte).any()):
        return Xtr, Xte
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        med = np.nanmedian(Xtr, axis=0)
    med = np.where(np.isnan(med), 0.0, med)
    return np.where(np.isnan(Xtr), med, Xtr), np.where(np.isnan(Xte), med, Xte)


def fit_score(fam, p, cols, Xtr, ytr, Xte):
    a, b = impute(Xtr[:, cols], Xte[:, cols])
    return make(fam, p).fit(a, ytr).predict_proba(b)[:, 1]


def folds(y, g, k, seed):
    k = max(2, min(k, len(set(g))))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return list(StratifiedGroupKFold(k, shuffle=True, random_state=seed).split(np.zeros(len(y)), y, g))


def _grid(fam, fixed_C):
    return [fixed_C] if fixed_C is not None and fam == "logreg" else GRID[fam]


def inner_pick_ex(fam, X, y, g, candidates, seed, fixed_C=None):
    """Choose (columns, hyperparameter) by inner grouped CV: best AUROC, ties broken by log-loss.
    Returns (cols, p, inner out-of-fold scores of the winner). Raises ValueError if no candidate could be
    scored (never silently picks the first column)."""
    best, pick = None, None
    for cols in candidates:
        for p in _grid(fam, fixed_C):
            oof = np.full(len(y), np.nan)
            for tr, te in folds(y, g, 3, seed):
                if len(set(y[tr])) == 2:
                    oof[te] = fit_score(fam, p, cols, X[tr], y[tr], X[te])
            ok = ~np.isnan(oof)
            if ok.sum() == 0 or len(set(y[ok])) < 2:
                continue
            score = (S.auroc(y[ok], oof[ok]), -log_loss(y[ok], np.clip(oof[ok], 1e-6, 1 - 1e-6), labels=[0, 1]))
            if best is None or score > best:
                best, pick = score, (cols, p, oof)
    if pick is None:
        raise Insufficient("inner CV failed for every candidate (too few sessions, or one class in each fold)")
    return pick


def rule_score(X, y, tr, te):
    """Baseline rule: CPUID cost above the midpoint of the two training class medians."""
    j = F.SIGNALS.index("cpuid_tsc")
    m0, m1 = np.nanmedian(X[tr][y[tr] == 0, j]), np.nanmedian(X[tr][y[tr] == 1, j])
    scale = max(np.nanstd(X[tr, j]), 1e-9)
    return 1 / (1 + np.exp(-np.clip((X[te, j] - (m0 + m1) / 2) * np.sign(m1 - m0) / scale * 4, -30, 30)))


def oof_scores(X, y, g, w, fam, mode, seed=0, lowo=None, outer_k=5, exclude_idx=(), fixed_C=None, aux=None,
               columns=None):
    """Out-of-fold row scores. mode: single | combined | rule. lowo: train without, test only on, a workload.
    g is the CV grouping (session, or day). exclude_idx: feature columns never used. fixed_C: no tuning of C.
    columns: the feature set fixed for the whole analysis (column indices); default = the columns without any NaN.
    aux (a dict) receives "thr" (per row, the Youden threshold chosen on the training folds' inner scores)
    and "sel" (per outer fold: (columns, C) chosen)."""
    cols = [j for j in (F.usable_columns(X) if columns is None else columns) if j not in set(exclude_idx)]
    if not cols:
        raise Insufficient("no usable signal columns: every signal is too often NaN (or excluded)")
    if mode == "rule" and F.SIGNALS.index("cpuid_tsc") not in cols:
        raise Insufficient("rule baseline needs cpuid_tsc, which is NaN in some rows or excluded")
    cands = [[j] for j in cols] if mode == "single" else [cols]
    oof = np.full(len(y), np.nan)
    thr = np.full(len(y), np.nan)
    sel, fallbacks = [], 0
    for tr, te in folds(y, g, outer_k, seed):
        if lowo:
            tr, te = tr[w[tr] != lowo], te[w[te] == lowo]
        if len(te) == 0 or len(set(y[tr])) < 2:
            continue
        if mode == "rule":
            oof[te] = rule_score(X, y, tr, te)
            continue
        c, p, inner = inner_pick_ex(fam, X[tr], y[tr], g[tr], cands, seed, fixed_C)
        ok = ~np.isnan(inner)
        thr[te], fell_back = S.youden_threshold_ex(y[tr][ok], inner[ok])
        fallbacks += fell_back
        sel.append((c, p))
        oof[te] = fit_score(fam, p, c, X[tr], y[tr], X[te])
    if aux is not None:
        aux["thr"], aux["sel"], aux["youden_fallbacks"] = thr, sel, fallbacks
    return oof


def _avg_ex(arrs):
    """(mean over repeats ignoring NaN, number of rows scored in some but not all repeats)."""
    a = np.vstack(arrs)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        mean = np.nanmean(a, axis=0)
    n = (~np.isnan(a)).sum(axis=0)
    return mean, int(((n > 0) & (n < len(arrs))).sum())


def _avg(arrs):
    return _avg_ex(arrs)[0]


def session_level(oof, y, g):
    """One decision per boot session: mean score over its rows. Returns (ids as str, y, score)."""
    ids = sorted(str(i) for i in set(g[~np.isnan(oof)]))
    ys = np.array([y[g == i][0] for i in ids])
    ss = session_mean(oof, g, ids)
    return ids, ys, ss


def session_mean(vec, g, ids):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return np.array([np.nanmean(vec[g == i]) for i in ids])


def _startup_s(sessions, g, w):
    """(startup seconds per table row, source). Measured = meta bench_startup_ms[workload] (process start to the
    first timed window: allocation, shuffle, load start, warm-up); a row without it uses the assumed
    WARMUP_S + LOAD_START_S and makes the source 'assumed'."""
    meta = {s["session"]: s.get("bench_startup_ms") for s in sessions}
    out, measured = [], True
    for sid, wl in zip(g, w):
        m = meta.get(str(sid))
        ms = m.get(wl) if isinstance(m, dict) else None
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and np.isfinite(ms) and ms > 0:
            out.append(ms / 1000.0)
        else:
            out.append(WARMUP_S + LOAD_START_S)
            measured = False
    return np.array(out), "measured" if measured and len(out) else "assumed"


def _per_class(vals, y, pair, fn=np.median):
    return {c: float(fn(vals[y == k])) if (y == k).any() else None for k, c in enumerate(pair)}


def evaluate_at(sessions, pair, seconds, fam, seed=0, repeats=REPEATS, modes=MODES, exclude=(), agg="median",
                cv="session", fixed_C=None, min_sessions=None, columns=None):
    """Session-level results at one measurement time (`seconds` of real time per workload).

    `columns` = the feature names fixed for the whole analysis (features.fixed_columns); None = fixed from this T
    alone. Per mode: ids, y, score (mean of the session's workload rows), auroc (primary), f1 at 0.5, f1_youden
    (threshold chosen inside the training folds), bal_acc, n per class (secondary), and by_workload (the decision from ONE workload's windows only, for
    single/combined). All modes are restricted to the same sessions. cv="day": leave-one-day-out (needs >= 3 days).
    Raises Insufficient (a ValueError) if a class has < min_sessions (default MIN_SESSIONS) sessions with data at
    this time, or fewer than that many still have an out-of-fold score after the CV.
    info also has youden_fallbacks (Youden threshold replaced by 0.5: folds + sessions) and rows_partially_scored
    (rows that got a score in some but not all repeats).
    """
    min_sessions = MIN_SESSIONS if min_sessions is None else min_sessions
    X, y, g, w, excluded, used, k_used = F.table_full(sessions, seconds, pair, agg)
    counts = {c: len({str(i) for i in g[y == k]}) for k, c in enumerate(pair)}
    if min(counts.values()) < min_sessions:
        raise Insufficient(f"fewer than {min_sessions} sessions with {seconds} s of data in a class: {counts}",
                           counts, min_sessions)
    names = F.feature_names(agg)
    excl = [names.index(n) for n in exclude if n in names]
    if columns is None:
        columns = F.fixed_columns(sessions, pair, (seconds,), agg)["names"]
    col_idx = [names.index(n) for n in columns if n in names]
    cvg, outer_k = g, 5
    if cv == "day":
        day_of = {s["session"]: s.get("day") for s in sessions}
        days = [day_of.get(i) for i in g]
        if any(d is None for d in days) or len(set(days)) < 3:
            raise Insufficient("leave-one-day-out needs >= 3 days with a recorded day; found %s"
                               % sorted({str(d) for d in days}), None, min_sessions)
        cvg, outer_k = np.array(days), len(set(days))
    sel = {"single_signals": Counter(), "single_C": Counter(), "combined_C": Counter()}
    rows, thrs = {}, {}
    fallbacks = partial = 0
    for m in modes:
        rr, tt = [], []
        for r in range(repeats):
            aux = {}
            rr.append(oof_scores(X, y, cvg, w, fam, m, seed + r, outer_k=outer_k, exclude_idx=excl,
                                 fixed_C=fixed_C if m == "single" else None, aux=aux, columns=col_idx))
            tt.append(aux.get("thr", np.full(len(y), np.nan)))
            fallbacks += aux.get("youden_fallbacks", 0)
            for c, p in aux.get("sel", []):
                if m == "single":
                    sel["single_signals"][names[c[0]]] += 1
                    sel["single_C"][str(p)] += 1
                elif m == "combined":
                    sel["combined_C"][str(p)] += 1
        (rows[m], n_part), thrs[m] = _avg_ex(rr), _avg(tt)
        partial += n_part
    lv = {m: session_level(rows[m], y, g) for m in modes}
    common = set.intersection(*(set(v[0]) for v in lv.values()))
    out = {}
    for m, (ids, ys, ss) in lv.items():
        keep = [i for i, sid in enumerate(ids) if sid in common]
        ids, ys, ss = [ids[i] for i in keep], ys[keep], ss[keep]
        thr = np.full(len(ids), 0.5) if m == "rule" else session_mean(thrs[m], g, ids)
        if m != "rule":
            fallbacks += int(np.isnan(thr).sum())
        thr = np.where(np.isnan(thr), 0.5, thr)
        out[m] = {"ids": ids, "y": ys, "score": ss, "auroc": S.auroc(ys, ss), "f1": S.f1(ys, ss),
                  "f1_youden": S.f1(ys, ss, thr), "bal_acc": S.bal_acc(ys, ss),
                  "n": {c: int((ys == k).sum()) for k, c in enumerate(pair)}}
        if m != "rule":
            out[m]["by_workload"] = {}
            for wl in F.WORKLOADS:
                i_w, y_w, s_w = session_level(np.where(w == wl, rows[m], np.nan), y, g)
                k_ = [k for k, i in enumerate(i_w) if i in common]
                if k_:
                    out[m]["by_workload"][wl] = {"n_sessions": len(k_), "auroc": S.auroc(y_w[k_], s_w[k_]),
                                                 "f1": S.f1(y_w[k_], s_w[k_])}
    ref = "combined" if "combined" in modes else modes[0]
    scored = set(out[ref]["ids"])
    declared = {s["session"]: s["cls"] for s in sessions if s["cls"] in pair}
    n_scored = {c: sum(declared[i] == c for i in scored) for c in pair}
    if min(n_scored.values()) < min_sessions:
        raise Insufficient(f"fewer than {min_sessions} sessions with an out-of-fold score in a class: {n_scored}",
                           n_scored, min_sessions)
    in_rows = np.isin(g, list(scored))
    startup, startup_source = _startup_s(sessions, g, w)
    per_row = used + startup
    used_cols = [j for j in col_idx if j not in set(excl)]
    in_table = {str(i) for i in g}
    out["info"] = {
        "n_sessions": n_scored, "youden_fallbacks": fallbacks, "rows_partially_scored": partial,
        "dropped_sessions": {i: ("not enough data at this time" if i not in in_table else "no out-of-fold score")
                             for i in declared if i not in scored},
        "excluded_rows": excluded,
        "signals_used": [names[j] for j in used_cols],
        "signals_dropped": [n for j, n in enumerate(names) if j not in used_cols],
        "selection": {k: dict(v) for k, v in sel.items()},
        "nan_fraction": {c: {n: float(np.isnan(X[y == k, j]).mean()) for j, n in enumerate(names)}
                         for k, c in enumerate(pair) if (y == k).any()},
        "used_seconds": _per_class(used, y, pair), "windows_used": _per_class(k_used, y, pair),
        "startup_source": startup_source,
        "cost_s": float(np.mean([per_row[g == i].sum() for i in scored])) if scored else float("nan"),
        "cost_single_workload_s": float(per_row[in_rows].mean()) if in_rows.any() else float("nan"),
        "repeats": repeats, "cv": cv, "agg": agg,
    }
    return out


def extra_arms(r, sessions, pair, seconds, fam, seed=0, repeats=REPEATS, columns=None):
    """Search-budget check: the best single signal with C fixed (1.0) and with C fixed to the combined arm's
    most often chosen C, so the single arm does not out-tune (or under-tune) the combined arm."""
    mc = r["info"]["selection"]["combined_C"]
    if fam != "logreg" or not mc:
        return _na("C is only tuned for logreg")
    c_match = float(max(mc, key=mc.get))
    out = {"combined_auroc": r["combined"]["auroc"], "matched_C": c_match,
           "note": "tlb_ratio is derived from stride_ns / seq_ns, so it is not an independent signal"}
    for name, c in (("single_C_fixed_1", 1.0), ("single_C_matched_to_combined", c_match)):
        try:
            x = evaluate_at(sessions, pair, seconds, fam, seed, repeats, modes=("single",), fixed_C=c,
                            columns=columns)
            out[name] = {"C": c, "auroc": x["single"]["auroc"], "f1": x["single"]["f1"]}
        except Insufficient as e:
            out[name] = _na(str(e))
    return out


def signal_arms(sessions, pair, seconds, fam, seed=0, repeats=REPEATS, columns=None, min_sessions=None):
    """Per-signal session AUROC of every kept signal ALONE (one fixed column, C still tuned by inner CV).
    Reports the pre-named arm `cpuid_tsc` and the NON-nested best single signal. The best is picked on the same
    scores it is reported on, so it is an optimistic bound; the nested single arm of H1 pays the selection cost.
    Raises Insufficient when a class has too few sessions at this time."""
    min_sessions = MIN_SESSIONS if min_sessions is None else min_sessions
    X, y, g, w = F.table(sessions, seconds, pair)
    counts = {c: len({str(i) for i in g[y == k]}) for k, c in enumerate(pair)}
    if min(counts.values()) < min_sessions:
        raise Insufficient(f"fewer than {min_sessions} sessions with {seconds} s of data in a class: {counts}",
                           counts, min_sessions)
    names = F.feature_names()
    if columns is None:
        columns = F.fixed_columns(sessions, pair, (seconds,))["names"]
    aur = {}
    for n in columns:
        try:
            oof = _avg([oof_scores(X, y, g, w, fam, "single", seed + r, columns=[names.index(n)])
                        for r in range(repeats)])
            aur[n] = S.auroc(*session_level(oof, y, g)[1:])
        except Insufficient:
            aur[n] = float("nan")
    ok = {n: v for n, v in aur.items() if not np.isnan(v)}
    best = max(ok, key=ok.get) if ok else None
    return {"per_signal_auroc": aur, "cpuid_tsc": {"auroc": aur.get("cpuid_tsc")},
            "best_single_non_nested": {"signal": best, "auroc": ok.get(best)},
            "note": "best_single_non_nested is chosen on the scores it is reported on: an optimistic bound. "
                    "cpuid_tsc is the pre-named single arm; H1's nested single arm pays a selection cost."}


def time_to_metric(ts, vals, target):
    """First measurement time whose metric >= target (NaN never qualifies); None if never reached."""
    ok = [t for t, v in zip(ts, vals) if v >= target]
    return min(ok) if ok else None


def choose_t_short(pilot_sessions, ts=TS, fam=PRIMARY_FAMILY, seed=0, repeats=1, min_sessions=None):
    """Window rule (pre-registered): T_short = the shortest T on the grid whose best-single-signal session
    AUROC is below T_SHORT_AUROC. Use PILOT DATA ONLY, never the 45 study boots.

    The grid is in real seconds and collapsed: a T whose windows are exactly those of an earlier T is not
    evaluated again (`duplicate_of` {T: earlier T}); `single_auroc` / the rules below work on the kept points.
    One feature set (features.fixed_columns on the longest T) serves every T.

    Returns {"t_short", "single_auroc" {T: auroc or NaN}, "errors" {T: why it could not be evaluated},
    "ceiling": bool, "reason", "duplicate_of"}. t_short is None (with a reason) when: any T could not be evaluated (or gave a
    NaN AUROC); the best single AUROC at the longest T is below T_SHORT_AUROC (no signal: bad data); no T on
    the grid is below T_SHORT_AUROC (the ceiling claim 'H1 will be untestable' is only made when every T was
    measured and is >= CEILING_AUROC); or the AUROC at the chosen T is below 0.5 (suspicious data)."""
    aur, errors = {}, {}
    grid = F.collapse_grid(pilot_sessions, PRIMARY_PAIR, ts)
    dup = {q["t"]: q["duplicate_of"] for q in grid if q["duplicate_of"] is not None}
    ts = [q["t"] for q in grid if q["duplicate_of"] is None]
    columns = F.fixed_columns(pilot_sessions, PRIMARY_PAIR, ts + list(dup))["names"]
    for t in ts:
        try:
            aur[t] = evaluate_at(pilot_sessions, PRIMARY_PAIR, t, fam, seed, repeats, modes=("single",),
                                 min_sessions=min_sessions, columns=columns)["single"]["auroc"]
        except ValueError as e:
            aur[t] = float("nan")
            errors[t] = ("insufficient data: " if isinstance(e, Insufficient) else "error: ") + str(e)
        if np.isnan(aur[t]):
            errors.setdefault(t, "AUROC is NaN (a class has no scored session)")
    res = {"t_short": None, "single_auroc": aur, "errors": errors, "ceiling": False, "reason": None,
           "duplicate_of": dup}
    if errors:
        res["reason"] = "could not evaluate at T=%s: %s" % (", ".join(str(t) for t in errors),
                                                          "; ".join(dict.fromkeys(errors.values())))
        return res
    if aur[max(ts)] < T_SHORT_AUROC:
        res["reason"] = ("no signal reaches AUROC %.2f even at the longest T: pilot cannot pick T_short "
                         "(check data quality)" % T_SHORT_AUROC)
        return res
    ok = [t for t in ts if aur[t] < T_SHORT_AUROC]
    if not ok:
        res["ceiling"] = all(v >= CEILING_AUROC for v in aur.values())
        res["reason"] = ("best single signal reaches AUROC >= %.2f at every T: H1 will be untestable" % CEILING_AUROC
                         if res["ceiling"] else
                         "best single signal reaches AUROC >= %.2f at every T (below the %.2f ceiling at some T): "
                         "no T_short below the threshold" % (T_SHORT_AUROC, CEILING_AUROC))
        return res
    t_short = min(ok)
    if aur[t_short] < 0.5:
        res["reason"] = ("best single AUROC at the shortest candidate T=%s is %.2f, below 0.5: data suspicious "
                         "(labels swapped or noise), no T_short chosen" % (t_short, aur[t_short]))
        return res
    res["t_short"] = t_short
    return res


def h4_decision(seconds, curve_complete=True):
    """H4 numbers and verdict. `seconds` = cost of one session decision at the smallest T reaching AUROC 0.95.
    overhead % = 100 * seconds / 300; supported iff seconds < 10 AND overhead < 5% (the 10 s limit binds: 3.3%).
    seconds None = AUROC 0.95 never reached: not supported if every curve point was computed, else unknown."""
    if seconds is None:
        return {"seconds": None, "cpu_percent": None, "interval_s": H4_INTERVAL_S,
                "supported": False if curve_complete else None}
    cpu = 100.0 * seconds / H4_INTERVAL_S
    return {"seconds": seconds, "cpu_percent": cpu, "interval_s": H4_INTERVAL_S,
            "supported": bool(seconds < H4_SECONDS and cpu < H4_CPU_PCT)}


def _t95_ci(pts, ts, reps, seed):
    """Bootstrap (over sessions, stratified by class) of the smallest T with session AUROC >= target.
    pts[i] = {session: (y, score)} at ts[i] or None. Returns (lo, hi) in T; None = not reached."""
    base = next((p for p in pts if p), None)
    if base is None:
        return [None, None]
    uni = sorted(base)
    yy = np.array([base[i][0] for i in uni])
    rng = np.random.default_rng(seed)
    res = []
    for _ in range(reps):
        draw = np.concatenate([rng.choice(np.array(uni, dtype=object)[yy == c], (yy == c).sum()) for c in (0, 1)])
        t_hit = np.inf
        for t, p in zip(ts, pts):
            if not p:
                continue
            d = [p[i] for i in draw if i in p]
            ys = np.array([a for a, _ in d])
            if len(set(ys)) == 2 and S.auroc(ys, np.array([b for _, b in d])) >= AUROC_TARGET:
                t_hit = t
                break
        res.append(t_hit)
    lo, hi = np.quantile(res, 0.025, method="lower"), np.quantile(res, 0.975, method="higher")
    return [None if np.isinf(lo) else float(lo), None if np.isinf(hi) else float(hi)]


def _na(reason, **extra):
    return {"status": "NA", "reason": reason, "supported": None, **extra}


def _num(x):
    return None if x is None or np.isnan(x) else float(x)


def _boot_problem(n_valid, dropped):
    """Why a bootstrap CI / p-value cannot be trusted (every replicate NaN, or > MAX_DROPPED_FRAC dropped), else None."""
    total = n_valid + dropped
    if n_valid == 0 or dropped / total > MAX_DROPPED_FRAC:
        return "bootstrap unreliable: %d of %d replicates were NaN and dropped (limit %d%%)" % (
            dropped, total, round(100 * MAX_DROPPED_FRAC))
    return None


def _pb(d):
    """Summary of S.paired_bootstrap output. CI and p are None (and `unreliable` says why) when the bootstrap
    dropped too many replicates, so no claim is built on them."""
    bad = _boot_problem(d["n_valid"], d["dropped"])
    return {"diff": _num(d["diff"]), "ci": [None, None] if bad else [_num(d["lo"]), _num(d["hi"])],
            "p_one_sided": None if bad else _num(d["p"]), "n_valid": d["n_valid"],
            "dropped_replicates": d["dropped"], "unreliable": bad}


def _arrays(r):
    return np.asarray(r["combined"]["y"]), np.asarray(r["combined"]["score"]), np.asarray(r["single"]["score"])


def _paired_summary(r, reps, seed):
    """Combined vs single on one evaluate_at result: AUROCs, paired session bootstrap, one-sided p."""
    y, c, s = _arrays(r)
    out = {"auroc_single": r["single"]["auroc"], "auroc_combined": r["combined"]["auroc"],
           **_pb(S.paired_bootstrap(y, c, s, S.auroc, reps, seed)), "n_sessions": r["info"]["n_sessions"],
           "signals_used": r["info"]["signals_used"]}
    out["supported"] = None if out["diff"] is None or out["p_one_sided"] is None else bool(
        out["diff"] > 0 and out["p_one_sided"] < ALPHA)
    return out


def _sensitivity(sessions, t, fam, reps, seed, repeats, **kw):
    try:
        return _paired_summary(evaluate_at(sessions, PRIMARY_PAIR, t, fam, seed, repeats, modes=("single", "combined"),
                                           **kw), reps, seed)
    except Insufficient as e:
        return _na(str(e))


def _h3(sessions, fam, t_short, reps, seed, repeats, columns=None):
    """One decision per session: mean score over the session's rows, in-distribution vs leave-one-workload-out.
    Primary: auroc_drop = AUROC(in-distribution) - AUROC(held-out workload), supported (raw) when the upper 95%
    bootstrap bound is < 0.05 (the Holm-adjusted p is applied later). f1_drop (F1 at 0.5) is a secondary point
    estimate."""
    X, y, g, w = F.table(sessions, t_short, PRIMARY_PAIR)
    cols = [F.SIGNALS.index(n) for n in (columns if columns is not None
                                         else F.fixed_columns(sessions, PRIMARY_PAIR, (t_short,))["names"])]
    ind = _avg([oof_scores(X, y, g, w, fam, "combined", seed + r, columns=cols) for r in range(repeats)])
    held = np.full(len(y), np.nan)
    for wl in F.WORKLOADS:
        m = _avg([oof_scores(X, y, g, w, fam, "combined", seed + r, lowo=wl, columns=cols) for r in range(repeats)])
        held[w == wl] = m[w == wl]
    ids_i, ys_i, si = session_level(ind, y, g)
    ids_h, _, sh = session_level(held, y, g)
    common = sorted(set(ids_i) & set(ids_h))
    if not common:
        raise Insufficient("no session has both an in-distribution and a held-out-workload score")
    ki, kh = [ids_i.index(i) for i in common], [ids_h.index(i) for i in common]
    ys, si, sh = ys_i[ki], si[ki], sh[kh]
    if len(set(ys)) < 2:
        raise Insufficient("H3 sessions contain a single class")
    f1_drop = S.f1(ys, si) - S.f1(ys, sh)

    def drop(b):
        return S.auroc(ys[b], si[b]) - S.auroc(ys[b], sh[b])

    bs = S.bootstrap_full(drop, len(ys), reps, seed, strata=ys)  # one bootstrap: CI and p share the resamples
    vals = bs["vals"]
    bad = _boot_problem(len(vals), bs["dropped"])
    if bad:
        return _na(bad, supported_raw=None, p=None, n_sessions=len(ys), dropped_replicates=bs["dropped"],
                   auroc_drop=_num(bs["point"]), f1_drop=f1_drop)
    p = float((np.sum(vals >= 0.05) + 1) / (len(vals) + 1))  # non-inferiority: P(drop >= 0.05)
    return {"n_sessions": len(ys), "auroc_in_distribution": S.auroc(ys, si), "auroc_held_workload": S.auroc(ys, sh),
            "auroc_drop": bs["point"], "drop_ci": [bs["lo"], bs["hi"]], "upper95": bs["hi"], "p": p,
            "dropped_replicates": bs["dropped"], "supported_raw": bool(bs["hi"] < 0.05),
            "f1_in_distribution": S.f1(ys, si), "f1_held_workload": S.f1(ys, sh), "f1_drop": f1_drop,
            "f1_note": "secondary: F1 at the fixed 0.5 threshold, point estimate only"}


def _exploratory_reasons(sessions, expected_per_class):
    """Why this run cannot be cited as the pre-registered result (empty list = it can): a class of the primary pair
    without exactly the expected number of sessions, or a session without all four workloads."""
    why = []
    for c in PRIMARY_PAIR:
        n = sum(s["cls"] == c for s in sessions)
        if n != expected_per_class:
            why.append(f"{c}: {n} sessions, expected exactly {expected_per_class}")
    short = sorted(s["session"] for s in sessions if s["cls"] in PRIMARY_PAIR and set(F.WORKLOADS) - set(s["windows"]))
    if short:
        why.append("sessions without all %d workloads: %s" % (len(F.WORKLOADS), ", ".join(short)))
    return why


def _curve_point(t, x):
    """One evaluated T of the curve (x = evaluate_at result)."""
    sm, cm, i = x["single"], x["combined"], x["info"]
    return {"t": t, "single_auroc": sm["auroc"], "combined_auroc": cm["auroc"], "single_f1": sm["f1"],
            "combined_f1": cm["f1"], "single_f1_youden": sm["f1_youden"], "combined_f1_youden": cm["f1_youden"],
            "single_bal_acc": sm["bal_acc"], "combined_bal_acc": cm["bal_acc"], "n_sessions": i["n_sessions"],
            "used_seconds": i["used_seconds"], "windows_used": i["windows_used"], "nan_fraction": i["nan_fraction"],
            "cost_s": i["cost_s"], "cost_single_workload_s": i["cost_single_workload_s"], "reason": None}


def _failed_point(t, e):
    nan = float("nan")
    return {"t": t, **{k: nan for k in ("single_auroc", "combined_auroc", "single_f1", "combined_f1",
                                        "single_f1_youden", "combined_f1_youden", "single_bal_acc",
                                        "combined_bal_acc", "cost_s", "cost_single_workload_s")},
            "n_sessions": getattr(e, "counts", None), "used_seconds": None, "windows_used": None,
            "nan_fraction": None, "reason": str(e)}


def analyze(sessions, t_short=1.0, ts=TS, families=("logreg", "rf"), reps=2000, seed=0, repeats=REPEATS,
            exclude_gate_failures=False, load_info=None, expected_per_class=EXPECTED_PER_CLASS):
    """The pre-registered M4 analysis. Returns a JSON-safe dict; {"status": "NA", ...} if it cannot be run.

    `t_short` comes from the caller (use choose_t_short on pilot data). Measurement seconds are real: they
    come from elapsed_ms in the CSVs. H1 is the single primary endpoint; H2, H3 and the two secondary
    combined-vs-single tests form the Holm family. `load_info` (features.load_report output) is passed through
    as "load_report" when the sessions came from load().

    Sessions flagged pilot are refused (ValueError). The status is 'EXPLORATORY' (citable false) unless each class
    of the primary pair has exactly `expected_per_class` sessions and every one has all four workloads. The
    feature set is fixed once per pair (features.fixed_columns on the longest T) and shared by every T and arm.
    The T grid is collapsed: T with identical windows are evaluated once (curve.grid has duplicate_of).
    """
    pilots = sorted(s["session"] for s in sessions if s.get("pilot"))
    if pilots:
        raise ValueError("pilot sessions (meta pilot:true) must not enter the analysis: " + ", ".join(pilots))
    fam = PRIMARY_FAMILY
    families = tuple(dict.fromkeys((fam, *families)))
    gate = F.confounds(sessions)["clocksource_gate"]
    if exclude_gate_failures and gate["failures"]:
        sessions = [s for s in sessions if s["session"] not in set(gate["failures"])]
    grid = F.collapse_grid(sessions, PRIMARY_PAIR, ts)
    ts_eval = [q["t"] for q in grid if q["duplicate_of"] is None]
    feat_sets = {}

    def feat(pair, agg="median"):
        if (pair, agg) not in feat_sets:
            feat_sets[(pair, agg)] = F.fixed_columns(sessions, pair, (*ts, t_short), agg)
        return feat_sets[(pair, agg)]

    def cols(pair, agg="median"):
        return feat(pair, agg)["names"]

    cache = {}

    def ev(pair, t, f, **kw):
        """evaluate_at, cached. Only Insufficient (an expected data shortage) is cached, as plain text + counts;
        any other exception is a bug and propagates."""
        key = (pair, t, f, tuple(sorted(kw.items())))
        if key not in cache:
            try:
                cache[key] = (evaluate_at(sessions, pair, t, f, seed, repeats,
                                          columns=cols(pair, kw.get("agg", "median")), **kw), None)
            except Insufficient as e:
                cache[key] = (None, (str(e), e.counts, e.min_sessions))
        result, err = cache[key]
        if err:
            raise Insufficient(*err)
        return result

    def na(reason, **extra):
        return {"status": "NA", "reason": reason, **extra, **({"load_report": load_info} if load_info else {})}

    try:
        r = ev(PRIMARY_PAIR, t_short, fam)
    except Insufficient as e:
        return na(str(e), n_sessions=e.counts)
    if np.isnan(r["combined"]["auroc"]) or np.isnan(r["single"]["auroc"]):
        return na("AUROC is NaN at t_short (a class has no scored session)", n_sessions=r["info"]["n_sessions"])

    info = r["info"]
    why_exploratory = _exploratory_reasons(sessions, expected_per_class)
    prim = [s for s in sessions if s["cls"] in PRIMARY_PAIR]
    res = {"status": "EXPLORATORY" if why_exploratory else "ok", "citable": not why_exploratory,
           "exploratory_reasons": why_exploratory, "primary_family": fam, "t_short_s": t_short,
           "n_sessions": info["n_sessions"],
           "dropped_sessions": info["dropped_sessions"], "excluded_rows": info["excluded_rows"],
           "signals_used": info["signals_used"], "signals_dropped": info["signals_dropped"],
           "selection": info["selection"], "youden_fallbacks": info["youden_fallbacks"],
           "rows_partially_scored": info["rows_partially_scored"], "load_report": load_info,
           "perf_exposed": F.perf_exposed(sessions), "clocksource_gate": gate,
           "n_days": len({s.get("day") for s in sessions if s.get("day") is not None}),
           "startup_source": info["startup_source"], "nan_fraction": {},
           "settings": {"repeats": repeats, "outer_folds": 5, "inner_folds": 3, "boot_reps": reps,
                        "warmup_s": WARMUP_S, "load_start_s": LOAD_START_S, "h4_interval_s": H4_INTERVAL_S,
                        "startup_source": info["startup_source"], "expected_per_class": expected_per_class,
                        "sessions_used": info["n_sessions"],
                        "workloads_used": sorted({w for s in prim for w in s["windows"]}),
                        "min_workloads_per_session": min((len(s["windows"]) for s in prim), default=0),
                        "feature_set_T": feat(PRIMARY_PAIR)["T"], "feature_set": cols(PRIMARY_PAIR),
                        "feature_set_dropped": feat(PRIMARY_PAIR)["dropped"],
                        "gate_failures_excluded": bool(exclude_gate_failures and gate["failures"])},
           "ci_note": CI_NOTE, "pairs": {}, "pairs_full": {}, "curve": {}}
    brief = lambda x: {m: {k: x[m][k] for k in ("auroc", "f1", "f1_youden")} for m in MODES}  # noqa: E731

    # secondary + sanity comparisons at the short window; combined-vs-single p for the Holm family
    sec_p = {}
    for pair in PAIRS:
        name = "%s_vs_%s" % pair
        res["pairs"][name], res["pairs_full"][name] = {}, {}
        for f in families:
            try:
                x = ev(pair, t_short, f)
            except Insufficient as e:
                res["pairs"][name][f] = _na(str(e))
                continue
            res["pairs"][name][f] = {**brief(x), "info": x["info"]}
            res["pairs_full"][name][f] = x
            if f == fam and pair != PRIMARY_PAIR:
                y_, c_, s_ = _arrays(x)
                t = _pb(S.paired_bootstrap(y_, c_, s_, S.auroc, reps, seed))
                sec_p[name] = t["p_one_sided"]
                res["pairs"][name][f]["combined_vs_single"] = t

    # AUROC (primary) / F1 / balanced accuracy / cost vs measurement time on the primary pair, on the collapsed
    # grid; flag points whose session set differs
    ref_ids = set(r["combined"]["ids"])
    pt_scores = {}
    for f in families:
        pts = []
        for t in ts_eval:
            try:
                x = ev(PRIMARY_PAIR, t, f)
                if f == fam:
                    pt_scores[t] = {i: (int(a), float(b)) for i, a, b in zip(x["combined"]["ids"], x["combined"]["y"],
                                                                             x["combined"]["score"])}
                pts.append({**_curve_point(t, x), "session_set_differs": set(x["combined"]["ids"]) != ref_ids})
            except Insufficient as e:
                pts.append({**_failed_point(t, e), "session_set_differs": True})
        col = lambda k: [q[k] for q in pts]  # noqa: E731
        res["curve"][f] = {
            "t": list(ts_eval), "grid": grid,
            **{k: col(k) for k in ("single_auroc", "combined_auroc", "single_f1", "combined_f1", "single_f1_youden",
                                   "combined_f1_youden", "single_bal_acc", "combined_bal_acc", "cost_s",
                                   "cost_single_workload_s", "n_sessions", "used_seconds", "windows_used",
                                   "nan_fraction", "session_set_differs")},
            "point_failures": {q["t"]: q["reason"] for q in pts if q["reason"]},
            "time_to_auroc_95": {"combined": time_to_metric(ts_eval, col("combined_auroc"), AUROC_TARGET),
                                 "single": time_to_metric(ts_eval, col("single_auroc"), AUROC_TARGET)},
            "time_to_f1_95_at_0.5 (secondary)": {"combined": time_to_metric(ts_eval, col("combined_f1"), 0.95),
                                                 "single": time_to_metric(ts_eval, col("single_f1"), 0.95)},
            "time_to_f1_95_youden (secondary)": {"combined": time_to_metric(ts_eval, col("combined_f1_youden"), 0.95),
                                                 "single": time_to_metric(ts_eval, col("single_f1_youden"), 0.95)}}
    cur = res["curve"][fam]
    res["nan_fraction"] = {str(t): nf for t, nf in zip(ts_eval, cur["nan_fraction"]) if nf}

    # H1 (the single primary endpoint, outside the Holm family): combined vs best single, same family
    ys, c, s = _arrays(r)
    h1 = _pb(S.paired_bootstrap(ys, c, s, S.auroc, reps, seed))
    not_evaluated = [t for t, v in zip(ts_eval, cur["single_auroc"]) if np.isnan(v)]
    ceiling = not not_evaluated and all(v >= CEILING_AUROC for v in cur["single_auroc"])
    sup = None if h1["diff"] is None or h1["p_one_sided"] is None else bool(h1["diff"] > 0 and h1["p_one_sided"] < ALPHA)
    try:
        arms = signal_arms(sessions, PRIMARY_PAIR, t_short, fam, seed, repeats, columns=cols(PRIMARY_PAIR))
    except Insufficient as e:
        arms = _na(str(e))
    res["H1"] = {"status": "NA" if not_evaluated else "untestable" if ceiling else "ok",
                 "reason": ("T points not evaluated: %s; the ceiling rule needs every point of the grid"
                            % ", ".join(str(t) for t in not_evaluated)) if not_evaluated else
                 ("best single signal has AUROC >= %.2f at every T on the grid (ceiling): H1 is untestable, "
                  "not a failed hypothesis" % CEILING_AUROC) if ceiling else None,
                 "auroc_combined": r["combined"]["auroc"], "auroc_single": r["single"]["auroc"], **h1,
                 "supported": None if ceiling or not_evaluated else sup,
                 "arms": {"nested_single": {"auroc": r["single"]["auroc"], "note": H1_NESTED_NOTE},
                          "combined": {"auroc": r["combined"]["auroc"]}, **arms},
                 "auroc_by_T": {"t": list(ts_eval), "single": cur["single_auroc"], "combined": cur["combined_auroc"]},
                 "time_to_auroc_95": cur["time_to_auroc_95"],
                 "by_workload": {m: r[m]["by_workload"] for m in ("single", "combined")}}
    res["H1_behaviour_only"] = {"excluded": ["cpuid_tsc"], "role": "secondary, reported next to H1, not in Holm family",
                                **_sensitivity(sessions, t_short, fam, reps, seed, repeats, exclude=("cpuid_tsc",),
                                               columns=cols(PRIMARY_PAIR))}
    res["secondary_mad"] = {"agg": "median+mad", "role": "secondary aggregation, primary pair only",
                            **_sensitivity(sessions, t_short, fam, reps, seed, repeats, agg="median+mad",
                                           columns=cols(PRIMARY_PAIR, "median+mad"))}
    res["single_arm_checks"] = extra_arms(r, sessions, PRIMARY_PAIR, t_short, fam, seed, repeats,
                                          columns=cols(PRIMARY_PAIR))
    res["leave_one_day_out"] = _sensitivity(sessions, t_short, fam, reps, seed, repeats, cv="day",
                                            columns=cols(PRIMARY_PAIR))
    if gate["failures"] and not exclude_gate_failures:
        keep = [x for x in sessions if x["session"] not in set(gate["failures"])]
        res["gate_sensitivity"] = {"n_excluded": len(gate["failures"]),
                                   **_sensitivity(keep, t_short, fam, reps, seed, repeats,
                                                  columns=F.fixed_columns(keep, PRIMARY_PAIR, (*ts, t_short))["names"])}

    # H2: false-positive rate on native at a fixed TPR (TPR_TARGET); estimation, low power
    fc, fs = S.fpr_at_tpr(ys, c, TPR_TARGET), S.fpr_at_tpr(ys, s, TPR_TARGET)
    h2 = _pb(S.paired_bootstrap(ys, c, s, lambda y_, s_: -S.fpr_at_tpr(y_, s_, TPR_TARGET), reps, seed))
    res["H2"] = {"tpr_target": TPR_TARGET, "fpr_combined": fc, "fpr_single": fs,
                 "diff_single_minus_combined_ci": h2["ci"], "p": h2["p_one_sided"],
                 "supported_raw": None if h2["ci"][0] is None else bool(h2["ci"][0] > 0)}

    # H3: train on 3 workloads, test on the 4th (combined model, primary family), one decision per session
    try:
        res["H3"] = _h3(sessions, fam, t_short, reps, seed, repeats, columns=cols(PRIMARY_PAIR))
    except Insufficient as e:
        res["H3"] = _na(str(e), supported_raw=None, p=None)

    # H4: cost of one session decision at the smallest T with session AUROC >= 0.95, with a bootstrap CI for T95
    t95 = cur["time_to_auroc_95"]["combined"]
    cost = None if t95 is None else cur["cost_s"][ts_eval.index(t95)]
    res["H4"] = h4_decision(cost, not any(np.isnan(cur["combined_auroc"])))
    ci = _t95_ci([pt_scores.get(t) for t in ts_eval], ts_eval, min(reps, 500), seed)
    res["H4"].update({"t95_per_workload_s": t95, "t95_ci": ci, "startup_source": info["startup_source"],
                      "seconds_ci": [None if t is None else cur["cost_s"][ts_eval.index(t)] for t in ci],
                      "single_workload_seconds": None if t95 is None else
                      cur["cost_single_workload_s"][ts_eval.index(t95)]})

    _apply_holm(res, fam, sec_p)

    res["session_predictions"] = [
        {"session": i, "declared": PRIMARY_PAIR[int(y_)], "predicted": PRIMARY_PAIR[int(sc >= 0.5)]}
        for i, y_, sc in zip(r["combined"]["ids"], r["combined"]["y"], r["combined"]["score"])]
    return _plain(res)


def _apply_holm(res, fam, sec_p):
    """Holm over H2, H3 and the two secondary combined-vs-single tests (family size fixed at 4; a test that
    could not run counts as p = 1 and is reported as None). Sets res["holm"], the `supported` flag of H2 and H3
    and p_holm / supported of each secondary pair's combined_vs_single."""
    fam_p = {"H2": res["H2"]["p"], "H3": res["H3"]["p"]}
    fam_p.update({"%s_vs_%s" % pr: sec_p.get("%s_vs_%s" % pr) for pr in PAIRS if pr != PRIMARY_PAIR})
    adj = S.holm({k: 1.0 if v is None else v for k, v in fam_p.items()})
    res["holm"] = {k: None if fam_p[k] is None else adj[k] for k in fam_p}
    for h in ("H2", "H3"):
        raw, a = res[h]["supported_raw"], res["holm"][h]
        res[h]["supported"] = None if raw is None or a is None else bool(raw and a < ALPHA)
    for name, v in res["pairs"].items():
        t = v.get(fam, {}).get("combined_vs_single")
        if t is not None:
            a = res["holm"][name]
            t["p_holm"] = a
            t["supported"] = None if a is None or t["diff"] is None else bool(t["diff"] > 0 and a < ALPHA)


def _plain(o):
    """numpy -> plain Python so the result is JSON-safe."""
    if isinstance(o, dict):
        return {(k if isinstance(k, str) else str(k)): _plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_plain(v) for v in o]
    if isinstance(o, np.ndarray):
        return _plain(o.tolist())
    if isinstance(o, np.generic):
        return o.item()
    return o
