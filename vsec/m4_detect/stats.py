"""Statistics for M4: bootstrap over sessions, paired tests, Holm correction, ROC helpers.

All CIs here are conditional on the session scores they are given (out-of-fold scores from one CV scheme):
variability of the CV itself, including the choice of the best single signal, is not resampled.
"""
import numpy as np
from scipy.stats import rankdata
from sklearn.metrics import balanced_accuracy_score, f1_score, roc_curve


def auroc(y, s):
    """Mann-Whitney AUROC (ties count half). NaN unless both classes are present."""
    y = np.asarray(y)
    n1 = int((y == 1).sum())
    n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return float("nan")
    r = rankdata(s)
    return float((r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n0 * n1))


def f1(y, s, thr=0.5):
    """F1 of the positive class for score >= thr (thr may be one number or one per row)."""
    return float(f1_score(y, np.asarray(s) >= thr, zero_division=0))


def bal_acc(y, s, thr=0.5):
    """Balanced accuracy (mean of TPR and TNR) for score >= thr; NaN unless both classes are present."""
    if len(set(np.asarray(y))) < 2:
        return float("nan")
    return float(balanced_accuracy_score(y, np.asarray(s) >= thr))


def fpr_at_tpr(y, s, tpr=0.95):
    """Smallest FPR whose TPR >= tpr (conservative, no interpolation).
    NaN unless both classes are present and some threshold reaches tpr."""
    if len(set(np.asarray(y))) < 2:
        return float("nan")
    fpr, t, _ = roc_curve(y, s)
    ok = t >= tpr - 1e-9
    return float(fpr[np.argmax(ok)]) if ok.any() else float("nan")


def youden_threshold_ex(y, s):
    """(threshold maximising TPR - FPR, fell_back). Falls back to 0.5 (fell_back True) when it cannot be
    computed: one class, or the best point is the non-finite 'accept nothing' threshold."""
    y = np.asarray(y)
    if len(set(y)) < 2:
        return 0.5, True
    fpr, tpr, thr = roc_curve(y, s)
    t = thr[int(np.argmax(tpr - fpr))]
    return (float(t), False) if np.isfinite(t) else (0.5, True)


def youden_threshold(y, s):
    """Score threshold maximising TPR - FPR; 0.5 if it cannot be computed (see youden_threshold_ex)."""
    return youden_threshold_ex(y, s)[0]


def bootstrap_full(fn, n, reps=2000, seed=0, strata=None):
    """Bootstrap fn(idx) over n sessions (resampled within strata if given).
    Returns {"point", "lo", "hi", "vals", "dropped"}; replicates where fn is NaN are skipped and counted."""
    rng = np.random.default_rng(seed)
    idx = np.arange(n)
    vals, dropped = [], 0
    for _ in range(reps):
        if strata is None:
            b = rng.choice(idx, n)
        else:
            b = np.concatenate([rng.choice(idx[strata == c], (strata == c).sum()) for c in np.unique(strata)])
        v = fn(b)
        if np.isnan(v):
            dropped += 1
        else:
            vals.append(v)
    vals = np.array(vals)
    lo, hi = np.percentile(vals, [2.5, 97.5]) if len(vals) else (float("nan"),) * 2
    return {"point": float(fn(idx)), "lo": float(lo), "hi": float(hi), "vals": vals, "dropped": dropped}


def bootstrap(fn, n, reps=2000, seed=0, strata=None):
    """-> (point, lo, hi, dropped) of fn over bootstrap resamples of n sessions. `dropped` = replicates where
    fn was NaN; the caller decides whether that many is acceptable (classify applies a 20% rule)."""
    r = bootstrap_full(fn, n, reps, seed, strata)
    return r["point"], r["lo"], r["hi"], r["dropped"]


def paired_bootstrap(y, sa, sb, metric=auroc, reps=2000, seed=0):
    """Paired session-level bootstrap of metric(sa) - metric(sb): the SAME resampled sessions are used for
    both models, stratified by class. One-sided p = (#diffs <= 0 + 1) / (n + 1) for 'a is better than b'.
    Returns {"diff", "lo", "hi", "p", "n_valid", "dropped"} (95% percentile CI)."""
    y, sa, sb = np.asarray(y), np.asarray(sa), np.asarray(sb)
    r = bootstrap_full(lambda b: metric(y[b], sa[b]) - metric(y[b], sb[b]), len(y), reps, seed, strata=y)
    v = r["vals"]
    p = float((np.sum(v <= 0) + 1) / (len(v) + 1)) if len(v) else float("nan")
    return {"diff": r["point"], "lo": r["lo"], "hi": r["hi"], "p": p, "n_valid": len(v), "dropped": r["dropped"]}


def holm(pvals):
    """Holm-Bonferroni adjusted p-values for a {name: p} dict."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m, out, run = len(items), {}, 0.0
    for i, (k, p) in enumerate(items):
        run = max(run, min(1.0, (m - i) * p))
        out[k] = run
    return out
