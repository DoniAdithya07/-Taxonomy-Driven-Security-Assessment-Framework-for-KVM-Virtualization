"""Metrics shared by all modules: Wilson and Clopper-Pearson CIs, precision/recall/F1, M1 scoring."""
from collections import defaultdict

from scipy.stats import beta


def _check_counts(k, n):
    if k < 0 or k > n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")


def wilson(k, n, z=1.96):
    _check_counts(k, n)
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def clopper_pearson(k, n, alpha=0.05):
    _check_counts(k, n)
    if n == 0:
        return (0.0, 1.0)
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (float(lo), float(hi))


def _ratio(num, den):
    return num / den if den else None  # undefined, not 0: "no data" must not look like "perfect/zero"


def prf(tp, fp, fn, tn=0):
    p, r, fpr = _ratio(tp, tp + fp), _ratio(tp, tp + fn), _ratio(fp, fp + tn)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r,
            "f1": _ratio(2 * tp, 2 * tp + fp + fn), "fpr": fpr,
            "recall_ci": wilson(tp, tp + fn), "precision_ci": wilson(tp, tp + fp), "fpr_ci": wilson(fp, fp + tn)}


# counter slots per control
TP, FP, FN, TN, NA_ON_PASS, NA_VIOLATIONS, NA_PRED, TOTAL = range(8)


def _classify(truth, pred):
    """Counter slot for one (case, control) pair. Positive class = FAIL."""
    if truth == "FAIL":
        return TP if pred == "FAIL" else FN  # an NA on a seeded fault is a miss
    if truth == "PASS":
        return {"FAIL": FP, "PASS": TN}.get(pred, NA_ON_PASS)  # NA on a clean control is not a true negative
    return FP if pred == "FAIL" else NA_VIOLATIONS if pred == "PASS" else None  # truth NA: only NA is right


def _summary(v):
    out = prf(v[TP], v[FP], v[FN], v[TN])
    out.update(na_on_pass=v[NA_ON_PASS], na_violations=v[NA_VIOLATIONS], na_pred=v[NA_PRED], total=v[TOTAL],
               coverage=_ratio(v[NA_PRED], v[TOTAL]))  # coverage = na_pred / total (share of pairs left untested)
    return out


def score_m1(pred, key):
    """pred, key: {case_id: {control_id: PASS|FAIL|NA}}. Unit = (case, control) pair.

    truth PASS + pred NA goes to `na_on_pass` (not tn); truth NA + pred PASS goes to `na_violations`
    (the checker claimed PASS for something that cannot be tested); truth NA + pred FAIL is a fp.
    """
    counts = defaultdict(lambda: [0] * 8)
    for case, truth in key.items():
        for cid, t in truth.items():
            p = pred.get(case, {}).get(cid, "NA")
            slot = _classify(t, p)
            if slot is not None:
                counts[cid][slot] += 1
            counts[cid][TOTAL] += 1
            counts[cid][NA_PRED] += p == "NA"
    tot = [sum(v[i] for v in counts.values()) for i in range(8)]
    return {"overall": _summary(tot), "per_control": {cid: _summary(v) for cid, v in sorted(counts.items())}}
