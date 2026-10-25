"""M4 data loading and feature extraction.

On-disk layout (one folder per boot session):
    data/m4/<session_id>/meta.json        {"cls": "native|kvm-plain|kvm-masked", "date": ..., "temp_c": ..., ...}
    data/m4/<session_id>/<workload>.csv   output of bench.c (one row per window, header: window,workload,elapsed_ms,<signals>)
"""
import csv
import json
import math
import warnings
from collections import Counter
from pathlib import Path

import numpy as np

WORKLOADS = ("idle", "cpu", "mem", "mixed")
CLASSES = ("native", "kvm-plain", "kvm-masked")
SIGNAL_GROUPS = {
    "timing": ["cpuid_tsc", "rdtsc_tsc", "syscall_ns", "pagefault_ns"],
    "memory": ["seq_ns", "stride_ns", "rand_ns", "tlb_ratio"],
    "perf": ["ipc", "dtlb_miss"],
    "scheduler": ["sleep_jitter_us"],
}
SIGNALS = [s for g in SIGNAL_GROUPS.values() for s in g]
RAW = [s for s in SIGNALS if s != "tlb_ratio"]


HEADER = ["window", "workload", "elapsed_ms", *RAW]
CONFOUND_FIELDS = ("clocksource", "governor", "kernel", "cmdline", "no_turbo", "nproc", "smt_active", "online_cpus",
                   "python_version")
# The host's cpufreq settings cannot be read inside a guest: None / absent in a whole class means unreadable, not 'differs'.
UNREADABLE_IN_GUEST = ("governor", "no_turbo")
META_KEYS = ("day", "batch", "order", "minutes_since_boot", "temp_before_c", "temp_after_c", "workload_order",
             "bench_sha256", "bench_startup_ms")
MIN_VALID_FRAC = 0.8      # a row's signal needs at least this fraction of valid windows, else NaN for the row
MAX_NAN_FRAC = 0.2        # a feature column is kept if at most this fraction of all rows is NaN


def _read_csv(f):
    """-> (elapsed_ms array, raw array[n, len(RAW)], truncated rows dropped (0 or 1)). Drops a truncated LAST
    row (and says so); any other bad row raises. The `workload` column must equal the file stem and `window` must
    run 0..n-1 without gaps or repeats."""
    with f.open(newline="") as fh:
        rows = [r for r in csv.reader(fh) if r]
    # Columns are matched BY NAME: bench.c writes sleep_jitter_us before ipc/dtlb_miss, the analysis uses RAW order.
    # The file may order the signal columns any way, but must hold exactly these names, no duplicates, and start
    # with window,workload,elapsed_ms.
    hdr = rows[0] if rows else []
    if sorted(hdr) != sorted(HEADER) or hdr[:3] != HEADER[:3]:
        raise ValueError(f"{f}: header must hold exactly the columns {','.join(HEADER)} (signal columns in any order)")
    order = [hdr.index(c) for c in HEADER]  # file position of each canonical column
    body = rows[1:]
    truncated = 0
    if body and len(body[-1]) < len(HEADER):
        body, truncated = body[:-1], 1  # run was cut off while writing the last row
    if not body:
        raise ValueError(f"{f}: no data rows")
    el, raw = [], []
    for n, r in enumerate(body, start=2):
        try:
            if len(r) != len(HEADER):
                raise ValueError("wrong number of fields")
            vals = [float(r[i]) for i in order[2:]]  # elapsed_ms first, then the signals in RAW order
            e = vals[0]
            if not math.isfinite(e) or e <= 0:
                raise ValueError("elapsed_ms must be a positive number")
            if r[1] != f.stem:
                raise ValueError(f"workload column {r[1]!r} does not match the file name {f.stem!r}")
            if int(r[0]) != n - 2:
                raise ValueError(f"window {r[0]!r} where {n - 2} was expected (windows must run 0..n-1)")
        except ValueError as exc:
            raise ValueError(f"{f} line {n}: malformed row ({exc})") from exc
        el.append(e)
        raw.append(vals[1:])
    return np.array(el), np.array(raw), truncated


def session_dict(session, cls, meta, windows, elapsed, truncated_rows=0):
    """The one session record shape, used by load() and by simulate_sessions() so both carry the same keys:
    session, cls, meta, windows {wl: array[n, len(SIGNALS)]}, elapsed {wl: array[n] ms}, missing_workloads,
    truncated_rows, pilot (bool: meta["pilot"] is true), and from meta (None if absent) every key of META_KEYS
    (bench_startup_ms = {workload: ms from process start to the first timed window})."""
    return {"session": session, "cls": cls, "meta": meta, "windows": windows, "elapsed": elapsed,
            "missing_workloads": [w for w in WORKLOADS if w not in windows], "truncated_rows": truncated_rows,
            "pilot": meta.get("pilot") is True, **{k: meta.get(k) for k in META_KEYS}}


def _read_meta(path):
    try:
        meta = json.loads(path.read_text())
    except ValueError as exc:
        raise ValueError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(meta, dict):
        raise ValueError(f"{path}: meta.json must be a JSON object, got {type(meta).__name__}")
    return meta


def _skip_reason(d):
    """Why folder d is not a session, or None if it should be loaded."""
    if (d / "FAILED").exists():
        why = (d / "FAILED").read_text(errors="replace").strip().splitlines()
        return "FAILED marker: " + (why[0] if why else "run did not finish")
    return None if (d / "meta.json").exists() else "no meta.json"


def load_with_report(data_dir):
    """-> (sessions, report). report = {"skipped_dirs": [{"dir", "reason"}], "sessions": [{"session",
    "missing_workloads", "truncated_rows"}], "total_truncated_rows": int, "pilot_sessions": [names],
    "row_count_mismatch": [{"session", "workload", "rows", "median_rows"}], "degenerate_windows": [{"session",
    "workload"}]}. Nothing is dropped without a record here; an unreadable or invalid meta.json / CSV / unknown
    class raises a ValueError naming the file. Pilot sessions are loaded (and listed) but analyze() refuses them."""
    out, skipped = [], []
    for d in sorted(p for p in Path(data_dir).iterdir() if p.is_dir()):
        why = _skip_reason(d)
        if why:
            skipped.append({"dir": d.name, "reason": why})
            continue
        meta = _read_meta(d / "meta.json")
        if meta.get("cls") not in CLASSES:
            raise ValueError(f"{d.name}: unknown cls {meta.get('cls')!r} (expected one of {CLASSES})")
        wins, elapsed, truncated = {}, {}, 0
        for w in WORKLOADS:
            f = d / f"{w}.csv"
            if f.exists():
                elapsed[w], raw, cut = _read_csv(f)
                wins[w] = add_derived(raw)
                truncated += cut
        out.append(session_dict(d.name, meta["cls"], meta, wins, elapsed, truncated))
    return out, {"skipped_dirs": skipped,
                 "sessions": [{k: s[k] for k in ("session", "missing_workloads", "truncated_rows")} for s in out],
                 "total_truncated_rows": sum(s["truncated_rows"] for s in out),
                 "pilot_sessions": [s["session"] for s in out if s["pilot"]],
                 "row_count_mismatch": [m for s in out for m in _row_count_mismatch(s)],
                 "degenerate_windows": [{"session": s["session"], "workload": w} for s in out
                                        for w, a in s["windows"].items() if _degenerate(a)]}


def _row_count_mismatch(s):
    """Workloads of one session whose row count differs from the median row count of its workloads."""
    counts = {w: len(a) for w, a in s["windows"].items()}
    if not counts:
        return []
    med = float(np.median(list(counts.values())))
    return [{"session": s["session"], "workload": w, "rows": n, "median_rows": med}
            for w, n in counts.items() if n != med]


def _degenerate(a):
    """True when cpuid_tsc equals rdtsc_tsc in every window: the CPUID probe measured nothing (e.g. the same
    instruction twice), so a real VM-exit cost can never show."""
    c, r = SIGNALS.index("cpuid_tsc"), SIGNALS.index("rdtsc_tsc")
    return bool(len(a) and np.array_equal(a[:, c], a[:, r]))


def load(data_dir):
    """-> list of session_dict(...) records, one per folder with a meta.json (see load_with_report)."""
    return load_with_report(data_dir)[0]


def load_report(data_dir):
    """What load(data_dir) skipped or repaired: see load_with_report."""
    return load_with_report(data_dir)[1]


def add_derived(raw):
    """Append tlb_ratio (stride cost over sequential cost) in SIGNALS order. NaN when seq_ns <= 0 (never inf)."""
    i = {s: k for k, s in enumerate(RAW)}
    seq, stride = raw[:, i["seq_ns"]], raw[:, i["stride_ns"]]
    ratio = np.full(len(raw), np.nan)
    ok = seq > 0
    ratio[ok] = stride[ok] / seq[ok]
    cols = {s: raw[:, i[s]] for s in RAW}
    cols["tlb_ratio"] = ratio
    return np.column_stack([cols[s] for s in SIGNALS])


def n_windows_for(elapsed_ms, seconds):
    """Number of leading windows whose cumulative elapsed time reaches `seconds`; None if the data is too short."""
    idx = int(np.searchsorted(np.cumsum(elapsed_ms), seconds * 1000 - 1e-6, side="left"))
    return idx + 1 if idx < len(elapsed_ms) else None


def _log(x):
    """Natural log of strictly positive values; NaN where the value is <= 0 or NaN (never -inf). This is also
    how a 0 in ipc, dtlb_miss or sleep_jitter_us (a counter that read nothing) becomes 'missing', not a reading."""
    x = np.asarray(x, dtype=float)
    out = np.full(x.shape, np.nan)
    ok = x > 0
    out[ok] = np.log(x[ok])
    return out


def feature_names(agg="median"):
    return list(SIGNALS) + ([s + "_mad" for s in SIGNALS] if agg == "median+mad" else [])


def _median_nan(a, min_frac=MIN_VALID_FRAC):
    """Column nanmedians of a window block (windows x columns); NaN for a column with fewer than `min_frac`
    valid (non-NaN) windows. One bad window therefore never removes a signal; a mostly-bad signal is NaN."""
    a = np.asarray(a, dtype=float)
    if not len(a):
        return np.full(a.shape[1], np.nan)
    valid = (~np.isnan(a)).sum(axis=0)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # nanmedian of an all-NaN column warns
        med = np.nanmedian(a, axis=0)
    return np.where(valid >= min_frac * len(a), med, np.nan)


def _aggregate(block, agg):
    """block: windows x signals (raw scale) -> feature vector on the log scale.
    median: nanmedian of each signal's log over the row's windows. median+mad: also the median absolute deviation
    of the log (pre-registered SECONDARY aggregation). A window value <= 0 or NaN is missing; a signal with fewer
    than MIN_VALID_FRAC valid windows is NaN for the row."""
    lg = _log(block)
    med = _median_nan(lg)
    if agg == "median":
        return med
    if agg != "median+mad":
        raise ValueError(f"unknown agg {agg!r}")
    return np.concatenate([med, _median_nan(np.abs(lg - med))])


def table_full(sessions, seconds, classes, agg="median"):
    """One row per (session, workload): features over the first k windows whose cumulative elapsed time reaches
    `seconds`. Returns X (natural-log scale), y (index into `classes`), session ids, workloads, excluded
    [(session, workload)] (too little data), used_seconds per row (real seconds of the k windows) and k per row."""
    X, y, sid, wl, excluded, used, ks = [], [], [], [], [], [], []
    for s in sessions:
        if s["cls"] not in classes:
            continue
        for w, arr in s["windows"].items():
            k = n_windows_for(s["elapsed"][w], seconds)
            if k is None:
                excluded.append((s["session"], w))
                continue
            X.append(_aggregate(arr[:k], agg))
            y.append(classes.index(s["cls"]))
            sid.append(s["session"])
            wl.append(w)
            used.append(float(np.sum(s["elapsed"][w][:k])) / 1000.0)
            ks.append(k)
    X = np.array(X) if X else np.empty((0, len(feature_names(agg))))
    return X, np.array(y, dtype=int), np.array(sid), np.array(wl), excluded, np.array(used), np.array(ks, dtype=int)


def table_ex(sessions, seconds, classes, agg="median"):
    """Like table() plus the (session, workload) rows excluded for too little data, and per kept row the
    real seconds of measurement used. Returns X, y, session ids, workloads, excluded, used_seconds."""
    return table_full(sessions, seconds, classes, agg)[:6]


def table(sessions, seconds, classes, agg="median"):
    """One row per (session, workload): features over the first k windows whose cumulative elapsed time
    reaches `seconds`. Rows with less data than that are excluded (see table_ex).

    A signal with fewer than MIN_VALID_FRAC valid windows in a row is NaN for that row (see _aggregate).
    Returns X (natural-log scale), y (index into `classes`), session ids, workloads.
    """
    return table_ex(sessions, seconds, classes, agg)[:4]


def fixed_columns(sessions, classes, ts, agg="median"):
    """The feature set for a whole analysis, fixed ONCE and label-free: computed on the longest T of `ts` that
    has data, from the sessions of `classes`; a column is kept if its NaN fraction over all those rows is
    <= MAX_NAN_FRAC. The same set is then used for every T and every arm, so the feature set never changes with T.
    Returns {"names": kept feature names, "dropped": [...], "T": the T used (None if no data),
    "nan_fraction": {name: fraction}}."""
    names = feature_names(agg)
    for t in sorted(ts, reverse=True):
        X = table_full(sessions, t, classes, agg)[0]
        if len(X):
            frac = np.isnan(X).mean(axis=0)
            keep = [n for n, f in zip(names, frac) if f <= MAX_NAN_FRAC]
            return {"names": keep, "dropped": [n for n in names if n not in keep], "T": t,
                    "nan_fraction": dict(zip(names, map(float, frac)))}
    return {"names": [], "dropped": list(names), "T": None, "nan_fraction": {}}


def collapse_grid(sessions, classes, ts):
    """The T grid on real seconds: windows come in whole steps, so several T can mean exactly the same windows.
    Returns [{"t", "duplicate_of"}] in grid order; a T whose per-row window counts equal an earlier T's has
    duplicate_of = that earlier T (kept once). A grid with no rows at all is never collapsed."""
    first, out = {}, []
    for t in ts:
        sig = tuple((s["session"], w, n_windows_for(s["elapsed"][w], t))
                    for s in sessions if s["cls"] in classes for w in sorted(s["windows"]))
        dup = first.get(sig) if sig else None
        if sig and dup is None:
            first[sig] = t
        out.append({"t": t, "duplicate_of": dup})
    return out


def confounds(sessions):
    """Per setup field (meta.json): the value set per class, and whether the classes differ (a confound).
    Fields a guest cannot read (UNREADABLE_IN_GUEST: governor, no_turbo) that are None / absent for a whole class
    are listed under `unreadable_in_class` and leave the comparison, instead of counting as 'differs'.
    bench_sha256 must be one value across ALL sessions (`differs` is True if not, whatever the class).
    Also the per-session clock-source gate: sessions whose clocksource is recorded and is not 'tsc'
    (failures) or is not recorded (unknown), and the classes that contain a failure."""
    out = {}
    for f in (*CONFOUND_FIELDS, "bench_sha256"):
        raw = {c: [s["meta"].get(f, "<missing>") for s in sessions if s["cls"] == c] for c in CLASSES}
        raw = {c: v for c, v in raw.items() if v}
        unreadable = sorted(c for c, v in raw.items()
                            if f in UNREADABLE_IN_GUEST and all(x in (None, "<missing>") for x in v))
        vals = {c: sorted({str(x) for x in v}) for c, v in raw.items() if c not in unreadable}
        out[f] = {"values": vals, "differs": len({tuple(v) for v in vals.values()}) > 1}
        if f in UNREADABLE_IN_GUEST:
            out[f]["unreadable_in_class"] = unreadable
        if f == "bench_sha256":
            out[f]["differs"] = len({str(x) for v in raw.values() for x in v}) > 1
    fail = [s for s in sessions if s["meta"].get("clocksource") not in (None, "tsc")]
    out["clocksource_gate"] = {
        "failures": [s["session"] for s in fail],
        "unknown": [s["session"] for s in sessions if s["meta"].get("clocksource") is None],
        "flagged_classes": sorted({s["cls"] for s in fail})}
    return out


def perf_exposed(sessions):
    """Descriptive: per class and counter, the number of sessions in which the counter was measured at all.
    Whether counters are exposed can itself separate classes, so it is reported, not hidden."""
    out = {}
    for c in CLASSES:
        ss = [s for s in sessions if s["cls"] == c]
        if ss:
            out[c] = {"n_sessions": len(ss), **{
                sig: sum(any(not np.isnan(a[:, SIGNALS.index(sig)]).all() for a in s["windows"].values()) for s in ss)
                for sig in SIGNAL_GROUPS["perf"]}}
    return out


STRING_INDICATORS = ("dmi_sys_vendor", "dmi_product_name", "dmi_bios_vendor", "disk_model", "nic_driver",
                     "systemd_detect_virt")


def _indicator_value(k, v):
    """('value', v) for a usable indicator value, ('unreadable', None) for None / blank, else None (ignored:
    counters, timestamps and anything that is not a bool, or a string for a known string indicator)."""
    if v is None or (isinstance(v, str) and not v.strip()):
        return "unreadable", None
    if isinstance(v, bool) or (k in STRING_INDICATORS and isinstance(v, str)):
        return "value", v
    return None


def indicator_table(sessions):
    """Which system indicators (meta["indicators"]) differ from native, per class. Not used by H1.

    Booleans and the STRING_INDICATORS (vendor, model and driver names) are compared; other values (counters,
    timestamps) are ignored. Per row: the sorted value set per class, `unreadable` (sessions per class where the
    indicator was null/blank, so a hidden value is not mistaken for 'same'), and masked_leaks: None when native or
    kvm-masked has no readable value, else True when the masked value set differs from native's.
    """
    seen, unreadable = {}, {}
    for s in sessions:
        ind = s["meta"].get("indicators")
        for k, v in (ind.items() if isinstance(ind, dict) else ()):
            kind = _indicator_value(k, v)
            if kind is None:
                continue
            seen.setdefault(k, {})
            unreadable.setdefault(k, Counter())
            if kind[0] == "value":
                seen[k].setdefault(s["cls"], set()).add(v)
            else:
                unreadable[k][s["cls"]] += 1
    return [{"indicator": k, **{c: sorted(v.get(c, []), key=str) for c in CLASSES},
             "unreadable": {c: unreadable[k][c] for c in CLASSES},
             "masked_leaks": (v["kvm-masked"] != v["native"]) if v.get("kvm-masked") and v.get("native") else None}
            for k, v in sorted(seen.items())]


def _num(m, key):
    v = m.get(key)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


def _temp_parts(m):
    """(readings, unusable): the numeric per-workload temp_before_c / temp_after_c values, and whether either
    field is present but not a dict (string, list, number) or holds a non-numeric value."""
    vals, bad = [], False
    for k in ("temp_before_c", "temp_after_c"):
        v = m.get(k)
        if v is None:
            continue
        if not isinstance(v, dict):
            bad = True
            continue
        for x in v.values():
            if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x):
                vals.append(x)
            elif x is not None:
                bad = True
    return vals, bad


def _temp(m):
    """Mean of the per-workload temp_before_c / temp_after_c readings when any exist, else temp_c."""
    vals = _temp_parts(m)[0]
    return float(np.mean(vals)) if vals else _num(m, "temp_c")


def _hour(m):
    try:
        return int(str(m["time"]).split(":")[0])
    except (KeyError, ValueError, TypeError):
        return None


SMD_FLAG = 0.5


def balance(sessions):
    """Class balance on nuisance variables: temperature (mean of the before/after readings, else temp_c), hour,
    `order` (meta['order'] only: None if absent, the list position is never used) and minutes since boot.
    Reports the mean per class, the standardized mean difference (SMD, difference of means over the pooled
    SD) for each class pair, imbalanced when any |SMD| > 0.5, and `n_unreadable` per class (sessions where the
    field is absent, None or not a finite number). temp_c also reports `unusable_temp_sessions`: sessions whose
    temp_before_c / temp_after_c is not a dict of numbers (ignored)."""
    getters = {"temp_c": _temp, "hour": _hour, "order": lambda m: _num(m, "order"),
               "minutes_since_boot": lambda m: _num(m, "minutes_since_boot")}
    out = {}
    for field, get in getters.items():
        raw = {c: [get(s["meta"]) for s in sessions if s["cls"] == c] for c in CLASSES}
        unread = {c: sum(x is None for x in v) for c, v in raw.items() if v}
        vals = {c: np.array([x for x in v if x is not None], dtype=float) for c, v in raw.items()}
        vals = {c: v for c, v in vals.items() if len(v)}
        smd = {}
        cs = list(vals)
        for a in range(len(cs)):
            for b in range(a + 1, len(cs)):
                pooled = np.sqrt((np.var(vals[cs[a]], ddof=1) + np.var(vals[cs[b]], ddof=1)) / 2) \
                    if min(len(vals[cs[a]]), len(vals[cs[b]])) > 1 else np.nan
                d = vals[cs[b]].mean() - vals[cs[a]].mean()
                smd[f"{cs[a]}_vs_{cs[b]}"] = float(d / pooled) if pooled and not np.isnan(pooled) and pooled > 0 \
                    else (0.0 if d == 0 else None)
        known = [v for v in smd.values() if v is not None]
        out[field] = {"mean": {c: float(v.mean()) for c, v in vals.items()}, "smd": smd,
                      "imbalanced": (any(abs(v) > SMD_FLAG for v in known) if known else None),
                      "n_unreadable": unread}
    out["temp_c"]["unusable_temp_sessions"] = sum(_temp_parts(s["meta"])[1] for s in sessions)
    return out


def usable_columns(X):
    return [j for j in range(X.shape[1]) if not np.isnan(X[:, j]).any()]
