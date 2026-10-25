#!/usr/bin/env python3
"""Quality check of one finished M4 boot session, run right after the four CSVs and meta.json exist.

    python3 session_qc.py <session_dir> [--max-nan-frac 0.2] [--max-elapsed-drift 0.5]

Reads <session_dir>/{idle,cpu,mem,mixed}.csv (bench.c output), <workload>.bench.txt and meta.json and writes
<session_dir>/qc.json. Per workload: row count, NaN fraction per signal column (columns are found by header NAME,
so the header may order the signal columns freely), elapsed_ms min/median/max and drift (median of the last
quarter of the rows over the median of the first quarter, minus 1), the workload column equals the file name, window
indices run 0..n-1 in order, and the header is exactly the expected one. Per session: whether perf counters are
exposed (ipc not all NaN), the thermal change before/after each workload (from meta.json), and bench.txt evidence
that the background load died (a line with load_dead=1, bench.c prints it): that is a FAIL for cpu, mem and mixed.

Exit 1, plus a reason written to <session_dir>/FAILED, if: a signal that is not a perf counter (ipc, dtlb_miss) has
a NaN fraction above --max-nan-frac, |elapsed drift| is above --max-elapsed-drift, any header/row/index/workload
problem, a missing or unreadable file, or a dead load. Exit 2 for bad arguments. A bad boot is thus found and re-run
before the other sessions are collected. Stdlib only.
"""
import argparse
import csv
import json
import math
import os
import re
import statistics
import sys

WORKLOADS = ("idle", "cpu", "mem", "mixed")
LOADED = ("cpu", "mem", "mixed")  # the workloads that run a background load
HEADER = ["window", "workload", "elapsed_ms", "cpuid_tsc", "rdtsc_tsc", "syscall_ns", "pagefault_ns", "seq_ns",
          "stride_ns", "rand_ns", "sleep_jitter_us", "ipc", "dtlb_miss"]  # vsec/m4_detect/bench.c, tests check it
SIGNALS = HEADER[3:]
PERF_COUNTERS = ("ipc", "dtlb_miss")  # NaN when the CPU (or VM) does not expose the counters: not a failure
LOAD_DEAD_RE = re.compile(r"\bload_dead=1(?!\d)")


def to_float(text):
    """float of a CSV cell; nan for empty or unparsable cells (glibc may print -nan)."""
    try:
        return float(text)
    except (TypeError, ValueError):
        return math.nan


def header_problems(header):
    problems = []
    if len(set(header)) != len(header):
        problems.append("duplicate column names")
    if sorted(header) != sorted(HEADER):
        problems.append(f"columns {sorted(set(header) ^ set(HEADER))} differ from the expected header")
    elif header[:3] != HEADER[:3]:
        problems.append("first three columns must be window, workload, elapsed_ms")
    return problems


def drift(values):
    """Median of the last quarter over the median of the first quarter, minus 1; None if under 4 usable values or
    the first-quarter median is not positive."""
    v = [x for x in values if math.isfinite(x)]
    q = len(v) // 4
    if q < 1:
        return None
    first, last = statistics.median(v[:q]), statistics.median(v[-q:])
    return last / first - 1 if first > 0 else None


def read_csv(path):
    """-> (header, rows) with rows as dicts of strings; raises OSError/csv.Error/UnicodeError for a bad file."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        return header, [r for r in reader if r]


def check_workload(session_dir, w, max_nan, max_drift):
    """-> (stats dict, problems list) for one workload CSV."""
    problems = []
    try:
        header, rows = read_csv(os.path.join(session_dir, f"{w}.csv"))
    except (OSError, csv.Error, UnicodeError) as exc:
        return {"rows": 0}, [f"{w}.csv unreadable ({type(exc).__name__}: {exc})"]
    hp = header_problems(header)
    problems += [f"{w}.csv header: {p}" for p in hp]
    st = {"rows": len(rows), "header_ok": not hp}
    if hp or not rows:
        if not rows and not hp:
            problems.append(f"{w}.csv has no data rows")
        return st, problems
    col = {name: i for i, name in enumerate(header)}
    ragged = sum(len(r) != len(header) for r in rows)
    st["ragged_rows"] = ragged
    if ragged:
        problems.append(f"{w}.csv: {ragged} row(s) with the wrong number of fields")
        return st, problems
    st["workload_column_ok"] = all(r[col["workload"]] == w for r in rows)
    if not st["workload_column_ok"]:
        problems.append(f"{w}.csv: workload column is not '{w}' in every row")
    st["window_index_ok"] = all(r[col["window"]] == str(i) for i, r in enumerate(rows))
    if not st["window_index_ok"]:
        problems.append(f"{w}.csv: window indices are not 0..{len(rows) - 1} in order")
    nan_frac = {}
    for name in SIGNALS:
        vals = [to_float(r[col[name]]) for r in rows]
        nan_frac[name] = sum(not math.isfinite(x) for x in vals) / len(vals)
        if nan_frac[name] > max_nan and name not in PERF_COUNTERS:
            problems.append(f"{w}.csv: {name} is NaN in {nan_frac[name]:.0%} of rows (limit {max_nan:.0%})")
    st["nan_frac"] = nan_frac
    elapsed = [to_float(r[col["elapsed_ms"]]) for r in rows]
    fin = [x for x in elapsed if math.isfinite(x)]
    st["elapsed_ms"] = ({"min": min(fin), "median": statistics.median(fin), "max": max(fin)} if fin
                        else {"min": None, "median": None, "max": None})
    st["elapsed_drift"] = d = drift(elapsed)
    if d is not None and abs(d) > max_drift:
        problems.append(f"{w}.csv: elapsed_ms drifts {d:+.0%} from the first to the last quarter (limit {max_drift:.0%})")
    return st, problems


def load_dead(session_dir, w):
    """True if <w>.bench.txt has a load_dead=1 line, False if it has none, None if there is no bench.txt."""
    try:
        with open(os.path.join(session_dir, f"{w}.bench.txt"), encoding="utf-8", errors="replace") as f:
            return any(LOAD_DEAD_RE.search(ln) for ln in f)
    except OSError:
        return None


def thermal_delta(meta):
    """{workload: after - before in degrees C or None} from meta.json."""
    before, after = meta.get("temp_before_c"), meta.get("temp_after_c")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return {}
    out = {}
    for w in before:
        b, a = before.get(w), after.get(w)
        num = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (a, b))
        out[w] = round(a - b, 3) if num else None
    return out


def run_qc(session_dir, max_nan=0.2, max_drift=0.5):
    """-> the qc report dict (key "problems" empty and "ok" true when the session passes)."""
    problems = []
    workloads = {}
    for w in WORKLOADS:
        workloads[w], p = check_workload(session_dir, w, max_nan, max_drift)
        problems += p
    ipc_seen = any(isinstance(s.get("nan_frac"), dict) and s["nan_frac"]["ipc"] < 1 for s in workloads.values())
    dead = {w: load_dead(session_dir, w) for w in WORKLOADS}
    problems += [f"{w}: bench reported load_dead=1 (the background load died; re-run the session)"
                 for w in LOADED if dead[w]]
    meta = {}
    try:
        with open(os.path.join(session_dir, "meta.json"), encoding="utf-8") as f:
            meta = json.load(f)
        if not isinstance(meta, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError, RecursionError) as exc:  # ValueError covers JSONDecodeError
        meta = {}
        problems.append(f"meta.json unreadable ({type(exc).__name__}: {exc})")
    delta = thermal_delta(meta)
    known = [d for d in delta.values() if d is not None]
    return {"ok": not problems, "problems": problems,
            "thresholds": {"max_nan_frac": max_nan, "max_elapsed_drift": max_drift},
            "workloads": workloads, "perf_counters_exposed": ipc_seen, "load_dead": dead,
            "thermal_delta_c": delta, "thermal_delta_max_c": max(known) if known else None}


def write_private(path, text):
    """Write via a temp name and rename, so a planted file or symlink at `path` is replaced, never followed."""
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "x", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def nonneg_float(text):
    v = float(text)
    if not math.isfinite(v) or v < 0:
        raise argparse.ArgumentTypeError(f"must be a finite number >= 0, got {text!r}")
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("session_dir")
    ap.add_argument("--max-nan-frac", type=nonneg_float, default=0.2)
    ap.add_argument("--max-elapsed-drift", type=nonneg_float, default=0.5)
    a = ap.parse_args(argv)
    if a.max_nan_frac > 1:
        ap.error("--max-nan-frac must be between 0 and 1")
    if not os.path.isdir(a.session_dir):
        ap.error(f"not a folder: {a.session_dir}")
    report = run_qc(a.session_dir, a.max_nan_frac, a.max_elapsed_drift)
    try:
        write_private(os.path.join(a.session_dir, "qc.json"), json.dumps(report, indent=1, allow_nan=False))
        if not report["ok"]:
            write_private(os.path.join(a.session_dir, "FAILED"), "session_qc: " + "; ".join(report["problems"]) + "\n")
    except OSError as exc:
        print(f"session_qc: cannot write results: {exc}", file=sys.stderr)
        return 1
    for p in report["problems"]:
        print(f"session_qc: FAIL: {p}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
