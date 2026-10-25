"""SIMULATED M4 sessions, in memory or in the on-disk format. For testing the analysis pipeline only.

Numbers here are invented: results from simulated data say nothing about real hypervisors.

scenario:
  default  invented medians per signal (CPUID separates the classes almost perfectly)
  null     only cpuid_tsc carries class information (same shift for both VM classes): combining adds nothing
  gain     every informative signal is weak (small shift each, independent noise): combining adds real information
no_cpuid=True removes the class effect from cpuid_tsc. Window noise is AR(1) (autocorrelation `ar`) and every
day has its own offset (`n_days`). On disk the CSV has bench.c's header (column order read from bench.c) and its
number formats, so the simulator exercises the same contract as the real tool.
"""
import csv
import json
import random
import re
from pathlib import Path

import numpy as np

from . import features as F
from .features import RAW, WORKLOADS

# median value per signal: (native, kvm-plain, kvm-masked). Invented, ordered like real hardware only roughly.
BASE = {"cpuid_tsc": (120, 1800, 1750), "rdtsc_tsc": (25, 25, 26), "syscall_ns": (90, 96, 97),
        "pagefault_ns": (700, 1250, 1180), "seq_ns": (1.1, 1.15, 1.15), "stride_ns": (3.0, 4.6, 4.4),
        "rand_ns": (35, 44, 43), "sleep_jitter_us": (12, 18, 17), "ipc": (1.5, 1.45, 1.46),
        "dtlb_miss": (0.9, 0.95, 0.94)}
WORKLOAD_SHIFT = {"idle": 1.0, "cpu": 1.03, "mem": 1.08, "mixed": 1.06}
CLASSES = ("native", "kvm-plain", "kvm-masked")
GAIN_SIGNALS = ("syscall_ns", "pagefault_ns", "seq_ns", "stride_ns", "rand_ns", "sleep_jitter_us")
BENCH_C = Path(__file__).with_name("bench.c")
SIG_FIGS = ("ipc", "dtlb_miss", "sleep_jitter_us")  # bench.c prints these %.6g, every other column %.4f


def bench_header():
    """The CSV header bench.c prints (its printf header string), as a list of column names."""
    m = re.search(r'printf\("(window,workload,elapsed_ms[^"\\]*)\\n"\)', BENCH_C.read_text(encoding="utf-8"))
    if not m:
        raise ValueError(f"{BENCH_C}: could not find the CSV header printf")
    return m.group(1).split(",")


def _fmt(col, v):
    return f"{v:.6g}" if col in SIG_FIGS else f"{v:.4f}"


def _effects(scenario, no_cpuid):
    """Log-multiplier of each signal for (native, kvm-plain, kvm-masked)."""
    if scenario == "default":
        eff = {s: np.log(np.array(BASE[s]) / BASE[s][0]) for s in RAW}
    elif scenario == "null":
        eff = {s: np.zeros(3) for s in RAW}
        eff["cpuid_tsc"] = np.array([0, np.log(1.2), np.log(1.2)])
    elif scenario == "gain":
        eff = {s: np.zeros(3) for s in RAW}
        eff["cpuid_tsc"] = np.array([0, 0.05, 0.05])
        for s in GAIN_SIGNALS:
            eff[s] = np.array([0, 0.11, 0.11])
    else:
        raise ValueError(f"unknown scenario {scenario!r}")
    if no_cpuid:
        eff["cpuid_tsc"] = np.zeros(3)
    return eff


def generate(per_class=15, windows=300, mean_elapsed_ms=40.0, seed=0, hard=True, scenario="default",
             no_cpuid=False, n_days=3, ar=0.5, pilot=False):
    """-> list of {"session", "cls", "meta", "raw": {wl: array[windows, len(RAW)]}, "elapsed": {wl: array ms}}.
    Each window takes about mean_elapsed_ms of (simulated) wall time, with small jitter. meta carries the keys
    the real session_meta writes: pilot, workload_order, bench_sha256, bench_startup_ms (~1.5 s per workload)."""
    rng = np.random.default_rng(seed)
    eff = _effects(scenario, no_cpuid)
    order = [(c, i) for c in range(3) for i in range(per_class)]
    random.Random(seed).shuffle(order)  # randomised, interleaved session order
    day_off = {d: {s: rng.normal(0, 0.03) for s in RAW} for d in range(n_days)}
    sigma = 0.25 if hard else 0.05
    out = []
    for n, (c, _) in enumerate(order):
        day = n % n_days
        sess = {s: rng.normal(0, 0.05 if hard else 0.01) for s in RAW}
        raw, elapsed = {}, {}
        for w in WORKLOADS:
            e = np.empty((windows, len(RAW)))
            e[0] = rng.normal(0, sigma, len(RAW))
            innov = rng.normal(0, sigma * np.sqrt(1 - ar ** 2), (windows, len(RAW)))
            for k in range(1, windows):
                e[k] = ar * e[k - 1] + innov[k]
            outl = np.where(rng.random(e.shape) < 0.05, rng.uniform(1.5, 4, e.shape), 1.0)  # interrupt outliers
            base = np.array([BASE[s][0] * np.exp(eff[s][c] + sess[s] + day_off[day][s]) for s in RAW])
            raw[w] = base * WORKLOAD_SHIFT[w] * np.exp(e) * outl
            elapsed[w] = mean_elapsed_ms * rng.uniform(0.95, 1.1, windows)
        meta = {"cls": CLASSES[c], "simulated": True, "scenario": scenario, "clocksource": "tsc",
                "governor": "performance", "no_turbo": 1, "day": f"d{day}", "order": n,
                "temp_c": 50 + float(rng.normal(0, 3)), "time": f"{rng.integers(8, 22)}:00", "pilot": bool(pilot),
                "workload_order": random.Random(seed * 1000 + n).sample(WORKLOADS, len(WORKLOADS)),
                "bench_sha256": "sim", "bench_startup_ms": {w: 1500.0 + float(rng.uniform(0, 50)) for w in WORKLOADS},
                "python_version": "sim"}
        out.append({"session": f"s{n:03d}", "cls": CLASSES[c], "meta": meta, "raw": raw, "elapsed": elapsed})
    return out


def simulate_sessions(**kw):
    """Like simulate() but in memory, in the format of features.load()."""
    return [F.session_dict(s["session"], s["cls"], s["meta"], {w: F.add_derived(a) for w, a in s["raw"].items()},
                           s["elapsed"]) for s in generate(**kw)]


def simulate(out, **kw):
    """Write generate(**kw) in the on-disk format (bench.c's header and number formats) and return the folder."""
    out = Path(out)
    hdr = bench_header()
    for s in generate(**kw):
        d = out / s["session"]
        d.mkdir(parents=True, exist_ok=True)
        for w in WORKLOADS:
            with (d / f"{w}.csv").open("w", newline="") as fh:
                wr = csv.writer(fh)
                wr.writerow(hdr)
                for k, (row, ms) in enumerate(zip(s["raw"][w], s["elapsed"][w])):
                    val = {"elapsed_ms": float(ms), **dict(zip(RAW, map(float, row)))}
                    wr.writerow([k, w, *[_fmt(c, val[c]) for c in hdr[2:]]])
        (d / "meta.json").write_text(json.dumps(s["meta"]))
    return out
