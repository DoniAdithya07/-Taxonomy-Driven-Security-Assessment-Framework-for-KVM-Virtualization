"""scripts/session_qc.py: the post-session quality check, on synthetic CSVs in bench.c's exact column order."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "session_qc.py"
BENCH_C = ROOT / "vsec" / "m4_detect" / "bench.c"
WORKLOADS = ("idle", "cpu", "mem", "mixed")


def load_qc():
    spec = importlib.util.spec_from_file_location("session_qc", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


qc = load_qc()


def bench_header():
    m = re.search(r'printf\("(window,workload,elapsed_ms[^"\\]*)\\n"\)', BENCH_C.read_text(encoding="utf-8"))
    assert m, "could not find the CSV header printf in bench.c"
    return m.group(1).split(",")


def write_csv(path, header, n=40, workload=None, **override):
    """n rows; override maps a column name to a function row_index -> cell text."""
    workload = workload or path.stem
    rows = []
    for i in range(n):
        cell = {c: "1.5" for c in header}
        cell.update(window=str(i), workload=workload, elapsed_ms="100.0")
        cell.update({k: f(i) for k, f in override.items()})
        rows.append(",".join(cell[c] for c in header))
    path.write_text(",".join(header) + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


@pytest.fixture
def session(tmp_path):
    d = tmp_path / "s1"
    d.mkdir()
    for w in WORKLOADS:
        write_csv(d / f"{w}.csv", bench_header())
    (d / "meta.json").write_text(json.dumps({
        "temp_before_c": {"idle": 40.0, "cpu": 41.0, "mem": None, "mixed": 50.0},
        "temp_after_c": {"idle": 42.5, "cpu": 51.0, "mem": 60.0, "mixed": 49.0}}))
    return d


def run(d, *args):
    return subprocess.run([sys.executable, str(SCRIPT), str(d), *args], capture_output=True, text=True)


def report(d):
    return json.loads((d / "qc.json").read_text())


def test_header_constant_matches_bench_c():
    assert qc.HEADER == bench_header()


def test_good_session_passes_and_writes_qc_json_without_failed_marker(session):
    r = run(session)
    assert r.returncode == 0, r.stderr
    rep = report(session)
    assert rep["ok"] and rep["problems"] == [] and not (session / "FAILED").exists()
    idle = rep["workloads"]["idle"]
    assert idle["rows"] == 40 and idle["header_ok"] and idle["window_index_ok"] and idle["workload_column_ok"]
    assert idle["elapsed_ms"] == {"min": 100.0, "median": 100.0, "max": 100.0} and idle["elapsed_drift"] == 0
    assert set(idle["nan_frac"]) == set(bench_header()[3:]) and set(idle["nan_frac"].values()) == {0.0}
    assert rep["perf_counters_exposed"] is True
    assert rep["thermal_delta_c"] == {"idle": 2.5, "cpu": 10.0, "mem": None, "mixed": -1.0}
    assert rep["thermal_delta_max_c"] == 10.0


def test_signal_columns_are_found_by_name_whatever_their_order(session):
    hdr = bench_header()
    shuffled = hdr[:3] + list(reversed(hdr[3:]))
    write_csv(session / "cpu.csv", shuffled, ipc=lambda i: "nan")
    assert run(session).returncode == 0
    rep = report(session)["workloads"]["cpu"]
    assert rep["header_ok"] and rep["nan_frac"]["ipc"] == 1.0 and rep["nan_frac"]["seq_ns"] == 0.0


def test_perf_counters_all_nan_is_recorded_not_failed(session):
    for w in WORKLOADS:
        write_csv(session / f"{w}.csv", bench_header(), ipc=lambda i: "nan", dtlb_miss=lambda i: "-nan")
    assert run(session).returncode == 0
    assert report(session)["perf_counters_exposed"] is False


def test_nan_in_a_non_perf_signal_above_the_limit_fails_and_writes_failed(session):
    write_csv(session / "mem.csv", bench_header(), seq_ns=lambda i: "nan" if i < 10 else "2.0")  # 25% > 20%
    r = run(session)
    assert r.returncode == 1 and "seq_ns is NaN in 25%" in r.stderr
    assert "seq_ns" in (session / "FAILED").read_text() and report(session)["ok"] is False
    assert run(session, "--max-nan-frac", "0.3").returncode == 0  # the limit is configurable
    assert run(session, "--max-nan-frac", "1.5").returncode == 2


def test_elapsed_drift_above_the_limit_fails(session):
    write_csv(session / "cpu.csv", bench_header(), elapsed_ms=lambda i: "100" if i < 20 else "200")
    r = run(session)
    assert r.returncode == 1 and "drifts +100%" in r.stderr
    assert report(session)["workloads"]["cpu"]["elapsed_drift"] == 1.0
    assert run(session, "--max-elapsed-drift", "1.5").returncode == 0


def test_drift_is_last_quarter_median_over_first_quarter_median_minus_one():
    vals = [10.0] * 4 + [99.0] * 4 + [15.0] * 4  # q = 3 of 12: first [10,10,10], last [15,15,15]
    assert qc.drift(vals) == pytest.approx(0.5)
    assert qc.drift([1.0, 2.0, 3.0]) is None and qc.drift([0.0] * 8) is None
    assert qc.drift([float("nan")] * 8) is None


@pytest.mark.parametrize("bad", ["missing", "duplicate", "unknown", "elapsed_not_third"])
def test_bad_headers_fail(session, bad):
    hdr = bench_header()
    if bad == "missing":
        hdr = hdr[:-1]
    elif bad == "duplicate":
        hdr = hdr[:-1] + [hdr[-2]]
    elif bad == "unknown":
        hdr = hdr[:-1] + ["bogus"]
    else:
        hdr = [hdr[0], hdr[2], hdr[1], *hdr[3:]]
    p = session / "idle.csv"
    p.write_text(",".join(hdr) + "\n" + ",".join("1" for _ in hdr) + "\n", encoding="utf-8")
    r = run(session)
    assert r.returncode == 1 and "idle.csv header" in r.stderr and report(session)["workloads"]["idle"]["header_ok"] is False


def test_wrong_workload_column_and_non_contiguous_window_indices_fail(session):
    write_csv(session / "cpu.csv", bench_header(), workload="mem")
    write_csv(session / "mem.csv", bench_header(), window=lambda i: str(i if i < 5 else i + 1))
    r = run(session)
    assert r.returncode == 1
    assert "cpu.csv: workload column is not 'cpu'" in r.stderr and "mem.csv: window indices are not 0..39" in r.stderr
    write_csv(session / "mem.csv", bench_header(), window=lambda i: str(39 - i))  # right set, wrong order
    assert "window indices" in run(session).stderr


def test_missing_empty_ragged_csv_and_missing_meta_are_failures_not_crashes(session):
    (session / "idle.csv").unlink()
    (session / "cpu.csv").write_text(",".join(bench_header()) + "\n")
    (session / "mem.csv").write_text(",".join(bench_header()) + "\n0,mem,1\n")
    (session / "meta.json").write_text("not json")
    r = run(session)
    assert r.returncode == 1 and "Traceback" not in r.stderr
    for text in ("idle.csv unreadable", "cpu.csv has no data rows", "mem.csv: 1 row(s)", "meta.json unreadable"):
        assert text in r.stderr


@pytest.mark.parametrize("w,fails", [("cpu", True), ("mem", True), ("mixed", True), ("idle", False)])
def test_load_dead_in_bench_txt_fails_loaded_workloads_only(session, w, fails):
    (session / f"{w}.bench.txt").write_text("# load_dead=1 worker exited\n")
    r = run(session)
    assert (r.returncode == 1) is fails
    if fails:
        assert f"{w}: bench reported load_dead=1" in r.stderr
    assert report(session)["load_dead"][w] is True


def test_load_dead_zero_or_prefixed_is_not_dead(session):
    (session / "cpu.bench.txt").write_text("# load_dead=0\nload_dead=10\nxload_dead=1\n")
    assert run(session).returncode == 0 and report(session)["load_dead"]["cpu"] is False


def test_bad_arguments_exit_2(tmp_path):
    assert run(tmp_path / "nope").returncode == 2
    assert run(tmp_path, "--max-elapsed-drift", "-1").returncode == 2
    assert run(tmp_path, "--max-nan-frac", "nan").returncode == 2


def test_script_is_stdlib_only_with_python3_shebang():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env python3\n") and b"\r" not in SCRIPT.read_bytes()
    imports = set(re.findall(r"^(?:import|from) (\w+)", text, re.M))
    assert imports <= set(sys.stdlib_module_names)
