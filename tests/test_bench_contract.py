"""The CSV written by vsec/m4_detect/bench.c must load into the right columns of the analysis.

A review found bench.c writes sleep_jitter_us before ipc/dtlb_miss while features.py expected the other order, so
every real session would have been rejected (the simulator wrote the Python order, so no test noticed). These tests
read the header straight out of bench.c's source, so a future change to either side fails here.
"""
import re
from pathlib import Path

import numpy as np
import pytest

from vsec.m4_detect import features as F

BENCH_C = Path(__file__).resolve().parent.parent / "vsec" / "m4_detect" / "bench.c"


def bench_header():
    m = re.search(r'printf\("(window,workload,elapsed_ms[^"\\]*)\\n"\)', BENCH_C.read_text(encoding="utf-8"))
    assert m, "could not find the CSV header printf in bench.c"
    return m.group(1).split(",")


def test_bench_header_has_exactly_the_expected_columns():
    hdr = bench_header()
    assert sorted(hdr) == sorted(F.HEADER)
    assert hdr[:3] == ["window", "workload", "elapsed_ms"]


def test_bench_csv_loads_into_the_right_columns(tmp_path):
    hdr = bench_header()
    # a distinct value per column name, so any swapped pair is visible
    value = {c: 100.0 + i for i, c in enumerate(hdr)}
    value["window"], value["workload"] = 0, "idle"
    p = tmp_path / "idle.csv"
    row = ",".join(str(value[c]) for c in hdr)
    p.write_text(",".join(hdr) + "\n" + row + "\n" + row.replace("0,idle", "1,idle", 1) + "\n", encoding="utf-8")
    el, raw, truncated = F._read_csv(p)
    assert truncated == 0 and raw.shape == (2, len(F.RAW))
    assert el[0] == value["elapsed_ms"]
    for j, name in enumerate(F.RAW):
        assert raw[0, j] == value[name], f"{name} landed in the wrong column"


def test_nan_for_absent_perf_counters_is_read_as_nan(tmp_path):
    hdr = bench_header()
    value = {c: "1.5" for c in hdr}
    value.update(window="0", workload="idle", ipc="nan", dtlb_miss="-nan")  # glibc may print -nan
    p = tmp_path / "idle.csv"
    p.write_text(",".join(hdr) + "\n" + ",".join(value[c] for c in hdr) + "\n", encoding="utf-8")
    _, raw, _ = F._read_csv(p)
    assert np.isnan(raw[0, F.RAW.index("ipc")]) and np.isnan(raw[0, F.RAW.index("dtlb_miss")])


@pytest.mark.parametrize("bad", ["missing", "duplicate", "unknown", "elapsed_not_third"])
def test_bad_headers_are_rejected(tmp_path, bad):
    hdr = bench_header()
    if bad == "missing":
        hdr = hdr[:-1]
    elif bad == "duplicate":
        hdr = hdr[:-1] + [hdr[-2]]
    elif bad == "unknown":
        hdr = hdr[:-1] + ["bogus"]
    else:
        hdr = [hdr[0], hdr[2], hdr[1], *hdr[3:]]
    p = tmp_path / "idle.csv"
    p.write_text(",".join(hdr) + "\n" + ",".join("1" for _ in hdr) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header"):
        F._read_csv(p)


def bench_source():
    return BENCH_C.read_text(encoding="utf-8")


def test_row_format_uses_six_significant_digits_for_tiny_columns_and_four_decimals_for_the_rest():
    m = re.search(r'printf\("%d,%s,([^"\\]*)\\n"', bench_source())
    assert m, "could not find the CSV row printf in bench.c"
    fmts = m.group(1).split(",")
    cols = bench_header()[2:]  # elapsed_ms and the signals, in file order
    assert len(fmts) == len(cols)
    for col, fmt in zip(cols, fmts):
        assert fmt == ("%.6g" if col in ("ipc", "dtlb_miss", "sleep_jitter_us") else "%.4f"), col


def test_load_child_is_polled_every_window_and_startup_is_reported():
    src = bench_source()
    assert "waitpid(load, NULL, WNOHANG)" in src and "# load_dead=1 window=%d" in src
    assert "return 3;" in src and "# load_alive=1" in src
    assert "startup_ms=%.1f" in src
    # the load poll sits inside the window loop, the metadata line comes after the warm-up window
    loop = src[src.index("for (int w = 0; w < n_windows; w++)"):]
    assert loop.index("load_died(load)") < loop.index("# load_alive=1")
    assert src.index("run_window(buf, scale, &r); /* discarded warm-up pass */") < src.index("print_metadata(cpu, (now_ns()")


def test_simulator_writes_bench_header_order_and_number_formats(tmp_path):
    from vsec.m4_detect import simulate
    assert simulate.bench_header() == bench_header()
    d = simulate.simulate(tmp_path / "s", per_class=1, windows=3)
    lines = (next(d.iterdir()) / "idle.csv").read_text().splitlines()
    assert lines[0].split(",") == bench_header()
    for line in lines[1:]:
        for col, field in zip(bench_header()[2:], line.split(",")[2:]):
            fmt = ".6g" if col in ("ipc", "dtlb_miss", "sleep_jitter_us") else ".4f"
            assert f"{float(field):{fmt}}" == field, (col, field)


def test_bench_compiles_without_warnings(tmp_path):
    pytest.importorskip("ziglang")
    import subprocess
    import sys
    cmd = [sys.executable, "-m", "ziglang", "cc", "-target", "x86_64-linux-gnu", "-O2", "-Wall", "-Wextra", "-c",
           str(BENCH_C), "-o", str(tmp_path / "bench.o")]
    done = subprocess.run(cmd, capture_output=True, text=True)
    assert done.returncode == 0 and done.stderr.strip() == "", done.stderr
