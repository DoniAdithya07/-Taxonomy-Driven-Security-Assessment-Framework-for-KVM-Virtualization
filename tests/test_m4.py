import json

import numpy as np
import pytest

from vsec.m4_detect import classify, features, simulate, stats

HEADER = "window,workload,elapsed_ms," + ",".join(features.RAW)  # signal columns in any order are accepted
ROW = "{k},{w},{e}," + ",".join(["1.5"] * len(features.RAW))
KW = dict(families=("logreg",), reps=30, repeats=1)
BENCH_HEADER = ",".join(simulate.bench_header())


def write_session(root, name, cls="native", rows=3, last=None, header=HEADER, elapsed=40, workloads=("idle",), extra=()):
    d = root / name
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"cls": cls}))
    for w in workloads:
        lines = [header] + [ROW.format(k=k, w=w, e=elapsed) for k in range(rows)] + list(extra)
        if last is not None:
            lines.append(last)
        (d / f"{w}.csv").write_text("\n".join(lines))
    return d


def fake_session(name, cls, elapsed, vals=None, meta=None):
    n = len(elapsed)
    arr = np.tile(np.arange(1.0, len(features.SIGNALS) + 1), (n, 1)) if vals is None else vals
    return {"session": name, "cls": cls, "meta": meta or {}, "windows": {"idle": arr},
            "elapsed": {"idle": np.array(elapsed)}, "missing_workloads": []}


@pytest.fixture(scope="session")
def sim_result(tmp_path_factory):
    """One analyze() on simulated sessions written to disk and read back, shared by every test that only inspects it."""
    ses = features.load(simulate.simulate(tmp_path_factory.mktemp("sim"), per_class=6, windows=30))
    # 0.11 s holds exactly the windows of 0.1 s (40 ms windows): collapsed, not evaluated twice
    r = classify.analyze(ses, t_short=0.2, ts=(0.1, 0.11, 0.5, 1.0), **KW | {"reps": 100})
    return ses, r


# ---- features: elapsed time, load, NaN, log ----

def test_table_uses_cumulative_elapsed_time():
    vals = np.arange(1, 1 + 5 * len(features.SIGNALS), dtype=float).reshape(5, -1)
    s = fake_session("a", "native", [100, 100, 300, 100, 100], vals)
    X, y, g, w, ex, used = features.table_ex([s], 0.25, ("native", "kvm-plain"))  # 100+100+300 >= 250 -> 3 windows
    assert ex == [] and np.allclose(X[0], np.median(np.log(vals[:3]), axis=0)) and used[0] == pytest.approx(0.5)
    X, *_ = features.table([s], 0.2, ("native",))  # exactly 200 ms reached after 2 windows
    assert np.allclose(X[0], np.median(np.log(vals[:2]), axis=0))
    X, y, g, w, ex, _ = features.table_ex([s], 1.0, ("native",))  # only 700 ms of data: excluded and counted
    assert len(X) == 0 and ex == [("a", "idle")]


def test_log_guards_nonpositive_and_mad_aggregation():
    assert np.isnan(features._log([0.0, -1.0, np.nan])).all() and features._log([np.e])[0] == pytest.approx(1.0)
    vals = np.ones((4, len(features.SIGNALS)))
    vals[0, 0] = 0.0  # a zero in a window makes that signal unavailable for the row
    s = fake_session("a", "native", [100] * 4, vals)
    X, *_ = features.table([s], 0.4, ("native",), agg="median+mad")
    assert X.shape == (1, 2 * len(features.SIGNALS)) and np.isnan(X[0, 0]) and X[0, 1] == 0.0
    assert features.feature_names("median+mad")[len(features.SIGNALS)] == features.SIGNALS[0] + "_mad"


def test_load_reads_elapsed_and_records_missing_workloads(tmp_path):
    write_session(tmp_path, "s1", elapsed=25, rows=4)
    (s,) = features.load(tmp_path)
    assert list(s["elapsed"]["idle"]) == [25] * 4 and s["missing_workloads"] == ["cpu", "mem", "mixed"]


def test_load_reads_day_and_batch(tmp_path):
    d = write_session(tmp_path, "s1")
    (d / "meta.json").write_text(json.dumps({"cls": "native", "day": "d1", "batch": 2}))
    (s,) = features.load(tmp_path)
    assert s["day"] == "d1" and s["batch"] == 2


def test_load_reads_order_boot_time_and_per_workload_temperatures(tmp_path):
    d = write_session(tmp_path, "s1")
    meta = {"cls": "native", "order": 4, "minutes_since_boot": 12.5,
            "temp_before_c": {"idle": 40.0, "cpu": None}, "temp_after_c": {"idle": 44.0, "cpu": 50.0}}
    (d / "meta.json").write_text(json.dumps(meta))
    (s,) = features.load(tmp_path)
    assert (s["order"], s["minutes_since_boot"]) == (4, 12.5)
    assert s["temp_before_c"] == meta["temp_before_c"] and s["temp_after_c"] == meta["temp_after_c"]
    write_session(tmp_path, "s2")  # a session without the fields loads with None, not an error
    assert features.load(tmp_path)[1]["order"] is None


def test_load_rejects_unknown_class(tmp_path):
    write_session(tmp_path, "s1", cls="vmware")
    with pytest.raises(ValueError, match="unknown cls"):
        features.load(tmp_path)


def test_load_drops_truncated_last_row_only(tmp_path):
    write_session(tmp_path, "s1", rows=3, last="3,idle,40,1.5,1.5")
    assert len(features.load(tmp_path)[0]["windows"]["idle"]) == 3


def test_load_report_records_everything_load_skips_or_repairs(tmp_path):
    write_session(tmp_path, "s1", rows=3, last="3,idle,40,1.5,1.5", workloads=("idle", "cpu"))  # 2 cut-off rows
    write_session(tmp_path, "s2")
    (tmp_path / "notes").mkdir()  # not a session: no meta.json
    failed = write_session(tmp_path, "s3")
    (failed / "FAILED").write_text("session_meta.py failed\nmore")
    (tmp_path / "schedule.json").write_text("[]")  # a plain file is not a folder: ignored
    rep = features.load_report(tmp_path)
    assert rep["skipped_dirs"] == [{"dir": "notes", "reason": "no meta.json"},
                                   {"dir": "s3", "reason": "FAILED marker: session_meta.py failed"}]
    assert rep["sessions"] == [{"session": "s1", "missing_workloads": ["mem", "mixed"], "truncated_rows": 2},
                               {"session": "s2", "missing_workloads": ["cpu", "mem", "mixed"], "truncated_rows": 0}]
    assert rep["total_truncated_rows"] == 2
    sessions, rep2 = features.load_with_report(tmp_path)
    assert [s["session"] for s in sessions] == ["s1", "s2"] and rep2 == rep and sessions[0]["truncated_rows"] == 2


@pytest.mark.parametrize("text,what", [("[1, 2]", "list"), ("null", "NoneType"), ('"x"', "str"), ("{broken", "not valid JSON")])
def test_load_rejects_meta_that_is_not_a_json_object_naming_the_file(tmp_path, text, what):
    d = write_session(tmp_path, "s1")
    (d / "meta.json").write_text(text)
    with pytest.raises(ValueError, match=r"s1.meta\.json.*" + what):
        features.load(tmp_path)


def test_load_and_simulate_sessions_carry_the_same_keys(tmp_path):
    from_disk = features.load(simulate.simulate(tmp_path / "s", per_class=1, windows=5))
    in_memory = simulate.simulate_sessions(per_class=1, windows=5)
    assert set(from_disk[0]) == set(in_memory[0]) >= {"order", "minutes_since_boot", "temp_before_c", "temp_after_c",
                                                      "batch", "day", "missing_workloads", "truncated_rows"}
    assert [s["order"] for s in in_memory] == [0, 1, 2]


def test_load_rejects_header_only_and_malformed(tmp_path):
    write_session(tmp_path / "a", "s1", rows=0)
    with pytest.raises(ValueError, match="no data rows"):
        features.load(tmp_path / "a")
    write_session(tmp_path / "b", "s1", rows=2, extra=["2,idle,40,1.5,1.5", "3,idle,40," + ",".join(["1.5"] * 10)])
    with pytest.raises(ValueError, match="malformed"):
        features.load(tmp_path / "b")  # short row in the middle
    write_session(tmp_path / "c", "s1", rows=2, last=ROW.format(k=9, w="idle", e="abc"))
    with pytest.raises(ValueError, match="malformed"):
        features.load(tmp_path / "c")
    write_session(tmp_path / "d", "s1", rows=2, elapsed=0)
    with pytest.raises(ValueError, match="elapsed_ms"):
        features.load(tmp_path / "d")
    write_session(tmp_path / "e", "s1", header=HEADER.replace("elapsed_ms", "ms"))
    with pytest.raises(ValueError, match="header"):
        features.load(tmp_path / "e")


def test_median_is_nan_if_any_value_is_nan_and_tlb_ratio_never_inf():
    a = np.array([[1.0, 1.0], [np.nan, 2.0], [3.0, 3.0]])
    m = features._median_nan(a)
    assert np.isnan(m[0]) and m[1] == 2.0
    raw = np.ones((2, len(features.RAW)))
    raw[0, features.RAW.index("seq_ns")] = 0.0
    raw[1, features.RAW.index("seq_ns")] = -1.0
    assert np.isnan(features.add_derived(raw)[:, features.SIGNALS.index("tlb_ratio")]).all()


def test_no_usable_columns_is_a_clear_error():
    X = np.full((10, len(features.SIGNALS)), np.nan)
    y, g, w = np.array([0, 1] * 5), np.array(list("abcdefghij")), np.array(["idle"] * 10)
    with pytest.raises(ValueError, match="no usable signal"):
        classify.oof_scores(X, y, g, w, "logreg", "combined")


def test_simulate_writes_elapsed_and_renamed_columns(tmp_path):
    d = simulate.simulate(tmp_path / "s", per_class=1, windows=5)
    first = (next(d.iterdir()) / "idle.csv").read_text().splitlines()
    assert first[0] == BENCH_HEADER and "cpuid_tsc" in first[0] and "cpuid_cyc" not in first[0]
    assert first[0].index("sleep_jitter_us") < first[0].index("ipc")  # bench.c's order, not the Python order
    assert 30 < float(first[1].split(",")[2]) < 50
    assert {s["cls"] for s in features.load(d)} == set(features.CLASSES)


# ---- features: confounds, indicators, balance ----

def test_confounds_flag_fields_and_clocksource_gate():
    mk = lambda n, c, **m: {"session": n, "cls": c, "meta": m}  # noqa: E731
    ses = [mk("a", "native", clocksource="tsc", governor="performance"),
           mk("b", "kvm-masked", clocksource="hpet", governor="performance"), mk("c", "kvm-plain")]
    c = features.confounds(ses)
    assert c["clocksource"]["differs"] is True and c["clocksource"]["values"]["kvm-masked"] == ["hpet"]
    assert c["governor"]["differs"] is False  # kvm-plain has none recorded: unreadable in a guest, not 'differs'
    assert c["governor"]["unreadable_in_class"] == ["kvm-plain"] and "kvm-plain" not in c["governor"]["values"]
    assert c["kernel"]["differs"] is False
    assert c["nproc"]["differs"] is False and c["nproc"]["values"] == {"native": ["<missing>"],
                                                                      "kvm-masked": ["<missing>"], "kvm-plain": ["<missing>"]}
    assert c["clocksource_gate"] == {"failures": ["b"], "unknown": ["c"], "flagged_classes": ["kvm-masked"]}


def test_perf_exposed_is_reported_per_class():
    vals = np.ones((3, len(features.SIGNALS)))
    nan = vals.copy()
    nan[:, features.SIGNALS.index("ipc")] = np.nan
    ses = [fake_session("a", "native", [100] * 3, vals), fake_session("b", "kvm-masked", [100] * 3, nan)]
    p = features.perf_exposed(ses)
    assert p["native"]["ipc"] == 1 and p["kvm-masked"]["ipc"] == 0 and p["kvm-masked"]["dtlb_miss"] == 1


def test_indicator_table_is_none_without_native_or_masked_and_ignores_counters():
    mk = lambda c, **i: {"cls": c, "meta": {"indicators": i}}  # noqa: E731
    ses = [mk("native", hv_bit=False, uptime=123), mk("kvm-masked", hv_bit=True, uptime=456, dmi_kvm=True),
           mk("kvm-plain", only_plain=True)]
    t = {r["indicator"]: r for r in features.indicator_table(ses)}
    assert set(t) == {"hv_bit", "dmi_kvm", "only_plain"}
    assert t["hv_bit"]["masked_leaks"] is True and t["dmi_kvm"]["masked_leaks"] is None
    assert t["only_plain"]["masked_leaks"] is None


def test_indicator_table_compares_string_indicators_per_class():
    mk = lambda c, **i: {"cls": c, "meta": {"indicators": i}}  # noqa: E731
    ses = [mk("native", dmi_sys_vendor="Dell Inc.", disk_model="NVMe X", nic_driver="e1000e", systemd_detect_virt="none"),
           mk("kvm-masked", dmi_sys_vendor="QEMU", disk_model="NVMe X", nic_driver="e1000e", systemd_detect_virt="none"),
           mk("kvm-plain", dmi_sys_vendor="QEMU")]
    t = {r["indicator"]: r for r in features.indicator_table(ses)}
    assert t["dmi_sys_vendor"]["masked_leaks"] is True and t["dmi_sys_vendor"]["native"] == ["Dell Inc."]
    assert t["dmi_sys_vendor"]["kvm-masked"] == ["QEMU"] and t["dmi_sys_vendor"]["kvm-plain"] == ["QEMU"]
    assert t["disk_model"]["masked_leaks"] is False and t["nic_driver"]["masked_leaks"] is False
    assert t["systemd_detect_virt"]["masked_leaks"] is False


def test_indicator_table_counts_unreadable_values_and_keeps_none_for_a_missing_class():
    mk = lambda c, **i: {"cls": c, "meta": {"indicators": i}}  # noqa: E731
    ses = [mk("native", dmi_product_name="Latitude", dmesg_hypervisor=None),
           mk("native", dmi_product_name=None, dmesg_hypervisor=None),
           mk("kvm-masked", dmi_product_name="  ", dmesg_hypervisor=None, uptime=5),
           mk("kvm-plain", dmi_product_name="KVM")]
    t = {r["indicator"]: r for r in features.indicator_table(ses)}
    assert t["dmi_product_name"]["unreadable"] == {"native": 1, "kvm-plain": 0, "kvm-masked": 1}
    assert t["dmi_product_name"]["masked_leaks"] is None  # masked has no readable value: neither leak nor match
    assert t["dmesg_hypervisor"]["unreadable"] == {"native": 2, "kvm-plain": 0, "kvm-masked": 1}
    assert t["dmesg_hypervisor"]["masked_leaks"] is None and "uptime" not in t


def test_balance_handles_missing_and_bad_values():
    ses = [{"cls": "native", "meta": {"temp_c": None, "time": "xx"}}, {"cls": "kvm-masked", "meta": {}}]
    b = features.balance(ses)
    assert b["temp_c"]["mean"] == {} and b["temp_c"]["imbalanced"] is None and b["hour"]["imbalanced"] is None
    assert b["temp_c"]["n_unreadable"] == {"native": 1, "kvm-masked": 1}


@pytest.mark.parametrize("bad", ["hot", [40.0, 41.0], 42.0, {"idle": "warm"}, {"idle": float("nan")}])
def test_balance_ignores_unusable_temperature_fields_and_counts_them(bad):
    ses = [{"cls": "native", "meta": {"temp_c": 50.0, "temp_before_c": bad, "temp_after_c": bad}},
           {"cls": "kvm-masked", "meta": {"temp_c": 52.0}}]
    b = features.balance(ses)["temp_c"]
    assert b["unusable_temp_sessions"] == 1 and b["mean"] == {"native": 50.0, "kvm-masked": 52.0}  # temp_c fallback


def test_balance_order_is_never_the_list_position():
    ses = [{"cls": "native", "meta": {}}, {"cls": "kvm-masked", "meta": {"order": "7"}},
           {"cls": "kvm-masked", "meta": {"order": 3}}, {"cls": "native", "meta": {"order": True}}]
    o = features.balance(ses)["order"]
    assert o["mean"] == {"kvm-masked": 3.0} and o["n_unreadable"] == {"native": 2, "kvm-masked": 1}


def test_confounds_flag_cpu_topology_differences():
    mk = lambda n, c, **m: {"session": n, "cls": c, "meta": m}  # noqa: E731
    c = features.confounds([mk("a", "native", nproc=8, smt_active="1", online_cpus="0-7"),
                            mk("b", "kvm-masked", nproc=2, smt_active="0", online_cpus="0-1")])
    assert all(c[f]["differs"] for f in ("nproc", "smt_active", "online_cpus"))
    assert c["nproc"]["values"]["native"] == ["8"]


def test_balance_prefers_mean_of_before_after_temperatures():
    temps = lambda t: {"temp_c": 99.0, "temp_before_c": {"idle": t, "cpu": None}, "temp_after_c": {"idle": t + 2, "cpu": t + 4}}  # noqa: E731
    ses = [{"cls": "native", "meta": temps(40.0)}, {"cls": "kvm-masked", "meta": {"temp_c": 60.0}}]
    m = features.balance(ses)["temp_c"]["mean"]
    assert m["native"] == pytest.approx(42.0) and m["kvm-masked"] == 60.0  # temp_c only used as the fallback


def test_balance_uses_standardized_mean_differences():
    rng = np.random.default_rng(0)
    ses = [{"cls": "native", "meta": {"temp_c": 50 + rng.normal()}} for _ in range(10)] + \
          [{"cls": "kvm-masked", "meta": {"temp_c": 55 + rng.normal()}} for _ in range(10)]
    b = features.balance(ses)
    assert b["temp_c"]["smd"]["native_vs_kvm-masked"] > 2 and b["temp_c"]["imbalanced"] is True
    assert b["minutes_since_boot"]["imbalanced"] is None and "order" in b


# ---- stats ----

def test_fpr_at_tpr_allows_one_miss_at_point_nine():
    y = np.array([0] * 10 + [1] * 10)
    s = np.array(list(np.linspace(0, 0.4, 10)) + [0.9] * 9 + [0.1])  # 9 of 10 positives above all negatives
    assert stats.fpr_at_tpr(y, s, classify.TPR_TARGET) == 0.0
    assert stats.fpr_at_tpr(y, s, 1.0) > 0.0


def test_paired_bootstrap_uses_same_sessions_and_detects_difference():
    rng = np.random.default_rng(2)
    y = np.repeat([0, 1], 30)
    good, bad = y + rng.normal(0, 0.4, 60), rng.normal(0, 1, 60)
    d = stats.paired_bootstrap(y, good, bad, reps=300)
    assert d["diff"] > 0.2 and d["lo"] > 0 and d["p"] < 0.05 and d["dropped"] == 0
    same = stats.paired_bootstrap(y, good, good, reps=100)
    assert same["diff"] == 0 and same["p"] == 1.0  # no difference: every bootstrap diff is 0 <= 0


def test_bootstrap_counts_dropped_replicates_and_youden():
    r = stats.bootstrap_full(lambda b: np.nan if b[0] % 2 else 1.0, 10, reps=100)
    assert r["dropped"] > 0 and r["dropped"] + len(r["vals"]) == 100
    assert 0.4 < stats.youden_threshold(np.array([0, 0, 1, 1]), np.array([0.1, 0.3, 0.6, 0.9])) <= 0.6
    assert stats.youden_threshold(np.array([1, 1]), np.array([0.2, 0.3])) == 0.5
    point, lo, hi, dropped = stats.bootstrap(lambda b: np.nan if b[0] % 2 else 1.0, 10, reps=100)
    assert dropped > 0 and point == 1.0 and lo == hi == 1.0


def test_youden_threshold_ex_says_when_it_fell_back_to_half():
    y = np.array([0, 0, 1, 1])
    assert stats.youden_threshold_ex(y, np.array([0.1, 0.3, 0.6, 0.9])) == (pytest.approx(0.6), False)
    assert stats.youden_threshold_ex(np.array([1, 1]), np.array([0.2, 0.3])) == (0.5, True)  # one class
    assert stats.youden_threshold_ex(y, np.array([0.9, 0.8, 0.2, 0.1])) == (0.5, True)  # inverted: best point is 'accept none'


# ---- classify units ----

def test_inner_pick_raises_when_every_inner_fold_fails():
    X = np.random.default_rng(0).normal(size=(8, 3))
    y, g = np.zeros(8, dtype=int), np.arange(8)
    with pytest.raises(ValueError, match="inner CV failed"):
        classify.inner_pick_ex("logreg", X, y, g, [[0], [1]], 0)


def test_avg_counts_rows_scored_in_only_some_repeats():
    mean, partial = classify._avg_ex([np.array([1.0, np.nan, np.nan]), np.array([3.0, 4.0, np.nan])])
    assert mean[0] == 2.0 and mean[1] == 4.0 and np.isnan(mean[2]) and partial == 1  # col 2 never scored: not 'partial'


def test_youden_fallbacks_are_counted_in_the_result(monkeypatch):
    ses = pilot()
    args = (ses, classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1)
    monkeypatch.setattr(classify.S, "youden_threshold_ex", lambda y, s: (0.5, True))
    info = classify.evaluate_at(*args, modes=("single",))["info"]
    assert info["youden_fallbacks"] == 5 and info["rows_partially_scored"] == 0  # one per outer fold


def test_class_without_enough_scored_sessions_after_cv_is_insufficient(monkeypatch):
    monkeypatch.setattr(classify, "oof_scores", lambda X, y, *a, **k: np.where(y == 1, np.nan, 0.3))
    with pytest.raises(classify.Insufficient, match="out-of-fold score") as ei:
        classify.evaluate_at(pilot(), classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, modes=("single",))
    assert ei.value.counts["kvm-masked"] == 0


def boom(*a, **k):
    raise ValueError("operands could not be broadcast together")


def test_only_insufficient_becomes_na_other_value_errors_propagate(monkeypatch):
    ses = pilot(2, 5)
    monkeypatch.setattr(classify, "evaluate_at", boom)
    with pytest.raises(ValueError, match="broadcast"):
        classify._sensitivity(ses, 0.1, "logreg", 10, 0, 1)
    with pytest.raises(ValueError, match="broadcast"):
        classify.analyze(ses, t_short=0.1, ts=(0.1,), **KW)
    r = {"info": {"selection": {"combined_C": {"1.0": 3}}}, "combined": {"auroc": 0.9}}
    with pytest.raises(ValueError, match="broadcast"):
        classify.extra_arms(r, ses, classify.PRIMARY_PAIR, 0.1, "logreg")
    short = classify.Insufficient("fewer than 5 sessions", {"native": 2})
    monkeypatch.setattr(classify, "evaluate_at", lambda *a, **k: (_ for _ in ()).throw(short))
    assert classify._sensitivity(ses, 0.1, "logreg", 10, 0, 1)["status"] == "NA"
    assert classify.extra_arms(r, ses, classify.PRIMARY_PAIR, 0.1, "logreg")["single_C_fixed_1"]["status"] == "NA"
    res = classify.analyze(ses, t_short=0.1, ts=(0.1,), load_info={"total_truncated_rows": 4}, **KW)
    assert res["status"] == "NA" and res["load_report"] == {"total_truncated_rows": 4} and res["n_sessions"] == {"native": 2}


def fake_bootstrap(vals, dropped):
    return lambda *a, **k: {"point": 0.01, "lo": 0.0, "hi": 0.03, "vals": np.array(vals), "dropped": dropped}


@pytest.mark.parametrize("vals,dropped,none", [([], 100, True), ([0.01] * 70, 30, True), ([0.01] * 80, 20, False),
                                               ([0.01] * 100, 0, False)])
def test_h3_is_none_not_false_when_the_bootstrap_is_unreliable(monkeypatch, vals, dropped, none):
    monkeypatch.setattr(classify.S, "bootstrap_full", fake_bootstrap(vals, dropped))
    h3 = classify._h3(pilot(), "logreg", 0.1, 100, 0, 1)
    if none:
        assert h3["supported_raw"] is None and h3["p"] is None and h3["status"] == "NA"
        assert "replicates" in h3["reason"] and h3["dropped_replicates"] == dropped
    else:
        assert h3["supported_raw"] is True and h3["p"] is not None  # exactly 20% dropped is still allowed


def test_every_bootstrap_ci_applies_the_twenty_percent_rule():
    good = {"diff": 0.2, "lo": 0.1, "hi": 0.3, "p": 0.01, "n_valid": 80, "dropped": 20}
    assert classify._pb(good)["ci"] == [0.1, 0.3] and classify._pb(good)["unreliable"] is None
    for bad in ({**good, "n_valid": 79, "dropped": 21}, {**good, "n_valid": 0, "dropped": 100}):
        r = classify._pb(bad)
        assert r["ci"] == [None, None] and r["p_one_sided"] is None and "replicates" in r["unreliable"]
        assert r["diff"] == 0.2  # the point estimate is still shown


def test_h4_formula():
    ok = classify.h4_decision(4.0)
    assert ok["supported"] is True and ok["cpu_percent"] == pytest.approx(100 * 4 / 300)
    bad = classify.h4_decision(12.0)
    assert bad["supported"] is False and bad["cpu_percent"] == pytest.approx(4.0)
    ten = classify.h4_decision(10.0)  # the 10 s limit is strict and binding (3.3% overhead is fine)
    assert ten["supported"] is False and ten["cpu_percent"] < 5
    assert classify.h4_decision(None)["supported"] is False  # AUROC 0.95 never reached
    assert classify.h4_decision(None, curve_complete=False)["supported"] is None


def stub_aurocs(monkeypatch, aur, calls=None):
    """evaluate_at stub: AUROC per T from `aur`; a value that is an Exception is raised instead."""
    def fake(sessions, pair, t, fam, seed, repeats, **kw):
        if calls is not None:
            calls.append(kw)
        if isinstance(aur[t], Exception):
            raise aur[t]
        return {"single": {"auroc": aur[t]}}
    monkeypatch.setattr(classify, "evaluate_at", fake)


TS3 = (0.1, 0.5, 1.0)


def test_choose_t_short_rule_picks_shortest_unsaturated_t(monkeypatch):
    stub_aurocs(monkeypatch, {0.1: 0.99, 0.5: 0.85, 1.0: 0.95})  # 0.1 is saturated, 0.5 is the shortest below 0.90
    r = classify.choose_t_short([], ts=TS3)
    assert r["t_short"] == 0.5 and r["reason"] is None and r["errors"] == {} and r["ceiling"] is False


def test_choose_t_short_ceiling_only_when_every_t_is_measured_and_at_least_099(monkeypatch):
    stub_aurocs(monkeypatch, {0.1: 0.99, 0.5: 0.99, 1.0: 1.0})
    r = classify.choose_t_short([], ts=TS3)
    assert r["t_short"] is None and r["ceiling"] is True and "untestable" in r["reason"]
    stub_aurocs(monkeypatch, {0.1: 0.99, 0.5: 0.95, 1.0: 1.0})  # >= 0.90 everywhere but not at the ceiling
    r = classify.choose_t_short([], ts=TS3)
    assert r["t_short"] is None and r["ceiling"] is False and "untestable" not in r["reason"]


def test_choose_t_short_unevaluable_t_gives_none_and_no_ceiling_claim(monkeypatch):
    for bad, label in ((classify.Insufficient("fewer than 5 sessions", {"native": 2}), "insufficient data"),
                       (ValueError("shape mismatch"), "error: shape mismatch"), (float("nan"), "NaN")):
        stub_aurocs(monkeypatch, {0.1: 1.0, 0.5: bad, 1.0: 1.0})  # the measured T are all at the ceiling
        r = classify.choose_t_short([], ts=TS3)
        assert r["t_short"] is None and r["reason"].startswith("could not evaluate at T=0.5: ")
        assert label in r["reason"] and "untestable" not in r["reason"] and set(r["errors"]) == {0.5}
    stub_aurocs(monkeypatch, {0.1: 0.5, 0.5: classify.Insufficient("x"), 1.0: 0.5})  # a good T_short must not be picked either
    assert classify.choose_t_short([], ts=TS3)["t_short"] is None


def test_choose_t_short_needs_signal_at_the_longest_t_and_a_sane_auroc(monkeypatch):
    stub_aurocs(monkeypatch, {0.1: 0.5, 0.5: 0.6, 1.0: 0.85})
    r = classify.choose_t_short([], ts=TS3)
    assert r["t_short"] is None and r["reason"] == ("no signal reaches AUROC 0.90 even at the longest T: pilot "
                                                    "cannot pick T_short (check data quality)")
    stub_aurocs(monkeypatch, {0.1: 0.3, 0.5: 0.6, 1.0: 0.95})  # T=0.1 would be chosen from an AUROC below chance
    r = classify.choose_t_short([], ts=TS3)
    assert r["t_short"] is None and "below 0.5" in r["reason"] and "suspicious" in r["reason"]


def test_choose_t_short_passes_min_sessions_without_touching_the_global(monkeypatch):
    calls = []
    stub_aurocs(monkeypatch, {0.1: 0.7, 0.5: 0.8, 1.0: 0.95}, calls)
    assert classify.choose_t_short([], ts=TS3, min_sessions=3)["t_short"] == 0.1
    assert {c["min_sessions"] for c in calls} == {3} and classify.MIN_SESSIONS == 5


PILOT_TS = (0.1, 0.2)
ONE_T = (0.1,)  # a single T keeps the real-CV pilot tests fast


def pilot(per_class=5, windows=12, **kw):
    return simulate.simulate_sessions(per_class=per_class, windows=windows, **kw)


def test_pilot_with_two_sessions_per_class_has_no_t_short_and_says_why():
    r = classify.choose_t_short(pilot(2), ts=PILOT_TS)
    assert r["t_short"] is None and r["reason"].startswith("could not evaluate at T=0.1, 0.2: ")
    assert "fewer than 5 sessions" in r["reason"] and "untestable" not in r["reason"]
    assert all(np.isnan(v) for v in r["single_auroc"].values()) and set(r["errors"]) == set(PILOT_TS)


def test_pilot_min_sessions_is_a_parameter_not_a_global():
    ses = pilot(3)
    assert classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, modes=("single",),
                                min_sessions=3)["single"]["auroc"] > 0.5
    with pytest.raises(classify.Insufficient, match="fewer than 5 sessions") as ei:
        classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, modes=("single",))
    assert ei.value.min_sessions == 5 and ei.value.counts == {"native": 3, "kvm-masked": 3}
    assert classify.MIN_SESSIONS == 5


def test_pilot_with_one_class_missing_has_no_t_short():
    ses = [s for s in pilot() if s["cls"] != "kvm-masked"]
    r = classify.choose_t_short(ses, ts=ONE_T)
    assert r["t_short"] is None and "could not evaluate" in r["reason"] and "'kvm-masked': 0" in r["reason"]


def test_pilot_with_identical_values_has_no_signal():
    ses = [fake_session(f"s{i}", c, [100] * 30) for i, c in enumerate(["native", "kvm-masked"] * 6)]
    r = classify.choose_t_short(ses, ts=ONE_T)
    assert r["t_short"] is None and r["errors"] == {} and "no signal reaches AUROC 0.90" in r["reason"]
    assert all(v <= 0.6 for v in r["single_auroc"].values())  # constant features: chance (fold priors can dip below 0.5)


def test_pilot_with_nan_columns_has_no_t_short():
    ses = pilot()
    for s in ses:
        for a in s["windows"].values():
            a[:, :] = np.nan
    r = classify.choose_t_short(ses, ts=ONE_T)
    assert r["t_short"] is None and "could not evaluate" in r["reason"] and "no usable signal" in r["reason"]


def test_pilot_with_only_the_idle_workload_runs():
    ses = pilot()
    for s in ses:
        s["windows"], s["elapsed"] = {"idle": s["windows"]["idle"]}, {"idle": s["elapsed"]["idle"]}
    r = classify.choose_t_short(ses, ts=ONE_T)
    assert r["errors"] == {} and all(0.5 < v <= 1.0 for v in r["single_auroc"].values())
    assert r["t_short"] is None and r["ceiling"] is True  # CPUID separates the simulated classes perfectly


def test_leave_one_day_out_needs_three_days():
    ses = simulate.simulate_sessions(per_class=6, windows=10, n_days=2)
    with pytest.raises(ValueError, match="leave-one-day-out"):
        classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.1, "logreg", repeats=1, cv="day")


# ---- analyze() ----

def test_status_na_on_tiny_data():
    ses = simulate.simulate_sessions(per_class=3, windows=10)
    r = classify.analyze(ses, t_short=0.2, ts=(0.1,), **KW)
    assert r["status"] == "NA" and "fewer than 5" in r["reason"] and "H1" not in r


def test_status_na_when_every_signal_is_nan():
    ses = simulate.simulate_sessions(per_class=6, windows=10)
    for s in ses:
        for a in s["windows"].values():
            a[:, :] = np.nan
    r = classify.analyze(ses, t_short=0.2, ts=(0.1,), **KW)
    assert r["status"] == "NA" and "no usable" in r["reason"]


def test_ceiling_makes_h1_untestable_not_failed(sim_result):
    _, r = sim_result
    # CPUID alone separates the default simulation at every T (all evaluated): the combination cannot beat it
    assert r["H1"]["status"] == "untestable" and r["H1"]["supported"] is None and "ceiling" in r["H1"]["reason"]
    assert min(r["H1"]["auroc_by_T"]["single"]) >= 0.99


def test_result_reports_sessions_signals_cost_and_curve_flags(sim_result):
    _, r = sim_result
    assert r["n_sessions"] == {"native": 6, "kvm-masked": 6}
    assert r["dropped_sessions"] == {} and "cpuid_tsc" in r["signals_used"] and r["signals_dropped"] == []
    c = r["curve"]["logreg"]
    assert c["t"] == [0.1, 0.5, 1.0] and c["grid"][1] == {"t": 0.11, "duplicate_of": 0.1}  # collapsed grid
    assert c["n_sessions"][0] == {"native": 6, "kvm-masked": 6} and c["session_set_differs"] == [False] * 3
    assert c["point_failures"] == {} and not np.isnan(c["combined_auroc"]).any()
    # real seconds: decision cost = 4 workloads x (measured start-up ~1.5 s + measured seconds >= T)
    assert r["startup_source"] == "measured" and r["H4"]["startup_source"] == "measured"
    assert 4 * (1.5 + 0.5) <= c["cost_s"][1] <= 4 * (1.55 + 0.5 + 0.06)
    assert c["cost_single_workload_s"][1] == pytest.approx(c["cost_s"][1] / 4, abs=0.05)
    assert "not resampled" in r["ci_note"] and r["perf_exposed"]["native"]["ipc"] == 6
    assert r["youden_fallbacks"] == 0 and r["rows_partially_scored"] == 0 and r["load_report"] is None


def test_curve_reports_real_seconds_windows_nan_fraction_and_secondary_metrics(sim_result):
    _, r = sim_result
    c = r["curve"]["logreg"]
    for i, t in enumerate(c["t"]):
        assert set(c["used_seconds"][i]) == set(c["windows_used"][i]) == {"native", "kvm-masked"}
        assert all(t <= v <= t + 0.05 for v in c["used_seconds"][i].values())  # whole windows: a bit over T
    assert c["windows_used"][0]["native"] == 3 and c["windows_used"][1]["native"] >= 12
    assert 0.5 <= c["combined_bal_acc"][2] <= 1.0 and 0.5 <= c["single_bal_acc"][2] <= 1.0
    assert set(r["nan_fraction"]) == {"0.1", "0.5", "1.0"}
    assert r["nan_fraction"]["0.5"]["native"]["cpuid_tsc"] == 0.0 and "tlb_ratio" in r["nan_fraction"]["0.5"]["kvm-masked"]
    assert r["settings"]["feature_set_T"] == 1.0 and "cpuid_tsc" in r["settings"]["feature_set"]
    assert r["settings"]["workloads_used"] == sorted(features.WORKLOADS) and r["settings"]["sessions_used"] == r["n_sessions"]


def test_run_with_too_few_sessions_is_exploratory_not_citable(sim_result):
    _, r = sim_result  # 8 sessions per class where 15 are expected
    assert r["status"] == "EXPLORATORY" and r["citable"] is False
    assert any("native: 6 sessions, expected exactly 15" in w for w in r["exploratory_reasons"])


def test_exploratory_reasons_need_exact_counts_and_all_four_workloads():
    ses = simulate.simulate_sessions(per_class=3, windows=4)
    assert classify._exploratory_reasons(ses, 3) == []
    assert "native: 3 sessions, expected exactly 4" in classify._exploratory_reasons(ses, 4)[0]
    del ses[0]["windows"]["mem"]
    why = classify._exploratory_reasons(ses, 3)
    assert len(why) == 1 and ses[0]["session"] in why[0] and "workloads" in why[0]


def test_secondary_analyses_and_selection_are_reported(sim_result):
    _, r = sim_result
    assert r["n_days"] == 3 and r["leave_one_day_out"]["supported"] in (True, False, None)
    assert "cpuid_tsc" not in r["H1_behaviour_only"]["signals_used"] and "p_one_sided" in r["H1_behaviour_only"]
    assert len(r["secondary_mad"]["signals_used"]) == 2 * 11 and r["secondary_mad"]["agg"] == "median+mad"
    assert r["leave_one_day_out"]["n_sessions"] == {"native": 6, "kvm-masked": 6}
    assert sum(r["selection"]["single_C"].values()) == 5  # one choice per outer fold, 1 repeat
    arms = r["single_arm_checks"]
    assert "auroc" in arms["single_C_fixed_1"] and "tlb_ratio" in arms["note"]
    assert set(r["H1"]["by_workload"]["combined"]) == set(features.WORKLOADS)
    assert r["H4"]["t95_ci"] is not None and r["H4"]["interval_s"] == 300.0
    arms = r["H1"]["arms"]  # H1: the pre-named cpuid_tsc arm and the non-nested best single, next to the nested one
    assert arms["cpuid_tsc"]["auroc"] >= 0.99 and arms["best_single_non_nested"]["auroc"] >= arms["cpuid_tsc"]["auroc"]
    assert arms["best_single_non_nested"]["signal"] in features.SIGNALS and "selection cost" in arms["nested_single"]["note"]
    assert arms["nested_single"]["auroc"] == r["H1"]["auroc_single"] and "optimistic" in arms["note"]


def test_h3_is_one_decision_per_session(sim_result):
    _, r = sim_result
    assert r["H3"]["n_sessions"] == 12  # sessions, not 48 rows
    h3 = r["H3"]
    assert 0 <= h3["auroc_held_workload"] <= 1 and h3["supported_raw"] in (True, False)
    assert h3["auroc_drop"] == pytest.approx(h3["auroc_in_distribution"] - h3["auroc_held_workload"])
    assert h3["f1_drop"] == pytest.approx(h3["f1_in_distribution"] - h3["f1_held_workload"])  # secondary, still there
    assert h3["dropped_replicates"] == 0


def test_session_predictions(sim_result):
    _, r = sim_result
    sp = r["session_predictions"]
    assert len(sp) == 12
    assert {p["declared"] for p in sp} == {"native", "kvm-masked"}
    assert sum(p["declared"] == p["predicted"] for p in sp) >= 9  # CPUID separates the simulated classes


def test_secondary_pairs_keep_full_results(sim_result):
    _, r = sim_result
    full = r["pairs_full"]["native_vs_kvm-plain"]["logreg"]
    assert len(full["combined"]["ids"]) == len(full["combined"]["score"]) == 12
    t = r["pairs"]["native_vs_kvm-plain"]["logreg"]["combined_vs_single"]
    assert 0 < t["p_one_sided"] <= 1 and "p_holm" in t
    assert set(r["holm"]) == {"H2", "H3", "native_vs_kvm-plain", "kvm-plain_vs_kvm-masked"}
    assert r["pairs"]["native_vs_kvm-plain"]["logreg"]["combined"]["auroc"] > 0.9


def holm_inputs(p2, p3, p_sec):
    pair = lambda: {"logreg": {"combined_vs_single": {"diff": 0.1}}}  # noqa: E731
    res = {"H2": {"p": p2, "supported_raw": True}, "H3": {"p": p3, "supported_raw": None if p3 is None else True},
           "pairs": {"native_vs_kvm-plain": pair(), "kvm-plain_vs_kvm-masked": pair()}}
    return res, {"native_vs_kvm-plain": p_sec, "kvm-plain_vs_kvm-masked": p_sec}


def test_holm_is_applied_to_supported():
    res, sec = holm_inputs(0.4, 0.5, 0.5)  # raw criterion met (CI > 0) but adjusted p is large
    classify._apply_holm(res, "logreg", sec)
    assert res["H2"]["supported"] is False and res["holm"]["H2"] >= 0.4
    assert res["pairs"]["native_vs_kvm-plain"]["logreg"]["combined_vs_single"]["supported"] is False
    res, sec = holm_inputs(0.001, 0.5, 0.001)
    classify._apply_holm(res, "logreg", sec)
    assert res["H2"]["supported"] is True and res["holm"]["H2"] == pytest.approx(0.004)
    assert res["pairs"]["native_vs_kvm-plain"]["logreg"]["combined_vs_single"]["supported"] is True
    assert res["H3"]["supported"] is False  # p = 0.5 adjusted stays above alpha


def test_supported_is_none_when_test_could_not_run():
    res, sec = holm_inputs(0.01, None, 0.5)  # H3 could not run
    classify._apply_holm(res, "logreg", sec)
    assert res["H3"]["supported"] is None and res["holm"]["H3"] is None
    assert set(res["holm"]) == {"H2", "H3", "native_vs_kvm-plain", "kvm-plain_vs_kvm-masked"}
    assert res["H2"]["supported"] is True and res["holm"]["H2"] == pytest.approx(0.04)  # family size stays 4


def test_gate_failures_are_reported_and_can_be_excluded(monkeypatch):
    # the slow secondary arms have their own tests; keep this one about the gate and the grid
    monkeypatch.setattr(classify, "_h3", lambda *a, **k: classify._na("stub", supported_raw=None, p=None))
    monkeypatch.setattr(classify, "signal_arms", lambda *a, **k: classify._na("stub"))
    monkeypatch.setattr(classify, "extra_arms", lambda *a, **k: {})
    ses = simulate.simulate_sessions(per_class=5, windows=10)
    bad = [s for s in ses if s["cls"] == "native"][:2]
    for s in bad:
        s["meta"] = {**s["meta"], "clocksource": "hpet"}
    r = classify.analyze(ses, t_short=0.2, ts=(0.1, 2.0), **KW)  # 10 windows ~ 0.4 s: T=2 cannot be evaluated
    assert r["clocksource_gate"]["failures"] == sorted(s["session"] for s in bad) or \
        set(r["clocksource_gate"]["failures"]) == {s["session"] for s in bad}
    assert r["gate_sensitivity"]["n_excluded"] == 2 and r["gate_sensitivity"]["status"] == "NA"  # native left with 3
    # the ceiling rule needs EVERY grid point evaluated: one failed point means 'NA with the reason', not 'untestable'
    assert "2.0" in r["curve"]["logreg"]["point_failures"] and np.isnan(r["curve"]["logreg"]["combined_auroc"][1])
    assert r["H1"]["status"] == "NA" and r["H1"]["supported"] is None and "2.0" in r["H1"]["reason"]
    r2 = classify.analyze(ses, t_short=0.2, ts=(0.1,), exclude_gate_failures=True, **KW)
    assert r2["status"] == "NA" and r2["n_sessions"]["native"] == 3


# ---- features: robust aggregation, fixed feature set, real-seconds grid ----

def test_one_bad_window_keeps_the_signal_but_a_mostly_bad_signal_is_nan():
    ipc = features.SIGNALS.index("ipc")
    vals = np.full((10, len(features.SIGNALS)), 2.0)
    vals[3, ipc] = 0.0  # one bad window in ten
    X, *_ = features.table([fake_session("a", "native", [100] * 10, vals)], 1.0, ("native",))
    assert np.isfinite(X).all() and X[0, ipc] == pytest.approx(np.log(2.0))
    vals[3, ipc] = 2.0
    vals[[1, 2], ipc] = 0.0  # 8 of 10 valid = MIN_VALID_FRAC: still a value
    assert np.isfinite(features.table([fake_session("a", "native", [100] * 10, vals)], 1.0, ("native",))[0][0, ipc])
    vals[4, ipc] = 0.0  # 7 of 10 valid: below the minimum fraction, NaN for the row
    X, *_ = features.table([fake_session("a", "native", [100] * 10, vals)], 1.0, ("native",))
    assert np.isnan(X[0, ipc]) and np.isfinite(np.delete(X[0], ipc)).all()


@pytest.mark.parametrize("sig", ["ipc", "dtlb_miss", "sleep_jitter_us"])
def test_zero_in_a_perf_or_jitter_column_is_missing_never_minus_infinity(sig):
    j = features.SIGNALS.index(sig)
    vals = np.full((5, len(features.SIGNALS)), 3.0)
    vals[:, j] = 0.0
    X, *_ = features.table([fake_session("a", "native", [100] * 5, vals)], 0.5, ("native",), agg="median+mad")
    assert np.isnan(X[0, j]) and not np.isinf(X).any()


def test_mad_aggregation_uses_the_same_valid_fraction_rule():
    vals = np.tile(np.arange(1.0, 6.0)[:, None], (1, len(features.SIGNALS)))  # 1..5 in every signal
    vals[0, 0] = np.nan
    X, *_ = features.table([fake_session("a", "native", [100] * 5, vals)], 0.5, ("native",), agg="median+mad")
    n = len(features.SIGNALS)
    assert np.isfinite(X[0, 0]) and np.isfinite(X[0, n])  # 4 of 5 valid: median and MAD both exist


def flipped(sessions):
    return [{**s, "cls": {"native": "kvm-masked", "kvm-masked": "native"}.get(s["cls"], s["cls"])} for s in sessions]


def test_fixed_columns_apply_the_twenty_percent_rule_and_never_look_at_labels():
    ipc, dtlb = features.SIGNALS.index("ipc"), features.SIGNALS.index("dtlb_miss")
    ses = [fake_session(f"s{i}", ["native", "kvm-masked"][i % 2], [100] * 5) for i in range(10)]
    for i in (0, 1):  # 2 of 10 rows: 20% NaN is still kept
        ses[i]["windows"]["idle"] = ses[i]["windows"]["idle"].copy()
        ses[i]["windows"]["idle"][:, ipc] = np.nan
    for i in (2, 3, 4):  # 3 of 10 rows: 30% NaN is dropped
        ses[i]["windows"]["idle"] = ses[i]["windows"]["idle"].copy()
        ses[i]["windows"]["idle"][:, dtlb] = np.nan
    fc = features.fixed_columns(ses, classify.PRIMARY_PAIR, (0.1, 0.5))
    assert "ipc" in fc["names"] and "dtlb_miss" not in fc["names"] and fc["T"] == 0.5
    assert fc["nan_fraction"]["ipc"] == pytest.approx(0.2) and fc["nan_fraction"]["dtlb_miss"] == pytest.approx(0.3)
    assert features.fixed_columns(flipped(ses), classify.PRIMARY_PAIR, (0.1, 0.5))["names"] == fc["names"]  # label-free
    assert features.fixed_columns([], classify.PRIMARY_PAIR, (0.1,))["names"] == []


def test_feature_set_is_fixed_once_and_does_not_change_with_T():
    ses = pilot()
    ipc = features.SIGNALS.index("ipc")
    for s in ses:
        for a in s["windows"].values():
            a[6:, ipc] = np.nan  # good for the 3 windows of T=0.1 s, bad in 4 of the 10 windows of T=0.4 s
    fixed = features.fixed_columns(ses, classify.PRIMARY_PAIR, (0.1, 0.4))
    assert fixed["T"] == 0.4 and "ipc" not in fixed["names"]
    for t in (0.1, 0.4):
        info = classify.evaluate_at(ses, classify.PRIMARY_PAIR, t, "logreg", 0, 1, modes=("rule",),
                                    columns=fixed["names"])["info"]
        assert info["signals_used"] == fixed["names"] and "ipc" in info["signals_dropped"]
    alone = classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, modes=("rule",))["info"]
    assert "ipc" in alone["signals_used"]  # a set chosen from T=0.1 alone would differ: that is why it is fixed once


def test_one_bad_window_does_not_drop_a_signal_for_every_row():
    ses = pilot()
    for s in ses:
        for a in s["windows"].values():
            a[0, :] = np.nan  # window 0 failed everywhere
    info = classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.4, "logreg", 0, 1, modes=("rule",))["info"]
    assert info["signals_used"] == features.SIGNALS and info["signals_dropped"] == []
    assert all(v == 0.0 for per in info["nan_fraction"].values() for v in per.values())


def test_rows_missing_a_kept_signal_are_imputed_from_training_data_only():
    Xtr, Xte = np.array([[1.0, 5.0], [3.0, np.nan], [2.0, 7.0]]), np.array([[np.nan, 100.0]])
    a, b = classify.impute(Xtr, Xte)
    assert a[1, 1] == 6.0 and b[0, 0] == 2.0 and b[0, 1] == 100.0  # medians of the TRAIN column, test untouched
    a, _ = classify.impute(np.full((2, 1), np.nan), Xte[:, :1])
    assert (a == 0).all()  # a column that is all NaN in the training fold becomes constant 0


def test_evaluate_at_reports_metrics_and_nan_fraction_per_class():
    r = classify.evaluate_at(pilot(), classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, modes=("rule",))
    rule = r["rule"]
    assert rule["n"] == {"native": 5, "kvm-masked": 5} and rule["bal_acc"] >= 0.9 and rule["auroc"] >= 0.99
    assert set(r["info"]["nan_fraction"]) == {"native", "kvm-masked"} and r["info"]["windows_used"]["native"] == 3
    assert 0.1 <= r["info"]["used_seconds"]["native"] <= 0.15


def test_collapse_grid_keeps_each_distinct_window_set_once():
    ses = [fake_session(f"s{i}", c, [100] * 20) for i, c in enumerate(["native", "kvm-masked"])]
    grid = features.collapse_grid(ses, classify.PRIMARY_PAIR, (0.1, 0.15, 0.2, 0.25))  # k = 1, 2, 2, 3
    assert [q["duplicate_of"] for q in grid] == [None, None, 0.15, None]
    assert features.collapse_grid([], classify.PRIMARY_PAIR, (0.1, 0.2)) == [{"t": 0.1, "duplicate_of": None},
                                                                              {"t": 0.2, "duplicate_of": None}]


def test_choose_t_short_evaluates_the_collapsed_grid_once_per_distinct_window_set(monkeypatch):
    ses = [fake_session(f"s{i}", c, [100] * 20) for i, c in enumerate(["native", "kvm-masked"] * 2)]
    seen, aur = [], {0.1: 0.95, 0.15: 0.8, 0.25: 0.95}

    def fake(sessions, pair, t, fam, seed, repeats, **kw):
        seen.append((t, tuple(kw["columns"])))
        return {"single": {"auroc": aur[t]}}
    monkeypatch.setattr(classify, "evaluate_at", fake)
    r = classify.choose_t_short(ses, ts=(0.1, 0.15, 0.2, 0.25))
    assert [t for t, _ in seen] == [0.1, 0.15, 0.25] and r["duplicate_of"] == {0.2: 0.15}
    assert set(r["single_auroc"]) == {0.1, 0.15, 0.25} and r["t_short"] == 0.15
    assert len({c for _, c in seen}) == 1  # one feature set for every T


# ---- features: strict CSV, load report, pilot ----

def rewrite(d, workload, fn):
    p = d / f"{workload}.csv"
    p.write_text("\n".join(fn(p.read_text().split("\n"))))


@pytest.mark.parametrize("what,fn,match", [
    ("wrong workload", lambda ls: ls[:-1] + [ls[-1].replace(",idle,", ",cpu,")], "does not match the file name"),
    ("window gap", lambda ls: ls[:2] + ls[3:], "window '2' where 1 was expected"),
    ("window starts at 1", lambda ls: [ls[0]] + [ls[i].replace(f"{i - 1},idle", f"{i},idle", 1) for i in (1, 2, 3)],
     "window '1' where 0 was expected"),
    ("repeated window", lambda ls: ls[:3] + [ls[1]], "window '0' where 2 was expected"),
])
def test_csv_workload_and_window_columns_are_checked(tmp_path, what, fn, match):
    d = write_session(tmp_path, "s1", rows=3)
    rewrite(d, "idle", fn)
    with pytest.raises(ValueError, match=match):
        features.load(tmp_path)


def test_truncated_last_row_is_still_dropped_but_a_malformed_full_row_is_rejected(tmp_path):
    write_session(tmp_path / "a", "s1", rows=3, last="3,idle,40,1.5")
    assert len(features.load(tmp_path / "a")[0]["windows"]["idle"]) == 3
    write_session(tmp_path / "b", "s1", rows=3, last=ROW.format(k=3, w="idle", e="4x0"))  # full field count, bad number
    with pytest.raises(ValueError, match="malformed"):
        features.load(tmp_path / "b")


def test_load_report_lists_row_count_mismatch_pilot_sessions_and_degenerate_windows(tmp_path):
    d = write_session(tmp_path, "s1", rows=4, workloads=("idle", "cpu", "mem"))
    rewrite(d, "mem", lambda ls: ls + [ROW.format(k=4, w="mem", e=40), ROW.format(k=5, w="mem", e=40)])
    rep = features.load_report(tmp_path)
    assert rep["row_count_mismatch"] == [{"session": "s1", "workload": "mem", "rows": 6, "median_rows": 4.0}]
    assert rep["pilot_sessions"] == []  # all-equal values: cpuid_tsc == rdtsc_tsc in every window of every workload
    assert rep["degenerate_windows"] == [{"session": "s1", "workload": w} for w in ("cpu", "mem", "idle")][::-1] or \
        sorted(x["workload"] for x in rep["degenerate_windows"]) == ["cpu", "idle", "mem"]
    (d / "meta.json").write_text(json.dumps({"cls": "native", "pilot": True}))
    assert features.load_report(tmp_path)["pilot_sessions"] == ["s1"]
    assert features.load(tmp_path)[0]["pilot"] is True  # still loaded: it is analyze() that refuses it


def test_simulated_sessions_have_no_degenerate_windows_or_row_count_mismatch(tmp_path):
    rep = features.load_report(simulate.simulate(tmp_path / "s", per_class=2, windows=6))
    assert rep["degenerate_windows"] == [] and rep["row_count_mismatch"] == [] and rep["pilot_sessions"] == []


def test_pilot_must_be_the_boolean_true_and_load_reads_the_new_meta_keys(tmp_path):
    d = write_session(tmp_path, "s1")
    meta = {"cls": "native", "pilot": "false", "workload_order": ["mem", "idle", "cpu", "mixed"],
            "bench_sha256": "ab12", "bench_startup_ms": {"idle": 1400.5, "cpu": 1900.0}}
    (d / "meta.json").write_text(json.dumps(meta))
    (s,) = features.load(tmp_path)
    assert s["pilot"] is False  # a string is not a pilot flag
    assert s["workload_order"] == meta["workload_order"] and s["bench_sha256"] == "ab12"
    assert s["bench_startup_ms"] == meta["bench_startup_ms"]
    (d / "meta.json").write_text(json.dumps({"cls": "native"}))
    assert features.load(tmp_path)[0]["pilot"] is False and features.load(tmp_path)[0]["bench_startup_ms"] is None


def test_analyze_refuses_pilot_sessions_and_names_them():
    ses = simulate.simulate_sessions(per_class=2, windows=4, pilot=True)
    assert all(s["pilot"] and s["meta"]["pilot"] is True for s in ses)
    with pytest.raises(ValueError, match=r"pilot.*" + ses[0]["session"]):
        classify.analyze(ses, t_short=0.1, ts=(0.1,), **KW)
    mixed = simulate.simulate_sessions(per_class=2, windows=4)
    mixed[0]["pilot"] = True
    with pytest.raises(ValueError, match=mixed[0]["session"]) as ei:
        classify.analyze(mixed, t_short=0.1, ts=(0.1,), **KW)
    assert mixed[1]["session"] not in str(ei.value)


def test_simulated_meta_carries_startup_order_and_hash():
    (s, *_) = simulate.simulate_sessions(per_class=1, windows=3)
    assert s["pilot"] is False and sorted(s["workload_order"]) == sorted(features.WORKLOADS)
    assert set(s["bench_startup_ms"]) == set(features.WORKLOADS) and all(1500 <= v <= 1550 for v in s["bench_startup_ms"].values())
    assert s["bench_sha256"] == "sim"


# ---- features: confounds ----

def test_confounds_unreadable_fields_bench_hash_and_python_version():
    mk = lambda n, c, **m: {"session": n, "cls": c, "meta": m}  # noqa: E731
    c = features.confounds([mk("a", "native", no_turbo=1, bench_sha256="x", python_version="3.12.1"),
                            mk("b", "kvm-masked", no_turbo=None, bench_sha256="x", python_version="3.11.9"),
                            mk("c", "kvm-plain", no_turbo=1, bench_sha256="x", python_version="3.12.1")])
    assert c["no_turbo"]["unreadable_in_class"] == ["kvm-masked"] and c["no_turbo"]["differs"] is False
    assert c["bench_sha256"]["differs"] is False and c["python_version"]["differs"] is True
    c = features.confounds([mk("a", "native", bench_sha256="x"), mk("b", "native", bench_sha256="y")])
    assert c["bench_sha256"]["differs"] is True  # one class, two binaries: still not identical across sessions
    assert features.confounds([mk("a", "native", governor="performance"), mk("b", "native", governor=None)])[
        "governor"]["unreadable_in_class"] == []  # only a WHOLE class without a value is 'unreadable'
    assert features.confounds([mk("a", "native", cmdline=None), mk("b", "kvm-masked", cmdline="x")])["cmdline"]["differs"]


# ---- H4 start-up, H3 on AUROC, H1 arms ----

def test_startup_is_measured_per_workload_else_assumed():
    s = {**fake_session("a", "native", [100] * 3), "bench_startup_ms": {"idle": 2000, "cpu": 0, "mem": "x", "mixed": True}}
    g = np.array(["a"])
    assert classify._startup_s([s], g, np.array(["idle"])) == (pytest.approx([2.0]), "measured")
    for wl in ("cpu", "mem", "mixed", "idle"):
        out, src = classify._startup_s([s], g, np.array([wl]))
        assert (src == "measured") == (wl == "idle") and out[0] == (2.0 if wl == "idle" else 1.5)
    assert classify._startup_s([s], np.array(["a", "zzz"]), np.array(["idle", "idle"]))[1] == "assumed"  # one unmeasured row
    assert classify._startup_s([fake_session("b", "native", [100])], np.array(["b"]), np.array(["idle"])) == (
        pytest.approx([classify.WARMUP_S + classify.LOAD_START_S]), "assumed")


def fake_oof_scores(held_scores):
    def fake(X, y, g, w, fam, mode, seed=0, lowo=None, columns=None, **kw):
        return y * 0.8 + 0.1 if lowo is None else held_scores(y, seed)
    return fake


def test_h3_compares_session_auroc_in_distribution_and_held_out(monkeypatch):
    monkeypatch.setattr(classify, "oof_scores", fake_oof_scores(lambda y, seed: np.random.default_rng(seed).random(len(y))))
    h3 = classify._h3(pilot(), "logreg", 0.1, 100, 0, 1)  # held-out workload scores are noise: a big AUROC drop
    assert h3["auroc_in_distribution"] == 1.0 and h3["auroc_drop"] == pytest.approx(1.0 - h3["auroc_held_workload"])
    assert h3["auroc_drop"] > 0.2 and h3["supported_raw"] is False and h3["upper95"] >= 0.05
    assert h3["f1_drop"] == pytest.approx(h3["f1_in_distribution"] - h3["f1_held_workload"]) and "f1_drop" in h3
    monkeypatch.setattr(classify, "oof_scores", fake_oof_scores(lambda y, seed: y * 0.8 + 0.1))
    h3 = classify._h3(pilot(), "logreg", 0.1, 100, 0, 1)  # held-out is as good as in-distribution: no drop
    assert h3["auroc_drop"] == 0.0 and h3["upper95"] < 0.05 and h3["supported_raw"] is True and h3["p"] < 0.05


def test_h3_holm_decision_needs_both_the_upper_bound_and_the_adjusted_p():
    res, sec = holm_inputs(0.001, 0.2, 0.001)  # raw criterion (upper95 < 0.05) met, but the Holm-adjusted p is 0.2
    res["H3"]["supported_raw"] = True
    classify._apply_holm(res, "logreg", sec)
    assert res["H3"]["supported"] is False
    res, sec = holm_inputs(0.001, 0.001, 0.001)
    classify._apply_holm(res, "logreg", sec)
    assert res["H3"]["supported"] is True


def test_signal_arms_report_cpuid_alone_and_the_non_nested_best_single():
    arms = classify.signal_arms(pilot(), classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1)
    assert set(arms["per_signal_auroc"]) == set(features.SIGNALS) and arms["cpuid_tsc"]["auroc"] >= 0.95
    best = arms["best_single_non_nested"]
    assert best["auroc"] == max(arms["per_signal_auroc"].values()) and best["auroc"] >= arms["cpuid_tsc"]["auroc"]
    with pytest.raises(classify.Insufficient, match="fewer than 5 sessions"):
        classify.signal_arms(pilot(3), classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1)
    only_syscall = classify.signal_arms(pilot(), classify.PRIMARY_PAIR, 0.1, "logreg", 0, 1, columns=["syscall_ns"])
    assert set(only_syscall["per_signal_auroc"]) == {"syscall_ns"} and only_syscall["cpuid_tsc"]["auroc"] is None


# ---- calibration of the H1 test ----

def _h1_trial(scenario, seed):
    ses = simulate.simulate_sessions(per_class=12, windows=12, scenario=scenario, seed=seed, no_cpuid=scenario == "gain")
    r = classify.evaluate_at(ses, classify.PRIMARY_PAIR, 0.3, "logreg", 0, 1, modes=("single", "combined"))
    y, c, s = classify._arrays(r)
    return stats.paired_bootstrap(y, c, s, stats.auroc, 300, seed)


@pytest.mark.slow
def test_h1_test_false_positive_rate_and_power():
    null = [_h1_trial("null", k) for k in range(6)]
    gain = [_h1_trial("gain", k) for k in range(6)]
    fp = np.mean([d["p"] < 0.05 for d in null])
    power = np.mean([d["p"] < 0.05 for d in gain])
    assert fp <= 0.10  # combining adds nothing: the test must not claim a gain
    assert power >= fp + 0.15  # combining adds real information: rejects clearly more often (low-n, modest power)
    assert np.mean([d["diff"] for d in gain]) > 0.05 > np.mean([d["diff"] for d in null])
