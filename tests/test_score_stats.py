import numpy as np
import pytest

from vsec import dump_json, score
from vsec.m4_detect import stats


def test_wilson_and_clopper_pearson():
    lo, hi = score.wilson(0, 10)
    assert lo == 0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = score.clopper_pearson(0, 10)
    assert lo == 0 and hi == pytest.approx(0.3085, abs=1e-3)
    assert score.clopper_pearson(10, 10)[1] == 1.0
    assert score.wilson(0, 0) == (0.0, 1.0)


def test_na_on_seeded_fault_is_a_miss():
    key = {"a": {"C01": "FAIL", "C02": "PASS"}}
    pred = {"a": {"C01": "NA", "C02": "FAIL"}}
    o = score.score_m1(pred, key)["overall"]
    assert (o["tp"], o["fn"], o["fp"], o["tn"]) == (0, 1, 1, 0)


def test_holm():
    adj = stats.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})


def test_fpr_at_tpr_and_auroc():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.6, 0.5, 0.7, 0.8, 0.9])
    assert stats.auroc(y, s) == pytest.approx(0.9375)
    assert stats.fpr_at_tpr(y, s, 1.0) == 0.25


def test_fpr_at_tpr_unreachable_is_nan_not_zero():
    # all-False argmax used to pick index 0 and report the best possible FPR (0.0)
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.8, 0.9])
    assert np.isnan(stats.fpr_at_tpr(y, s, 1.01))
    assert np.isnan(stats.fpr_at_tpr(np.zeros(4), s, 0.95))
    assert np.isnan(stats.fpr_at_tpr(np.ones(4), s, 0.95))


def test_prf_undefined_is_none_not_zero():
    p = score.prf(0, 0, 0, 0)
    assert p["precision"] is p["recall"] is p["f1"] is p["fpr"] is None
    assert p["fpr_ci"] == (0.0, 1.0)
    p = score.prf(0, 2, 0, 8)
    assert p["precision"] == 0.0 and p["recall"] is None and p["f1"] == 0.0
    assert p["fpr"] == 0.2 and p["fpr_ci"] == score.wilson(2, 10)


def test_ci_rejects_impossible_counts():
    for fn in (score.wilson, score.clopper_pearson):
        with pytest.raises(ValueError):
            fn(5, 3)
        with pytest.raises(ValueError):
            fn(-1, 3)


def test_na_on_clean_control_is_not_a_true_negative():
    key = {"a": {"C01": "PASS", "C02": "PASS", "C03": "NA", "C04": "NA", "C05": "NA"}}
    pred = {"a": {"C01": "NA", "C02": "PASS", "C03": "FAIL", "C04": "PASS", "C05": "NA"}}
    s = score.score_m1(pred, key)
    o = s["overall"]
    assert (o["tn"], o["na_on_pass"], o["fp"], o["na_violations"]) == (1, 1, 1, 1)
    assert s["per_control"]["C01"]["tn"] == 0 and s["per_control"]["C01"]["fpr"] is None
    assert (o["na_pred"], o["total"], o["coverage"]) == (2, 5, 0.4)


def test_json_dump_is_valid_with_numpy_and_nan(tmp_path):
    import json
    dump_json({"a": np.int64(3), "b": np.array([1.5, np.nan]), "c": float("inf"), "d": (1, 2)}, tmp_path / "x.json")
    assert json.loads((tmp_path / "x.json").read_text()) == {"a": 3, "b": [1.5, None], "c": None, "d": [1, 2]}
