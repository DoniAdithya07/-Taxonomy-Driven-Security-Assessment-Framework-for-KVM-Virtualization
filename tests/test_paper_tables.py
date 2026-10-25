"""Tests for scripts/make_paper_tables.py

Refusal rules, draft stamping, load errors, and (most important) the tables built from a REAL report that
`python -m vsec run --fast --simulate` wrote, so the key names the script reads are the keys the tool really writes.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
MAKE_TABLES = ROOT / "scripts" / "make_paper_tables.py"
STAMP = "**DRAFT: NOT CITABLE**"


def _run_make_tables(report_path, allow_draft=False):
    """Run make_paper_tables.py on a report file; return (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(MAKE_TABLES), str(report_path)]
    if allow_draft:
        cmd.append("--allow-draft")
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return result.returncode, result.stdout, result.stderr


def _write(tmp_path, report):
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    return p


def _base(**kw):
    return {"contains_simulated_or_synthetic": False, "modules_failed": [], "matrix": {"classes": {}, "vms": {}},
            "modules": {}, **kw}


def _table_rows(stdout):
    """List of tables, each a list of lines, in document order."""
    tables, cur = [], []
    for line in stdout.splitlines():
        if line.startswith("|"):
            cur.append(line)
        elif cur:
            tables.append(cur)
            cur = []
    if cur:
        tables.append(cur)
    return tables


def _assert_table_shape(stdout):
    for t in _table_rows(stdout):
        n = len(re.findall(r"(?<!\\)\|", t[0]))
        assert re.fullmatch(r"\|(---\|)+", t[1]), t[:2]
        assert t[1].count("---") == n - 1
        for row in t:
            assert len(re.findall(r"(?<!\\)\|", row)) == n, row


# ---- refusal rules ----

def test_refuses_simulated_data_without_allow_draft(tmp_path):
    code, _, stderr = _run_make_tables(_write(tmp_path, _base(contains_simulated_or_synthetic=True)))
    assert code == 2
    assert "simulated or synthetic" in stderr.lower()


def test_allows_simulated_data_with_allow_draft(tmp_path):
    code, stdout, _ = _run_make_tables(_write(tmp_path, _base(contains_simulated_or_synthetic=True)), allow_draft=True)
    assert code == 0
    assert "NOT CITABLE" in stdout


def test_refuses_module_error_even_with_allow_draft(tmp_path):
    report = _write(tmp_path, _base(modules_failed=[{"name": "M1", "reason": "Crash"}]))
    for draft in (False, True):
        code, _, stderr = _run_make_tables(report, allow_draft=draft)
        assert code == 2
        assert "failed" in stderr.lower()


@pytest.mark.parametrize("m4", [{"status": "EXPLORATORY"}, {"status": "ok", "citable": False}])
def test_refuses_m4_not_citable_unless_allow_draft(tmp_path, m4):
    report = _write(tmp_path, _base(modules={"M4 (hypervisor detection)": m4}))
    code, _, stderr = _run_make_tables(report)
    assert code == 2
    assert "exploratory" in stderr.lower()
    assert _run_make_tables(report, allow_draft=True)[0] == 0


def test_refuses_fast_report_without_allow_draft(tmp_path):
    code, _, stderr = _run_make_tables(_write(tmp_path, _base(fast=True)))
    assert code == 2
    assert "fast" in stderr.lower()


# ---- load errors: exit 3 with a clear message ----

def test_missing_report_file(tmp_path):
    code, _, stderr = _run_make_tables(tmp_path / "nonexistent.json")
    assert code == 3
    assert "cannot load" in stderr.lower()


def test_malformed_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {")
    code, _, stderr = _run_make_tables(bad)
    assert code == 3
    assert "cannot load" in stderr.lower()


def test_report_path_is_a_directory(tmp_path):
    code, _, stderr = _run_make_tables(tmp_path)
    assert code == 3
    assert "cannot load" in stderr.lower()


def test_report_not_utf8(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe\x00{\x80")
    code, _, stderr = _run_make_tables(bad)
    assert code == 3
    assert "cannot load" in stderr.lower()


def test_report_not_an_object(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2]")
    assert _run_make_tables(bad)[0] == 3


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_message(flag):
    result = subprocess.run([sys.executable, str(MAKE_TABLES), flag], capture_output=True, text=True)
    assert result.returncode == 0
    assert "report" in result.stdout.lower()


# ---- NOT RUN instead of empty or broken tables ----

def test_missing_and_na_modules_say_not_run(tmp_path):
    modules = {"M3 (forensics)": {"status": "NA", "reason": "no results: pass --m3-results"},
               "M4 (hypervisor detection)": {"status": "NA", "reason": "no M4 data"}}
    code, stdout, _ = _run_make_tables(_write(tmp_path, _base(modules=modules)))
    assert code == 0
    assert "NOT RUN: no results: pass --m3-results" in stdout
    assert "NOT RUN: no M4 data" in stdout
    assert "NOT RUN: module M1 is not in the report" in stdout  # absent module
    assert "NOT RUN: module M2 is not in the report" in stdout
    assert "NOT RUN: no threat-class matrix" in stdout


def test_errored_module_in_modules_dict_says_not_run(tmp_path):
    modules = {"M2 (snapshot privacy)": {"status": "ERROR", "reason": "boom"}}
    _, stdout, _ = _run_make_tables(_write(tmp_path, _base(modules=modules)))
    assert "NOT RUN: module errored: boom" in stdout


# ---- hand-made reports: values and escaping ----

def test_threat_class_table_uses_label_and_counts(tmp_path):
    matrix = {"classes": {"Guest->Guest": {"label": "Config-proxy", "controls": 3, "tested": 2, "na": 1,
                                           "effective_label": "Config-proxy"}},
              "vms": {"vm|1": {"Guest->Guest": {"status": "PASS", "tested": 2, "controls": 3, "na": 1}}}}
    code, stdout, _ = _run_make_tables(_write(tmp_path, _base(matrix=matrix)))
    assert code == 0
    assert "| Guest->Guest | Config-proxy | Config-proxy | 3 | 2 | 1 |" in stdout
    assert "| vm\\|1 | PASS (2/3) |" in stdout
    _assert_table_shape(stdout)


def test_m3_counts_when_present(tmp_path):
    m3 = {"detected": 7, "hidden_total": 8, "detection_ci": [0.62, 0.98], "false_items": 1, "clean_dumps": 4,
          "clean_with_alarm": 0, "clean_alarm_ci": [0.0, 0.5], "failures": ["img2"]}
    code, stdout, _ = _run_make_tables(_write(tmp_path, _base(modules={"M3 (forensics)": m3})))
    assert code == 0
    assert "| Hidden objects detected | 7 / 8 | [0.620, 0.980] |" in stdout
    assert "| Clean dumps with a false alarm | 0 / 4 | [0.000, 0.500] |" in stdout
    assert "img2" in stdout
    _assert_table_shape(stdout)


def test_missing_numbers_print_n_a_not_none(tmp_path):
    m2 = {"cells": {"aws/live": {"detected": 0, "present": 0, "recall": None, "ci": [0.0, 1.0]}},
          "real_programs": {"detected": 0, "present": 0, "recall": None, "ci": [0.0, 1.0]}}
    code, stdout, _ = _run_make_tables(_write(tmp_path, _base(modules={"M2 (snapshot privacy)": m2})))
    assert code == 0
    assert "| aws/live | 0 | 0 | n/a | [0.000, 1.000] |" in stdout
    assert not re.search(r"\b(None|nan)\b", stdout, re.IGNORECASE)


# ---- the real report ----

@pytest.fixture(scope="session")
def real_report(tmp_path_factory, fixtures):
    """A report.json written by the real `python -m vsec run --fast --simulate` (takes about a minute)."""
    out = tmp_path_factory.mktemp("real_run")
    r = subprocess.run([sys.executable, "-m", "vsec", "run", "--fast", "--simulate", "--out", str(out),
                        "--fixtures", str(fixtures)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode in (0, 1), r.stderr[-2000:]
    return json.loads((out / "report.json").read_text(encoding="utf-8")), out / "report.json"


@pytest.fixture(scope="session")
def real_tables(real_report):
    _, path = real_report
    code, stdout, stderr = _run_make_tables(path, allow_draft=True)
    assert code == 0, stderr
    return stdout


def test_real_report_is_refused_without_allow_draft(real_report):
    code, _, stderr = _run_make_tables(real_report[1])
    assert code == 2
    assert "simulated or synthetic" in stderr.lower()


def test_real_report_stamp_is_on_its_own_line_above_every_table(real_tables):
    lines = real_tables.splitlines()
    tables = _table_rows(real_tables)
    assert len(tables) >= 10
    starts = [i for i, ln in enumerate(lines) if ln.startswith("|") and not lines[i - 1].startswith("|")]
    assert len(starts) == len(tables)
    for i in starts:
        assert lines[i - 2] == STAMP and lines[i - 1] == ""
    assert not any(STAMP in ln and "|" in ln for ln in lines)
    _assert_table_shape(real_tables)


def test_real_report_has_no_none_or_nan_cells(real_tables):
    assert not re.search(r"\b(None|nan|inf)\b", real_tables, re.IGNORECASE)


def test_real_report_matrix_tables(real_report, real_tables):
    matrix = real_report[0]["matrix"]
    for name, c in matrix["classes"].items():
        assert f"| {name} | {c['label']} | {c['effective_label']} | {c['controls']} | {c['tested']} | {c['na']} |" in real_tables
    assert "Config-proxy" in real_tables
    assert "| m4-sessions |" in real_tables


def test_real_report_m1_numbers(real_report, real_tables):
    ev = real_report[0]["modules"]["M1 (audit)"]["evaluation_synthetic"]
    assert "| Precision | 1.000 | [0.956, 1.000] |" in real_tables
    assert f"TP {ev['overall']['tp']}, FP {ev['overall']['fp']}, FN {ev['overall']['fn']}, TN {ev['overall']['tn']}" in real_tables
    assert "| C28 | 3 | 0 | 0 | 47 | 1.000 | 1.000 |" in real_tables


def test_real_report_m2_numbers(real_report, real_tables):
    m2 = real_report[0]["modules"]["M2 (snapshot privacy)"]
    assert "| hex32/live | 7 | 10 | 0.700 | [0.397, 0.892] |" in real_tables
    assert "| ssh_key/live/base64 | 0 | 10 | 0.000 | [0.000, 0.278] |" in real_tables
    assert f"| plain | {m2['plain']['detected']} | {m2['plain']['present']} | 0.975 |" in real_tables
    assert "| real_programs | 0 | 0 | n/a |" in real_tables


def test_real_report_m3_is_not_run(real_tables):
    assert "NOT RUN: no results: pass --m3-results" in real_tables


def test_real_report_m4_tables(real_report, real_tables):
    m4 = real_report[0]["modules"]["M4 (hypervisor detection)"]
    assert "| Citable | no |" in real_tables
    assert "simulated data" in real_tables
    assert "native: 15, kvm-masked: 15" in real_tables
    assert "| H1 combined vs best single signal (AUROC) |" in real_tables
    assert "untestable" in real_tables
    assert f"{m4['H4']['seconds']:.2f} s" in real_tables
    assert f"| H3 held-out workload (AUROC) | in-dist 1.000, held-out 1.000 | drop 0.000 [0.000, 0.000] | {m4['H3']['p']:.4f} | yes |" in real_tables
    assert "| 0.1 | 1.000 | 1.000 |" in real_tables  # detection curve row for T = 0.1 s
    assert "| order | yes |" in real_tables  # balance: run order is imbalanced in this simulation
    assert "| clocksource | no | " in real_tables  # confounds
    assert "NOT RUN: no indicator values were recorded" in real_tables  # indicator_leaks is an empty list
