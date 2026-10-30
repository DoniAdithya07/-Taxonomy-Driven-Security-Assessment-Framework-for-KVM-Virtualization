# synthetic test value, not a credential
import argparse
import json
from types import SimpleNamespace

import pytest

import make_fixtures as mf
import vsec.__main__ as cli
from vsec import m2_snapshot, m3_forensics
from vsec.__main__ import main
from vsec.m4_detect import classify, features, simulate


def good_case(d):
    d.mkdir()
    for fn, text in mf.files_for({}, e0=False).items():
        (d / fn).write_text(text)
    return d


@pytest.fixture
def sandbox_dirs(tmp_path, monkeypatch):
    """Send generated fixtures and module logs to tmp, never into the project's .local."""
    monkeypatch.setattr(cli, "GEN_FIXTURES", tmp_path / "gen_fixtures")
    monkeypatch.setattr(cli, "LOG_DIR", tmp_path / "logs")
    return tmp_path


def stub_modules(monkeypatch, **replace):
    """Replace run_m1..run_m4 with cheap NA stubs; `replace` maps a name (m1..m4) to a function."""
    for n in ("m1", "m2", "m3", "m4"):
        monkeypatch.setattr(cli, f"run_{n}", replace.get(n, lambda *a, **k: (cli._na("stub"), [])))


# ---- audit ----
def test_audit_exit_codes(tmp_path, capsys):
    good = good_case(tmp_path / "good")
    assert main(["audit", str(good), "--env", "E1"]) == 0
    (good / "ksm_run").write_text("1")
    assert main(["audit", str(good), "--env", "E1"]) == 1
    assert "C09 FAIL" in capsys.readouterr().out
    assert main(["audit", str(tmp_path / "missing")]) == 2
    assert "not found" in capsys.readouterr().err


def test_audit_default_env_is_e0(tmp_path, capsys):
    main(["audit", str(good_case(tmp_path / "g"))])
    assert "C02 NA" in capsys.readouterr().out


def test_audit_output_has_no_control_characters(tmp_path, capsys):
    good = good_case(tmp_path / "g")
    (good / "cmdline").write_bytes(b"ro intel_iommu=off \x1b[31mRED\x1b[0m\r\x07 end")
    main(["audit", str(good), "--env", "E1"])
    out = capsys.readouterr().out
    assert "RED" in out and "\x1b" not in out and "\r" not in out and "\x07" not in out


@pytest.mark.parametrize("argv", [
    ["run", "--vm", "noequals"], ["run", "--vm", "x=" ], ["run", "--vm", "x=/no/such/folder"],
    ["run", "--m2-n", "0"],
])
def test_run_rejects_bad_args(argv, capsys):
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


# ---- M3 command ----
def fake_detect(monkeypatch, verified=True, sandbox=True):
    calls = []

    def detect(dump, symbols_dir=None, sandbox=False, expected_sha256=None, allow_unverified=False, **kw):
        calls.append({"dump": dump, "symbols": symbols_dir, "sha": expected_sha256, "allow": allow_unverified,
                      "sandbox": sandbox})
        return {"hidden_pids": [], "sandboxed": sandbox, "symbols_sha_verified": verified, "vol_version": "2.7.0"}
    monkeypatch.setattr(m3_forensics, "detect", detect)
    monkeypatch.setattr(m3_forensics, "available", lambda: True)
    monkeypatch.setattr(m3_forensics, "sandbox_available", lambda: sandbox)
    return calls


def test_m3_without_volatility_is_friendly(monkeypatch, capsys):
    monkeypatch.setattr(m3_forensics, "available", lambda: False)
    assert main(["m3", "dump.raw"]) == 2
    assert "Volatility" in capsys.readouterr().err


def test_m3_requires_the_symbols_hash(monkeypatch, capsys):
    calls = fake_detect(monkeypatch)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(["m3", "dump.raw", "--symbols", "isf"]) == 2
    err = capsys.readouterr().err
    assert "--symbols-sha256" in err and "VSEC_SYMBOLS_SHA256" in err and "--allow-unverified" in err
    assert calls == []  # nothing ran


def test_m3_hash_from_flag_or_env_is_passed_to_detect_and_recorded(monkeypatch, capsys):
    calls = fake_detect(monkeypatch)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", "ab" * 32]) == 0
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert calls[-1]["sha"] == "ab" * 32 and out["symbols_verified"] is True
    assert "sandboxed=True" in captured.err and "symbols_sha_verified=True" in captured.err
    assert "vol_version=2.7.0" in captured.err
    monkeypatch.setenv("VSEC_SYMBOLS_SHA256", "cd" * 32)
    assert main(["m3", "dump.raw", "--symbols", "isf"]) == 0
    assert calls[-1]["sha"] == "cd" * 32


def test_m3_allow_unverified_records_that_symbols_were_not_verified(monkeypatch, capsys):
    calls = fake_detect(monkeypatch, verified=False)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(["m3", "dump.raw", "--symbols", "isf", "--allow-unverified"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert calls[-1]["allow"] is True and calls[-1]["sha"] is None
    assert out["symbols_verified"] is False and out["symbols_sha_verified"] is False


def test_m3_refuses_to_run_unsandboxed_unless_told(monkeypatch, capsys):
    calls = fake_detect(monkeypatch, sandbox=False)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", "ab" * 32]) == 2
    err = capsys.readouterr().err
    assert "sandbox" in err and "--allow-unsandboxed" in err
    assert calls == []  # vol never started
    assert main(["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", "ab" * 32, "--allow-unsandboxed"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sandboxed"] is False and calls[-1]["sandbox"] is False


@pytest.mark.parametrize("bad", ["abc", "zz" * 32, "ab" * 31, "ab" * 33, "not a hash"])
def test_m3_malformed_hash_is_an_error_even_with_allow_unverified(monkeypatch, capsys, bad):
    calls = fake_detect(monkeypatch)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", bad, "--allow-unverified"]) == 2
    assert "64" in capsys.readouterr().err and calls == []
    monkeypatch.setenv("VSEC_SYMBOLS_SHA256", bad)  # a mistyped environment value is no different
    assert main(["m3", "dump.raw", "--symbols", "isf", "--allow-unverified"]) == 2
    assert calls == []


def test_m3_error_text_from_vol_is_cleaned_and_truncated(monkeypatch, capsys):
    fake_detect(monkeypatch)
    evil = "\x1b[2J" + "gu\u202eest" + "X" * 5000
    monkeypatch.setattr(m3_forensics, "detect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(evil)))
    assert main(["m3", "dump.raw", "--symbols-sha256", "ab" * 32]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\u202e" not in err and len(err) < 1000


def test_m3_detect_failure_is_a_friendly_error(monkeypatch, capsys):
    fake_detect(monkeypatch)
    monkeypatch.setattr(m3_forensics, "detect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("hash mismatch")))
    assert main(["m3", "dump.raw", "--symbols-sha256", "ab" * 32]) == 1
    assert "hash mismatch" in capsys.readouterr().err


# ---- run: argument rules ----
def test_simulate_with_m4_data_is_an_argparse_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["run", "--simulate", "--m4-data", str(tmp_path), "--out", str(tmp_path / "o")])
    assert e.value.code == 2 and "cannot be used together" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


def test_fast_help_text_is_precise(capsys):
    with pytest.raises(SystemExit):
        main(["run", "--help"])
    assert "200 bootstrap reps, 1 CV repeat, logreg only" in " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("bad", ["0", "-1", "-0.5", "nan", "inf", "-inf", "abc", ""])
def test_t_short_must_be_finite_and_positive(bad, tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["run", "--t-short", bad, "--out", str(tmp_path / "o")])
    assert e.value.code == 2 and "--t-short" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


def test_t_short_is_required_with_m4_data(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["run", "--m4-data", str(tmp_path), "--out", str(tmp_path / "o")])
    assert e.value.code == 2
    assert "pass --t-short from `python -m vsec pilot`" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


def test_t_short_is_not_required_for_simulate_or_without_m4(monkeypatch, sandbox_dirs):
    stub_modules(monkeypatch)
    assert main(["run", "--simulate", "--out", str(sandbox_dirs / "a")]) == 0
    assert main(["run", "--out", str(sandbox_dirs / "b")]) == 0


# ---- pilot ----
def fake_pilot_sessions(monkeypatch):
    """Make features.load return one valid-looking session (choose_t_short / evaluate_at are stubbed by the test)."""
    monkeypatch.setattr(features, "load", lambda d: [{"cls": "native"}])


def test_pilot_prints_short_text_by_default_and_exit_1_without_a_t_short(tmp_path, capsys):
    data = simulate.simulate(tmp_path / "pilot", per_class=5, windows=30)
    assert main(["pilot", "--data", str(data)]) == 1  # no T_short chosen: exit 1
    out = capsys.readouterr().out
    # 30 windows (about 1.2 s) cannot be evaluated at T >= 2 s, so no T_short is chosen and the reasons are printed
    assert out.startswith("no T_short chosen: could not evaluate")
    assert "T (s)  single AUROC  combined AUROC" in out and "T=2.0 s: " in out
    assert len(out.splitlines()) < 30 and '"auroc_grid"' not in out  # short, and not the ~80-line JSON
    row = next(ln for ln in out.splitlines() if ln.split()[:1] == ["0.5"])
    assert float(row.split()[2]) > 0.9  # the combined AUROC is filled where the pilot has data
    assert "prereg.md PILOT" not in out
    assert classify.MIN_SESSIONS == 5  # never mutated


def test_pilot_json_flag_prints_the_full_json(tmp_path, capsys):
    data = simulate.simulate(tmp_path / "pilot", per_class=5, windows=30)
    assert main(["pilot", "--data", str(data), "--json"]) == 1  # exit codes do not depend on --json
    res = json.loads(capsys.readouterr().out)  # JSON only: parseable as a whole
    assert set(res) >= {"t_short", "single_auroc", "auroc_grid", "reason", "per_class_min", "pilot_sessions"}
    assert res["pilot_sessions"] == 15 and set(res["auroc_grid"]["0.1"]) >= {"single", "combined"}
    assert res["auroc_grid"]["0.5"]["combined"] > 0.9
    assert res["t_short"] is None and res["reason"].startswith("could not evaluate")


def test_pilot_with_a_chosen_t_short_prints_the_prereg_instruction(tmp_path, monkeypatch, capsys):
    fake_pilot_sessions(monkeypatch)
    monkeypatch.setattr(classify, "choose_t_short", lambda s, **k: {"t_short": 0.5, "single_auroc": {}, "reason": None})
    monkeypatch.setattr(classify, "evaluate_at", lambda *a, **k: (_ for _ in ()).throw(ValueError("too few")))
    assert main(["pilot", "--data", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("T_short = 0.5 s")
    assert "Put this value into prereg.md PILOT: T_short = 0.5 s" in out


def test_pilot_passes_min_sessions_as_a_parameter_and_never_mutates_classify(monkeypatch):
    seen = []

    def fake_choose(sessions, **kw):
        seen.append(("choose", kw["min_sessions"]))
        return {"t_short": None, "single_auroc": {}, "reason": "stub"}

    def fake_eval(*a, **kw):
        seen.append(("eval", kw["min_sessions"], classify.MIN_SESSIONS))
        raise ValueError("too few")
    monkeypatch.setattr(classify, "choose_t_short", fake_choose)
    monkeypatch.setattr(classify, "evaluate_at", fake_eval)
    out = cli.pilot_report([], per_class_min=3)
    assert seen[0] == ("choose", 3) and all(s == ("eval", 3, 5) for s in seen[1:]) and len(seen) == 1 + len(classify.TS)
    assert classify.MIN_SESSIONS == 5
    assert out["per_class_min"] == 3 and out["auroc_grid"][0.1]["reason"] == "too few"


def test_pilot_without_t_short_prints_the_reasons_and_not_the_prereg_instruction(tmp_path, monkeypatch, capsys):
    fake_pilot_sessions(monkeypatch)
    monkeypatch.setattr(classify, "choose_t_short", lambda s, **k: {
        "t_short": None, "single_auroc": {}, "errors": {0.1: "insufficient data: only 2 sessions"},
        "reason": "could not evaluate at T=0.1"})
    monkeypatch.setattr(classify, "evaluate_at", lambda *a, **k: (_ for _ in ()).throw(ValueError("only 2 sessions")))
    assert main(["pilot", "--data", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "no T_short chosen: could not evaluate at T=0.1" in out
    assert "T=0.1 s: " in out and "only 2 sessions" in out  # the per-T reason
    assert "prereg" not in out.lower()  # nothing to record in prereg


def test_pilot_errors_are_friendly(tmp_path, capsys):
    assert main(["pilot", "--data", str(tmp_path / "missing")]) == 2
    assert "error" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["pilot", "--data", str(tmp_path), "--per-class-min", "0"])


def test_pilot_exits_2_when_no_valid_session_can_be_loaded(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("junk")  # a folder with only junk files, and an empty sub-folder
    (tmp_path / "empty_dir").mkdir()
    assert main(["pilot", "--data", str(tmp_path)]) == 2
    cap = capsys.readouterr()
    assert "no valid pilot session" in cap.err and "empty_dir" in cap.err
    assert cap.out == ""  # nothing that looks like a result
    assert main(["pilot", "--data", str(tmp_path), "--json"]) == 2
    assert capsys.readouterr().out == ""


# ---- run_m4 ----
def m4_args(data, t_short=None, simulate_=False, fast=True):
    return argparse.Namespace(m4_data=str(data) if data else None, simulate=simulate_, fast=fast, t_short=t_short)


def stub_analyze(monkeypatch, **extra):
    monkeypatch.setattr(classify, "analyze", lambda sessions, t_short, **kw: {
        "status": "ok", "settings": {"x": 1}, "opts": kw, **extra})


def test_run_m4_records_t_short_source(tmp_path, monkeypatch, capsys):
    data = simulate.simulate(tmp_path / "d", per_class=2, windows=3)
    stub_analyze(monkeypatch)
    res, _ = cli.run_m4(m4_args(data, t_short=0.5))
    assert res["settings"] == {"x": 1, "t_short": 0.5, "t_short_source": "cli"}
    res, _ = cli.run_m4(m4_args(None, simulate_=True))  # simulated: the default is allowed and recorded
    assert res["settings"]["t_short"] == 1.0 and res["settings"]["t_short_source"] == "default"
    assert res["simulated"] is True
    assert capsys.readouterr().err == ""


def test_run_m4_with_real_data_needs_t_short(tmp_path, monkeypatch):
    data = simulate.simulate(tmp_path / "d", per_class=2, windows=3)
    stub_analyze(monkeypatch)
    with pytest.raises(ValueError, match="pass --t-short from `python -m vsec pilot`"):
        cli.run_m4(m4_args(data))


def test_run_m4_fast_is_marked_and_noted(tmp_path, monkeypatch):
    data = simulate.simulate(tmp_path / "d", per_class=2, windows=3)
    stub_analyze(monkeypatch)
    res, _ = cli.run_m4(m4_args(data, t_short=0.5, fast=True))
    assert res["fast"] is True and res["notes"][0] == "FAST mode: 200 bootstrap reps, 1 CV repeat: not citable"
    assert res["opts"]["reps"] == 200 and res["opts"]["repeats"] == 1
    res, _ = cli.run_m4(m4_args(data, t_short=0.5, fast=False))
    assert "fast" not in res and not any("FAST" in n for n in res["notes"])


def edit_meta(data, session, **changes):
    p = data / session / "meta.json"
    meta = json.loads(p.read_text())
    meta.update(changes)
    p.write_text(json.dumps(meta))


def test_run_m4_reports_confounds_load_problems_and_the_clock_gate(tmp_path, monkeypatch):
    data = simulate.simulate(tmp_path / "d", per_class=3, windows=3)
    sessions = sorted(p.name for p in data.iterdir())
    for s in sessions:
        edit_meta(data, s, governor="performance", clocksource="tsc")
    native = next(s for s in sessions if json.loads((data / s / "meta.json").read_text())["cls"] == "native")
    edit_meta(data, native, governor="powersave", clocksource="hpet")  # differs from the other classes + gate failure
    (data / "broken").mkdir()
    (data / "broken" / "meta.json").write_text(json.dumps({"cls": "native"}))
    (data / "broken" / "FAILED").write_text("run did not finish")
    stub_analyze(monkeypatch)
    res, _ = cli.run_m4(m4_args(data, t_short=0.5))
    assert res["confounds"]["governor"]["differs"] is True
    assert res["confounds"]["clocksource_gate"]["failures"] == [native]
    assert [d["dir"] for d in res["load_report"]["skipped_dirs"]] == ["broken"]
    notes = " | ".join(res["notes"])
    assert "CONFOUND" in notes and "governor" in notes
    assert "CLOCK GATE" in notes and native in notes
    assert "LOAD" in notes and "broken" in notes


def test_run_m4_clean_data_has_no_confound_or_clock_notes(tmp_path, monkeypatch):
    data = simulate.simulate(tmp_path / "d", per_class=2, windows=3)
    for s in data.iterdir():
        edit_meta(data, s.name, governor="performance", clocksource="tsc")
    stub_analyze(monkeypatch)
    res, _ = cli.run_m4(m4_args(data, t_short=0.5, fast=False))
    notes = " | ".join(res["notes"])
    assert "CONFOUND" not in notes and "CLOCK GATE" not in notes and "LOAD" not in notes


# ---- C29 / C30 truth tables ----
def cell(detected, present, absent=0):
    return {"detected": detected, "present": present, "planted_but_absent": absent}


def m2_res(cells=(), hits=0, gb=1.0, synthetic=False, **extra):
    res = {"cells": {f"c{i}/live": c for i, c in enumerate(cells)}, "total_hits": hits, "gb_scanned": gb,
           "synthetic": synthetic, **extra}
    return res


@pytest.mark.parametrize("res,status,ev", [
    (m2_res(synthetic=True), "NA", "synthetic"),
    (m2_res(synthetic=True, hits=5), "NA", "synthetic"),
    (m2_res(), "PASS", "no secrets found"),
    (m2_res([cell(0, 0)]), "PASS", "no secrets found"),  # a cell with nothing planted
    (m2_res(hits=2), "FAIL", "2 secret(s) found in dumps"),
    (m2_res([cell(3, 3)], hits=3), "FAIL", "3 secret(s) found"),
    (m2_res([cell(1, 3)], hits=1), "FAIL", "scanner also missed 2 known planted secrets"),
    (m2_res([cell(0, 3)]), "NA", "scanner missed 3 known planted secrets: result not trustworthy"),
    (m2_res([cell(0, 2), cell(1, 2)]), "NA", "scanner missed 3 known planted secrets: result not trustworthy"),
    (m2_res([cell(0, 0, absent=2)]), "NA", "2 planted secrets are not in the dumps"),
    (m2_res(gb=0.0), "NA", "no bytes scanned"),
    ({**m2_res(), "total_hits": None}, "NA", "unavailable"),
])
def test_c29_truth_table(res, status, ev):
    got_status, got_ev = cli._c29(res)
    assert got_status == status and ev in got_ev


def test_c29_pass_requires_every_condition_not_just_zero_hits():
    assert cli._c29(m2_res([cell(0, 1)]))[0] == "NA"  # blind scanner: zero hits proves nothing
    assert cli._c29(m2_res([cell(0, 0, absent=1)]))[0] == "NA"
    assert cli._c29(m2_res(gb=0))[0] == "NA"


def test_run_m2_uses_evaluate_total_hits_and_passes_synthetic_through(monkeypatch):
    seen = {}

    def fake_evaluate(dumps, synthetic=False):
        seen["synthetic"] = synthetic
        seen["consumed"] = list(dumps)  # the generator is handed over untouched, not scanned here
        return m2_res(hits=4, synthetic=synthetic)
    monkeypatch.setattr(m2_snapshot, "evaluate", fake_evaluate)
    monkeypatch.setattr(m2_snapshot, "synthetic_dumps", lambda n: iter([(b"x", {"cell": "negative", "needles": []})]))
    monkeypatch.setattr(m2_snapshot, "scan", lambda data: (_ for _ in ()).throw(AssertionError("second scan")))
    res, findings = cli.run_m2(argparse.Namespace(m2_dumps=None, m2_n=1))
    assert seen["synthetic"] is True and len(seen["consumed"]) == 1
    assert res["synthetic"] is True and [(f["id"], f["status"]) for f in findings] == [("C29", "NA")]
    assert not hasattr(cli, "counted")


def test_run_m2_real_dumps_end_to_end(tmp_path):
    clean = b"\0" * 8192
    leaked = b"x" * 100 + b"AKIAABCDEFGHIJKLMNOP" + b"x" * 100
    for name, data in (("a", clean), ("b", leaked)):
        (tmp_path / f"{name}.mem").write_bytes(data)
        (tmp_path / f"{name}.json").write_text(json.dumps({"cell": "negative", "needles": []}))
    res, findings = cli.run_m2(argparse.Namespace(m2_dumps=str(tmp_path), m2_n=1))
    assert res["total_hits"] >= 1 and res["synthetic"] is False
    assert findings[0]["status"] == "FAIL" and "secret(s) found" in findings[0]["evidence"]
    (tmp_path / "b.mem").write_bytes(clean)
    res, findings = cli.run_m2(argparse.Namespace(m2_dumps=str(tmp_path), m2_n=1))
    assert res["total_hits"] == 0 and findings[0]["status"] == "PASS"


def row(truth, got, **flags):
    return {"name": "img1", "truth_hidden": truth, "detected": got, **flags}


OP_SHA = "ab" * 32  # what the operator typed on the command line
V = {"symbols_sha_verified": True, "symbols_sha256": OP_SHA}


@pytest.mark.parametrize("r,status,ev", [
    (row([], [], **V), "PASS", "no hidden items"),
    (row([], ["77"], **V), "FAIL", "1 hidden item(s) detected in a dump with none planted"),
    (row(["4"], ["4"], **V), "FAIL", "VM has hidden items"),
    (row(["4", "5"], ["4"], **V), "FAIL", "detector missed 1 known hidden items"),
    (row(["4"], ["99"], **V), "FAIL", "VM has hidden items"),
    (row(["4"], [], **V), "NA", "img1: detector missed 1 known hidden items"),
    (row(["4", "5", "6"], [], **V), "NA", "detector missed 3 known hidden items"),
    (row([], [], symbols_verified=True, symbols_sha256=OP_SHA.upper()), "PASS", "no hidden items"),
    (row([], []), "NA", "symbols not hash-verified"),  # nothing recorded about the symbols
    (row(["4"], ["4"], symbols_sha_verified=False, symbols_sha256=OP_SHA), "NA", "symbols not hash-verified"),
    (row([], [], symbols_verified=False, symbols_sha256=OP_SHA), "NA", "symbols not hash-verified"),
    # a bare flag in the results file proves nothing: the recorded hash must equal the operator's
    (row([], [], symbols_sha_verified=True), "NA", "symbols not hash-verified"),
    (row([], [], symbols_sha_verified=True, symbols_sha256="cd" * 32), "NA", "symbols not hash-verified"),
    (row([], [], symbols_sha_verified=True, symbols_sha256="garbage"), "NA", "symbols not hash-verified"),
    (row([], [], symbols_sha_verified=True, symbols_sha256=None), "NA", "symbols not hash-verified"),
    (row([], [], symbols_sha256=OP_SHA), "NA", "symbols not hash-verified"),  # hash recorded but never verified
    # rows dropped by the guest-controlled exit-state field: the verdict cannot be trusted
    (row([], [], excluded_exited=[{"pid": 5, "offset": None, "reason": "EXIT_STATE=dead"}], exclusion_applied=True, **V),
     "NA", "1 rows excluded by exit-state (guest-controlled field)"),
    (row([], ["9"], excluded_exited=[{"pid": 5}, {"pid": 6}], **V), "NA", "2 rows excluded by exit-state"),
    (row([], [], excluded_exited=[], exclusion_applied=False, **V), "PASS", "no hidden items"),
])
def test_c30_truth_table(r, status, ev):
    got_status, got_ev = cli._c30(r, OP_SHA)
    assert got_status == status and ev in got_ev


def test_c30_is_na_when_the_operator_supplied_no_hash():
    assert cli._c30(row([], [], **V))[0] == "NA"
    assert cli._c30(row([], [], **V), None)[1].startswith("img1: symbols not hash-verified")


def test_run_m3_marks_unverified_symbols_na_and_lists_them(tmp_path):
    path = tmp_path / "m3.json"
    path.write_text(json.dumps([row([], [], **V), {**row(["4"], ["4"], symbols_sha_verified=False), "name": "bad"}]))
    res, findings = cli.run_m3(argparse.Namespace(m3_results=str(path), symbols_sha256=OP_SHA))
    assert [f["status"] for f in findings] == ["PASS", "NA"] and res["symbols_unverified"] == ["bad"]
    assert cli.run_m3(argparse.Namespace(m3_results=None, symbols_sha256=None))[0]["status"] == "NA"


def test_run_m3_compares_recorded_hashes_with_the_operators_flag_or_env(tmp_path, monkeypatch):
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    path = tmp_path / "m3.json"
    other = {**row([], [], **V), "name": "other", "symbols_sha256": "cd" * 32}
    path.write_text(json.dumps([row([], [], **V), other, {**row([], [], symbols_sha_verified=True), "name": "bare"}]))
    ns = lambda sha: argparse.Namespace(m3_results=str(path), symbols_sha256=sha)  # noqa: E731
    res, findings = cli.run_m3(ns(OP_SHA))
    assert [f["status"] for f in findings] == ["PASS", "NA", "NA"] and res["symbols_unverified"] == ["other", "bare"]
    res, findings = cli.run_m3(ns(None))  # no operator hash at all: nothing can be verified
    assert [f["status"] for f in findings] == ["NA", "NA", "NA"] and len(res["symbols_unverified"]) == 3
    monkeypatch.setenv("VSEC_SYMBOLS_SHA256", OP_SHA)  # the environment works like the flag
    assert [f["status"] for f in cli.run_m3(ns(None))[1]] == ["PASS", "NA", "NA"]
    with pytest.raises(ValueError, match="64"):
        cli.run_m3(ns("not-a-hash"))


def test_run_m3_lists_images_whose_rows_were_excluded(tmp_path):
    path = tmp_path / "m3.json"
    path.write_text(json.dumps([{**row([], [], excluded_exited=[{"pid": 5}], **V), "name": "ex"}, row([], [], **V)]))
    res, findings = cli.run_m3(argparse.Namespace(m3_results=str(path), symbols_sha256=OP_SHA))
    assert [f["status"] for f in findings] == ["NA", "PASS"] and res["exclusions"] == ["ex"]


def test_run_accepts_the_symbols_hash_flag(monkeypatch, sandbox_dirs):
    seen = {}
    stub_modules(monkeypatch, m3=lambda args: seen.update(sha=args.symbols_sha256) or (cli._na("stub"), []))
    assert main(["run", "--symbols-sha256", OP_SHA, "--out", str(sandbox_dirs / "o")]) == 0
    assert seen["sha"] == OP_SHA


def test_fail_cleans_and_truncates_the_guest_derived_message(sandbox_dirs, capsys):
    try:
        raise RuntimeError("X" * 5000 + chr(27) + "[2Jgu" + chr(0x202E) + "est")
    except RuntimeError as e:
        res = cli._fail("M3 (forensics)", e)
    shown = capsys.readouterr().err
    for text in (res["reason"], res["traceback"], shown, (sandbox_dirs / "logs" / "m3_forensics.log").read_text()):
        assert chr(27) not in text and chr(0x202E) not in text
    assert len(res["reason"]) < 600 and "Traceback" in res["traceback"] and len(res["traceback"]) < 25000


# ---- fixtures directory ----
def test_fixtures_default_is_regenerated_fresh_and_never_the_committed_copy(sandbox_dirs):
    assert not cli.GEN_FIXTURES.exists()
    first = cli._fixtures_dir(None)
    assert first == cli.GEN_FIXTURES and (first / "answer_key.json").is_file()
    (first / "stale.txt").write_text("old")
    (first / "case00" / "vm.xml").write_text("tampered")
    again = cli._fixtures_dir(None)
    assert not (again / "stale.txt").exists() and "tampered" not in (again / "case00" / "vm.xml").read_text()
    assert again != cli.ROOT / "tests" / "fixtures"


def test_fixtures_explicit_folder_is_used_only_with_an_answer_key(sandbox_dirs):
    empty = sandbox_dirs / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError, match="no answer_key.json"):
        cli._fixtures_dir(str(empty))
    assert not cli.GEN_FIXTURES.exists()  # no silent regeneration
    (empty / "answer_key.json").write_text("{}")
    assert cli._fixtures_dir(str(empty)) == empty
    assert not cli.GEN_FIXTURES.exists() and (empty / "answer_key.json").read_text() == "{}"  # untouched


def test_make_fixtures_is_imported_once(monkeypatch):
    first = cli._make_fixtures()
    assert cli._make_fixtures() is first and first.main.__module__ == "make_fixtures"


# ---- module failures ----
def test_module_turns_a_crash_into_error_with_traceback_and_log(sandbox_dirs, capsys):
    def boom():
        raise KeyError("missing")
    res, findings = cli._module(boom, "M9 (demo module)")
    assert res["status"] == "ERROR" and res["reason"] == "KeyError: 'missing'" and findings == []
    assert "Traceback" in res["traceback"] and "boom" in res["traceback"] and "elapsed_s" in res
    assert "Traceback" in capsys.readouterr().err
    assert "KeyError: 'missing'" in (sandbox_dirs / "logs" / "m9_demo_module.log").read_text()


@pytest.mark.parametrize("value", ["text", None, ["a"], 3])
def test_module_treats_a_non_dict_result_as_error(sandbox_dirs, value):
    res, findings = cli._module(lambda: (value, []), "M9")
    assert res["status"] == "ERROR" and "expected a dict" in res["reason"] and findings == []
    res, _ = cli._module(lambda: value, "M9")  # not even a pair
    assert res["status"] == "ERROR"


def test_module_na_stays_na_and_ok_results_pass_through(sandbox_dirs):
    res, fs = cli._module(lambda: (cli._na("no data"), [1]), "M9")
    assert res["status"] == "NA" and fs == [1]
    assert not (sandbox_dirs / "logs").exists()


def test_a_module_that_raises_gives_exit_1_report_fields_and_a_red_banner(sandbox_dirs, monkeypatch, capsys):
    def m2(args):
        raise RuntimeError("boom")
    stub_modules(monkeypatch, m2=m2)
    out = sandbox_dirs / "out"
    assert main(["run", "--out", str(out)]) == 1
    rep = json.loads((out / "report.json").read_text())
    assert rep["modules_failed"] == [{"name": "M2 (snapshot privacy)", "reason": "RuntimeError: boom"}]
    m2res = rep["modules"]["M2 (snapshot privacy)"]
    assert m2res["status"] == "ERROR" and "Traceback" in m2res["traceback"]
    assert [n["name"] for n in rep["modules_na"]] == ["M1 (audit)", "M3 (forensics)", "M4 (hypervisor detection)"]
    html = (out / "report.html").read_text()
    assert "MODULES FAILED" in html and "M2 (snapshot privacy): RuntimeError: boom" in html
    assert html.index("MODULES FAILED") < html.index("<h1>")
    err = capsys.readouterr().err
    assert "Traceback" in err and "modules failed: M2 (snapshot privacy)" in err
    assert "RuntimeError: boom" in (sandbox_dirs / "logs" / "m2_snapshot_privacy.log").read_text()


def test_a_crashing_module_does_not_discard_a_real_siblings_findings(sandbox_dirs, monkeypatch):
    """Every other crash-isolation test stubs the surviving modules to trivial `_na("stub")`, which never
    proves isolation holds for a module producing REAL findings. Here M1 runs for real against a real
    fixture folder while M2 crashes, and M1's real results must land in report.json untouched."""
    def crashing_m2(args):
        raise RuntimeError("boom")
    stub_modules(monkeypatch, m1=cli.run_m1, m2=crashing_m2)
    good = good_case(sandbox_dirs / "good")
    out = sandbox_dirs / "out"
    assert main(["run", "--vm", f"good={good}", "--env", "E1", "--out", str(out)]) == 1
    rep = json.loads((out / "report.json").read_text())

    m1 = rep["modules"]["M1 (audit)"]
    assert "status" not in m1  # the real M1 run succeeded: no ERROR/NA flag
    assert m1["kind"] == "self_consistency" and "evaluation_synthetic" in m1

    mine = {f["id"]: f["status"] for f in rep["findings"] if f["vm"] == "good"}
    assert len(mine) == 28 and "PASS" in mine.values()  # real findings, not empty, not all NA
    assert "FAIL" not in mine.values() and "ERROR" not in mine.values()

    m2res = rep["modules"]["M2 (snapshot privacy)"]
    assert m2res["status"] == "ERROR" and "boom" in m2res["reason"]
    assert rep["modules_failed"] == [{"name": "M2 (snapshot privacy)", "reason": "RuntimeError: boom"}]
    assert [n["name"] for n in rep["modules_na"]] == ["M3 (forensics)", "M4 (hypervisor detection)"]

    html = (out / "report.html").read_text()
    assert "MODULES FAILED" in html and "M2 (snapshot privacy): RuntimeError: boom" in html
    assert html.index("MODULES FAILED") < html.index("<h1>")


def test_na_modules_alone_exit_0_but_warn(sandbox_dirs, monkeypatch, capsys):
    stub_modules(monkeypatch)
    out = sandbox_dirs / "out"
    assert main(["run", "--out", str(out)]) == 0
    rep = json.loads((out / "report.json").read_text())
    assert rep["modules_failed"] == [] and len(rep["modules_na"]) == 4
    assert "MODULES FAILED" not in (out / "report.html").read_text()
    assert "warning: not real results" in capsys.readouterr().err


def test_a_non_dict_module_result_in_run_is_an_error(sandbox_dirs, monkeypatch):
    stub_modules(monkeypatch, m3=lambda args: ("oops", []))
    out = sandbox_dirs / "out"
    assert main(["run", "--out", str(out)]) == 1
    rep = json.loads((out / "report.json").read_text())
    assert rep["modules"]["M3 (forensics)"]["status"] == "ERROR"


def test_vm_findings_survive_a_missing_fixture_folder(sandbox_dirs, monkeypatch):
    stub_modules(monkeypatch, m1=cli.run_m1)
    case = good_case(sandbox_dirs / "weak")
    (case / "ksm_run").write_text("1")
    out = sandbox_dirs / "out"
    code = main(["run", "--fixtures", str(sandbox_dirs / "nope"), "--vm", f"weak={case}", "--env", "E1",
                 "--out", str(out)])
    assert code == 1  # the fixture scoring failed
    rep = json.loads((out / "report.json").read_text())
    m1 = rep["modules"]["M1 (audit)"]
    assert m1["status"] == "ERROR" and "no answer_key.json" in m1["reason"]
    mine = {f["id"]: f for f in rep["findings"] if f["vm"] == "weak"}
    assert len(mine) == 28 and mine["C09"]["status"] == "FAIL"  # the host audit was not discarded
    assert rep["modules_failed"][0]["name"] == "M1 (audit)"


def test_a_failing_vm_audit_does_not_stop_the_fixture_scoring(sandbox_dirs, monkeypatch):
    real = cli.m1_audit.audit

    def audit(folder, env="E0", vm="", cves_path=None):
        if vm == "bad":
            raise RuntimeError("audit crashed")
        return real(folder, env=env, vm=vm, cves_path=cves_path)
    monkeypatch.setattr(cli.m1_audit, "audit", audit)
    ok, bad = good_case(sandbox_dirs / "ok"), good_case(sandbox_dirs / "bad")
    res, findings = cli.run_m1(None, [("ok", str(ok)), ("bad", str(bad))], "E1")
    assert res["status"] == "ERROR" and "audit crashed" in res["reason"] and "evaluation_synthetic" in res
    assert {f["vm"] for f in findings} == {"ok"}


def test_run_m1_scores_fixtures_with_the_verified_fixture_cves_not_the_real_list(sandbox_dirs):
    res, findings = cli.run_m1(None, [], "E1")
    o = res["evaluation_synthetic"]["overall"]
    assert "status" not in res and o["recall"] == 1.0 and o["fp"] == 0 and findings == []
    assert res["evaluation_synthetic"]["per_control"]["C23"]["recall"] == 1.0
    assert res["evaluation_synthetic"]["per_control"]["C24"]["recall"] == 1.0


# ---- full run ----
def test_run_end_to_end_simulated(sandbox_dirs, monkeypatch, capsys):
    monkeypatch.setattr(cli, "SIM_KW", {"per_class": 5, "windows": 16})  # keep the simulated M4 run short
    calls = []
    real = simulate.simulate_sessions
    monkeypatch.setattr(simulate, "simulate_sessions", lambda **kw: calls.append(kw) or real(**kw))
    monkeypatch.setattr(simulate, "simulate", lambda *a, **k: pytest.fail("simulated sessions were written to disk"))
    out = sandbox_dirs / "out"
    assert main(["run", "--simulate", "--fast", "--m2-n", "2", "--t-short", "0.5", "--out", str(out)]) == 0
    assert calls == [{"per_class": 5, "windows": 16}]  # in memory, exactly once
    rep = json.loads((out / "report.json").read_text())
    assert set(rep) == {"contains_simulated_or_synthetic", "fast", "modules_failed", "modules_na", "notes",
                        "modules", "findings", "matrix"}
    assert rep["contains_simulated_or_synthetic"] is True and rep["fast"] is True
    assert rep["modules_failed"] == [] and [n["name"] for n in rep["modules_na"]] == ["M3 (forensics)"]
    html = (out / "report.html").read_text()
    assert html.index("CONTAINS SIMULATED/SYNTHETIC DATA: not citable") < html.index("<h1>")
    m1, m2, m3, m4 = rep["modules"].values()
    assert m1["kind"] == "self_consistency" and "evaluation_synthetic" in m1 and not m1.get("synthetic")
    assert m2["synthetic"] is True and m3["status"] == "NA"
    assert m4["status"] == "ok" and m4["simulated"] is True and m4["fast"] is True
    assert m4["settings"]["t_short"] == 0.5 and m4["settings"]["t_short_source"] == "cli"
    assert "confounds" in m4 and "load_report" in m4
    assert "FAST mode: 200 bootstrap reps, 1 CV repeat: not citable" in rep["notes"]
    c31 = [f for f in rep["findings"] if f["id"] == "C31"]
    assert c31 and {f["status"] for f in c31} == {"NA"}
    assert any("self-consistency" in n and "solo project" in n for n in rep["notes"])
    assert "not real results" in capsys.readouterr().err


# ---- pilot exit code, empty hash, m3 result rows ----
def test_pilot_exits_1_without_a_t_short_and_0_with_one(tmp_path, monkeypatch, capsys):
    fake_pilot_sessions(monkeypatch)
    monkeypatch.setattr(classify, "evaluate_at", lambda *a, **k: (_ for _ in ()).throw(ValueError("too few")))
    for chosen, code in ((None, 1), (0.5, 0)):
        monkeypatch.setattr(classify, "choose_t_short", lambda s, t=chosen, **k: {
            "t_short": t, "single_auroc": {}, "reason": None if t else "no T qualified"})
        assert main(["pilot", "--data", str(tmp_path)]) == code
        capsys.readouterr()


def test_m3_an_empty_hash_flag_is_an_error_even_with_allow_unverified(monkeypatch, capsys):
    calls = fake_detect(monkeypatch)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    for extra in ([], ["--allow-unverified"]):
        assert main(["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", "", *extra]) == 2
        err = capsys.readouterr().err
        assert "64" in err or "required" in err
    assert calls == []


def fake_detect_rows(monkeypatch, **extra):
    calls = fake_detect(monkeypatch)
    out = {"hidden_pids": [4, 7], "hidden_modules": ["diamorphine"], "sandboxed": True, "symbols_sha_verified": True,
           "vol_version": "2.7.0", **extra}
    monkeypatch.setattr(m3_forensics, "detect", lambda *a, **k: calls.append(1) or dict(out))
    return calls


def m3_row_args(tmp_path, *more):
    return ["m3", "dump.raw", "--symbols", "isf", "--symbols-sha256", "AB" * 32, "--row-name", "img1",
            "--append", str(tmp_path / "rows.json"), *more]


def test_m3_row_name_appends_a_result_row_and_the_printed_json_is_unchanged(monkeypatch, tmp_path, capsys):
    fake_detect_rows(monkeypatch, excluded_exited=[{"pid": 9}])
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    assert main(m3_row_args(tmp_path, "--truth-hidden", "4, evilmod,,7")) == 0
    printed = json.loads(capsys.readouterr().out)
    assert "truth_hidden" not in printed and printed["hidden_pids"] == [4, 7] and printed["symbols_verified"] is True
    assert json.loads((tmp_path / "rows.json").read_text()) == [{
        "name": "img1", "truth_hidden": [4, "evilmod", 7], "detected": [4, 7, "diamorphine"],
        "symbols_sha256": "ab" * 32, "symbols_sha_verified": True, "excluded_exited": [{"pid": 9}]}]
    assert main(m3_row_args(tmp_path)) == 0  # second image: appended, not overwritten; no truth = clean dump
    rows = json.loads((tmp_path / "rows.json").read_text())
    assert [r["name"] for r in rows] == ["img1", "img1"] and rows[1]["truth_hidden"] == [] and rows[1]["detected"] == [4, 7, "diamorphine"]


def test_m3_row_file_feeds_run_m3_directly(monkeypatch, tmp_path, capsys):
    fake_detect_rows(monkeypatch)
    assert main(m3_row_args(tmp_path, "--truth-hidden", "4,7,diamorphine")) == 0
    res, findings = cli.run_m3(argparse.Namespace(m3_results=str(tmp_path / "rows.json"), symbols_sha256="ab" * 32))
    assert res["detected"] == 3 and res["hidden_total"] == 3 and res["symbols_unverified"] == []
    assert [f["status"] for f in findings] == ["FAIL"] and "VM has hidden items" in findings[0]["evidence"]


def test_m3_unverified_row_is_na_in_run(monkeypatch, tmp_path):
    fake_detect_rows(monkeypatch, symbols_sha_verified=False)
    monkeypatch.delenv("VSEC_SYMBOLS_SHA256", raising=False)
    argv = ["m3", "dump.raw", "--allow-unverified", "--row-name", "u", "--append", str(tmp_path / "rows.json")]
    assert main(argv) == 0
    (row_,) = json.loads((tmp_path / "rows.json").read_text())
    assert row_["symbols_sha256"] is None and row_["symbols_sha_verified"] is False
    _, findings = cli.run_m3(argparse.Namespace(m3_results=str(tmp_path / "rows.json"), symbols_sha256=None))
    assert [f["status"] for f in findings] == ["NA"]


@pytest.mark.parametrize("content", ['{"a": 1}', '"text"', "not json", "5"])
def test_m3_append_refuses_a_file_that_is_not_a_json_list_before_running_volatility(monkeypatch, tmp_path, capsys, content):
    calls = fake_detect_rows(monkeypatch)
    (tmp_path / "rows.json").write_text(content)
    assert main(m3_row_args(tmp_path)) == 2
    assert "rows.json" in capsys.readouterr().err and calls == [] and (tmp_path / "rows.json").read_text() == content


@pytest.mark.parametrize("extra", [["--append", "x.json"], ["--truth-hidden", "4"]])
def test_m3_row_options_need_a_row_name(monkeypatch, extra, capsys):
    calls = fake_detect_rows(monkeypatch)
    assert main(["m3", "dump.raw", "--symbols-sha256", "ab" * 32, *extra]) == 2
    assert "--row-name" in capsys.readouterr().err and calls == []


def test_m3_row_name_without_append_prints_the_row_to_stderr_only(monkeypatch, capsys):
    fake_detect_rows(monkeypatch)
    assert main(["m3", "dump.raw", "--symbols-sha256", "ab" * 32, "--row-name", "r1"]) == 0
    cap = capsys.readouterr()
    assert "truth_hidden" not in json.loads(cap.out) and '"name": "r1"' in cap.err
