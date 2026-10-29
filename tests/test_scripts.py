"""Tests of the guest-side scripts: session_meta.py, plan_sessions.py and run_session.sh."""
import glob
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from vsec.m4_detect import features

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
ROOT = SCRIPTS.parent
THERMAL = "idle before=40000 after=42500 uptime_s=10\ncpu before=na after=51000 uptime_s=20\n"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def plan(tmp_path, per_class, per_day):
    out = tmp_path / "schedule.json"
    r = subprocess.run([sys.executable, str(SCRIPTS / "plan_sessions.py"), str(per_class), str(per_day), str(out)],
                       capture_output=True, text=True)
    return r, out


# ---- plan_sessions ----

def test_plan_every_day_has_all_three_classes_and_sessions_are_balanced(tmp_path):
    r, out = plan(tmp_path, 6, 6)
    assert r.returncode == 0, r.stderr
    sched = json.loads(out.read_text())
    assert Counter(e["cls"] for e in sched) == {c: 6 for c in features.CLASSES}
    days = {}
    for e in sched:
        days.setdefault(e["day"], []).append(e["cls"])
    assert len(days) == 3
    for d, classes in days.items():
        assert Counter(classes) == {c: 2 for c in features.CLASSES}, f"day {d}"
    assert len({e["session"] for e in sched}) == len(sched)


def plan_main(*argv):
    return load_script("plan_sessions").main([str(a) for a in argv])


def test_plan_records_seed_and_batch_and_is_deterministic(tmp_path):
    a, b, c = (tmp_path / n for n in ("a.json", "b.json", "c.json"))
    plan_main(6, 6, a, "--seed", 7)
    plan_main(6, 6, b, "--seed", 7)
    plan_main(6, 6, c)
    sa = json.loads(a.read_text())
    assert a.read_text() == b.read_text() and a.read_text() != c.read_text()
    assert all(e["seed"] == 7 and e["batch"] == e["day"] for e in sa)
    assert set(sa[0]) == {"session", "cls", "day", "batch", "seed"}
    assert {e["seed"] for e in json.loads(c.read_text())} == {2025}
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("args,msg", [((0, 6), "per_class"), ((15, -3), "per_day"), ((15, 0), "per_day"),
                                      ((-1, 6), "per_class"), ((15, 4), "multiple of 3"), (("abc", 6), "invalid int"),
                                      ((6, "x"), "invalid int"), ((6, 2.5), "invalid int")])
def test_plan_rejects_odd_numbers_without_traceback_and_writes_nothing(tmp_path, capsys, args, msg):
    out = tmp_path / "sub" / "schedule.json"
    with pytest.raises(SystemExit) as e:
        plan_main(*args, out)
    assert e.value.code == 2 and msg in capsys.readouterr().err
    assert not out.parent.exists()
    r = subprocess.run([sys.executable, str(SCRIPTS / "plan_sessions.py"), *map(str, args), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "Traceback" not in r.stderr and not out.parent.exists()


def test_plan_failure_while_writing_leaves_no_half_file(tmp_path, monkeypatch):
    out = tmp_path / "schedule.json"
    mod = load_script("plan_sessions")
    monkeypatch.setattr(mod.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        mod.main(["6", "6", str(out)])
    assert list(tmp_path.iterdir()) == []


def test_plan_default_output_is_relative_to_the_repo_not_the_cwd():
    assert load_script("plan_sessions").DEFAULT_OUT == ROOT / "data" / "m4" / "schedule.json"


def test_plan_rejects_days_that_cannot_hold_all_classes_and_never_overwrites(tmp_path):
    r, out = plan(tmp_path, 6, 4)
    assert r.returncode == 2 and "multiple of 3" in r.stderr and not out.exists()
    assert plan(tmp_path, 6, 6)[0].returncode == 0
    r, _ = plan(tmp_path, 6, 6)
    assert r.returncode != 0 and "refusing to overwrite" in r.stderr


# ---- session_meta ----

def test_session_meta_output_loads_with_day_order_and_batch(tmp_path):
    sched_path = plan(tmp_path, 4, 6)[1]
    sched = json.loads(sched_path.read_text())
    entry = sched[7]
    root = tmp_path / "data"
    d = root / entry["session"]
    d.mkdir(parents=True)
    (d / "thermal.txt").write_text(THERMAL)
    load_script("session_meta").main(entry["cls"], str(d), None, str(sched_path))
    (s,) = features.load(root)
    # Linux-only reads (/proc, /sys) are None on Windows, so only schedule- and thermal-derived fields are asserted
    assert (s["day"], s["order"], s["batch"]) == (entry["day"], 7, entry["day"])
    assert s["day"] is not None and s["order"] is not None
    assert s["temp_before_c"] == {"idle": 40.0, "cpu": None}
    assert s["temp_after_c"] == {"idle": 42.5, "cpu": 51.0}
    assert {"minutes_since_boot", "nproc", "smt_active", "online_cpus"} <= set(s["meta"]) and "uptime_min" not in s["meta"]


def test_session_meta_batch_comes_from_the_schedule_when_present(tmp_path):
    sched = tmp_path / "s.json"
    sched.write_text(json.dumps([{"session": "a", "cls": "native", "day": 1}, {"session": "b", "cls": "native", "day": 1, "batch": 9}]))
    meta = load_script("session_meta")
    meta.main("native", str(tmp_path / "b"), None, str(sched))
    assert json.loads((tmp_path / "b" / "meta.json").read_text())["batch"] == 9


def test_session_meta_unscheduled_session_is_null_with_warning(tmp_path, capsys):
    sched = tmp_path / "s.json"
    sched.write_text("[]")
    load_script("session_meta").main("native", str(tmp_path / "zzz"), None, str(sched), allow_unscheduled=True)
    m = json.loads((tmp_path / "zzz" / "meta.json").read_text())
    assert (m["day"], m["order"], m["batch"]) == (None, None, None) and m["temp_before_c"] == {}
    assert "not in the schedule" in capsys.readouterr().err
    load_script("session_meta").main("native", str(tmp_path / "q"), None, str(tmp_path / "missing.json"), allow_unscheduled=True)
    assert "schedule unreadable" in capsys.readouterr().err


def sched_entry(tmp_path, content, session="a"):
    path = tmp_path / "sched.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return load_script("session_meta").schedule_entry(str(path), session)


@pytest.mark.parametrize("content,why", [
    ("null", "list of objects"), ("5", "list of objects"), ("true", "list of objects"), ("{}", "list of objects"),
    ("[1]", "list of objects"), ('[{"session": "a", "day": 1}, 5]', "list of objects"), ("{broken", "unreadable"),
    ([], "not in the schedule"),
    ([{"session": "a", "day": 1}, {"session": "a", "day": 2}], "2 times"),
    ([{"session": "a", "day": True}], "invalid day"), ([{"session": "a", "day": [1]}], "invalid day"),
    ([{"session": "a", "day": 1.5}], "invalid day"), ([{"session": "a"}], "invalid day"),
    ([{"session": "a", "day": 1, "batch": False}], "invalid day"),
    pytest.param("[" * 100000 + "]" * 100000, "unreadable", id="deeply-nested"),
])
def test_schedule_entry_bad_shapes_warn_and_give_none(tmp_path, capsys, content, why):
    assert sched_entry(tmp_path, content) == (None, None, None)
    err = capsys.readouterr().err
    assert "warning" in err and why in err and "stored as null" in err


@pytest.mark.parametrize("entry,expected", [({"day": 3}, (3, 1, 3)), ({"day": "d2"}, ("d2", 1, "d2")),
                                            ({"day": 3, "batch": None}, (3, 1, 3)), ({"day": 3, "batch": "B"}, (3, 1, "B")),
                                            ({"day": 1}, (1, 1, 1))])
def test_schedule_entry_valid_shapes(tmp_path, entry, expected):
    assert sched_entry(tmp_path, [{"session": "x", "day": 1}, {"session": "a", **entry}]) == expected


def test_schedule_entry_missing_file_warns(tmp_path, capsys):
    assert load_script("session_meta").schedule_entry(str(tmp_path / "nope.json"), "a") == (None, None, None)
    assert "schedule unreadable" in capsys.readouterr().err


@pytest.mark.parametrize("text,expected", [
    ("idle before=40000 after=-2500", {"idle": (40.0, -2.5)}), ("idle before=--5 after=5", {"idle": (None, 0.005)}),
    ("idle before=\u00b2 after=na", {"idle": (None, None)}), ("idle before=\u0663 after=1", {"idle": (0.003, 0.001)}),
    ("idle before= after=1.5", {"idle": (None, None)}), ("idle before=- after=+5", {"idle": (None, None)}),
    ("idle before=" + "9" * 5000 + " after=1", {"idle": (None, 0.001)}), ("\n  \ncpu garbage", {"cpu": (None, None)}),
])
def test_parse_thermal_edge_values_never_crash(tmp_path, text, expected):
    f = tmp_path / "thermal.txt"
    f.write_text(text, encoding="utf-8")
    before, after = load_script("session_meta").parse_thermal(str(f))
    assert {k: (before[k], after[k]) for k in before} == expected


def test_parse_thermal_warns_about_unreadable_but_not_na(tmp_path, capsys):
    f = tmp_path / "thermal.txt"
    f.write_text("idle before=na after=--5\n")
    load_script("session_meta").parse_thermal(str(f))
    err = capsys.readouterr().err
    assert "after='--5'" in err and "before" not in err


@pytest.mark.parametrize("temp", ["nan", "inf", "-inf", "NaN"])
def test_session_meta_non_finite_temperature_is_null_with_warning(tmp_path, capsys, temp):
    load_script("session_meta").main("native", str(tmp_path / "s"), temp, str(tmp_path / "none.json"), allow_unscheduled=True)
    meta_text = (tmp_path / "s" / "meta.json").read_text()
    assert json.loads(meta_text)["temp_c"] is None and "NaN" not in meta_text and "Infinity" not in meta_text
    assert "not a finite number" in capsys.readouterr().err


def test_session_meta_never_writes_nan_and_leaves_no_half_file(tmp_path, monkeypatch):
    mod = load_script("session_meta")
    monkeypatch.setattr(mod, "parse_thermal", lambda p: ({"idle": float("nan")}, {}))
    with pytest.raises(ValueError, match="Out of range"):
        mod.main("native", str(tmp_path / "s"), None, str(tmp_path / "none.json"), allow_unscheduled=True)
    assert not (tmp_path / "s" / "meta.json").exists()


def test_session_meta_failure_exits_nonzero_with_message(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    for argv in (["native", str(blocker / "sub")], ["vmware", str(tmp_path / "d")]):  # unwritable folder, bad class
        r = subprocess.run([sys.executable, str(SCRIPTS / "session_meta.py"), *argv], capture_output=True, text=True)
        assert r.returncode != 0 and ("session_meta: FAILED" in r.stderr or "class must be" in r.stderr)


def test_session_meta_cli_takes_schedule_and_session(tmp_path):
    sched = tmp_path / "s.json"
    sched.write_text(json.dumps([{"session": "x1", "cls": "native", "day": 2}]))
    out = tmp_path / "other_dir_name"
    r = subprocess.run([sys.executable, str(SCRIPTS / "session_meta.py"), "--schedule", str(sched), "--session", "x1",
                        "--", "native", str(out), ""], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    m = json.loads((out / "meta.json").read_text())
    assert (m["day"], m["order"], m["batch"]) == (2, 0, 2)


# ---- run_session.sh ----

GIT_BASH = r"C:\Program Files\Git\bin\bash.exe"


def _bash_works(exe):
    try:
        ok = subprocess.run([exe, "-c", "echo ok"], capture_output=True, text=True, timeout=60).stdout.strip() == "ok"
        return ok and subprocess.run([exe, "-n", "scripts/run_session.sh"], cwd=ROOT, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.fixture(scope="module")
def bash():
    """A bash that really runs and accepts run_session.sh (Git Bash on Windows; the WSL stub is not trusted)."""
    for exe in (GIT_BASH, shutil.which("bash")):
        if exe and Path(exe).exists() and _bash_works(exe):
            return exe
    pytest.skip("no working bash")


def ansi_c(arg):
    """bash $'...' quoting: lets an argument with a newline reach the script (a Windows argv cannot carry one)."""
    return "$'" + arg.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def run_sh(bash, *args, env=None):
    cmd = "sh scripts/run_session.sh " + " ".join(ansi_c(a) for a in args)
    return subprocess.run([bash, "-c", cmd], cwd=ROOT, capture_output=True, text=True, env=env)


def test_run_session_script_is_valid_shell_and_has_hardening(bash):
    assert subprocess.run([bash, "-n", "scripts/run_session.sh"], cwd=ROOT).returncode == 0
    text = (SCRIPTS / "run_session.sh").read_text()
    assert "umask 077" in text and "trap" in text and "HUP" in text and "| grep" not in text and "grep -q" not in text
    assert b"\r" not in (SCRIPTS / "run_session.sh").read_bytes()


@pytest.mark.parametrize("win,n,bad", [("0", "10", "window_ms"), ("abc", "10", "window_ms"), ("100", "0", "n_windows"),
                                       ("100", "-5", "n_windows"), ("100", "1.5", "n_windows"),
                                       ("5\n1", "10", "window_ms"), ("100", "5\n../../evil", "n_windows"),
                                       ("007", "10", "window_ms")])
def test_run_session_rejects_bad_window_arguments_separately(bash, win, n, bad):
    r = run_sh(bash, "native", "t1", win, n)
    assert r.returncode == 1 and f"{bad} must be a whole number >= 1" in r.stderr


@pytest.mark.parametrize("sid", ["ok\n../../evil", "ok\n", "\nok", "a/b", "..", ".hidden", "-x", "a b", "a;b", ""])
def test_run_session_rejects_bad_session_ids_before_touching_anything(bash, tmp_path, sid):
    out = tmp_path / "out"
    r = run_sh(bash, "native", sid, "100", "10", out.as_posix())
    assert r.returncode == 1 and "bad session id" in r.stderr
    assert not out.exists() and not (tmp_path / "evil").exists() and list(tmp_path.iterdir()) == []


REAL_PY = Path(sys.executable).as_posix()


def fake_tools(tmp_path, python3_body=None):
    """A fake bench and a fake python3 first on PATH, so run_session.sh can run to the end without Linux sysfs.
    The fake python3 logs its arguments (and BENCH_PATH) to <tmp>/py.log. session_meta.py is faked: by python3_body,
    or by default it writes a minimal meta.json into the session folder (the 2nd argument from the end).
    session_qc.py runs for real (so the fake bench's bad CSV is caught) unless python3_body is given."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if os.name != "nt":
        bin_dir.chmod(0o755)
    bench = bin_dir / "bench"
    bench.write_text("#!/bin/sh\necho 'window,workload'\necho '0,x'\n", newline="\n")
    log = tmp_path / "py.log"
    write_meta = 'eval "D=\\${$(($#-1))}"\necho \'{"cls": "native"}\' > "$D/meta.json"\n'
    qc = 'case "$1" in *session_qc.py) exec "' + REAL_PY + '" "$@";; esac\n'
    py = bin_dir / "python3"
    py.write_text('#!/bin/sh\necho "$@ BENCH_PATH=$BENCH_PATH" >> "' + log.as_posix() + '"\n'
                  + (qc + write_meta if python3_body is None else python3_body), newline="\n")
    for f in (bench, py):
        f.chmod(0o755)
    return bench, {**os.environ, "BENCH": bench.as_posix(), "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"]}


def skip_if_perms(r):
    if "must be owned" in r.stderr or "writable" in r.stderr:
        pytest.skip("temp folder permissions are not representable here: " + r.stderr.strip())


def py_log(tmp_path):
    return (tmp_path / "py.log").read_text().splitlines()


def test_run_session_session_meta_failure_leaves_failed_marker_and_exits_nonzero(bash, tmp_path):
    bench, env = fake_tools(tmp_path, "echo 'meta exploded' >&2\nexit 3\n")
    out = tmp_path / "out"
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "session_meta.py failed" in r.stderr and "meta exploded" in r.stderr
    assert "session_meta.py failed" in (out / "s1" / "FAILED").read_text()
    assert not (out / "s1" / "meta.json").exists()
    (skipped,) = features.load_report(out)["skipped_dirs"]  # and the loader will not take the half session for a real one
    assert skipped["dir"] == "s1" and skipped["reason"].startswith("FAILED marker: session_meta.py failed")


def test_run_session_qc_failure_keeps_data_leaves_failed_marker_and_exits_nonzero(bash, tmp_path):
    bench, env = fake_tools(tmp_path)  # the fake bench writes a bad header, so the real session_qc.py must fail
    out = tmp_path / "out"
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "QC failed" in r.stderr and "session_qc: FAIL" in r.stderr
    assert "session_qc" in (out / "s1" / "FAILED").read_text()
    assert (out / "s1" / "qc.json").exists() and (out / "s1" / "meta.json").exists()
    assert len(list((out / "s1").glob("*.csv"))) == 4


def test_run_session_success_removes_the_failed_marker(bash, tmp_path):
    # both python scripts faked (the fake bench's CSV is not a real one); session_meta.py's folder is the 2nd arg from the end
    body = ('case "$1" in *session_meta.py) eval "D=\\${$(($#-1))}"; echo \'{"cls": "native"}\' > "$D/meta.json";; esac\n'
            "exit 0\n")
    bench, env = fake_tools(tmp_path, body)
    out = tmp_path / "out"
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 0, r.stderr
    assert (out / "s1" / "meta.json").exists() and not (out / "s1" / "FAILED").exists()
    assert len(list((out / "s1").glob("*.csv"))) == 4


def test_run_session_passes_double_dash_bench_path_and_unscheduled_flag(bash, tmp_path):
    bench, env = fake_tools(tmp_path)
    out = tmp_path / "out"
    r = run_sh(bash, "--allow-unscheduled", "native", "s1", "100", "10", out.as_posix(),
               env={**env, "TEMP_C": "--schedule=x"})
    skip_if_perms(r)
    meta_call = next(ln for ln in py_log(tmp_path) if "session_meta.py" in ln)
    assert "--allow-unscheduled" in meta_call and "--pilot" not in meta_call
    assert f" -- native {out.as_posix()}/s1 --schedule=x " in meta_call  # TEMP_C cannot become an option
    assert meta_call.endswith("/bin/bench")  # the fake logs BENCH_PATH last: exported by run_session.sh


def test_run_session_requires_the_schedule_unless_flagged_and_marks_a_pilot(bash, tmp_path):
    bench, env = fake_tools(tmp_path)
    for name in ("out", "pilot"):
        skip_if_perms(run_sh(bash, "native", f"s_{name}", "100", "10", (tmp_path / name).as_posix(), env=env))
    calls = [ln for ln in py_log(tmp_path) if "session_meta.py" in ln]
    assert "--pilot" not in calls[0] and "--allow-unscheduled" not in calls[0]
    assert "--pilot" in calls[1]


def test_run_session_refuses_an_existing_session_folder_and_leaves_it_alone(bash, tmp_path):
    bench, env = fake_tools(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    if os.name != "nt":
        out.chmod(0o755)
    (out / "s1").mkdir()
    (out / "s1" / "keep.txt").write_text("mine")
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "cannot create session folder" in r.stderr
    assert sorted(p.name for p in (out / "s1").iterdir()) == ["keep.txt"]
    (out / "s2").mkdir()
    (out / "s2" / "meta.json").write_text("{}")
    r = run_sh(bash, "native", "s2", "100", "10", out.as_posix(), env=env)
    assert r.returncode == 1 and "meta.json already exists" in r.stderr
    assert (out / "s2" / "meta.json").read_text() == "{}" and not (out / "s2" / "FAILED").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_run_session_refuses_a_world_writable_out_root(bash, tmp_path):
    bench, env = fake_tools(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o777)
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    assert r.returncode == 1 and "must not be world-writable" in r.stderr and list(out.iterdir()) == []


def test_run_session_script_uses_noclobber_plain_mkdir_and_double_dash():
    text = (SCRIPTS / "run_session.sh").read_text()
    assert "set -C" in text and 'mkdir -- "$D"' in text and 'mkdir -p "$D"' not in text
    assert '[ -e "$D/meta.json" ] || [ -L "$D/meta.json" ]' in text and '-- "$CLS" "$D"' in text


def test_run_session_rejects_a_missing_bench_and_creates_nothing(bash, tmp_path):
    bench, env = fake_tools(tmp_path)
    out = tmp_path / "out"
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env={**env, "BENCH": (tmp_path / "nope").as_posix()})
    assert r.returncode == 1 and ("cannot resolve bench" in r.stderr or "not found" in r.stderr)
    assert not out.exists()


# ---- session_meta: schedule is required, new fields ----

def test_session_meta_unscheduled_session_or_missing_schedule_is_a_hard_error(tmp_path):
    sched = tmp_path / "s.json"
    sched.write_text("[]")
    meta = load_script("session_meta")
    for path in (sched, tmp_path / "missing.json"):
        with pytest.raises(ValueError, match="no usable entry in the schedule"):
            meta.main("native", str(tmp_path / "zzz"), None, str(path))
        assert not (tmp_path / "zzz" / "meta.json").exists()
        r = subprocess.run([sys.executable, str(SCRIPTS / "session_meta.py"), "--schedule", str(path), "--", "native",
                            str(tmp_path / "zzz")], capture_output=True, text=True)
        assert r.returncode != 0 and "session_meta: FAILED" in r.stderr and not (tmp_path / "zzz" / "meta.json").exists()


def test_session_meta_allow_unscheduled_and_pilot_flags(tmp_path):
    meta = load_script("session_meta")
    meta.main("native", str(tmp_path / "a"), None, str(tmp_path / "none.json"), allow_unscheduled=True)
    meta.main("native", str(tmp_path / "b"), None, str(tmp_path / "none.json"), pilot=True)
    a, b = (json.loads((tmp_path / n / "meta.json").read_text()) for n in "ab")
    assert (a["pilot"], a["day"], a["order"]) == (False, None, None)
    assert (b["pilot"], b["day"], b["order"]) == (True, None, None)


def test_session_meta_cli_double_dash_keeps_option_like_temp_a_value(tmp_path):
    sched = tmp_path / "s.json"
    sched.write_text(json.dumps([{"session": "x1", "cls": "native", "day": 2}]))
    r = subprocess.run([sys.executable, str(SCRIPTS / "session_meta.py"), "--schedule", str(sched), "--session", "x1",
                        "--", "native", str(tmp_path / "d"), "--schedule=evil"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    m = json.loads((tmp_path / "d" / "meta.json").read_text())
    assert m["day"] == 2 and m["temp_c"] is None


def scheduled_meta(tmp_path, **kw):
    sched = tmp_path / "s.json"
    sched.write_text(json.dumps([{"session": "s1", "cls": "native", "day": 1}]))
    d = tmp_path / "s1"
    d.mkdir(exist_ok=True)
    return d, sched, kw


def test_session_meta_new_fields_workload_order_uptime_bench_hash_and_startup(tmp_path):
    d, sched, _ = scheduled_meta(tmp_path)
    (d / "thermal.txt").write_text("mem before=1000 after=2000 uptime_s=30\nidle before=na after=na uptime_s=oops\n"
                                   "cpu before=1 after=2 uptime_s=50\nmixed before=1 after=2 uptime_s=70\n")
    (d / "cpu.bench.txt").write_text("# bench v1 startup_ms=12.5\nnoise\n")
    (d / "mem.bench.txt").write_text("startup_ms=3\n# startup_ms=nan\n")  # not a comment line / not finite
    (d / "idle.bench.txt").write_text("# a startup_ms=oops\n# startup_ms=7\n")
    bench = tmp_path / "bench"
    bench.write_bytes(b"BIN")
    load_script("session_meta").main("native", str(d), None, str(sched), bench=str(bench))
    m = json.loads((d / "meta.json").read_text())
    assert m["workload_order"] == ["mem", "idle", "cpu", "mixed"]
    assert m["workload_uptime_s"] == {"mem": 30, "idle": None, "cpu": 50, "mixed": 70}
    assert m["bench_sha256"] == hashlib.sha256(b"BIN").hexdigest()
    assert m["bench_startup_ms"] == {"idle": 7.0, "cpu": 12.5, "mem": None, "mixed": None}
    assert "seed" not in m and m["pilot"] is False and m["python_version"] == platform.python_version()


def test_session_meta_bench_hash_comes_from_env_and_is_null_when_unreadable(tmp_path, monkeypatch, capsys):
    d, sched, _ = scheduled_meta(tmp_path)
    meta = load_script("session_meta")
    monkeypatch.delenv("BENCH_PATH", raising=False)
    meta.main("native", str(d), None, str(sched))
    m = json.loads((d / "meta.json").read_text())
    assert m["bench_sha256"] is None and m["workload_order"] == [] and set(m["bench_startup_ms"].values()) == {None}
    (d / "meta.json").unlink()
    monkeypatch.setenv("BENCH_PATH", str(tmp_path / "nope"))
    meta.main("native", str(d), None, str(sched))
    assert json.loads((d / "meta.json").read_text())["bench_sha256"] is None
    assert "cannot hash bench" in capsys.readouterr().err


def test_session_meta_refuses_to_overwrite_an_existing_meta_json(tmp_path):
    d, sched, _ = scheduled_meta(tmp_path)
    (d / "meta.json").write_text("keep")
    with pytest.raises(FileExistsError):
        load_script("session_meta").main("native", str(d), None, str(sched))
    assert (d / "meta.json").read_text() == "keep"


# ---- build_symbols.sh and run_vol_sandboxed.sh ----

def sh_script(bash, name, *args, cwd=None, env=None):
    argv = [a.replace("\\", "/") for a in args]  # POSIX-style paths, as on the real (Linux) host
    return subprocess.run([bash, (SCRIPTS / name).as_posix(), *argv], cwd=cwd, capture_output=True, text=True, env=env)


def symbol_inputs(tmp_path, d2j_name="dwarf2json"):
    """A fake vmlinux-<ver> and a fake dwarf2json that records the paths it was started with."""
    work = tmp_path / "in"
    work.mkdir()
    vm = work / "vmlinux-5.15.0-1"
    vm.write_bytes(b"kernel")
    d2j = work / d2j_name
    d2j.write_text('#!/bin/sh\necho "{\\"self\\": \\"$0\\", \\"elf\\": \\"$3\\"}"\n', newline="\n")
    d2j.chmod(0o755)
    return work, vm, d2j, hashlib.sha256(b"kernel").hexdigest(), hashlib.sha256(d2j.read_bytes()).hexdigest()


def test_build_symbols_runs_a_hashed_private_copy_never_the_originals(bash, tmp_path):
    work, vm, d2j, vm_sha, d2j_sha = symbol_inputs(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = sh_script(bash, "build_symbols.sh", str(vm), vm_sha.upper(), str(d2j), d2j_sha, str(out), env={**os.environ, "TMPDIR": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    isf = json.loads((out / "ubuntu-5.15.0-1.json").read_text())
    assert Path(isf["self"]).name == "dwarf2json" and Path(isf["elf"]).name == "vmlinux-5.15.0-1"
    assert Path(isf["self"]).parent != work and Path(isf["elf"]).parent != work  # ran the copies
    assert Path(isf["self"]).parent == Path(isf["elf"]).parent
    assert not Path(isf["self"]).parent.exists()  # private temp dir removed on exit
    assert (out / "ubuntu-5.15.0-1.json.sha256").exists() and not list(out.glob("*.XXXXXX"))


def test_build_symbols_bare_dwarf2json_name_is_taken_from_the_current_folder_not_path(bash, tmp_path):
    work, vm, d2j, vm_sha, d2j_sha = symbol_inputs(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = sh_script(bash, "build_symbols.sh", str(vm), vm_sha, "dwarf2json", d2j_sha, str(out), cwd=work)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("which,bad", [("vm", ""), ("vm", "abc"), ("vm", "g" * 64), ("d2j", ""), ("d2j", "a" * 63), ("d2j", "a" * 65)])
def test_build_symbols_requires_both_hashes_to_be_exactly_64_hex(bash, tmp_path, which, bad):
    work, vm, d2j, vm_sha, d2j_sha = symbol_inputs(tmp_path)
    args = [str(vm), bad if which == "vm" else vm_sha, str(d2j), bad if which == "d2j" else d2j_sha, str(tmp_path)]
    r = sh_script(bash, "build_symbols.sh", *args)
    assert r.returncode == 2 and "64 hex" in r.stderr and not list(tmp_path.glob("ubuntu-*"))


def test_build_symbols_hash_mismatch_and_sha256sum_failure_are_clear_errors(bash, tmp_path):
    work, vm, d2j, vm_sha, d2j_sha = symbol_inputs(tmp_path)
    r = sh_script(bash, "build_symbols.sh", str(vm), "0" * 64, str(d2j), d2j_sha, str(tmp_path))
    assert r.returncode == 1 and "SHA-256 mismatch" in r.stderr
    broken = tmp_path / "broken.sh"  # bash runs $BASH_ENV first: a sha256sum that always fails
    broken.write_text("sha256sum() { return 1; }\n", newline="\n")
    env = {**os.environ, "BASH_ENV": broken.as_posix()}
    r = sh_script(bash, "build_symbols.sh", str(vm), vm_sha, str(d2j), d2j_sha, str(tmp_path), env=env)
    assert r.returncode == 1 and "sha256sum failed" in r.stderr and not list(tmp_path.glob("ubuntu-*.json"))


def test_run_vol_sandboxed_is_valid_shell_and_has_the_hardening_flags(bash):
    path = SCRIPTS / "run_vol_sandboxed.sh"
    assert subprocess.run([bash, "-n", str(path)]).returncode == 0
    text = path.read_text()
    for needle in ("--tmpfs /run", "--tmpfs /var/run", "--clearenv", "--allow-unsandboxed-fs", "VOL_ALLOW_WEAK_SANDBOX",
                   "kernel.apparmor_restrict_unprivileged_userns=1", "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"):
        assert needle in text
    assert "VOL_BWRAP_HIDE_HOME" not in text and "XDG_CACHE_HOME" not in text and b"\r" not in path.read_bytes()


def vol_env(tmp_path):
    """No bwrap; a fake `unshare` that works, so only the weak-sandbox policy decides."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "unshare").write_text('#!/bin/sh\nshift\n[ "$1" = true ] && exit 0\nshift 0\nexec "$@"\n', newline="\n")
    (fake / "unshare").chmod(0o755)
    (fake / "vol").write_text("#!/bin/sh\necho vol-ran\n", newline="\n")
    (fake / "vol").chmod(0o755)
    dump = tmp_path / "mem.raw"
    dump.write_bytes(b"x")
    dump.chmod(0o444)
    env = {k: v for k, v in os.environ.items() if k not in ("VOL_ALLOW_WEAK_SANDBOX", "VOL_ALLOW_NETWORK")}
    return dump, fake / "vol", {**env, "PATH": str(fake) + os.pathsep + os.environ["PATH"]}


def test_run_vol_sandboxed_refuses_the_unshare_fallback_without_an_explicit_opt_in(bash, tmp_path):
    dump, vol, env = vol_env(tmp_path)
    r = sh_script(bash, "run_vol_sandboxed.sh", str(dump), str(vol), env=env)
    if "writable" in r.stderr or "process-count" in r.stderr or "bwrap" not in r.stderr and r.returncode != 2:
        pytest.skip("cannot exercise the sandbox policy here: " + r.stderr.strip())
    assert r.returncode == 2 and "NO filesystem isolation" in r.stderr and "vol-ran" not in r.stdout
    for opt_in in (["--allow-unsandboxed-fs"], []):
        e = {**env, **({"VOL_ALLOW_WEAK_SANDBOX": "1"} if not opt_in else {})}
        r = sh_script(bash, "run_vol_sandboxed.sh", *opt_in, str(dump), str(vol), env=e)
        assert r.returncode == 0 and "vol-ran" in r.stdout and "NOT applied" in r.stderr


# ---- session_meta: temp and schedule labels ----
@pytest.mark.parametrize("temp", ["abc", "0x10", "12C", "1,5", "--"])
def test_session_meta_non_numeric_temperature_is_null_with_warning(tmp_path, capsys, temp):
    load_script("session_meta").main("native", str(tmp_path / "s"), temp, str(tmp_path / "none.json"), allow_unscheduled=True)
    assert json.loads((tmp_path / "s" / "meta.json").read_text())["temp_c"] is None
    assert "not a number" in capsys.readouterr().err


def test_session_meta_numeric_temperature_is_kept_without_warning(tmp_path, capsys):
    load_script("session_meta").main("native", str(tmp_path / "s"), "41.5", str(tmp_path / "none.json"), allow_unscheduled=True)
    assert json.loads((tmp_path / "s" / "meta.json").read_text())["temp_c"] == 41.5
    assert "temperature" not in capsys.readouterr().err


@pytest.mark.parametrize("entry", [{"day": 0}, {"day": -3}, {"day": ""}, {"day": "   "}, {"day": 2, "batch": 0},
                                   {"day": 2, "batch": ""}, {"day": 2, "batch": -1}])
def test_schedule_day_and_batch_must_be_positive_ints_or_non_empty_strings(tmp_path, capsys, entry):
    assert sched_entry(tmp_path, [{"session": "a", **entry}]) == (None, None, None)
    err = capsys.readouterr().err
    assert "warning" in err and "invalid day/batch" in err and "stored as null" in err


# ---- run_session.sh: --retry and the thermal default ----
SUCCESS_BODY = ('case "$1" in *session_meta.py) eval "D=\\${$(($#-1))}"; echo \'{"cls": "native"}\' > "$D/meta.json";; esac\n'
                "exit 0\n")


def failed_session(out, name="s1", **files):
    out.mkdir(exist_ok=True)
    if os.name != "nt":
        out.chmod(0o755)
    d = out / name
    d.mkdir()
    (d / "FAILED").write_text("QC failed\n")
    (d / "qc.json").write_text("{}")
    for fn, text in files.items():
        (d / fn).write_text(text)
    return d


def test_run_session_without_retry_names_the_exact_retry_command_and_qc_json(bash, tmp_path):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    d = failed_session(out)
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "FAILED marker" in r.stderr and "qc.json" in r.stderr
    assert f"--retry native s1 100 10 {out.as_posix()}" in r.stderr
    assert sorted(p.name for p in d.iterdir()) == ["FAILED", "qc.json"] and (d / "FAILED").read_text() == "QC failed\n"
    assert [p.name for p in out.iterdir()] == ["s1"]


@pytest.mark.parametrize("flags", [("--retry",), ("--retry", "--allow-unscheduled"), ("--allow-unscheduled", "--retry")])
def test_run_session_retry_renames_the_failed_folder_and_starts_fresh(bash, tmp_path, flags):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    old = failed_session(out, **{"idle.csv": "old data"})
    r = run_sh(bash, *flags, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 0, r.stderr
    (moved,) = [p for p in out.iterdir() if p.name != "s1"]
    assert re.fullmatch(r"s1\.failed-\d{8}T\d{6}Z", moved.name)
    assert (moved / "idle.csv").read_text() == "old data" and (moved / "FAILED").exists() and (moved / "qc.json").exists()
    assert (out / "s1" / "meta.json").exists() and not (out / "s1" / "FAILED").exists()
    assert "old data" not in (out / "s1" / "idle.csv").read_text()
    assert old.exists() and (old / "meta.json").exists()  # the fresh session is the one at the old path


def test_run_session_retry_never_touches_a_session_with_meta_json(bash, tmp_path):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    d = failed_session(out, **{"meta.json": "{}"})
    r = run_sh(bash, "--retry", "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "meta.json already exists" in r.stderr
    assert sorted(p.name for p in d.iterdir()) == ["FAILED", "meta.json", "qc.json"] and [p.name for p in out.iterdir()] == ["s1"]


def test_run_session_retry_refuses_a_folder_without_a_failed_marker(bash, tmp_path):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    out.mkdir()
    if os.name != "nt":
        out.chmod(0o755)
    (out / "s1").mkdir()
    (out / "s1" / "keep.txt").write_text("mine")
    r = run_sh(bash, "--retry", "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 1 and "no FAILED marker" in r.stderr
    assert [p.name for p in (out / "s1").iterdir()] == ["keep.txt"] and [p.name for p in out.iterdir()] == ["s1"]


def test_run_session_retry_on_a_new_session_just_runs(bash, tmp_path):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    r = run_sh(bash, "--retry", "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    assert r.returncode == 0 and (out / "s1" / "meta.json").exists() and [p.name for p in out.iterdir()] == ["s1"]


@pytest.mark.skipif(glob.glob("/sys/class/thermal/thermal_zone*/temp"), reason="this host has thermal zones")
def test_run_session_missing_thermal_zone_is_recorded_as_na_after_the_workload_too(bash, tmp_path):
    bench, env = fake_tools(tmp_path, SUCCESS_BODY)
    out = tmp_path / "out"
    r = run_sh(bash, "native", "s1", "100", "10", out.as_posix(), env=env)
    skip_if_perms(r)
    lines = (out / "s1" / "thermal.txt").read_text().splitlines()
    assert len(lines) == 4 and all(" before=na after=na uptime_s=" in ln for ln in lines)


def test_run_session_script_has_retry_flag_and_never_deletes_a_failed_folder():
    text = (SCRIPTS / "run_session.sh").read_text()
    assert "--retry" in text and ".failed-" in text and "rm -r" not in text
