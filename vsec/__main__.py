"""python -m vsec run [options]   |   audit <case-folder>   |   m3 <dump>   |   pilot --data DIR"""
import argparse
import functools
import json
import math
import os
import re
import shutil
import sys
import time
import traceback
from pathlib import Path

from . import ROOT, clean_text, finding, jsonable, m1_audit, m2_snapshot, m3_forensics, report, score

FAST = {"reps": 200, "repeats": 1}
FAST_NOTE = "FAST mode: 200 bootstrap reps, 1 CV repeat: not citable"
DEFAULT_T_SHORT = 1.0
SIM_KW = {"per_class": 15}  # --simulate size (tests shrink it)
GEN_FIXTURES = ROOT / ".local" / "work" / "fixtures"  # regenerated (deleted first) on every run without --fixtures
LOG_DIR = ROOT / ".local" / "work" / "logs"  # one traceback file per failed module
CVES_FIXTURE = "cves_fixture.yaml"  # written by tests/make_fixtures.py: verified CVE list, fixture scoring only
MAX_TRACEBACK_CHARS = 20_000  # traceback kept in the report and the log
MAX_REASON_CHARS = 500  # one-line error reason


def _vm_spec(text):
    name, sep, folder = text.partition("=")
    if not sep or not name or not folder:
        raise argparse.ArgumentTypeError(f"expected NAME=CASE_FOLDER, got {text!r}")
    if not Path(folder).is_dir():
        raise argparse.ArgumentTypeError(f"case folder not found: {folder}")
    return name, folder


def _positive_int(text):
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _positive_float(text):
    try:
        x = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(x) or x <= 0:
        raise argparse.ArgumentTypeError(f"must be a finite number > 0, got {text!r}")
    return x


def _na(reason):
    """A module with nothing to run (no data supplied). A crashed module is ERROR, not NA."""
    return {"status": "NA", "reason": str(reason)}


def _short(text, limit):
    """clean_text(text) cut to `limit` characters (an ellipsis marks the cut)."""
    text = clean_text(text)
    return text if len(text) <= limit else text[:limit] + "..."


def _fail(name, exc):
    """ERROR result for the exception being handled: logged to LOG_DIR and printed, never swallowed."""
    # exception text can carry guest-derived data (e.g. Volatility's stderr): strip control/bidi characters, cap size
    tb = "\n".join(clean_text(line) for line in traceback.format_exc().splitlines())[-MAX_TRACEBACK_CHARS:]
    print(f"error: module {name} failed\n{tb}", file=sys.stderr)
    log = LOG_DIR / (re.sub(r"\W+", "_", name).strip("_").lower() + ".log")
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log.write_text(tb, encoding="utf-8")
    except OSError as e:
        print(f"warning: could not write {log}: {e}", file=sys.stderr)
    return {"status": "ERROR", "reason": _short(f"{type(exc).__name__}: {exc}", MAX_REASON_CHARS), "traceback": tb}


def _module(fn, name="module"):
    """Run one module: (result dict, findings). fn returns (dict, findings); a crash or a non-dict result
    becomes an ERROR entry, so one broken module cannot kill the report (and cannot pass as NA)."""
    t0 = time.perf_counter()
    try:
        res, findings = fn()
        if not isinstance(res, dict):
            raise TypeError(f"module returned {type(res).__name__}, expected a dict")
    except Exception as e:  # noqa: BLE001 - reported as ERROR with the full traceback
        res, findings = _fail(name, e), []
    res["elapsed_s"] = round(time.perf_counter() - t0, 2)
    return res, findings


@functools.lru_cache(maxsize=None)
def _make_fixtures():
    tests = str(ROOT / "tests")
    if tests not in sys.path:
        sys.path.insert(0, tests)
    import make_fixtures
    return make_fixtures


def _fixtures_dir(arg):
    """arg None: regenerate into a fresh GEN_FIXTURES (never reuse an old or committed copy). arg given: use it
    only if it holds answer_key.json."""
    if arg is not None:
        fixtures = Path(arg)
        if not (fixtures / "answer_key.json").is_file():
            raise FileNotFoundError(f"--fixtures {fixtures} has no answer_key.json (omit --fixtures to regenerate)")
        return fixtures
    if GEN_FIXTURES.exists():
        shutil.rmtree(GEN_FIXTURES)
    _make_fixtures().main(GEN_FIXTURES)
    return GEN_FIXTURES


def _score_fixtures(arg):
    fixtures = _fixtures_dir(arg)
    key = json.loads((fixtures / "answer_key.json").read_text(encoding="utf-8"))
    cves = fixtures / CVES_FIXTURE  # verified list: the real one is unverified, which would make C23/C24 NA
    cves_path = cves if cves.is_file() else None
    pred = {c: {f["id"]: f["status"] for f in m1_audit.audit(fixtures / c, env="E1", cves_path=cves_path)}
            for c in key}
    return {"evaluation_synthetic": score.score_m1(pred, key), "kind": "self_consistency", "cases": len(key)}


def run_m1(fixtures_arg, vms, env="E0"):
    """Host audits (--vm) run first and on their own: a broken fixture set must not discard their findings."""
    findings, errors = [], []
    for name, folder in vms:
        try:
            findings += m1_audit.audit(folder, env=env, vm=name)
        except Exception as e:  # noqa: BLE001
            errors.append((f"M1 audit of {name}", _fail(f"m1_audit_{name}", e)))
    try:
        out = _score_fixtures(fixtures_arg)
    except Exception as e:  # noqa: BLE001
        out = {"kind": "self_consistency"}
        errors.append(("M1 fixture scoring", _fail("m1_fixtures", e)))
    if errors:
        out.update(status="ERROR", reason="; ".join(f"{n}: {d['reason']}" for n, d in errors),
                   traceback="\n".join(d["traceback"] for _, d in errors))
    return out, findings


def _c29(res):
    """(status, evidence) for C29 from m2_snapshot.evaluate(): PASS only if the scanner proved itself on every
    planted secret AND found nothing, so a blind scanner can never produce a PASS."""
    if res.get("synthetic"):
        return "NA", "synthetic"
    hits = res.get("total_hits")
    if hits is None:
        return "NA", "scanner hit count unavailable (evaluate() returned no total_hits)"
    cells = res["cells"].values()
    missed = sum(c["present"] - c["detected"] for c in cells)
    absent = sum(c["planted_but_absent"] for c in cells)
    if hits > 0:
        also = f" (scanner also missed {missed} known planted secrets)" if missed else ""
        return "FAIL", f"{hits} secret(s) found in dumps{also}"
    if missed:
        return "NA", f"scanner missed {missed} known planted secrets: result not trustworthy"
    if absent:
        return "NA", f"{absent} planted secrets are not in the dumps: ground truth invalid"
    if not res.get("gb_scanned"):
        return "NA", "no bytes scanned"
    return "PASS", "no secrets found"


def run_m2(args):
    synthetic = not args.m2_dumps
    dumps = m2_snapshot.synthetic_dumps(n=args.m2_n) if synthetic else m2_snapshot.load_dumps(args.m2_dumps)
    res = m2_snapshot.evaluate(dumps, synthetic=synthetic)
    return res, [finding("C29", *_c29(res), vm="m2-dumps")]


def _operator_sha(arg):
    """The symbols hash the operator supplied now (flag, else env VSEC_SYMBOLS_SHA256), lowercase; None if none.
    ValueError if one was given but is not 64 hex characters."""
    raw = arg if arg is not None else os.environ.get(m3_forensics.SYMBOLS_SHA_ENV)  # an empty flag is a typo, not "none"
    sha = m3_forensics.normalize_sha256(raw)
    if sha is None and (arg is not None or str(raw or "").strip()):
        raise ValueError(f"the symbols SHA-256 must be exactly 64 hex characters, got {_short(raw, 80)!r}")
    return sha


def _symbols_verified(row, expected_sha):
    """True only if the row says it was verified AND the hash it recorded equals the one the operator supplied
    now. A bare `symbols_sha_verified: true` in a results file proves nothing: anyone can write it."""
    flagged = row.get("symbols_sha_verified") is True or row.get("symbols_verified") is True
    return bool(flagged and expected_sha and m3_forensics.normalize_sha256(row.get("symbols_sha256")) == expected_sha)


def _excluded_count(row):
    excluded = row.get("excluded_exited")
    return len(excluded) if isinstance(excluded, list) else 0


def _c30(row, expected_sha=None):
    """(status, evidence) for one M3 result row {name, truth_hidden, detected, symbols_sha_verified,
    symbols_sha256, excluded_exited}. expected_sha: the hash the operator supplied (see _operator_sha)."""
    name = row.get("name")
    if not _symbols_verified(row, expected_sha):
        why = "recorded hash differs from the supplied one or is missing" if expected_sha else "no hash supplied to compare"
        return "NA", f"{name}: symbols not hash-verified ({why}): result not trustworthy"
    if _excluded_count(row):
        return "NA", f"{name}: {_excluded_count(row)} rows excluded by exit-state (guest-controlled field)"
    truth, got = set(map(str, row["truth_hidden"])), set(map(str, row["detected"]))
    missed = len(truth - got)
    if truth and got:
        also = f", detector missed {missed} known hidden items" if missed else ""
        return "FAIL", f"{name}: VM has hidden items ({len(got)} detected{also})"
    if truth:
        return "NA", f"{name}: detector missed {missed} known hidden items"
    if got:
        return "FAIL", f"{name}: {len(got)} hidden item(s) detected in a dump with none planted"
    return "PASS", f"{name}: no hidden items, none detected"


def run_m3(args):
    if not args.m3_results:
        return _na("no results: pass --m3-results (see README)"), []
    expected = _operator_sha(getattr(args, "symbols_sha256", None))
    results = json.loads(Path(args.m3_results).read_text(encoding="utf-8"))
    res = m3_forensics.evaluate(results)
    res["symbols_unverified"] = [str(r.get("name")) for r in results if not _symbols_verified(r, expected)]
    res["exclusions"] = [str(r.get("name")) for r in results if _excluded_count(r)]
    return res, [finding("C30", *_c30(row, expected), vm="m3-images") for row in results]


def _load_problems(rep):
    """Plain-English lines about what features.load_report says was skipped, cut or missing."""
    out = []
    if rep.get("skipped_dirs"):
        out.append(f"{len(rep['skipped_dirs'])} session folder(s) skipped: "
                   + ", ".join(f"{d['dir']} ({d['reason']})" for d in rep["skipped_dirs"]))
    if rep.get("total_truncated_rows"):
        out.append(f"{rep['total_truncated_rows']} truncated CSV row(s) dropped")
    missing = [s["session"] for s in rep.get("sessions", []) if s.get("missing_workloads")]
    if missing:
        out.append(f"sessions with missing workloads: {', '.join(missing)}")
    return out


def _m4_notes(conf, load_rep):
    notes = []
    differs = [f for f, v in conf.items() if v.get("differs")]
    if differs:
        notes.append(f"CONFOUND: setup fields differ across classes ({', '.join(differs)}): "
                     "a classifier may be separating the setup, not the hypervisor.")
    gate = conf.get("clocksource_gate", {})
    if gate.get("failures"):
        notes.append(f"CLOCK GATE: {len(gate['failures'])} session(s) not on the tsc clock source "
                     f"({', '.join(gate['failures'])}); timing results are suspect.")
    notes += [f"LOAD: {p}" for p in _load_problems(load_rep)]
    return notes


def run_m4(args):
    from .m4_detect import classify, features, simulate
    simulated = not args.m4_data and args.simulate
    load_rep = {}
    if args.m4_data:
        if args.t_short is None:
            raise ValueError("--t-short is required with --m4-data: pass --t-short from `python -m vsec pilot`")
        sessions, load_rep = features.load(args.m4_data), features.load_report(args.m4_data)
    elif simulated:
        sessions = simulate.simulate_sessions(**SIM_KW)
    else:
        return _na("no M4 data: pass --m4-data DIR (or --simulate for a pipeline check)"), []
    t_short = DEFAULT_T_SHORT if args.t_short is None else args.t_short
    opts = {"families": ("logreg",), **FAST} if args.fast else {"families": ("logreg", "rf")}
    if simulated:  # a simulated run has its own size; real data must have exactly the expected 15 per class
        opts["expected_per_class"] = SIM_KW["per_class"]
    res = classify.analyze(sessions, t_short=t_short, **opts)
    res.setdefault("settings", {}).update(t_short=t_short, t_short_source="default" if args.t_short is None else "cli")
    res["indicator_leaks"] = features.indicator_table(sessions)
    res["balance"] = features.balance(sessions)
    res["confounds"] = features.confounds(sessions)
    res["load_report"] = load_rep
    res.setdefault("notes", []).extend(_m4_notes(res["confounds"], load_rep))
    if args.fast:
        res["fast"] = True
        res["notes"].insert(0, FAST_NOTE)
    if simulated:
        res["simulated"] = True
        res["citable"] = False  # simulated data is never citable, whatever the session counts say
        res.setdefault("exploratory_reasons", []).append("simulated data")
    findings = []
    for p in res.get("session_predictions", []):
        if simulated:
            status, ev = "NA", "synthetic"
        else:
            status = "PASS" if p["declared"] == p["predicted"] else "FAIL"
            ev = f"{p['session']}: declared {p['declared']}, predicted {p['predicted']}"
        findings.append(finding("C31", status, ev, vm="m4-sessions"))
    return res, findings


def pilot_report(sessions, per_class_min=5):
    """T_short from PILOT sessions (classify.choose_t_short) plus the single/combined session AUROC per T."""
    from .m4_detect import classify
    res = classify.choose_t_short(sessions, min_sessions=per_class_min)
    grid = {}
    for t in classify.TS:
        try:
            r = classify.evaluate_at(sessions, classify.PRIMARY_PAIR, t, classify.PRIMARY_FAMILY, 0, 1,
                                     modes=("single", "combined"), min_sessions=per_class_min)
            grid[t] = {m: r[m]["auroc"] for m in ("single", "combined")}
        except ValueError as e:  # too few sessions with data at this T
            grid[t] = {"single": None, "combined": None, "reason": str(e)}
    return {**res, "auroc_grid": grid, "per_class_min": per_class_min, "pilot_sessions": len(sessions)}


def _auroc_cell(v):
    return f"{v:.3f}" if isinstance(v, float) and math.isfinite(v) else "n/a"


def _pilot_text(out):
    """Short human-readable pilot summary (the full dict is available with --json)."""
    t = out["t_short"]
    lines = [f"T_short = {t} s" if t is not None else f"no T_short chosen: {out['reason']}",
             f"({out['pilot_sessions']} pilot sessions, at least {out['per_class_min']} per class needed)", "",
             "  T (s)  single AUROC  combined AUROC"]
    lines += [f"  {tt:5}  {_auroc_cell(c['single']):>12}  {_auroc_cell(c['combined']):>14}"
              for tt, c in out["auroc_grid"].items()]
    reasons = {**out.get("errors", {}), **{tt: c["reason"] for tt, c in out["auroc_grid"].items() if c.get("reason")}}
    lines += ["", *(f"T={tt} s: {why}" for tt, why in sorted(reasons.items()))] if reasons else []
    if t is not None:
        lines += ["", f"Put this value into prereg.md PILOT: T_short = {t} s (pilot data only, never the study boots)."]
    return "\n".join(lines)


def cmd_pilot(args):
    """Exit 0: T_short chosen. 1: valid sessions but none chosen. 2: error, or no valid session in the folder."""
    from .m4_detect import features
    try:
        sessions = features.load(args.data)
        if not sessions:
            skipped = features.load_report(args.data).get("skipped_dirs", [])
            why = "; ".join(f"{d['dir']} ({d['reason']})" for d in skipped) or "no session folders (each needs a meta.json)"
            print(f"error: no valid pilot session found in {args.data}: {why}", file=sys.stderr)
            return 2
        out = pilot_report(sessions, args.per_class_min)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(jsonable(out), indent=1) if args.json else _pilot_text(out))
    return 0 if out["t_short"] is not None else 1


def _warn(modules):
    weak = [f"{n} ({'NA' if m.get('status') == 'NA' else 'synthetic/simulated'})" for n, m in modules.items()
            if m.get("status") == "NA" or m.get("synthetic") or m.get("simulated")]
    if weak:
        print("warning: not real results: " + ", ".join(weak), file=sys.stderr)


def cmd_run(args):
    """Returns the exit code: 1 if any module crashed (ERROR); NA modules only warn."""
    steps = (("M1 (audit)", lambda: run_m1(args.fixtures, args.vm, args.env)),
             ("M2 (snapshot privacy)", lambda: run_m2(args)),
             ("M3 (forensics)", lambda: run_m3(args)), ("M4 (hypervisor detection)", lambda: run_m4(args)))
    modules, findings = {}, []
    for name, step in steps:
        modules[name], fs = _module(step, name)
        findings += fs
    m2, m3, m4 = (modules[n] for n in ("M2 (snapshot privacy)", "M3 (forensics)", "M4 (hypervisor detection)"))
    notes = ["M1 results are self-consistency tests: one author wrote both checker and fixtures (solo project), "
             "not independent ground truth."]
    if m2.get("synthetic"):
        notes.append("M2 results are from SYNTHETIC dumps. Run on real `virsh dump` output with --m2-dumps.")
    if m3.get("symbols_unverified"):
        notes.append("M3 images without a verified symbols hash give C30 = NA: " + ", ".join(m3["symbols_unverified"]))
    if m4.get("simulated"):
        notes.append("M4 results are from SIMULATED data. They only check the pipeline.")
    notes += m4.get("notes", [])
    failed = report.failed_modules(modules)
    rep = {"contains_simulated_or_synthetic": report.contains_synthetic(modules), "fast": bool(m4.get("fast")),
           "modules_failed": failed, "modules_na": report.na_modules(modules), "notes": notes,
           "modules": modules, "findings": findings, "matrix": report.matrix(findings)}
    print(report.write(rep, args.out))
    _warn(modules)
    if failed:
        print("error: modules failed: " + ", ".join(f["name"] for f in failed), file=sys.stderr)
    return 1 if failed else 0


def cmd_audit(args):
    try:
        findings = m1_audit.audit(args.folder, env=args.env)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for f in findings:
        print(f"{f['id']} {f['status']:4} {f['control']:22} {clean_text(f['evidence'])}")
    return 1 if any(f["status"] == "FAIL" for f in findings) else 0


def _truth_ids(text):
    """'4, evilmod,,7' -> [4, 'evilmod', 7]: whole numbers become ints (a PID), anything else stays a name."""
    items = [t.strip() for t in (text or "").split(",") if t.strip()]
    return [int(t) if t.isascii() and t.isdecimal() else t for t in items]


def _load_rows(path):
    """The JSON list in `path` ([] if the file does not exist). ValueError if it is not a JSON list."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise ValueError(f"{path} is not readable JSON, refusing to touch it ({type(e).__name__})") from None
    if not isinstance(rows, list):
        raise ValueError(f"{path} does not hold a JSON list, refusing to touch it")
    return rows


def _m3_row(args, res, sha):
    """One `run --m3-results` row from a detect() result. symbols_sha256 is the hash the OPERATOR supplied (None
    with --allow-unverified and no hash), so run can compare it with the one it is given."""
    return {"name": args.row_name, "truth_hidden": _truth_ids(args.truth_hidden),
            "detected": [*res.get("hidden_pids", []), *res.get("hidden_modules", [])],
            "symbols_sha256": sha, "symbols_sha_verified": bool(res.get("symbols_sha_verified", False)),
            "excluded_exited": res.get("excluded_exited") or []}


def _row_options_error(args):
    """Why the --row-name family of options cannot be used, or None. Checked before Volatility runs."""
    if not args.row_name:
        extra = [o for o, v in (("--append", args.append), ("--truth-hidden", args.truth_hidden)) if v is not None]
        return f"{' and '.join(extra)} need --row-name" if extra else None
    if not args.row_name.strip():
        return "--row-name must not be empty"
    if args.append:
        try:
            _load_rows(args.append)
        except ValueError as e:
            return str(e)
    return None


def _write_row(args, res, sha):
    row = jsonable(_m3_row(args, res, sha))
    if not args.append:
        print(f"result row (use --append FILE to collect rows for `run --m3-results`): {json.dumps(row)}", file=sys.stderr)
        return 0
    try:
        rows = _load_rows(args.append)
        Path(args.append).write_text(json.dumps([*rows, row], indent=1), encoding="utf-8")
    except (ValueError, OSError) as e:
        print(f"error: could not append the row: {_short(e, MAX_REASON_CHARS)}", file=sys.stderr)
        return 1
    print(f"row {row['name']!r} appended to {args.append} ({len(rows) + 1} rows)", file=sys.stderr)
    return 0


def cmd_m3(args):
    if not m3_forensics.available():
        print("error: Volatility 3 not found; install it or set the VOL environment variable", file=sys.stderr)
        return 2
    try:
        sha = _operator_sha(args.symbols_sha256)  # a mistyped hash is an error even with --allow-unverified
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not sha and not args.allow_unverified:
        print("error: the symbols hash is required: pass --symbols-sha256 HASH or set "
              f"{m3_forensics.SYMBOLS_SHA_ENV} (the value recorded in prereg.md), or pass --allow-unverified "
              "for a throwaway check", file=sys.stderr)
        return 2
    problem = _row_options_error(args)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    sandboxed = m3_forensics.sandbox_available()
    if not sandboxed and not args.allow_unsandboxed:
        print("error: the Volatility sandbox is unavailable here (needs a POSIX sh and scripts/run_vol_sandboxed.sh): "
              "Volatility would parse the untrusted dump with no memory limit and network access; pass "
              "--allow-unsandboxed to run anyway (recorded as sandboxed: false)", file=sys.stderr)
        return 2
    try:
        res = m3_forensics.detect(args.dump, args.symbols, sandbox=sandboxed,
                                  expected_sha256=sha, allow_unverified=args.allow_unverified)
    except (RuntimeError, ValueError, OSError) as e:  # may carry Volatility's stderr: guest-derived text
        print(f"error: {_short(e, MAX_REASON_CHARS)}", file=sys.stderr)
        return 1
    res = {**res, "symbols_verified": bool(res.get("symbols_sha_verified", bool(sha)))}
    print(f"sandboxed={res.get('sandboxed')} symbols_sha_verified={res.get('symbols_sha_verified')} "
          f"vol_version={res.get('vol_version')}", file=sys.stderr)
    print(json.dumps(jsonable(res), indent=1))
    return _write_row(args, res, sha) if args.row_name else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vsec")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="full report (exit 1 if any module failed)")
    r.add_argument("--fixtures", default=None, help="M1 fixture folder with answer_key.json "
                   "(default: regenerate into .local/work/fixtures)")
    r.add_argument("--vm", action="append", default=[], type=_vm_spec, metavar="NAME=CASE_FOLDER")
    r.add_argument("--m2-dumps")
    r.add_argument("--m2-n", type=_positive_int, default=10)
    r.add_argument("--m3-results")
    r.add_argument("--symbols-sha256", help="symbols hash you trust (or env "
                   f"{m3_forensics.SYMBOLS_SHA_ENV}): an M3 result row only counts as verified if its recorded hash equals it")
    r.add_argument("--m4-data")
    r.add_argument("--env", default="E0", help="environment of the --vm hosts: E0 (C02 is N/A) or E1")
    r.add_argument("--simulate", action="store_true")
    r.add_argument("--t-short", type=_positive_float,
                   help="T_short in seconds from `python -m vsec pilot` (required with --m4-data)")
    r.add_argument("--fast", action="store_true", help="quick M4 run: 200 bootstrap reps, 1 CV repeat, logreg only")
    r.add_argument("--out", default=str(ROOT / "out"))
    a = sub.add_parser("audit", help="audit one captured case folder (exit 1 if any FAIL, 2 if folder missing)")
    a.add_argument("folder")
    a.add_argument("--env", default="E0")
    pl = sub.add_parser("pilot", help="choose T_short from M4 pilot sessions (value goes into prereg.md PILOT)")
    pl.add_argument("--data", required=True)
    pl.add_argument("--per-class-min", type=_positive_int, default=5)
    pl.add_argument("--json", action="store_true", help="print the full result as JSON instead of the short summary")
    m = sub.add_parser("m3", help="hidden process/module check on one dump")
    m.add_argument("dump")
    m.add_argument("--symbols")
    m.add_argument("--symbols-sha256", help=f"expected SHA-256 of the symbol file (or env {m3_forensics.SYMBOLS_SHA_ENV})")
    m.add_argument("--allow-unverified", action="store_true", help="run without a symbols hash (result recorded unverified)")
    m.add_argument("--allow-unsandboxed", action="store_true",
                   help="run Volatility even when the sandbox wrapper is unavailable (recorded as sandboxed: false)")
    m.add_argument("--row-name", help="also build a result row for `run --m3-results` under this image name")
    m.add_argument("--truth-hidden", help="with --row-name: comma-separated PIDs/module names planted as hidden "
                   "(omit for a clean dump)")
    m.add_argument("--append", metavar="FILE", help="with --row-name: append the row to this JSON list "
                   "(created if missing; a file that is not a list is refused)")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        if args.simulate and args.m4_data:
            ap.error("--simulate and --m4-data cannot be used together")
        if args.m4_data and args.t_short is None:
            ap.error("--t-short is required with --m4-data: pass --t-short from `python -m vsec pilot`")
    return {"run": cmd_run, "audit": cmd_audit, "m3": cmd_m3, "pilot": cmd_pilot}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
