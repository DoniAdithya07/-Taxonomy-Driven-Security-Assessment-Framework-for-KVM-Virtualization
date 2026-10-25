"""M3: offline memory forensics on `virsh dump` output with Volatility 3.

Scope: unlinked (hidden) processes and modules only. Checks happen only when a dump is taken.
Plugin names differ between Volatility 3 releases; check them with `vol --help` and edit PLUGINS.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import ROOT, clean_text
from .score import clopper_pearson

PLUGINS = {"pslist": "linux.pslist.PsList", "psscan": "linux.psscan.PsScan",
           "lsmod": "linux.lsmod.Lsmod", "hidden_modules": "linux.hidden_modules.Hidden_modules"}
EXITED_WORDS = ("exit", "dead", "zombie")
# columns that tell two tasks with the same PID apart, best first; used only if present in BOTH pslist and psscan
IDENTITY_COLUMNS = ("Offset", "OFFSET (V)", "Offset(V)", "Address", "TID")
NO_IDENTITY_NOTE = ("no Offset/Address/TID column in both pslist and psscan: tasks compared by PID only "
                    "(a hidden task that reuses a listed PID is not detected)")
MAX_MESSAGE_CHARS = 300  # guest-derived text in an error message is cut to this
SANDBOX = ROOT / "scripts" / "run_vol_sandboxed.sh"
SYMBOLS_SHA_ENV = "VSEC_SYMBOLS_SHA256"
ISF_EXTENSIONS = (".json", ".json.xz", ".json.gz", ".json.bz2", ".zip")
MAX_SKIPPED_FRACTION = 0.20  # more non-numeric PID rows than this: the plugin output is not what we parse
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _vol():
    """Absolute path of the Volatility executable (env VOL, default `vol`), or None."""
    return shutil.which(os.environ.get("VOL", "vol"))


def available():
    return _vol() is not None


def sandbox_available():
    """True if the sandbox wrapper can run here (a POSIX `sh` and the script itself)."""
    return os.name != "nt" and SANDBOX.is_file() and shutil.which("sh") is not None


def build_command(vol, dump, plugin, symbols_dir=None, sandbox=False):
    """The argv for one Volatility run. sandbox=True wraps it in scripts/run_vol_sandboxed.sh (memory limit,
    no network, not root, read-only dump); the wrapper takes the dump path first, then the vol command."""
    cmd = [vol, "-q", "-r", "json"]
    if symbols_dir:
        cmd += ["-s", str(symbols_dir)]
    cmd += ["-f", str(dump), PLUGINS.get(plugin, plugin)]
    return ["sh", str(SANDBOX), str(dump)] + cmd if sandbox else cmd


def _safe(text, limit=MAX_MESSAGE_CHARS):
    """Guest-derived text for an error message: truncated first (cheap), then stripped of control and bidi
    characters (clean_text)."""
    return clean_text(str(text)[-limit:])


def run_plugin(dump, plugin, symbols_dir=None, sandbox=False):
    vol = _vol()
    if vol is None:
        raise RuntimeError("Volatility not found: install it or set VOL to its path")
    if sandbox and not sandbox_available():
        raise RuntimeError(f"sandbox requested but unavailable (needs POSIX sh and {SANDBOX})")
    cmd = build_command(vol, dump, plugin, symbols_dir, sandbox)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"{plugin} timed out after {e.timeout}s") from e
    if out.returncode:
        raise RuntimeError(f"{plugin} failed: {_safe(out.stderr)}")
    try:
        return json.loads(out.stdout)
    except ValueError:
        raise RuntimeError(f"{plugin} output is not valid JSON: {_safe(out.stdout, 80)!r}") from None


def normalize_sha256(value):
    """The 64-hex-char lowercase digest in `value` (whitespace/newline stripped, any case), or None."""
    value = str(value or "").strip().lower()
    return value if _SHA256.fullmatch(value) else None


def _isf_entries(folder):
    return sorted(f for f in folder.rglob("*") if f.name.lower().endswith(ISF_EXTENSIONS))


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_symbols(path, expected_sha256):
    """Raise RuntimeError unless the ISF file at `path` has SHA-256 `expected_sha256` (from prereg.md). A folder
    must hold exactly one ISF file and no other entry with an ISF extension (.json .json.xz .json.gz .json.bz2
    .zip, any case): Volatility loads every one of them. Returns that file's path."""
    path = Path(path)
    if path.is_dir():
        files = _isf_entries(path)
        if len(files) != 1:
            raise RuntimeError(f"{path}: expected exactly one symbol file, found {len(files)}: "
                               f"{', '.join(f.name for f in files) or 'none'}")
        path = files[0]
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"symbol file not found (or a symlink): {path}")
    expected = normalize_sha256(expected_sha256)
    got = _file_sha256(path)
    if expected is None or got != expected:
        raise RuntimeError(f"symbol file {path} SHA-256 {got} does not match the expected "
                           f"{str(expected_sha256).strip()}; refusing to run Volatility with unverified symbols")
    return path


def stage_verified_symbols(path, expected_sha256):
    """Verify the ISF, copy it into a fresh 0700 folder under <repo>/.local/tmp, re-hash the COPY and return
    the folder (the caller deletes it). Volatility then reads the bytes that were hashed, not whatever the
    source path holds later (closes the check-then-use gap)."""
    src = verify_symbols(path, expected_sha256)
    base = ROOT / ".local" / "tmp"
    base.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix="vsec-isf-", dir=base))  # mkdtemp is mode 0700
    try:
        copy = staged / src.name
        shutil.copyfile(src, copy)
        verify_symbols(copy, expected_sha256)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return staged


def vol_version(vol):
    """Volatility's version string from `vol --version`, or None if it cannot be read."""
    try:
        r = subprocess.run([vol, "--version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"\d+\.\d+(?:\.\d+)*", f"{r.stdout}\n{r.stderr}") if r.returncode == 0 else None
    return m.group() if m else None


def pids(rows):
    """Return (set of int PIDs, number of rows skipped because their PID is not a number, e.g. '-', 'N/A').
    Raises ValueError if a row has no 'PID' key at all (the plugin's output format differs)."""
    found, skipped = set(), 0
    for r in rows:
        if "PID" not in r:
            raise ValueError(f"plugin row has no 'PID' key (keys: {_safe(sorted(map(str, r)), 120)}); "
                             "output format differs")
        try:
            found.add(int(r["PID"]))
        except (TypeError, ValueError):
            skipped += 1
    return found, skipped


def hidden_pids(listed, scanned):
    """Present in a raw memory scan but missing from the kernel's process list."""
    return scanned - listed


def identity_column(*row_lists):
    """The first of IDENTITY_COLUMNS present in every row of every list, or None (compare by PID only)."""
    for col in IDENTITY_COLUMNS:
        if all(col in r for rows in row_lists for r in rows):
            return col
    return None


def _norm_id(value):
    """Offsets compare as numbers when they look like numbers ('0xA000' == 40960), else as lowercase text."""
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    for base in (0, 10):
        try:
            return int(text, base)
        except ValueError:
            continue
    return text


def task_keys(rows, column):
    """{(pid, normalised identity): raw identity} for the rows with a numeric PID (identity None without a column)."""
    keys = {}
    for r in rows:
        try:
            pid = int(r["PID"])
        except (TypeError, ValueError):
            continue
        raw = r[column] if column else None
        keys.setdefault((pid, None if column is None else _norm_id(raw)), raw)
    return keys


def exit_reason(row):
    """Why a row looks like an already-exited task (the first key containing 'exit' or 'state' whose value contains
    exit/dead/zombie, case-insensitive), or None. Limitation: key names vary between Volatility releases; a row
    with no such field is treated as live. The field is read from guest memory, so a guest controls it."""
    for k, v in row.items():
        if ("exit" in k.lower() or "state" in k.lower()) and any(w in str(v).lower() for w in EXITED_WORDS):
            return _safe(f"{k}={v}", 80)
    return None


def is_exited(row):
    return exit_reason(row) is not None


def _names(rows):
    return sorted(_safe(m.get("Name", m), 128) for m in rows)


def _split_exited(rows, column):
    """(rows kept, [{pid, offset, reason}] for every exited-looking row removed)."""
    kept, excluded = [], []
    for r in rows:
        reason = exit_reason(r)
        if reason is None:
            kept.append(r)
        else:
            pid = r.get("PID")
            excluded.append({"pid": pid if isinstance(pid, int) else _safe(pid, 20),
                             "offset": r[column] if column else None, "reason": reason})
    return kept, excluded


def _check_rows(rows, listed, scanned, skipped):
    """Refuse output that cannot support a hidden-process verdict (empty scan, scan smaller than the list,
    mostly non-numeric PIDs)."""
    if not rows["pslist"]:
        raise RuntimeError("pslist returned zero rows: wrong symbols or plugin; refusing to call every pid hidden")
    if not rows["psscan"]:
        raise RuntimeError("psscan returned zero rows: wrong symbols or plugin; refusing to compare with pslist")
    if len(scanned) < len(listed):
        raise RuntimeError(f"psscan found {len(scanned)} PIDs but pslist {len(listed)}: a scan must see at least "
                           "every listed process, so the symbols or plugin are wrong")
    for name in ("pslist", "psscan"):
        if skipped[name] > MAX_SKIPPED_FRACTION * len(rows[name]):
            raise RuntimeError(f"{name}: {skipped[name]} of {len(rows[name])} rows have a non-numeric PID "
                               f"(over {MAX_SKIPPED_FRACTION:.0%}); the output format differs")


def _symbols_for_run(symbols_dir, expected_sha256, allow_unverified):
    """(symbols dir to pass to vol, folder to delete or None, verified sha256 or None). The hash is mandatory
    (argument or env VSEC_SYMBOLS_SHA256, 64 hex chars) unless allow_unverified=True."""
    given = expected_sha256 or os.environ.get(SYMBOLS_SHA_ENV)
    digest = normalize_sha256(given)
    if digest is None and str(given or "").strip():  # a mistyped hash is never silently ignored
        raise RuntimeError(f"the symbols SHA-256 is mandatory and must be exactly 64 hex characters, got {_safe(given, 80)!r}")
    if digest is None:
        if not allow_unverified:
            raise RuntimeError(f"the symbols SHA-256 is mandatory: pass expected_sha256 or set {SYMBOLS_SHA_ENV} to "
                               "the 64-hex-char hash from prereg.md (allow_unverified=True skips this, and is recorded)")
        return symbols_dir, None, None
    if not symbols_dir:
        raise RuntimeError("an expected symbols hash was given but no symbols path to check it against")
    staged = stage_verified_symbols(symbols_dir, digest)
    return staged, staged, digest


def detect(dump, symbols_dir=None, sandbox=False, expected_sha256=None, allow_unverified=False,
           exclude_exited=False):
    """Hidden tasks are (PID, offset) pairs in psscan but not in pslist (offset = the first IDENTITY_COLUMNS column
    both outputs carry, else PID only with a recorded limitation). exclude_exited=True drops psscan rows that
    look like already-exited processes (see exit_reason), because a scan also finds dead tasks that were
    legitimately unlinked; the guest controls that field, so every dropped row is returned in `excluded_exited`
    and `exclusion_applied` says it happened (the CLI then reports C30 as NA). sandbox=True runs vol through
    scripts/run_vol_sandboxed.sh (the CLI should pass sandbox_available()). The ISF hash (expected_sha256 or env
    VSEC_SYMBOLS_SHA256) is mandatory: the verified ISF is copied to a private temp folder, re-hashed, and that
    copy is what vol reads. allow_unverified=True runs without it and records symbols_sha_verified=False.
    Raises RuntimeError for any output that cannot support a verdict (see _check_rows)."""
    if not available():
        raise RuntimeError("Volatility not found: install it or set VOL to its path")
    run_symbols, staged, digest = _symbols_for_run(symbols_dir, expected_sha256, allow_unverified)
    try:
        seconds, rows = {}, {}
        for name in ("pslist", "psscan", "lsmod", "hidden_modules"):
            t0 = time.perf_counter()
            rows[name] = run_plugin(dump, name, run_symbols, sandbox)
            seconds[name] = time.perf_counter() - t0
        version = vol_version(_vol())
    finally:
        if staged:
            shutil.rmtree(staged, ignore_errors=True)
    listed, skipped_listed = pids(rows["pslist"])
    scanned_all, skipped_scanned = pids(rows["psscan"])
    _check_rows(rows, listed, scanned_all, {"pslist": skipped_listed, "psscan": skipped_scanned})
    column = identity_column(rows["pslist"], rows["psscan"])
    kept, excluded = _split_exited(rows["psscan"], column) if exclude_exited else (rows["psscan"], [])
    scanned_keys = task_keys(kept, column)
    hidden = scanned_keys.keys() - task_keys(rows["pslist"], column).keys()
    tasks = sorted(({"pid": pid, "offset": scanned_keys[(pid, ident)]} for pid, ident in hidden),
                   key=lambda t: (t["pid"], str(t["offset"])))
    return {"hidden_pids": sorted({t["pid"] for t in tasks}), "hidden_tasks": tasks,
            "hidden_identity": column, "limitations": [] if column else [NO_IDENTITY_NOTE],
            "excluded_exited": excluded, "exclusion_applied": bool(excluded),
            "lsmod_modules": _names(rows["lsmod"]),
            "lsmod_empty": not rows["lsmod"],
            "hidden_modules": _names(rows["hidden_modules"]),
            "skipped_non_numeric_pid_rows": {"pslist": skipped_listed, "psscan": skipped_scanned},
            "exclude_exited": exclude_exited,
            "sandboxed": bool(sandbox), "symbols_sha_verified": digest is not None, "symbols_sha256": digest,
            "vol_version": version,
            "scan_seconds": seconds}


def evaluate(results):
    """results: [{"name", "truth_hidden": [...], "detected": [...]}]. Truth empty = clean dump.

    Reports exact counts with Clopper-Pearson CIs (detected objects; clean dumps with a false alarm).
    Raises ValueError for an empty list or a row missing a required key.
    """
    results = list(results)
    if not results:
        raise ValueError("evaluate() got zero results")
    for i, r in enumerate(results):
        missing = [k for k in ("name", "truth_hidden", "detected") if not isinstance(r, dict) or k not in r]
        if missing:
            raise ValueError(f"result #{i} is missing {', '.join(missing)}")
    det = miss = fp_items = 0
    clean = clean_alarm = 0
    for r in results:
        truth, got = set(map(str, r["truth_hidden"])), set(map(str, r["detected"]))
        det += len(truth & got)
        miss += len(truth - got)
        fp_items += len(got - truth)
        if not truth:
            clean += 1
            clean_alarm += bool(got)
    n = det + miss
    return {"detected": det, "hidden_total": n, "detection_ci": clopper_pearson(det, n),
            "false_items": fp_items, "clean_dumps": clean, "clean_with_alarm": clean_alarm,
            "clean_alarm_ci": clopper_pearson(clean_alarm, clean),
            "failures": [r["name"] for r in results if set(map(str, r["truth_hidden"])) - set(map(str, r["detected"]))]}
