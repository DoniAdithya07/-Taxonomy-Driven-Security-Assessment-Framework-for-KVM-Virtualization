#!/usr/bin/env python3
"""Write meta.json for one M4 boot session (run in the booted OS: native or VM guest).

    python3 session_meta.py [--schedule PATH] [--session ID] [--allow-unscheduled] [--pilot] [--bench PATH]
        -- <native|kvm-plain|kvm-masked> <session_dir> [temp_c]

--schedule (default data/m4/schedule.json next to the repo) gives day, order (0-based position in the schedule)
and batch (= day unless the entry has one) for --session (default: the session_dir name). A session that is not
in the schedule, or a missing/unreadable schedule, is a HARD ERROR (exit nonzero, no meta.json) unless
--allow-unscheduled (then day/order/batch are None, with a warning). --pilot marks a pilot run (meta "pilot": true)
and implies --allow-unscheduled. Put `--` before the positionals so a value like '--schedule=x' stays a value.
Per-workload temperatures, order and uptime come from <session_dir>/thermal.txt (written by run_session.sh before
this script runs, one line per workload in the order they ran); startup times come from
<session_dir>/<workload>.bench.txt lines '# ... startup_ms=<number>'; --bench PATH (or env BENCH_PATH) is the
bench binary whose sha256 is recorded. Stdlib only.
Records the declared class, the environment that must be logged per session, and the system
indicators (which are NOT features for H1; they feed the indicator-leak table).
Any item that cannot be read is stored as null (None), never as an empty string. A failure (bad class, unwritable
folder, a value that cannot be stored as JSON) exits nonzero with a message; it is never silent.
"""
import argparse
import datetime
import glob
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys

CLASSES = ("native", "kvm-plain", "kvm-masked")
WORKLOADS = ("idle", "cpu", "mem", "mixed")
STARTUP_RE = re.compile(r"^#.*\bstartup_ms=(\S+)")
DEFAULT_SCHEDULE = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "data", "m4", "schedule.json")


def sh(argv):
    """stdout of a command (stripped), or None if it failed, is missing or printed nothing."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None if r.returncode == 0 else None


def read(p):
    try:
        with open(p) as f:
            return f.read().strip() or None
    except OSError:
        return None


def first_line(s):
    return s.splitlines()[0] if s else None


def temp_c():
    t = []
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        v = read(p)
        if v and v.lstrip("-").isdigit():
            t.append(int(v))
    return max(t) / 1000 if t else None


def warn(msg):
    print(f"session_meta: warning: {msg}", file=sys.stderr)


def millideg(v):
    """'<int millidegrees>' (optional single leading '-') -> degrees C; None for 'na' or anything unreadable."""
    digits = v[1:] if v.startswith("-") else v
    if not digits.isdecimal():
        return None
    try:
        t = int(v) / 1000
    except (ValueError, OverflowError):
        return None
    return t if math.isfinite(t) else None


def thermal_rows(path):
    """thermal.txt -> [(workload, {key: value})] in file order; [] if the file is missing."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    rows = []
    for ln in lines:
        parts = ln.split()
        if parts:
            rows.append((parts[0], dict(p.split("=", 1) for p in parts[1:] if "=" in p)))
    return rows


def parse_thermal(path):
    """thermal.txt lines '<workload> before=<millideg|na> after=<..> uptime_s=<..>' -> (before, after) dicts of
    degrees C keyed by workload; None for 'na' or an unreadable value (warned about). Missing file -> two empty
    dicts."""
    before, after = {}, {}
    for name, kv in thermal_rows(path):
        for dst, key in ((before, "before"), (after, "after")):
            v = kv.get(key, "na")
            dst[name] = millideg(v)
            if dst[name] is None and v != "na":
                warn(f"thermal.txt: unreadable {key}={v!r} for workload {name!r}; stored as null")
    return before, after


def workload_order_and_uptime(path):
    """-> (workloads in the order they ran, {workload: uptime_s int or None}), both from thermal.txt."""
    rows = thermal_rows(path)
    uptime = {}
    for name, kv in rows:
        v = kv.get("uptime_s", "")
        uptime[name] = int(v) if v.isascii() and v.isdecimal() and len(v) <= 12 else None
    return [name for name, _ in rows], uptime


def bench_startup_ms(session_dir):
    """{workload: startup milliseconds from '# ... startup_ms=<n>' in <workload>.bench.txt, or None}."""
    out = {}
    for w in WORKLOADS:
        out[w] = None
        try:
            with open(os.path.join(session_dir, f"{w}.bench.txt"), encoding="utf-8", errors="replace") as f:
                for ln in f:
                    m = STARTUP_RE.match(ln)
                    if m:
                        try:
                            v = float(m.group(1))
                        except ValueError:
                            continue
                        out[w] = v if math.isfinite(v) else None
        except OSError:
            pass
    return out


def file_sha256(path):
    """sha256 hex of the file, or None (with a warning) if no path was given or it cannot be read."""
    if not path:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()
    except OSError as exc:
        warn(f"cannot hash bench {path!r}: {exc}; bench_sha256 stored as null")
        return None


def _label(v):
    """A schedule day / batch must be a positive int (>= 1) or a non-empty string (a bool is not a day)."""
    if isinstance(v, bool):
        return False
    return v >= 1 if isinstance(v, int) else isinstance(v, str) and bool(v.strip())


def schedule_entry(path, session):
    """-> (day, order, batch) of `session` in the schedule file; (None, None, None) with a warning if the file
    is missing/unreadable/malformed, the session is not in it, is listed twice (not guessed), or has a day or
    batch that is not a positive int or non-empty string. batch defaults to day."""
    try:
        with open(path) as f:
            sched = json.load(f)
        if not isinstance(sched, list) or not all(isinstance(e, dict) for e in sched):
            raise ValueError("schedule must be a JSON list of objects")
        hits = [(i, e) for i, e in enumerate(sched) if e.get("session") == session]
        if not hits:
            why = "not in the schedule"
        elif len(hits) > 1:
            why = f"listed {len(hits)} times in the schedule (ambiguous)"
        else:
            i, e = hits[0]
            day = e.get("day")
            batch = day if e.get("batch") is None else e["batch"]
            if _label(day) and _label(batch):
                return day, i, batch
            why = f"has an invalid day/batch ({day!r}/{batch!r}; need an int >= 1 or a non-empty string)"
    except Exception as exc:  # unreadable file, bad JSON, RecursionError on deep nesting, wrong shape ...
        why = f"schedule unreadable ({type(exc).__name__}: {exc})"
    warn(f"session {session!r} {why} ({path}); day/order/batch stored as null")
    return None, None, None


def cpuinfo_field(text, pattern):
    for ln in (text or "").splitlines():
        m = re.match(pattern, ln)
        if m:
            return m
    return None


def dmesg_hypervisor():
    """True/False from a successful dmesg, None if dmesg failed or was denied."""
    out = sh(["dmesg"])
    return None if out is None else "hypervisor" in out.lower()


def main(cls, out, temp=None, schedule=None, session=None, allow_unscheduled=False, pilot=False, bench=None):
    if cls not in CLASSES:
        sys.exit(f"class must be one of {CLASSES}, got {cls!r}")
    os.makedirs(out, exist_ok=True)
    now = datetime.datetime.now()
    session = session or os.path.basename(os.path.normpath(out))
    day, order, batch = schedule_entry(schedule or DEFAULT_SCHEDULE, session)
    if order is None and not (allow_unscheduled or pilot):
        raise ValueError(f"session {session!r} has no usable entry in the schedule (reason above); a real run needs "
                         "one. Pass --allow-unscheduled only for a pilot")
    thermal = os.path.join(out, "thermal.txt")
    t_before, t_after = parse_thermal(thermal)
    wl_order, wl_uptime = workload_order_and_uptime(thermal)
    cpuinfo = read("/proc/cpuinfo")
    m = cpuinfo_field(cpuinfo, r"flags\s*:(.*)")
    hv_bit = None if m is None else "hypervisor" in m.group(1).split()
    model = cpuinfo_field(cpuinfo, r"model name\s*:(.*)")
    nic = sorted({os.path.basename(os.path.realpath(p)) for p in glob.glob("/sys/class/net/*/device/driver")
                  if p.split("/")[4] != "lo"})
    try:
        temp_val = float(temp) if temp else temp_c()
    except ValueError:
        warn(f"temperature {temp!r} is not a number; temp_c stored as null")
        temp_val = None
    if temp_val is not None and not math.isfinite(temp_val):
        warn(f"temperature {temp!r} is not a finite number; temp_c stored as null")
        temp_val = None
    meta = {
        "cls": cls, "date": now.date().isoformat(), "time": now.strftime("%H:%M"),
        "temp_c": temp_val,
        "day": day, "batch": batch, "order": order, "pilot": bool(pilot),
        "workload_order": wl_order, "workload_uptime_s": wl_uptime,
        "bench_sha256": file_sha256(bench or os.environ.get("BENCH_PATH")),
        "bench_startup_ms": bench_startup_ms(out),
        "temp_before_c": t_before, "temp_after_c": t_after,
        "nproc": os.cpu_count(), "smt_active": read("/sys/devices/system/cpu/smt/active"),
        "online_cpus": read("/sys/devices/system/cpu/online"),
        "minutes_since_boot": round(float(read("/proc/uptime").split()[0]) / 60, 1) if read("/proc/uptime") else None,
        "kernel": platform.release() or None, "cmdline": read("/proc/cmdline"),
        "clocksource": read("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
        "available_clocksource": read("/sys/devices/system/clocksource/clocksource0/available_clocksource"),
        "governor": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "no_turbo": read("/sys/devices/system/cpu/intel_pstate/no_turbo"),
        "thp": read("/sys/kernel/mm/transparent_hugepage/enabled"),
        "cpu_model": model.group(1).strip() if model else None,
        "qemu": first_line(sh(["qemu-system-x86_64", "--version"])),
        "python_version": platform.python_version(),
        "indicators": {
            "cpuid_hypervisor_bit": hv_bit,
            "dmi_sys_vendor": read("/sys/class/dmi/id/sys_vendor"),
            "dmi_product_name": read("/sys/class/dmi/id/product_name"),
            "dmi_bios_vendor": read("/sys/class/dmi/id/bios_vendor"),
            "disk_model": first_line(sh(["lsblk", "-dno", "MODEL"])),
            "nic_driver": ",".join(nic) or None,
            "systemd_detect_virt": sh(["systemd-detect-virt"]),
            "dmesg_hypervisor": dmesg_hypervisor(),
        },
    }
    text = json.dumps(meta, indent=1, allow_nan=False)  # before opening the file: a failure leaves no half file
    with open(os.path.join(out, "meta.json"), "x") as f:
        f.write(text)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cls")
    ap.add_argument("out")
    ap.add_argument("temp", nargs="?", default=None)
    ap.add_argument("--schedule", default=None)
    ap.add_argument("--session", default=None)
    ap.add_argument("--allow-unscheduled", action="store_true")
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--bench", default=None)
    a = ap.parse_args()
    try:
        main(a.cls, a.out, a.temp, a.schedule, a.session, a.allow_unscheduled, a.pilot, a.bench)
    except Exception as exc:
        sys.exit(f"session_meta: FAILED, no meta.json written: {type(exc).__name__}: {exc}")
