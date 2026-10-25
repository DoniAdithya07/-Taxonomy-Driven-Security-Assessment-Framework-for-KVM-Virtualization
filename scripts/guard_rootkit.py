#!/usr/bin/env python3
"""Run INSIDE `target` before loading any research rootkit. It only checks and prints instructions: it never
loads anything.

    python3 guard_rootkit.py --mark-reverted                      # right after reverting the snapshot
    python3 guard_rootkit.py --allow-dir /opt/rootkits --module /opt/rootkits/diamorphine.ko --sha256 <hex>

Refuses unless (a) the guest is offline (same checks as plant_guest.py, which must sit in the same folder),
(b) the module path is inside the allow-list directory, and that directory is owned by root or the current user
and is not group/world-writable, (c) the module file has the MANDATORY --sha256, (d) the revert marker
/var/lib/vsec/target.reverted is valid: JSON {vm, created_utc, pid} made by --mark-reverted (O_EXCL|O_NOFOLLOW),
not a symlink, for VM `target`, younger than --max-age-minutes (default 15). The marker is deleted by a passing
run (single use). The host-side scripts/preflight_target.py stays the authoritative isolation gate.

The module is opened without following symlinks and fstat-checked on that same descriptor (owner root or the
current user, no group/world write bit), then COPIED into a private 0700 temp dir; the copy is re-hashed and the
operator must insmod the printed COPY, never the original. This closes the check-then-use gap on the original file.
The printed command re-checks the copy's hash right before insmod. --max-age-minutes is capped at 1440.

Needs plant_guest.py and (vsec/guards.py next to this script's folder, or guards.py beside it) on the guest.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile

MARKER = "/var/lib/vsec/target.reverted"
MAX_AGE_LIMIT = 1440  # minutes, same upper bound as preflight
VM = "target"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, *candidates):
    for path in candidates:
        if os.path.isfile(path):
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            return mod
    raise FileNotFoundError(f"{name}: not found in {', '.join(candidates)}")


def load_plant_guest():
    return _load("plant_guest", os.path.join(_HERE, "plant_guest.py"))


def load_guards():
    return _load("vsec_guards", os.path.join(_HERE, "guards.py"), os.path.join(_HERE, "..", "vsec", "guards.py"))


def dir_problems(mode, uid, my_uid):
    """Why an allow-list directory with this st_mode / owner is not trustworthy ([] = fine)."""
    problems = []
    if uid not in (0, my_uid):
        problems.append(f"owned by uid {uid}, not root or the current user")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"group/world-writable (mode {stat.S_IMODE(mode):03o})")
    return problems


def check_module_allowed(module, allow_dir):
    """Raise ValueError unless the real path of `module` is a file inside the real path of `allow_dir`, and (on
    POSIX) `allow_dir` is owned by root or us and not group/world-writable."""
    mod, allow = os.path.realpath(module), os.path.realpath(allow_dir)
    if not os.path.isdir(allow):
        raise ValueError(f"allow-list directory does not exist: {allow}")
    if os.name != "nt":
        st = os.stat(allow)
        problems = dir_problems(st.st_mode, st.st_uid, os.getuid())
        if problems:
            raise ValueError(f"allow-list directory {allow} is not trustworthy: {'; '.join(problems)}")
    if os.path.commonpath([mod, allow]) != allow or mod == allow:
        raise ValueError(f"module {mod} is not under the allow-list directory {allow}")
    if not os.path.isfile(mod):
        raise ValueError(f"module file not found: {mod}")
    return mod


def check_sha256(path, expected):
    """Raise ValueError unless `path` has SHA-256 `expected` (64 hex chars, any case)."""
    expected = str(expected).strip().lower()
    if not _SHA256_RE.fullmatch(expected):
        raise ValueError("--sha256 must be 64 hex characters")
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError(f"module {path} SHA-256 {digest.hexdigest()} does not match --sha256 {expected}")
    return expected


def file_problems(mode, uid, my_uid):
    """Why a module file with this st_mode / owner is not trustworthy ([] = fine)."""
    problems = []
    if uid not in (0, my_uid):
        problems.append(f"owned by uid {uid}, not root or the current user")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"group/world-writable (mode {stat.S_IMODE(mode):03o})")
    return problems


def copy_verified(mod, sha256):
    """Open `mod` (no symlink following), fstat-check that descriptor, copy it into a private 0700 temp dir and
    re-hash the COPY against `sha256`. Returns the copy's path; raises ValueError (temp dir removed) on any problem.
    The operator must insmod the copy: the original can change after this point."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(mod, flags)
    tmp = None
    try:
        with os.fdopen(fd, "rb") as src:
            st = os.fstat(src.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"module {mod} is not a regular file")
            if os.name != "nt":
                problems = file_problems(st.st_mode, st.st_uid, os.getuid())
                if problems:
                    raise ValueError(f"module {mod} is not trustworthy: {'; '.join(problems)}")
            tmp = tempfile.mkdtemp(prefix="vsec-rk-")  # mkdtemp is 0700
            copy = os.path.join(tmp, os.path.basename(mod))
            with open(copy, "xb") as dst:
                shutil.copyfileobj(src, dst)
        check_sha256(copy, sha256)
        return copy
    except BaseException:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        raise


def consume_marker(marker=MARKER, max_age_minutes=15):
    """Raise RuntimeError unless the revert marker is valid (see guards.check_marker); delete it (single use)."""
    load_guards().check_marker(marker, VM, max_age_minutes)
    os.remove(marker)


def mark_reverted(marker=MARKER):
    load_guards().write_marker(marker, VM)


def check_all(module, allow_dir, sha256, root="/", marker=MARKER, offline_problems=None, max_age_minutes=15):
    """Run every check; the marker is consumed last, only if all the others passed. Returns the path of the
    verified private COPY of the module (the one to insmod). sha256 is mandatory: empty, None and anything that is
    not 64 hex characters is refused up front, never treated as "skip the check"."""
    if not sha256 or not str(sha256).strip():
        raise ValueError("--sha256 is mandatory")
    if not _SHA256_RE.fullmatch(str(sha256).strip().lower()):
        raise ValueError("--sha256 must be 64 hex characters")
    if not 0 < max_age_minutes <= MAX_AGE_LIMIT:
        raise ValueError(f"--max-age-minutes must be in (0, {MAX_AGE_LIMIT}]")
    problems = (offline_problems or load_plant_guest().offline_problems)(root)
    if problems:
        raise RuntimeError("guest is not offline: " + "; ".join(problems))
    copy = copy_verified(check_module_allowed(module, allow_dir), sha256)
    try:
        consume_marker(marker, max_age_minutes)
    except BaseException:
        shutil.rmtree(os.path.dirname(copy), ignore_errors=True)
        raise
    return copy


def insmod_instructions(mod, sha256=None):
    quoted = shlex.quote(mod)
    check = f"printf '%s\\n' {shlex.quote(sha256.strip().lower() + '  ' + mod)} | sha256sum -c - && " if sha256 else ""
    return f"  {check}sudo insmod {quoted}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mark-reverted", action="store_true", help="record that the snapshot was just reverted")
    ap.add_argument("--allow-dir")
    ap.add_argument("--module")
    ap.add_argument("--sha256", help="expected SHA-256 of the module (MANDATORY unless --mark-reverted)")
    ap.add_argument("--max-age-minutes", type=float, default=15, help=f"marker age limit, at most {MAX_AGE_LIMIT}")
    args = ap.parse_args(argv)
    try:
        if args.mark_reverted:
            mark_reverted(MARKER)
            print(f"marked: {MARKER}")
            return 0
        if not (args.allow_dir and args.module):
            ap.error("--allow-dir and --module are required (unless --mark-reverted)")
        if not args.sha256:
            ap.error("--sha256 is mandatory")
        mod = check_all(args.module, args.allow_dir, args.sha256, marker=MARKER,
                        max_age_minutes=args.max_age_minutes)
    except (RuntimeError, ValueError, OSError) as e:
        print(f"REFUSING: {e}", file=sys.stderr)
        return 1
    print("checks passed (marker consumed). insmod the COPY printed below (not the original); load it yourself, once:\n"
          + insmod_instructions(mod, args.sha256)
          + "\nThis script loaded nothing. Dump from the HOST only through scripts/preflight_target.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
