#!/usr/bin/env python3
"""Build the hand-in zip of the repository (standard library only).

Usage:
  python scripts/make_submission_zip.py [--out dist/vsec_submission.zip] [--exclude-notes] [--list]

Includes every regular file under the repo root except build output, caches, virtual environments, test
fixtures, generated data, and key/image/dump files (see EXCLUDE_* below). Before writing anything it checks
that SUBMISSION.md exists, that no included file is larger than 5 MB, and that no included text file looks
like it holds a secret, an e-mail address, a personal path or the current OS user name. The zip is
reproducible: sorted order, fixed timestamps, one top-level folder `vsec_submission/`.

Exit codes: 0 zip written; 2 refused (nothing written) or bad arguments.
"""
import argparse
import fnmatch
import getpass
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOP_FOLDER = "vsec_submission"
MAX_FILE_BYTES = 5 * 1024 * 1024
ZIP_DATE = (2026, 1, 1, 0, 0, 0)

EXCLUDE_DIR_NAMES = {".git", ".local", "out", "dist", ".claude", ".pytest_cache", "__pycache__", "data", "cases"}
EXCLUDE_ROOT_DIRS = {"bench"}  # only at the repo root, like /bench in .gitignore
EXCLUDE_REL_DIRS = {"tests/fixtures"}
EXCLUDE_FILE_GLOBS = ["*.pyc", "*.pyo", "*.o", "*.mem", "*.dump", "*.save", "*.key", "*.pem", "*.env", ".env",
                      "*.qcow2", "*.img", "*.iso"]
NOTE_FILES = {"docs/YOUR_TASKS.md", "docs/paper/README.md", "docs/slides/README.md"}  # with --exclude-notes
REQUIRED_FILE = "SUBMISSION.md"

# Secret patterns are not applied to the two places that hold the project's own synthetic test secrets.
SECRET_ALLOW = ("tests/", "vsec/secrets_gen.py")
SECRET_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{20,}")),
    ("API token (sk-)", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
]
PRIVACY_PATTERNS = [
    ("e-mail address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    ("Windows user path", re.compile(r"[Cc]:\\+Users\\+", re.IGNORECASE)),
    ("Linux home path", re.compile(r"/home/[A-Za-z0-9_.-]+")),
]


def _fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    return 2


def _dir_excluded(root, rel):
    name = rel.rsplit("/", 1)[-1]
    return (name in EXCLUDE_DIR_NAMES or rel in EXCLUDE_REL_DIRS or (rel in EXCLUDE_ROOT_DIRS)
            or (root / rel / "pyvenv.cfg").exists())


def _file_excluded(name):
    return any(fnmatch.fnmatch(name, g) for g in EXCLUDE_FILE_GLOBS)


def collect_files(root, exclude_notes=False):
    """Sorted repo-relative posix paths of every regular file that goes into the zip."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if here == "." else here + "/"
        dirnames[:] = sorted(d for d in dirnames if not _dir_excluded(root, prefix + d))
        for name in filenames:
            rel = prefix + name
            path = root / rel
            if _file_excluded(name) or path.is_symlink() or not path.is_file():
                continue
            if exclude_notes and rel in NOTE_FILES:
                continue
            found.append(rel)
    return sorted(found)


def excluded_top_level(root):
    return [item.name + ("/" if item.is_dir() else "") for item in sorted(root.iterdir(), key=lambda p: p.name)
            if (_dir_excluded(root, item.name) if item.is_dir() else _file_excluded(item.name))]


def _os_usernames():
    names = set()
    for getter in (os.getlogin, getpass.getuser):
        try:
            names.add(getter())
        except Exception:  # noqa: BLE001  (getlogin: OSError without a terminal; getuser: KeyError on odd systems)
            pass
    return {n for n in names if len(n) >= 3}


def _as_text(data):
    """The text of a file, or None for binary content."""
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(rel, text, usernames):
    """[(line_no, kind)] for every secret / privacy hit in one text file (never the matched value)."""
    patterns = list(PRIVACY_PATTERNS)
    if not any(rel == a or (a.endswith("/") and rel.startswith(a)) for a in SECRET_ALLOW):
        patterns = SECRET_PATTERNS + patterns
    patterns += [(f"OS user name '{u}'", re.compile(rf"(?<![A-Za-z0-9_]){re.escape(u)}(?![A-Za-z0-9_])", re.IGNORECASE))
                 for u in usernames]
    hits = []
    for no, line in enumerate(text.splitlines(), 1):
        hits += [(no, kind) for kind, rx in patterns if rx.search(line)]
    return hits


def check_files(root, files):
    """-> (problems, {rel: bytes}). problems is a list of readable lines; content is read once."""
    problems, contents = [], {}
    usernames = _os_usernames()
    if not (root / REQUIRED_FILE).is_file():
        problems.append(f"{REQUIRED_FILE} missing: create it in the repo root before building the submission")
    for rel in files:
        # collect_files() already excluded symlinks, but re-open with O_NOFOLLOW + fstat instead of
        # Path.stat()/read_bytes() (which both follow symlinks): closes the TOCTOU window where `rel`
        # could be swapped for a symlink to an arbitrary file between the scan and this read.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(str(root / rel), flags)
        try:
            with os.fdopen(fd, "rb") as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode):
                    problems.append(f"{rel}: became a non-regular file (e.g. a symlink) after the file list "
                                     f"was built, refusing to read it")
                    continue
                size = st.st_size
                if size > MAX_FILE_BYTES:
                    problems.append(
                        f"{rel}: {size / 1024 / 1024:.1f} MB is over the {MAX_FILE_BYTES // 1024 // 1024} MB limit")
                    continue
                data = f.read()
        except OSError as e:
            problems.append(f"{rel}: {e}")
            continue
        contents[rel] = data
        text = _as_text(data)
        if text is not None:
            problems += [f"{rel}:{no}: {kind}" for no, kind in scan_text(rel, text, usernames)]
    return problems, contents


def resolve_out(root, out):
    """The output path, which must lie inside <root>/dist; None otherwise."""
    dist = (root / "dist").resolve()
    path = (root / out).resolve()
    return path if dist in path.parents else None


def write_zip(path, contents):
    """Reproducible zip: sorted names, fixed timestamps and permissions, deflate."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for rel in sorted(contents):
                info = zipfile.ZipInfo(f"{TOP_FOLDER}/{rel}", ZIP_DATE)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o644 << 16
                zf.writestr(info, contents[rel], compresslevel=6)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the hand-in zip (dist/vsec_submission.zip).")
    ap.add_argument("--out", default="dist/vsec_submission.zip", help="output zip; must be inside dist/")
    ap.add_argument("--exclude-notes", action="store_true", help="also leave out the working notes files")
    ap.add_argument("--list", action="store_true", help="print every included path")
    ap.add_argument("--root", default=str(REPO_ROOT), help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    out = resolve_out(root, args.out)
    if out is None:
        return _fail(f"--out {args.out} is outside {root / 'dist'}: the zip may only be written under dist/")
    files = collect_files(root, args.exclude_notes)
    problems, contents = check_files(root, files)
    if problems:
        print("\n".join(f"error: {p}" for p in problems), file=sys.stderr)
        print(f"refusing to build: {len(problems)} problem(s); no zip written", file=sys.stderr)
        return 2
    write_zip(out, contents)

    sizes = sorted(((len(d), rel) for rel, d in contents.items()), reverse=True)
    print(f"wrote {out}")
    print(f"files: {len(files)}, total size: {sum(s for s, _ in sizes)} bytes (zip: {out.stat().st_size} bytes)")
    print("10 largest files:")
    print("\n".join(f"  {s:>10}  {rel}" for s, rel in sizes[:10]))
    print("excluded top-level items: " + (", ".join(excluded_top_level(root)) or "none"))
    if args.list:
        print("included paths:")
        print("\n".join(f"  {rel}" for rel in files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
