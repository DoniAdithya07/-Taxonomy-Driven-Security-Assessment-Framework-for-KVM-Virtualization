"""Tests for scripts/make_submission_zip.py, run against a small fake repo under tmp_path (via --root)."""
import hashlib
import importlib.util
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "make_submission_zip.py"
spec = importlib.util.spec_from_file_location("make_submission_zip", SCRIPT)
zipper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zipper)

# Built from pieces so this file itself never contains a literal secret, e-mail or personal path.
EMAIL = "someone" + "@" + "example.com"
PRIVATE_KEY = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
AWS_ID = "AKIA" + "ABCDEFGHIJKLMNOP"
WIN_HOME = "C:" + "\\Users\\" + "alice"
FAKE_USER = "zorb" + "ax"


@pytest.fixture(autouse=True)
def fake_os_user(monkeypatch):
    monkeypatch.setattr(zipper.os, "getlogin", lambda: FAKE_USER)
    monkeypatch.setattr(zipper.getpass, "getuser", lambda: FAKE_USER)


def put(root, rel, content="x\n"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return p


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    put(root, "SUBMISSION.md", "# hand-in\n")
    put(root, "README.md", "readme\n")
    put(root, "vsec/__init__.py", "")
    put(root, "scripts/tool.py", "print(1)\n")
    put(root, "docs/YOUR_TASKS.md", "notes\n")
    put(root, "docs/paper/README.md", "notes\n")
    put(root, "docs/slides/README.md", "notes\n")
    put(root, "docs/paper/paper.md", "paper\n")
    return root


def run(root, *args, capsys=None):
    code = zipper.main(["--root", str(root), *args])
    return (code, *capsys.readouterr()) if capsys else code


def names(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        return zf.namelist()


def test_builds_zip_with_top_level_folder_and_summary(repo, capsys):
    code, out, err = run(repo, "--list", capsys=capsys)
    assert code == 0, err
    got = names(repo / "dist" / "vsec_submission.zip")
    assert got == sorted(got)
    assert all(n.startswith("vsec_submission/") for n in got)
    assert "vsec_submission/SUBMISSION.md" in got and "vsec_submission/vsec/__init__.py" in got
    assert "files: 8" in out and "10 largest files:" in out and "excluded top-level items:" in out
    assert "  docs/paper/paper.md" in out  # --list prints included paths


def test_excluded_paths_and_patterns_are_left_out(repo, capsys):
    skipped = [".git/config", ".local/work/a.txt", "out/report.json", "dist/old.zip", ".claude/settings.json",
               ".pytest_cache/v/x", "vsec/__pycache__/m.cpython-311.pyc", "a.pyc", "a.pyo", "tests/fixtures/f.txt",
               "data/m2/d.bin", "cases/c1/x", "bench/b.c", "bench/b.o", "dump.mem", "x.dump", "x.save", "id.key",
               "cert.pem", "prod.env", ".env", "disk.qcow2", "disk.img", "disk.iso", "myvenv/pyvenv.cfg",
               "myvenv/lib/site.py", "vsec/sub/out/y.txt"]
    for rel in skipped:
        put(repo, rel)
    put(repo, "tests/test_a.py", "assert True\n")  # tests/ itself stays; only tests/fixtures goes
    put(repo, "benchmarks/keep.txt")  # only the exact folder name `bench` is excluded
    code, out, err = run(repo, capsys=capsys)
    assert code == 0, err
    got = {n.split("/", 1)[1] for n in names(repo / "dist" / "vsec_submission.zip")}
    assert got.isdisjoint(skipped)
    assert {"tests/test_a.py", "benchmarks/keep.txt", "README.md"} <= got
    top = out.split("excluded top-level items:")[1]
    assert ".git/" in top and "bench/" in top and "myvenv/" in top and "dist/" in top and "docs" not in top


def test_exclude_notes_removes_only_the_working_notes(repo, capsys):
    assert run(repo, "--exclude-notes") == 0
    got = {n.split("/", 1)[1] for n in names(repo / "dist" / "vsec_submission.zip")}
    assert got.isdisjoint({"docs/YOUR_TASKS.md", "docs/paper/README.md", "docs/slides/README.md"})
    assert "docs/paper/paper.md" in got
    assert run(repo) == 0
    assert "docs/YOUR_TASKS.md" in {n.split("/", 1)[1] for n in names(repo / "dist" / "vsec_submission.zip")}


def test_missing_submission_md_refuses_and_writes_nothing(repo, capsys):
    (repo / "SUBMISSION.md").unlink()
    code, out, err = run(repo, capsys=capsys)
    assert code == 2 and "SUBMISSION.md missing" in err
    assert not (repo / "dist").exists()


def test_file_over_5_mb_refuses_and_writes_nothing(repo, capsys):
    put(repo, "big.bin", b"\0" * (5 * 1024 * 1024 + 1))
    code, out, err = run(repo, capsys=capsys)
    assert code == 2 and "big.bin" in err and "5 MB" in err
    assert not (repo / "dist").exists()


def test_file_of_exactly_5_mb_is_allowed(repo):
    put(repo, "ok.bin", b"\0" * (5 * 1024 * 1024))
    assert run(repo) == 0


@pytest.mark.parametrize("content, kind", [
    (f"{PRIVATE_KEY}\nabc\n", "private key block"),
    ("token = ghp_" + "a" * 36 + "\n", "GitHub token"),
    ("key = sk-" + "b" * 30 + "\n", "API token"),
    (f"id = {AWS_ID}\n", "AWS access key id"),
    (f"contact {EMAIL}\n", "e-mail address"),
    (f"path = {WIN_HOME}\\x\n", "Windows user path"),
    ("cd /home" + "/alice/work\n", "Linux home path"),
    (f"written by {FAKE_USER.upper()} yesterday\n", "OS user name"),
])
def test_secret_and_privacy_hits_refuse_without_writing_or_echoing(repo, capsys, content, kind):
    put(repo, "vsec/leak.py", "ok = 1\n" + content)
    code, out, err = run(repo, capsys=capsys)
    assert code == 2 and "vsec/leak.py:2" in err and kind in err
    assert content.strip().split()[-1] not in err  # the secret value itself is never printed
    assert not (repo / "dist").exists()


def test_username_inside_a_longer_word_is_not_a_hit(repo):
    put(repo, "docs/note.md", f"the {FAKE_USER}ification step, un{FAKE_USER}\n")
    assert run(repo) == 0


def test_binary_files_are_not_text_scanned(repo):
    put(repo, "blob.bin", b"\0\1" + EMAIL.encode() + b"\xff")
    assert run(repo) == 0


def test_synthetic_secrets_are_allowed_only_in_tests_and_secrets_gen(repo, capsys):
    fake = f"{PRIVATE_KEY}\n{AWS_ID}\n"
    put(repo, "tests/test_x.py", fake)
    put(repo, "vsec/secrets_gen.py", fake)
    assert run(repo) == 0
    put(repo, "scripts/other.py", fake)
    put(repo, "vsec/secrets_gen_copy.py", fake)
    code, out, err = run(repo, capsys=capsys)
    assert code == 2 and "scripts/other.py:1" in err and "vsec/secrets_gen_copy.py:1" in err
    assert "tests/test_x.py" not in err and "vsec/secrets_gen.py:" not in err


def test_allow_list_does_not_cover_email_or_paths(repo, capsys):
    put(repo, "tests/test_x.py", f"{EMAIL}\n")
    code, out, err = run(repo, capsys=capsys)
    assert code == 2 and "tests/test_x.py:1: e-mail address" in err


def test_zip_is_reproducible_byte_for_byte(repo, tmp_path):
    put(repo, "vsec/a.py", "a = 1\n" * 500)
    assert run(repo, "--out", "dist/one.zip") == 0
    import os
    import time
    for p in repo.rglob("*.py"):  # different mtimes must not change the zip
        os.utime(p, (time.time() + 1000, time.time() + 1000))
    assert run(repo, "--out", "dist/two.zip") == 0
    digest = lambda n: hashlib.sha256((repo / "dist" / n).read_bytes()).hexdigest()  # noqa: E731
    assert digest("one.zip") == digest("two.zip")
    with zipfile.ZipFile(repo / "dist" / "one.zip") as zf:
        assert {i.date_time for i in zf.infolist()} == {(2026, 1, 1, 0, 0, 0)}
        assert {i.compress_type for i in zf.infolist()} == {zipfile.ZIP_DEFLATED}
        assert zf.testzip() is None


@pytest.mark.parametrize("out", ["out.zip", "../escape.zip", "dist/../escape.zip", "docs/x.zip", "dist"])
def test_refuses_output_outside_dist(repo, capsys, out):
    code, _, err = run(repo, "--out", out, capsys=capsys)
    assert code == 2 and "dist" in err
    assert not (repo / "dist").exists() and not (repo.parent / "escape.zip").exists()
    assert not (repo / "out.zip").exists()


def test_refuses_absolute_output_outside_dist(repo, tmp_path, capsys):
    target = tmp_path / "elsewhere.zip"
    code, _, err = run(repo, "--out", str(target), capsys=capsys)
    assert code == 2 and not target.exists()


def test_output_in_a_subfolder_of_dist_is_created(repo):
    assert run(repo, "--out", "dist/sub/final.zip") == 0
    assert (repo / "dist" / "sub" / "final.zip").is_file()


def test_the_real_repo_passes_every_check_without_writing_a_zip(tmp_path, monkeypatch):
    """Dry run of the real repo layout: collect + check only (no zip), so a leak in a new file fails this test."""
    monkeypatch.undo()  # use the real OS user name here, not the fake one
    root = SCRIPT.parent.parent
    files = zipper.collect_files(root)
    problems, _ = zipper.check_files(root, files)
    assert [p for p in problems if not p.startswith("SUBMISSION.md missing")] == []  # that file is another task's
    assert not any(f.startswith((".git/", ".local/", "out/", "dist/", "tests/fixtures/")) for f in files)
