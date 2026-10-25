# synthetic test value, not a credential
import base64
import hashlib
import importlib.util
import json
import os
import random
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

import pytest

from vsec import m2_snapshot as m2
from vsec import m3_forensics as m3

ROOT = Path(__file__).resolve().parent.parent


def test_scanner_finds_plain_secrets_and_redacts():
    rng = random.Random(3)
    for kind in m2.TYPES:
        data, man = m2.build_dump(kind, "live", None, 256 * 1024, rng)
        needle = bytes.fromhex(man["needles"][0])
        assert any(needle in h[3] for h in m2.scan(data)), kind
        assert not m2.scan(m2.redact(data)), kind
        assert len(m2.redact(data)) == len(data)


def test_entropy_filter_and_negative_controls():
    assert not m2.scan(b"0" * 64 + b" " + b"ab" * 32)
    n = 5 * 256 * 1024
    assert not m2.scan(random.Random(1).randbytes(n))


def test_held_out_variants_are_present_but_worse_than_plain():
    res = m2.evaluate(m2.synthetic_dumps(n=2, size=128 * 1024), synthetic=True)
    assert res["synthetic"] is True
    assert res["plain"]["present"] == 24 and res["held_out"]["present"] == 24
    assert res["held_out"]["recall"] < res["plain"]["recall"]  # holds even if the scanner improves
    # measured 1.0 on this seed (0.967 with n=10); 0.95 leaves a one-miss margin, not a loose bound
    assert res["plain"]["recall"] >= 0.95
    assert res["false_positives"] == 0
    assert res["scan_seconds"] > 0 and res["size_overhead_bytes"] == 0
    assert res["total_hits"] >= res["plain"]["detected"] and res["total_bytes"] == res["dumps"] * 128 * 1024


def test_evaluate_zero_dumps_raises():
    with pytest.raises(ValueError):
        m2.evaluate([])


def test_evaluate_counts_planted_but_absent():
    data = bytes(8192)
    man = {"cell": "aws/live", "needles": [(b"N" * 40).hex()]}
    res = m2.evaluate([(data, man)])
    assert res["cells"]["aws/live"]["planted_but_absent"] == 1
    assert res["cells"]["aws/live"]["present"] == 0 and res["cells"]["aws/live"]["recall"] is None
    assert res["plain"]["planted_but_absent"] == 1


def test_real_programs_group_is_separate():
    secret = b"AKIAABCDEFGHIJKLMNOP"
    man = {"cell": "real/openssl", "needles": [secret.hex()]}
    res = m2.evaluate([(b"xx" + secret + b"yy", man)])
    assert res["real_programs"]["present"] == 1 and res["real_programs"]["detected"] == 1
    assert res["plain"]["present"] == 0 and res["plain"]["recall"] is None


def test_evaluate_works_on_mmap_via_load_dumps(tmp_path):
    for i, (data, man) in enumerate(m2.synthetic_dumps(n=1, size=64 * 1024)):
        if i == 2:
            break
        (tmp_path / f"d{i}.mem").write_bytes(data)
        (tmp_path / f"d{i}.json").write_text(json.dumps(man))
    res = m2.evaluate(m2.load_dumps(tmp_path))
    assert res["dumps"] == 2 and res["plain"]["present"] == 2


def test_load_dumps_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        m2.load_dumps(tmp_path / "missing")
    with pytest.raises(ValueError, match="no dumps"):
        m2.load_dumps(tmp_path)
    (tmp_path / "a.json").write_text(json.dumps({"cell": "x/y", "needles": []}))
    with pytest.raises(ValueError, match="partner"):
        m2.load_dumps(tmp_path)
    (tmp_path / "a.mem").write_bytes(b"data")
    (tmp_path / "a.json").write_text(json.dumps({"cell": "x/y", "needles": ["zz"]}))
    with pytest.raises(ValueError, match="a.json"):
        m2.load_dumps(tmp_path)
    (tmp_path / "a.json").write_text("{not json")
    with pytest.raises(ValueError, match="a.json: invalid JSON"):
        m2.load_dumps(tmp_path)
    (tmp_path / "a.json").write_text(json.dumps({"cell": 5, "needles": []}))
    with pytest.raises(ValueError, match="cell"):
        m2.load_dumps(tmp_path)


def test_evaluate_rejects_bad_manifests():
    with pytest.raises(ValueError, match="needles"):
        m2.evaluate([(b"x", {"cell": "aws/live"})])
    with pytest.raises(ValueError, match=r"dump #0 \(cell 'aws/live'\)"):
        m2.evaluate([(b"x", {"cell": "aws/live", "needles": ["abc"]})])  # odd length


AWS_SECRET = "A" * 20 + "b" * 10 + "/+" + "9" * 8
HEX64 = hashlib.sha256(b"x").hexdigest()
JWT = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
PEM = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"QUJD" * 20 + b"\n-----END OPENSSH PRIVATE KEY-----"


def manifest(cell, *needles, planted=None):
    man = {"cell": cell, "needles": [n.hex() for n in needles]}
    if planted is not None:
        man["planted"] = [planted.hex()]
    return man


@pytest.mark.parametrize("kind,variant", [(k, v) for k in m2.TYPES for v in (None, *m2.VARIANTS)])
def test_make_manifest_passes_the_validator_for_every_cell(kind, variant):
    secret = m2.make_secret(kind, random.Random(7))
    man = m2.make_manifest(kind, "live", secret, variant)
    m2._validate_manifest(man, "t")
    assert man["cell"] == f"{kind}/live" + (f"/{variant}" if variant else "")


def test_make_manifest_rejects_unknown_cells():
    for args in (("nope", "live", "x"), ("aws", "dead", "x"), ("aws", "live", "x", "rot13")):
        with pytest.raises(ValueError, match="bad cell"):
            m2.make_manifest(*args)


@pytest.mark.parametrize("cell", ["foo/live", "aws/dead", "aws/live/rot13", "aws/live/split/x", "real/UPPER", "real/",
                                  "real/" + "a" * 33, "AWS/live", "aws", "negative/x", "../aws/live"])
def test_manifest_cell_must_be_on_the_allow_list(cell):
    with pytest.raises(ValueError, match="cell"):
        m2._validate_manifest(manifest(cell, AWS_SECRET.encode()), "t")


@pytest.mark.parametrize("cell,needle", [
    ("aws/live", b"A" * 16), ("aws/live", b"AKIA" + b"A" * 15), ("aws/live", AWS_SECRET.encode()[:39]),
    ("aws/live", AWS_SECRET.encode() + b"A"), ("aws/live", b"Z" * 20),
    ("hex32/live", HEX64.encode()[:32]), ("hex32/live", HEX64.encode() + b"aa"), ("hex32/live", b"AKIAABCDEFGHIJKLMNOP"),
    ("hex32/live", b"g" * 64),
    ("jwt/live", b"eyJabc.eyJdef.sig-sig-sig-sig"), ("jwt/live", b"x" * 32),
    ("ssh_key/live", b"-----BEGIN OPENSSH PRIVATE KEY-----"), ("ssh_key/live", b"A" * 64),
    ("ssh_key/live", PEM[:-5]), ("real/openssl", b"just some 16+ byte text"),
])
def test_needle_must_match_its_kinds_rule_in_full(cell, needle):
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest(cell, needle), "t")


@pytest.mark.parametrize("cell,needle", [
    ("aws/live", AWS_SECRET.encode()), ("aws/freed", b"AKIAABCDEFGHIJKLMNOP"), ("hex32/exited", HEX64.encode()),
    ("hex32/live", HEX64.upper().encode()), ("jwt/live", JWT), ("ssh_key/live", PEM), ("real/openssl", JWT),
    ("real/my-prog_1", b"AKIAABCDEFGHIJKLMNOP"),
])
def test_needle_matching_its_rule_is_accepted(cell, needle):
    m2._validate_manifest(manifest(cell, needle), "t")


def test_negative_cell_has_no_needles_and_nothing_else_is_allowed_with_it():
    m2._validate_manifest({"cell": "negative", "needles": []}, "t")
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest("negative", HEX64.encode()), "t")


def test_encoded_variants_are_decoded_before_the_rule_check():
    m2._validate_manifest(manifest("hex32/live/utf16", HEX64.encode().decode().encode("utf-16-le")), "t")
    m2._validate_manifest(manifest("jwt/live/base64", base64.b64encode(JWT)), "t")
    for bad in (b"\xff" * 70, b"abc" * 20, b"A" * 64):  # not utf-16 text / not a secret
        with pytest.raises(ValueError, match="needle"):
            m2._validate_manifest(manifest("hex32/live/utf16", bad), "t")
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest("jwt/live/base64", b"!!not base64!!" * 4), "t")
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest("hex32/live/base64", base64.b64encode(b"A" * 40)), "t")


def test_split_needles_must_be_two_halves_of_one_secret():
    half = len(PEM) // 2
    m2._validate_manifest(manifest("ssh_key/live/split", PEM[:half], PEM[half:]), "t")
    with pytest.raises(ValueError, match="two"):
        m2._validate_manifest(manifest("ssh_key/live/split", PEM), "t")
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest("ssh_key/live/split", PEM[half:], PEM[:half]), "t")  # wrong order
    with pytest.raises(ValueError, match="needle"):
        m2._validate_manifest(manifest("ssh_key/live/split", b"A" * 20, b"B" * 20), "t")


def test_planted_entry_cannot_be_a_huge_blob_that_hides_false_positives():
    m2._validate_manifest(manifest("jwt/live", JWT, planted=JWT + b"\n"), "t")
    with pytest.raises(ValueError, match="planted"):
        m2._validate_manifest(manifest("jwt/live", JWT, planted=b"." * 4096 + JWT), "t")


def test_needle_that_is_a_slice_of_a_real_hit_is_rejected_by_evaluate():
    data = b"." * 64 + JWT + b"\n" + b"." * 64
    slice_needle = JWT[:-4]  # still a full jwt-rule match on its own, but not the whole hit
    m2._validate_manifest(manifest("jwt/live", slice_needle), "t")
    with pytest.raises(ValueError, match="slice of a scanner hit"):
        m2.evaluate([(data, manifest("jwt/live", slice_needle))])
    res = m2.evaluate([(data, manifest("jwt/live", JWT))])  # the whole match is fine
    assert res["cells"]["jwt/live"]["detected"] == 1


def test_build_dump_too_small_raises():
    with pytest.raises(ValueError, match="too small"):
        m2.build_dump("hex32", "live", None, 8 * m2.PAGE, random.Random(1))


def test_redact_file_catches_match_across_chunk_edge(tmp_path):
    aws = b"AKIAABCDEFGHIJKLMNOP"
    buf = bytearray(b"." * 400)
    buf[90:110] = aws  # crosses the chunk edge at 100
    path = tmp_path / "img.save"
    path.write_bytes(bytes(buf))
    assert m2.redact_file(path, chunk=100, overlap=64) == 1
    out = path.read_bytes()
    assert len(out) == 400 and not m2.scan(out) and out[:90] == b"." * 90


def test_redact_file_without_overlap_would_miss_edge_match(tmp_path):
    buf = bytearray(b"." * 400)
    buf[90:110] = b"AKIAABCDEFGHIJKLMNOP"
    path = tmp_path / "img.save"
    path.write_bytes(bytes(buf))
    m2.redact_file(path, chunk=100, overlap=0)
    assert m2.scan(path.read_bytes())  # proves the overlap is what catches it


def test_scanner_real_format_variants():
    pem = (b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n"
           + b"A" * 64 + b"\n-----END RSA PRIVATE KEY-----")
    assert [h[0] for h in m2.scan(pem)] == ["ssh_key"]
    key = b"A" * 20 + b"b" * 10 + b"/+" + b"9" * 8
    assert len(key) == 40
    for form in (b'"aws_secret_access_key": "%s"', b'aws_secret_access_key="%s"', b"aws_secret_access_key='%s'",
                 b"AWS_SECRET_ACCESS_KEY=%s"):
        assert [h[3] for h in m2.scan(form % key)] == [key], form
    assert [h[0] for h in m2.scan(b"eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.")] == ["jwt"]  # empty signature


def test_hex_rule_ignores_substring_of_longer_run():
    h = os.urandom(40).hex()  # 80 hex chars
    assert not m2.scan(h.encode())
    assert not m2.scan(b"a" + hashlib.sha256(b"x").hexdigest().encode())


def test_known_limitation_real_sha256_is_flagged_as_secret():
    digest = hashlib.sha256(b"abc").hexdigest().encode()
    # KNOWN false positive: a genuine SHA-256 looks exactly like a 32-byte hex secret. Documented, not a bug.
    assert [h[0] for h in m2.scan(digest)] == ["hex32"]


# ---- restore_test ----
def test_restore_test_refuses_other_vms(tmp_path):
    with pytest.raises(ValueError, match="target"):
        m2.restore_test("prod", tmp_path / ".local" / "img")


def test_restore_test_requires_dir_under_dot_local(tmp_path):
    with pytest.raises(ValueError, match=r"\.local"):
        m2.restore_test("target", Path(tmp_path.anchor) / "no_such_dir_img")


def test_private_dir_must_resolve_inside_repo_local(tmp_path):
    for bad in (Path.home() / ".local" / "img", Path(tmp_path.anchor) / "tmp" / ".local" / "x",
                m2.ROOT / ".local" / ".." / "elsewhere"):
        with pytest.raises(ValueError, match=r"\.local"):
            m2._private_dir_path(bad)
    assert m2._private_dir_path(m2.ROOT / ".local" / "tmp" / "img") == (m2.ROOT / ".local" / "tmp" / "img").resolve()


def test_restore_test_na_without_virsh(tmp_path, monkeypatch):
    monkeypatch.setattr(m2.shutil, "which", lambda name: None)
    d = tmp_path / ".local" / "img"
    res = m2.restore_test("target", d)
    assert res["status"] == "NA" and "virsh" in res["reason"] and not d.exists()


UUID = "6d2f5a8e-1c3b-4e57-9a10-0123456789ab"


@pytest.fixture(autouse=True)
def revert_marker(tmp_path, monkeypatch):
    """A fresh, valid revert marker bound to UUID (the one fake_virsh reports) for every restore_test run."""
    path = tmp_path / "target.reverted"
    m2.guards.write_marker(path, "target", uuid=UUID, state="shut off")
    monkeypatch.setattr(m2, "MARKER", path)
    return path


NET_XML = "<network><name>iso</name></network>"
DOM_XML = ("<domain><devices><interface type='network'><source network='iso'/><link state='down'/></interface>"
           "</devices></domain>")
DOMIFLIST = (" Interface   Type      Source   Model    MAC\n" + "-" * 50 + "\n"
             " vnet0       network   iso      virtio   52:54:00:00:00:01\n\n")


def fake_virsh(monkeypatch, image_secret=b"AKIAABCDEFGHIJKLMNOP", net_xml=NET_XML, fail=None, state="running",
               running="target", dom_xml=DOM_XML, write_image=True, uuid=UUID):
    calls = []

    def run(*args, timeout=300):
        calls.append(args)
        if fail == "timeout-save" and args[0] == "save":
            raise subprocess.TimeoutExpired("virsh", timeout)
        out, rc = "", 0
        if args[0] == fail:
            rc = 1
        elif args[0] == "dumpxml":
            out = dom_xml
        elif args[0] == "net-dumpxml":
            out = net_xml
        elif args[0] == "save":
            if write_image:
                Path(args[2]).write_bytes(b"pad" + image_secret + b"pad")
        elif args[0] == "domiflist":
            out = DOMIFLIST
        elif args[0] == "domif-getlink":
            out = "vnet0 down"
        elif args[:2] == ("list", "--name"):
            out = running
        elif args[0] == "domstate":
            out = state
        elif args[0] == "domuuid":
            out = uuid + chr(10)
        return subprocess.CompletedProcess(args, rc, out, "boom")
    monkeypatch.setattr(m2.shutil, "which", lambda name: "/usr/bin/virsh")
    monkeypatch.setattr(m2, "_virsh", run)
    return calls


def test_restore_test_ok_redacts_and_deletes_image(tmp_path, monkeypatch):
    fake_virsh(monkeypatch)
    d = tmp_path / ".local" / "img"
    res = m2.restore_test("target", d)
    assert res["status"] == "OK" and res["restored"] and res["same_scanner_rescan_hits"] == 0
    assert res["service_check"] == "NA (not automated)"
    assert not d.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_restore_test_dir_is_0700(tmp_path, monkeypatch):
    seen = {}
    calls = fake_virsh(monkeypatch)
    orig = m2._virsh

    def spy(*a, timeout=300):
        if a[0] == "save":
            seen["mode"] = stat.S_IMODE(os.stat(Path(a[2]).parent).st_mode)
        return orig(*a, timeout=timeout)
    monkeypatch.setattr(m2, "_virsh", spy)
    m2.restore_test("target", tmp_path / ".local" / "img")
    assert seen["mode"] == 0o700 and calls


def test_restore_test_refuses_forwarding_network(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, net_xml="<network><forward mode='nat'/></network>")
    d = tmp_path / ".local" / "img"
    with pytest.raises(RuntimeError, match="not isolated"):
        m2.restore_test("target", d)
    assert not d.exists()


def test_restore_test_failed_restore_says_after_redaction(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, fail="restore")
    d = tmp_path / ".local" / "img"
    res = m2.restore_test("target", d)
    assert res["status"] == "FAILED" and "after redaction" in res["reason"] and not res["restored"]
    assert not d.exists()


def test_restore_test_failed_save_and_timeout(tmp_path, monkeypatch, revert_marker):
    fake_virsh(monkeypatch, fail="save")
    res = m2.restore_test("target", tmp_path / ".local" / "a")
    assert res["status"] == "FAILED" and "save failed" in res["reason"]
    m2.guards.write_marker(revert_marker, "target", uuid=UUID)
    fake_virsh(monkeypatch, fail="timeout-save")
    res = m2.restore_test("target", tmp_path / ".local" / "b")
    assert res["status"] == "FAILED" and "timeout" in res["reason"]
    assert not (tmp_path / ".local" / "b").exists()


def test_restore_test_refuses_existing_dir(tmp_path, monkeypatch):
    fake_virsh(monkeypatch)
    (tmp_path / ".local" / "img").mkdir(parents=True)
    with pytest.raises(FileExistsError):
        m2.restore_test("target", tmp_path / ".local" / "img")


def test_restore_test_refuses_other_running_domain_before_save(tmp_path, monkeypatch):
    calls = fake_virsh(monkeypatch, running="target kvm-plain")
    d = tmp_path / ".local" / "img"
    with pytest.raises(RuntimeError, match="kvm-plain"):
        m2.restore_test("target", d)
    assert not any(c[0] == "save" for c in calls) and not d.exists()


def test_restore_test_refuses_without_a_fresh_valid_marker(tmp_path, monkeypatch, revert_marker):
    calls = fake_virsh(monkeypatch)
    d = tmp_path / ".local" / "img"
    revert_marker.unlink()
    with pytest.raises(RuntimeError, match="no revert marker"):
        m2.restore_test("target", d)
    old = datetime.now(timezone.utc) - timedelta(minutes=16)
    revert_marker.write_text(json.dumps({"vm": "target", "uuid": UUID, "created_utc": old.strftime("%Y-%m-%dT%H:%M:%SZ")}))
    with pytest.raises(RuntimeError, match="older than"):
        m2.restore_test("target", d)
    m2.guards.write_marker(revert_marker, "target")  # no uuid: not bound to this domain
    with pytest.raises(RuntimeError, match="uuid"):
        m2.restore_test("target", d)
    assert not any(c[0] in ("save", "restore") for c in calls) and not d.exists()


def test_restore_test_refuses_a_marker_for_another_domain_uuid(tmp_path, monkeypatch):
    calls = fake_virsh(monkeypatch, uuid="11111111-2222-4333-8444-555555555555")
    with pytest.raises(RuntimeError, match="uuid"):
        m2.restore_test("target", tmp_path / ".local" / "img")
    assert not any(c[0] == "save" for c in calls)


def test_restore_test_uses_up_the_marker(tmp_path, monkeypatch, revert_marker):
    fake_virsh(monkeypatch)
    assert m2.restore_test("target", tmp_path / ".local" / "img")["status"] == "OK"
    assert not revert_marker.exists()  # every save/restore needs a fresh revert


def test_m2_virsh_wrapper_is_pinned_to_the_system_connection(monkeypatch):
    seen = {}
    monkeypatch.setattr(m2.guards.subprocess, "run",
                        lambda argv, **k: seen.update(argv=argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    m2._virsh("list")
    assert tuple(seen["argv"][:3]) == ("virsh", "-c", "qemu:///system")


def test_restore_test_refuses_hostdev_before_save(tmp_path, monkeypatch):
    xml = DOM_XML.replace("</devices>", "<hostdev mode='subsystem' type='pci'/></devices>")
    calls = fake_virsh(monkeypatch, dom_xml=xml)
    with pytest.raises(RuntimeError, match="hostdev"):
        m2.restore_test("target", tmp_path / ".local" / "img")
    assert not any(c[0] == "save" for c in calls)


# ---- plant_guest ----
@pytest.fixture
def plant_guest(tmp_path):
    for src in (ROOT / "scripts" / "plant_guest.py", ROOT / "vsec" / "secrets_gen.py"):
        (tmp_path / src.name).write_bytes(src.read_bytes())
    spec = importlib.util.spec_from_file_location("plant_guest_under_test", tmp_path / "plant_guest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_plant_guest_freed_state_keeps_no_reference(plant_guest):
    assert plant_guest.plant("hex32", "freed", "ab" * 32) is None
    assert plant_guest.plant("hex32", "exited", "ab" * 32) is None
    assert plant_guest.plant("hex32", "live", "ab" * 32) == b"ab" * 32


# ---- M3 ----
def test_m3_counts_and_cis():
    assert m3.hidden_pids({1, 2, 3}, {1, 2, 3, 99}) == {99}
    r = m3.evaluate([
        {"name": "a", "truth_hidden": [7], "detected": [7]},
        {"name": "b", "truth_hidden": [8], "detected": []},
        {"name": "clean", "truth_hidden": [], "detected": [5]},
    ])
    assert (r["detected"], r["hidden_total"], r["false_items"]) == (1, 2, 1)
    assert r["failures"] == ["b"] and r["clean_with_alarm"] == 1
    assert r["detection_ci"][0] < 0.5 < r["detection_ci"][1]


def test_m3_evaluate_validates_input():
    with pytest.raises(ValueError):
        m3.evaluate([])
    with pytest.raises(ValueError, match="result #1 is missing detected"):
        m3.evaluate([{"name": "a", "truth_hidden": [], "detected": []}, {"name": "b", "truth_hidden": []}])


def test_m3_pids_missing_key_raises_and_non_numeric_skipped():
    with pytest.raises(ValueError, match="PID"):
        m3.pids([{"Pid": 1}])
    assert m3.pids([{"PID": 1}, {"PID": "-"}, {"PID": "N/A"}, {"PID": None}, {"PID": "7"}]) == ({1, 7}, 3)


@pytest.mark.parametrize("bad", ["12abc", "not-hex" * 10, "ab" * 31, "ab" * 33, "zz" * 32])
def test_malformed_symbols_hash_is_an_error_even_with_allow_unverified(stub_vol, bad):
    with pytest.raises(RuntimeError, match="64"):
        m3.detect(stub_vol(), "isf", expected_sha256=bad, allow_unverified=True)


def test_malformed_symbols_hash_in_the_environment_is_an_error_too(stub_vol, monkeypatch):
    monkeypatch.setenv("VSEC_SYMBOLS_SHA256", "oops")
    with pytest.raises(RuntimeError, match="64"):
        m3.detect(stub_vol(), allow_unverified=True)


def test_vol_stderr_is_cleaned_and_truncated_before_it_is_raised(stub_vol, monkeypatch):
    evil = "X" * 5000 + "\x1b[2J\x1b]0;pwned\x07" + "gu" + "‮" + "est" + "​"  # the tail is what gets printed
    monkeypatch.setattr(m3.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", evil))
    with pytest.raises(RuntimeError) as e:
        m3.run_plugin("d.mem", "pslist")
    msg = str(e.value)
    assert "\x1b" not in msg and "\x07" not in msg and "‮" not in msg and "​" not in msg
    assert len(msg) < 400


def test_a_row_without_pid_does_not_echo_raw_keys():
    with pytest.raises(ValueError) as e:
        m3.pids([{"\x1b[31mevil‮" + "k" * 500: 1}])
    assert "\x1b" not in str(e.value) and "‮" not in str(e.value) and len(str(e.value)) < 400


def test_vol_output_that_is_not_json_is_a_clean_error(monkeypatch):
    monkeypatch.setattr(m3.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "\x1b[31mnot json", ""))
    monkeypatch.setenv("VOL", sys.executable)
    with pytest.raises(RuntimeError, match="not valid JSON") as e:
        m3.run_plugin("d.mem", "pslist")
    assert "\x1b" not in str(e.value)


def test_clean_text_strips_bidi_zero_width_and_line_separators():
    from vsec import clean_text
    dirty = ("a‪b‫c‬d‭e‮f⁦g⁧h⁨i⁩j​k‌l‍m‎n‏o"
             " p q﻿r")
    assert clean_text(dirty) == "abcdefghijklmnopqr"
    assert clean_text("ok\ttext\nline é中") == "ok text line é中"  # real letters survive


def test_m3_is_exited():
    assert m3.is_exited({"PID": 5, "EXIT_STATE": "EXIT_ZOMBIE"})
    assert m3.is_exited({"State": "Dead"})
    assert not m3.is_exited({"PID": 5, "State": "running", "COMM": "exit_helper"})


@pytest.fixture
def stub_vol(tmp_path, monkeypatch):
    """A fake `vol`: the 'dump' is a JSON file {plugin name: rows | "FAIL"}; the stub prints that plugin's rows."""
    stub = tmp_path / "stub.py"
    stub.write_text("import json, sys\na = sys.argv\nif '--version' in a:\n    print('Volatility 3 Framework 2.7.1')\n"
                    "    sys.exit(0)\nrows = json.load(open(a[a.index('-f') + 1]))[a[-1]]\n"
                    "if rows == 'FAIL':\n    sys.stderr.write('boom')\n    sys.exit(2)\nprint(json.dumps(rows))\n")
    if os.name == "nt":
        exe = tmp_path / "vol.bat"
        exe.write_text(f'@"{sys.executable}" "{stub}" %*\r\n')
    else:
        exe = tmp_path / "vol"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{stub}" "$@"\n')
        exe.chmod(0o755)
    monkeypatch.setenv("VOL", str(exe))

    def make(**rows):
        base = {"pslist": [{"PID": 1}, {"PID": 2}], "psscan": [{"PID": 1}, {"PID": 2}],
                "lsmod": [{"Name": "ext4"}], "hidden_modules": []}
        base.update(rows)
        dump = tmp_path / "dump.json"
        dump.write_text(json.dumps({m3.PLUGINS[k]: v for k, v in base.items()}))
        return dump
    return make


def test_m3_detect_end_to_end_with_stub(stub_vol):
    dump = stub_vol(psscan=[{"PID": 1}, {"PID": 2}, {"PID": 99}, {"PID": 50, "EXIT_STATE": "EXIT_DEAD"}, {"PID": "-"}],
                    hidden_modules=[{"Name": "rootkit"}])
    res = m3.detect(dump, allow_unverified=True)
    assert res["lsmod_modules"] == ["ext4"] and res["hidden_modules"] == ["rootkit"]
    assert res["skipped_non_numeric_pid_rows"] == {"pslist": 0, "psscan": 1}
    assert set(res["scan_seconds"]) == {"pslist", "psscan", "lsmod", "hidden_modules"}
    assert res["hidden_pids"] == [50, 99] and res["exclude_exited"] is False  # nothing is dropped by default
    assert res["exclusion_applied"] is False and res["excluded_exited"] == []
    assert (res["sandboxed"], res["symbols_sha_verified"], res["vol_version"]) == (False, False, "2.7.1")
    assert res["lsmod_empty"] is False


def test_m3_exclude_exited_reports_every_dropped_row(stub_vol):
    dump = stub_vol(psscan=[{"PID": 1}, {"PID": 2}, {"PID": 99}, {"PID": 50, "EXIT_STATE": "EXIT_DEAD"}])
    res = m3.detect(dump, allow_unverified=True, exclude_exited=True)
    assert res["hidden_pids"] == [99] and res["exclude_exited"] is True and res["exclusion_applied"] is True
    assert len(res["excluded_exited"]) == 1
    row = res["excluded_exited"][0]
    assert row["pid"] == 50 and row["offset"] is None and "EXIT_STATE" in row["reason"]
    # asking for exclusion but having nothing to exclude: applied is about the rows that were really removed
    clean = m3.detect(stub_vol(), allow_unverified=True, exclude_exited=True)
    assert clean["exclusion_applied"] is False and clean["excluded_exited"] == []


def rows_with(column, pairs):
    return [{"PID": pid, column: off, "COMM": "x"} for pid, off in pairs]


@pytest.mark.parametrize("column", ["Offset", "OFFSET (V)", "Offset(V)", "Address"])
def test_m3_hidden_task_reusing_a_listed_pid_is_still_reported(stub_vol, column):
    listed = rows_with(column, [(1, "0xa000"), (2, "0xb000")])
    scanned = rows_with(column, [(1, "0xa000"), (2, "0xb000"), (2, "0xdead0")])  # a second task wearing PID 2
    res = m3.detect(stub_vol(pslist=listed, psscan=scanned), allow_unverified=True)
    assert res["hidden_pids"] == [2]
    assert res["hidden_tasks"] == [{"pid": 2, "offset": "0xdead0"}]
    assert res["hidden_identity"] == column and res["limitations"] == []


def test_m3_offset_formats_compare_equal_when_they_are_the_same_number(stub_vol):
    listed = rows_with("Offset", [(1, 0xA000), (2, "0xB000")])
    scanned = rows_with("Offset", [(1, "0xa000"), (2, 0xB000)])
    assert m3.detect(stub_vol(pslist=listed, psscan=scanned), allow_unverified=True)["hidden_tasks"] == []


def test_m3_tid_is_the_fallback_identity(stub_vol):
    listed = [{"PID": 1, "TID": 1}, {"PID": 2, "TID": 2}]
    scanned = listed + [{"PID": 2, "TID": 777}]
    res = m3.detect(stub_vol(pslist=listed, psscan=scanned), allow_unverified=True)
    assert res["hidden_tasks"] == [{"pid": 2, "offset": 777}] and res["hidden_identity"] == "TID"


def test_m3_without_an_identity_column_compares_pids_only_and_says_so(stub_vol):
    res = m3.detect(stub_vol(pslist=[{"PID": 1}, {"PID": 2}], psscan=[{"PID": 1}, {"PID": 2}, {"PID": 2}, {"PID": 9}]),
                    allow_unverified=True)
    assert res["hidden_pids"] == [9] and res["hidden_identity"] is None
    assert any("PID only" in x for x in res["limitations"])


def test_m3_identity_column_must_be_in_both_outputs(stub_vol):
    # pslist has no offsets: using psscan's offsets alone would call every process hidden
    res = m3.detect(stub_vol(pslist=[{"PID": 1}, {"PID": 2}], psscan=rows_with("Offset", [(1, 1), (2, 2)])),
                    allow_unverified=True)
    assert res["hidden_identity"] is None and res["hidden_pids"] == []


def test_m3_detect_errors_with_stub(stub_vol):
    with pytest.raises(RuntimeError, match="zero rows"):
        m3.detect(stub_vol(pslist=[]), allow_unverified=True)
    with pytest.raises(ValueError, match="PID"):
        m3.detect(stub_vol(pslist=[{"Pid": 1}]), allow_unverified=True)
    with pytest.raises(RuntimeError, match="psscan failed"):
        m3.detect(stub_vol(psscan="FAIL"), allow_unverified=True)


def test_m3_missing_volatility_and_timeout(monkeypatch, stub_vol):
    dump = stub_vol()
    monkeypatch.setattr(m3.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("vol", 900)))
    with pytest.raises(RuntimeError, match="timed out"):
        m3.run_plugin(dump, "pslist")
    monkeypatch.setenv("VOL", "definitely-not-installed-vol")
    assert not m3.available()
    with pytest.raises(RuntimeError, match="not found"):
        m3.detect(dump, allow_unverified=True)


def test_m3_build_command_plain_and_sandboxed():
    plain = m3.build_command("/bin/vol", "d.mem", "pslist", "/sym")
    assert plain == ["/bin/vol", "-q", "-r", "json", "-s", "/sym", "-f", "d.mem", "linux.pslist.PsList"]
    boxed = m3.build_command("/bin/vol", "d.mem", "pslist", None, sandbox=True)
    assert boxed[:3] == ["sh", str(m3.SANDBOX), "d.mem"] and boxed[3:] == [
        "/bin/vol", "-q", "-r", "json", "-f", "d.mem", "linux.pslist.PsList"]


def test_m3_detect_passes_sandbox_to_every_plugin(stub_vol, monkeypatch):
    seen = []
    monkeypatch.setattr(m3, "run_plugin", lambda dump, name, sym=None, sandbox=False: seen.append(sandbox) or
                        [{"PID": 1}])
    assert m3.detect("d.mem", sandbox=True, allow_unverified=True)["sandboxed"] is True
    assert m3.detect("d.mem", allow_unverified=True)["sandboxed"] is False
    assert seen == [True] * 4 + [False] * 4


def test_m3_sandbox_requested_but_unavailable_raises(stub_vol, monkeypatch):
    monkeypatch.setattr(m3, "sandbox_available", lambda: False)
    with pytest.raises(RuntimeError, match="sandbox"):
        m3.run_plugin(stub_vol(), "pslist", sandbox=True)


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="needs POSIX bash")
def test_shell_scripts_pass_bash_n():
    for name in ("run_vol_sandboxed.sh", "build_symbols.sh"):
        assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / name)]).returncode == 0


# ---- manifest hardening ----
def test_manifest_needle_and_planted_must_be_at_least_16_bytes():
    ok, short = b"AKIAABCDEFGHIJKLMNOP", b"A" * 15
    m2.evaluate([(b"x" * 64, {"cell": "aws/live", "needles": [ok.hex()]})])  # a full 20-char key id is fine
    with pytest.raises(ValueError, match="shorter than 16 bytes"):
        m2.evaluate([(b"x" * 64, {"cell": "aws/live", "needles": [short.hex()]})])
    with pytest.raises(ValueError, match="shorter than 16 bytes"):
        m2.evaluate([(b"x" * 64, {"cell": "aws/live", "needles": [ok.hex()], "planted": [short.hex()]})])


def test_every_planted_entry_must_contain_a_needle():
    needle = b"AKIAABCDEFGHIJKLMNOP"
    with pytest.raises(ValueError, match="does not contain a needle"):
        m2.evaluate([(needle, {"cell": "aws/live", "needles": [needle.hex()], "planted": [(b"B" * 30).hex()]})])
    with pytest.raises(ValueError, match="does not contain"):  # planted text but no needle at all
        m2.evaluate([(needle, {"cell": "negative", "needles": [], "planted": [needle.hex()]})])
    ok = {"cell": "aws/live", "needles": [needle.hex()], "planted": [(b"id=" + needle + b"\n").hex()]}
    assert m2.evaluate([(b"id=" + needle + b"\n", ok)])["plain"]["present"] == 1


def test_split_variant_needs_both_halves_in_the_planted_text():
    a, b = HEX64.encode()[:32], HEX64.encode()[32:]
    base = {"cell": "hex32/live/split", "needles": [a.hex(), b.hex()]}
    with pytest.raises(ValueError, match="both halves"):
        m2.evaluate([(a + b"." + b, {**base, "planted": [a.hex()]})])
    assert m2.evaluate([(a + b"." + b, {**base, "planted": [(a + b).hex()]})])["held_out"]["present"] == 1


def test_a_hit_is_a_false_positive_unless_inside_planted_text():
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2"
    man = {"cell": "jwt/live", "needles": [jwt.hex()], "planted": [jwt.hex()]}
    clean = m2.evaluate([(b"..." + jwt + b"\n...", man)])
    assert clean["false_positives"] == 0 and clean["plain"]["detected"] == 1
    other = JWT  # a second, real-looking token that was not planted
    stray = m2.evaluate([(b"..." + jwt + b"\n..." + other + b"\n", man)])
    assert stray["false_positives"] == 1 and stray["plain"]["detected"] == 1
    # the rule runs on into trailing token characters: the hit is LONGER than the needle, i.e. the needle is a
    # slice of it, which evaluate() refuses (see test_needle_that_is_a_slice_of_a_real_hit_...)
    with pytest.raises(ValueError, match="slice"):
        m2.evaluate([(b"..." + jwt + b"EXTRATOKENCHARS", man)])


def test_synthetic_manifests_all_pass_validation_and_real_cells_still_work():
    for _, man in m2.synthetic_dumps(n=1, size=64 * 1024):
        m2._validate_manifest(man, man["cell"])
    secret = b"AKIAABCDEFGHIJKLMNOP"
    res = m2.evaluate([(b"xx" + secret + b"yy", {"cell": "real/openssl", "needles": [secret.hex()]})])
    assert res["real_programs"]["detected"] == 1 and res["false_positives"] == 0


# ---- ssh_key rule: bounded ----
def test_ssh_key_rule_is_linear_on_repeated_headers():
    import time
    data = b"-----BEGIN RSA PRIVATE KEY-----\n" * 8000
    t0 = time.perf_counter()
    assert m2.scan(data) == []
    assert time.perf_counter() - t0 < 2


def test_ssh_key_rule_still_matches_real_pems_and_respects_bounds():
    enc = (b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\n"
           + (b"A" * 64 + b"\n") * 50 + b"-----END RSA PRIVATE KEY-----")
    assert [h[0] for h in m2.scan(b"junk" + enc + b"junk")] == ["ssh_key"]
    huge = b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 9000 + b"\n-----END PRIVATE KEY-----"
    assert m2.scan(huge) == []  # body over 8192 characters: not matched, and not slow
    real = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"B" * 200 + b"\n-----END OPENSSH PRIVATE KEY-----"
    hits = m2.scan(b"-----BEGIN RSA PRIVATE KEY-----\n" + b"C" * 50 + b"\n" + real)  # first header has no END
    assert len(hits) == 1 and hits[0][3] == real  # the body cannot swallow the next BEGIN


# ---- restore_test hardening ----
def test_restore_test_fails_when_save_wrote_no_image(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, write_image=False)
    d = tmp_path / ".local" / "img"
    res = m2.restore_test("target", d)
    assert res["status"] == "FAILED" and res["reason"] == "virsh save wrote no image" and not d.exists()


def test_restore_test_filenotfound_is_na_only_when_virsh_is_missing(tmp_path, monkeypatch, revert_marker):
    fake_virsh(monkeypatch)
    real = m2._virsh

    def boom(*a, timeout=300):
        if a[0] == "save":
            raise FileNotFoundError("no such file")
        return real(*a, timeout=timeout)
    monkeypatch.setattr(m2, "_virsh", boom)
    res = m2.restore_test("target", tmp_path / ".local" / "a")
    assert res["status"] == "FAILED" and "no such file" in res["reason"]  # virsh exists: a real failure
    m2.guards.write_marker(revert_marker, "target", uuid=UUID)  # the first run used the marker up
    answers = iter(["/usr/bin/virsh"])
    monkeypatch.setattr(m2.shutil, "which", lambda name: next(answers, None))  # present at start, gone later
    assert m2.restore_test("target", tmp_path / ".local" / "b")["status"] == "NA"


def test_restore_test_cleanup_error_is_recorded_and_does_not_replace_the_result(tmp_path, monkeypatch):
    fake_virsh(monkeypatch)
    real_unlink = Path.unlink

    def stuck(self, missing_ok=False):
        if self.name.endswith(".save"):
            raise PermissionError("locked")
        return real_unlink(self, missing_ok=missing_ok)
    monkeypatch.setattr(Path, "unlink", stuck)
    d = tmp_path / ".local" / "img"
    res = m2.restore_test("target", d)
    assert res["status"] == "OK" and "locked" in res["cleanup_error"]
    monkeypatch.undo()
    shutil.rmtree(d)


def test_restore_test_checks_links_down_before_saving(tmp_path, monkeypatch):
    calls = fake_virsh(monkeypatch)
    real = m2._virsh
    monkeypatch.setattr(m2, "_virsh", lambda *a, timeout=300: subprocess.CompletedProcess(
        a, 0, "vnet0 up", "") if a[0] == "domif-getlink" else real(*a, timeout=timeout))
    with pytest.raises(RuntimeError, match="not confirmed down"):
        m2.restore_test("target", tmp_path / ".local" / "img")
    assert not any(c[0] == "save" for c in calls) and not (tmp_path / ".local" / "img").exists()


def test_assert_vm_isolated_public_name_and_deprecated_alias(monkeypatch):
    fake_virsh(monkeypatch)
    m2.assert_vm_isolated("target")
    assert m2._assert_vm_isolated is m2.assert_vm_isolated
    fake_virsh(monkeypatch, dom_xml=DOM_XML.replace("</devices>", "<filesystem type='mount'/></devices>"))
    with pytest.raises(RuntimeError, match="filesystem"):
        m2.assert_vm_isolated("target")


# ---- M3: mandatory, copied and re-hashed symbols ----
def isf_file(folder, name="ubuntu-6.8.0-1.json", content=b'{"symbols": {}}'):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def test_symbols_hash_is_mandatory_empty_counts_as_missing(stub_vol, tmp_path, monkeypatch):
    monkeypatch.delenv(m3.SYMBOLS_SHA_ENV, raising=False)
    dump, (path, _) = stub_vol(), isf_file(tmp_path / "isf")
    for bad in (None, "", "  \n", "abc", "z" * 64, "a" * 63):
        with pytest.raises(RuntimeError, match="mandatory"):
            m3.detect(dump, path, expected_sha256=bad)
    monkeypatch.setenv(m3.SYMBOLS_SHA_ENV, "")
    with pytest.raises(RuntimeError, match="mandatory"):
        m3.detect(dump, path)
    with pytest.raises(RuntimeError, match="mandatory"):
        m3.detect(dump)  # no symbols at all is not an escape hatch
    res = m3.detect(dump, path, allow_unverified=True)
    assert res["symbols_sha_verified"] is False and res["symbols_sha256"] is None


def test_symbols_hash_accepts_uppercase_and_trailing_newline(stub_vol, tmp_path):
    path, digest = isf_file(tmp_path / "isf")
    res = m3.detect(stub_vol(), path, expected_sha256=digest.upper() + "\n")
    assert res["symbols_sha_verified"] is True and res["symbols_sha256"] == digest


@pytest.mark.parametrize("extra", ["evil.json.gz", "EVIL.JSON", "x.zip", "y.json.bz2", "z.json.xz", "sub/w.json"])
def test_symbols_dir_with_another_isf_file_is_refused(stub_vol, tmp_path, extra):
    folder = tmp_path / "isf"
    path, digest = isf_file(folder)
    isf_file(folder / Path(extra).parent, Path(extra).name, b"{}")
    with pytest.raises(RuntimeError, match="exactly one"):
        m3.detect(stub_vol(), folder, expected_sha256=digest)


def test_symbols_dir_with_one_isf_and_other_files_is_fine(stub_vol, tmp_path):
    folder = tmp_path / "isf"
    path, digest = isf_file(folder)
    (folder / "notes.txt").write_text("x")
    assert m3.detect(stub_vol(), folder, expected_sha256=digest)["symbols_sha_verified"] is True


def test_vol_reads_a_private_copy_which_is_removed_afterwards(stub_vol, tmp_path, monkeypatch):
    src, digest = isf_file(tmp_path / "isf")
    seen = {}

    def run(dump, name, sym=None, sandbox=False):
        sym = Path(sym)
        seen.setdefault("dirs", set()).add(sym)
        seen["files"] = [p.name for p in sym.iterdir()]
        seen["content"] = (sym / src.name).read_bytes()
        seen["mode"] = stat.S_IMODE(sym.stat().st_mode)
        return [{"PID": 1}]
    monkeypatch.setattr(m3, "run_plugin", run)
    m3.detect(stub_vol(), src.parent, expected_sha256=digest)
    (staged,) = seen["dirs"]
    assert staged != src.parent
    assert staged.parent == m3.ROOT / ".local" / "tmp"
    assert seen["files"] == [src.name] and seen["content"] == src.read_bytes()
    if os.name != "nt":
        assert seen["mode"] == 0o700
    assert not staged.exists()  # cleaned up


def test_copy_is_rehashed_and_a_swapped_file_is_refused(stub_vol, tmp_path, monkeypatch):
    src, digest = isf_file(tmp_path / "isf")
    made = []
    real_mkdtemp = m3.tempfile.mkdtemp
    monkeypatch.setattr(m3.tempfile, "mkdtemp", lambda **kw: made.append(real_mkdtemp(**kw)) or made[-1])
    monkeypatch.setattr(m3.shutil, "copyfile", lambda s, d: Path(d).write_bytes(b'{"evil": 1}'))  # swapped in flight
    ran = []
    monkeypatch.setattr(m3, "run_plugin", lambda *a, **k: ran.append(a) or [{"PID": 1}])
    with pytest.raises(RuntimeError, match="does not match"):
        m3.detect(stub_vol(), src, expected_sha256=digest)
    assert ran == [] and made and not Path(made[0]).exists()


# ---- M3: refuse output that cannot support a verdict ----
def test_detect_refuses_empty_or_short_psscan(stub_vol):
    with pytest.raises(RuntimeError, match="psscan returned zero rows"):
        m3.detect(stub_vol(psscan=[]), allow_unverified=True)
    with pytest.raises(RuntimeError, match="psscan found 2 PIDs but pslist 3"):
        m3.detect(stub_vol(pslist=[{"PID": 1}, {"PID": 2}, {"PID": 3}], psscan=[{"PID": 1}, {"PID": 2}]),
                  allow_unverified=True)


def test_detect_refuses_too_many_non_numeric_pids(stub_vol):
    bad = [{"PID": 1}, {"PID": 2}, {"PID": "-"}, {"PID": "N/A"}, {"PID": 3}]  # 2 of 5 = 40%
    with pytest.raises(RuntimeError, match="psscan: 2 of 5"):
        m3.detect(stub_vol(psscan=bad), allow_unverified=True)
    with pytest.raises(RuntimeError, match="pslist: 2 of 5"):
        m3.detect(stub_vol(pslist=bad, psscan=bad), allow_unverified=True)
    ok = [{"PID": 1}, {"PID": 2}, {"PID": 3}, {"PID": 4}, {"PID": "-"}]  # exactly 20% is allowed
    assert m3.detect(stub_vol(psscan=ok), allow_unverified=True)["skipped_non_numeric_pid_rows"]["psscan"] == 1


def test_detect_records_empty_lsmod_without_failing(stub_vol):
    res = m3.detect(stub_vol(lsmod=[]), allow_unverified=True)
    assert res["lsmod_empty"] is True and res["lsmod_modules"] == []


def test_vol_version_is_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(m3.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("gone")))
    assert m3.vol_version("vol") is None
    monkeypatch.setattr(m3.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "usage"))
    assert m3.vol_version("vol") is None
    monkeypatch.setattr(m3.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", "Volatility 3 Framework 2.5.0\n"))
    assert m3.vol_version("vol") == "2.5.0"


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="needs POSIX bash")
@pytest.mark.parametrize("name, value", [("VOL_MEM_KB", "unlimited"), ("VOL_MEM_KB", ""), ("VOL_CPU_S", "-1"),
                                         ("VOL_NPROC", "99999999"), ("VOL_FSIZE_MB", "1e3")])
def test_sandbox_script_rejects_bad_limits(tmp_path, name, value):
    dump = tmp_path / "d.mem"
    dump.write_bytes(b"x")
    dump.chmod(0o444)
    r = subprocess.run(["bash", str(ROOT / "scripts" / "run_vol_sandboxed.sh"), str(dump), "/bin/true"],
                       env={**os.environ, name: value}, capture_output=True, text=True)
    assert r.returncode == 2 and name in r.stderr
