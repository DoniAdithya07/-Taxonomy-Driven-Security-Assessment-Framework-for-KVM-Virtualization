import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import make_fixtures as mf
from vsec import clean_text, collect, control_index, finding, m1_audit, score

XML_IDS = ("C11", "C12", "C13", "C14", "C15", "C22", "C27")
CONF_IDS = ("C03", "C05", "C07", "C08", "C19", "C20", "C28")
PERM_IDS = ("C17", "C18", "C21")
REAL_CVES = m1_audit.CVES_PATH  # the shipped list: every entry unverified


def write_cves(path, entries):
    path.write_text(yaml.safe_dump({"cves": entries}), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def verified_cves(tmp_path_factory, monkeypatch):
    """Logic tests run against a copy of the shipped CVE list with every entry verified (the real list is not)."""
    entries = [{**e, "verified": True} for e in m1_audit._cves(REAL_CVES)]
    path = write_cves(tmp_path_factory.mktemp("cves") / "verified.yaml", entries)
    monkeypatch.setattr(m1_audit, "CVES_PATH", path)
    return path


def write_case(d, settings=None, drop=(), override=None, crlf=False):
    d.mkdir(parents=True, exist_ok=True)
    files = {**mf.files_for(settings or {}, e0=False), **(override or {})}
    for fn, text in files.items():
        if fn not in drop:
            if crlf:
                text = text.replace("\n", "\r\n") + "\r\n"
            with open(d / fn, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
    return d


def st(d, env="E1"):
    return {f["id"]: f for f in m1_audit.audit(d, env=env)}


def status(d, cid, **kw):
    return st(d, **kw)[cid]["status"]


def test_every_m1_control_has_a_check_and_three_faults():
    m1_ids = {c for c, v in control_index().items() if v["module"] == "M1"}
    assert set(m1_audit.CHECKS) == m1_ids == set(mf.FAULTS)
    for cid, faults in mf.FAULTS.items():
        assert len({json.dumps(f, sort_keys=True) for f in faults}) >= 3, cid


def test_good_case_passes_everything(tmp_path):
    write_case(tmp_path)
    assert {f["status"] for f in m1_audit.audit(tmp_path, env="E1")} == {"PASS"}


def test_each_fault_is_caught_alone(tmp_path):
    for cid, faults in mf.FAULTS.items():
        for i, fault in enumerate(faults):
            d = write_case(tmp_path / f"{cid}_{i}", fault)
            res = {k: f["status"] for k, f in st(d).items()}
            assert res[cid] == "FAIL", (cid, fault)
            assert [k for k, v in res.items() if v == "FAIL"] == [cid], (cid, fault)  # no collateral FAILs


def test_missing_live_files_are_na(tmp_path):
    res = {k: f["status"] for k, f in st(tmp_path).items()}
    assert res["C02"] == res["C04"] == res["C06"] == res["C16"] == "NA"


def test_empty_case_folder_has_no_pass_at_all(tmp_path):
    assert {f["status"] for f in m1_audit.audit(tmp_path, env="E1")} == {"NA"}


def test_missing_folder_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        m1_audit.audit(tmp_path / "nope")


def test_empty_files_are_na(tmp_path):
    empty = {"vm.xml": " \n", "qemu.conf": "", "libvirtd.conf": "\n", "perms.txt": ""}
    d = write_case(tmp_path, override=empty)
    res = {k: f["status"] for k, f in st(d).items()}
    for cid in XML_IDS + CONF_IDS + PERM_IDS:
        assert res[cid] == "NA", cid


def test_malformed_and_oversized_xml_is_na(tmp_path):
    d = write_case(tmp_path / "a", override={"vm.xml": "<domain><devices>"})
    assert all(status(d, c) == "NA" for c in XML_IDS)
    d = write_case(tmp_path / "b", override={"vm.xml": "<domain>" + " " * 1_100_000 + "</domain>"})
    assert all(status(d, c) == "NA" for c in XML_IDS)


def test_malformed_iommu_groups_is_na_not_a_crash(tmp_path):
    d = write_case(tmp_path, override={"iommu_groups": "abc"})
    assert status(d, "C02") == "NA"


def test_e0_makes_iommu_na(tmp_path):
    d = write_case(tmp_path)
    assert status(d, "C02", env="E0") == "NA"
    assert status(d, "C02", env="E1") == "PASS"


def test_blank_qemu_version_is_na_and_cannot_capture_next_line(tmp_path):
    d = write_case(tmp_path, override={"versions.txt": "qemu \nkernel 6.8.0"})
    assert status(d, "C23") == "NA" and status(d, "C24") == "PASS"
    d = write_case(tmp_path / "u", override={"versions.txt": "qemu unknown\nkernel unknown"})
    assert status(d, "C23") == status(d, "C24") == "NA"


def test_cve_evidence_and_unlisted_product(tmp_path, monkeypatch):
    d = write_case(tmp_path)
    assert "checked against" in st(d)["C23"]["evidence"]
    monkeypatch.setattr(m1_audit, "_cves", lambda path=None: [])
    assert status(d, "C23") == "NA"


def test_every_shipped_cve_entry_is_marked_unverified():
    entries = m1_audit._cves(REAL_CVES)
    assert entries and all(e["verified"] is False for e in entries)


@pytest.mark.parametrize("versions", ["qemu 8.2.2\nkernel 6.8.0", "qemu 4.2.1\nkernel 5.4.0"])
def test_c23_c24_are_na_while_the_shipped_list_is_unverified(tmp_path, monkeypatch, versions):
    monkeypatch.setattr(m1_audit, "CVES_PATH", REAL_CVES)
    d = write_case(tmp_path, override={"versions.txt": versions})
    for cid in ("C23", "C24"):
        f = st(d)[cid]
        assert f["status"] == "NA" and "CVE entries are unverified: list not usable for results" in f["evidence"]
    assert "3 of 3 qemu" in st(d)["C23"]["evidence"] and "2 of 2 kernel" in st(d)["C24"]["evidence"]


def test_one_unverified_entry_is_enough_for_na(tmp_path):
    entries = [{"cve": "CVE-X", "product": "qemu", "fixed_in": "9.0.0", "verified": True},
               {"cve": "CVE-Y", "product": "qemu", "fixed_in": "5.0.0", "verified": False},
               {"cve": "CVE-Z", "product": "qemu", "fixed_in": "5.0.0"}]  # missing key counts as unverified
    cves = write_cves(tmp_path / "c.yaml", entries)
    d = write_case(tmp_path / "case")
    res = {f["id"]: f for f in m1_audit.audit(d, env="E1", cves_path=cves)}
    assert res["C23"]["status"] == "NA" and "2 of 3 qemu CVE entries are unverified" in res["C23"]["evidence"]


@pytest.mark.parametrize("cid,line", [
    ("C24", "kernel 6.1.0-18-amd64"), ("C24", "kernel 5.15.0-91-generic"), ("C24", "kernel 6.8.0-45"),
    ("C23", "qemu 1:8.2.2+dfsg-1ubuntu3"), ("C23", "qemu 8.2.2+ds"), ("C23", "qemu 8.0.0-rc1"),
])
def test_distro_versions_are_na_even_with_a_verified_list(tmp_path, cid, line):
    versions = f"{line}\nkernel 6.8.0" if cid == "C23" else f"qemu 8.2.2\n{line}"
    f = st(write_case(tmp_path, override={"versions.txt": versions}))[cid]
    assert f["status"] == "NA" and "distro version: backports ignored, use the distro tracker" in f["evidence"]


def test_plain_versions_with_a_verified_list_still_pass_and_fail(tmp_path):
    d = write_case(tmp_path / "a", override={"versions.txt": "qemu 8.2.2\nkernel 6.8.0"})
    assert status(d, "C23") == status(d, "C24") == "PASS"
    d = write_case(tmp_path / "b", override={"versions.txt": "qemu 5.0.0\nkernel 5.4.0"})
    assert status(d, "C23") == status(d, "C24") == "FAIL"
    d = write_case(tmp_path / "c", override={"versions.txt": "qemu 1:8.2.2\nkernel 6.8"})  # epoch alone is not a distro suffix
    assert status(d, "C23") == status(d, "C24") == "PASS"


def test_version_parsing_epoch_and_padding():
    assert m1_audit._ver("1:8.2.2+ds-1") == (8, 2, 2)
    assert m1_audit._ver("8.1") == (8, 1, 0) and m1_audit._ver("unknown") is None


def test_unset_key_in_existing_conf(tmp_path):
    d = write_case(tmp_path, override={"qemu.conf": "# only a comment"})
    s = st(d)
    for cid in ("C05", "C07"):
        assert s[cid]["status"] == "NA" and "key unset" in s[cid]["evidence"]
    for cid in ("C03", "C08", "C28"):
        assert s[cid]["status"] == "PASS" and "unset: libvirt default" in s[cid]["evidence"]
    d = write_case(tmp_path / "l", override={"libvirtd.conf": "# x"})
    s = st(d)
    assert s["C19"]["status"] == s["C20"]["status"] == "PASS" and "unset: libvirt default" in s["C19"]["evidence"]


@pytest.mark.parametrize("line,cid,want", [
    ("user = root", "C07", "FAIL"), ('user = "0"', "C07", "FAIL"), ('user = "root:root"', "C07", "FAIL"),
    ("user = 'root'", "C07", "FAIL"), ("user = qemu:kvm", "C07", "PASS"),
    ("user = '+0'", "C07", "FAIL"), ("user = 00", "C07", "FAIL"), ('user = "+0:root"', "C07", "FAIL"),
    ("user = 0x0", "C07", "FAIL"), ('user = "root:qemu"', "C07", "FAIL"), ("user = 107", "C07", "PASS"),
    ('security_driver = [ "selinux", "none" ]', "C05", "FAIL"), ('security_driver = [ "none", "apparmor" ]', "C05", "FAIL"),
    ("security_driver = []", "C05", "FAIL"), ('security_driver = ["apparmor"]', "C05", "PASS"),
    ("seccomp_sandbox = '0'", "C03", "FAIL"),
    ('security_driver = [ "selinux", "apparmor" ]', "C05", "PASS"),
    ('security_driver = [ "none" ]', "C05", "FAIL"), ('security_driver = "none"', "C05", "FAIL"),
])
def test_qemu_conf_parsing(tmp_path, line, cid, want):
    d = write_case(tmp_path, override={"qemu.conf": "# x\n" + line})
    assert status(d, cid) == want


@pytest.mark.parametrize("line,want", [
    ("unix_sock_rw_perms = 0662", "FAIL"), ("unix_sock_rw_perms = '0667'", "FAIL"),
    ("unix_sock_rw_perms = 0776", "FAIL"), ("unix_sock_rw_perms = 00777", "FAIL"),
    ('unix_sock_rw_perms = "0770"', "PASS"), ("unix_sock_rw_perms = 0660", "PASS"),
    ("unix_sock_rw_perms = banana", "NA"),
])
def test_c19_octal_other_write(tmp_path, line, want):
    d = write_case(tmp_path, override={"libvirtd.conf": "# x\n" + line})
    assert status(d, "C19") == want


def test_c20_single_quoted_none_fails(tmp_path):
    d = write_case(tmp_path, override={"libvirtd.conf": "listen_tcp = 1\nauth_tcp = 'none'"})
    assert status(d, "C20") == "FAIL"


@pytest.mark.parametrize("cmdline,want", [
    ("ro intel_iommu=on iommu=pt", "PASS"), ("ro amd_iommu=on", "PASS"), ("ro intel_iommu=on,sm_on", "PASS"),
    ("ro nointel_iommu=on", "FAIL"), ("ro intel_iommu=off iommu=pt", "FAIL"), ("ro iommu=pt", "FAIL"),
    ("ro intel_iommu=on intel_iommu=off", "FAIL"),
])
def test_c01_whole_word_tokens(tmp_path, cmdline, want):
    d = write_case(tmp_path, override={"cmdline": cmdline})
    assert status(d, "C01") == want


def xml_case(tmp_path, devices):
    return write_case(tmp_path, override={"vm.xml": f"<domain><devices>{devices}</devices></domain>"})


@pytest.mark.parametrize("graphics,cid,want", [
    ("<graphics type='vnc' passwd='x' socket='/run/vnc.sock'/>", "C12", "PASS"),
    ("<graphics type='vnc' passwd='x'><listen type='socket' socket='/run/v.sock'/></graphics>", "C12", "PASS"),
    ("<graphics type='vnc' passwd='x'/>", "C12", "PASS"),
    ("<graphics type='vnc' passwd='x' listen='127.0.0.2'/>", "C12", "PASS"),
    ("<graphics type='spice' passwd='x'><listen type='address' address='::1'/></graphics>", "C12", "PASS"),
    ("<graphics type='vnc' passwd='x' listen='0.0.0.0'/>", "C12", "FAIL"),
    ("<graphics type='vnc' passwd='x'><listen type='address' address='10.0.0.5'/></graphics>", "C12", "FAIL"),
    ("<graphics type='rdp'/>", "C11", "FAIL"), ("<graphics type='rdp' passwd='x'/>", "C11", "PASS"),
])
def test_graphics_checks(tmp_path, graphics, cid, want):
    assert status(xml_case(tmp_path, graphics), cid) == want


def test_interfaces_and_cache(tmp_path):
    assert status(xml_case(tmp_path / "a", "<interface type='direct'><source dev='eth0'/></interface>"), "C15") == "FAIL"
    assert status(xml_case(tmp_path / "b", "<interface type='user'/>"), "C15") == "PASS"
    assert status(xml_case(tmp_path / "c", "<disk><driver cache='UNSAFE'/></disk>"), "C22") == "FAIL"


def c16(tmp_path, host, scan):
    d = write_case(tmp_path, drop=("net_scan.txt", "net_isolation.txt"))
    for name, text in (("net_isolation.txt", host), ("net_scan.txt", scan)):
        if text is not None:
            (d / name).write_bytes(text.encode("utf-8"))  # exact bytes: no newline translation
    return st(d)["C16"]


@pytest.mark.parametrize("host,scan,want,ev", [
    ("isolated", "isolated: 0 open ports", "PASS", "host-verified (guest scan: isolated: 0 open ports)"),
    ("isolated", None, "PASS", "host-verified"),
    ("isolated", "timeout", "PASS", "guest scan: timeout"),
    ("isolated\r\n", None, "PASS", "host-verified"),  # CRLF
    ("isolated\n\n", None, "PASS", "host-verified"),
    ("Isolated", None, "NA", "unrecognised"),  # exactly `isolated`, lower case
    ("isolated: yes", None, "NA", "unrecognised"),
    ("﻿isolated", None, "NA", "unrecognised"),  # BOM
    ("garbage", "isolated: 0 open ports", "NA", "unrecognised"),
    ("not-isolated: network default has <forward>", "isolated: 0 open ports", "FAIL", "host: not-isolated"),
    ("isolated\nnot-isolated: bridge", None, "FAIL", "host: not-isolated: bridge"),  # a later line still fails
    ("unknown: x\nnot-isolated: y", None, "FAIL", "host: not-isolated: y"),
    ("unknown: cannot read network", None, "NA", "could not verify"),
    ("unknown: cannot read network", "isolated: 0 open ports", "NA", "could not verify"),
    ("isolated\nunknown: later", None, "NA", "'unknown' line after 'isolated'"),
    ("isolated", "reachable: 22/tcp open", "FAIL", "guest scan: reachable"),
    ("isolated", "Reachable: icmp reply", "FAIL", "guest scan"),
    ("isolated", "ping: host is unreachable", "PASS", "host-verified"),  # not the whole word 'reachable'
    ("isolated", "UNREACHABLE", "PASS", "host-verified"),
    ("isolated", "target not reachable", "PASS", "host-verified"),
    ("isolated", "target not-reachable", "PASS", "host-verified"),
    ("not-isolated: x", "reachable: 80/tcp open", "FAIL", "host: not-isolated: x; guest scan: reachable"),
    (None, "isolated: 0 open ports", "NA", "guest-attested only, not proof"),  # a guest scan never gives PASS
    (None, "timeout", "NA", "guest-attested only, not proof"),
    (None, "unreachable", "NA", "guest-attested only, not proof"),
    (None, "reachable: 22/tcp open", "FAIL", "guest scan"),
    (None, None, "NA", ""),
])
def test_c16_host_file_is_the_proof(tmp_path, host, scan, want, ev):
    f = c16(tmp_path, host, scan)
    assert f["status"] == want and ev in f["evidence"]


def test_c16_control_characters_never_reach_the_evidence(tmp_path):
    f = c16(tmp_path, "isolated", "\x1b[31m reachable\x1b[0m: 22/tcp\r\nsecond\x07 line")
    assert f["status"] == "FAIL" and "reachable" in f["evidence"]
    assert not any(ord(ch) < 32 or 127 <= ord(ch) < 160 for ch in f["evidence"])
    assert clean_text("a\x1b[2Jb\0c\rd\te\nf\x85g") == "a[2Jbcd e fg"
    assert finding("C01", "NA", "x\x1by")["evidence"] == "xy"


@pytest.mark.parametrize("label,want", [
    ("libvirt-1234 (enforce)", "PASS"), ("not enforcing", "FAIL"), ("unconfined", "FAIL"),
    ("system_u:system_r:svirt_t:s0:c1,c2", "PASS"),
])
def test_c06_needs_real_enforce(tmp_path, label, want):
    assert status(write_case(tmp_path, override={"qemu_label": label}), "C06") == want


def test_nul_bytes_are_stripped_on_read(tmp_path):
    d = write_case(tmp_path, override={"qemu_label": "libvirt-1234 (enforce)\0"})
    f = st(d)["C06"]
    assert f["status"] == "PASS" and "\0" not in f["evidence"]
    assert m1_audit.Case(d).read("qemu_label") == "libvirt-1234 (enforce)"


def test_vulns_and_smt(tmp_path):
    d = write_case(tmp_path / "a", override={"vulns.txt": "mds: VULNERABLE: clear"})
    assert status(d, "C25") == "FAIL"
    d = write_case(tmp_path / "b", override={"vulns.txt": "garbage without colon"})
    assert status(d, "C25") == status(d, "C26") == "NA"
    d = write_case(tmp_path / "c", override={"smt": "forceon"})
    assert status(d, "C26") == "FAIL"
    d = write_case(tmp_path / "d", override={"smt": "notsupported"})
    assert status(d, "C26") == "PASS"
    d = write_case(tmp_path / "e", drop=("smt",))
    assert status(d, "C26") == "NA"
    d = write_case(tmp_path / "f", override={"smt": "weird"})
    assert status(d, "C26") == "NA"


def test_perms_format_and_na_rules(tmp_path):
    d = write_case(tmp_path / "a", override={"perms.txt": "image 600 0 0 /var/lib/libvirt/images/a b.qcow2"})
    s = st(d)
    assert s["C17"]["status"] == "PASS" and s["C18"]["status"] == s["C21"]["status"] == "NA"
    d = write_case(tmp_path / "b", override={"perms.txt": "image 666 0 0 /var/lib/images/a b.qcow2"})
    assert "a b.qcow2" in st(d)["C17"]["evidence"] and status(d, "C17") == "FAIL"
    d = write_case(tmp_path / "c", override={"perms.txt": "image /old/format 666 0 0"})  # legacy row: ignored
    assert status(d, "C17") == "NA"
    d = write_case(tmp_path / "d", override={"perms.txt": "socket 777 0 0 /run/libvirt/libvirt-sock-ro"})
    assert status(d, "C18") == "NA"
    d = write_case(tmp_path / "e", override={"perms.txt": "socket 777 0 0 /run/libvirt/libvirt-sock-ro\n"
                                                         "socket 666 0 0 /run/libvirt/libvirt-sock"})
    assert status(d, "C18") == "FAIL"


def test_crashing_check_is_na(tmp_path, monkeypatch):
    def boom(c):
        raise RuntimeError("kaput")
    monkeypatch.setitem(m1_audit.CHECKS, "C01", boom)
    f = st(write_case(tmp_path))["C01"]
    assert f["status"] == "NA" and f["evidence"] == "check error: kaput"


def test_finding_rejects_bad_status():
    with pytest.raises(ValueError):
        finding("C01", "MAYBE")


def test_fixture_set(fixtures):
    key = json.loads((fixtures / "answer_key.json").read_text())
    assert len(key) == 50
    for cid in mf.FAULTS:
        if cid != "C02":
            assert sum(t[cid] == "FAIL" for t in key.values()) >= 3, cid
    cves = fixtures / mf.CVES_FIXTURE
    pred = {c: {f["id"]: f["status"] for f in m1_audit.audit(fixtures / c, env="E1", cves_path=cves)} for c in key}
    o = score.score_m1(pred, key)["overall"]
    assert o["recall"] == 1.0 and o["fp"] == 0
    assert o["na_on_pass"] == 0 and o["na_violations"] == 0


def test_fixture_cves_file_is_verified_and_the_real_list_is_not_touched(fixtures):
    fixture = m1_audit._cves(fixtures / mf.CVES_FIXTURE)
    assert fixture and all(e["verified"] is True for e in fixture)
    assert all(e["verified"] is False for e in m1_audit._cves(REAL_CVES))
    na = {f["id"] for f in m1_audit.audit(fixtures / "case10", env="E1", cves_path=REAL_CVES) if f["status"] == "NA"}
    assert na == {"C23", "C24"}  # with the real list only the version checks lose their verdict


def test_fixture_files_are_written_with_lf_except_the_crlf_case(fixtures):
    assert mf.CRLF_CASE == 49
    for case in sorted(p for p in fixtures.iterdir() if p.is_dir()):
        for f in case.iterdir():
            raw = f.read_bytes()
            assert (b"\r\n" in raw) == (case.name == "case49"), f
            assert not raw.startswith(b"\xef\xbb\xbf")  # no BOM anywhere


def test_checkers_handle_crlf_files(tmp_path):
    """Every control: the good case passes and each seeded fault is caught alone with CRLF line endings."""
    d = write_case(tmp_path / "good", crlf=True)
    assert all(b"\r\n" in f.read_bytes() for f in d.iterdir())
    assert {f["status"] for f in m1_audit.audit(d, env="E1")} == {"PASS"}
    for cid, faults in mf.FAULTS.items():
        for i, fault in enumerate(faults):
            res = {k: f["status"] for k, f in st(write_case(tmp_path / f"{cid}_{i}", fault, crlf=True)).items()}
            assert [k for k, v in res.items() if v == "FAIL"] == [cid], (cid, fault)


def test_case_read_refuses_symlinks_so_nothing_leaks(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-HOST-DATA")
    d = write_case(tmp_path / "case", drop=("ksm_run",))
    make_symlink(d / "ksm_run", secret)
    assert m1_audit.Case(d).read("ksm_run") is None
    f = st(d)["C09"]
    assert f["status"] == "NA" and "SECRET" not in f["evidence"]
    assert m1_audit.Case(d).read("cmdline")  # regular files still work


def test_case_read_is_symlink_check_without_real_symlinks(tmp_path, monkeypatch):
    """Where symlinks cannot be created (unprivileged Windows) the is_symlink guard (Windows has no O_NOFOLLOW)
    is still exercised with a stand-in."""
    d = write_case(tmp_path / "case")
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "ksm_run")
    assert m1_audit.Case(d).read("ksm_run") is None and m1_audit.Case(d).read("nested")


def test_case_read_refuses_directories_and_missing_files(tmp_path):
    d = write_case(tmp_path / "case", drop=("nested",))
    (d / "nested").mkdir()
    case = m1_audit.Case(d)
    assert case.read("nested") is None and case.read("missing") is None
    assert st(d)["C10"]["status"] == "NA"


def test_baseline_confs_are_non_empty(fixtures):
    for case in ("case10", "case30"):
        for fn in ("qemu.conf", "libvirtd.conf"):
            assert (fixtures / case / fn).read_text().startswith("# vsec fixture")


# ---- collect.py (the parts that run anywhere) ----
@pytest.mark.parametrize("bad", ["", "-x", "a b", "a;rm", "../x", "a/b"])
def test_collect_rejects_bad_vm_name(tmp_path, bad):
    with pytest.raises(ValueError):
        collect.collect(bad, tmp_path / "o")


def test_collect_fails_loudly_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(collect, "virsh_dumpxml", lambda vm: (_ for _ in ()).throw(RuntimeError("virsh failed")))
    with pytest.raises(RuntimeError):
        collect.collect("vm1", tmp_path / "o", allow_anywhere=True)  # works with any pytest basetemp
    assert not (tmp_path / "o").exists()


def test_collect_refuses_non_empty_out_dir(tmp_path):
    (tmp_path / "x").write_text("1")
    with pytest.raises(FileExistsError):
        collect.collect("vm1", tmp_path, allow_anywhere=True)


def test_mode_row_format_and_unreadable(tmp_path):
    p = tmp_path / "a b"
    p.write_text("x")
    row = collect.mode_row("image", str(p)).split(None, 4)
    assert row[0] == "image" and row[4] == str(p) and row[1].isdigit()
    assert collect.mode_row("image", str(tmp_path / "gone")) is None
    assert collect.read_file(str(tmp_path / "gone")) is None


def fake_virsh(monkeypatch, vm_xml, networks=None):
    monkeypatch.setattr(collect, "virsh_dumpxml", lambda vm: vm_xml)
    nets = networks or {}

    def net(name):
        if name not in nets:
            raise RuntimeError("no such network")
        return nets[name]
    monkeypatch.setattr(collect, "virsh_net_dumpxml", net)


NIC = "<interface type='network'><source network='iso'/></interface>"
VM = "<domain><devices><graphics type='vnc' passwd='hunter2' listen='127.0.0.1'/>" + NIC + "</devices></domain>"
ISO_NET = "<network><name>iso</name></network>"


def test_collect_end_to_end_redacts_and_writes_host_isolation(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, VM, {"iso": ISO_NET})
    out = collect.collect("vm1", tmp_path / "case", allow_anywhere=True)
    xml = (out / "vm.xml").read_text()
    assert "hunter2" not in xml and "passwd='REDACTED'" in xml
    assert (out / "net_isolation.txt").read_text() == "isolated"
    assert status(out, "C11") == "PASS" and status(out, "C16") == "PASS"  # a password still exists; host-verified


@pytest.mark.parametrize("nets,vm_xml,verdict,reason", [
    ({"iso": "<network><forward mode='nat'/></network>"}, VM, "not-isolated", "has <forward"),
    ({}, VM, "unknown", "cannot read network iso"),  # cannot be read is unknown, never a verdict
    ({"iso": ISO_NET}, VM.replace(NIC, NIC + "<interface type='bridge'><source bridge='br0'/></interface>"),
     "not-isolated", "interface type bridge"),
    ({}, "<domain><devices/></domain>", "isolated", ""),  # no NIC and no other exit
    ({}, "<domain>", "unknown", "unparseable"),
    ({}, VM.replace("network='iso'", "network='-x'"), "not-isolated", "bad network name"),
])
def test_net_isolation_reasons(monkeypatch, nets, vm_xml, verdict, reason):
    fake_virsh(monkeypatch, vm_xml, nets)
    got = collect.net_isolation(vm_xml)
    assert (got == "isolated" if verdict == "isolated" else got.startswith(f"{verdict}: ")) and reason in got


def test_net_isolation_checks_every_network(monkeypatch):
    two = "<domain>" + NIC + "<interface type='network'><source network='nat'/></interface></domain>"
    fake_virsh(monkeypatch, two, {"iso": ISO_NET, "nat": "<network><forward mode='nat'/></network>"})
    assert "network nat" in collect.net_isolation(two)


def test_collect_refuses_output_outside_cases_and_local(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, VM, {"iso": ISO_NET})
    outside = collect.ROOT.parent / "vsec_outside_test"
    with pytest.raises(ValueError, match="must be inside"):
        collect.collect("vm1", outside)
    assert not outside.exists()
    with pytest.raises(ValueError, match="must be inside"):
        collect.collect("vm1", collect.ROOT / "cases" / ".." / ".." / "vsec_outside_test")
    monkeypatch.setattr(collect, "ALLOWED_OUT", ())  # pretend tmp is outside, then use the explicit override
    with pytest.raises(ValueError, match="must be inside"):
        collect.collect("vm1", tmp_path / "a")
    assert (collect.collect("vm1", tmp_path / "a", allow_anywhere=True) / "vm.xml").exists()


def make_symlink(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")


def test_collect_rejects_symlinked_out_path(tmp_path, monkeypatch):
    fake_virsh(monkeypatch, VM, {"iso": ISO_NET})
    (tmp_path / "real").mkdir()
    make_symlink(tmp_path / "link", tmp_path / "real")
    with pytest.raises(ValueError, match="symlink"):
        collect.collect("vm1", tmp_path / "link", allow_anywhere=True)
    assert not any((tmp_path / "real").iterdir())


def test_read_file_and_mode_row_do_not_follow_symlinks(tmp_path):
    (tmp_path / "t").write_text("secret")
    make_symlink(tmp_path / "l", tmp_path / "t")
    assert collect.read_file(str(tmp_path / "t")) == b"secret"
    assert collect.mode_row("image", str(tmp_path / "l")) is None  # lstat: the link itself is skipped
    if hasattr(os, "O_NOFOLLOW"):  # POSIX only; Windows has no O_NOFOLLOW
        assert collect.read_file(str(tmp_path / "l")) is None


def test_read_file_strips_nul_and_refuses_directories(tmp_path):
    (tmp_path / "label").write_bytes(b"libvirt-1 (enforce)\0")
    assert collect.read_file(str(tmp_path / "label")) == b"libvirt-1 (enforce)"
    assert collect.read_file(str(tmp_path)) is None


def test_redact_xml_hides_values_but_keeps_presence():
    out = collect.redact_xml("<graphics type='vnc' passwd='hunter2'/><graphics type='spice' passwd=\"p w\" />"
                             "<graphics type='vnc' passwd=''/>")
    assert "hunter2" not in out and "p w" not in out
    assert out.count("REDACTED") == 2 and "passwd=''" in out  # an empty password stays visibly empty


def test_redact_conf_keeps_key_replaces_value():
    out = collect.redact_conf("# vnc_password = \"commented\"\nvnc_password = \"abc\"\n  spice_password='x y'  # c\nuser = \"q\"")
    assert "abc" not in out and "x y" not in out
    assert 'vnc_password = "REDACTED"' in out and 'spice_password="REDACTED"' in out
    assert '# vnc_password = "REDACTED"' in out and "commented" not in out  # a commented-out secret is still a secret
    assert 'user = "q"' in out


def test_collect_nested_is_y_if_any_kvm_module_is_y(tmp_path, monkeypatch):
    paths = []
    for mod, val in (("kvm_amd", "N"), ("kvm_intel", "Y\n")):
        f = tmp_path / mod
        f.write_text(val)
        paths.append(str(f))
    # patch the module-level name in collect, not the stdlib glob module (that would leak into other code)
    monkeypatch.setattr(collect, "glob", SimpleNamespace(glob=lambda pat: paths))
    assert collect._nested_value() == "Y"
    for f in paths:
        Path(f).write_text("0")
    assert collect._nested_value() == "0"
    monkeypatch.setattr(collect, "glob", SimpleNamespace(glob=lambda pat: []))
    assert collect._nested_value() == ""


# ---- qemu distro banner, numeric fixed_in, C16 evidence ----
@pytest.mark.parametrize("line", [
    "qemu 7.2.9 (Debian 1:7.2.9+dfsg-0+deb12u1)", "qemu 8.2.2 (Ubuntu 1:8.2.2+ds-0ubuntu1)",
    "qemu 7.2.9 (1:7.2.9+dfsg-0+deb12u1)", "qemu 8.2.2 (deb12u3)", "qemu 8.2.2 (ubuntu)", "qemu 8.2.2 (Debian)",
])
def test_c23_is_na_for_a_distro_banner_even_with_a_verified_list(tmp_path, line):
    f = st(write_case(tmp_path, override={"versions.txt": f"{line}\nkernel 6.8.0"}))["C23"]
    assert f["status"] == "NA" and "distro version: backports ignored" in f["evidence"]


@pytest.mark.parametrize("line", ["qemu 8.2.2", "qemu 8.2.2 (v8.2.2)", "qemu 1:8.2.2"])
def test_c23_still_passes_for_an_upstream_build(tmp_path, line):
    assert status(write_case(tmp_path, override={"versions.txt": f"{line}\nkernel 6.8.0"}), "C23") == "PASS"


def test_a_numeric_fixed_in_does_not_crash_and_is_called_out(tmp_path):
    entries = [{"cve": "CVE-N", "product": "qemu", "fixed_in": 8.1, "verified": True},
               {"cve": "CVE-M", "product": "qemu", "fixed_in": 9, "verified": True}]
    cves = write_cves(tmp_path / "c.yaml", entries)
    assert isinstance(m1_audit._cves(cves)[0]["fixed_in"], float)  # YAML really parses it as a number
    d = write_case(tmp_path / "a", override={"versions.txt": "qemu 8.0.0\nkernel 6.8.0"})
    f = {x["id"]: x for x in m1_audit.audit(d, env="E1", cves_path=cves)}["C23"]
    assert f["status"] == "FAIL" and "CVE-N" in f["evidence"] and "CVE-M" in f["evidence"]
    assert "check error" not in f["evidence"] and "['CVE-N', 'CVE-M'] are not strings" in f["evidence"]
    d = write_case(tmp_path / "b", override={"versions.txt": "qemu 9.0.0\nkernel 6.8.0"})
    f = {x["id"]: x for x in m1_audit.audit(d, env="E1", cves_path=cves)}["C23"]
    assert f["status"] == "PASS" and "not strings" in f["evidence"]


def test_an_unparseable_fixed_in_is_na_not_a_crash(tmp_path):
    cves = write_cves(tmp_path / "c.yaml", [{"cve": "CVE-X", "product": "qemu", "fixed_in": "soon", "verified": True}])
    f = {x["id"]: x for x in m1_audit.audit(write_case(tmp_path / "a"), env="E1", cves_path=cves)}["C23"]
    assert f["status"] == "NA" and "CVE-X" in f["evidence"] and "check error" not in f["evidence"]


def test_c16_evidence_shows_every_scan_line_so_the_failing_one_is_visible(tmp_path):
    f = c16(tmp_path, "isolated", "unreachable\nreachable: 80/tcp open")
    assert f["status"] == "FAIL" and "unreachable | reachable: 80/tcp open" in f["evidence"]
    f = c16(tmp_path / "x", "isolated", "\n".join(f"line{i} " + "x" * 40 for i in range(20)) + "\nreachable: 1/tcp")
    assert f["status"] == "FAIL" and "line0" in f["evidence"] and len(f["evidence"]) < 300  # capped
    f = c16(tmp_path / "y", "isolated", "ok\n\x1b[31m reachable\x1b[0m: 22\x07/tcp")
    assert f["status"] == "FAIL" and not any(ord(ch) < 32 or 127 <= ord(ch) < 160 for ch in f["evidence"])


@pytest.mark.parametrize("host", ["isolated\n  not-isolated: x", "isolated\n\tnot-isolated: x", "isolated\r\n   not-isolated: x\r\n"])
def test_an_indented_not_isolated_line_still_counts(tmp_path, host):
    f = c16(tmp_path, host, None)
    assert f["status"] == "FAIL" and "not-isolated: x" in f["evidence"]
