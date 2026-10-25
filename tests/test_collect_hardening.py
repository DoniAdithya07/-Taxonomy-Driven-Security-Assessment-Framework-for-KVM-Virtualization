"""collect.py hardening: redaction forms and fail-closed verifier, manifest, cleanup on failure, missing virsh,
host-side net_isolation texts."""
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from vsec import collect

ROOT = Path(__file__).resolve().parent.parent
QEMU_NS = "xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'"
NIC = "<interface type='network'><source network='iso'/><link state='down'/></interface>"
ISO_NET = "<network><name>iso</name></network>"


def dom(devices="", extra="", attrs=""):
    return f"<domain type='kvm' {attrs}><name>vm1</name><devices>{devices}{NIC}</devices>{extra}</domain>"


def fake_virsh(monkeypatch, vm_xml, networks=None):
    monkeypatch.setattr(collect, "virsh_dumpxml", lambda vm: vm_xml)
    nets = {"iso": ISO_NET} if networks is None else networks

    def net(name):
        if name not in nets:
            raise RuntimeError("no such network")
        return nets[name]
    monkeypatch.setattr(collect, "virsh_net_dumpxml", net)


# ---- redaction forms ----
@pytest.mark.parametrize("devices, secret", [
    ("<graphics type='vnc' passwd='hunter2secret'/>", "hunter2secret"),
    ('<graphics type="vnc" passwd="hunter2secret"/>', "hunter2secret"),
    ("<graphics type='vnc' passwd=\"it's-a-secret\"/>", "it's-a-secret"),
    ("<graphics type='vnc' passwd='a&amp;b&quot;secret1'/>", "secret1"),
    ("<graphics type='vnc' passwd='line1&#10;secretline2'/>", "secretline2"),
    ("<graphics type='vnc' passwd='line1\nsecretline2'/>", "secretline2"),
    ("<graphics type='vnc'\n   passwd\n =\n 'multi-line-secret'/>", "multi-line-secret"),
    ("<graphics type='vnc'><passwd>element-secret</passwd></graphics>", "element-secret"),
    ("<graphics type='vnc'><password>element-secret</password></graphics>", "element-secret"),
    ("<graphics type='vnc'><passwd><![CDATA[cdata<secret>]]></passwd></graphics>", "cdata<secret>"),
    ("<disk><auth username='u'><secret type='ceph' uuid='x'>sec-in-text</secret></auth></disk>", "sec-in-text"),
    ("<encryption format='luks'><secret type='passphrase' secret='attr-secret1'/></encryption>", "attr-secret1"),
    ("<graphics type='vnc' PASSWD='upper-secret'/>", "upper-secret"),
])
def test_redaction_forms_leave_no_original_value(devices, secret):
    xml = dom(devices)
    out, bad = collect.redact_checked(xml, "xml")
    assert bad is None and secret not in out
    assert "REDACTED" in out
    ET.fromstring(out)  # still well-formed, so M1 can parse it


def test_qemu_arg_password_and_secret_object_are_redacted():
    extra = ("<qemu:commandline><qemu:arg value='-vnc'/><qemu:arg value=':1,password=vncsecret1,websocket=5700'/>"
             "<qemu:arg value='-object'/><qemu:arg value='secret,id=sec0,data=objsecret99'/>"
             "<qemu:arg value='-cpu'/><qemu:arg value='host,data=keepme'/></qemu:commandline>")
    out, bad = collect.redact_checked(dom(extra=extra, attrs=QEMU_NS), "xml")
    assert bad is None and "vncsecret1" not in out and "objsecret99" not in out
    assert "password=REDACTED,websocket=5700" in out and "secret,id=sec0,data=REDACTED" in out
    assert "host,data=keepme" in out  # data= outside a secret object is not touched


def test_empty_password_stays_visibly_empty_and_key_is_kept():
    out = collect.redact_xml("<graphics passwd=''/><graphics passwd='x1y2z3'/>")
    assert "passwd=''" in out and "passwd='REDACTED'" in out


def test_self_closing_secret_element_does_not_swallow_the_document():
    xml = dom("<disk><auth><secret type='ceph' usage='k'/></auth></disk><graphics passwd='pw-longer'/>"
              "<secret>text-secret</secret>")
    out, bad = collect.redact_checked(xml, "xml")
    assert bad is None and "<disk>" in out and "usage='k'" in out and "text-secret" not in out and "pw-longer" not in out


def test_unparseable_xml_falls_back_to_regex_redaction():
    broken = "<domain><graphics passwd='hunter2-x' <<oops>\n<graphics passwd=\"two words\"/>"
    out, bad = collect.redact_checked(broken, "xml")
    assert bad is None and "hunter2-x" not in out and "two words" not in out and out.count("REDACTED") == 2


def test_verifier_fails_closed_when_the_redactor_leaks(monkeypatch):
    monkeypatch.setattr(collect, "redact_xml", lambda text: text)  # a broken redactor
    assert collect.redact_checked(dom("<graphics passwd='hunter2-x'/>"), "xml") == (None, "redaction failed")
    monkeypatch.setattr(collect, "redact_xml", lambda text: text.replace("hunter2-x", "hunter2-x ").replace("passwd", "passwd"))
    assert collect.redact_checked(dom("<graphics passwd='hunter2-x'/>"), "xml")[0] is None
    monkeypatch.setattr(collect, "redact_conf", lambda text: text)
    assert collect.redact_checked('vnc_password = "abc12345"\n', "conf") == (None, "redaction failed")


def test_verifier_catches_a_value_that_survives_only_in_decoded_form(monkeypatch):
    monkeypatch.setattr(collect, "redact_xml", lambda text: text.replace("passwd='hunter&amp;two'", "passwd='REDACTED'")
                        + "<!-- hunter&amp;two -->")
    assert collect.redact_checked(dom("<graphics passwd='hunter&amp;two'/>"), "xml")[0] is None


def test_redactor_exception_also_fails_closed(monkeypatch):
    monkeypatch.setattr(collect, "redact_xml", lambda text: (_ for _ in ()).throw(RecursionError()))
    assert collect.redact_checked(dom("<graphics passwd='x1y2z3'/>"), "xml") == (None, "redaction failed (RecursionError)")


@pytest.mark.parametrize("line", ['vnc_password = "abc12345"', "  spice_password='x y z w'  # c", '# vnc_password = "commented1"',
                                  '#vnc_password="commented2"', "\t#  spice_password = bare-secret-9"])
def test_conf_password_lines_incl_commented_are_redacted(line):
    out, bad = collect.redact_checked(f"user = \"q\"\n{line}\nvnc_tls_x509_secure = 1\n", "conf")
    assert bad is None and "REDACTED" in out
    for value in ("abc12345", "x y z w", "commented1", "commented2", "bare-secret-9"):
        assert value not in out
    assert 'user = "q"' in out and "vnc_tls_x509_secure = 1" in out  # only password lines change


def args_xml(*values, env=()):
    """A <qemu:commandline> with one <qemu:arg> per value (raw, already XML-escaped) and <qemu:env name value> pairs."""
    body = "".join(f"<qemu:arg value='{v}'/>" for v in values)
    body += "".join(f"<qemu:env name='{n}' value='{v}'/>" for n, v in env)
    return f"<qemu:commandline>{body}</qemu:commandline>"


def redact_args(*values, env=()):
    return collect.redact_checked(dom(extra=args_xml(*values, env=env), attrs=QEMU_NS), "xml")


def test_doubled_commas_inside_a_qemu_option_value_do_not_cut_the_redaction_short():
    out, bad = redact_args(":1,password=ab,,cd1234,websocket=5700", "secret,id=s0,data=aa,,bbsecret7,format=raw")
    assert bad is None
    assert "cd1234" not in out and "bbsecret7" not in out and "aa,,bb" not in out
    assert "password=REDACTED,websocket=5700" in out and "data=REDACTED,format=raw" in out


@pytest.mark.parametrize("value, leaked", [
    ("-object secret,id=a,data=x,,y-leak1", "y-leak1"),
    (":1,vnc-password=hunter2pw", "hunter2pw"),
    (":1,Password=MixedCase99", "MixedCase99"),
    ("id=tok,token=tok-leak55,x=1", "tok-leak55"),
    ("&#112;assword=entity-leak1", "entity-leak1"),  # the keyword itself is entity-encoded
    ("x>password=gt-leak99", "gt-leak99"),  # an unescaped '>' inside the attribute must not end the tag early
    ("key secret-thing: free-form-leak9", "free-form-leak9"),  # not option syntax: the whole value goes
])
def test_every_qemu_arg_value_with_a_secret_word_is_redacted(value, leaked):
    out, bad = redact_args(value)
    assert bad is None and leaked not in out and "REDACTED" in out
    ET.fromstring(out)


def test_qemu_arg_without_a_secret_word_is_untouched():
    out, bad = redact_args("-cpu", "host,data=keepme,x=1")
    assert bad is None and "host,data=keepme,x=1" in out and "REDACTED" not in out


def test_qemu_env_value_is_redacted_when_the_name_or_the_value_says_secret():
    out, bad = redact_args(env=[("VNC_PASSWORD", "env-leak11"), ("SPICE_TOKEN", "env-leak22"),
                                ("PLAIN", "password=env-leak33"), ("HOME", "/root"), ("EMPTY_SECRET", "")])
    assert bad is None
    assert not any(x in out for x in ("env-leak11", "env-leak22", "env-leak33"))
    assert "name='HOME' value='/root'" in out and "name='EMPTY_SECRET' value=''" in out
    assert out.count("REDACTED") == 3


def test_independent_detector_drops_an_arg_the_redactor_left_alone(monkeypatch):
    monkeypatch.setattr(collect, "redact_xml", lambda text: text)
    for xml in (dom(extra=args_xml(":1,password=leakyleaky"), attrs=QEMU_NS),
                dom(extra=args_xml(env=[("DB_TOKEN", "leaky-value1")]), attrs=QEMU_NS),
                dom(extra=args_xml("secret,id=s,data=leaky-data9"), attrs=QEMU_NS)):
        assert collect.redact_checked(xml, "xml") == (None, "redaction failed")


def test_detector_drops_a_value_cut_at_a_doubled_comma(monkeypatch):
    # the old tokenizer stopped at ',,': the tail of the secret stays behind the REDACTED marker
    monkeypatch.setattr(collect, "redact_xml", lambda text: text.replace("password=ab,,cdtail9", "password=REDACTED,,cdtail9"))
    assert collect.redact_checked(dom(extra=args_xml(":1,password=ab,,cdtail9"), attrs=QEMU_NS), "xml") == (
        None, "redaction failed")


@pytest.mark.parametrize("line", ['## vnc_password = "dbl-hash1"', 'listen = 1 # vnc_password = "midline2"',
                                  '#### spice_password=hash4-x', "x vnc_password='single3' # c", "VNC_PASSWORD = upper-case5"])
def test_conf_password_keys_are_found_after_extra_hashes_and_mid_line(line):
    out, bad = collect.redact_checked(f"user = \"q\"\n{line}\n", "conf")
    assert bad is None and "REDACTED" in out and 'user = "q"' in out
    for value in ("dbl-hash1", "midline2", "hash4-x", "single3", "upper-case5"):
        assert value not in out


@pytest.mark.parametrize("text, leaked", [
    ("root=/dev/vda ro vnc.password=cmd-leak1 quiet", "cmd-leak1"),
    ("a=1 api_token=cmd-leak2,,tail5 b=2", "tail5"),
    ("secret: cmd-leak3", "cmd-leak3"),
    ('"passwd": "json-leak4"', "json-leak4"),
    ("auth_token = 'conf-leak6'", "conf-leak6"),
])
def test_cmdline_and_libvirtd_conf_get_key_value_redaction_too(text, leaked):
    out, bad = collect.redact_checked(text + "\nkeep = 1\n", "conf")
    assert bad is None and leaked not in out and "REDACTED" in out and "keep = 1" in out


def test_conf_verifier_is_independent_of_the_redactor(monkeypatch):
    monkeypatch.setattr(collect, "redact_conf", lambda text: text)
    for text in ("root=/dev/vda password=leakleak1\n", "token: leakleak2\n", "x=1 secret=leakleak3,,t\n"):
        assert collect.redact_checked(text, "conf") == (None, "redaction failed")


def test_cmdline_and_libvirtd_conf_are_redacted_in_the_case_folder(host, monkeypatch, tmp_path):
    files, globs = host
    complete_host(files, tmp_path, globs)
    files["/etc/libvirt/libvirtd.conf"] = b"auth_tcp = 'none'\nsecret_key = cmd-leak7\n"
    files["/proc/cmdline"] = b"ro intel_iommu=on vnc.password=cmd-leak8\n"
    fake_virsh(monkeypatch, dom())
    out = collect.collect("vm1", tmp_path / "case")
    man = json.loads((out / "collect_manifest.json").read_text())["files"]
    assert man["libvirtd.conf"]["status"] == man["cmdline"]["status"] == "redacted"
    text = (out / "libvirtd.conf").read_text() + (out / "cmdline").read_text()
    assert "cmd-leak7" not in text and "cmd-leak8" not in text and "intel_iommu=on" in text and "auth_tcp = 'none'" in text


def test_a_leaking_conf_redactor_drops_libvirtd_conf_and_cmdline(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    files["/etc/libvirt/libvirtd.conf"] = b"secret_key = cmd-leak7\n"
    files["/proc/cmdline"] = b"vnc.password=cmd-leak8\n"
    monkeypatch.setattr(collect, "redact_conf", lambda text: text)
    fake_virsh(monkeypatch, dom())
    out = tmp_path / "case"
    assert collect.main(["vm1", str(out)]) == 1
    man = json.loads((out / "collect_manifest.json").read_text())["files"]
    assert man["libvirtd.conf"] == man["cmdline"] == {"status": "dropped", "reason": "redaction failed"}
    assert not (out / "libvirtd.conf").exists() and not (out / "cmdline").exists()


def test_collect_virsh_is_pinned_to_the_system_connection(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, env=kw.get("env"))
        return subprocess.CompletedProcess(argv, 0, "<domain/>", "")
    monkeypatch.setattr(collect.subprocess, "run", fake_run)
    monkeypatch.setenv("LIBVIRT_DEFAULT_URI", "qemu+ssh://evil/system")
    collect.virsh_dumpxml("vm1")
    assert tuple(seen["argv"][:3]) == ("virsh", "-c", "qemu:///system") and "LIBVIRT_DEFAULT_URI" not in seen["env"]


# ---- hermetic host reads ----
@pytest.fixture
def host(monkeypatch):
    """Fake host: path -> bytes (missing otherwise); no globbing unless a test adds paths; no subprocesses."""
    files, globs = {}, {}
    monkeypatch.setattr(collect, "read_file_ex", lambda src: (files[str(src)], "ok", "") if str(src) in files
                        else (None, "missing", "does not exist"))
    monkeypatch.setattr(collect.glob, "glob", lambda pat: globs.get(pat, []))
    monkeypatch.setattr(collect, "sh", lambda *cmd: "")
    return files, globs


def complete_host(files, tmp_path, globs):
    image = tmp_path / "img.qcow2"
    image.write_text("x")
    globs["/var/lib/libvirt/images/*"] = [str(image)]
    files["/etc/libvirt/libvirtd.conf"] = b"# conf\n"
    files["/run/libvirt/qemu/vm1.pid"] = b"123\n"
    files["/proc/123/status"] = b"Name: qemu\n"
    files["/proc/123/attr/current"] = b"libvirt-1 (enforce)"
    files["/etc/libvirt/qemu.conf"] = b'vnc_password = "abc12345"\nuser = "root"\n'


def test_manifest_lists_every_expected_file_with_status_and_reason(host, monkeypatch, tmp_path):
    files, globs = host
    complete_host(files, tmp_path, globs)
    fake_virsh(monkeypatch, dom("<graphics type='vnc' passwd='hunter2-x'/>"))
    out = collect.collect("vm1", tmp_path / "case")
    man = json.loads((out / "collect_manifest.json").read_text())
    assert set(man["files"]) == set(collect.EXPECTED_FILES) and man["vm"] == "vm1"
    st = {n: e["status"] for n, e in man["files"].items()}
    assert st["vm.xml"] == "redacted" and st["qemu.conf"] == "redacted"
    assert st["net_isolation.txt"] == "ok" and st["perms.txt"] == "ok" and st["qemu_status"] == "ok"
    assert st["cmdline"] == "missing" and man["files"]["cmdline"]["reason"] == "does not exist"
    assert man["live_problems"] == [] and "hunter2-x" not in (out / "vm.xml").read_text()
    assert 'vnc_password = "REDACTED"' in (out / "qemu.conf").read_text()
    if os.name != "nt":
        assert (out.stat().st_mode & 0o777) == 0o700 and ((out / "collect_manifest.json").stat().st_mode & 0o077) == 0


def test_cli_exits_zero_when_complete(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    fake_virsh(monkeypatch, dom())
    assert collect.main(["vm1", str(tmp_path / "case")]) == 0
    assert "INCOMPLETE" not in capsys.readouterr().err


def test_cli_exits_nonzero_and_names_live_file_missing_without_explanation(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    del files["/etc/libvirt/libvirtd.conf"]
    fake_virsh(monkeypatch, dom())
    out = tmp_path / "case"
    assert collect.main(["vm1", str(out)]) == 1
    err = capsys.readouterr().err
    assert "libvirtd.conf: missing (does not exist)" in err and "INCOMPLETE" in err and "libvirtd.conf" in err
    man = json.loads((out / "collect_manifest.json").read_text())
    assert man["live_problems"] == ["libvirtd.conf"]


def test_stopped_vm_explains_missing_qemu_files_but_nothing_else(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    del files["/run/libvirt/qemu/vm1.pid"]
    fake_virsh(monkeypatch, dom())
    out = tmp_path / "case"
    assert collect.main(["vm1", str(out)]) == 0
    man = json.loads((out / "collect_manifest.json").read_text())
    assert man["files"]["qemu_status"]["explained"] is True and "not running" in man["files"]["qemu_status"]["reason"]
    assert "qemu_status: missing" in capsys.readouterr().err  # still printed, just not fatal


def test_symlinked_image_is_reported_not_silently_dropped(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    target = tmp_path / "real.img"
    target.write_text("x")
    link = tmp_path / "link.img"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")
    globs["/var/lib/libvirt/images/*"].append(str(link))
    fake_virsh(monkeypatch, dom())
    out = tmp_path / "case"
    assert collect.main(["vm1", str(out)]) == 1
    man = json.loads((out / "collect_manifest.json").read_text())
    assert man["files"]["perms.txt"]["status"] == "symlink-skipped"
    assert {"path": str(link), "status": "symlink-skipped", "reason": "is a symlink"} in man["skipped_items"]
    assert str(link) in capsys.readouterr().err


def test_mode_row_reports_why_it_skipped(tmp_path):
    skipped = []
    assert collect.mode_row("image", str(tmp_path / "gone"), skipped) is None
    assert collect.mode_row("image", "bad\npath", skipped) is None
    assert [s["status"] for s in skipped] == ["missing", "unreadable"]
    real = tmp_path / "f"
    real.write_text("x")
    assert collect.mode_row("image", str(real), skipped).startswith("image ")
    assert len(skipped) == 2


def test_read_file_ex_statuses(tmp_path):
    (tmp_path / "f").write_text("x")
    assert collect.read_file_ex(str(tmp_path / "f"))[1] == "ok"
    assert collect.read_file_ex(str(tmp_path / "gone"))[1] == "missing"
    assert collect.read_file_ex(str(tmp_path))[1:] == ("unreadable", "not a regular file") or os.name == "nt"
    link = tmp_path / "l"
    try:
        os.symlink(tmp_path / "f", link)
    except (OSError, NotImplementedError):
        return
    assert collect.read_file_ex(str(link))[1] == "symlink-skipped"


def test_dropped_file_is_missing_from_the_case_and_makes_the_run_incomplete(host, monkeypatch, tmp_path, capsys):
    files, globs = host
    complete_host(files, tmp_path, globs)
    monkeypatch.setattr(collect, "redact_xml", lambda text: text)  # leaking redactor
    fake_virsh(monkeypatch, dom("<graphics type='vnc' passwd='hunter2-x'/>"))
    out = tmp_path / "case"
    assert collect.main(["vm1", str(out)]) == 1
    assert not (out / "vm.xml").exists()
    man = json.loads((out / "collect_manifest.json").read_text())
    assert man["files"]["vm.xml"] == {"status": "dropped", "reason": "redaction failed"}
    assert "vm.xml: dropped (redaction failed)" in capsys.readouterr().err
    assert not any("hunter2-x" in p.read_text() for p in out.iterdir() if p.is_file())


# ---- cleanup on failure ----
def test_failure_after_creation_removes_the_folder_it_created(host, monkeypatch, tmp_path):
    fake_virsh(monkeypatch, dom())
    monkeypatch.setattr(collect, "_collect_host", lambda vm, out, man: (_ for _ in ()).throw(OSError("disk full")))
    out = tmp_path / "case"
    with pytest.raises(RuntimeError, match=r"collect failed \(OSError: disk full\).*removed partial output"):
        collect.collect("vm1", out)
    assert not out.exists()


def test_preexisting_empty_folder_is_kept_but_emptied_and_nonempty_is_untouched(host, monkeypatch, tmp_path):
    fake_virsh(monkeypatch, dom())
    monkeypatch.setattr(collect, "_collect_host", lambda vm, out, man: (_ for _ in ()).throw(OSError("boom")))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RuntimeError, match="collect failed"):
        collect.collect("vm1", empty)
    assert empty.is_dir() and list(empty.iterdir()) == []  # vm.xml written earlier was removed, folder not
    full = tmp_path / "full"
    full.mkdir()
    (full / "keep.txt").write_text("mine")
    with pytest.raises(FileExistsError):
        collect.collect("vm1", full)
    assert (full / "keep.txt").read_text() == "mine"


def test_keyboard_interrupt_also_cleans_up_and_is_not_wrapped(host, monkeypatch, tmp_path):
    fake_virsh(monkeypatch, dom())
    monkeypatch.setattr(collect, "_collect_host", lambda vm, out, man: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        collect.collect("vm1", tmp_path / "case")
    assert not (tmp_path / "case").exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows umask keeps only the owner bits")
def test_umask_is_restored_after_failure(host, monkeypatch, tmp_path):
    fake_virsh(monkeypatch, dom())
    monkeypatch.setattr(collect, "_collect_host", lambda vm, out, man: (_ for _ in ()).throw(OSError("x")))
    before = os.umask(0o022)
    try:
        with pytest.raises(RuntimeError):
            collect.collect("vm1", tmp_path / "case")
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(before)


# ---- virsh missing ----
def test_missing_virsh_is_a_clear_error_with_exit_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("virsh")))
    with pytest.raises(collect.VirshNotFound, match="virsh not found"):
        collect.virsh_dumpxml("vm1")
    assert collect.main(["vm1", str(tmp_path / "case")]) == 2
    err = capsys.readouterr().err
    assert "virsh not found" in err and "Traceback" not in err and not (tmp_path / "case").exists()


def test_cli_process_without_virsh_exits_2_without_traceback(tmp_path):
    env = {**os.environ, "PATH": str(tmp_path)}  # no virsh anywhere
    r = subprocess.run([sys.executable, "-m", "vsec.collect", "vm1", str(tmp_path / "case")], cwd=ROOT, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 2 and "virsh not found" in r.stderr and "Traceback" not in r.stderr
    assert not (tmp_path / "case").exists()


def test_cli_usage_and_bad_input_exit_2_without_traceback(tmp_path, capsys):
    assert collect.main([]) == 2
    assert collect.main(["bad name", str(tmp_path / "x")]) == 2
    assert collect.main(["vm1", str(ROOT.parent / "outside_vsec_test")]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_virsh_timeout_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(collect.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("virsh", 60)))
    with pytest.raises(RuntimeError, match="timed out"):
        collect.virsh_dumpxml("vm1")


# ---- net_isolation texts (first line is what M1 reads) ----
def test_net_isolation_isolated_for_clean_domain(monkeypatch):
    fake_virsh(monkeypatch, dom())
    assert collect.net_isolation(dom()) == "isolated"


def test_net_isolation_isolated_for_vm_without_any_nic_or_exit():
    nic_less = "<domain type='kvm'><name>t</name><devices><graphics type='vnc' listen='127.0.0.1'/></devices></domain>"
    assert collect.net_isolation(nic_less) == "isolated"


@pytest.mark.parametrize("devices, reason", [
    ("<hostdev mode='subsystem' type='usb'/>", "<hostdev>"),
    ("<filesystem type='mount'/>", "<filesystem>"),
    ("<vsock model='virtio'/>", "<vsock>"),
    ("<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>", "channel type='unix'"),
    ("<serial type='tcp'><source host='0.0.0.0' service='1'/></serial>", "serial type='tcp'"),
    ("<disk type='network'><source protocol='nbd'/></disk>", "network-backed"),
    ("<interface type='bridge'><source bridge='br0'/></interface>", "interface type bridge"),
    ("<graphics type='vnc' listen='0.0.0.0'/>", "non-loopback"),
])
def test_net_isolation_not_isolated_for_each_exit(monkeypatch, devices, reason):
    xml = dom(devices)
    fake_virsh(monkeypatch, xml)
    got = collect.net_isolation(xml)
    assert got.startswith("not-isolated: ") and reason in got


def test_net_isolation_not_isolated_for_raw_qemu_args(monkeypatch):
    xml = dom(extra="<qemu:commandline><qemu:arg value='-netdev'/></qemu:commandline>", attrs=QEMU_NS)
    assert collect.net_isolation(xml).startswith("not-isolated: qemu:commandline")


@pytest.mark.parametrize("net, reason", [
    ("<network><forward mode='nat'/></network>", "has <forward"),
    ("<network><ip address='10.1.1.1'/></network>", "<ip>"),
    ("<network><ip address='10.1.1.1'><dhcp/></ip></network>", "<ip>"),
    ("<network><dns><forwarder addr='1.1.1.1'/></dns></network>", "forwarder"),
])
def test_net_isolation_not_isolated_for_each_network_exit(monkeypatch, net, reason):
    fake_virsh(monkeypatch, dom(), {"iso": net})
    got = collect.net_isolation(dom())
    assert got.startswith("not-isolated: network iso ") and reason in got


def test_net_isolation_unknown_when_xml_or_network_cannot_be_read(monkeypatch):
    assert collect.net_isolation("<domain").startswith("unknown: vm.xml unparseable")
    assert collect.net_isolation("").startswith("unknown: ")
    fake_virsh(monkeypatch, dom(), {})  # virsh net-dumpxml fails
    assert collect.net_isolation(dom()) == "unknown: cannot read network iso: RuntimeError"
    fake_virsh(monkeypatch, dom(), {"iso": "<network"})
    assert collect.net_isolation(dom()) == "unknown: network iso XML unparseable"
    monkeypatch.setattr(collect, "virsh_net_dumpxml", lambda n: (_ for _ in ()).throw(collect.VirshNotFound("x")))
    assert collect.net_isolation(dom()).startswith("unknown: cannot read network iso")


def test_net_isolation_bad_network_name_and_every_network_is_checked(monkeypatch):
    xml = dom().replace("network='iso'", "network='-x'")
    assert collect.net_isolation(xml).startswith("not-isolated: bad network name")
    two = dom().replace("</devices>", "<interface type='network'><source network='nat'/><link state='down'/></interface></devices>")
    fake_virsh(monkeypatch, two, {"iso": ISO_NET, "nat": "<network><forward mode='nat'/></network>"})
    assert "network nat" in collect.net_isolation(two)


def test_collect_writes_the_first_line_m1_reads(host, monkeypatch, tmp_path):
    for xml, nets, first in ((dom(), None, "isolated"), (dom("<hostdev type='usb'/>"), None, "not-isolated"),
                             (dom(), {}, "unknown")):
        fake_virsh(monkeypatch, xml, nets)
        out = collect.collect("vm1", tmp_path / f"c-{first}-{len(xml)}")
        assert (out / "net_isolation.txt").read_text().splitlines()[0].split(":")[0] == first


# ---- leak verifier: a secret value that is also legitimate text elsewhere in the file ----
def legit_dom(pw, extra=""):
    """A domain whose text legitimately contains the words people pick as weak passwords."""
    return (f"<domain type='kvm' {QEMU_NS}><name>weak</name><uuid>0a123456-1b2c-4d5e-8f90-123456abcdef</uuid>"
            "<title>libvirt network</title>"
            "<metadata><libosinfo:libosinfo xmlns:libosinfo='http://libosinfo.org/xmlns/libvirt/domain/1.0'>"
            "<libosinfo:os id='http://ubuntu.com/ubuntu/22.04'/></libosinfo:libosinfo></metadata>"
            "<devices><interface type='network'><source network='default'/><model type='virtio'/></interface>"
            f"<graphics type='vnc' passwd='{pw}'/></devices><seclabel type='dynamic' model='apparmor'/>{extra}</domain>")


WEAK_PASSWORDS = ["weak", "123456", "qemu", "libvirt", "default", "virtio", "ubuntu", "network", "apparmor"]


@pytest.mark.parametrize("pw", WEAK_PASSWORDS)
def test_a_password_that_is_also_legit_text_elsewhere_is_redacted_not_dropped(pw):
    out, bad = collect.redact_checked(legit_dom(pw), "xml")
    assert bad is None, pw
    assert "passwd='REDACTED'" in out
    ET.fromstring(out)
    assert "<name>weak</name>" in out and "0a123456-1b2c" in out and "model='apparmor'" in out  # legit text untouched


@pytest.mark.parametrize("pw", ["weak", "123456", "qemu"])
def test_a_legit_looking_password_that_really_leaks_still_drops_the_file(pw, monkeypatch):
    xml = legit_dom(pw)
    monkeypatch.setattr(collect, "redact_xml", lambda text: text)  # nothing redacted: structure check must catch it
    assert collect.redact_checked(xml, "xml") == (None, "redaction failed")
    real = collect.redact_xml  # redacted, but the value is left in a qemu:arg that the redactor did not see
    leak = "<qemu:commandline><qemu:arg value='-vnc :1,password=" + pw + "'/></qemu:commandline>"
    monkeypatch.setattr(collect, "redact_xml", lambda text: real(text).replace("</domain>", leak + "</domain>"))
    assert collect.redact_checked(xml, "xml") == (None, "redaction failed")


def test_a_weak_value_left_in_a_qemu_env_value_still_drops_the_file(monkeypatch):
    real = collect.redact_xml
    leak = "<qemu:commandline><qemu:env name='VNC_PASSWORD' value='weak'/></qemu:commandline>"
    monkeypatch.setattr(collect, "redact_xml", lambda text: real(text).replace("</domain>", leak + "</domain>"))
    assert collect.redact_checked(legit_dom("weak"), "xml") == (None, "redaction failed")


def test_a_weak_conf_password_that_is_legit_elsewhere_is_redacted_and_a_leak_still_drops(monkeypatch):
    conf = "\n".join(['user = "weak"', 'vnc_password = "weak"', "# weak default", ""])
    out, bad = collect.redact_checked(conf, "conf")
    assert bad is None and 'vnc_password = "REDACTED"' in out and 'user = "weak"' in out
    monkeypatch.setattr(collect, "redact_conf", lambda text: text)
    assert collect.redact_checked(conf, "conf") == (None, "redaction failed")


@pytest.mark.parametrize("name", ["VNC_PW", "AUTH_KEY", "X_PASS", "DB_CRED", "SPICE_PSK", "PRIVATE"])
def test_qemu_env_with_a_secretish_name_is_redacted_even_if_the_value_looks_harmless(name):
    out, bad = redact_args(env=[(name, "plainvalue77"), ("HOME", "/root")])
    assert bad is None and "plainvalue77" not in out and "name='HOME' value='/root'" in out


def test_qemu_env_without_a_usable_name_is_redacted_when_unsure():
    out, bad = collect.redact_checked(dom(extra="<qemu:commandline><qemu:env value='unsure-val9'/></qemu:commandline>",
                                         attrs=QEMU_NS), "xml")
    assert bad is None and "unsure-val9" not in out and "value='REDACTED'" in out


def test_a_split_data_arg_is_redacted_but_data_inside_a_normal_option_list_is_not():
    out, bad = redact_args("-object", "secret,id=s0", "data=splitpw99", "-cpu", "host,data=keepme")
    assert bad is None and "splitpw99" not in out and "value='data=REDACTED'" in out and "host,data=keepme" in out


def test_a_split_data_arg_left_by_the_redactor_drops_the_file(monkeypatch):
    monkeypatch.setattr(collect, "redact_xml", lambda text: text)
    assert collect.redact_checked(dom(extra=args_xml("data=splitpw99"), attrs=QEMU_NS), "xml") == (None, "redaction failed")


def test_the_password_inside_free_text_in_metadata_is_blanked_as_a_whole_token():
    xml = dom(extra="<metadata><note a='pw hunter22x'>vnc pw is hunter22x, ok (xhunter22xy)</note></metadata>",
              devices="<graphics type='vnc' passwd='hunter22x'/>")
    out, bad = collect.redact_checked(xml, "xml")
    assert bad is None and "pw is REDACTED, ok" in out and "a='pw REDACTED'" in out
    assert "xhunter22xy" in out  # only whole tokens go
    ET.fromstring(out)


def test_a_short_password_in_metadata_free_text_cannot_be_blanked_so_the_file_is_dropped():
    xml = dom(extra="<metadata><note>the pw is abcd</note></metadata>", devices="<graphics type='vnc' passwd='abcd'/>")
    assert collect.redact_checked(xml, "xml") == (None, "redaction failed")


def test_versions_txt_records_the_full_qemu_version_line_text(host, monkeypatch, tmp_path):
    files, globs = host
    complete_host(files, tmp_path, globs)
    banner = {"qemu-system-x86_64": "QEMU emulator version 7.2.9 (Debian 1:7.2.9+dfsg-0+deb12u1)\nCopyright (c) 2003-2022\n",
              "uname": "6.1.0-18-amd64\n"}
    monkeypatch.setattr(collect, "sh", lambda *cmd: banner.get(cmd[0], ""))
    fake_virsh(monkeypatch, dom())
    out = collect.collect("vm1", tmp_path / "case")
    assert (out / "versions.txt").read_text().splitlines() == [
        "qemu 7.2.9 (Debian 1:7.2.9+dfsg-0+deb12u1)", "kernel 6.1.0-18-amd64"]
    banner["qemu-system-x86_64"] = "QEMU emulator version 8.2.2\n"  # no suffix: no parentheses
    out = collect.collect("vm1", tmp_path / "case2")
    assert (out / "versions.txt").read_text().splitlines()[0] == "qemu 8.2.2"
