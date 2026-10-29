"""Tests for the isolation guards: vsec/guards.py (loaded without the vsec package), preflight_target (host),
guard_rootkit and plant_guest (guest), verify_symbols."""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vsec import m3_forensics as m3

ROOT = Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pf = load_script("preflight_target")
gr = load_script("guard_rootkit")
pg = load_script("plant_guest")  # also proves plant_guest imports without secrets_gen next to it
guards = pf.guards  # the stdlib-only module, loaded by file path exactly as the host gate does

QEMU_NS = "xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'"
NIC = "<interface type='network'><source network='iso'/><model type='virtio'/><link state='down'/></interface>"
CLEAN_DEVICES = (
    "<emulator>/usr/bin/qemu-system-x86_64</emulator>"
    "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/t.qcow2'/>"
    "<target dev='vda' bus='virtio'/></disk>"
    "<controller type='usb' index='0'/><input type='tablet' bus='usb'/><serial type='pty'><target port='0'/></serial>"
    "<console type='pty'/><graphics type='spice' autoport='yes' listen='127.0.0.1'><listen type='address' address='127.0.0.1'/></graphics>"
    "<video><model type='qxl'/></video><memballoon model='virtio'/><rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>"
)


def domain(devices=CLEAN_DEVICES + NIC, extra="", root_attrs=""):
    return f"<domain type='kvm' {root_attrs}><name>target</name><devices>{devices}</devices>{extra}</domain>"


DOM_XML = domain()
DOMIFLIST = (" Interface   Type      Source   Model    MAC\n" + "-" * 50 + "\n"
             " vnet0       network   iso      virtio   52:54:00:00:00:01\n\n")


UUID = "6d2f5a8e-1c3b-4e57-9a10-0123456789ab"


def fake_virsh(monkeypatch, running="target", dom_xml=DOM_XML, net_xml="<network/>", link="vnet0 down",
               domiflist=DOMIFLIST, uuid=UUID, state="shut off"):
    def run(*args, timeout=60):
        out = {"list": running, "dumpxml": dom_xml, "net-dumpxml": net_xml, "domiflist": domiflist,
               "domif-getlink": link, "domuuid": uuid + "\n", "domstate": state + "\n"}[args[0]]
        return subprocess.CompletedProcess(args, 0, out, "")
    monkeypatch.setattr(pf, "_virsh", run)


@pytest.fixture
def marker(tmp_path, monkeypatch):
    fake_virsh(monkeypatch)
    path = tmp_path / "target.reverted"
    pf.mark_reverted(path)
    return path


def make_symlink(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")


def write_marker_json(path, vm="target", age_minutes=0.0, **extra):
    created = datetime.now(timezone.utc) - timedelta(minutes=age_minutes)
    body = {"vm": vm, "created_utc": created.strftime("%Y-%m-%dT%H:%M:%SZ"), "uuid": UUID, **extra}
    Path(path).write_text(json.dumps({k: v for k, v in body.items() if v is not None}))


# ---- guards.exit_problems: one realistic XML per way out ----
def test_clean_domain_has_no_exit_problems():
    assert guards.exit_problems(DOM_XML) == []
    assert guards.exit_problems(DOM_XML.encode()) == []  # bytes work too
    assert guards.exit_problems(DOM_XML, expected_network="iso") == []


@pytest.mark.parametrize("devices, extra, root_attrs, expected", [
    ("<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0' bus='1' slot='0' function='0'/></source></hostdev>",
     "", "", "<hostdev>"),
    ("<hostdev mode='subsystem' type='usb'><source><vendor id='0x1'/></source></hostdev>", "", "", "<hostdev>"),
    ("<filesystem type='mount' accessmode='passthrough'><source dir='/srv/share'/><target dir='share'/></filesystem>",
     "", "", "<filesystem>"),
    ("<vsock model='virtio'><cid auto='yes'/></vsock>", "", "", "<vsock>"),
    ("<redirdev bus='usb' type='spicevmc'/>", "", "", "<redirdev>"),
    ("<channel type='unix'><source mode='bind' path='/var/lib/libvirt/qemu/channel/target/org.qemu.guest_agent.0'/>"
     "<target type='virtio' name='org.qemu.guest_agent.0'/></channel>", "", "", "channel type='unix'"),
    ("<channel type='spicevmc'><target type='virtio' name='com.redhat.spice.0'/></channel>", "", "", "channel type='spicevmc'"),
    ("<channel type='tcp'><source mode='connect' host='10.0.0.1' service='4000'/></channel>", "", "", "channel type='tcp'"),
    ("<serial type='tcp'><source mode='bind' host='0.0.0.0' service='4555'/><protocol type='raw'/></serial>",
     "", "", "serial type='tcp'"),
    ("<serial type='udp'><source mode='connect' host='10.0.0.1' service='9'/></serial>", "", "", "serial type='udp'"),
    ("<console type='unix'><source mode='bind' path='/tmp/c.sock'/></console>", "", "", "console type='unix'"),
    ("<disk type='network' device='disk'><driver name='qemu' type='raw'/>"
     "<source protocol='nbd'><host name='10.0.0.9' port='10809'/></source><target dev='vdb' bus='virtio'/></disk>",
     "", "", "network-backed"),
    ("<disk type='file' device='disk'><source file='/a.qcow2'/><backingStore type='network'>"
     "<source protocol='http' name='/base.img'><host name='evil' port='80'/></source></backingStore></disk>",
     "", "", "network-backed"),
    ("<interface type='bridge'><source bridge='br0'/></interface>", "", "", "interface type bridge"),
    ("<interface type='user'/>", "", "", "interface type user"),
    ("<interface type='direct'><source dev='eth0' mode='bridge'/></interface>", "", "", "interface type direct"),
    ("<interface type='network'/>", "", "", "no <source network"),
    (NIC.replace("iso", "default"), "", "", "expected 'iso'"),
    ("", "<qemu:commandline><qemu:arg value='-netdev'/><qemu:arg value='user,id=n1'/></qemu:commandline>",
     QEMU_NS, "qemu:commandline"),
    ("", "<qemu:commandline><qemu:arg value='-device'/></qemu:commandline>", QEMU_NS, "qemu:arg"),
    ("<graphics type='vnc' port='5900' listen='0.0.0.0'/>", "", "", "non-loopback address '0.0.0.0'"),
    ("<graphics type='spice'><listen type='address' address='192.168.1.5'/></graphics>", "", "", "192.168.1.5"),
    ("<graphics type='vnc'><listen type='network' network='default'/></graphics>", "", "", "listens on a libvirt network"),
    ("<rng model='virtio'><backend model='egd' type='tcp'><source mode='connect' host='h' service='1'/></backend></rng>",
     "", "", "egd"),
    ("<input type='passthrough' bus='virtio'><source evdev='/dev/input/event0'/></input>", "", "", "passes a host input"),
    ("<smartcard mode='passthrough' type='tcp'/>", "", "", "unexpected <smartcard>"),
])
def test_each_way_out_is_reported(devices, extra, root_attrs, expected):
    xml = domain(devices=CLEAN_DEVICES + NIC + devices, extra=extra, root_attrs=root_attrs)
    problems = guards.exit_problems(xml, expected_network="iso" if "expected" in expected else None)
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize("devices, extra, expected", [
    # every <devices> element is walked, and a second one is itself a problem
    ("</devices><devices><hostdev mode='subsystem' type='usb'/>", "", "<hostdev>"),
    ("</devices><devices><serial type='tcp'><source mode='bind' host='0.0.0.0' service='1'/></serial>", "", "serial type='tcp'"),
    ("</devices><devices>", "", "2 <devices> elements"),
    # chardev allow-list: pty, null, none only
    ("<serial type='dev'><source path='/dev/ttyS0'/></serial>", "", "serial type='dev'"),
    ("<serial type='file'><source path='/tmp/s.log'/></serial>", "", "serial type='file'"),
    ("<serial type='pipe'><source path='/tmp/p'/></serial>", "", "serial type='pipe'"),
    ("<console type='stdio'/>", "", "console type='stdio'"),
    ("<serial type='nmdm'><source master='/dev/nmdm0A' slave='/dev/nmdm0B'/></serial>", "", "serial type='nmdm'"),
    ("<serial type='spiceport'><source channel='org.x'/></serial>", "", "serial type='spiceport'"),
    ("<parallel type='file'><source path='/tmp/l'/></parallel>", "", "parallel type='file'"),
    ("<parallel type='dev'><source path='/dev/parport0'/></parallel>", "", "parallel type='dev'"),
    ("<channel type='spiceport'><source channel='x'/></channel>", "", "channel type='spiceport'"),
    ("<serial/>", "", "serial type=None"),
    # disk allow-list: file (not under /dev) and volume
    ("<disk type='block' device='disk'><source dev='/dev/sda'/><target dev='vdb'/></disk>", "", "disk type='block'"),
    ("<disk type='file' device='disk'><source file='/dev/sda'/><target dev='vdb'/></disk>", "", "under /dev"),
    ("<disk type='file' device='disk'><source file='/dev/../dev/sda'/><target dev='vdb'/></disk>", "", "under /dev"),
    ("<disk type='file' device='lun'><source file='/a.img'/><target dev='vdb'/></disk>", "", "device='lun'"),
    ("<disk type='nvme' device='disk'><source type='pci' managed='yes' namespace='1'>"
     "<address domain='0' bus='1' slot='0' function='0'/></source><target dev='vdb'/></disk>", "", "disk type='nvme'"),
    ("<disk type='vhostuser' device='disk'><source type='unix' path='/tmp/vu'/><target dev='vdb'/></disk>", "",
     "disk type='vhostuser'"),
    ("<disk type='dir' device='disk'><source dir='/srv'/><target dev='vdb'/></disk>", "", "disk type='dir'"),
    ("<disk type='file' device='disk'><source file='/a.qcow2'/><backingStore type='block'><source dev='/dev/sdb'/>"
     "</backingStore><target dev='vdb'/></disk>", "", "backingStore type='block'"),
    # audio and sound
    ("<audio id='1' type='pulseaudio'/>", "", "audio type='pulseaudio'"),
    ("<audio id='1' type='pipewire'/>", "", "audio type='pipewire'"),
    ("<audio id='1' type='file' path='/tmp/a.wav'/>", "", "audio type='file'"),
    ("<audio id='1' type='alsa'/>", "", "audio type='alsa'"),
    ("<audio id='1'/>", "", "audio type=None"),
    ("<sound model='ich6'/>", "", "<sound>"),
    # graphics: explicit loopback or unix socket only
    ("<graphics type='vnc'/>", "", "no explicit"),
    ("<graphics type='vnc' port='5900'/>", "", "no explicit"),
    ("<graphics type='spice' autoport='yes'/>", "", "no explicit"),
    ("<graphics type='vnc'><listen type='socket' socket='/tmp/v'/></graphics><graphics type='spice'/>", "", "no explicit"),
    ("<graphics type='spice' listen='127.0.0.1'><clipboard copypaste='yes'/></graphics>", "", "clipboard"),
    ("<graphics type='spice' listen='127.0.0.1'><filetransfer enable='yes'/></graphics>", "", "filetransfer"),
    ("<graphics type='sdl' display=':0'/>", "", "graphics type='sdl'"),
    # security labelling switched off
    ("", "<seclabel type='none'/>", "seclabel"),
    ("", "<seclabel type='dynamic' model='none'/>", "seclabel"),
])
def test_allow_list_rules_report_each_way_out(devices, extra, expected):
    xml = domain(devices=CLEAN_DEVICES + NIC + devices, extra=extra)
    problems = guards.exit_problems(xml)
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize("devices, extra", [
    ("<serial type='null'/>", ""), ("<console type='none'/>", ""), ("<channel type='null'/>", ""),
    ("<parallel type='pty'/>", ""), ("<audio id='1' type='none'/>", ""),
    ("<graphics type='vnc'><listen type='socket' socket='/tmp/v.sock'/></graphics>", ""),
    ("<graphics type='vnc' socket='/tmp/v.sock'/>", ""),
    ("<graphics type='spice' listen='::1'><clipboard copypaste='no'/><filetransfer enable='no'/></graphics>", ""),
    ("<disk type='volume' device='disk'><source pool='p' volume='v'/><target dev='vdb'/></disk>", ""),
    ("<disk type='file' device='cdrom'><source file='/var/lib/libvirt/images/a.iso'/><target dev='sda'/></disk>", ""),
    ("", "<seclabel type='dynamic' model='selinux'/>"),
])
def test_allow_list_accepts_safe_variants(devices, extra):
    assert guards.exit_problems(domain(devices=CLEAN_DEVICES + NIC + devices, extra=extra)) == []


def test_loopback_forms_are_accepted_for_graphics():
    for listen in ("127.0.0.1", "127.1.2.3", "::1", "localhost"):
        xml = domain(devices=CLEAN_DEVICES + NIC.replace(NIC, NIC) + f"<graphics type='vnc' listen='{listen}'/>")
        assert guards.exit_problems(xml) == [], listen


def test_exit_problems_never_raises_on_bad_input():
    for bad in ("", "<domain>", "not xml", "<network/>", None, 5, b"\xff\xfe", "<domain>" + "<a>" * 100000):
        problems = guards.exit_problems(bad)
        assert problems and problems[0].startswith("unparseable XML"), (bad, problems)
    big = "<domain><name>" + "x" * (guards.MAX_XML_BYTES + 1) + "</name></domain>"
    assert "larger than" in guards.exit_problems(big)[0]
    assert guards.network_problems("<network") == ["unparseable XML: ParseError"]
    assert guards.domain_links_down("<domain") is False


def test_entity_bomb_is_not_expanded_or_raised():
    bomb = ("<?xml version='1.0'?><!DOCTYPE d [<!ENTITY a 'aaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>"
            "<!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'><!ENTITY d '&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;'>]><domain>&d;</domain>")
    assert isinstance(guards.exit_problems(bomb), list)  # returns (clean or unparseable), never raises


# ---- guards.network_problems / domain_links_down / interface_networks ----
@pytest.mark.parametrize("net, expected", [
    ("<network><forward mode='nat'/></network>", "<forward mode='nat'>"),
    ("<network><forward/></network>", "<forward mode='nat'>"),
    ("<network><name>iso</name><ip address='192.168.100.1' netmask='255.255.255.0'/></network>", "<ip>"),
    ("<network><ip address='10.0.0.1'><dhcp><range start='10.0.0.2' end='10.0.0.9'/></dhcp></ip></network>", "<dhcp>"),
    ("<network><dns><forwarder addr='8.8.8.8'/></dns></network>", "forwarder"),
])
def test_network_problems(net, expected):
    assert any(expected in p for p in guards.network_problems(net)), guards.network_problems(net)


def test_bare_network_is_isolated():
    assert guards.network_problems("<network><name>iso</name><bridge name='virbr9' stp='on'/></network>") == []


def test_domain_links_down_reads_the_xml():
    assert guards.domain_links_down(DOM_XML)
    assert not guards.domain_links_down(DOM_XML.replace("<link state='down'/>", ""))
    assert not guards.domain_links_down(DOM_XML.replace("state='down'", "state='up'"))
    assert not guards.domain_links_down(DOM_XML.replace("</devices>", "<interface type='network'/></devices>"))
    assert guards.domain_links_down("<domain><devices/></domain>")  # no NIC: nothing is up


def test_interface_networks_and_unparseable():
    assert guards.interface_networks(DOM_XML) == ["iso"]
    with pytest.raises(ValueError, match="unparseable"):
        guards.interface_networks("<domain")


def test_guards_imports_only_the_standard_library():
    import ast
    tree = ast.parse((ROOT / "vsec" / "guards.py").read_text(encoding="utf-8"))
    mods = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert mods <= {"ipaddress", "json", "os", "posixpath", "re", "stat", "subprocess", "xml", "datetime"}, mods


# ---- preflight_target gate ----
def test_gate_passes_and_consumes_marker(monkeypatch, marker):
    fake_virsh(monkeypatch)
    pf.run_gate("target", marker)
    assert not marker.exists()
    with pytest.raises(RuntimeError, match="no revert marker"):  # single use
        pf.run_gate("target", marker)


def test_gate_refuses_without_marker(monkeypatch, tmp_path):
    fake_virsh(monkeypatch)
    with pytest.raises(RuntimeError, match="--mark-reverted"):
        pf.run_gate("target", tmp_path / "missing")


@pytest.mark.parametrize("kwargs, message", [
    ({"running": "target\nkvm-masked"}, "kvm-masked"),
    ({"dom_xml": domain(CLEAN_DEVICES + NIC + "<hostdev type='usb'/>")}, "hostdev"),
    ({"dom_xml": domain(CLEAN_DEVICES + NIC + "<filesystem type='mount'/>")}, "filesystem"),
    ({"dom_xml": domain(CLEAN_DEVICES + NIC + "<vsock model='virtio'/>")}, "vsock"),
    ({"net_xml": "<network><forward mode='nat'/></network>"}, "not isolated"),
    ({"net_xml": "<network><ip address='10.9.0.1'/></network>"}, "<ip>"),
    ({"dom_xml": domain(CLEAN_DEVICES + "<interface type='bridge'><source bridge='br0'/></interface>")}, "bridge"),
    ({"link": "vnet0 up"}, "not confirmed down"),
    ({"dom_xml": DOM_XML.replace("<link state='down'/>", "")}, "<link state='down'/>"),
    ({"dom_xml": "<domain"}, "unparseable"),
    ({"net_xml": "<network"}, "unparseable"),
])
def test_gate_failures_keep_the_marker(monkeypatch, marker, kwargs, message):
    fake_virsh(monkeypatch, **kwargs)
    with pytest.raises(RuntimeError, match=message):
        pf.run_gate("target", marker)
    assert marker.exists()


def test_gate_allows_domain_not_running_with_no_interface_names(monkeypatch, marker):
    stopped = " Interface Type Source Model MAC\n---\n - network iso virtio 52:54\n"
    fake_virsh(monkeypatch, running="", domiflist=stopped)
    pf.run_gate("target", marker)


def test_empty_or_garbled_domiflist_fails_when_the_xml_has_a_nic(monkeypatch, marker):
    for out in ("", "\n\n", "error: something odd", " Interface Type Source\n"):
        fake_virsh(monkeypatch, domiflist=out)
        with pytest.raises(RuntimeError, match="lists 0 interface"):
            pf.run_gate("target", marker)
    fake_virsh(monkeypatch, domiflist=DOMIFLIST + " vnet1 network iso virtio 52:54:00:00:00:02\n")
    with pytest.raises(RuntimeError, match="lists 2 interface"):  # a NIC the XML does not show
        pf.run_gate("target", marker)
    assert marker.exists()


def test_interface_named_down_cannot_fake_a_down_link(monkeypatch, marker):
    named_down = DOMIFLIST.replace("vnet0", "down ")
    fake_virsh(monkeypatch, domiflist=named_down, link="down up")  # the old `"down" in tokens` check passed this
    with pytest.raises(RuntimeError, match="not confirmed down"):
        pf.run_gate("target", marker)
    for bad in ("down", "vnet0 down extra", "up down", ""):
        fake_virsh(monkeypatch, link=bad)
        with pytest.raises(RuntimeError, match="not confirmed down"):
            pf.run_gate("target", marker)
    fake_virsh(monkeypatch, domiflist=named_down, link="down down")
    pf.run_gate("target", marker)


# ---- preflight marker: JSON, TTL, symlink, other VM ----
def test_marker_is_json_with_vm_time_and_pid(marker):
    data = json.loads(marker.read_text())
    assert data["vm"] == "target" and data["pid"] == os.getpid()
    assert datetime.strptime(data["created_utc"], "%Y-%m-%dT%H:%M:%SZ")
    if os.name != "nt":
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600


def test_old_marker_is_rejected_and_ttl_is_configurable(monkeypatch, tmp_path):
    fake_virsh(monkeypatch)
    old = tmp_path / "m"
    write_marker_json(old, age_minutes=16)
    with pytest.raises(RuntimeError, match="older than 15 minutes"):
        pf.run_gate("target", old)
    pf.run_gate("target", old, max_age_minutes=30)  # same marker passes with a longer allowance
    fresh = tmp_path / "f"
    write_marker_json(fresh, age_minutes=14)
    pf.run_gate("target", fresh)


def test_marker_for_another_vm_future_dated_or_malformed_is_rejected(tmp_path):
    for body, message in ((dict(vm="other"), "for VM 'other'"), (dict(age_minutes=-30), "future"),
                          (dict(vm=5), "for VM 5")):
        path = tmp_path / "m"
        write_marker_json(path, **body)
        with pytest.raises(RuntimeError, match=message):
            guards.check_marker(path, "target")
    for text in ("", "not json", "[]", '{"vm": "target"}', '{"vm": "target", "created_utc": "yesterday"}'):
        Path(tmp_path / "m").write_text(text)
        with pytest.raises(RuntimeError, match="malformed"):
            guards.check_marker(tmp_path / "m", "target")


def test_symlinked_marker_is_rejected_and_never_followed(tmp_path, monkeypatch):
    real = tmp_path / "real"
    write_marker_json(real)
    link = tmp_path / "link"
    make_symlink(link, real)
    with pytest.raises(RuntimeError, match="symlink"):
        guards.check_marker(link, "target")
    fake_virsh(monkeypatch)
    pf.mark_reverted(link)  # replaces the link itself; the target is untouched
    assert not link.is_symlink() and json.loads(real.read_text())["vm"] == "target"
    assert json.loads(link.read_text())["pid"] == os.getpid()


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX only")
def test_marker_is_created_exclusively_without_following_links(tmp_path, monkeypatch):
    fake_virsh(monkeypatch)  # mark_reverted binds the marker to the domain uuid: never call a real virsh in a unit test
    seen = {}
    real_open = os.open
    monkeypatch.setattr(guards.os, "open", lambda p, flags, mode=0o777: seen.setdefault("flags", flags)
                        and real_open(p, flags, mode))
    pf.mark_reverted(tmp_path / "m")
    assert seen["flags"] & os.O_EXCL and seen["flags"] & os.O_NOFOLLOW


def test_marker_is_bound_to_the_domain_uuid_and_state(marker):
    data = json.loads(marker.read_text())
    assert data["uuid"] == UUID and data["state"] == "shut off"


def test_gate_fails_when_the_domain_was_redefined_after_the_revert(monkeypatch, marker):
    fake_virsh(monkeypatch, uuid="11111111-2222-4333-8444-555555555555")  # same name, different domain
    with pytest.raises(RuntimeError, match="uuid"):
        pf.run_gate("target", marker)
    assert marker.exists()
    fake_virsh(monkeypatch)
    pf.run_gate("target", marker)  # the original domain passes


def test_marker_without_a_uuid_is_refused_by_the_host_gate(monkeypatch, tmp_path):
    fake_virsh(monkeypatch)
    old_style = tmp_path / "m"
    write_marker_json(old_style, uuid=None)  # {vm, created_utc} only
    with pytest.raises(RuntimeError, match="uuid"):
        pf.run_gate("target", old_style)
    guards.check_marker(old_style, "target")  # the guest-side caller passes no uuid: still accepted


@pytest.mark.parametrize("out", ["", "not-a-uuid", "6d2f5a8e-1c3b-4e57-9a10-0123456789ab; rm -rf /", "error: no domain"])
def test_garbled_domuuid_fails_closed(monkeypatch, out):
    fake_virsh(monkeypatch, uuid=out)
    with pytest.raises(RuntimeError, match="uuid"):
        guards.domain_uuid("target", pf._virsh)


def test_virsh_is_pinned_to_the_system_connection_and_ignores_the_environment(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, env=kw.get("env"))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(guards.subprocess, "run", fake_run)
    monkeypatch.setenv("LIBVIRT_DEFAULT_URI", "qemu+ssh://evil/system")
    guards.virsh("list", "--name")
    assert tuple(seen["argv"][:3]) == ("virsh", "-c", "qemu:///system") and guards.VIRSH_URI == "qemu:///system"
    assert "LIBVIRT_DEFAULT_URI" not in (seen["env"] or {})
    guards.virsh("list", uri="test:///default")  # explicit argument (tests only)
    assert tuple(seen["argv"][:3]) == ("virsh", "-c", "test:///default")


def test_vm_argument_is_validated_and_must_be_target(capsys):
    for vm in ("other", "a;b", "", "../x", "-x", "target "):
        assert pf.main([f"--vm={vm}"]) == 1
        err = capsys.readouterr().err
        assert err.startswith("PREFLIGHT FAILED:") and "Traceback" not in err, vm
    assert pf.main(["--vm", "kvm-plain", "--mark-reverted"]) == 1
    assert pf.main(["--max-age-minutes", "0"]) == 1
    assert pf.main(["--max-age-minutes", "nan"]) == 1


def test_mark_reverted_and_cli_exit_codes(monkeypatch, tmp_path, capsys):
    fake_virsh(monkeypatch)
    monkeypatch.setattr(pf, "MARKER", tmp_path / "sub" / "m")
    assert pf.main(["--mark-reverted"]) == 0 and (tmp_path / "sub" / "m").is_file()
    monkeypatch.setattr(pf, "run_gate", lambda vm, marker, age: (_ for _ in ()).throw(RuntimeError("boom")))
    assert pf.main([]) == 1 and "PREFLIGHT FAILED: boom" in capsys.readouterr().err
    monkeypatch.setattr(pf, "run_gate", lambda vm, marker, age: None)
    assert pf.main([]) == 0


@pytest.mark.parametrize("exc", [ET.ParseError("bad xml"), AttributeError("'NoneType' has no attribute 'get'"),
                                 subprocess.TimeoutExpired("virsh", 60), FileNotFoundError("virsh"),
                                 KeyError("list"), OSError("disk"), ValueError("v"), ZeroDivisionError()])
def test_no_traceback_escapes_the_gate(monkeypatch, capsys, exc):
    def boom(vm, marker, age):
        raise exc
    monkeypatch.setattr(pf, "run_gate", boom)
    assert pf.main([]) == 1
    err = capsys.readouterr().err
    assert err.startswith("PREFLIGHT FAILED: ") and "Traceback" not in err


def test_garbled_virsh_output_end_to_end_fails_cleanly(monkeypatch, tmp_path, capsys):
    fake_virsh(monkeypatch)
    monkeypatch.setattr(pf, "MARKER", tmp_path / "m")
    pf.mark_reverted(pf.MARKER)
    for kwargs in ({"dom_xml": "<domain"}, {"dom_xml": ""}, {"dom_xml": "\x00\x01"}, {"domiflist": "\x00"},
                   {"running": "target\x00evil"}):
        fake_virsh(monkeypatch, **kwargs)
        assert pf.main([]) == 1, kwargs
        err = capsys.readouterr().err
        assert err.startswith("PREFLIGHT FAILED:") and "Traceback" not in err
    assert pf.MARKER.exists()


def test_virsh_timeout_and_missing_virsh_through_the_real_path(monkeypatch, tmp_path, capsys):
    fake_virsh(monkeypatch)
    monkeypatch.setattr(pf, "MARKER", tmp_path / "m")
    pf.mark_reverted(pf.MARKER)
    monkeypatch.setattr(pf, "_virsh", lambda *a, timeout=60: guards.virsh(*a, timeout=timeout))  # the real path
    monkeypatch.setattr(guards.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("virsh")))
    assert pf.main([]) == 1 and "PREFLIGHT FAILED: FileNotFoundError" in capsys.readouterr().err
    monkeypatch.setattr(guards.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("virsh", 60)))
    assert pf.main([]) == 1 and "TimeoutExpired" in capsys.readouterr().err


# ---- plant_guest offline checks (fake /proc and /sys under a root dir) ----
ROUTE_HEAD = "Iface\tDestination\tGateway\tFlags\n"


def fake_root(tmp_path, ifaces=(("lo", "unknown"), ("eth0", "down")), route="", inet6="", fib=""):
    for name, state in ifaces:
        (tmp_path / "sys/class/net" / name).mkdir(parents=True, exist_ok=True)
        (tmp_path / "sys/class/net" / name / "operstate").write_text(state + "\n")
    (tmp_path / "proc/net").mkdir(parents=True, exist_ok=True)
    (tmp_path / "proc/net/route").write_text(ROUTE_HEAD + "lo\t0000007F\t00000000\t0001\n" + route)
    if inet6:
        (tmp_path / "proc/net/if_inet6").write_text(inet6)
    if fib:
        (tmp_path / "proc/net/fib_trie").write_text(fib)
    return str(tmp_path)


FIB = "Local:\n  +-- 10.0.0.0/24 2 0 2\n     |-- 10.0.0.5\n        /32 host LOCAL\n"
FIB_LO = "Local:\n  +-- 127.0.0.0/8 2 0 2\n     |-- 127.0.0.1\n        /32 host LOCAL\n"


def test_offline_guest_has_no_problems(tmp_path):
    root = fake_root(tmp_path, fib=FIB_LO, inet6="0" * 31 + "1 01 80 10 80       lo\n")
    assert pg.offline_problems(root) == []
    pg.check_offline(root)


@pytest.mark.parametrize("build, expected", [
    (dict(ifaces=(("lo", "unknown"), ("eth0", "unknown"))), "eth0 is not down"),
    (dict(ifaces=(("lo", "unknown"), ("eth0", "up"))), "eth0 is not down"),
    (dict(ifaces=(("lo", "unknown"), ("eth0", "dormant"))), "eth0 is not down"),
    (dict(route="eth0\t00000000\t0102A8C0\t0003\n"), "default route via eth0"),
    (dict(route="eth0\t0000A8C0\t00000000\t0001\n"), "IPv4 route on interface eth0"),
    (dict(inet6="fe80000000000000020c29fffe123456 02 40 20 80   eth0\n"), "IPv6 address on interface eth0"),
    (dict(fib=FIB), "IPv4 address 10.0.0.5"),
])
def test_online_guest_is_refused(tmp_path, build, expected):
    root = fake_root(tmp_path, **build)
    assert any(expected in p for p in pg.offline_problems(root)), pg.offline_problems(root)
    with pytest.raises(SystemExit, match="preflight_target.py"):
        pg.check_offline(root)


def test_check_offline_fails_closed_when_route_file_missing(tmp_path):
    (tmp_path / "sys/class/net").mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        pg.offline_problems(str(tmp_path))


# ---- guard_rootkit ----
@pytest.fixture
def kit(tmp_path, monkeypatch):
    # guard_rootkit keeps its verified private copy on success (the operator insmods it): put those copies under the
    # test's own temp folder so pytest removes them, instead of leaving vsec-rk-* folders in TMP
    copies = tmp_path / "rk-copies"
    copies.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(copies))
    allow = tmp_path / "allowed"
    allow.mkdir()
    if os.name != "nt":
        allow.chmod(0o755)
    mod = allow / "rk.ko"
    mod.write_bytes(b"x")
    if os.name != "nt":
        mod.chmod(0o644)
    outside = tmp_path / "evil.ko"
    outside.write_bytes(b"x")
    if os.name != "nt":
        outside.chmod(0o644)
    marker = tmp_path / "target.reverted"
    write_marker_json(marker)
    return allow, mod, outside, marker


def test_module_must_be_inside_allow_list(kit, tmp_path):
    allow, mod, outside, _ = kit
    assert gr.check_module_allowed(mod, allow) == str(mod.resolve())
    for bad in (outside, allow / ".." / "evil.ko", allow, allow / "missing.ko"):
        with pytest.raises(ValueError):
            gr.check_module_allowed(bad, allow)
    with pytest.raises(ValueError, match="allow-list directory"):
        gr.check_module_allowed(mod, tmp_path / "nope")


def test_allow_dir_must_be_owned_by_root_or_us_and_not_group_world_writable():
    assert gr.dir_problems(0o40755, uid=1000, my_uid=1000) == []
    assert gr.dir_problems(0o40755, uid=0, my_uid=1000) == []
    assert any("owned by uid 1001" in p for p in gr.dir_problems(0o40755, uid=1001, my_uid=1000))
    assert any("writable" in p for p in gr.dir_problems(0o40775, uid=1000, my_uid=1000))
    assert any("writable" in p for p in gr.dir_problems(0o40757, uid=1000, my_uid=1000))
    assert len(gr.dir_problems(0o40777, uid=1001, my_uid=1000)) == 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_writable_allow_dir_is_refused_on_posix(kit):
    allow, mod, _, _ = kit
    allow.chmod(0o775)
    with pytest.raises(ValueError, match="not trustworthy"):
        gr.check_module_allowed(mod, allow)
    allow.chmod(0o755)
    assert gr.check_module_allowed(mod, allow)


def test_sha256_pin_is_verified_before_anything_is_printed(kit, capsys):
    allow, mod, _, _ = kit
    good = hashlib.sha256(b"x").hexdigest()
    assert gr.check_sha256(mod, good.upper() + "\n") == good
    for bad in ("0" * 64, "abc", "g" * 64, ""):
        with pytest.raises(ValueError):
            gr.check_sha256(mod, bad)
    assert gr.main(["--allow-dir", str(allow), "--module", str(mod), "--sha256", "0" * 64]) == 1
    assert "insmod" not in capsys.readouterr().out


def test_printed_command_quotes_the_module_path():
    cmd = gr.insmod_instructions("/opt/root kits/a;rm -rf x.ko")
    assert "insmod '/opt/root kits/a;rm -rf x.ko'" in cmd
    pinned = gr.insmod_instructions("/opt/a b.ko", "A" * 64)
    assert "sha256sum -c -" in pinned and "'/opt/a b.ko'" in pinned and "a" * 64 in pinned
    assert "printf '%s\\n'" in pinned and "echo" not in pinned  # printf, so backslashes in the path are not interpreted


def test_marker_is_single_use_ttl_and_symlink_checked(kit, tmp_path):
    marker = kit[3]
    gr.consume_marker(str(marker))
    assert not marker.exists()
    with pytest.raises(RuntimeError, match="no revert marker"):
        gr.consume_marker(str(marker))
    write_marker_json(marker, age_minutes=20)
    with pytest.raises(RuntimeError, match="older than"):
        gr.consume_marker(str(marker))
    assert marker.exists()  # a refused marker is kept
    write_marker_json(marker, vm="kvm-plain")
    with pytest.raises(RuntimeError, match="not 'target'"):
        gr.consume_marker(str(marker))
    marker.unlink()
    link = tmp_path / "ln"
    write_marker_json(tmp_path / "real")
    make_symlink(link, tmp_path / "real")
    with pytest.raises(RuntimeError, match="symlink"):
        gr.consume_marker(str(link))


GOOD = hashlib.sha256(b"x").hexdigest()


def test_check_all_passes_consumes_marker_and_returns_a_verified_private_copy(kit, tmp_path):
    allow, mod, _, marker = kit
    copy = gr.check_all(mod, allow, GOOD, root=fake_root(tmp_path / "r"), marker=str(marker))
    assert not marker.exists()
    assert copy != str(mod.resolve()) and os.path.basename(copy) == "rk.ko" and Path(copy).read_bytes() == b"x"
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(os.path.dirname(copy)).st_mode) == 0o700
    mod.write_bytes(b"swapped")  # the original changing afterwards does not touch the verified copy
    assert Path(copy).read_bytes() == b"x"


def test_sha256_is_mandatory_for_check_all_and_the_cli(kit, tmp_path, capsys):
    allow, mod, _, marker = kit
    with pytest.raises(TypeError):
        gr.check_all(mod, allow, root=fake_root(tmp_path / "r"), marker=str(marker))
    with pytest.raises(ValueError, match="mandatory"):
        gr.check_all(mod, allow, "", root=fake_root(tmp_path / "r"), marker=str(marker))
    with pytest.raises(SystemExit) as e:
        gr.main(["--allow-dir", str(allow), "--module", str(mod)])
    assert e.value.code == 2 and "--sha256 is mandatory" in capsys.readouterr().err
    assert marker.exists()


@pytest.mark.parametrize("age", [0, -1, 1441, float("nan")])
def test_max_age_minutes_is_bounded_like_preflight(kit, tmp_path, age):
    allow, mod, _, marker = kit
    with pytest.raises(ValueError, match="max-age-minutes"):
        gr.check_all(mod, allow, GOOD, root=fake_root(tmp_path / "r"), marker=str(marker), max_age_minutes=age)
    assert marker.exists()


def test_failed_copy_check_leaves_no_temp_dir(kit, tmp_path, monkeypatch):
    allow, mod, _, _ = kit
    made = []
    real = gr.tempfile.mkdtemp
    monkeypatch.setattr(gr.tempfile, "mkdtemp", lambda **kw: made.append(real(**kw)) or made[-1])
    with pytest.raises(ValueError, match="SHA-256"):
        gr.copy_verified(str(mod), "0" * 64)
    assert len(made) == 1 and not os.path.exists(made[0])


def test_module_file_owner_and_mode_rules():
    assert gr.file_problems(0o100644, uid=0, my_uid=1000) == []
    assert any("owned by uid 5" in p for p in gr.file_problems(0o100644, uid=5, my_uid=1000))
    assert any("writable" in p for p in gr.file_problems(0o100664, uid=1000, my_uid=1000))
    assert any("writable" in p for p in gr.file_problems(0o100646, uid=1000, my_uid=1000))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions and symlinks")
def test_writable_module_and_symlinked_module_are_refused(kit):
    allow, mod, _, _ = kit
    mod.chmod(0o666)
    with pytest.raises(ValueError, match="not trustworthy"):
        gr.copy_verified(str(mod), GOOD)
    mod.chmod(0o644)
    link = allow / "link.ko"
    link.symlink_to(mod)
    with pytest.raises(OSError):  # O_NOFOLLOW: ELOOP
        gr.copy_verified(str(link), GOOD)
    assert Path(gr.copy_verified(str(mod), GOOD)).read_bytes() == b"x"


def test_check_all_keeps_marker_when_another_check_fails(kit, tmp_path):
    allow, mod, outside, marker = kit
    online = fake_root(tmp_path / "online", ifaces=(("lo", "unknown"), ("eth0", "up")))
    with pytest.raises(RuntimeError, match="not offline"):
        gr.check_all(mod, allow, GOOD, root=online, marker=str(marker))
    with pytest.raises(ValueError, match="allow-list"):
        gr.check_all(outside, allow, GOOD, root=fake_root(tmp_path / "ok"), marker=str(marker))
    with pytest.raises(ValueError, match="SHA-256"):
        gr.check_all(mod, allow, "1" * 64, root=fake_root(tmp_path / "ok3"), marker=str(marker))
    assert marker.exists()
    marker.unlink()
    with pytest.raises(RuntimeError, match="no revert marker"):
        gr.check_all(mod, allow, GOOD, root=fake_root(tmp_path / "ok2"), marker=str(marker))


def test_guard_rootkit_main_prints_instructions_and_loads_nothing(kit, tmp_path, monkeypatch, capsys):
    allow, mod, _, marker = kit
    monkeypatch.setattr(gr, "MARKER", str(marker))
    monkeypatch.setattr(gr, "check_all", lambda module, allow_dir, sha, **kw: gr.check_module_allowed(module, allow_dir))
    assert gr.main(["--allow-dir", str(allow), "--module", str(mod), "--sha256", GOOD]) == 0
    out = capsys.readouterr().out
    assert "loaded nothing" in out and f"insmod {mod.resolve()}" in out.replace("'", "") and "COPY" in out
    assert gr.main(["--allow-dir", str(allow), "--module", str(tmp_path / "evil.ko"), "--sha256", GOOD]) == 1


def test_guard_rootkit_mark_reverted_writes_a_json_marker(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gr, "MARKER", str(tmp_path / "var" / "target.reverted"))
    assert gr.main(["--mark-reverted"]) == 0
    assert json.loads((tmp_path / "var" / "target.reverted").read_text())["vm"] == "target"


# ---- plant_guest: broken child pipe ----
class FakeProc:
    def __init__(self, write_exc=None, wait_exc=None):
        self.killed = False
        self.stdin = self
        self._write_exc, self._wait_exc = write_exc, wait_exc

    def write(self, text):
        if self._write_exc:
            raise self._write_exc

    def close(self):
        pass

    def wait(self, timeout=None):
        if self._wait_exc and not self.killed:
            raise self._wait_exc
        return 0

    def kill(self):
        self.killed = True

    def poll(self):
        return None


@pytest.mark.parametrize("write_exc, wait_exc, state", [
    (BrokenPipeError("pipe closed"), None, "live"),
    (None, subprocess.TimeoutExpired("child", 30), "exited"),
    (OSError("stdin gone"), None, "freed"),
])
def test_start_child_kills_the_child_and_reports_instead_of_raising(monkeypatch, write_exc, wait_exc, state):
    child = FakeProc(write_exc, wait_exc)
    monkeypatch.setattr(pg.subprocess, "Popen", lambda *a, **k: child)
    ok, msg = pg.start_child("hex32", state, "ab" * 32)
    assert ok is False and child.killed and msg


def test_planting_failure_exits_nonzero_with_message_not_traceback(monkeypatch, tmp_path):
    monkeypatch.setattr(pg, "check_offline", lambda root="/": None)
    monkeypatch.setattr(pg, "_load_secrets_gen", lambda: __import__("types").SimpleNamespace(
        make_secret=lambda kind, rng: "ab" * 32, plant_text=lambda kind, secret: secret))
    monkeypatch.setattr(pg, "start_child", lambda *a: (False, "BrokenPipeError: simulated"))
    with pytest.raises(SystemExit, match="planting failed: BrokenPipeError: simulated"):
        pg.main(["hex32", "live", str(tmp_path / "m.json")])
    assert not (tmp_path / "m.json").exists()


def test_every_script_i_own_has_a_python3_shebang():
    for name in ("preflight_target.py", "guard_rootkit.py", "plant_guest.py", "guest_scan.py"):
        first = (ROOT / "scripts" / name).read_text(encoding="utf-8").splitlines()[0]
        assert first == "#!/usr/bin/env python3", name


# ---- verify_symbols ----
def isf(tmp_path, content=b'{"symbols": {}}'):
    path = tmp_path / "ubuntu-6.8.0-1.json"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def test_verify_symbols_accepts_matching_hash_for_file_and_folder(tmp_path):
    path, digest = isf(tmp_path)
    assert m3.verify_symbols(path, digest) == path
    assert m3.verify_symbols(tmp_path, digest.upper() + "\n") == path


def test_verify_symbols_rejects_mismatch_missing_and_ambiguous_folder(tmp_path):
    path, digest = isf(tmp_path)
    with pytest.raises(RuntimeError, match="does not match"):
        m3.verify_symbols(path, "0" * 64)
    with pytest.raises(RuntimeError, match="does not match"):
        m3.verify_symbols(path, "")  # an empty hash never verifies
    with pytest.raises(RuntimeError, match="not found"):
        m3.verify_symbols(tmp_path / "missing.json", digest)
    (tmp_path / "second.json").write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="exactly one"):
        m3.verify_symbols(tmp_path, digest)


def test_detect_verifies_symbols_before_running_vol(tmp_path, monkeypatch):
    path, digest = isf(tmp_path)
    ran = []
    monkeypatch.setattr(m3, "available", lambda: True)
    monkeypatch.setattr(m3, "vol_version", lambda vol: None)
    monkeypatch.setattr(m3, "_vol", lambda: "vol")
    monkeypatch.setattr(m3, "run_plugin", lambda dump, name, sym=None, sandbox=False: ran.append(sym) or
                        [{"PID": 1, "Name": "x"}])
    with pytest.raises(RuntimeError, match="does not match"):
        m3.detect("d.mem", symbols_dir=path, expected_sha256="1" * 64)
    assert ran == []
    monkeypatch.setenv(m3.SYMBOLS_SHA_ENV, "1" * 64)  # env is used when no argument is given
    with pytest.raises(RuntimeError, match="does not match"):
        m3.detect("d.mem", symbols_dir=path)
    m3.detect("d.mem", symbols_dir=path, expected_sha256=digest)  # argument wins over env
    assert ran and len(set(ran)) == 1 and ran[0] != path.parent  # vol got the private copy, not the source
    with pytest.raises(RuntimeError, match="no symbols path"):
        m3.detect("d.mem", expected_sha256=digest)


# ---- guard_rootkit: the hash can never be skipped ----
@pytest.mark.parametrize("bad", ["", None, "   ", "abc", "zz" * 32, "ab" * 31, "ab" * 33, GOOD + "0"])
def test_check_all_rejects_every_empty_or_malformed_hash_before_any_other_check(kit, tmp_path, bad):
    allow, mod, _, marker = kit

    def never(root):
        raise AssertionError("the offline check must not run before the hash is validated")
    with pytest.raises(ValueError, match="mandatory|64 hex"):
        gr.check_all(mod, allow, bad, root=tmp_path, marker=str(marker), offline_problems=never)
    assert marker.exists()


@pytest.mark.parametrize("bad", ["", " ", "abc", "zz" * 32])
def test_cli_sha256_empty_or_malformed_is_an_error_not_a_skipped_check(kit, capsys, bad):
    allow, mod, _, marker = kit
    argv = ["--allow-dir", str(allow), "--module", str(mod), "--sha256", bad]
    try:
        code = gr.main(argv)
    except SystemExit as e:  # argparse error
        code = e.code
    err = capsys.readouterr().err
    assert code in (1, 2) and ("REFUSING" in err or "--sha256 is mandatory" in err)
    assert marker.exists()
