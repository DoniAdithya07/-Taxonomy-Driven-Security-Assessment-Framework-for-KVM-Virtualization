"""Generate the M1 ground-truth fixtures: 50 case folders + a hidden answer key.

    python tests/make_fixtures.py [out_dir]     (default: tests/fixtures)

Each control gets >= 3 distinct seeded faults. A case holds several faults on different settings.
Also writes cves_fixture.yaml: the real CVE list with every entry marked verified, so the C23/C24 version
logic can be scored (the real list is unverified, which makes C23/C24 NA). Files are written with LF; case49 uses CRLF.
NOTE: this generator has the same author as the checker (solo project), so the M1 score is a
self-consistency test, not independent ground truth.
"""
import json
import random
import sys
from pathlib import Path

import yaml

N_CASES, SEED, N_E0 = 50, 7, 6  # the first N_E0 cases mimic E0: no IOMMU groups, so C02 is NA
CRLF_CASE = 49  # every file of this case uses CRLF line endings (truth unchanged)
CVES_FIXTURE = "cves_fixture.yaml"  # vsec/cves.yaml with every entry marked verified: FIXTURE ONLY, never for results

GOOD = {
    "cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro intel_iommu=on iommu=pt",
    "iommu_groups": "14", "ksm_run": "0", "nested": "N", "smt": "0",
    "qemu_status": "Name:\tqemu\nSeccomp:\t2\n", "qemu_label": "libvirt-1234 (enforce)",
    "vuln.a": "", "ver.qemu": "8.2.2", "ver.kernel": "6.8.0", "net_scan.txt": "isolated: 0 open ports",
    "net_isolation.txt": "isolated",
    "perm.image": "600", "perm.socket": "660", "perm.savedir": "700",
    "qconf.seccomp": "", "qconf.driver": 'security_driver = "apparmor"', "qconf.user": 'user = "libvirt-qemu"',
    "qconf.caps": "", "qconf.confined": "", "lconf.sock": "", "lconf.tcp": "",
    "x.graphics": "vnc|127.0.0.1|secret", "x.redirdev": "0", "x.devices": "", "x.iface": "isolated",
    "x.cache": "none", "x.shmem": "0",
}


def F(*pairs):
    return [dict([p]) if isinstance(p, tuple) else p for p in pairs]


FAULTS = {  # control -> >= 3 distinct faults, each a {setting: value}
    "C01": F(("cmdline", "ro quiet"), ("cmdline", "ro quiet splash"), ("cmdline", "ro nomodeset")),
    "C02": F(("iommu_groups", "0"), ("iommu_groups", "00"), ("iommu_groups", "0\n")),
    "C03": F(("qconf.seccomp", "seccomp_sandbox = 0"), ("qconf.seccomp", "# x\nseccomp_sandbox=0"),
             ("qconf.seccomp", 'seccomp_sandbox = "0"')),
    "C04": F(("qemu_status", "Name:\tqemu\nSeccomp:\t0\n"), ("qemu_status", "Name:\tqemu\nSeccomp:\t1\n"),
             ("qemu_status", "Name:\tqemu\n")),
    "C05": F(("qconf.driver", 'security_driver = "none"'), ("qconf.driver", "security_driver = none"),
             ("qconf.driver", 'security_driver = ""')),
    "C06": F(("qemu_label", "unconfined"), ("qemu_label", "unconfined (complain)"), ("qemu_label", "none")),
    "C07": F(("qconf.user", 'user = "root"'), ("qconf.user", "user=root"), ("qconf.user", "user = root\ngroup = root")),
    "C08": F(("qconf.caps", "clear_emulator_capabilities = 0"), ("qconf.caps", "clear_emulator_capabilities=0"),
             ("qconf.caps", "x = 1\nclear_emulator_capabilities = 0")),
    "C09": F(("ksm_run", "1"), ("ksm_run", "2"), ("ksm_run", "1\n")),
    "C10": F(("nested", "Y"), ("nested", "1"), ("nested", "Y\n")),
    "C11": F(("x.graphics", "vnc|127.0.0.1|"), ("x.graphics", "spice|127.0.0.1|"), ("x.graphics", "spice|::1|")),
    "C12": F(("x.graphics", "vnc|0.0.0.0|secret"), ("x.graphics", "spice|192.168.1.5|secret"), ("x.graphics", "vnc|::|secret")),
    "C13": F(("x.redirdev", "1"), ("x.redirdev", "2"), ("x.redirdev", "3")),
    "C14": F(("x.devices", "sound"), ("x.devices", "parallel"), ("x.devices", "floppy")),
    "C15": F(("x.iface", "default"), ("x.iface", "bridge"), ("x.iface", "isolated|default")),
    "C16": F(("net_scan.txt", "reachable: 22/tcp open"),  # guest scan says reachable
             ("net_isolation.txt", "not-isolated: network default has <forward mode='nat'>"),  # host file only
             {"net_scan.txt": "REACHABLE: 80/tcp open", "net_isolation.txt": "not-isolated: interface type bridge"}),
    "C17": F(("perm.image", "644"), ("perm.image", "666"), ("perm.image", "604")),
    "C18": F(("perm.socket", "666"), ("perm.socket", "777"), ("perm.socket", "662")),
    "C19": F(("lconf.sock", 'unix_sock_rw_perms = "0777"'), ("lconf.sock", 'unix_sock_rw_perms = "0666"'),
             ("lconf.sock", "unix_sock_rw_perms = 0777")),
    "C20": F(("lconf.tcp", 'listen_tcp = 1\nauth_tcp = "none"'), ("lconf.tcp", "listen_tcp=1\nauth_tcp=none"),
             ("lconf.tcp", "listen_tcp = 1\nauth_tcp = none\n# x")),
    "C21": F(("perm.savedir", "755"), ("perm.savedir", "777"), ("perm.savedir", "705")),
    "C22": F(("x.cache", "unsafe"), ("x.cache", "none|unsafe"), ("x.cache", "unsafe|unsafe")),
    "C23": F(("ver.qemu", "4.2.1"), ("ver.qemu", "5.0.0"), ("ver.qemu", "7.2.0")),
    "C24": F(("ver.kernel", "5.4.0"), ("ver.kernel", "5.15.0"), ("ver.kernel", "5.11.0")),
    "C25": F(("vuln.a", "spectre_v2: Vulnerable"), ("vuln.a", "mds: Vulnerable: Clear CPU buffers"),
             ("vuln.a", "meltdown: Vulnerable")),
    "C26": F(("smt", "1"), ("smt", "1\n"), ("smt", "1 ")),
    "C27": F(("x.shmem", "1"), ("x.shmem", "2"), ("x.shmem", "3")),
    "C28": F(("qconf.confined", "security_default_confined = 0"), ("qconf.confined", "security_default_confined=0"),
             ("qconf.confined", "x=1\nsecurity_default_confined = 0")),
}

IFACE = {"isolated": "<interface type='network'><source network='isolated'/></interface>",
         "default": "<interface type='network'><source network='default'/></interface>",
         "bridge": "<interface type='bridge'><source bridge='br0'/></interface>"}
DEVICE = {"sound": "<sound model='ich9'/>", "parallel": "<parallel type='pty'/>",
          "floppy": "<disk type='file' device='floppy'><target dev='fda'/></disk>", "": ""}


def vm_xml(s):
    gtype, listen, pw = s["x.graphics"].split("|")
    g = f"<graphics type='{gtype}'" + (f" listen='{listen}'" if listen else "") + (f" passwd='{pw}'" if pw else "") + "/>"
    disks = "".join(f"<disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='{c}'/></disk>"
                    for c in s["x.cache"].split("|"))
    ifaces = "".join(IFACE[i] for i in s["x.iface"].split("|"))
    return ("<domain type='kvm'><name>vm</name><devices>" + disks + g + DEVICE[s["x.devices"]]
            + "<redirdev bus='usb' type='spicevmc'/>" * int(s["x.redirdev"])
            + "<shmem name='ivshm'/>" * int(s["x.shmem"]) + ifaces + "</devices></domain>")


def files_for(settings, e0):
    s = {**GOOD, **settings}
    vulns = "\n".join(x for x in ("meltdown: Mitigation: PTI", "l1tf: Mitigation: PTE Inversion; SMT vulnerable",
                                  s["vuln.a"]) if x)
    out = {
        "vm.xml": vm_xml(s), "cmdline": s["cmdline"], "ksm_run": s["ksm_run"], "nested": s["nested"],
        "smt": s["smt"], "qemu_status": s["qemu_status"], "qemu_label": s["qemu_label"], "vulns.txt": vulns,
        "net_scan.txt": s["net_scan.txt"], "net_isolation.txt": s["net_isolation.txt"], "iommu_groups": s["iommu_groups"],
        "versions.txt": f"qemu {s['ver.qemu']}\nkernel {s['ver.kernel']}",
        "perms.txt": (f"image {s['perm.image']} 0 0 /var/lib/libvirt/images/a b.qcow2\n"
                      f"socket {s['perm.socket']} 0 0 /run/libvirt/libvirt-sock\n"
                      f"socket 777 0 0 /run/libvirt/libvirt-sock-ro\n"
                      f"savedir {s['perm.savedir']} 0 0 /var/lib/libvirt/qemu/save"),
        "qemu.conf": "\n".join(["# vsec fixture"] + [s[k] for k in (
            "qconf.seccomp", "qconf.driver", "qconf.user", "qconf.caps", "qconf.confined") if s[k]]),
        "libvirtd.conf": "\n".join(["# vsec fixture"] + [s[k] for k in ("lconf.sock", "lconf.tcp") if s[k]]),
    }
    if e0:
        del out["iommu_groups"]
    return out


def _real_cves():
    return yaml.safe_load((Path(__file__).parent.parent / "vsec" / "cves.yaml").read_text(encoding="utf-8"))["cves"]


def _write(path, text):
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def main(out):
    rng = random.Random(SEED)
    out = Path(out)
    cases = [{"settings": {}, "key": {}} for _ in range(N_CASES)]
    pairs = [(cid, f) for cid, fl in FAULTS.items() for f in fl]
    rng.shuffle(pairs)
    for cid, fault in pairs:
        ok = [i for i, c in enumerate(cases)
              if not set(fault) & set(c["settings"]) and cid not in c["key"] and not (cid == "C02" and i < N_E0)]
        if not ok:
            raise SystemExit(f"could not place {cid} {fault}")
        c = cases[rng.choice(ok)]
        c["settings"].update(fault)
        c["key"][cid] = "FAIL"
    answer = {}
    for i, c in enumerate(cases):
        name = f"case{i:02d}"
        folder = out / name
        folder.mkdir(parents=True, exist_ok=True)
        for fn, text in files_for(c["settings"], i < N_E0).items():
            if i == CRLF_CASE:  # Windows-style line endings and a trailing newline: the checkers must not care
                text = text.replace("\n", "\r\n") + "\r\n"
            with open(folder / fn, "w", encoding="utf-8", newline="") as fh:  # no newline translation, on any OS
                fh.write(text)
        truth = {cid: "PASS" for cid in FAULTS}
        truth.update(c["key"])
        if i < N_E0:
            truth["C02"] = "NA"
        answer[name] = truth
    _write(out / "answer_key.json", json.dumps(answer, indent=1))
    _write(out / CVES_FIXTURE, yaml.safe_dump({"cves": [{**e, "verified": True} for e in _real_cves()]}))
    seeded = sum(v == "FAIL" for t in answer.values() for v in t.values())
    print(f"{N_CASES} cases, {seeded} seeded faults -> {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "fixtures")
