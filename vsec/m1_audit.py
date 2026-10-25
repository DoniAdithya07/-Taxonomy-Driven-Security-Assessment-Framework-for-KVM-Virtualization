"""M1: configuration auditor. Reads a case folder (captured host files) and returns findings.

Case folder files (all optional; a missing or empty file gives NA, never PASS):
  vm.xml  qemu.conf  libvirtd.conf  cmdline  ksm_run  nested  iommu_groups  qemu_status
  qemu_label  perms.txt  vulns.txt  smt  versions.txt  net_isolation.txt (written by the host)
  net_scan.txt (written INSIDE the guest: corroboration only, never proof)
perms.txt rows: `tag mode uid gid path...` (path may contain spaces).
"""
import functools
import ipaddress
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from . import HERE, clean_text, finding

MAX_BYTES = 1_000_000
CVES_PATH = HERE / "cves.yaml"  # tests (or audit(cves_path=...)) point this at a verified list
# O_NOFOLLOW refuses a symlink atomically; O_NONBLOCK: opening a FIFO must not hang
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
UNSET = "key unset, effective value unknown (see live check)"
DEFAULTED = " (unset: libvirt default)"


class Case:
    def __init__(self, folder, cves_path=None):
        self.folder = Path(folder)
        self.cves_path = cves_path
        self._xml = False  # False = not parsed yet; None = unusable

    def read(self, name):
        """Stripped text of a case file (NUL bytes removed), or None if missing/empty/unreadable (capped at 1 MB).
        A symlink or anything but a regular file is refused, so a planted link cannot leak another file."""
        p = self.folder / name
        try:
            if p.is_symlink():  # O_NOFOLLOW does not exist on Windows
                return None
            fd = os.open(p, _OPEN_FLAGS)  # a symlink raises OSError here on POSIX (no check-then-open race)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = os.read(fd, MAX_BYTES)
        except OSError:
            return None
        finally:
            os.close(fd)
        return data.replace(b"\0", b"").decode("utf-8", errors="replace").strip() or None

    @property
    def xml(self):
        """Parsed vm.xml root, or None when missing/empty/oversized/unparseable."""
        if self._xml is False:
            self._xml = None
            t = self.read("vm.xml")
            if t and len(t) < MAX_BYTES:
                try:
                    self._xml = ET.fromstring(t)
                except ET.ParseError:
                    pass
        return self._xml

    def conf_raw(self, name, key):
        """Raw value text of `key = value` (comment stripped, last uncommented line wins); None if unset."""
        val = None
        for line in (self.read(name) or "").splitlines():
            m = re.match(rf"\s*{re.escape(key)}\s*=\s*(.*)", line)
            if m:
                val = re.sub(r"\s*#.*$", "", m.group(1)).strip()
        return val

    def conf(self, name, key, default=None):
        """Scalar value of a libvirt-style conf key, single and double quotes stripped; `default` when unset."""
        raw = self.conf_raw(name, key)
        return default if raw is None else raw.strip("\"'").strip()

    def conf_list(self, name, key):
        """Items of `key = "a"` or `key = [ "a", "b" ]`; None if unset."""
        raw = self.conf_raw(name, key)
        if raw is None:
            return None
        return [x.strip("\"' ") for x in raw.strip("[] ").split(",")]

    def perms(self, tag):
        """Rows of perms.txt for one tag: [(path, mode_string)]; None if the file is missing."""
        t = self.read("perms.txt")
        if t is None:
            return None
        rows = []
        for ln in t.splitlines():
            f = ln.split(None, 4)
            if len(f) == 5 and f[0] == tag and re.fullmatch(r"[0-7]{3,4}", f[1]):
                rows.append((f[4], f[1]))
        return rows


def _ver(s):
    """Version tuple padded to 3 numeric parts (Debian epoch stripped); None if no digits."""
    nums = [int(x) for x in re.findall(r"\d+", re.sub(r"^\d+:", "", s))[:3]]
    return tuple(nums + [0] * (3 - len(nums))) if nums else None


def _other_bits(mode, bits):
    return int(mode, 8) & bits


def r(ok, evidence):
    return ("PASS" if ok else "FAIL", evidence)


NA = ("NA", "input not available")


def _val(c, fname, key, default):
    """(value, na, note): NA if the file is missing; `default` (a documented libvirt default) if key unset."""
    if c.read(fname) is None:
        return None, NA, ""
    v = c.conf(fname, key)
    if v is None:
        return default, None, DEFAULTED
    return v, None, ""


def needs_xml(fn):
    @functools.wraps(fn)
    def wrapper(c):
        return fn(c) if c.xml is not None else NA
    return wrapper


def c01(c):
    t = c.read("cmdline")
    if t is None:
        return NA
    on = off = False
    for tok in t.split():
        key, _, val = tok.partition("=")
        if key in ("intel_iommu", "amd_iommu"):
            on |= "on" in val.split(",")
            off |= "off" in val.split(",")
    return r(on and not off, f"cmdline: {t[:120]}")


def c02(c):
    t = c.read("iommu_groups")
    if t is None:
        return NA
    try:
        return r(int(t) > 0, f"iommu groups: {t}")
    except ValueError:
        return ("NA", f"unparseable iommu_groups: {t[:40]!r}")


def c03(c):
    v, na, note = _val(c, "qemu.conf", "seccomp_sandbox", "1")
    return na or r(v != "0", f"seccomp_sandbox={v}{note}")


def c04(c):
    t = c.read("qemu_status")
    if t is None:
        return NA
    m = re.search(r"^Seccomp:\s*(\d+)", t, re.M)
    return r(bool(m) and m.group(1) == "2", f"Seccomp: {m.group(1) if m else 'missing'}")


def c05(c):
    if c.read("qemu.conf") is None:
        return NA
    items = c.conf_list("qemu.conf", "security_driver")
    if items is None:
        return ("NA", UNSET)
    items = [i for i in items if i]  # `[]` splits to ['']: an empty list is not a driver
    return r(bool({"selinux", "apparmor"} & set(items)) and "none" not in items, f"security_driver={items}")


def c06(c):
    t = c.read("qemu_label")
    if t is None:
        return NA
    low = t.lower()
    bad = "unconfined" in low or re.search(r"not\s+enforc|complain|permissive", low)
    return r(not bad and bool(re.search(r"\benforce\b|svirt", low)), f"label: {t[:80]}")


def _is_root_user(value):
    """True if a qemu.conf `user` value means uid 0: 'root', '0', '00', '+0', '0x0', with or without ':group'
    and with quotes around the name or the whole value."""
    who = value.split(":")[0].strip("\"' ").lower()
    if who == "root":
        return True
    for base in (10, 0):  # 0 = honour a 0x/0o prefix
        try:
            return int(who, base) == 0
        except ValueError:
            continue
    return False


def c07(c):
    if c.read("qemu.conf") is None:
        return NA
    v = c.conf("qemu.conf", "user")
    if not v:
        return ("NA", UNSET)
    return r(not _is_root_user(v), f"user={v}")


def c08(c):
    v, na, note = _val(c, "qemu.conf", "clear_emulator_capabilities", "1")
    return na or r(v != "0", f"clear_emulator_capabilities={v}{note}")


def c09(c):
    t = c.read("ksm_run")
    if t is None:
        return NA
    return r(t == "0", f"ksm run={t}")


def c10(c):
    t = c.read("nested")
    if t is None:
        return NA
    return r(t in ("N", "0"), f"nested={t}")


def _graphics(c):
    return [g for g in c.xml.iter("graphics") if g.get("type") in ("vnc", "spice", "rdp")]


@needs_xml
def c11(c):
    bad = [g.get("type") for g in _graphics(c) if not g.get("passwd")]
    return r(not bad, f"no password on: {bad}" if bad else "ok")


def _is_loopback(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return addr == "localhost"


@needs_xml
def c12(c):
    bad, unset = [], 0
    for g in _graphics(c):
        listens = list(g.iter("listen"))
        if g.get("socket") or any(x.get("type") == "socket" for x in listens):
            continue  # unix socket: not network-reachable
        addr = g.get("listen") or next((x.get("address") for x in listens if x.get("address")), None)
        if addr is None and not any(x.get("type") == "network" for x in listens):
            unset += 1  # libvirt default (qemu.conf vnc_listen) is 127.0.0.1
        elif addr is None or not _is_loopback(addr):
            bad.append(addr or "network")
    if bad:
        return ("FAIL", f"listens on: {bad}")
    return ("PASS", "no listen address: libvirt default is localhost" if unset else "ok")


@needs_xml
def c13(c):
    n = len(list(c.xml.iter("redirdev")))
    return r(n == 0, f"redirdev count={n}")


@needs_xml
def c14(c):
    bad = [t for t in ("sound", "parallel") if list(c.xml.iter(t))]
    bad += ["floppy" for d in c.xml.iter("disk") if d.get("device") == "floppy"]
    return r(not bad, f"unused devices: {bad}" if bad else "ok")


@needs_xml
def c15(c):
    bad = []
    for i in c.xml.iter("interface"):
        src = i.find("source")
        net = src.get("network") if src is not None else None
        if i.get("type") == "bridge" and i.find("filterref") is None:
            bad.append("unfiltered bridge")
        elif i.get("type") == "network" and net == "default":
            bad.append("default network")
        elif i.get("type") == "direct":
            bad.append("direct (macvtap)")
    return r(not bad, f"{bad}" if bad else "ok")


def _scan_lines(t):
    """Every non-empty line of the guest scan, control characters stripped, joined and cut to 200 characters, so
    the line that decided a FAIL is shown, not just the first one."""
    return " | ".join(ln for ln in (clean_text(x).strip() for x in t.splitlines()) if ln)[:200]


# 'reachable' as a whole word, but not 'unreachable', 'not reachable' or 'not-reachable'
_REACHABLE = re.compile(r"\b(?<!un)(?<!not )(?<!not-)reachable\b", re.I)


def _host_isolation(host):
    """(status, evidence) from net_isolation.txt: PASS only if line 1 is exactly `isolated` and no other line
    says not-isolated/unknown; any not-isolated line is a FAIL; unknown, a BOM or anything else is NA."""
    lines = [ln.lstrip() for ln in host.splitlines()]  # an indented `  not-isolated: x` counts too
    bad = next((ln for ln in lines if ln.startswith("not-isolated")), None)
    if bad:
        return "FAIL", f"host: {bad[:60]}"
    if lines[0].startswith("unknown"):
        return "NA", f"host could not verify isolation: {lines[0][:60]}"
    if lines[0] != "isolated":
        return "NA", f"unrecognised net_isolation.txt: {lines[0][:60]!r}"
    if any(ln.startswith("unknown") for ln in lines[1:]):
        return "NA", "net_isolation.txt has an 'unknown' line after 'isolated'"
    return "PASS", "host-verified"


def c16(c):
    """Host-written net_isolation.txt is the proof; the guest-written net_scan.txt can only add a FAIL."""
    host, scan = c.read("net_isolation.txt"), c.read("net_scan.txt")
    scan_fail = scan is not None and _REACHABLE.search(scan) is not None
    status, ev = _host_isolation(host) if host else (None, "")
    if scan_fail:
        why = [ev] if status == "FAIL" else []
        return ("FAIL", "; ".join(why + [f"guest scan: {_scan_lines(scan)}"]))
    if status == "PASS":
        return ("PASS", f"{ev} (guest scan: {_scan_lines(scan) if scan else 'none'})")
    if status:
        return (status, ev)
    return ("NA", "guest-attested only, not proof") if scan is not None else NA


def c17(c):
    rows = c.perms("image")
    if not rows:
        return NA
    bad = [p for p, m in rows if _other_bits(m, 0o007)]
    return r(not bad, f"world-accessible images: {bad}" if bad else "ok")


def c18(c):
    # -sock-ro is world-accessible by design
    rows = [(p, m) for p, m in c.perms("socket") or [] if not p.endswith("-sock-ro")]
    if not rows:
        return NA
    bad = [p for p, m in rows if _other_bits(m, 0o002)]
    return r(not bad, f"world-writable sockets: {bad}" if bad else "ok")


def c19(c):
    v, na, note = _val(c, "libvirtd.conf", "unix_sock_rw_perms", "0770")
    if na:
        return na
    try:
        return r(not int(v, 8) & 0o002, f"unix_sock_rw_perms={v}{note}")
    except ValueError:
        return ("NA", f"unparseable unix_sock_rw_perms={v!r}")


def c20(c):
    listen, na, n1 = _val(c, "libvirtd.conf", "listen_tcp", "0")
    if na:
        return na
    auth, _, n2 = _val(c, "libvirtd.conf", "auth_tcp", "sasl")
    return r(listen == "0" or auth != "none", f"listen_tcp={listen} auth_tcp={auth}{n1 or n2}")


def c21(c):
    rows = c.perms("savedir")
    if not rows:
        return NA
    bad = [p for p, m in rows if _other_bits(m, 0o007)]
    return r(not bad, f"world-accessible save dirs: {bad}" if bad else "ok")


@needs_xml
def c22(c):
    bad = [d for d in c.xml.iter("driver") if (d.get("cache") or "").lower() == "unsafe"]
    return r(not bad, "cache=unsafe" if bad else "ok")


def _cves(path=None):
    return yaml.safe_load(Path(path or CVES_PATH).read_text(encoding="utf-8"))["cves"]


def _is_distro_version(s):
    """True if the version (Debian epoch stripped) is not plain dotted digits: `6.1.0-18-amd64`, `8.2.2+dfsg-1`."""
    return re.fullmatch(r"\d+(\.\d+)*", re.sub(r"^\d+:", "", s)) is None


# what a distro build adds after the version in `qemu --version`: `(Debian 1:7.2.9+dfsg-0+deb12u1)`
_DISTRO_MARK = re.compile(r"(?i)debian|ubuntu|dfsg|\+ds\b|deb\d+u|\.el\d|\.fc\d|fedora|centos|red ?hat|suse")


def _cve_check(c, product, key):
    t = c.read("versions.txt")
    if t is None:
        return NA
    m = re.search(rf"^{key}[ 	]+(\S+)(.*)$", t, re.M)  # group 2: what follows the version, e.g. `(Debian 1:...)`
    have = _ver(m.group(1)) if m else None
    if have is None:
        return ("NA", f"no parseable {key} version")
    listed = [e for e in _cves(c.cves_path) if e["product"] == product]
    if not listed:
        return ("NA", f"no {product} entries in cves.yaml")
    # ponytail: plain version compare; a distro build is refused (NA) because backports are ignored
    unverified = sum(1 for e in listed if e.get("verified") is not True)
    why = []
    if unverified:
        why.append(f"{unverified} of {len(listed)} {product} CVE entries are unverified: list not usable for results")
    if _is_distro_version(m.group(1)) or _DISTRO_MARK.search(m.group(2)):
        why.append("distro version: backports ignored, use the distro tracker")
    if why:
        return ("NA", f"{key} {m.group(1)}: " + "; ".join(why))
    numeric = [str(e["cve"]) for e in listed if not isinstance(e["fixed_in"], str)]
    fixed = {str(e["cve"]): _ver(str(e["fixed_in"])) for e in listed}  # YAML parses `fixed_in: 8.1` as a float
    if None in fixed.values():
        return ("NA", f"{key} {m.group(1)}: unparseable fixed_in for {[c for c, v in fixed.items() if v is None]}")
    old = [c for c, v in fixed.items() if have < v]
    n = f"checked against {len(listed)} listed CVEs"
    if numeric:
        n += f"; fixed_in of {numeric} are not strings (YAML numbers lose zeros: quote them in cves.yaml)"
    return r(not old, f"{key} {m.group(1)} lacks fixes: {old} ({n})" if old else f"{key} {m.group(1)} ok ({n})")


def c23(c):
    return _cve_check(c, "qemu", "qemu")


def c24(c):
    return _cve_check(c, "kernel", "kernel")


def _vuln_lines(t):
    return [ln for ln in (t or "").splitlines() if re.match(r"[\w.-]+:\s*\S", ln)]


def c25(c):
    lines = _vuln_lines(c.read("vulns.txt"))
    if not lines:
        return NA
    bad = [ln.split(":")[0] for ln in lines if re.search(r":\s*vulnerable", ln, re.I)]
    return r(not bad, f"vulnerable: {bad}" if bad else "ok")


def c26(c):
    smt, t = c.read("smt"), c.read("vulns.txt")
    if smt is None or not _vuln_lines(t):
        return NA
    smt = smt.lower()
    if smt not in ("1", "on", "forceon", "0", "off", "forceoff", "notsupported", "notimplemented"):
        return ("NA", f"unrecognised smt value {smt[:20]!r}")
    on = smt in ("1", "on", "forceon")
    needs = "smt vulnerable" in t.lower()
    return r(not (on and needs), f"smt={smt} smt_vulnerable={needs}")


@needs_xml
def c27(c):
    n = len(list(c.xml.iter("shmem")))
    return r(n == 0, f"shmem count={n}")


def c28(c):
    v, na, note = _val(c, "qemu.conf", "security_default_confined", "1")
    return na or r(v != "0", f"security_default_confined={v}{note}")


CHECKS = {k.upper(): v for k, v in globals().items() if re.fullmatch(r"c\d\d", k)}


def audit(folder, env="E0", vm="", cves_path=None):
    """Run every check. Raises FileNotFoundError if the folder is missing. IOMMU is NA on E0.
    cves_path: CVE list for C23/C24 (default CVES_PATH; only a list with every entry verified gives PASS/FAIL)."""
    if not Path(folder).is_dir():
        raise FileNotFoundError(f"case folder not found: {folder}")
    case = Case(folder, cves_path)
    out = []
    for cid, fn in sorted(CHECKS.items()):
        if env == "E0" and cid == "C02":
            status, ev = "NA", "IOMMU not testable on E0"
        else:
            try:
                status, ev = fn(case)
            except Exception as e:  # a crashing check must never turn into a PASS
                status, ev = "NA", f"check error: {e}"
        out.append(finding(cid, status, ev, env=env, vm=vm or Path(folder).name))
    return out
