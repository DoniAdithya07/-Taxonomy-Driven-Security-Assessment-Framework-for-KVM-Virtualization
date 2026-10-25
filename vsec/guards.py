"""Isolation guards for the `target` VM. Standard library only (no scipy, no yaml, no vsec imports), so the host
gate scripts and collect.py can use it without the project's scientific venv. Load it by file path from a
script (importing the `vsec` package would pull in yaml via vsec/__init__.py).

Pure XML checks return a list of problems (empty = no way out found); they never raise on bad input.
The virsh-backed assert_* helpers take a `virsh(*args, timeout=)` callable (default: the real `virsh`) and
raise RuntimeError on the first failed check. The revert-marker helpers are shared by preflight_target.py and
guard_rootkit.py.

Limits (honest): these read the libvirt XML only. They cannot see QEMU defaults that are not in the XML, a
compromised hypervisor, or anything that changed after the check ran.
"""
import ipaddress
import json
import os
import posixpath
import re
import stat
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
MAX_XML_BYTES = 1_000_000
UNPARSEABLE = "unparseable XML"
_QEMU_NS = "{http://libvirt.org/schemas/domain/qemu/1.0}"
# device types that are fine to have; anything else under <devices> is reported (allow-list, not deny-list)
_ALLOWED_DEVICES = {"emulator", "disk", "controller", "interface", "input", "graphics", "video", "audio",
                    "memballoon", "rng", "serial", "console", "channel", "parallel", "watchdog", "panic"}
_NEVER_DEVICES = ("hostdev", "filesystem", "vsock", "redirdev", "sound")
_CHARDEVS = ("serial", "console", "channel", "parallel")
_OK_CHARDEV_TYPES = {"pty", "null", "none"}
_OK_DISK_TYPES = {"file", "volume"}
_LOCAL_NAMES = {"localhost"}


def _parse(xml, root_tag):
    """(root element, None) or (None, problem). Size-capped; any parser failure becomes a problem string."""
    if isinstance(xml, str):
        size = len(xml.encode("utf-8", "replace"))
    elif isinstance(xml, (bytes, bytearray)):
        size = len(xml)
    else:
        return None, f"{UNPARSEABLE}: not text"
    if size > MAX_XML_BYTES:
        return None, f"{UNPARSEABLE}: larger than {MAX_XML_BYTES} bytes"
    try:
        root = ET.fromstring(xml)
    except Exception as e:  # ParseError, ValueError, RecursionError ...: never reaches the caller
        return None, f"{UNPARSEABLE}: {type(e).__name__}"
    if root.tag != root_tag:
        return None, f"{UNPARSEABLE}: root element is <{root.tag}>, expected <{root_tag}>"
    return root, None


def _is_loopback(addr):
    addr = (addr or "").strip().lower()
    if addr in _LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _graphics_problems(g):
    kind = g.get("type")
    if kind not in ("vnc", "spice", "rdp"):
        return [f"<graphics type={kind!r}> uses the host display"]
    out, listens, explicit = [], [], bool(g.get("socket"))
    if g.get("listen") is not None:
        listens.append(g.get("listen"))
    for el in g.findall("listen"):
        if el.get("type") == "network":
            out.append(f"<graphics type={kind!r}> listens on a libvirt network")
        elif el.get("type") in ("socket", "none"):
            explicit = True  # unix socket (or no listener at all): not network-reachable
        else:
            listens.append(el.get("address"))
    for addr in listens:
        if _is_loopback(addr):
            explicit = True
        else:
            out.append(f"<graphics type={kind!r}> listens on non-loopback address {addr!r}")
    if not explicit and not out:  # the default would come from qemu.conf (vnc_listen / spice_listen), not the XML
        out.append(f"<graphics type={kind!r}> has no explicit loopback <listen> or unix socket")
    # clipboard/filetransfer are 'yes' by default, but only reach the guest over a spicevmc channel, which is flagged
    if g.find("clipboard") is not None and g.find("clipboard").get("copypaste") == "yes":
        out.append(f"<graphics type={kind!r}> has the spice clipboard enabled")
    if g.find("filetransfer") is not None and g.find("filetransfer").get("enable") == "yes":
        out.append(f"<graphics type={kind!r}> has spice filetransfer enabled")
    return out


def _interface_problems(nic, expected_network):
    kind = nic.get("type")
    if kind != "network":
        return [f"interface type {kind} is not 'network'"]
    src = nic.find("source")
    name = src.get("network") if src is not None else None
    if not name:
        return ["interface has no <source network=...>"]
    if expected_network and name != expected_network:
        return [f"interface is on network {name!r}, expected {expected_network!r}"]
    return []


def _under_dev(path):
    norm = posixpath.normpath((path or "").strip() or ".")
    norm = "/" + norm.lstrip("/") if norm.startswith("/") else norm  # normpath keeps a leading '//'
    return norm == "/dev" or norm.startswith("/dev/")


def _disk_problems(disk):
    out = []
    kind = disk.get("type") or "file"  # libvirt's default
    if kind == "network" or any(s.get("protocol") for s in disk.iter("source")):
        out.append("network-backed <disk> (source protocol)")
    elif kind not in _OK_DISK_TYPES:
        out.append(f"<disk type={kind!r}> is not on the allow-list (file, volume)")
    if disk.get("device") == "lun":
        out.append("<disk device='lun'> passes a host SCSI device")
    for store in disk.iter("backingStore"):
        if store.get("type") not in (None, "file", "volume"):
            out.append(f"<backingStore type={store.get('type')!r}> is not on the allow-list (file, volume)")
    if any(_under_dev(s.get(k)) for s in disk.iter("source") for k in ("file", "dev")):
        out.append("<disk> source is under /dev (host device)")
    return out


def _chardev_problems(dev):
    kind, tag = dev.get("type"), dev.tag
    if tag == "rng":
        return ["<rng> uses an egd backend"] if any(b.get("model") == "egd" for b in dev.findall("backend")) else []
    if kind not in _OK_CHARDEV_TYPES:
        return [f"<{tag} type={kind!r}> is not on the chardev allow-list (pty, null, none)"]
    return []


def exit_problems(domain_xml, expected_network=None):
    """Reasons the domain XML gives the guest a way out (host device, shared folder, vsock, guest channel,
    network socket, non-network NIC, raw QEMU arguments, exposed console, host audio, unlabelled VM). Allow-lists
    throughout. Empty list = none found."""
    root, bad = _parse(domain_xml, "domain")
    if bad:
        return [bad]
    problems = []
    for el in root.iter():
        if el.tag.startswith(_QEMU_NS):
            problems.append(f"qemu:{el.tag[len(_QEMU_NS):]} element (raw QEMU arguments)")
        elif el.tag in _NEVER_DEVICES:
            problems.append(f"<{el.tag}> device ({el.get('type') or el.get('mode') or 'present'})")
        elif el.tag == "seclabel" and "none" in (el.get("type"), el.get("model")):
            problems.append("<seclabel> switches security labelling off")
    all_devices = list(root.iter("devices"))
    if len(all_devices) > 1:  # a second block must not hide devices from a check that reads only the first
        problems.append(f"{len(all_devices)} <devices> elements (exactly one is allowed)")
    for devices in all_devices:
        for dev in devices:
            problems += _device_problems(dev, expected_network)
    return problems


def _device_problems(dev, expected_network):
    tag = dev.tag
    if tag in _NEVER_DEVICES:
        return []  # reported once by the walk in exit_problems
    if tag not in _ALLOWED_DEVICES:
        return [f"unexpected <{tag}> device (not on the allow-list)"]
    if tag == "interface":
        return _interface_problems(dev, expected_network)
    if tag == "disk":
        return _disk_problems(dev)
    if tag == "graphics":
        return _graphics_problems(dev)
    if tag == "audio" and dev.get("type") != "none":
        return [f"<audio type={dev.get('type')!r}> reaches the host sound server"]
    if tag == "input" and dev.get("type") in ("passthrough", "evdev"):
        return [f"<input type={dev.get('type')!r}> passes a host input device"]
    if tag in _CHARDEVS or tag == "rng":
        return _chardev_problems(dev)
    return []


def network_problems(network_xml):
    """Reasons a libvirt network is not host-only isolated: <forward>, any <ip> (the guest gets a route to the
    host's bridge address), dhcp, dns forwarders. Empty list = a bare bridge with nothing configured."""
    root, bad = _parse(network_xml, "network")
    if bad:
        return [bad]
    problems = []
    fwd = root.find("forward")
    if fwd is not None:
        problems.append(f"has <forward mode={fwd.get('mode', 'nat')!r}>")
    if next(root.iter("ip"), None) is not None:
        problems.append("has an <ip> element (guest can reach services on the host bridge address)")
    if next(root.iter("dhcp"), None) is not None:
        problems.append("has <dhcp>")
    if next(root.iter("forwarder"), None) is not None:
        problems.append("has a <dns> forwarder")
    return problems


def interface_networks(domain_xml):
    """Names of the libvirt networks the domain's type=network interfaces use. ValueError if unparseable."""
    root, bad = _parse(domain_xml, "domain")
    if bad:
        raise ValueError(bad)
    names = []
    for nic in root.iter("interface"):
        src = nic.find("source")
        if nic.get("type") == "network" and src is not None and src.get("network"):
            names.append(src.get("network"))
    return names


def domain_links_down(domain_xml):
    """True only if the XML parses and EVERY interface carries <link state='down'/> (no NIC: True)."""
    root, bad = _parse(domain_xml, "domain")
    if bad:
        return False
    for nic in root.iter("interface"):
        link = nic.find("link")
        if link is None or link.get("state") != "down":
            return False
    return True


# ---- virsh-backed checks ------------------------------------------------------------------
VIRSH_URI = "qemu:///system"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def virsh(*args, timeout=60, uri=VIRSH_URI):
    """Run `virsh -c <uri>`: the connection is always explicit, so the caller's LIBVIRT_DEFAULT_URI (removed from
    the child's environment too) cannot point the checks at another hypervisor. `uri` is for tests only.
    FileNotFoundError (virsh missing) and TimeoutExpired are NOT caught: callers decide."""
    env = {k: v for k, v in os.environ.items() if k != "LIBVIRT_DEFAULT_URI"}
    return subprocess.run(("virsh", "-c", uri, *args), capture_output=True, text=True, timeout=timeout, env=env)


def _ok(r, what):
    if r.returncode:
        raise RuntimeError(f"cannot {what}: {r.stderr.strip()[-200:]}")
    return r.stdout


def domain_xml_text(vm, virsh=virsh):
    return _ok(virsh("dumpxml", vm, timeout=60), f"read domain XML for {vm!r}")


def domain_uuid(vm, virsh=virsh):
    """The domain's UUID from `virsh domuuid`; RuntimeError unless it is a well-formed UUID (fail closed)."""
    value = _ok(virsh("domuuid", vm, timeout=60), f"read the uuid of {vm!r}").strip().lower()
    if not _UUID.fullmatch(value):
        raise RuntimeError(f"`virsh domuuid {vm}` did not print a uuid: {value[:60]!r}")
    return value


def domain_state(vm, virsh=virsh):
    """`virsh domstate` text (e.g. 'running', 'shut off'), whitespace-trimmed and capped."""
    return _ok(virsh("domstate", vm, timeout=60), f"read the state of {vm!r}").strip()[:40]


def assert_isolated(network, virsh=virsh):
    """RuntimeError unless the libvirt network is a bare host-only bridge (see network_problems)."""
    problems = network_problems(_ok(virsh("net-dumpxml", network, timeout=60), f"read libvirt network {network!r}"))
    if problems:
        raise RuntimeError(f"libvirt network {network!r} is not isolated: {'; '.join(problems)}")


def assert_vm_isolated(vm, virsh=virsh, expected_network=None):
    """RuntimeError if the domain has any way out (exit_problems) or any of its networks is not isolated."""
    xml = domain_xml_text(vm, virsh)
    problems = exit_problems(xml, expected_network)
    if problems:
        raise RuntimeError(f"domain {vm!r} has a way out: {'; '.join(problems)}")
    for name in interface_networks(xml):
        assert_isolated(name, virsh)


def assert_no_hostdev(vm, virsh=virsh):
    """RuntimeError if the domain passes a host device through (<hostdev>), or its XML cannot be read."""
    bad = [p for p in exit_problems(domain_xml_text(vm, virsh)) if p.startswith(("<hostdev>", UNPARSEABLE))]
    if bad:
        raise RuntimeError(f"domain {vm!r} has a <hostdev> device (host passthrough): {'; '.join(bad)}")


def assert_no_other_running_domain(vm, virsh=virsh):
    names = _ok(virsh("list", "--name", timeout=60), "list running domains").split()
    others = sorted(n for n in names if n != vm)
    if others:
        raise RuntimeError(f"other domains are running: {', '.join(others)}; shut them down before dumping {vm!r}")


def domiflist_names(text):
    """Interface names listed by `virsh domiflist` (rows after the dashed line); None if no dashed line."""
    rows = [ln.split() for ln in text.splitlines()]
    sep = next((i for i, c in enumerate(rows) if c and set(c[0]) == {"-"} and len(c[0]) > 2), None)
    return None if sep is None else [c[0] for c in rows[sep + 1:] if c]


def assert_links_down(vm, virsh=virsh):
    """RuntimeError unless every interface link is confirmed down: `domif-getlink` must print exactly
    '<name> down' for a running interface (exact token match), and the domain XML must carry
    <link state='down'/> on every interface. An empty or garbled `domiflist` fails when the XML has a NIC."""
    xml = domain_xml_text(vm, virsh)
    root, bad = _parse(xml, "domain")
    if bad:
        raise RuntimeError(f"cannot read interfaces of {vm!r}: {bad}")
    nics = len(list(root.iter("interface")))
    names = domiflist_names(_ok(virsh("domiflist", vm, timeout=60), f"read interfaces of {vm!r}"))
    names = names or []
    if len(names) != nics:
        raise RuntimeError(f"`virsh domiflist {vm}` lists {len(names)} interface(s) but the domain XML has {nics}")
    for name in names:
        if name == "-":  # domain not running: no live link to read, the XML check below covers it
            continue
        r = virsh("domif-getlink", vm, name, timeout=60)
        if r.returncode or r.stdout.split() != [name, "down"]:
            raise RuntimeError(f"interface {name} of {vm!r} is not confirmed down: {(r.stdout or r.stderr).strip()[-100:]}")
    if not domain_links_down(xml):
        raise RuntimeError(f"domain {vm!r} XML does not show <link state='down'/> on every interface")


# ---- revert marker (shared by preflight_target.py and guard_rootkit.py) --------------------
_OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
_TS = "%Y-%m-%dT%H:%M:%SZ"


def write_marker(path, vm, uuid=None, state=None):
    """Create the marker JSON {vm, created_utc, pid[, uuid, state]} atomically: O_EXCL|O_NOFOLLOW, mode 0600. An existing
    entry (a stale marker, or a symlink an attacker left) is unlinked first; the unlink never follows a link."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    data = {"vm": vm, "created_utc": datetime.now(timezone.utc).strftime(_TS), "pid": os.getpid()}
    data.update({k: v for k, v in (("uuid", uuid), ("state", state)) if v is not None})
    body = json.dumps(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _OPEN_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(body)


def check_marker(path, vm, max_age_minutes=15, now=None, uuid=None):
    """RuntimeError unless the marker exists, is a plain (non-symlink) file of ours, names `vm` and is not older
    than max_age_minutes (nor dated in the future). With `uuid` (host callers pass `virsh domuuid`), the marker
    must carry that same domain uuid: a domain redefined under the same name is not the one that was reverted.
    Does not delete it."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise RuntimeError(f"no revert marker {path}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"revert marker {path} is a symlink or not a regular file")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise RuntimeError(f"revert marker {path} is owned by another user")
    try:
        fd = os.open(path, os.O_RDONLY | _OPEN_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            data = json.loads(f.read(4096).decode("utf-8"))
        created = datetime.strptime(data["created_utc"], _TS).replace(tzinfo=timezone.utc)
        marker_vm, marker_uuid = data["vm"], data.get("uuid")
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise RuntimeError(f"revert marker {path} is unreadable or malformed ({type(e).__name__})") from None
    if marker_vm != vm:
        raise RuntimeError(f"revert marker {path} is for VM {marker_vm!r}, not {vm!r}")
    if uuid is not None and marker_uuid != uuid:
        raise RuntimeError(f"revert marker {path} is for domain uuid {marker_uuid!r}, not {uuid!r}: "
                           "the domain was redefined or the marker predates uuid binding")
    now = now or datetime.now(timezone.utc)
    if created > now + timedelta(minutes=1):
        raise RuntimeError(f"revert marker {path} is dated in the future")
    if now - created > timedelta(minutes=max_age_minutes):
        raise RuntimeError(f"revert marker {path} is older than {max_age_minutes} minutes: revert again and re-mark")
