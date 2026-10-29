"""Capture the host files M1 needs into a case folder (run on the KVM host, Linux only).

    python -m vsec.collect <vm-name> <out-folder>

The out folder must be inside <repo>/cases or <repo>/.local and must not be a symlink. VNC/SPICE password
VALUES, every password/passwd/secret/token value in <qemu:arg>/<qemu:env> and in the conf files, libvirtd.conf and
/proc/cmdline are replaced by REDACTED before writing (the key stays, so "a password exists" is still checkable;
QEMU's doubled commas inside a value are handled); an independent verifier re-checks every redacted file and DROPS
the file (fail closed) if an original value or any secret-looking key=value is still in it.
A collect_manifest.json lists every expected file as ok / redacted / missing / unreadable / symlink-skipped /
dropped, with a reason. Exit codes: 0 complete; 1 a LIVE file is missing or skipped without an explanation
(see the manifest and stderr); 2 error (bad input, virsh not found, virsh failed). On any error the output
folder this run created is removed.
WARNING: a case folder still holds sensitive host data (VM definition, host config, kernel version, file
permissions). It is created mode 0700; do not share or commit it.
"""
import errno
import glob
import html
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from . import ROOT, clean_text, guards

VM_NAME = guards.VM_NAME
MAX_BYTES = 1_000_000
ALLOWED_OUT = (ROOT / "cases", ROOT / ".local")
MANIFEST = "collect_manifest.json"
LIVE_FILES = ("qemu_status", "qemu_label", "perms.txt", "libvirtd.conf", "net_isolation.txt")
EXPECTED_FILES = ("vm.xml", "net_isolation.txt", "qemu.conf", "libvirtd.conf", "cmdline", "ksm_run", "nested",
                  "iommu_groups", "smt", "vulns.txt", "qemu_status", "qemu_label", "perms.txt", "versions.txt")
BAD_STATUS = ("missing", "unreadable", "symlink-skipped", "dropped")
REDACTED = "REDACTED"
MIN_VERIFY_LEN = 4  # shorter originals ("1", "on") would match unrelated text; the structural check covers them
META_TOKEN_MIN = 6  # a secret is blanked as a whole token in <metadata> free text only from this length on
# O_NOFOLLOW refuses a symlink atomically (no islink-then-open race); O_NONBLOCK: opening a FIFO must not hang
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
_SECRET_NAMES = ("passwd", "password", "secret", "token")
_SECRET_ATTR = re.compile(r"""(?is)((?<![\w:.-])(?:passwd|password|secret|token)\s*=\s*)(['"])((?:(?!\2).)+)\2""")
_SECRET_ELEM = re.compile(r"(?is)(<(passwd|password|secret|token)\b[^>]*(?<!/)>)(.*?)(</\2\s*>)")  # (?<!/): not <x/>
_KEYWORD = re.compile(r"(?i)password|passwd|secret|token")
# QEMU doubles a comma inside an option value ("a,,b" is the value "a,b"), so a value is (?:[^,]|,,)*, not [^,]*
_OPT_SECRET = re.compile(r"(?i)((?<![\w.-])[\w.-]*(?:password|passwd|secret|token)[\w.-]*=)((?:[^,]|,,)*)")
_OPT_DATA = re.compile(r"(?i)((?<![\w.-])data=)((?:[^,]|,,)*)")
# an env variable whose NAME says "secret" (its value may look harmless)
_ENV_SECRET_NAME = re.compile(r"(?i)pass|pwd|(?<![a-z])pw(?![a-z])|key|auth|cred|psk|private|login")
_METADATA = re.compile(r"(?is)<metadata\b[^>]*(?<!/)>.*?</metadata\s*>")
_QUOTED = re.compile(r"""(=\s*)(['"])(.*?)\2""", re.S)
# a <qemu:arg>/<qemu:env> start tag; a quoted attribute value may contain '>'
_ARG_TAG = re.compile(r"""(?is)<[\w.-]*:?(?:arg|env)\b(?:[^>"']|"[^"]*"|'[^']*')*>""")
_ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(['"])(.*?)\2""", re.S)
# key=value or key: value for a secret-looking key in conf lines, /proc/cmdline and similar text
_KV = re.compile(r"""(?i)((?:password|passwd|secret|token)[\w.-]*["']?[ \t]*[=:][ \t]*)("[^"\n]*"|'[^'\n]*'|(?:[^,\s"']|,,)+)""")
_CONF_KEY = re.compile(r"^([^\n]*?(?:vnc|spice)_password[ \t]*=[ \t]*)([^\n]*)$", re.M | re.I)
_CONF_VALUE = re.compile(r"""^\s*(?:(['"])(.*?)\1|([^\s#'"]+))""")
# the verifier's detector: written separately from the redactors above. A secret-looking key followed by any
# value that is not REDACTED (or empty), and a ',,' tail after a REDACTED marker (a value cut at a doubled comma)
_LEFT = re.compile(r"""(?i)(?:password|passwd|secret|token)[\w.-]*['"]?[ \t]*[=:][ \t]*['"]?(?!REDACTED|['"\s])\S""")
_CONT = re.compile(r"REDACTED,,")


class VirshNotFound(RuntimeError):
    """The `virsh` executable is not installed or not on PATH."""


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _virsh(*args):
    try:
        p = guards.virsh(*args, timeout=60)  # always `virsh -c qemu:///system`, whatever LIBVIRT_DEFAULT_URI says
    except FileNotFoundError:
        raise VirshNotFound("virsh not found: install libvirt-clients and run this on the KVM host") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"virsh {' '.join(args)} timed out after 60 s") from None
    if p.returncode or not p.stdout.strip():
        raise RuntimeError(f"virsh {' '.join(args)} failed (exit {p.returncode}): {p.stderr.strip()[:200]}")
    return p.stdout


def virsh_dumpxml(vm):
    """Domain XML incl. security info. Raises RuntimeError if virsh fails or returns nothing."""
    return _virsh("dumpxml", "--security-info", vm)


def virsh_net_dumpxml(name):
    return _virsh("net-dumpxml", name)


def read_file_ex(src):
    """(bytes up to 1 MB with NULs removed, status, reason). status: ok | missing | symlink-skipped | unreadable;
    data is None unless ok. Never follows a symlink."""
    try:
        if stat.S_ISLNK(os.lstat(src).st_mode):
            return None, "symlink-skipped", "is a symlink"
        fd = os.open(src, _OPEN_FLAGS)
    except FileNotFoundError:
        return None, "missing", "does not exist"
    except OSError as e:
        if e.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
            return None, "symlink-skipped", "is a symlink"
        return None, "unreadable", f"{type(e).__name__}: {e.strerror or e}"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "unreadable", "not a regular file"
        return os.read(fd, MAX_BYTES).replace(b"\0", b""), "ok", ""  # /proc/<pid>/attr/current ends with a NUL
    except OSError as e:
        return None, "unreadable", f"{type(e).__name__}: {e.strerror or e}"
    finally:
        os.close(fd)


def read_file(src):
    """Up to 1 MB of a regular, non-symlink file with NUL bytes removed; None if refused or unreadable."""
    return read_file_ex(src)[0]


# ---- redaction ------------------------------------------------------------------------------
def _redact_options(value):
    """Blank every secret option value (comma-aware) in a QEMU option string; `data=` too, since a secret
    object carries its secret there."""
    value = _OPT_SECRET.sub(lambda m: m.group(1) + REDACTED, value)
    return _OPT_DATA.sub(lambda m: m.group(1) + REDACTED, value)


def _tag_attrs(tag):
    return {m.group(1).lower(): html.unescape(m.group(3)) for m in _ATTR.finditer(tag)}


def _is_env_tag(tag):
    return re.match(r"<[\w.-]*:?env\b", tag, re.I) is not None


def _secret_ish(local, attrs):
    """True if a qemu arg/env element (attrs: decoded attribute dict, lowercase names) may carry a secret: an
    attribute mentions password/secret/token; an env whose name looks secret-ish or is missing (unsure); an arg
    that is a bare `data=...` option (the split form of `-object secret,id=x` + `data=<pw>`)."""
    if _KEYWORD.search(" ".join(attrs.values())):
        return True
    if local == "env":
        name = attrs.get("name", "").strip()
        return not name or _ENV_SECRET_NAME.search(name) is not None
    return re.match(r"\s*data=", attrs.get("value", ""), re.I) is not None


def _escape_forms(values):
    """Each value as it may appear in raw XML: plain, and with the XML escapes (quotes escaped or not)."""
    return {f for v in values if v for f in (v, html.escape(v), html.escape(v, quote=False))}


def _blank_tokens(text, forms):
    """Replace each whole-token occurrence (not glued to word characters or '-') of a long-enough value."""
    for v in sorted(forms, key=len, reverse=True):
        if len(v) >= META_TOKEN_MIN and v != REDACTED:
            text = re.sub(rf"(?<![\w-]){re.escape(v)}(?![\w-])", REDACTED, text)
    return text


def _blank_region(region, forms):
    """A <metadata> region of raw XML: blank the values in its text and in its quoted attribute values, never in
    tag or attribute names (the markup stays well-formed)."""
    parts = re.split(r"(<[^>]*>)", region)
    for i, part in enumerate(parts):
        if i % 2 == 0:
            parts[i] = _blank_tokens(part, forms)
        else:
            parts[i] = _QUOTED.sub(lambda m: m.group(1) + m.group(2) + _blank_tokens(m.group(3), forms) + m.group(2), part)
    return "".join(parts)


def _redact_arg_tag(tag):
    """One <qemu:arg>/<qemu:env> start tag. If it may carry a secret (see _secret_ish), its value= is redacted:
    option by option for an arg, whole for an env, and whole for an arg when the option-wise result still looks
    secret or nothing changed (unsure)."""
    is_env = _is_env_tag(tag)
    if not _secret_ish("env" if is_env else "arg", _tag_attrs(tag)):
        return tag

    def fix(m):
        if m.group(1).lower() != "value":
            return m.group(0)
        plain = html.unescape(m.group(3))
        new = REDACTED if is_env else _redact_options(plain)
        if not plain.strip() or new == plain or _LEFT.search(new) or _CONT.search(new):
            new = REDACTED if plain.strip() else plain
        if new == plain:
            return m.group(0)
        return m.group(0)[:m.start(3) - m.start(0)] + html.escape(new, quote=True) + m.group(2)
    return _ATTR.sub(fix, tag)


def redact_xml(text):
    """Hide VNC/SPICE/any passwd|password|secret|token attribute and element text, and the secret values in
    <qemu:arg>/<qemu:env> (password=/secret data=/anything whose key says secret, comma-aware; a value is redacted
    whole when unsure); keep the key so C11 still sees that a password exists. Empty values stay empty. The password
    value is also blanked, as a whole token of >= META_TOKEN_MIN chars, in free text inside <metadata>."""
    forms = _escape_forms(_xml_secret_values(text))
    text = _METADATA.sub(lambda m: _blank_region(m.group(0), forms), text)
    text = _SECRET_ATTR.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", text)
    text = _SECRET_ELEM.sub(lambda m: m.group(0) if not m.group(3).strip()
                            else f"{m.group(1)}{REDACTED}{m.group(4)}", text)
    return _ARG_TAG.sub(lambda m: _redact_arg_tag(m.group(0)), text)


def _kv_redacted(m):
    quote = m.group(2)[0] if m.group(2)[0] in "\"'" else ""
    return f"{m.group(1)}{quote}{REDACTED}{quote}"


def redact_conf(text):
    """Conf files, /proc/cmdline, libvirtd.conf: blank the value of every vnc_password / spice_password line
    (commented ones, `##` and mid-line ones included) and of every other password/passwd/secret/token key."""
    text = _CONF_KEY.sub(lambda m: f'{m.group(1)}"{REDACTED}"', text)
    return _KV.sub(_kv_redacted, text)


def _option_values(value):
    """Secret option values of a QEMU option string, found by splitting on single commas (not by the redactor's
    regex). Both the raw (',,') and the unescaped (',') form are returned."""
    found = set()
    for token in re.split(r"(?<!,),(?!,)", value):
        key, _, val = token.partition("=")
        if val and (_KEYWORD.search(key) or key.strip().lower() == "data"):
            found.update({val, val.replace(",,", ",")})
    return found


def _arg_secret_values(local, attrs):
    """Original secret values of one arg/env element (attrs: decoded attribute dict, lowercase names)."""
    value = attrs.get("value", "")
    if not _secret_ish(local, attrs):
        return set()
    return {value} if local == "env" else _option_values(value)


def _arg_problem(local, attrs):
    """True if a redacted arg/env element still holds a secret (attrs: decoded attribute dict)."""
    value = attrs.get("value", "")
    if not _secret_ish(local, attrs):
        return False
    if _LEFT.search(value) or _CONT.search(value):
        return True
    if local == "env":
        return value not in ("", REDACTED)
    return re.search(r"(?i)(?<![\w.-])data=(?!REDACTED)", value) is not None


def _xml_secret_values(text):
    """Every original secret value in the XML text, found WITHOUT the redactor's regexes when the XML parses
    (ElementTree: decoded attributes and element text); the regexes are the fallback for broken XML."""
    found = set()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        root = None
    if root is not None:
        for el in root.iter():
            local = el.tag.rsplit("}", 1)[-1].lower()
            found.update(v for k, v in el.attrib.items() if k.rsplit("}", 1)[-1].lower() in _SECRET_NAMES)
            if local in _SECRET_NAMES and el.text:
                found.add(el.text.strip())
            if local in ("arg", "env"):
                found |= _arg_secret_values(local, {k.rsplit("}", 1)[-1].lower(): v for k, v in el.attrib.items()})
    else:
        found.update(html.unescape(m.group(3)) for m in _SECRET_ATTR.finditer(text))
        found.update(html.unescape(m.group(3).strip()) for m in _SECRET_ELEM.finditer(text))
        for m in _ARG_TAG.finditer(text):
            found |= _arg_secret_values("env" if _is_env_tag(m.group(0)) else "arg", _tag_attrs(m.group(0)))
    return found


def _conf_secret_values(text):
    found = set()
    for m in _CONF_KEY.finditer(text):
        v = _CONF_VALUE.match(m.group(2))
        if v:
            found.add(v.group(2) if v.group(1) else v.group(3))
    found.update(m.group(2).strip("\"'") for m in _KV.finditer(text))
    return found


def _leaked_values(redacted, originals, legit=("", "")):
    """The originals still present (raw or HTML-unescaped) in the redacted text. Short ones are skipped, and so is
    a value that also occurs as legitimate text in the original with its secret fields blanked (`legit` = (text
    outside <metadata>, metadata text with the value blanked as the redactor does)): the structural check, not a
    substring match, decides whether a secret FIELD still holds it. Metadata text only counts for long values:
    a short one cannot be blanked there, so it stays a leak."""
    plain = html.unescape(redacted)
    main, meta = (html.unescape(t) for t in legit)

    def is_legit(v):
        return v in main or (len(v) >= META_TOKEN_MIN and v in meta)
    return sorted(v for v in originals
                  if v and v != REDACTED and len(v) >= MIN_VERIFY_LEN and (v in redacted or v in plain)
                  and not is_legit(v))


def _xml_legit(text, originals):
    """(main, meta): the ORIGINAL XML with its secret fields blanked, split into the text outside <metadata> and
    the <metadata> regions (secret values blanked in those like the redactor does). Broken XML gives ('', ''):
    nothing is legitimate then, the strictest verdict."""
    if not _parses(text):
        return "", ""
    blanked = _SECRET_ATTR.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(2)}", text)
    blanked = _SECRET_ELEM.sub(lambda m: m.group(1) + m.group(4), blanked)

    def drop_arg_secrets(m):
        tag = m.group(0)
        for form in _escape_forms(_arg_secret_values("env" if _is_env_tag(tag) else "arg", _tag_attrs(tag))):
            tag = tag.replace(form, "")
        return tag
    blanked = _ARG_TAG.sub(drop_arg_secrets, blanked)
    forms = _escape_forms(originals)
    meta = "".join(_blank_region(m.group(0), forms) for m in _METADATA.finditer(blanked))
    return _METADATA.sub("", blanked), meta


def _conf_legit(text, _originals):
    """(main, meta) for a conf file: the text with every secret value blanked."""
    return _KV.sub(lambda m: m.group(1), _CONF_KEY.sub(lambda m: m.group(1), text)), ""


def _xml_structure_problems(redacted):
    """Independent re-check of the redacted XML: every secret attribute/element holds only '' or REDACTED, and no
    qemu arg/env still carries a secret."""
    try:
        root = ET.fromstring(redacted)
    except ET.ParseError:  # cannot walk it: fall back to the attribute and arg-tag regexes
        bad = [m.group(3) for m in _SECRET_ATTR.finditer(redacted) if m.group(3) != REDACTED]
        for m in _ARG_TAG.finditer(redacted):
            local = "env" if _is_env_tag(m.group(0)) else "arg"
            if _arg_problem(local, _tag_attrs(m.group(0))):
                bad.append(f"{local} secret")
        return bad
    bad = []
    for el in root.iter():
        local = el.tag.rsplit("}", 1)[-1].lower()
        bad += [k for k, v in el.attrib.items() if k.rsplit("}", 1)[-1].lower() in _SECRET_NAMES
                and v not in ("", REDACTED)]
        if local in _SECRET_NAMES and (el.text or "").strip() not in ("", REDACTED):
            bad.append(local)
        if local in ("arg", "env") and _arg_problem(local, {k.rsplit("}", 1)[-1].lower(): v for k, v in el.attrib.items()}):
            bad.append(f"{local} secret")
    return bad


def _verify_xml(redacted, originals, original_parsed, legit):
    leaks = _leaked_values(redacted, originals, legit)
    structure = _xml_structure_problems(redacted)
    broken = original_parsed and not _parses(redacted)
    return bool(leaks or structure or broken)


def _parses(text):
    try:
        ET.fromstring(text)
        return True
    except ET.ParseError:
        return False


def _verify_conf(redacted, originals, _parsed, legit):
    unredacted = [m for m in _CONF_KEY.finditer(redacted) if m.group(2).strip() != f'"{REDACTED}"']
    return bool(unredacted or _LEFT.search(redacted) or _CONT.search(redacted)
                or _leaked_values(redacted, originals, legit))


# kind -> (redactor, original-values finder, legit-text builder, verifier); looked up by name at call time so
# tests can swap them
def _kinds():
    return {"xml": (redact_xml, _xml_secret_values, _xml_legit, _verify_xml),
            "conf": (redact_conf, _conf_secret_values, _conf_legit, _verify_conf)}


def redact_checked(text, kind):
    """(redacted text, None) or (None, reason): the text is only returned if the verifier finds no original
    secret value left in it. Fail closed: a verifier error also yields (None, reason)."""
    redactor, finder, legit_text, verifier = _kinds()[kind]
    try:
        originals = finder(text)
        redacted = redactor(text)
        if verifier(redacted, originals, kind == "xml" and _parses(text), legit_text(text, originals)):
            return None, "redaction failed"
        return redacted, None
    except Exception as e:  # never write unverified text
        return None, f"redaction failed ({type(e).__name__})"


# ---- manifest -------------------------------------------------------------------------------
class Manifest:
    """What was collected, per expected file, plus items skipped inside a file (perms.txt rows)."""

    def __init__(self, vm):
        self.vm, self.files, self.skipped_items = vm, {}, []

    def record(self, name, status, reason="", explained=False):
        entry = {"status": status, "reason": reason}
        if explained:
            entry["explained"] = True
        self.files[name] = entry

    def live_problems(self):
        """Files that make the case incomplete: a LIVE file that is bad (missing/unreadable/skipped/dropped)
        without an explanation, or ANY file dropped by the redaction verifier (fail closed)."""
        bad = [n for n in LIVE_FILES
               if self.files.get(n, {}).get("status", "missing") in BAD_STATUS and not self.files.get(n, {}).get("explained")]
        return bad + [n for n, e in sorted(self.files.items()) if e["status"] == "dropped" and n not in bad]

    def as_dict(self):
        for n in EXPECTED_FILES:
            self.files.setdefault(n, {"status": "missing", "reason": "not collected"})
        return {"vm": self.vm, "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "files": dict(sorted(self.files.items())), "skipped_items": self.skipped_items,
                "live_problems": self.live_problems()}

    def report(self):
        """stderr lines for everything that is not ok/redacted."""
        for n, e in sorted(self.files.items()):
            if e["status"] in BAD_STATUS:
                print(f"collect: {n}: {e['status']} ({e['reason']})", file=sys.stderr)
        for it in self.skipped_items:
            print(f"collect: perms item {it['path']}: {it['status']} ({it['reason']})", file=sys.stderr)


def _store(out, man, name, text, empty_reason="empty"):
    if text and text.strip():
        (out / name).write_text(text, encoding="utf-8")
        man.record(name, "ok")
    else:
        man.record(name, "missing", empty_reason)


def _store_redacted(out, man, name, text, kind):
    redacted, bad = redact_checked(text, kind)
    if bad:
        man.record(name, "dropped", bad)
        return
    (out / name).write_text(redacted, encoding="utf-8")
    man.record(name, "redacted" if redacted != text else "ok")


def copy(src, dst, redact=None, man=None, kind=None):
    """Copy a host file (no symlinks, 1 MB cap). With a manifest, record the outcome under dst's name."""
    data, status, reason = read_file_ex(src)
    out, name = Path(dst).parent, Path(dst).name
    if status != "ok":
        man and man.record(name, status, reason)
    elif not data:
        man and man.record(name, "missing", "empty")
    else:
        text = data.decode("utf-8", "replace")
        if man is not None and kind:
            _store_redacted(out, man, name, text, kind)
        else:
            Path(dst).write_text(redact(text) if redact else text, encoding="utf-8")
            man and man.record(name, "ok")


def mode_row(tag, path, skipped=None):
    """`tag mode uid gid path` (path last, may contain spaces); None if missing, a symlink, or unreadable.
    A symlink or unreadable entry is appended to `skipped` (a list) as {path, status, reason}; a link's own
    mode (always 777) says nothing about its target, so it is never reported as a row."""
    def skip(status, reason):
        if skipped is not None:
            skipped.append({"path": path, "status": status, "reason": reason})
        return None
    if "\n" in path:
        return skip("unreadable", "newline in path")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return skip("missing", "does not exist")
    except OSError as e:
        return skip("unreadable", type(e).__name__)
    if stat.S_ISLNK(st.st_mode):
        return skip("symlink-skipped", "is a symlink")
    return f"{tag} {st.st_mode & 0o7777:03o} {st.st_uid} {st.st_gid} {path}"


def _check_out(out, allow_anywhere):
    if out.is_symlink():
        raise ValueError(f"refusing a symlinked output path: {out}")
    resolved = out.resolve()
    if not allow_anywhere and not any(resolved.is_relative_to(a.resolve()) for a in ALLOWED_OUT):
        raise ValueError(f"output must be inside {ROOT / 'cases'} or {ROOT / '.local'}: {resolved}")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise FileExistsError(f"refusing to write into existing non-empty path: {out}")


def net_isolation(vm_xml, read_network=None):
    """Host-side proof for C16. First line: 'isolated' (every exit check passed and every network is a bare
    host-only bridge; a VM with no NIC and no other exit counts), 'not-isolated: <reason>', or
    'unknown: <reason>' when the domain or a network XML cannot be read. Never trusts anything in the guest."""
    read_network = read_network or virsh_net_dumpxml
    problems = guards.exit_problems(vm_xml)
    if problems and problems[0].startswith(guards.UNPARSEABLE):
        return "unknown: vm.xml unparseable"
    if problems:
        return "not-isolated: " + "; ".join(problems[:3])
    for name in guards.interface_networks(vm_xml):
        if not VM_NAME.fullmatch(name):
            return f"not-isolated: bad network name {name!r}"
        try:
            net_problems = guards.network_problems(read_network(name))
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            return f"unknown: cannot read network {name}: {type(e).__name__}"
        if net_problems and net_problems[0].startswith(guards.UNPARSEABLE):
            return f"unknown: network {name} XML unparseable"
        if net_problems:
            return f"not-isolated: network {name} {'; '.join(net_problems)}"
    return "isolated"


def _cleanup(out, created):
    """Remove only what this run made: the folder if it created it, else the files inside an empty one."""
    if created:
        shutil.rmtree(out, ignore_errors=True)
    elif out.is_dir() and not out.is_symlink():
        for p in out.iterdir():
            p.unlink(missing_ok=True)


def _run(vm, out, allow_anywhere=False):
    if not VM_NAME.fullmatch(vm):
        raise ValueError(f"invalid VM name: {vm!r}")
    out = Path(out)
    _check_out(out, allow_anywhere)
    xml = virsh_dumpxml(vm)  # fail before creating anything
    # Re-check right before use: closes the TOCTOU window around the virsh round-trip above, during
    # which `out` could have been replaced by a symlink. exist_ok=True is deliberately not used:
    # it treats an existing symlink-to-a-directory as "already there, nothing to do" (pathlib checks
    # is_dir(), which follows symlinks), silently adopting an attacker-controlled target directory.
    _check_out(out, allow_anywhere)
    created = not out.exists()
    man = Manifest(vm)
    old_umask = os.umask(0o077)
    try:
        try:
            out.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            if out.is_symlink() or not out.is_dir():
                raise ValueError(f"refusing a symlinked or non-directory output path: {out}")
        os.chmod(out, 0o700)
        _store_redacted(out, man, "vm.xml", xml, "xml")
        _store(out, man, "net_isolation.txt", net_isolation(xml), "empty")
        _collect_host(vm, out, man)
        man.report()
        (out / MANIFEST).write_text(json.dumps(man.as_dict(), indent=1), encoding="utf-8")
    except BaseException as e:
        _cleanup(out, created)
        if not isinstance(e, Exception) or isinstance(e, VirshNotFound):
            raise
        raise RuntimeError(f"collect failed ({type(e).__name__}: {e}); removed partial output {out}") from e
    finally:
        os.umask(old_umask)
    return out, man


def collect(vm, out, allow_anywhere=False):
    """allow_anywhere=True lifts the cases/.local restriction (tests only). Returns the output folder; the
    manifest is written to <out>/collect_manifest.json."""
    return _run(vm, out, allow_anywhere)[0]


def _nested_value():
    """One value for all kvm_* modules (kvm_intel, kvm_amd): Y if any is Y, else the first non-empty one."""
    vals = [(read_file(n) or b"").decode("ascii", "replace").strip()
            for n in sorted(glob.glob("/sys/module/kvm_*/parameters/nested"))]
    vals = [v for v in vals if v]
    if not vals:
        return ""
    return "Y" if any(v in ("Y", "1") for v in vals) else vals[0]


def _collect_host(vm, out, man):
    copy("/etc/libvirt/qemu.conf", out / "qemu.conf", man=man, kind="conf")
    copy("/etc/libvirt/libvirtd.conf", out / "libvirtd.conf", man=man, kind="conf")
    copy("/proc/cmdline", out / "cmdline", man=man, kind="conf")
    copy("/sys/kernel/mm/ksm/run", out / "ksm_run", man=man)
    _store(out, man, "nested", _nested_value(), "no /sys/module/kvm_*/parameters/nested")
    if os.path.isdir("/sys/kernel/iommu_groups"):
        _store(out, man, "iommu_groups", str(len(glob.glob("/sys/kernel/iommu_groups/*"))))
    else:
        man.record("iommu_groups", "missing", "no /sys/kernel/iommu_groups")
    copy("/sys/devices/system/cpu/smt/active", out / "smt", man=man)
    vulns = []
    for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        data = read_file(p)
        if data:
            vulns.append(f"{Path(p).name}: {data.decode('utf-8', 'replace').strip()}")
    _store(out, man, "vulns.txt", "\n".join(vulns), "no readable vulnerability files")
    _collect_live(vm, out, man)
    kernel = sh("uname", "-r").strip()
    _store(out, man, "versions.txt", "".join(f"{k} {v}\n" for k, v in (("qemu", _qemu_version()), ("kernel", kernel)) if v),
           "qemu and kernel versions unavailable")


def _qemu_version():
    """`<version> (<rest of the banner's first line>)` from `qemu-system-x86_64 --version`, so M1 can see a distro
    build ('QEMU emulator version 7.2.9 (Debian 1:7.2.9+dfsg-0+deb12u1)'); None if there is no version."""
    banner = (sh("qemu-system-x86_64", "--version").strip().splitlines() or [""])[0]
    m = re.search(r"version\s+(\S+)(.*)", banner)
    if not m:
        return None
    suffix = re.search(r"\((.*)\)", m.group(2))
    text = clean_text(suffix.group(1)).strip()[:120] if suffix else ""
    return f"{m.group(1)} ({text})" if text else m.group(1)


def _collect_live(vm, out, man):
    """The QEMU process of this VM, then file modes. A missing pid file means the VM is not running, which
    explains missing qemu_status / qemu_label; everything else missing is unexplained."""
    pid = (read_file(f"/run/libvirt/qemu/{vm}.pid") or b"").decode("ascii", "replace").strip()
    if re.fullmatch(r"[0-9]+", pid):
        copy(f"/proc/{pid}/status", out / "qemu_status", man=man)
        copy(f"/proc/{pid}/attr/current", out / "qemu_label", man=man)
    else:
        for name in ("qemu_status", "qemu_label"):
            man.record(name, "missing", f"VM {vm} not running (no pid in /run/libvirt/qemu/{vm}.pid)", explained=True)
    rows, skipped = [], man.skipped_items
    for tag, pattern in (("image", "/var/lib/libvirt/images/*"), ("socket", "/run/libvirt/*-sock*")):
        rows += [mode_row(tag, p, skipped) for p in glob.glob(pattern)]
    for path in ("/var/lib/libvirt/qemu/save", "/var/lib/libvirt/qemu/dump"):
        rows.append(mode_row("savedir", path, skipped))
    rows = [r for r in rows if r]
    _store(out, man, "perms.txt", "\n".join(rows), "no image, socket or save-dir entries found")
    bad = [s for s in skipped if s["status"] in ("symlink-skipped", "unreadable")]
    if bad:  # the file exists but does not describe these paths: not a clean PASS source
        man.record("perms.txt", "symlink-skipped" if any(s["status"] == "symlink-skipped" for s in bad) else "unreadable",
                   f"{len(bad)} path(s) left out of perms.txt (see skipped_items)")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        out, man = _run(argv[0], argv[1])
    except (ValueError, RuntimeError, OSError) as e:  # VirshNotFound is a RuntimeError
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(out)
    bad = man.live_problems()
    if bad:
        print(f"collect: INCOMPLETE, live file(s) missing or skipped without an explanation: {', '.join(bad)}"
              f" (see {out / MANIFEST})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
