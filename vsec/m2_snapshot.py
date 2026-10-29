"""M2: snapshot privacy. Scan memory dumps for secrets, redact them, score against planted ground truth.

A dump is bytes plus a manifest {"cell": "<type>/<state>[/<variant>]", "needles": [hex, ...]}.
Ground truth: a planted secret is *present* only if every needle is found by an exact byte search. Needles and
planted entries must each be >= 16 bytes, and every planted entry must contain a needle (for the 'split'
variant: both halves), so a manifest cannot "plant" something trivial or unrelated.
Scanner rules are plain ASCII patterns, written without looking at the held-out variants.

The manifest is written by whoever plants the secrets, and in a real run that is code inside the guest, so it is
treated as untrusted input. It is checked against the scanner's own rules (see _validate_manifest): the cell must be
on an allow-list, every needle must match the rule of its declared kind IN FULL (PEM block, 20-char AKIA id or
40-char AWS secret, JWT, 64 hex chars; for utf16/base64/split cells the decoded or re-joined text), and a needle may
not be a slice of a scanner hit unless it equals the whole rule match. Best practice: generate the manifest on the
HOST from the secret the host passes in, with make_manifest(kind, state, secret, variant=None), not in the guest.
What still cannot be proven here: that the needle really was planted by the host; the checks only make a lying
manifest expensive and visible.

Known limitation (documented, not fixable by a pattern): any genuine 64-hex string with enough entropy, such as
a real SHA-256 digest, is indistinguishable from a 32-byte hex secret and is flagged by the hex32 rule.
"""
import base64
import binascii
import json
import math
import mmap
import os
import random
import re
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path

from . import ROOT, guards
from .score import wilson
from .secrets_gen import make_secret, plant_text

TYPES = ("ssh_key", "aws", "jwt", "hex32")
STATES = ("live", "freed", "exited")
VARIANTS = ("split", "utf16", "base64")
PAGE = 4096
MIN_ENTRY_BYTES = 16
REDACT_CHUNK = 64 * 2**20
# Must be >= the longest possible single match so "a match crossing a chunk edge is seen whole"
# (see redact_file's docstring) actually holds for every current RULE: ssh_key's body is capped at
# 8192 chars plus the BEGIN/END header/footer (~80 chars). 1024 used to be smaller than that, so a
# private key straddling a chunk boundary could be silently left unredacted.
REDACT_OVERLAP = 16384
_HEX = re.compile(r"([0-9a-fA-F]{2})+")
MARKER = ROOT / ".local" / "target.reverted"  # written by scripts/preflight_target.py --mark-reverted
_CELL = re.compile(r"(?:(?:ssh_key|aws|jwt|hex32)/(?:live|freed|exited)(?:/(?:split|utf16|base64))?"
                   r"|real/[a-z0-9_-]{1,32}|negative)")

RULES = {
    # bounded body (<= 8192 chars) that cannot run into the next BEGIN: linear time even on 8000 repeated headers
    "ssh_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?!-----BEGIN)[A-Za-z0-9+/=\s:,.\\-]){40,8192}?"
                          rb"-----END [A-Z ]*PRIVATE KEY-----"),
    "aws_id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(rb"(?i)aws_secret_access_key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+]{40})"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    "hex32": re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"),
}
# what a needle of each declared kind must look like in full (aws: the 20-char key id or the 40-char secret)
NEEDLE_RULES = {
    "ssh_key": RULES["ssh_key"],
    "aws": re.compile(rb"AKIA[0-9A-Z]{16}|[A-Za-z0-9/+]{40}"),
    "jwt": RULES["jwt"],
    "hex32": re.compile(rb"[0-9a-fA-F]{64}"),
}
MIN_ENTROPY = 3.0  # bits per char; rejects "0000..." and "abab..." that match hex32


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in (b.count(x) for x in set(b)))


def _matches(data):
    """Yield (rule, match, group): the group is the secret part (aws_secret: the value after the key name)."""
    for name, rx in RULES.items():
        for m in rx.finditer(data):
            if name == "hex32" and entropy(m.group()) < MIN_ENTROPY:
                continue
            yield name, m, 1 if name == "aws_secret" else 0


def scan(data):
    """Return [(rule, start, end, matched_bytes)]."""
    return [(name, m.start(g), m.end(g), m.group(g)) for name, m, g in _matches(data)]


def redact(data):
    """Overwrite every hit with zeros (same size). Takes bytes and returns a COPY: needs 2x memory, so use
    redact_file() for multi-GB `virsh save` images."""
    out = bytearray(data)
    for _, s, e, _ in scan(data):
        out[s:e] = bytes(e - s)
    return bytes(out)


def redact_file(path, chunk=REDACT_CHUNK, overlap=REDACT_OVERLAP):
    """Zero every hit in the file in place, streaming `chunk` bytes at a time. Each window reads `overlap`
    extra bytes so a match crossing a chunk edge is seen whole; a hit starting inside the overlap is left to
    the next window. Matches longer than `overlap` that cross an edge are only partly seen (known limit).
    Returns the number of hits zeroed."""
    zeroed = 0
    with open(path, "r+b") as f:
        size = os.fstat(f.fileno()).st_size
        for pos in range(0, size, chunk):
            f.seek(pos)
            window = f.read(chunk + overlap)
            last = pos + chunk >= size
            for _, m, g in _matches(window):
                s, e = m.start(g), m.end(g)
                # own the hit by where the whole match starts: the next window cannot see a key name before its start
                if m.start() < chunk or last:
                    f.seek(pos + s)
                    f.write(bytes(e - s))
                    zeroed += 1
    return zeroed


# ---- synthetic ground truth -------------------------------------------------------------
def background(rng, size, state):
    """Zero pages, text-like pages and random pages, as in a real guest dump."""
    pages = []
    for _ in range(size // PAGE):
        t = rng.random()
        if t < 0.5:
            pages.append(bytes(PAGE))
        elif t < 0.8:
            pages.append((rng.choice([b"kernel ", b"/usr/lib ", b"GET / HTTP/1.1 ", b"0x7ffc "]) * 600)[:PAGE])
        else:
            pages.append(rng.randbytes(PAGE))
    return bytearray(b"".join(pages))


def make_manifest(kind, state, secret, variant=None):
    """The manifest {"cell", "needles", "planted"} (hex strings) for a secret the HOST chose: the plant flows
    and tests call this instead of letting the guest describe what it planted. `secret` is the str that
    make_secret() returns; the memory image of the planted bytes is `planted`."""
    if kind not in TYPES or state not in STATES or variant not in (None, *VARIANTS):
        raise ValueError(f"bad cell: kind={kind!r} state={state!r} variant={variant!r}")
    text = plant_text(kind, secret).encode()
    planted = text  # the bytes actually written to memory (the encoded form for utf16/base64)
    if variant is None:
        needles = [secret.encode()]
    elif variant == "utf16":
        planted = text.decode().encode("utf-16-le")
        needles = [planted]
    elif variant == "base64":
        planted = base64.b64encode(text)
        needles = [planted]
    else:  # split: two halves, planted separately
        half = len(text) // 2
        needles = [text[:half], text[half:]]
    cell = f"{kind}/{state}" + (f"/{variant}" if variant else "")
    return {"cell": cell, "needles": [n.hex() for n in needles], "planted": [planted.hex()]}


def build_dump(kind, state, variant, size, rng):
    buf = background(rng, size, state)
    secret = make_secret(kind, rng)
    manifest = make_manifest(kind, state, secret, variant)
    text = plant_text(kind, secret).encode()
    if size < 12 * PAGE + 4 * len(text):
        raise ValueError(f"size {size} too small: need >= 12 pages + 4x the secret ({12 * PAGE + 4 * len(text)})")
    off = rng.randrange(PAGE, size - 10 * PAGE - len(text) * 4)
    if state == "freed":  # a freed buffer keeps stale text around the secret
        off = off // PAGE * PAGE
        buf[off - 16:off] = b"free-list-ptr...."[:16] if off >= 16 else b""
    elif state == "exited":  # exited process leaves the secret in an otherwise zeroed page
        page = off // PAGE * PAGE
        buf[page:page + PAGE] = bytes(PAGE)
        off = page + 64

    def put(pos, data):  # strings in memory end somewhere: a newline stops the token rules at the secret's end
        buf[pos:pos + len(data) + 1] = data + b"\n"

    if variant == "split":  # first half at the end of one page, second half in a page 7 pages away
        halves = [bytes.fromhex(h) for h in manifest["needles"]]
        a = (off // PAGE + 1) * PAGE - len(halves[0])
        put(a, halves[0])
        put(a + len(halves[0]) + 7 * PAGE, halves[1])
    else:
        put(off, bytes.fromhex(manifest["planted"][0]))
    return bytes(buf), manifest


def synthetic_dumps(n=10, size=256 * 1024, seed=1):
    rng = random.Random(seed)
    for kind in TYPES:
        for state in STATES:
            for _ in range(n):
                yield build_dump(kind, state, None, size, rng)
    for variant in VARIANTS:
        for kind in TYPES:
            for _ in range(n):
                yield build_dump(kind, "live", variant, size, rng)
    for i in range(2 * n):  # negative controls: empty dumps and high-entropy padding
        buf = background(rng, size, "live") if i % 2 == 0 else bytearray(rng.randbytes(size))
        yield bytes(buf), {"cell": "negative", "needles": []}


def _validate_manifest(man, where):
    if not isinstance(man, dict):
        raise ValueError(f"{where}: manifest must be an object")
    if not isinstance(man.get("cell"), str) or not man["cell"]:
        raise ValueError(f"{where}: manifest 'cell' must be a non-empty string")
    if not _CELL.fullmatch(man["cell"]):
        raise ValueError(f"{where}: manifest cell {man['cell'][:40]!r} is not an allowed cell name")
    for key, required in (("needles", True), ("planted", False)):
        if key not in man and not required:
            continue
        vals = man.get(key)
        if not isinstance(vals, list):
            raise ValueError(f"{where}: manifest '{key}' must be a list of hex strings")
        for v in vals:
            if not isinstance(v, str) or not _HEX.fullmatch(v):
                raise ValueError(f"{where}: manifest '{key}' has an invalid hex entry {str(v)[:20]!r}")
            if len(v) < 2 * MIN_ENTRY_BYTES:
                raise ValueError(f"{where}: manifest '{key}' entry {v[:20]!r} is shorter than {MIN_ENTRY_BYTES} bytes")
    _check_needle_rules(man["cell"], [bytes.fromhex(h) for h in man["needles"]], where)
    _check_planted_contain_needles(man, where)


def _decode_variant(needle, variant):
    """The text behind a utf16/base64 needle, or None if it does not decode."""
    try:
        if variant == "utf16":
            return needle.decode("utf-16-le").encode("ascii")
        return base64.b64decode(needle, validate=True)
    except (UnicodeError, binascii.Error):
        return None


def _is_whole_secret(kind, text):
    """True if `text` is one complete secret of `kind` (any kind for a real program). aws plants carry the key id
    and the secret as two assignments, so decoded or re-joined aws text only has to contain a full rule match."""
    if kind == "aws" and len(text) > 40:
        return any(RULES[r].search(text) for r in ("aws_id", "aws_secret"))
    rules = NEEDLE_RULES.values() if kind == "real" else [NEEDLE_RULES[kind]]
    return any(rx.fullmatch(text) for rx in rules)


def _check_needle_rules(cell, needles, where):
    """Each needle must be the scanner's own rule match for the declared kind, in full: a guest-written manifest
    cannot claim a trivial or unrelated byte string as a planted secret."""
    parts = cell.split("/")
    kind, variant = parts[0], (parts[2] if len(parts) == 3 else None)
    if kind == "negative":
        if needles:
            raise ValueError(f"{where}: a negative cell must have no needle")
        return
    if variant == "split":
        if len(needles) != 2:
            raise ValueError(f"{where}: a split cell needs exactly two needles (the two halves), got {len(needles)}")
        texts = [b"".join(needles)]
    elif variant in ("utf16", "base64"):
        texts = [_decode_variant(n, variant) for n in needles]
    else:
        texts = needles
    for n, text in zip(needles if variant != "split" else needles[:1], texts):
        if text is None or not _is_whole_secret(kind, text):
            raise ValueError(f"{where}: needle {n[:20].hex()}... does not match the {kind} rule in full "
                             f"(cell {cell!r})")


def _check_planted_contain_needles(man, where):
    needles = [bytes.fromhex(h) for h in man["needles"]]
    split = man["cell"].count("/") == 2 and man["cell"].endswith("/split")
    for h in man.get("planted", []):
        planted = bytes.fromhex(h)
        found = [n in planted for n in needles]
        if not (all(found) if split else any(found)) or not needles:
            raise ValueError(f"{where}: a planted entry does not contain "
                             f"{'both halves' if split else 'a needle'}: planted text and needles disagree")
        if len(planted) > 4 * sum(map(len, needles)):  # an oversized blob would hide false positives
            raise ValueError(f"{where}: a planted entry is more than 4x as long as the needles")


def _reject_slices(needles, hits, where):
    """A needle inside a scanner hit must BE the hit: a slice of a real hit would count a secret that was
    already in the dump as planted and detected."""
    for n in needles:
        if any(n != h[3] and n in h[3] for h in hits):
            raise ValueError(f"{where}: a needle is a slice of a scanner hit, not the whole rule match")


def load_dumps(folder):
    """Real dumps: <name>.mem next to <name>.json with the manifest. Validates everything up front, then
    returns a generator that memory-maps each .mem read-only (multi-GB dumps are never read whole)."""
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"dump folder not found: {folder}")
    jsons = {p.stem: p for p in folder.glob("*.json")}
    mems = {p.stem: p for p in folder.glob("*.mem")}
    unpaired = sorted(set(jsons) ^ set(mems))
    if unpaired:
        raise ValueError(f"{folder}: .json/.mem files without a partner: {', '.join(unpaired)}")
    if not jsons:
        raise ValueError(f"{folder}: no dumps (<name>.mem + <name>.json) found")
    pairs = []
    for name in sorted(jsons):
        try:
            man = json.loads(jsons[name].read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"{jsons[name].name}: invalid JSON: {e}") from e
        _validate_manifest(man, jsons[name].name)
        if mems[name].stat().st_size == 0:
            raise ValueError(f"{mems[name].name}: empty dump")
        pairs.append((mems[name], man))
    return _iter_mapped(pairs)


def _iter_mapped(pairs):
    for mem, man in pairs:
        with open(mem, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield data, man


# ---- evaluation -------------------------------------------------------------------------
def _group(cell):
    if cell.startswith("real/"):
        return "real_programs"
    return {1: "plain", 2: "held_out"}.get(cell.count("/"))


def _ratio_stats(d, p, absent):
    return {"detected": d, "present": p, "planted_but_absent": absent,
            "recall": d / p if p else None, "ci": wilson(d, p)}


def evaluate(dumps, synthetic=False):
    """Score dumps ((bytes-like, manifest) pairs). Recall is detected / present (all needles found).
    Planted dumps whose needles are NOT all found are counted per cell as `planted_but_absent`, never dropped
    silently. Raises ValueError for zero dumps or a bad manifest. Redaction overwrites in place, so it adds
    no size: size_overhead_bytes is 0 by construction (tested via len(redact(x)) == len(x))."""
    cells = defaultdict(lambda: [0, 0, 0])  # cell -> [detected, present, planted_but_absent]
    fp = size = count = total_hits = 0
    scan_seconds = 0.0
    for i, (data, man) in enumerate(dumps):
        count += 1
        _validate_manifest(man, f"dump #{i} (cell {man.get('cell')!r})" if isinstance(man, dict) else f"dump #{i}")
        needles = [bytes.fromhex(h) for h in man["needles"]]
        t0 = time.perf_counter()
        hits = scan(data)
        scan_seconds += time.perf_counter() - t0
        _reject_slices(needles, hits, f"dump #{i} (cell {man['cell']!r})")
        total_hits += len(hits)
        if needles:
            row = cells[man["cell"]]
            if all(data.find(n) != -1 for n in needles):
                row[1] += 1
                row[0] += any(n in h[3] for h in hits for n in needles)
            else:
                row[2] += 1
        planted = [bytes.fromhex(h) for h in man.get("planted", [])] + needles  # a hit is no FP only inside planted text
        fp += sum(1 for h in hits if not any(h[3] in p for p in planted))
        size += len(data)
    if not count:
        raise ValueError("evaluate() got zero dumps")
    gb = size / 2**30
    out = {"cells": {c: _ratio_stats(*v) for c, v in sorted(cells.items())},
           "synthetic": synthetic, "dumps": count,
           "total_hits": total_hits, "total_bytes": size,
           "false_positives": fp, "gb_scanned": gb, "fp_per_gb": fp / gb if gb else None,
           "scan_seconds": scan_seconds, "size_overhead_bytes": 0}
    for group in ("plain", "held_out", "real_programs"):
        v = [r for c, r in cells.items() if _group(c) == group]
        out[group] = _ratio_stats(sum(r[0] for r in v), sum(r[1] for r in v), sum(r[2] for r in v))
    return out


# ---- virsh save -> redact -> restore ----------------------------------------------------
def _virsh(*args, timeout=300):
    return guards.virsh(*args, timeout=timeout)  # always `virsh -c qemu:///system`


def assert_isolated(network):
    """Raise RuntimeError unless the libvirt network is a bare host-only bridge (guards.network_problems)."""
    guards.assert_isolated(network, _virsh)


def assert_vm_isolated(vm):
    """Raise RuntimeError if the domain XML shows any way out (guards.exit_problems) or a non-isolated network."""
    guards.assert_vm_isolated(vm, _virsh)


_assert_vm_isolated = assert_vm_isolated  # deprecated alias, kept for old callers


def assert_no_hostdev(vm):
    """Raise RuntimeError if the domain passes a host device through (<hostdev>): that is a path to host hardware."""
    guards.assert_no_hostdev(vm, _virsh)


def assert_no_other_running_domain(vm):
    """Raise RuntimeError if any libvirt domain other than `vm` is running (kvm-plain, kvm-masked, anything)."""
    guards.assert_no_other_running_domain(vm, _virsh)


def assert_links_down(vm):
    """Raise RuntimeError unless every interface link is confirmed down (see guards.assert_links_down)."""
    guards.assert_links_down(vm, _virsh)


def _private_dir_path(image_dir):
    path = Path(image_dir).resolve()
    local = (ROOT / ".local").resolve()
    if not path.is_relative_to(local):
        raise ValueError(f"image dir must be inside this project's .local folder ({local}): {path}")
    return path


def _count_hits(path):
    if os.path.getsize(path) == 0:
        return 0
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        return len(scan(data))


def _require_marker(vm, marker, max_age_minutes):
    """RuntimeError unless a fresh revert marker bound to this domain's uuid exists (see preflight_target.py)."""
    try:
        uuid = guards.domain_uuid(vm, _virsh)
    except subprocess.TimeoutExpired:
        raise RuntimeError("timeout reading the domain uuid") from None
    guards.check_marker(marker or MARKER, vm, max_age_minutes, uuid=uuid)


def restore_test(vm, image_dir, marker=None, max_age_minutes=15):
    """virsh save -> redact -> virsh restore -> VM running? Only for the isolated `target` VM, with the image in
    a fresh 0700 folder under <repo>/.local that is always deleted. Needs the same fresh revert marker as the
    preflight gate (<repo>/.local/target.reverted, bound to the domain uuid); it is used up once the isolation
    checks pass, so every save/restore follows a new revert. Raises ValueError (bad vm or folder) or
    RuntimeError (no valid marker, network not isolated). Returns {"status": OK|FAILED|NA, "reason", "restored",
    "same_scanner_rescan_hits", "service_check"} plus "cleanup_error" if the image or folder could not be
    deleted; NA means virsh is not installed. Note: after a failed restore the VM stays shut off."""
    if vm != "target":
        raise ValueError(f"restore_test only runs on the 'target' VM, not {vm!r}")
    folder = _private_dir_path(image_dir)
    res = {"status": "FAILED", "reason": "", "restored": False, "same_scanner_rescan_hits": 0,
           "service_check": "NA (not automated)"}
    if shutil.which("virsh") is None:
        res.update(status="NA", reason="virsh not installed")
        return res
    _require_marker(vm, marker, max_age_minutes)
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir(mode=0o700, parents=False)  # FileExistsError if not fresh: a pre-existing folder is never touched
    image = folder / f"{vm}.save"
    phase = "setup"
    try:
        os.chmod(folder, 0o700)
        phase = "isolation check"
        assert_vm_isolated(vm)
        assert_no_hostdev(vm)
        assert_no_other_running_domain(vm)
        assert_links_down(vm)
        (marker or MARKER).unlink(missing_ok=True)  # single use, as in the preflight gate
        phase = "virsh save"
        r = _virsh("save", vm, str(image))
        if r.returncode:
            res["reason"] = f"virsh save failed: {r.stderr.strip()[-200:]}"
            return res
        if not image.is_file():
            res["reason"] = "virsh save wrote no image"
            return res
        phase = "redaction"
        redact_file(image)
        res["same_scanner_rescan_hits"] = _count_hits(image)
        phase = "virsh restore (after redaction)"
        r = _virsh("restore", str(image))
        if r.returncode:
            res["reason"] = f"virsh restore failed after redaction: {r.stderr.strip()[-200:]}"
            return res
        res["restored"] = "running" in _virsh("domstate", vm, timeout=60).stdout
        if not res["restored"]:
            res["reason"] = "restore returned success but the VM is not running (after redaction)"
        elif res["same_scanner_rescan_hits"]:
            res["reason"] = "scanner still finds secrets after redaction"
        else:
            res.update(status="OK", reason="restored and running; rescan clean")
        return res
    except subprocess.TimeoutExpired:
        res["reason"] = f"timeout during {phase}"
        return res
    except FileNotFoundError as e:
        if shutil.which("virsh") is None:
            res.update(status="NA", reason="virsh not installed")
        else:
            res["reason"] = f"{phase}: {e}"
        return res
    except OSError as e:
        res["reason"] = f"{phase}: {e}"
        return res
    finally:
        _remove_private_folder(folder, image, res)


def _remove_private_folder(folder, image, res):
    """Delete the saved image and its folder. A failure is recorded in res['cleanup_error'], never raised, so
    it cannot replace the result."""
    errors = []
    for step in (lambda: image.unlink(missing_ok=True), folder.rmdir):
        try:
            step()
        except OSError as e:
            errors.append(f"{type(e).__name__}: {e}")
    if errors:
        res["cleanup_error"] = "; ".join(errors)
