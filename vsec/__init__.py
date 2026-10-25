"""vsec: taxonomy-driven security assessment framework for KVM virtualization."""
import functools
import json
import math
from pathlib import Path

import yaml

HERE = Path(__file__).parent
ROOT = HERE.parent

# C0/C1 control characters (ESC, NUL, CR, ...) are dropped; newline and tab become a space
_CONTROL = {c: None for c in (*range(32), *range(127, 160))}
_CONTROL.update({10: " ", 9: " "})
# Unicode characters that reorder, hide or split text: bidi embeddings/isolates, zero-width marks, line/paragraph
# separators and the byte-order mark
_CONTROL.update({c: None for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), *range(0x200B, 0x2010),
                                   0x2028, 0x2029, 0xFEFF)})


@functools.lru_cache(maxsize=None)
def load_taxonomy():
    return yaml.safe_load((HERE / "taxonomy.yaml").read_text(encoding="utf-8"))


def control_index():
    return {c["id"]: c for c in load_taxonomy()["controls"]}


def clean_text(s):
    """Evidence text safe to store and print: control characters and invisible/bidi Unicode removed, so captured
    host or guest text cannot drive a terminal, reorder it or hide content."""
    return str(s).translate(_CONTROL)


def finding(cid, status, evidence="", env="E0", vm="", **extra):
    """One finding in the common format. status: PASS | FAIL | NA. Evidence is stripped of control characters."""
    if status not in ("PASS", "FAIL", "NA"):
        raise ValueError(f"bad status: {status!r}")
    c = control_index()[cid]
    f = {"id": cid, "module": c["module"], "taxonomy": c["threat"], "control": c["control"],
         "status": status, "severity": c["severity"], "evidence": clean_text(evidence),
         "fix": c["fix"] if status == "FAIL" else "", "env": env, "vm": vm}
    f.update(extra)
    return f


def jsonable(o):
    """Plain-JSON copy of o: numpy values become Python ones, NaN/inf become None (valid JSON)."""
    if hasattr(o, "tolist"):
        o = o.tolist()
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [jsonable(v) for v in o]
    if isinstance(o, float) and not math.isfinite(o):
        return None
    return o


def dump_json(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(jsonable(obj), indent=1, default=str, allow_nan=False), encoding="utf-8")
