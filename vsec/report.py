"""Result matrix and JSON/HTML report. Works from findings only, so dummy findings render too."""
import html
from collections import defaultdict
from pathlib import Path

from . import dump_json, load_taxonomy


NOT_TESTED = "Not tested in this run"


def _vm_class_status(ids, statuses):
    """statuses: control -> set of statuses for one VM. PASS only if every control was tested and passed."""
    tested = {i for i in ids if statuses.get(i, set()) - {"NA"}}
    if any("FAIL" in statuses.get(i, ()) for i in ids):
        status = "FAIL"
    elif ids and len(tested) == len(ids):
        status = "PASS"
    else:
        status = "PARTIAL" if tested else "NA"
    return {"status": status, "tested": len(tested), "na": len(ids) - len(tested), "controls": len(ids)}


def matrix(findings):
    """Per threat class: label, controls, tested, N/A. Per VM and class: status/tested/controls (never pooled)."""
    tax = load_taxonomy()
    controls = defaultdict(set)
    for c in tax["controls"]:
        controls[c["threat"]].add(c["id"])
    seen = defaultdict(lambda: defaultdict(set))  # class -> control -> statuses
    per_vm = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))  # vm -> class -> control -> statuses
    for f in findings:
        seen[f["taxonomy"]][f["id"]].add(f["status"])
        per_vm[f["vm"]][f["taxonomy"]][f["id"]].add(f["status"])
    classes = {}
    for cls, label in tax["threat_classes"].items():
        ids = controls[cls]
        tested = {i for i in ids if seen[cls][i] - {"NA"}}
        classes[cls] = {"label": label, "controls": len(ids), "tested": len(tested), "na": len(ids) - len(tested),
                        "effective_label": label if tested else NOT_TESTED}
    vms = {vm: {cls: _vm_class_status(controls[cls], d[cls]) for cls in tax["threat_classes"]}
           for vm, d in per_vm.items()}
    return {"classes": classes, "vms": vms}


def _table(rows, head):
    th = "".join(f"<th>{html.escape(str(h))}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{th}</tr>{body}</table>"


def _cell(v):
    return f"{v['status']} ({v['tested']}/{v['controls']} tested)" if v else ""


def contains_synthetic(modules):
    """True if any module result is flagged synthetic or simulated."""
    return any(m.get("synthetic") or m.get("simulated") for m in modules.values())


def failed_modules(modules):
    """[{name, reason}] for every module whose status is ERROR (it crashed; NA means no data was supplied)."""
    return [{"name": n, "reason": m.get("reason", "")} for n, m in modules.items() if m.get("status") == "ERROR"]


def na_modules(modules):
    return [{"name": n, "reason": m.get("reason", "")} for n, m in modules.items() if m.get("status") == "NA"]


def to_html(report):
    m = report["matrix"]
    parts = ["<!doctype html><meta charset=utf-8><title>vsec report</title>",
             "<style>body{font:14px sans-serif;margin:2em}table{border-collapse:collapse;margin:1em 0}"
             "td,th{border:1px solid #999;padding:4px 8px}.n{background:#ffe9a8;padding:6px}"
             ".banner{background:#b00020;color:#fff;padding:10px;font-size:18px}</style>"]
    failed = report.get("modules_failed")
    if failed:
        listing = "; ".join(f"{f['name']}: {f['reason']}" for f in failed)
        parts.append(f"<p class=banner><b>MODULES FAILED: results incomplete.</b> {html.escape(listing)}</p>")
    if report.get("contains_simulated_or_synthetic"):
        parts.append("<p class=banner><b>CONTAINS SIMULATED/SYNTHETIC DATA: not citable</b></p>")
    parts.append("<h1>vsec report</h1>")
    for n in report.get("notes", []):
        parts.append(f"<p class=n>{html.escape(n)}</p>")
    parts.append("<h2>Threat classes</h2>" + _table(
        [(c, v["effective_label"], v["controls"], v["tested"], v["na"]) for c, v in m["classes"].items()],
        ["Threat class", "Label", "Controls", "Tested", "N/A"]))
    if m["vms"]:
        classes = list(m["classes"])
        parts.append("<h2>Per VM</h2>" + _table(
            [(vm, *[_cell(d.get(c)) for c in classes]) for vm, d in m["vms"].items()], ["VM", *classes]))
    for name, sect in report["modules"].items():
        parts.append(f"<h2>{html.escape(name)}</h2><pre>{html.escape(_pretty(sect))}</pre>")
    return "".join(parts)


def _pretty(o, ind=0):
    pad = "  " * ind
    if isinstance(o, dict):
        return "\n".join(f"{pad}{k}:" + (("\n" + _pretty(v, ind + 1)) if isinstance(v, (dict, list)) and v else f" {_fmt(v)}")
                         for k, v in o.items())
    if isinstance(o, list):
        if all(not isinstance(x, (dict, list)) for x in o):
            return pad + ", ".join(_fmt(x) for x in o)
        return "\n".join(_pretty(x, ind + 1) for x in o)
    return pad + _fmt(o)


def _fmt(v):
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def write(report, out_dir):
    out = Path(out_dir)
    dump_json(report, out / "report.json")
    (out / "report.html").write_text(to_html(report), encoding="utf-8")
    return out / "report.html"
