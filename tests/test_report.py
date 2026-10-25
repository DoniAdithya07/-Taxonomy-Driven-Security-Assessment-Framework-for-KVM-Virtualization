import json

from vsec import finding, load_taxonomy, report


def class_ids(cls):
    return [c["id"] for c in load_taxonomy()["controls"] if c["threat"] == cls]


def all_findings(cls, status, vm):
    return [finding(i, status, vm=vm) for i in class_ids(cls)]


def test_matrix_counts_na_and_per_vm():
    f = [finding("C01", "PASS", vm="weak"), finding("C02", "NA", vm="weak"),
         finding("C03", "FAIL", vm="weak"), finding("C03", "PASS", vm="hardened")]
    m = report.matrix(f)
    assert m["classes"]["DMA/IOMMU"] == {"label": "Tested on E1", "controls": 2, "tested": 1, "na": 1,
                                         "effective_label": "Tested on E1"}
    assert m["vms"]["weak"]["Guest->Host"]["status"] == "FAIL"
    assert m["vms"]["hardened"]["Guest->Host"]["status"] == "PARTIAL"  # one control tested, the rest not
    assert m["vms"]["weak"]["DMA/IOMMU"] == {"status": "PARTIAL", "tested": 1, "na": 1, "controls": 2}


def test_pass_needs_every_control_tested():
    ids = class_ids("DMA/IOMMU")
    m = report.matrix(all_findings("DMA/IOMMU", "PASS", "vm"))
    assert m["vms"]["vm"]["DMA/IOMMU"]["status"] == "PASS"
    partial = [finding(ids[0], "PASS", vm="vm"), finding(ids[1], "NA", vm="vm")]
    assert report.matrix(partial)["vms"]["vm"]["DMA/IOMMU"]["status"] == "PARTIAL"
    assert report.matrix([finding(ids[0], "NA", vm="vm")])["vms"]["vm"]["DMA/IOMMU"]["status"] == "NA"


def test_tested_is_per_vm_not_pooled():
    ids = class_ids("DMA/IOMMU")
    f = [finding(ids[0], "PASS", vm="a"), finding(ids[1], "PASS", vm="b")]
    m = report.matrix(f)
    assert m["classes"]["DMA/IOMMU"]["tested"] == 2
    assert m["vms"]["a"]["DMA/IOMMU"]["tested"] == m["vms"]["b"]["DMA/IOMMU"]["tested"] == 1
    assert m["vms"]["a"]["DMA/IOMMU"]["status"] == m["vms"]["b"]["DMA/IOMMU"]["status"] == "PARTIAL"


def test_fail_beats_everything():
    f = all_findings("DMA/IOMMU", "PASS", "vm")[:1] + [finding(class_ids("DMA/IOMMU")[1], "FAIL", vm="vm")]
    assert report.matrix(f)["vms"]["vm"]["DMA/IOMMU"]["status"] == "FAIL"


def test_untested_class_is_labelled_and_rendered():
    m = report.matrix([finding("C01", "PASS", vm="v")])
    assert m["classes"]["Snapshot privacy"]["effective_label"] == "Not tested in this run"
    assert m["classes"]["DMA/IOMMU"]["effective_label"] == "Tested on E1"
    page = report.to_html({"matrix": m, "modules": {}, "notes": ["n"]})
    assert "Not tested in this run" in page


def test_html_shows_class_names_and_fail_cell():
    m = report.matrix([finding("C03", "FAIL", vm="weak"), finding("C01", "PASS", vm="weak")])
    page = report.to_html({"matrix": m, "modules": {}, "notes": []})
    assert "<table>" in page and "weak" in page
    for cls in m["classes"]:
        assert cls.replace(">", "&gt;") in page
    assert "<td>FAIL (1/" in page and "<td>PARTIAL (1/2 tested)</td>" in page


BANNER = "CONTAINS SIMULATED/SYNTHETIC DATA: not citable"


def test_banner_only_when_flagged():
    m = report.matrix([finding("C01", "PASS", vm="v")])
    base = {"matrix": m, "modules": {}, "notes": []}
    assert BANNER not in report.to_html(base)
    page = report.to_html({**base, "contains_simulated_or_synthetic": True})
    assert f"<b>{BANNER}</b>" in page and page.index(BANNER) < page.index("<h1>")


def test_contains_synthetic_looks_at_every_module_flag():
    assert not report.contains_synthetic({"M1": {"status": "ok"}, "M3": {"status": "NA"}})
    assert report.contains_synthetic({"M2": {"synthetic": True}})
    assert report.contains_synthetic({"M1": {}, "M4": {"simulated": True}})


def test_write_keeps_flag_in_json_and_banner_in_html(tmp_path):
    rep = {"contains_simulated_or_synthetic": True, "notes": [], "modules": {"M4": {"simulated": True}},
           "findings": [], "matrix": report.matrix([])}
    page = report.write(rep, tmp_path / "o")
    assert json.loads((tmp_path / "o" / "report.json").read_text())["contains_simulated_or_synthetic"] is True
    assert BANNER in page.read_text(encoding="utf-8")


MODULES = {"M1": {"status": "ok"}, "M2": {"status": "ERROR", "reason": "RuntimeError: boom <b>", "traceback": "tb"},
           "M3": {"status": "NA", "reason": "no results"}, "M4": {"synthetic": True}}


def test_failed_and_na_modules_are_listed_separately():
    assert report.failed_modules(MODULES) == [{"name": "M2", "reason": "RuntimeError: boom <b>"}]
    assert report.na_modules(MODULES) == [{"name": "M3", "reason": "no results"}]
    assert report.failed_modules({"M1": {"status": "ok"}}) == [] == report.na_modules({})


def test_an_error_module_is_not_synthetic_data():
    assert not report.contains_synthetic({"M2": MODULES["M2"]})  # a separate flag: failure is not simulation


def test_red_banner_lists_failed_modules_escaped_and_keeps_the_synthetic_banner():
    m = report.matrix([finding("C01", "PASS", vm="v")])
    base = {"matrix": m, "modules": MODULES, "notes": []}
    assert "MODULES FAILED" not in report.to_html({**base, "modules_failed": []})
    page = report.to_html({**base, "modules_failed": report.failed_modules(MODULES),
                           "contains_simulated_or_synthetic": True})
    assert "<p class=banner><b>MODULES FAILED: results incomplete.</b> M2: RuntimeError: boom &lt;b&gt;</p>" in page
    assert "boom <b>" not in page.split("<h1>")[0]  # nothing unescaped before the content
    assert BANNER in page and page.index("MODULES FAILED") < page.index("<h1>")


def test_write_keeps_failed_modules_in_json(tmp_path):
    rep = {"modules_failed": [{"name": "M2", "reason": "x"}], "modules_na": [], "notes": [], "modules": MODULES,
           "findings": [], "matrix": report.matrix([])}
    report.write(rep, tmp_path / "o")
    assert json.loads((tmp_path / "o" / "report.json").read_text())["modules_failed"] == [{"name": "M2", "reason": "x"}]
