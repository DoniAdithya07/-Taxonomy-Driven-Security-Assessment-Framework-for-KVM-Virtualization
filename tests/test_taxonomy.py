from vsec import load_taxonomy


def test_every_control_is_complete_and_unique():
    tax = load_taxonomy()
    ids = [c["id"] for c in tax["controls"]]
    assert len(ids) == len(set(ids))
    for c in tax["controls"]:
        for k in ("id", "threat", "module", "control", "expected", "test", "fix", "source"):
            assert str(c.get(k) or "").strip(), (c.get("id"), k)
        assert c["type"] in ("live", "config", "version"), c["id"]
        assert c["severity"] in (1, 2, 3, 4), c["id"]
        assert c["threat"] in tax["threat_classes"], c["id"]
