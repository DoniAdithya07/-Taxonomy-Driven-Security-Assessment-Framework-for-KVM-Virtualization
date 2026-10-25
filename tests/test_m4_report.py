import numpy as np

from vsec.m4_detect import features, simulate


def test_window_pooling_uses_first_k_windows(tmp_path):
    d = simulate.simulate(tmp_path / "s", per_class=2, windows=10)
    ses = features.load(d)
    X1, y, g, w = features.table(ses, 0.1, ("native", "kvm-plain"))
    X5, *_ = features.table(ses, 0.3, ("native", "kvm-plain"))
    assert X1.shape == X5.shape == (16, len(features.SIGNALS)) and set(y) == {0, 1}
    assert not np.allclose(X1, X5)


def test_nan_signal_is_dropped(tmp_path):
    ses = features.load(simulate.simulate(tmp_path / "s", per_class=2, windows=5))
    for s in ses:
        for arr in s["windows"].values():
            arr[:, features.SIGNALS.index("ipc")] = np.nan  # counters not exposed
    X, *_ = features.table(ses, 0.1, ("native", "kvm-plain"))
    assert features.SIGNALS.index("ipc") not in features.usable_columns(X)
