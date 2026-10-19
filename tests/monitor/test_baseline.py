import pandas as pd
from monitor.baseline import build_baseline


def test_build_baseline_returns_dataframe():
    df = build_baseline(days=30, seed=42)
    assert isinstance(df, pd.DataFrame)
    assert set(df.columns) == {"timestamp", "value", "destination"}
    assert len(df) == 30 * 200


def test_baseline_is_calibrated_heavy_tail_not_gaussian():
    df = build_baseline(days=30, seed=42)
    v = df["value"]
    assert (v > 0).all()
    assert v.mean() > v.median()          # right-skew (log-normal), impossible for the old N(50,30)
    assert v.skew() > 2.0                 # heavy tail (generator ledger: skew ~10.7 at scale)
    assert 20 < v.mean() < 80             # calibrated regime magnitude (ledger mu~42.87)


def test_baseline_deterministic_and_time_ordered():
    a = build_baseline(days=30, seed=42)
    b = build_baseline(days=30, seed=42)
    pd.testing.assert_frame_equal(a, b)
    assert a["timestamp"].is_monotonic_increasing
