"""Tests for the calibrated heavy-tailed transaction generator (gap G9).

Spec (source plan §8):
- value: log-normal (heavy-tailed), NOT Gaussian.
- inter-arrival times: Poisson process (exponential gaps) -> cumulative timestamps;
  mean ≈ variance of gaps.
- destination: Zipf-distributed over an OPEN, GROWING address set (open-set).
- fully deterministic for a fixed seed.

Written BEFORE the implementation (TDD step 11.4).
"""
import numpy as np
import pandas as pd
import pandas.api.types as ptypes
import pytest
from scipy import stats

from monitor.generator import generate

SCHEMA_COLS = ["timestamp", "value", "destination"]


# ---------------------------------------------------------------------------
# (e) schema
# ---------------------------------------------------------------------------
def test_schema_columns_exact_and_ordered():
    df = generate(seed=7, n=2000)
    assert list(df.columns) == SCHEMA_COLS


def test_schema_dtypes_and_value_positive():
    df = generate(seed=7, n=2000)
    assert ptypes.is_datetime64_any_dtype(df["timestamp"]), "timestamp must be datetime"
    assert ptypes.is_float_dtype(df["value"]), "value must be float"
    assert (df["value"] > 0).all(), "value must be strictly positive"
    assert df["destination"].map(lambda s: isinstance(s, str)).all()
    assert df["destination"].str.match(r"^0x[0-9a-fA-F]{40}$").all(), "dest must be 0x address"


def test_schema_row_count():
    df = generate(seed=7, n=1500)
    assert len(df) == 1500


def test_timestamps_monotonic_increasing():
    df = generate(seed=11, n=3000)
    ts = df["timestamp"]
    assert ts.is_monotonic_increasing


# ---------------------------------------------------------------------------
# (a) heavy tail: excess kurtosis >> 0 and clearly above a Gaussian sample
# ---------------------------------------------------------------------------
def test_values_heavy_tailed_vs_gaussian():
    n = 20000
    seed = 123
    df = generate(seed=seed, n=n)
    vals = df["value"].to_numpy()

    # Fisher excess kurtosis: Gaussian -> ~0, heavy-tailed -> >> 0.
    excess_kurt = stats.kurtosis(vals, fisher=True, bias=False)

    # Reference Gaussian sample, same size/seed family.
    gauss = np.random.default_rng(seed).normal(loc=vals.mean(), scale=vals.std(), size=n)
    gauss_kurt = stats.kurtosis(gauss, fisher=True, bias=False)

    assert excess_kurt > 5.0, f"expected heavy tail, got excess kurtosis {excess_kurt}"
    assert excess_kurt > gauss_kurt + 5.0, (
        f"log-normal kurtosis {excess_kurt} must clearly exceed Gaussian {gauss_kurt}"
    )


def test_values_right_skewed():
    df = generate(seed=321, n=20000)
    skew = stats.skew(df["value"].to_numpy(), bias=False)
    assert skew > 1.0, f"log-normal should be strongly right-skewed, got skew {skew}"


# ---------------------------------------------------------------------------
# (b) Poisson arrivals: inter-arrival gaps have mean ≈ variance
# ---------------------------------------------------------------------------
def test_poisson_interarrival_mean_approx_variance():
    df = generate(seed=99, n=40000)
    # gaps in seconds between consecutive events
    gaps = df["timestamp"].diff().dropna().dt.total_seconds().to_numpy()
    assert (gaps > 0).all(), "exponential gaps must be strictly positive"

    mean = gaps.mean()
    var = gaps.var(ddof=1)
    # For exponential(rate), mean == std, so mean^2 == var. Ratio var/mean^2 ~ 1.
    ratio = var / (mean ** 2)
    assert 0.8 < ratio < 1.25, (
        f"exponential gaps should satisfy var ≈ mean^2 (ratio≈1), got {ratio}"
    )


# ---------------------------------------------------------------------------
# (c) open-set Zipf destinations
# ---------------------------------------------------------------------------
def test_destinations_open_set_grows_over_stream():
    df = generate(seed=55, n=20000)
    dests = df["destination"].to_numpy()

    # Distinct-count must grow as we move through the stream.
    first_half = set(dests[: len(dests) // 2])
    second_half = set(dests[len(dests) // 2 :])
    distinct_first = len(first_half)
    distinct_full = len(set(dests))

    assert distinct_full > distinct_first, "distinct destination count must grow over stream"

    # New addresses appear in the later half that were absent in the first half (open-set).
    newcomers = second_half - first_half
    assert len(newcomers) > 0, "open-set: new addresses must appear in the later half"


def test_destinations_zipf_skewed_rank_frequency():
    df = generate(seed=55, n=30000)
    counts = df["destination"].value_counts()
    top = counts.iloc[0]
    median = counts.median()
    assert top > 10 * median, (
        f"Zipf rank-frequency must be skewed: top {top} should dominate median {median}"
    )
    # more than one distinct destination exists
    assert len(counts) > 5


# ---------------------------------------------------------------------------
# (d) determinism
# ---------------------------------------------------------------------------
def test_determinism_same_seed_identical():
    a = generate(seed=2024, n=5000)
    b = generate(seed=2024, n=5000)
    pd.testing.assert_frame_equal(a, b)


def test_determinism_different_seed_differs():
    a = generate(seed=1, n=5000)
    b = generate(seed=2, n=5000)
    # values must differ
    assert not np.array_equal(a["value"].to_numpy(), b["value"].to_numpy())
    # destinations must differ
    assert not np.array_equal(
        a["destination"].to_numpy(), b["destination"].to_numpy()
    )
