"""Calibrated heavy-tailed transaction generator (fixes gap G9).

The legacy ``baseline.build_baseline`` drew transaction *values* from a Gaussian
and *destinations* from a fixed closed pool of 20 addresses. Both are the wrong
distributions for real bridge/withdrawal traffic, which is heavy-tailed in value,
Poisson in arrivals, and Zipf-distributed over an open, growing set of payees.

This module implements the documented spec (source plan §8):

- ``value``        : log-normal (heavy-tailed), strictly positive.
- inter-arrivals   : Poisson process -> i.i.d. exponential gaps; timestamps are the
                     cumulative sum of those gaps (mean ≈ std for an exponential, so
                     mean ≈ variance^{1/2} and var ≈ mean^2).
- ``destination``  : Zipf-distributed over an OPEN, GROWING address universe. New
                     addresses are minted as the stream progresses (open-set), rather
                     than recycling a fixed pool. Rank-frequency is heavily skewed so a
                     few "hot" addresses dominate.

The output DataFrame matches the schema consumed elsewhere in ``monitor/``:
columns exactly ``["timestamp", "value", "destination"]`` with a pandas datetime
timestamp, float positive value, and ``0x``-prefixed 40-hex-char address string.

Fully deterministic for a fixed ``seed`` via ``numpy.random.default_rng``.

Academic framing: this is a *design specification* for a calibrated synthetic
generator. Parameter values (the log-normal sigma, arrival rate, Zipf exponent,
open-set growth rate) are illustrative defaults; real calibration to on-chain data
is out of scope for this PoC. Honest caveat: synthetic data only.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Default distribution parameters (illustrative; see module docstring caveat).
# ---------------------------------------------------------------------------
# Log-normal: underlying normal mean/sigma. sigma ~1.25 gives strong heavy tails
# (theoretical excess kurtosis of a log-normal grows very fast with sigma).
_LOGNORM_MU = 3.0
_LOGNORM_SIGMA = 1.25

# Poisson arrivals: mean inter-arrival gap in seconds (rate = 1 / mean_gap).
_MEAN_GAP_SECONDS = 432.0  # matches the legacy baseline cadence

# Zipf rank-frequency exponent (>1 required by numpy's zipf; ~1.4 is skewed).
_ZIPF_EXPONENT = 1.4

# Open-set growth: the address universe starts at this size and one new address is
# minted (made eligible) every ``_OPEN_SET_GROWTH_EVERY`` events, so the distinct
# destination count keeps growing across the stream.
_OPEN_SET_INITIAL = 8
_OPEN_SET_GROWTH_EVERY = 50

_START = pd.Timestamp("2022-01-01 00:00:00")


def _make_address(idx: int) -> str:
    """Deterministic 0x-prefixed 40-hex-char address for a universe index."""
    return f"0x{idx:040x}"


def _generate_values(rng: np.random.Generator, n: int) -> np.ndarray:
    """Heavy-tailed, strictly-positive log-normal values."""
    vals = rng.lognormal(mean=_LOGNORM_MU, sigma=_LOGNORM_SIGMA, size=n)
    return vals.astype(float)


def _generate_timestamps(rng: np.random.Generator, n: int) -> pd.DatetimeIndex:
    """Poisson arrival process: exponential gaps, cumulative timestamps."""
    gaps = rng.exponential(scale=_MEAN_GAP_SECONDS, size=n)
    # Cumulative arrival times; first event offset by its own gap so all gaps are
    # genuine exponential draws (keeps mean ≈ var^{1/2} property clean).
    elapsed = np.cumsum(gaps)
    deltas = pd.to_timedelta(elapsed, unit="s")
    return _START + deltas


def _generate_destinations(rng: np.random.Generator, n: int) -> np.ndarray:
    """Zipf-distributed destinations over an open, growing address universe.

    At event ``i`` the eligible universe has size
    ``_OPEN_SET_INITIAL + i // _OPEN_SET_GROWTH_EVERY``. A Zipf rank is drawn and
    mapped into the *current* universe (modulo its size), so low ranks (hot
    addresses) are reused heavily while the universe keeps admitting newcomers.
    """
    dests = np.empty(n, dtype=object)
    # Draw all Zipf ranks up front for determinism/perf; ranks are >= 1.
    ranks = rng.zipf(_ZIPF_EXPONENT, size=n)
    for i in range(n):
        universe_size = _OPEN_SET_INITIAL + (i // _OPEN_SET_GROWTH_EVERY)
        # Map the (possibly huge) Zipf rank into the current open universe while
        # preserving the heavy skew toward low indices (rank 1 == hottest address).
        idx = (int(ranks[i]) - 1) % universe_size
        dests[i] = _make_address(idx)
    return dests


def generate(
    seed: int,
    n: int,
    dist: str = "lognorm",
    arrivals: str = "poisson",
    dests: str = "zipf",
) -> pd.DataFrame:
    """Generate a calibrated heavy-tailed synthetic transaction stream.

    Parameters
    ----------
    seed:
        Seed for ``numpy.random.default_rng``; the seed fully determines the output.
    n:
        Number of transactions to generate.
    dist:
        Value distribution. Only ``"lognorm"`` is supported.
    arrivals:
        Arrival process. Only ``"poisson"`` is supported.
    dests:
        Destination distribution. Only ``"zipf"`` (open-set) is supported.

    Returns
    -------
    pandas.DataFrame
        Columns ``["timestamp", "value", "destination"]`` with a datetime
        timestamp, strictly-positive float value, and ``0x`` address string.
    """
    if dist != "lognorm":
        raise ValueError(f"unsupported value distribution: {dist!r} (only 'lognorm')")
    if arrivals != "poisson":
        raise ValueError(f"unsupported arrival process: {arrivals!r} (only 'poisson')")
    if dests != "zipf":
        raise ValueError(f"unsupported destination distribution: {dests!r} (only 'zipf')")
    if n < 0:
        raise ValueError("n must be non-negative")

    rng = np.random.default_rng(seed)

    # Order of draws is fixed for reproducibility: values, then timestamps, then dests.
    values = _generate_values(rng, n)
    timestamps = _generate_timestamps(rng, n)
    destinations = _generate_destinations(rng, n)

    return pd.DataFrame(
        {
            "timestamp": timestamps,
            "value": values,
            "destination": destinations,
        }
    )
