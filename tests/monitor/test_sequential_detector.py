"""Tests for the BOLT Phase 12 sequential change-point detector (gap G2).

The production value-dominated z-score (monitor.anomaly.compute_score) is, in
practice, a univariate threshold on transaction *value*: a single huge outflow
trips it, but a low-and-slow / structuring attack (many same-counterparty
withdrawals each only ~1.5σ above the benign mean) is invisible per event yet
accumulates. A Page-Hinkley / CUSUM statistic over a *per-counterparty* sliding
window of cumulative outflow makes that structuring visible, while the same total
value spread across many DISTINCT counterparties (or as one-off normal txs) does
NOT trip.

Written BEFORE the implementation (TDD step 12.1 / 12.5 / 12.7).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from monitor.generator import generate
from monitor.sequential_detector import Arl1Estimate, SequentialChangePointDetector


# Benign stream calibration (seed 42, n=5000): value mean ≈ 43, std ≈ 79.
# A structuring tx sits ~1.5σ above the mean, below any single-event alarm.
BENIGN_MEAN = 43.0
BENIGN_STD = 79.0
STRUCTURING_VALUE = BENIGN_MEAN + 1.5 * BENIGN_STD  # ≈ 161 ETH per withdrawal

# Train-selected (shipped evaluation) detector configuration: δ=0.25, λ=4,
# cap=2.0 (docs/parameter_choices.md). The service-code DEFAULTS remain
# δ=0.5, λ=8.0; the legacy pair is exercised alongside this one, not replaced.
SELECTED_DRIFT = 0.25
SELECTED_THRESHOLD = 4.0


def _make_detector() -> SequentialChangePointDetector:
    """Detector calibrated to the benign generator stream (seed 42)."""
    return SequentialChangePointDetector.from_baseline(
        baseline=generate(seed=42, n=5000),
        window_seconds=3600.0,
        drift=0.5,        # δ in baseline-σ units (allowed slack)
        threshold=8.0,    # λ
    )


# ---------------------------------------------------------------------------
# 12.1 structuring detection
# ---------------------------------------------------------------------------
def test_detects_structuring():
    """Many same-counterparty sub-threshold withdrawals must TRIP the detector."""
    det = _make_detector()
    attacker = "0x" + "a" * 40
    t = 0.0
    tripped_any = False
    n_to_trip = None
    for i in range(40):
        stat, tripped = det.update(attacker, STRUCTURING_VALUE, t)
        t += 60.0  # one structuring tx per minute, well inside the 1h window
        if tripped:
            tripped_any = True
            n_to_trip = i + 1
            break
    assert tripped_any, "structuring (same-counterparty drip) must trip the detector"
    assert n_to_trip is not None and n_to_trip > 1, (
        "structuring should require accumulation, not a single event"
    )


def test_same_total_across_distinct_counterparties_does_not_trip():
    """The SAME total value spread across many DISTINCT counterparties must NOT trip."""
    det = _make_detector()
    t = 0.0
    tripped_any = False
    for i in range(200):
        cp = "0x" + f"{i:040x}"  # a fresh counterparty every event
        _stat, tripped = det.update(cp, STRUCTURING_VALUE, t)
        t += 60.0
        tripped_any = tripped_any or tripped
    assert not tripped_any, (
        "value spread across distinct counterparties must not look like structuring"
    )


def test_oneoff_normal_stream_does_not_trip():
    """A benign one-off normal stream from the calibrated generator must NOT trip."""
    det = _make_detector()
    stream = generate(seed=7, n=3000)
    t0 = stream["timestamp"].iloc[0]
    tripped_any = False
    for _, row in stream.iterrows():
        t = (row["timestamp"] - t0).total_seconds()
        _stat, tripped = det.update(row["destination"], float(row["value"]), t)
        tripped_any = tripped_any or tripped
    assert not tripped_any, "calibrated benign stream must not trip the detector"


# ---------------------------------------------------------------------------
# 12.5 ARL reporting
# ---------------------------------------------------------------------------
def test_arl_reporting():
    """Detector exposes empirical ARL₀ (benign, large) and ARL₁ (post-change, small).

    ARL₀: mean run length (seconds) between false trips under a benign generator
    stream. ARL₁ = D: mean time-to-detection (seconds) after a structuring onset.
    On calibrated streams, ARL₁ must be strictly less than ARL₀.

    Both quantities are CENSORED estimates and both must surface that fact: ARL₀
    reports ``all_censored`` (no benign stream false-tripped ⇒ lower bound), ARL₁
    reports ``n_detected``/``n_trials`` (its mean is conditional on detection ⇒
    lower bound). A bare ``arl1 > 0`` assertion is near-vacuous on its own, so the
    detection fraction is pinned here too.
    """
    seeds = [1, 2, 3, 4, 5]
    arl0, arl0_all_censored = SequentialChangePointDetector.measure_arl0(
        window_seconds=3600.0,
        drift=0.5,
        threshold=8.0,
        baseline=generate(seed=42, n=5000),
        seeds=seeds,
        n=4000,
        return_censored=True,
    )
    est = SequentialChangePointDetector.measure_arl1(
        window_seconds=3600.0,
        drift=0.5,
        threshold=8.0,
        baseline=generate(seed=42, n=5000),
        structuring_value=STRUCTURING_VALUE,
        inter_arrival_seconds=60.0,
        seeds=seeds,
    )
    arl1 = est.mean_delay
    assert arl0 > 0.0
    assert arl1 > 0.0
    assert arl1 < arl0, f"ARL₁ (D={arl1}s) must be < ARL₀ ({arl0}s)"

    # ARL₀ on this calibrated benign stream never false-trips → fully censored,
    # so the reported value is a lower bound, not a point estimate.
    assert arl0_all_censored is True

    # ARL₁ must carry its censoring bookkeeping, not just a mean. On the legacy
    # δ=0.5 / λ=8.0 pair every seed detects, so the mean is unconditional here,
    # and that has to be ASSERTED, not assumed.
    assert isinstance(est, Arl1Estimate)
    assert est.n_trials == len(seeds)
    assert est.n_detected == len(seeds), (
        f"every seed must detect on the legacy config; got {est}"
    )
    assert est.detection_rate == 1.0
    assert est.censored is False
    assert np.isfinite(est.mean_delay)
    # The estimate must not be usable as a bare float: callers have to reach for
    # .mean_delay so the detection fraction cannot be silently dropped.
    assert not isinstance(est, float)
    assert not hasattr(est, "__float__")


def test_arl1_selected_configuration_reports_detection_fraction():
    """ARL₁ under the SHIPPED train-selected params (δ=0.25, λ=4, cap=2.0).

    ``test_arl_reporting`` exercises the legacy hand-picked δ=0.5 / λ=8.0 pair;
    the published evaluation headline uses the train-selected pair, so it needs
    its own coverage. The lower λ detects strictly sooner than the legacy pair,
    and, as everywhere, the detection fraction is reported alongside the mean.
    """
    seeds = [1, 2, 3, 4, 5]
    baseline = generate(seed=42, n=5000)
    selected = SequentialChangePointDetector.measure_arl1(
        window_seconds=3600.0,
        drift=SELECTED_DRIFT,
        threshold=SELECTED_THRESHOLD,
        baseline=baseline,
        structuring_value=STRUCTURING_VALUE,
        inter_arrival_seconds=60.0,
        seeds=seeds,
    )
    legacy = SequentialChangePointDetector.measure_arl1(
        window_seconds=3600.0,
        drift=0.5,
        threshold=8.0,
        baseline=baseline,
        structuring_value=STRUCTURING_VALUE,
        inter_arrival_seconds=60.0,
        seeds=seeds,
    )
    assert selected.n_detected == selected.n_trials == len(seeds)
    assert selected.detection_rate == 1.0
    assert selected.censored is False
    assert np.isfinite(selected.mean_delay) and selected.mean_delay > 0.0
    assert selected.mean_delay < legacy.mean_delay, (
        "the lower selected threshold λ=4 must detect no later than λ=8: "
        f"selected {selected}, legacy {legacy}"
    )


def test_arl1_fully_censored_configuration_returns_inf():
    """No trial detecting ⇒ mean is +inf, NOT a mean over an empty survivor set.

    Structuring at the benign mean gives every event a deviation below the slack
    δ, so the accumulator drifts down and never reaches λ. The estimate must say
    so loudly (``inf``) rather than return a finite number, otherwise an
    ``ARL₁ < ARL₀`` assertion would pass on a detector that never fires.
    """
    seeds = [1, 2, 3]
    est = SequentialChangePointDetector.measure_arl1(
        window_seconds=3600.0,
        drift=0.5,
        threshold=8.0,
        baseline=generate(seed=42, n=5000),
        structuring_value=BENIGN_MEAN,  # deviation ≈ 0 < δ: nothing accumulates
        inter_arrival_seconds=60.0,
        seeds=seeds,
        max_events=50,
        warmup_benign=50,
    )
    assert est.mean_delay == float("inf")
    assert est.n_detected == 0
    assert est.n_trials == len(seeds)
    assert est.detection_rate == 0.0
    assert est.censored is True


def test_arl1_partial_censoring_is_reported_not_averaged_away():
    """MIXED batch: some trials detect, some never do; the fraction must survive.

    This is the regression that matters. Non-detecting trials are RIGHT-CENSORED
    (their delay is unobserved and unbounded) and are exactly the slowest trials,
    so averaging only the survivors understates D. Dropping them silently (the
    old behaviour) returned a bare finite mean indistinguishable from a clean
    all-detect run.

    A genuinely mixed batch cannot be produced through the ``seeds`` axis alone:
    ``measure_arl1`` injects the attacker on a FRESH key whose arrival schedule is
    seed-independent, so the delay is identical across seeds. The subclass below
    therefore varies the per-trial detector (``measure_arl1`` builds one per seed
    via ``from_baseline``), handing an unreachable λ to the trailing trials.
    """
    n_detecting = 3
    seeds = [1, 2, 3, 4, 5]

    class _PartiallyDetecting(SequentialChangePointDetector):
        """Test double: the first ``n_detecting`` trials detect, the rest cannot."""

        built = 0

        @classmethod
        def from_baseline(cls, baseline, **kwargs):
            cls.built += 1
            if cls.built > n_detecting:
                kwargs["threshold"] = 1e9  # unreachable λ → this trial censors
            return super().from_baseline(baseline=baseline, **kwargs)

    est = _PartiallyDetecting.measure_arl1(
        window_seconds=3600.0,
        drift=0.5,
        threshold=8.0,
        baseline=generate(seed=42, n=5000),
        structuring_value=STRUCTURING_VALUE,
        inter_arrival_seconds=60.0,
        seeds=seeds,
        max_events=60,
        warmup_benign=50,
    )
    assert est.n_trials == len(seeds)
    assert est.n_detected == n_detecting
    assert est.n_detected < est.n_trials, "the censored trials must be visible"
    assert est.censored is True
    assert est.detection_rate == n_detecting / len(seeds)
    # The mean is finite and CONDITIONAL on detection: a lower bound on the true
    # mean delay, and reported as such rather than passed off as the whole story.
    assert np.isfinite(est.mean_delay) and est.mean_delay > 0.0
    assert f"{est.n_detected}/{est.n_trials}" in str(est)


# ---------------------------------------------------------------------------
# 12.7 Ronin fast-path regression
# ---------------------------------------------------------------------------
def test_catches_ronin_fast_path():
    """The single 173,600 ETH outlier (Ronin drain) must still trip immediately."""
    det = _make_detector()
    ronin = "0x" + "d" * 40
    stat, tripped = det.update(ronin, 173_600.0, 0.0)
    assert tripped, "the single Ronin-scale withdrawal must trip the detector (fast path)"
