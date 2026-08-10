"""Unit tests for the phase-22 Tier B evaluation overhaul in scenario_6.

Locks in the four methodology fixes an IJIS referee would reject on:

  B2(b): the low-and-slow comparison is a σ SWEEP whose value-baseline recall
         crosses over from 0 (blind below its threshold, by construction) to 1
         (each tx flags on its own), never a single rigged point.
  B2(c): the H1 McNemar runs on a MIXED benign+injected stream (y = injected
         mask, both classes present), not the y=all-True design whose n10=0
         was structurally guaranteed.
  B4:    every baseline flag threshold is FPR-matched on TRAIN to one shared
         benign-FPR budget (``_fpr_matched_threshold``).
  B5:    CIs come from ≥1000 stratified bootstrap resamples (the ``CISummary``
         field is ``n_boot``; no "seeds" language).
  B6:    the sequential detector's per-row ROC score is the INSTANTANEOUS
         Page-Hinkley statistic; the legacy running-max score is a separate,
         annotated mode with IDENTICAL flags.

All tests run on synthetic streams (no parquet dependency); offline/node-less.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

import scenarios.scenario_6_detection_eval as s6
from monitor.generator import generate
from monitor.param_select import EVAL_DRAIN_EVENTS, EVAL_DRAIN_SIGMA
from monitor.sequential_detector import SequentialChangePointDetector


# ---------------------------------------------------------------------------
# synthetic fixtures
# ---------------------------------------------------------------------------
def _with_tsec(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["t_sec"] = (df["timestamp"] - df["timestamp"].iloc[0]).dt.total_seconds()
    return df


def _splits(n_train: int = 1500, n_test: int = 800) -> s6.CctxSplits:
    train = _with_tsec(generate(seed=11, n=n_train))
    test = _with_tsec(generate(seed=13, n=n_test))
    for df in (train, test):
        df["label"] = "benign"
    y = np.zeros(len(test), dtype=bool)
    return s6.CctxSplits(
        train=train, test=test, y_test=y, positive_labels=[],
        sha_verified={"train": False, "test": False},
    )


def _mini_detectors(splits: s6.CctxSplits, scale: s6.LogScale, budget: float = 0.01):
    """seq + FPR-matched value-zscore, the two detectors the H1 machinery needs
    (skips the IsolationForest fit to keep the test fast)."""
    train = splits.train
    fp = s6.fast_path_from_train(train, scale)
    seq = SequentialChangePointDetector.from_baseline(
        train, window_seconds=3600.0, drift=0.25, threshold=4.0,
        contribution_cap=2.0, fast_path_z=fp,
    )

    def seq_score(df):
        return s6.score_sequential(seq, df, scale)

    z_thr = s6._fpr_matched_threshold(
        np.abs(scale.z(train["value"].to_numpy())), budget
    )

    def z_score(df):
        z = np.abs(scale.z(df["value"].to_numpy()))
        return z.astype(float), (z > z_thr)

    return [
        s6.Detector("sequential-cpd", seq_score, "sequential"),
        s6.Detector("value-zscore", z_score, "value-zscore"),
    ], z_thr


# ---------------------------------------------------------------------------
# B6: score semantics
# ---------------------------------------------------------------------------
def test_score_sequential_instantaneous_is_not_running_max_but_flags_match():
    train = _with_tsec(generate(seed=3, n=800))
    scale = s6.LogScale.fit(train)
    det = SequentialChangePointDetector.from_baseline(
        train, window_seconds=3600.0, drift=0.25, threshold=4.0,
        contribution_cap=2.0, fast_path_z=100.0,
    )
    # One counterparty: a burst of high-z events (statistic climbs) followed by
    # low-z events (contributions go negative, the instantaneous statistic
    # falls back toward 0 while the running max stays at its peak).
    hi = float(10 ** (scale.mu + 1.6 * scale.sigma))
    lo = float(10 ** (scale.mu - 1.0 * scale.sigma))
    vals = [hi] * 10 + [lo] * 10
    df = pd.DataFrame({
        "timestamp": pd.to_datetime(np.arange(20) * 60.0, unit="s", origin="2022-06-01"),
        "value": vals,
        "destination": ["0x" + "b" * 40] * 20,
        "t_sec": np.arange(20) * 60.0,
    })
    inst_scores, inst_flags = s6.score_sequential(det, df, scale, mode="instantaneous")
    rm_scores, rm_flags = s6.score_sequential(det, df, scale, mode="running-max")
    # Flags are the alarm path, identical regardless of score mode.
    assert (inst_flags == rm_flags).all()
    # Running max is monotone non-decreasing (the B6 time-ordering artifact)…
    assert (np.diff(rm_scores) >= 0).all()
    # …while the instantaneous statistic decays once the drain stops.
    assert inst_scores[-1] < rm_scores[-1]
    assert (np.diff(inst_scores) < 0).any()


def test_score_sequential_rejects_unknown_mode():
    train = _with_tsec(generate(seed=3, n=100))
    scale = s6.LogScale.fit(train)
    det = SequentialChangePointDetector.from_baseline(train)
    with pytest.raises(ValueError, match="mode"):
        s6.score_sequential(det, train, scale, mode="cumulative")


# ---------------------------------------------------------------------------
# B4: FPR-matched thresholds
# ---------------------------------------------------------------------------
def test_fpr_matched_threshold_spends_the_budget_on_train():
    rng = np.random.default_rng(0)
    scores = rng.normal(size=20_000)
    for budget in (0.01, 0.05):
        thr = s6._fpr_matched_threshold(scores, budget)
        rate = float((scores > thr).mean())
        # ≤ budget up to quantile-interpolation ties, and not absurdly below it.
        assert rate <= budget + 1e-9
        assert rate >= budget * 0.5


def test_fpr_matched_threshold_rejects_degenerate_budget():
    with pytest.raises(ValueError):
        s6._fpr_matched_threshold(np.arange(10.0), 0.0)
    with pytest.raises(ValueError):
        s6._fpr_matched_threshold(np.arange(10.0), 1.0)


# ---------------------------------------------------------------------------
# B5: CI construction
# ---------------------------------------------------------------------------
def test_bootstrap_cis_uses_1000_default_resamples_and_brackets_means():
    assert s6.N_BOOT >= 1000, "B5: the default CI construction must use >=1000 resamples"
    splits = _splits(n_train=400, n_test=400)
    # Plant 25 positives with clearly higher scores so metrics are non-trivial.
    y = splits.y_test.copy()
    y[-25:] = True
    splits.y_test = y
    rng = np.random.default_rng(1)
    scores = np.where(y, 5.0 + rng.normal(size=len(y)), rng.normal(size=len(y)))
    flags = scores > 2.5

    det = s6.Detector("stub", lambda df: (scores, flags), "value-zscore")
    ci = s6.bootstrap_cis(det, splits, n_boot=250, seed=7)
    # The field is n_boot (resamples); the "12 seeds" construction is retired.
    assert ci.n_boot == 250
    assert not hasattr(ci, "n_seeds")
    for lo, mean, hi in [
        (ci.auc_roc_lo, ci.auc_roc_mean, ci.auc_roc_hi),
        (ci.auc_pr_lo, ci.auc_pr_mean, ci.auc_pr_hi),
        (ci.f1_lo, ci.f1_mean, ci.f1_hi),
        (ci.phi_lo, ci.phi_mean, ci.phi_hi),
    ]:
        assert lo <= mean <= hi
    # With 250 resamples the band must not collapse to a single draw.
    assert ci.f1_hi > ci.f1_lo


def test_bootstrap_cis_deterministic_for_fixed_seed():
    splits = _splits(n_train=300, n_test=300)
    y = splits.y_test.copy()
    y[-20:] = True
    splits.y_test = y
    scores = np.linspace(0, 1, len(y))
    flags = scores > 0.9
    det = s6.Detector("stub", lambda df: (scores, flags), "value-zscore")
    a = s6.bootstrap_cis(det, splits, n_boot=50, seed=9)
    b = s6.bootstrap_cis(det, splits, n_boot=50, seed=9)
    assert (a.auc_roc_lo, a.auc_roc_hi, a.f1_lo, a.f1_hi) == \
           (b.auc_roc_lo, b.auc_roc_hi, b.f1_lo, b.f1_hi)


# ---------------------------------------------------------------------------
# B2(c): mixed-stream McNemar (no y=all-True p-value theater)
# ---------------------------------------------------------------------------
def test_low_and_slow_h1_mcnemar_runs_on_a_mixed_stream():
    splits = _splits()
    scale = s6.LogScale.fit(splits.train)
    detectors, _z_thr = _mini_detectors(splits, scale)
    lns = s6.low_and_slow_win(splits, scale, detectors)
    # The paired test's stream contains BOTH classes: every benign test row plus
    # the injected drain; y is emphatically not all-True.
    n_injected = lns.h1_mixed_n_rows - lns.h1_mixed_n_benign
    assert lns.h1_mixed_n_benign == int((~splits.y_test).sum())
    assert n_injected == EVAL_DRAIN_EVENTS
    # The demoted injected-only illustration keeps its structural property
    # (n10 = 0 whenever the value baseline misses every event) with NO p-value
    # field: it is two bare counts.
    assert lns.h1_injected_n10 == 0
    assert lns.h1_injected_n01 > 0
    # The headline McNemar is a real test result on the mixed stream.
    assert 0.0 <= lns.h1_mcnemar_mixed.p_value <= 1.0
    assert lns.h1_mcnemar_mixed.n01 >= lns.h1_injected_n01


def test_low_and_slow_rejects_geometry_inside_selection_family():
    splits = _splits(n_train=300, n_test=300)
    scale = s6.LogScale.fit(splits.train)
    detectors, _z_thr = _mini_detectors(splits, scale)
    # σ=1.0 and 30/90 events are members of the TRAIN selection family; using
    # them as the evaluation geometry would re-introduce the B2a circularity.
    with pytest.raises(AssertionError, match="circular"):
        s6.low_and_slow_win(splits, scale, detectors, sigma_above=1.0)
    with pytest.raises(AssertionError, match="circular"):
        s6.low_and_slow_win(splits, scale, detectors, n_events=90)


# ---------------------------------------------------------------------------
# B2(b): σ sweep shows the crossover
# ---------------------------------------------------------------------------
def test_sigma_sweep_shows_value_baseline_crossover():
    splits = _splits()
    scale = s6.LogScale.fit(splits.train)
    detectors, z_thr = _mini_detectors(splits, scale)
    sigmas = (1.0, EVAL_DRAIN_SIGMA, z_thr + 0.5, z_thr + 1.5)
    sweep = s6.lowslow_sigma_sweep(splits, scale, detectors, sigmas=sigmas)
    assert [p.sigma for p in sweep] == [float(x) for x in sigmas]
    by_sigma = {p.sigma: p for p in sweep}
    # Below its threshold the value baseline is blind BY CONSTRUCTION…
    assert by_sigma[1.0].zscore_recall == 0.0
    assert by_sigma[float(EVAL_DRAIN_SIGMA)].zscore_recall == 0.0
    # …and above it every injected tx flags on its own (the crossover the old
    # single-point comparison hid).
    assert by_sigma[z_thr + 0.5].zscore_recall == 1.0
    assert by_sigma[z_thr + 1.5].zscore_recall == 1.0
    cross = s6.sweep_crossover_sigma(sweep)
    assert cross is not None and cross > float(EVAL_DRAIN_SIGMA)
    # The sequential detector catches the drain by accumulation on BOTH sides.
    assert all(p.seq_recall > 0.5 for p in sweep)
    # Exactly one point is marked as the headline evaluation geometry.
    assert sum(p.is_eval_point for p in sweep) == 1


def test_sweep_crossover_none_when_value_baseline_never_fires():
    pts = [
        s6.LowSlowSweepPoint(sigma=s, per_tx_value_usd=1.0, seq_recall=1.0,
                             zscore_recall=0.0, seq_first_trip_event=1,
                             is_eval_point=False)
        for s in (1.0, 2.0)
    ]
    assert s6.sweep_crossover_sigma(pts) is None
