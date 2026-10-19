"""Tests for the corrected baseline detectors (BOLT Phase 16, task 16.1).

These baselines are the comparators the sequential change-point detector
(:mod:`monitor.sequential_detector`) must be evaluated against on real CCTX in
scenario_6. Two things are under test here:

1. **The §4.1e IsolationForest degeneracy is fixed.** The legacy
   :mod:`monitor.isolation_forest` set the destination-novelty feature to a
   CONSTANT all-zero column at *fit* time (``novelty = np.zeros(...)``). A
   zero-variance feature carries no signal during training, so the forest learnt
   only the value distribution and the novelty dimension was dead weight. The fix
   makes destination-novelty **non-constant in the training matrix** (both ``0``
   and ``1`` present at fit), so the forest actually splits on it, and a
   novel-destination transaction is then scored more anomalous than an
   identical-value known-destination one.

2. **A shared scoring interface.** Both baselines (corrected IForest +
   rolling-mean/3σ) expose the SAME interface as the sequential detector: feed an
   event, get back ``(continuous_score, binary_flag)`` with higher score = more
   anomalous. That lets scenario_6 run the detector and all three baselines
   through one code path on one dataset with one seed set. ROC/PR come from the
   continuous score; F1/confusion from the binary flag.

Written BEFORE the implementation (TDD step 16.1): with no ``monitor.baselines``
module and the unfixed degeneracy, this file FAILS at collection / on the novelty
assertions. Step 16.2 implements the module and the fix → PASS.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from monitor.generator import generate

# The module under test does not exist yet (TDD 16.1): this import fails first.
from monitor.baselines import (
    IsolationForestBaseline,
    RobustMadBaseline,
    RollingSigmaBaseline,
)
# The degeneracy fix lives in the existing module's feature builder; we assert on
# the TRAINING feature matrix it produces (both classes present at fit).
from monitor.isolation_forest import build_training_features, train_iforest


# ---------------------------------------------------------------------------
# Shared fixtures: a calibrated benign baseline (the same generator Phase 12 used).
# ---------------------------------------------------------------------------
BASELINE = generate(seed=42, n=2000)
KNOWN_DEST = BASELINE["destination"].iloc[0]
NOVEL_DEST = "0x" + "f" * 40  # not minted by the generator's open-set universe
BENIGN_MEAN = float(BASELINE["value"].mean())
BENIGN_STD = float(BASELINE["value"].std())


# ===========================================================================
# 16.1(a), the §4.1e fix: TRAINING novelty is NON-CONSTANT (both 0 and 1 present)
# ===========================================================================
def test_training_feature_matrix_has_nonconstant_novelty():
    """The corrected IForest training matrix must contain BOTH novelty classes.

    This is the direct §4.1e fix: a constant (all-zero) novelty column at fit time
    is the degeneracy. After the fix the novelty column (column index 1) must have
    non-zero variance, i.e. contain both 0.0 and 1.0.
    """
    X = build_training_features(BASELINE, seed=42)
    assert X.shape[1] == 2, "feature matrix must be [value, dest_novelty]"
    novelty = X[:, 1]
    classes = set(np.unique(novelty).tolist())
    assert classes == {0.0, 1.0}, (
        f"training novelty must be non-constant (both 0.0 and 1.0 present); "
        f"got unique values {sorted(classes)} — the §4.1e degeneracy is NOT fixed"
    )
    assert novelty.var() > 0.0, "training novelty column must have non-zero variance"
    # Sanity: not a trivial all-novel column either; the majority are known.
    assert 0.0 < novelty.mean() < 1.0, (
        "training novelty should be a genuine mix, not all-0 or all-1"
    )


# ===========================================================================
# 16.1(b): the corrected model GENUINELY USES novelty
# ===========================================================================
def test_corrected_model_uses_novelty_in_scoring():
    """A novel-destination tx must score MORE anomalous than an identical-value
    known-destination tx. That shows the forest learnt the novelty split and not
    only the value distribution, which is identical for the two probes here.
    """
    model = IsolationForestBaseline.fit(BASELINE, seed=42)
    value = BENIGN_MEAN  # identical value for both probes; only novelty differs
    score_known, _ = model.score_event(value, KNOWN_DEST)
    score_novel, _ = model.score_event(value, NOVEL_DEST)
    assert score_novel > score_known, (
        f"novel-destination tx must be more anomalous (higher score) than an "
        f"identical-value known-destination tx; got novel={score_novel:.5f} "
        f"<= known={score_known:.5f} — novelty is not being used"
    )


def test_corrected_model_still_flags_ronin_scale_value():
    """Regression: the corrected IForest must still flag a Ronin-scale outflow."""
    model = IsolationForestBaseline.fit(BASELINE, seed=42)
    s_normal, flag_normal = model.score_event(BENIGN_MEAN, KNOWN_DEST)
    s_ronin, flag_ronin = model.score_event(173_600.0, NOVEL_DEST)
    assert s_ronin > s_normal, "Ronin-scale tx must be more anomalous than a normal tx"
    assert flag_ronin, "Ronin-scale tx must raise the binary flag"


# ===========================================================================
# 16.1(c): rolling-mean/3σ flags a known outlier, passes a known-normal tx
# ===========================================================================
def test_rolling_sigma_flags_outlier_passes_normal():
    """The rolling-mean/3σ rule flags a clear outlier and passes a normal tx."""
    model = RollingSigmaBaseline.fit(BASELINE, sigma=3.0)
    # A near-mean transaction is well inside ±3σ → must PASS (not flagged).
    s_normal, flag_normal = model.score_event(BENIGN_MEAN, KNOWN_DEST)
    assert not flag_normal, (
        f"a near-mean tx ({BENIGN_MEAN:.1f}) must not be flagged by 3σ; "
        f"score={s_normal:.3f}"
    )
    # A tx many sigmas above the mean is a clear outlier → must FLAG.
    outlier_value = BENIGN_MEAN + 20.0 * BENIGN_STD
    s_out, flag_out = model.score_event(outlier_value, KNOWN_DEST)
    assert flag_out, (
        f"a {(outlier_value - BENIGN_MEAN) / BENIGN_STD:.0f}σ outlier must be "
        f"flagged by the 3σ rule; score={s_out:.3f}"
    )
    # Continuous score must be monotone in deviation (needed for ROC).
    assert s_out > s_normal, "rolling-σ score must increase with deviation"


def test_rolling_sigma_score_is_absolute_deviation_in_sigma():
    """The rolling-σ continuous score is |value-μ|/σ; the flag is score>sigma."""
    model = RollingSigmaBaseline.fit(BASELINE, sigma=3.0)
    # Exactly 5σ above the mean.
    value = BENIGN_MEAN + 5.0 * BENIGN_STD
    score, flag = model.score_event(value, KNOWN_DEST)
    assert score == pytest.approx(5.0, abs=1e-6), (
        f"score should be the deviation in σ units (~5.0); got {score:.4f}"
    )
    assert flag, "5σ exceeds the 3σ threshold → flagged"


# ===========================================================================
# 16.1(c2), robust median/MAD baseline: a STATISTICALLY DISTINCT value scorer
# ===========================================================================
def test_robust_mad_score_is_modified_z():
    """The robust score is |value − median| / (1.4826·MAD); flag is score > k."""
    model = RobustMadBaseline.fit(BASELINE, k=3.5)
    median = float(np.median(BASELINE["value"].to_numpy(dtype=float)))
    mad = float(np.median(np.abs(BASELINE["value"].to_numpy(dtype=float) - median)))
    scale = 1.4826 * mad
    # A point exactly 5 scaled-MAD above the median has modified-z 5.0.
    value = median + 5.0 * scale
    score, flag = model.score_event(value, KNOWN_DEST)
    assert score == pytest.approx(5.0, rel=1e-9, abs=1e-9), (
        f"robust score should be the modified-z (~5.0); got {score:.4f}"
    )
    assert flag, "modified-z 5.0 exceeds the k=3.5 threshold → flagged"
    # A near-median tx is inside the threshold → not flagged.
    s0, f0 = model.score_event(median, KNOWN_DEST)
    assert not f0 and s0 < model.k, "a near-median tx must not be flagged"


def test_robust_mad_is_distinct_from_mean_sigma_zscore():
    """REGRESSION GUARD for the §3 baseline-padding finding.

    The robust median/MAD deviation must be a GENUINELY DIFFERENT statistic from the
    mean/σ z-score (``RollingSigmaBaseline``) on heavy-tailed data (different ranking,
    different scores), not the same statistic under a different threshold. If a future
    edit makes the third ROC-axis baseline collapse back onto the value z-score's
    mean/σ log-deviation (corr ≈ 1.0, identical AUC), that is exactly the padding the
    reviewer flagged; this test fails loudly if so.
    """
    # Heavy-tailed log-value-like sample (a few large outliers dominate mean/σ).
    rng = np.random.default_rng(0)
    vals = np.concatenate([rng.normal(0.0, 1.0, size=500), rng.normal(8.0, 0.5, size=20)])
    df = pd.DataFrame(
        {
            "timestamp": np.arange(len(vals), dtype=float),
            "value": vals,
            "destination": [KNOWN_DEST] * len(vals),
        }
    )
    cal = pd.DataFrame({"value": vals, "destination": [KNOWN_DEST] * len(vals)})
    mad = RobustMadBaseline.fit(cal, k=3.5)
    sig = RollingSigmaBaseline.fit(cal, sigma=3.0)
    s_mad, _ = mad.score_frame(df)
    s_sig, _ = sig.score_frame(df)
    # Not byte-identical, and not perfectly correlated: a distinct statistic.
    assert np.max(np.abs(s_mad - s_sig)) > 1e-3, (
        "robust median/MAD and mean/σ scores are numerically identical — the third "
        "baseline has collapsed onto the value z-score (the §3 padding finding)"
    )
    corr = float(np.corrcoef(s_mad, s_sig)[0, 1])
    assert corr < 0.999, (
        f"robust median/MAD and mean/σ scores are ~perfectly correlated (corr={corr:.5f}) "
        f"— they rank identically and so coincide on ROC/PR; not a distinct baseline"
    )


# ===========================================================================
# 16.1(d): all baselines expose the SHARED scoring interface
# ===========================================================================
@pytest.mark.parametrize(
    "model",
    [
        IsolationForestBaseline.fit(BASELINE, seed=42),
        RollingSigmaBaseline.fit(BASELINE, sigma=3.0),
        RobustMadBaseline.fit(BASELINE, k=3.5),
    ],
)
def test_shared_scoring_interface_per_event(model):
    """Every baseline exposes ``score_event(value, destination, timestamp=None)``
    returning ``(float_score, bool_flag)``, the same shape scenario_6 feeds the
    sequential detector through.
    """
    assert hasattr(model, "score_event"), "baseline must expose score_event"
    out = model.score_event(BENIGN_MEAN, KNOWN_DEST, timestamp=0.0)
    assert isinstance(out, tuple) and len(out) == 2, (
        "score_event must return a (score, flag) 2-tuple"
    )
    score, flag = out
    assert isinstance(score, float), f"score must be float, got {type(score)}"
    assert isinstance(flag, (bool, np.bool_)), f"flag must be bool, got {type(flag)}"


@pytest.mark.parametrize(
    "model",
    [
        IsolationForestBaseline.fit(BASELINE, seed=42),
        RollingSigmaBaseline.fit(BASELINE, sigma=3.0),
        RobustMadBaseline.fit(BASELINE, k=3.5),
    ],
)
def test_shared_scoring_interface_batch(model):
    """Every baseline can score a whole CCTX-shaped frame in one call, returning a
    continuous score array and a boolean flag array (one code path for scenario_6).
    """
    assert hasattr(model, "score_frame"), "baseline must expose score_frame"
    df = pd.DataFrame(
        {
            "timestamp": [0.0, 1.0, 2.0],
            "value": [BENIGN_MEAN, BENIGN_MEAN + 50 * BENIGN_STD, BENIGN_MEAN],
            "destination": [KNOWN_DEST, NOVEL_DEST, KNOWN_DEST],
        }
    )
    scores, flags = model.score_frame(df)
    scores = np.asarray(scores)
    flags = np.asarray(flags)
    assert scores.shape == (3,), "one continuous score per row"
    assert flags.shape == (3,), "one binary flag per row"
    assert scores.dtype.kind == "f", "scores must be floating point"
    assert flags.dtype == bool, "flags must be boolean"
    # The middle row is a gross outlier → strictly the most anomalous score.
    assert scores[1] == scores.max() and scores[1] > scores[0], (
        "the injected outlier row must be the most anomalous in batch scoring"
    )


def test_batch_and_per_event_scores_agree(model=None):
    """score_frame must agree with row-by-row score_event (one consistent path)."""
    for model in (
        RollingSigmaBaseline.fit(BASELINE, sigma=3.0),
        RobustMadBaseline.fit(BASELINE, k=3.5),
        IsolationForestBaseline.fit(BASELINE, seed=42),
    ):
        df = pd.DataFrame(
            {
                "timestamp": [0.0, 1.0, 2.0],
                "value": [BENIGN_MEAN, 10_000.0, BENIGN_MEAN * 2],
                "destination": [KNOWN_DEST, NOVEL_DEST, KNOWN_DEST],
            }
        )
        batch_scores, batch_flags = model.score_frame(df)
        batch_scores = np.asarray(batch_scores)
        for i, row in df.iterrows():
            s, f = model.score_event(
                float(row["value"]), row["destination"], timestamp=float(row["timestamp"])
            )
            assert s == pytest.approx(float(batch_scores[i]), rel=1e-9, abs=1e-9), (
                f"row {i}: per-event score {s} disagrees with batch {batch_scores[i]}"
            )
