"""Composite anomaly scorer (§11.2.3).

`compute_score` evaluates a single transaction against a 30-day rolling baseline,
returning a weighted z-score across three components:

1. **value_z**: z-score of the transaction's value vs. the baseline value distribution.
2. **vol_z**:  z-score of the *current-hour transaction count* vs. the baseline's
   per-hour count distribution. The current count is `len(window) + 1` if a `window`
   of recently-observed transactions in the same hour is supplied, otherwise it
   defaults to 1 (the kernel-only mode used by the headline Ronin case where the
   value term saturates the score). With `window=None` that count is fixed at 1
   independently of the transaction, so against the calibrated baseline
   (`monitor.baseline.build_baseline()`, seed=42: 6,000 txs over 720 hours, hourly
   count mean 8.3333, std 2.8844) `vol_z` is the constant −2.5424 and contributes a
   fixed −0.7627 to every score at `DEFAULT_WEIGHTS`. `compute_score` documents the
   effective thresholds that constant implies.
3. **dest_novelty**: 0 if the destination is in the baseline destination set, 1 if novel.

Composite weighting is `0.5 * value_z + 0.3 * vol_z + 0.2 * dest_novelty`, taken
verbatim from the dissertation §11.2.3. Threshold semantics: `score >= 3.0`
classifies as ALERT, `score >= 6.0` as CRITICAL.

Provenance (V2 task 2.3): the weights (0.5, 0.3, 0.2) and the ALERT=3.0 /
CRITICAL=6.0 thresholds are **dissertation constants** (§11.2.3); they are NOT
tuned on any test data. They are now explicitly *ablated* (weight grid + an
ALERT-threshold axis, evaluated by ``scenarios/scenario_6_detection_eval.py`` and
rendered into ``docs/bolt/ablations.md``), and their FPR behaviour is empirically
characterised by ``scenarios/scenario_4_fpr_sweep.py``. ``compute_score`` therefore
takes the weights as a parameter (``DEFAULT_WEIGHTS`` preserves the dissertation
behaviour exactly) so the ablation can vary them without touching the defaults.
"""
from __future__ import annotations

from typing import Optional, Sequence

import pandas as pd

ALERT_THRESHOLD = 3.0
CRITICAL_THRESHOLD = 6.0

DEFAULT_WEIGHTS = (0.5, 0.3, 0.2)  # dissertation §11.2.3 provenance; ablated in scenario_6


def compute_score(
    tx: dict,
    baseline: pd.DataFrame,
    window: Optional[pd.DataFrame] = None,
    weights: Sequence[float] = DEFAULT_WEIGHTS,
) -> float:
    """Score a transaction against the baseline.

    Parameters
    ----------
    tx : dict
        Must contain ``value`` (float, ETH) and ``destination`` (str).
    baseline : pd.DataFrame
        30-day baseline with columns ``timestamp``, ``value``, ``destination``.
    window : pd.DataFrame | None, optional
        Transactions already observed in the same hour as ``tx`` (excluding
        ``tx`` itself). When supplied, ``vol_z`` reflects the *elevated* count
        ``len(window) + 1`` against the baseline's hourly mean/std. When None,
        ``vol_z`` is computed for a single-tx hour, which is the appropriate
        mode for one-shot scoring of an outsized outlier where the value term
        dominates.
    weights : Sequence[float], optional
        The ``(w_value, w_volume, w_destination)`` composite weights. Defaults to
        the dissertation §11.2.3 constants ``DEFAULT_WEIGHTS = (0.5, 0.3, 0.2)``
        (backwards-compatible); non-default values are used only by the scenario_6
        weight ablation (``docs/bolt/ablations.md``), never tuned on test.

    Notes
    -----
    **One-shot mode (``window is None``) and its effective thresholds.** With no
    window, ``current_count`` is fixed at 1 and ``vol_z`` therefore does not vary
    with the transaction being scored. Against the calibrated baseline
    (``monitor.baseline.build_baseline()``, seed=42: 6,000 txs spanning 720 hours,
    hourly count mean 8.3333, hourly count std 2.8844) it takes the constant value
    ``(1 − 8.3333) / 2.8844 = −2.5424``, contributing a fixed
    ``0.3 × −2.5424 = −0.7627`` to every score at ``DEFAULT_WEIGHTS``. In this mode
    the volume term is a constant handicap rather than a feature: it can only lower
    a score, never raise one, and it carries no information about the transaction.
    It becomes informative only when a ``window`` is supplied and
    ``len(window) + 1`` tracks observed traffic: done by
    ``scenarios/scenario_3_stress.py`` sub-scenario B and by
    ``tests/monitor/test_anomaly.py::test_volume_window_elevates_score``, and
    nowhere else.

    The handicap moves the operating point. Read literally, ``0.5 * value_z >=
    ALERT_THRESHOLD`` would place ALERT at 6.0σ (531.04 ETH on this baseline) for a
    known destination and 5.6σ (498.54 ETH) for a novel one. Carrying the −0.7627
    offset, the one-shot crossings sit 1.5254σ higher: ALERT at an effective
    **7.5254σ = 654.95 ETH** to a known destination and **7.1254σ = 622.46 ETH** to a
    novel one; CRITICAL at **13.5254σ = 1,142.35 ETH** (known) and **13.1254σ =
    1,109.86 ETH** (novel). The ETH figures use the calibrated baseline's value mean
    43.6371 ETH and std 81.2334 ETH and move with the baseline draw; the σ figures
    do not. A reader arriving from the write-up will meet ≈668 ETH for the same
    crossing in Figure 11.9 and in the manuscript prose derived from it; that is a
    grid readout rather than a competing estimate. The figure scores a 160-point
    ``np.logspace(1, log10(2500))`` sweep stepping 3.53% per point and reports the
    first sample to reach ``ALERT_THRESHOLD``, so it brackets the analytic 654.95 ETH
    between its 645.31 ETH sample (score 2.941) and its 668.11 ETH sample
    (score 3.081).

    Because the offset is the same constant for every transaction scored this way,
    it is rank-invariant: score ordering and any ranking metric (AUC-ROC, AUC-PR)
    are unaffected, while every fixed-threshold quantity is shifted. The alert and
    critical rates characterised by ``scenarios/scenario_4_fpr_sweep.py`` are
    therefore measured at the effective crossings above, not at the nominal 3.0 / 6.0
    reading of ``0.5 * value_z``. Call sites that score in one-shot mode:
    ``monitor/service.py`` (``MonitoringService.process_event`` and the ``evaluate``
    facade, the production monitoring path), ``scenarios/scenario_2_ronin.py``,
    ``scenarios/scenario_2b_iforest_compare.py`` and
    ``scenarios/scenario_4_fpr_sweep.py``.
    """
    mean_val = baseline["value"].mean()
    std_val = baseline["value"].std()
    value_z = (tx["value"] - mean_val) / max(std_val, 1e-9)

    hourly = baseline.groupby(baseline["timestamp"].dt.floor("h")).size()
    current_count = 1 if window is None else len(window) + 1
    vol_z = (current_count - hourly.mean()) / max(hourly.std(), 1e-9)

    dest_novelty = 0.0 if tx["destination"] in baseline["destination"].values else 1.0

    w_val, w_vol, w_dest = weights
    return w_val * value_z + w_vol * vol_z + w_dest * dest_novelty


def classify(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= ALERT_THRESHOLD:
        return "ALERT"
    return "NORMAL"
