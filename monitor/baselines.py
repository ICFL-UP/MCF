"""Baseline detectors behind a shared scoring interface (BOLT Phase 16, task 16.2).

These are the comparators the Phase 12 sequential change-point detector
(:mod:`monitor.sequential_detector`) is evaluated against on the real XChainWatcher
CCTX data in ``scenarios/scenario_6_detection_eval.py``. The whole point of this
module is **methodological consistency**: every baseline is scored through ONE code
path, on one dataset, with one seed set, so a comparison table is apples-to-apples
rather than an assembly of bespoke per-baseline scripts.

Shared scoring interface
------------------------
Each baseline mirrors how the sequential detector is fed
(:meth:`SequentialChangePointDetector.update` → ``(statistic, tripped)``):

* ``score_event(value, destination, timestamp=None) -> (score: float, flag: bool)``:
  one event in, a **continuous anomaly score** and a **binary alarm** out.
* ``score_frame(df) -> (scores: np.ndarray[float], flags: np.ndarray[bool])``:
  vectorised scoring of a CCTX-shaped frame (columns ``timestamp, value,
  destination``); equivalent to calling ``score_event`` row by row.

**Score direction convention (important for ROC/PR):** higher score = more
anomalous, for every baseline AND for the detector (whose Page-Hinkley
``statistic`` is already "higher = more anomalous"). This lets scenario_6 sweep one
decision threshold direction uniformly. sklearn's IsolationForest
``score_samples`` is the opposite (higher = more normal), so it is **negated** here.

Baselines implemented
---------------------
* :class:`IsolationForestBaseline`: wraps the **corrected** IsolationForest from
  :mod:`monitor.isolation_forest` (non-constant training novelty; §4.1e fixed). The
  forest genuinely uses the destination-novelty split, so a novel-destination tx is
  more anomalous than an identical-value known-destination one.
* :class:`RollingSigmaBaseline`: a rolling-mean / k·σ rule. Continuous score is the
  absolute deviation in σ units, ``|value − μ| / σ``; the binary flag is
  ``score > k`` (default ``k = 3``). This is the classic "3-sigma" control-chart
  rule, a fair, standard outlier baseline.
* :class:`RobustMadBaseline`: a **robust** median / MAD outlier rule. Continuous
  score is the robust z, ``|value − median| / (1.4826·MAD)``; the binary flag is
  ``score > k`` (default ``k = 3.5``, Iglewicz–Hoaglin). The median and MAD are
  resistant to the heavy tail (unlike the mean/σ, which a handful of whales dominate),
  so this is a **statistically distinct scorer** from :class:`RollingSigmaBaseline`:
  it produces a different ranking and a different ROC/PR, not merely a different
  threshold on the same statistic. The `1.4826` factor makes MAD a consistent σ
  estimator under normality (standard robust-statistics convention).

Academic framing: established methods only (IsolationForest; 3σ control chart;
median/MAD robust z). No novel statistics. These baselines exist to make the
sequential detector's evaluation honest and comparable, not to be strawmen; each is
tuned reasonably, and the three ROC-axis baselines are statistically distinct (mean/σ
z-deviation, robust median/MAD z-deviation, and the IsolationForest), not the same
statistic under different thresholds.
"""
from __future__ import annotations

from typing import Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from monitor.isolation_forest import (
    DEFAULT_CONTAMINATION,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_NOVEL_HOLDOUT_FRAC,
    build_training_features,
)


class BaselineDetector:
    """Common interface marker for the scenario_6 single-code-path scorer.

    Subclasses implement :meth:`score_event`; :meth:`score_frame` is provided here
    as a vectorised default that simply iterates :meth:`score_event`, so per-event
    and batch results are identical by construction. Subclasses may override
    :meth:`score_frame` with a faster vectorised path **only if** it stays numerically
    identical to the per-event path (the tests pin this).
    """

    #: Human-readable name used in scenario_6 tables/figures.
    name: str = "baseline"

    def score_event(
        self, value: float, destination: str, timestamp: Optional[float] = None
    ) -> Tuple[float, bool]:  # pragma: no cover - abstract
        raise NotImplementedError

    def score_frame(
        self, df: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Score every row of ``df``; returns ``(scores, flags)`` arrays.

        ``df`` must expose ``value`` and ``destination`` columns; ``timestamp`` is
        used if present. The default implementation iterates :meth:`score_event` so
        it is, by definition, consistent with per-event scoring.
        """
        values = df["value"].to_numpy(dtype=float)
        dests = df["destination"].to_numpy()
        has_ts = "timestamp" in df.columns
        ts = df["timestamp"].to_numpy() if has_ts else None
        scores = np.empty(len(df), dtype=float)
        flags = np.empty(len(df), dtype=bool)
        for i in range(len(df)):
            t = float(ts[i]) if has_ts else None
            s, f = self.score_event(float(values[i]), dests[i], timestamp=t)
            scores[i] = s
            flags[i] = bool(f)
        return scores, flags


class RollingSigmaBaseline(BaselineDetector):
    """Rolling-mean / k·σ control-chart rule.

    Continuous score = ``|value − μ| / σ`` (absolute deviation in σ units). Binary
    flag = ``score > sigma`` (the classic k-σ outlier rule, default ``k = 3``). μ and
    σ are estimated once from the calibration baseline; "rolling" here means the
    location/scale are the baseline's, against which each event is compared.
    """

    name = "rolling-sigma-3"

    def __init__(self, mean: float, std: float, sigma: float = 3.0) -> None:
        if sigma <= 0:
            raise ValueError("sigma threshold k must be positive")
        self.mean = float(mean)
        self.std = max(float(std), 1e-9)
        self.sigma = float(sigma)
        self.name = f"rolling-sigma-{self.sigma:g}"

    @classmethod
    def fit(cls, baseline: pd.DataFrame, sigma: float = 3.0) -> "RollingSigmaBaseline":
        """Calibrate μ, σ from ``baseline['value']``."""
        return cls(
            mean=float(baseline["value"].mean()),
            std=float(baseline["value"].std()),
            sigma=sigma,
        )

    def score_event(
        self, value: float, destination: str, timestamp: Optional[float] = None
    ) -> Tuple[float, bool]:
        score = abs(float(value) - self.mean) / self.std
        return float(score), bool(score > self.sigma)

    def score_frame(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        values = df["value"].to_numpy(dtype=float)
        scores = np.abs(values - self.mean) / self.std
        flags = scores > self.sigma
        return scores.astype(float), flags.astype(bool)


class RobustMadBaseline(BaselineDetector):
    """Robust median / MAD outlier rule (a statistically distinct value baseline).

    Continuous score = the **robust z** ``|value − median| / (1.4826·MAD)`` where
    ``MAD = median(|value − median|)`` and ``1.4826`` rescales MAD to a consistent σ
    estimator under normality. Binary flag = ``score > k`` (Iglewicz–Hoaglin modified
    z-score rule, default ``k = 3.5``). location/scale are estimated once from the
    calibration baseline.

    Why it exists (and is NOT a duplicate of :class:`RollingSigmaBaseline`): the
    mean/σ z-score is dominated by the heavy tail (a few whale transfers inflate σ and
    drag the mean), so on heavy-tailed bridge value the mean/σ deviation and the
    median/MAD deviation give **different rankings** and therefore different ROC/PR/AUC:
    they are genuinely distinct statistics, not two thresholds on one statistic.
    This keeps the "≥3 baselines" requirement satisfied by three statistically
    distinct scorers (mean/σ z, robust median/MAD z, IsolationForest).
    """

    name = "robust-mad"

    #: 1 / Φ⁻¹(3/4): rescales MAD to a consistent estimator of σ under normality.
    MAD_TO_SIGMA = 1.4826

    def __init__(self, median: float, mad: float, k: float = 3.5) -> None:
        if k <= 0:
            raise ValueError("modified-z threshold k must be positive")
        self.median = float(median)
        # Scaled MAD (σ-equivalent); floor to avoid divide-by-zero on degenerate data.
        self.scale = max(self.MAD_TO_SIGMA * float(mad), 1e-9)
        self.k = float(k)
        self.name = f"robust-mad-{self.k:g}"

    @classmethod
    def fit(cls, baseline: pd.DataFrame, k: float = 3.5) -> "RobustMadBaseline":
        """Calibrate the median and MAD from ``baseline['value']``."""
        v = baseline["value"].to_numpy(dtype=float)
        med = float(np.median(v))
        mad = float(np.median(np.abs(v - med)))
        return cls(median=med, mad=mad, k=k)

    def score_event(
        self, value: float, destination: str, timestamp: Optional[float] = None
    ) -> Tuple[float, bool]:
        score = abs(float(value) - self.median) / self.scale
        return float(score), bool(score > self.k)

    def score_frame(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        values = df["value"].to_numpy(dtype=float)
        scores = np.abs(values - self.median) / self.scale
        flags = scores > self.k
        return scores.astype(float), flags.astype(bool)


class IsolationForestBaseline(BaselineDetector):
    """Corrected IsolationForest baseline (§4.1e degeneracy fixed).

    Wraps :mod:`monitor.isolation_forest`: the model is fit on a training matrix
    whose destination-novelty column is **non-constant** (a deterministic fraction of
    baseline destinations is held out as novel at fit time), so the forest learns the
    novelty split rather than only the value distribution.

    Continuous score = ``− score_samples`` (negated so higher = more anomalous, the
    repo-wide convention). Binary flag = the forest's own ``predict == -1`` (outlier)
    decision at its calibrated contamination.
    """

    name = "iforest-corrected"

    def __init__(
        self,
        model: IsolationForest,
        known_destinations: set,
    ) -> None:
        self.model = model
        self._known = set(known_destinations)

    @classmethod
    def fit(
        cls,
        baseline: pd.DataFrame,
        seed: int = 42,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        contamination=DEFAULT_CONTAMINATION,
        novel_holdout_frac: float = DEFAULT_NOVEL_HOLDOUT_FRAC,
    ) -> "IsolationForestBaseline":
        """Fit on the corrected non-constant-novelty training matrix."""
        X = build_training_features(
            baseline, seed=seed, novel_holdout_frac=novel_holdout_frac
        )
        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=seed,
        )
        model.fit(X)
        return cls(model=model, known_destinations=set(baseline["destination"].values))

    def _features(self, values: np.ndarray, destinations: np.ndarray) -> np.ndarray:
        novelty = np.array(
            [0.0 if d in self._known else 1.0 for d in destinations], dtype=float
        )
        return np.column_stack([values.astype(float), novelty])

    def score_event(
        self, value: float, destination: str, timestamp: Optional[float] = None
    ) -> Tuple[float, bool]:
        X = self._features(np.array([value], dtype=float), np.array([destination], dtype=object))
        # Negate so higher = more anomalous (sklearn: higher score_samples = normal).
        score = -float(self.model.score_samples(X)[0])
        flag = int(self.model.predict(X)[0]) == -1
        return score, bool(flag)

    def score_frame(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        values = df["value"].to_numpy(dtype=float)
        dests = df["destination"].to_numpy()
        X = self._features(values, dests)
        scores = -self.model.score_samples(X).astype(float)
        flags = self.model.predict(X) == -1
        return scores, flags.astype(bool)
