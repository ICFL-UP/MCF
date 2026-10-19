"""IsolationForest comparator for the MCF anomaly detector (Phase 9b; §4.1e fix in
Phase 16).

Provides an alternative to the z-score detector in :mod:`monitor.anomaly`.
IsolationForest is an unsupervised tree-ensemble that isolates outliers by random
recursive partitioning, a different statistical family from the z-score baseline,
which makes it useful as a sanity check on the dissertation's primary detector
(§11.2.3).

Features used: ``[value, dest_novelty]`` where destination novelty is ``1`` for a
destination not present in the calibration baseline and ``0`` otherwise.

The §4.1e degeneracy (and its fix)
----------------------------------
The original feature builder set destination-novelty to a **constant** all-zero
column at *training* time (every baseline destination is, by construction, "known",
so ``novelty = np.zeros(...)``). A zero-variance feature carries no information when
the forest is fit, so the model learnt **only** the value distribution and the
novelty dimension was dead weight that did nothing: the §4.1e degeneracy.

The fix (:func:`build_training_features`) makes destination-novelty **non-constant
in the training matrix**: a deterministic fraction of the baseline's distinct
destinations is *held out* and the rows routed to those destinations are labelled
``novelty = 1`` at fit time. The training matrix therefore contains **both** novelty
classes, so the forest can (and does) split on novelty. A novel-destination
transaction is then scored more anomalous than an identical-value
known-destination one (see ``tests/monitor/test_baselines.py``). This changes the
*training distribution*, not merely the inference-time labelling.

The held-out destinations are treated as "novel" only for the purpose of training
the novelty split; at inference time the standard rule applies: a destination is
novel iff it is absent from the full calibration baseline.
"""

from typing import Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

DEFAULT_N_ESTIMATORS = 100
DEFAULT_CONTAMINATION = "auto"

# Fraction of the baseline's DISTINCT destinations held out as "novel" at training
# time so the novelty feature is non-constant when the forest is fit (the §4.1e
# fix). 0.25 gives a clear minority-novel signal without distorting the value
# distribution the forest also learns.
DEFAULT_NOVEL_HOLDOUT_FRAC = 0.25


def _novelty_for_destination(destination: str, known: set) -> float:
    """Inference-time novelty: 1.0 if the destination is unknown, else 0.0."""
    return 0.0 if destination in known else 1.0


def build_training_features(
    baseline: pd.DataFrame,
    seed: int = 42,
    novel_holdout_frac: float = DEFAULT_NOVEL_HOLDOUT_FRAC,
) -> np.ndarray:
    """Build the ``[value, dest_novelty]`` TRAINING matrix with NON-CONSTANT novelty.

    A deterministic ``novel_holdout_frac`` of the baseline's distinct destinations is
    held out and every row routed to those destinations is labelled ``novelty = 1``;
    all other rows are ``novelty = 0``. The resulting novelty column therefore
    contains both classes (non-zero variance), which directly fixes the §4.1e
    all-zero-column degeneracy, so the forest can learn the novelty split.

    Determinism: the holdout is chosen with ``numpy.random.default_rng(seed)`` over
    the sorted distinct destinations, so the same baseline + seed always yields the
    same training matrix.
    """
    values = baseline["value"].to_numpy(dtype=float).reshape(-1, 1)

    distinct = sorted(baseline["destination"].unique().tolist())
    rng = np.random.default_rng(seed)
    n_novel = max(1, int(round(len(distinct) * novel_holdout_frac))) if distinct else 0
    # Guard against marking *every* destination novel (keep the majority known).
    n_novel = min(n_novel, max(0, len(distinct) - 1))
    novel_dests = (
        set(rng.choice(distinct, size=n_novel, replace=False).tolist())
        if n_novel > 0
        else set()
    )

    novelty = np.array(
        [1.0 if d in novel_dests else 0.0 for d in baseline["destination"]],
        dtype=float,
    ).reshape(-1, 1)
    return np.hstack([values, novelty])


def _inference_features(tx: dict, known: set) -> np.ndarray:
    """Single-transaction ``[value, dest_novelty]`` row for scoring/inference."""
    novelty = _novelty_for_destination(tx["destination"], known)
    return np.array([[float(tx["value"]), novelty]])


def _known_destinations(baseline: pd.DataFrame) -> set:
    return set(baseline["destination"].values)


def train_iforest(
    baseline: pd.DataFrame,
    seed: int = 42,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    contamination: Union[str, float] = DEFAULT_CONTAMINATION,
    novel_holdout_frac: float = DEFAULT_NOVEL_HOLDOUT_FRAC,
) -> IsolationForest:
    """Fit an IsolationForest on the corrected (non-constant-novelty) training matrix.

    Public API preserved for :mod:`scenarios.scenario_2b_iforest_compare`.
    """
    X = build_training_features(baseline, seed=seed, novel_holdout_frac=novel_holdout_frac)
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=seed,
    )
    model.fit(X)
    return model


def score_iforest(model: IsolationForest, tx: dict, baseline: pd.DataFrame) -> float:
    """Raw ``score_samples`` for ``tx`` (lower = more anomalous, sklearn convention)."""
    X = _inference_features(tx, _known_destinations(baseline))
    return float(model.score_samples(X)[0])


def classify_iforest(model: IsolationForest, tx: dict, baseline: pd.DataFrame) -> str:
    X = _inference_features(tx, _known_destinations(baseline))
    label = int(model.predict(X)[0])
    return "ANOMALY" if label == -1 else "NORMAL"
