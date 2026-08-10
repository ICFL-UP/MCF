"""Scenario 6: real-CCTX detection evaluation, Phase 16 (contribution C1-eval).

This harness closes the **P0 evaluation gap G3**. The legacy "0% FPR" headline was
*circular*: it was measured on draws from the SAME Gaussian used to set the detector
thresholds, so it was not evidence of anything. Scenario 6 replaces it with a real
evaluation on the **real XChainWatcher CCTX** data (arXiv:2410.02029; the Ronin and
Nomad bridge drains are present and labelled) against **three fairly-tuned
baselines**, with ROC / PR / AUC / F1 / confusion / ARL, ≥1000-resample stratified
bootstrap confidence intervals, a {T,B,r,W,Δ} sensitivity sweep, a low-and-slow σ
SWEEP that shows the seq-vs-value crossover (not one rigged point), and the benign
false-positive rate **φ** that Phase 17 consumes.

Phase-22 Tier B methodology fixes carried by this file
------------------------------------------------------
* **B2 de-circularization**: (δ, λ, cap) selection uses a TRAIN-only
  attack-geometry family (σ ∈ {1.0, 2.0} × {30, 90} events) DISJOINT from the
  σ=1.5/60 evaluation point (monitor/param_select.py); the seq-vs-value
  comparison is a σ sweep including levels above the value threshold; the
  y=all-True injected-drain McNemar is demoted to a labelled illustration and the
  headline paired test runs on a MIXED benign+injected stream.
* **B4 FPR-matched baselines**: every baseline's flag threshold is calibrated on
  TRAIN to the SAME benign-FPR budget the sequential detector's selection uses
  (1%); "as-published/default" operating points are secondary, clearly labelled.
* **B5 CIs**: ≥1000 stratified bootstrap resamples from one seeded RNG (the
  retired 12-draw construction's 2.5th percentile was the sample minimum).
* **B6 score semantics**: the per-row ROC score is the INSTANTANEOUS
  Page-Hinkley statistic (the running-max variant is monotone along the stream,
  so its AUC partly ranks by TIME); change-point-native metrics (delay, ARL,
  precision at matched φ) are primary, per-row ROC/PR secondary, and both AUC
  variants are reported with the running-max artifact annotated.

Anti-circularity (the WHOLE point, gap G3)
-------------------------------------------
Thresholds / location-scale for EVERY detector are calibrated on the **TRAIN** split
(``data/cctx/train.parquet``, 100% benign). Every reported metric (ROC, PR, AUC,
F1, φ, ARL) is measured on the **held-out TEST** split
(``data/cctx/test.parquet``, which is where the 384 incident rows live). The two
splits are disjoint in time, so the threshold-setting data is NEVER scored. This is
doubly non-circular: (a) thresholds from train, metrics on test; (b) the positives
exist only in test, so calibration never sees a single attack row.

Units
-----
The CCTX ``value`` column is the raw on-chain ``amount`` in **token base units with
MIXED per-token decimals** (18-decimal ETH-class tokens next to 6-decimal USDC and
8-decimal WBTC), so no single rescale makes rows comparable: a blanket /1e18 would
shrink every low-decimal token by ≥1e10 (Ronin's 25.5M-USDC leg becomes a
value-invisible 2.55e-05 "ETH", and ~200-unit stablecoin transfers land below any
dust cutoff as pure decimal artifacts). Every detector therefore scores
``value_usd``, the upstream per-transaction **USD valuation**, the dataset's one
common denomination. A silent unit mismatch destroys the ROC, so the loader asserts
the known Ronin drain row round-trips BOTH ways: 1.736e23 base units (wei) = 173,600
ETH, and value_usd ≈ 5.399e8 USD.

Heavy-tailed scale
------------------
Real bridge value is heavy-tailed across many orders of magnitude (sub-cent dust to
9-figure USD whale transfers). A raw mean/σ z-score is the wrong scale statistic for
such a distribution (σ is dominated by a handful of whales, which collapses every z toward 0).
We therefore score on a **signed log deviation** ``z = (log10(value) − μ_log) / σ_log``
with μ_log, σ_log calibrated on TRAIN benign, a standard transform for heavy-tailed
financial/on-chain magnitudes, used identically for the sequential detector's
``value_z`` feature, the value z-score baseline, and the robust median/MAD baseline,
so the comparison stays apples-to-apples through one shared code path.

The honest finding (and why H1 needs a sequential detector)
-----------------------------------------------------------
In the common USD denomination, benign bridge traffic contains genuine *whale*
transfers of the same order as the biggest drain rows (benign transfers up to
~$396M in train / ~$156M in test, vs Ronin's $539.9M leg and Nomad rows with a
~$202k median). Only the single largest Ronin leg exceeds every benign transfer;
the Nomad drain rows sit well inside the benign bulk, so **no per-transaction
value threshold can cleanly separate the incidents from benign traffic on value
alone**, exactly the motivation for H1. The
value-baselines achieve a deceptively high value-ROC but at pathological operating
points (the corrected IsolationForest flags ~70% of benign at its ``auto``
contamination), whereas the per-counterparty sequential change-point detector keeps
φ near zero AND catches the low-and-slow / structuring pattern the value baselines
miss. The headline result is therefore the **low-and-slow recall gap** and **φ**, not
the raw per-row AUC (a streaming change-point detector is not a per-row population
classifier; its AUC is reported honestly as a secondary number).

Academic framing: a design specification, not a tested production system. The CCTX
labels, the synthetic low-and-slow injection cadence, and the calibrated parameters
are illustrative; absolute numbers are not claimed to transfer to live bridges.
Node-less by nature (pure Python/data); no Hardhat node required.
"""
from __future__ import annotations

import hashlib
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

# Ensure project root is on sys.path when run as a script (mirrors scenario_5).
sys.path.insert(0, str(Path(__file__).parent.parent))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from monitor.baselines import (
    IsolationForestBaseline,
    RobustMadBaseline,
    RollingSigmaBaseline,
)
from monitor.param_select import (
    EVAL_DRAIN_EVENTS,
    EVAL_DRAIN_SIGMA,
    TRAIN_DRAIN_EVENTS,
    TRAIN_DRAIN_SIGMAS,
    SelectedParams,
    select_params_on_train,
    selection_grid,
)
from monitor.sequential_detector import SequentialChangePointDetector
from monitor.xchainwatcher_rules import XChainWatcherRules
from monitor.stats_tests import (
    DeLongResult,
    McNemarResult,
    RecallCI,
    delong_test,
    mcnemar_test,
    per_incident_recall_ci,
)

# --------------------------------------------------------------------------- paths
DATA_DIR = Path("data/cctx")
TRAIN_PARQUET = DATA_DIR / "train.parquet"
TEST_PARQUET = DATA_DIR / "test.parquet"
LOG_PATH = Path("docs/logs/scenario_6_detection_eval.log")
FIG_ROC_PR = Path("figures/roc_pr_curves.png")
FIG_ARL = Path("figures/arl_curves.png")
FIG_SENS = Path("figures/sensitivity.png")
FIG_LOWSLOW = Path("figures/lowslow_sweep.png")

WEI_PER_ETH = 1e18
RONIN_ETH = 173_600.0        # the actual Ronin ETH drain, base-unit round-trip check
RONIN_USD = 539_884_275.7504  # upstream value_usd of that row, scored-unit check
# Dust cutoff in the scored (USD) denomination. NOTE: rows are dust only if their
# COMMON-denomination value is tiny; the raw base-unit column must never be used
# here (a 200-unit 6-decimal stablecoin transfer is 2e8 base units ≈ $200, not dust).
DUST_USD = 1.0

# --- Locked ledger values (docs/bolt/theorem.md symbol table). Defaults for sweeps.
B0 = 1000.0     # token-bucket burst capacity  [ETH]
R0 = 1.0        # token-bucket refill rate      [ETH/s]
T0 = 5000.0     # per-window outflow threshold  [ETH]
W0 = 3600.0     # detector / breaker window     [s]
D0 = 480.0      # ARL1 detector worst-case mean time-to-detection [s] (Phase 12)
DELTA0 = 60.0   # response latency Δ [s] (δ_detect + δ_include; illustrative)

# Detector calibration knobs (Phase 12 names): δ/λ/cap are now SELECTED on the
# benign TRAIN split by monitor.param_select.select_params_on_train (V2 task 2.3
# FPR-budget procedure; provenance printed + logged). The old hand-picked triple
# is retained ONLY as the ablation delta reference (docs/bolt/ablations.md).
LEGACY_PARAMS = (0.5, 8.0, 2.0)   # (δ drift, λ threshold, contribution cap); Phase-12 hand-picked
FIG_ABLATIONS_MD = Path("docs/bolt/ablations.md")

# B5: number of stratified bootstrap RESAMPLES for the confidence intervals.
# An earlier revision drew 12 "seeds"; those were 12 resamples of ONE deterministic
# detector output (never independent replicates), and the 2.5th percentile of 12
# points is the sample minimum, not a CI endpoint. One seeded RNG, >=1000 draws.
N_BOOT = 1000
BOOT_SEED = 1000

# B4: the single TRAIN benign-FPR budget EVERY operating point is calibrated to.
# This is the same budget the sequential detector's (δ, λ, cap) selection is
# constrained to (monitor/param_select.py, fpr_budget=0.01), so the comparison
# table's flags all spend the same TRAIN false-positive budget. Realized TEST φ
# is reported per detector (train→test drift means realized φ can exceed the
# train budget, which the log records).
FPR_BUDGET = 0.01

# As-published default k for the robust median/MAD baseline (Iglewicz–Hoaglin
# modified z-score rule). Since B4, this fixed k is only the clearly-labelled
# SECONDARY "as-published/default" operating point; the PRIMARY flag threshold is
# FPR-matched on TRAIN to FPR_BUDGET. The median/MAD deviation remains the third,
# statistically-distinct ROC-axis baseline (it does NOT reduce to the value
# z-score's mean/σ log-deviation; see the §3 note in docs/bolt/detection_eval.md).
MAD_K = 3.5

# B2(b): σ levels for the low-and-slow sweep (per-tx value = μ_log + σ·σ_log).
# Includes the σ=1.5 evaluation point AND levels above the value baseline's
# train-matched threshold (≈2.9 log-σ at the 1% budget), so the seq-vs-value
# CROSSOVER is shown rather than a single point where the value baseline is
# 0-recall by construction.
LOWSLOW_SWEEP_SIGMAS = (1.0, 1.5, 2.0, 2.5, 2.75, 3.0, 3.5, 4.0)


# ===========================================================================
# 16.3. CCTX loader: sha256 verify, common-USD units fix, label alignment, split
# ===========================================================================
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _verify_sha256(parquet: Path) -> bool:
    """Verify a parquet against its ``.sha256`` sidecar if present (else skip)."""
    sidecar = parquet.with_suffix(parquet.suffix + ".sha256")
    if not sidecar.exists():
        return False
    expected = sidecar.read_text().split()[0].strip()
    actual = _sha256(parquet)
    if actual != expected:
        raise ValueError(
            f"sha256 mismatch for {parquet.name}: expected {expected[:12]}…, "
            f"got {actual[:12]}… — data file is not the published one"
        )
    return True


@dataclass
class CctxSplits:
    """The loaded, unit-fixed, label-aligned CCTX splits.

    ``train`` is 100% benign (calibration only); ``test`` carries the incident rows
    (evaluation only). ``y_test`` is the boolean positive mask (incident:* → True).
    """

    train: pd.DataFrame
    test: pd.DataFrame
    y_test: np.ndarray
    positive_labels: list[str]
    sha_verified: dict[str, bool]


def _align_labels(df: pd.DataFrame) -> np.ndarray:
    """incident:* → positive (True); benign → negative (False)."""
    return df["label"].astype(str).str.startswith("incident").to_numpy()


def load_cctx() -> CctxSplits:
    """Load + verify + unit-fix the real CCTX splits (task 16.3).

    * Verifies each parquet against its ``.sha256`` sidecar.
    * Scores on the common USD denomination: ``value`` ← ``value_usd`` (the raw
      mixed-decimals base-unit amount is kept aside as ``value_base_units``), and
      ASSERTS the known Ronin drain row round-trips both ways (1.736e23 base units
      = 173,600 ETH; value_usd ≈ 5.399e8 USD).
    * Aligns labels (incident:* positive, benign negative).
    * Sorts each split by timestamp and attaches ``t_sec`` = seconds since that
      split's first event (the stream clock the sequential detector consumes).
    """
    if not TRAIN_PARQUET.exists() or not TEST_PARQUET.exists():
        raise FileNotFoundError(
            f"CCTX parquet missing under {DATA_DIR}/ — run `make data` first. "
            "This is the never-drop evaluation set; it must be present."
        )

    sha = {
        "train": _verify_sha256(TRAIN_PARQUET),
        "test": _verify_sha256(TEST_PARQUET),
    }

    train = pd.read_parquet(TRAIN_PARQUET).copy()
    test = pd.read_parquet(TEST_PARQUET).copy()

    # --- UNIT FIX (mixed token decimals): score on the common USD denomination. ---
    # The raw ``value`` column is the on-chain amount in token BASE UNITS with
    # per-token decimals (18-dec ETH-class next to 6-dec USDC / 8-dec WBTC), so NO
    # single divisor makes rows comparable: a blanket /1e18 shrinks every
    # low-decimal token by >=1e10 (Ronin's 25.5M-USDC leg -> 2.55e-05 "ETH") and
    # turns ~200-unit stablecoin transfers into sub-"dust" decimal artifacts.
    # ``value_usd`` (the upstream per-tx USD valuation) is the dataset's one
    # common denomination; the raw amount is kept as ``value_base_units`` for the
    # round-trip check below and for audit.
    for df in (train, test):
        if "value_usd" not in df.columns:
            raise ValueError(
                "parquet lacks the `value_usd` column — regenerate the dataset "
                "(`make data`); scripts/fetch_cctx.py now carries the common USD "
                "denomination alongside the mixed-decimals base-unit amount"
            )
        df["value_base_units"] = df["value"].astype(float)
        df["value"] = df["value_usd"].astype(float)

    ronin_rows = test[test["label"] == "incident:ronin"]
    if len(ronin_rows) and (ronin_rows["provenance"] == "XChainWatcher").all():
        ronin_max_eth = float(ronin_rows["value_base_units"].max()) / WEI_PER_ETH
        if not np.isclose(ronin_max_eth, RONIN_ETH, rtol=1e-6):
            raise ValueError(
                f"unit check FAILED: Ronin max base-unit value is {ronin_max_eth:.3f} "
                f"ETH-equivalent, expected {RONIN_ETH:.0f} ETH"
            )
        ronin_max_usd = float(ronin_rows["value"].max())
        if not np.isclose(ronin_max_usd, RONIN_USD, rtol=1e-6):
            raise ValueError(
                f"unit check FAILED: Ronin max scored value is {ronin_max_usd:,.2f} USD, "
                f"expected {RONIN_USD:,.2f} USD — the value_usd normalization is wrong"
            )

    # --- Sort by time and attach the per-split stream clock (seconds from start). ---
    for df in (train, test):
        df.sort_values("timestamp", inplace=True, kind="mergesort")
        df.reset_index(drop=True, inplace=True)
        t0 = df["timestamp"].iloc[0]
        df["t_sec"] = (df["timestamp"] - t0).dt.total_seconds().astype(float)

    y_test = _align_labels(test)
    pos_labels = sorted(
        test.loc[y_test, "label"].astype(str).unique().tolist()
    )
    return CctxSplits(
        train=train,
        test=test,
        y_test=y_test,
        positive_labels=pos_labels,
        sha_verified=sha,
    )


# ===========================================================================
# Heavy-tailed scale: signed log deviation calibrated on TRAIN benign.
# ===========================================================================
@dataclass
class LogScale:
    """Signed log10 deviation ``z = (log10(value) − μ_log) / σ_log``.

    Calibrated on TRAIN benign only. ``floor`` clips non-positive / dust values so
    log10 is finite (CCTX has USD values down to ~1e-15). Used identically by the
    detector's ``value_z`` feature and the value baselines, so all detectors see the
    SAME scale (apples-to-apples).
    """

    mu: float
    sigma: float
    floor: float = 1e-9

    @classmethod
    def fit(cls, train: pd.DataFrame, floor: float = 1e-9) -> "LogScale":
        lv = np.log10(np.clip(train["value"].to_numpy(dtype=float), floor, None))
        return cls(mu=float(lv.mean()), sigma=float(max(lv.std(), 1e-9)), floor=floor)

    def z(self, value) -> np.ndarray:
        lv = np.log10(np.clip(np.asarray(value, dtype=float), self.floor, None))
        return (lv - self.mu) / self.sigma

    def log_value(self, value) -> np.ndarray:
        """log10(value) (floored), the feature the log-space baselines consume."""
        return np.log10(np.clip(np.asarray(value, dtype=float), self.floor, None))


def fast_path_from_train(train: pd.DataFrame, scale: LogScale, q: float = 0.999) -> float:
    """Train-derived fast-path z for the detector (NON-circular).

    Set to a high quantile of TRAIN benign signed-log-z so a genuinely extreme single
    event trips immediately while ordinary benign traffic does not, a threshold
    derived purely from train (only ~0.1% of benign exceeds it), never tuned on the
    test positives.
    """
    tz = scale.z(train["value"].to_numpy())
    return float(np.quantile(tz, q))


def _fpr_matched_threshold(train_scores: np.ndarray, budget: float) -> float:
    """B4: flag threshold spending exactly the shared TRAIN benign-FPR budget.

    Returns the (1 − budget) empirical quantile of the detector's OWN continuous
    scores on the benign TRAIN stream, so ``score > threshold`` flags ≈ ``budget``
    of TRAIN benign (≤ budget up to ties). Used for every baseline so their
    operating points are calibrated to the SAME budget the sequential detector's
    (δ, λ, cap) selection is constrained to.
    """
    if not 0.0 < budget < 1.0:
        raise ValueError("budget must be a rate in (0, 1)")
    return float(np.quantile(np.asarray(train_scores, dtype=float), 1.0 - budget))


# ===========================================================================
# Shared scoring interface: ONE code path for the detector and all 3 baselines
# ===========================================================================
def _to_log_frame(df: pd.DataFrame, scale: LogScale) -> pd.DataFrame:
    """A copy of ``df`` whose ``value`` column is log10(value) (for log-space
    baselines). ``destination``/``timestamp`` are preserved so the shared baseline
    ``score_frame`` works unchanged."""
    out = df.copy()
    out["value"] = scale.log_value(df["value"].to_numpy())
    return out


def score_sequential(
    detector: SequentialChangePointDetector,
    df: pd.DataFrame,
    scale: LogScale,
    mode: str = "instantaneous",
) -> tuple[np.ndarray, np.ndarray]:
    """Score a CCTX stream with the sequential detector through the shared contract.

    Returns ``(scores, flags)`` aligned to ``df`` rows. ``flags`` is the binary
    alarm (``tripped``), identical in both modes.

    B6 (score semantics): the PRIMARY per-row ROC score (``mode="instantaneous"``)
    is the Page-Hinkley statistic AT that row (the fast-path z for fast-path rows,
    exactly what ``update`` returns). The legacy ``mode="running-max"`` score (the
    running maximum of the statistic along the stream) is monotone non-decreasing,
    so its ROC partly ranks rows by TIME-ORDER rather than separability; it is
    retained ONLY so the artifact's size can be reported honestly (both AUCs appear
    in the log header), never as the headline. The detector is fed the
    signed-log-z feature so its scale matches the baselines.
    """
    if mode not in ("instantaneous", "running-max"):
        raise ValueError(f"unknown score mode {mode!r}")
    dests = df["destination"].to_numpy()
    vals = df["value"].to_numpy(dtype=float)
    tsec = df["t_sec"].to_numpy(dtype=float)
    zsig = scale.z(vals)

    n = len(df)
    scores = np.empty(n, dtype=float)
    flags = np.empty(n, dtype=bool)
    running_max = 0.0
    detector.reset()
    for i in range(n):
        stat, tripped = detector.update(
            dests[i], float(vals[i]), float(tsec[i]), value_z=float(zsig[i])
        )
        if mode == "running-max":
            if stat > running_max:
                running_max = stat
            scores[i] = running_max
        else:
            scores[i] = stat
        flags[i] = bool(tripped)
    return scores, flags


@dataclass
class Detector:
    """A named scorer with a uniform ``score(df) -> (scores, flags)`` callable.

    Wrapping every detector this way is what makes scenario_6 a single code path:
    the sequential detector and the three baselines are all invoked identically.
    """

    name: str
    score: Callable[[pd.DataFrame], tuple[np.ndarray, np.ndarray]]
    kind: str  # "sequential" | "value-zscore" | "iforest" | "robust-mad" | "published-rules"
    # B4: how this detector's PRIMARY flag threshold was calibrated (log provenance).
    calibration: str = ""
    # B4: the clearly-labelled SECONDARY "as-published/default" operating point
    # (df -> flags), reported alongside but never headline. None if no default exists.
    default_flags: Optional[Callable[[pd.DataFrame], np.ndarray]] = None
    # B6: the legacy running-max scorer (sequential detector only) so the
    # running-max ROC artifact can be quantified next to the instantaneous score.
    score_running_max: Optional[Callable[[pd.DataFrame], tuple[np.ndarray, np.ndarray]]] = None


def build_detectors(
    train: pd.DataFrame,
    scale: LogScale,
    seed: int = 42,
    *,
    drift: float = LEGACY_PARAMS[0],
    threshold: float = LEGACY_PARAMS[1],
    contribution_cap: float = LEGACY_PARAMS[2],
    fpr_budget: float = FPR_BUDGET,
) -> list[Detector]:
    """Construct the sequential detector + the 3 baselines (all calibrated on
    TRAIN) + the XChainWatcher published-rules comparator (V2 2.4; rule-based,
    needs no calibration).

    B4 (FPR-matched baselines): the sequential detector's (δ, λ, cap) selection is
    constrained to a TRAIN benign flag rate ≤ ``fpr_budget``; previously the
    baselines ran at UNMATCHED "as-published" operating points (value-zscore at the
    q=0.999 fast-path quantile, robust-MAD at fixed k=3.5, IsolationForest at
    ``contamination="auto"``, which flags ~86% of benign here, pathological), so
    operating-point columns (F1/φ/confusion/precision) were not comparable across
    rows. Every baseline's PRIMARY flag threshold is now the (1 − budget) quantile
    of its OWN continuous score on the benign TRAIN stream: the same budget, spent
    the same way. The old defaults survive only as each Detector's
    ``default_flags`` (clearly-labelled secondary rows in the log).

    ``drift``/``threshold``/``contribution_cap`` (δ/λ/cap) come from the V2 2.3
    train-only FPR-budget selection in ``main`` (``select_params_on_train``); the
    keyword defaults are the legacy hand-picked triple, kept only for
    backwards-compatible ad-hoc use; ``main`` always passes the selected values.

    (1) sequential change-point detector: the system under evaluation.
    (2) value z-score: the H1 "value-threshold baseline" (mean/σ ``|signed log-z|``;
        the same statistic monitor.anomaly.compute_score's value_z term reduces to,
        evaluated on the heavy-tail-appropriate log scale); flag threshold
        FPR-matched on TRAIN.
    (3) corrected IsolationForest: non-constant training novelty (§4.1e fixed),
        fit on log-value + destination novelty; flag threshold FPR-matched on the
        forest's own TRAIN scores (``contamination="auto"`` demoted to secondary).
    (4) robust median/MAD: ``|log-value − median| / (1.4826·MAD)``; flag threshold
        FPR-matched on TRAIN (fixed k=3.5 demoted to secondary).

    The three ROC-axis baselines are **statistically distinct scorers**, by design:
    (2) is the mean/σ log-deviation; (4) is the robust median/MAD log-deviation:
    median/MAD are resistant to the heavy tail while mean/σ are not, so the two give
    *different* rankings and therefore different ROC/PR/AUC. (An earlier draft used a
    rolling-mean/σ rule for (4); on log-value that reduces to EXACTLY the value
    z-score's mean/σ statistic: byte-identical continuous scores, identical AUC,
    differing only in the flag threshold; i.e. one statistic under two thresholds,
    not two baselines. ``RollingSigmaBaseline`` remains available in
    ``monitor.baselines`` and is unit-tested, but it is intentionally NOT used as a
    distinct ROC-axis baseline here; ``RobustMadBaseline`` is the genuinely different
    third scorer. See the §3 note in docs/bolt/detection_eval.md.)
    """
    log_train = _to_log_frame(train, scale)

    # (1) Sequential change-point detector: train-derived fast path (non-circular).
    fp = fast_path_from_train(train, scale, q=0.999)
    seq = SequentialChangePointDetector.from_baseline(
        train,
        window_seconds=W0,
        drift=drift,
        threshold=threshold,
        contribution_cap=contribution_cap,
        fast_path_z=fp,
    )

    def seq_score(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        return score_sequential(seq, df, scale, mode="instantaneous")

    def seq_score_rm(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        # B6: legacy running-max scorer, kept ONLY to quantify the artifact.
        return score_sequential(seq, df, scale, mode="running-max")

    # (2) Value z-score baseline: continuous = mean/σ |signed log-z|; PRIMARY flag
    #     threshold FPR-matched on TRAIN to the shared budget (B4). The old
    #     operating point (the seq fast-path q=0.999 quantile, i.e. a 0.1% budget,
    #     NOT the 1% budget the seq selection was constrained to) is kept as the
    #     labelled secondary default.
    z_train_abs = np.abs(scale.z(train["value"].to_numpy()))
    z_thresh = _fpr_matched_threshold(z_train_abs, fpr_budget)

    def zscore_score(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        z = np.abs(scale.z(df["value"].to_numpy()))
        return z.astype(float), (z > z_thresh)

    def zscore_default_flags(df: pd.DataFrame) -> np.ndarray:
        return np.abs(scale.z(df["value"].to_numpy())) > fp

    # (3) Corrected IsolationForest (log value + novelty), shared interface.
    #     PRIMARY flags: FPR-matched threshold on the forest's own TRAIN scores
    #     (B4). The forest's contamination="auto" predict() decision (which flags
    #     ~86% of benign here, pathological) is the labelled secondary default.
    iforest = IsolationForestBaseline.fit(log_train, seed=seed)
    if_train_scores, _ = iforest.score_frame(log_train)
    if_thresh = _fpr_matched_threshold(if_train_scores, fpr_budget)

    def iforest_score(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        s, _default = iforest.score_frame(_to_log_frame(df, scale))
        return s, (s > if_thresh)

    def iforest_default_flags(df: pd.DataFrame) -> np.ndarray:
        _s, f = iforest.score_frame(_to_log_frame(df, scale))
        return f

    # (4) Robust median/MAD on log value, shared interface: the statistically
    #     DISTINCT third scorer (does NOT collapse to the mean/σ value z-score).
    #     PRIMARY flags: FPR-matched k on the TRAIN robust-z scores (B4); the
    #     as-published Iglewicz–Hoaglin k=3.5 is the labelled secondary default.
    robust = RobustMadBaseline.fit(log_train, k=MAD_K)
    mad_train_scores, _ = robust.score_frame(log_train)
    mad_k_matched = _fpr_matched_threshold(mad_train_scores, fpr_budget)

    def robust_score(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        s, _default = robust.score_frame(_to_log_frame(df, scale))
        return s, (s > mad_k_matched)

    def robust_default_flags(df: pd.DataFrame) -> np.ndarray:
        _s, f = robust.score_frame(_to_log_frame(df, scale))
        return f

    budget_pct = f"{fpr_budget:.0%}"
    detectors = [
        Detector(
            "sequential-cpd", seq_score, "sequential",
            calibration=(f"(δ,λ,cap) train-selected under φ_train<={fpr_budget:g}; "
                         f"fast-path z=q0.999={fp:.3f}"),
            score_running_max=seq_score_rm,
        ),
        Detector(
            "value-zscore", zscore_score, "value-zscore",
            calibration=f"|log-z| > {z_thresh:.3f} (TRAIN q{1 - fpr_budget:g}, {budget_pct} budget)",
            default_flags=zscore_default_flags,
        ),
        Detector(
            "iforest-corrected", iforest_score, "iforest",
            calibration=f"score > {if_thresh:.4f} (TRAIN q{1 - fpr_budget:g}, {budget_pct} budget)",
            default_flags=iforest_default_flags,
        ),
        Detector(
            "robust-mad", robust_score, "robust-mad",
            calibration=(f"robust-z > k={mad_k_matched:.3f} "
                         f"(TRAIN q{1 - fpr_budget:g}, {budget_pct} budget; as-published k={MAD_K:g} secondary)"),
            default_flags=robust_default_flags,
        ),
    ]

    # (5) V2 2.4. Published/domain comparator: XChainWatcher rule engine
    #     (Augusto et al., arXiv:2410.02029) over the parquet's cross-chain
    #     linkage columns (matched / finality_gap_s). NOT train-calibrated (a
    #     deterministic rule system) and NOT a fair same-information baseline:
    #     the CCTX incident labels were derived by XChainWatcher's
    #     unmatched-withdrawal analysis, so its ~perfect recall here is BY
    #     CONSTRUCTION; it is a capability/deployment-cost comparator (both
    #     chains instrumented + protocol rules vs destination-stream-only).
    #     kind == "published-rules" is excluded from the sequential-only
    #     assertions (phi <= 0.05 etc. stay scoped to the sequential detector).
    xcw = XChainWatcherRules()
    detectors.append(Detector(
        name="xchainwatcher-rules",
        score=lambda df: xcw.score_frame(df),
        kind="published-rules",
    ))
    return detectors


# ===========================================================================
# 16.4. Metrics: ROC/PR/AUC/F1/confusion + ARL0/ARL1
# ===========================================================================
@dataclass
class DetectorMetrics:
    name: str
    auc_roc: float
    auc_pr: float
    f1: float
    confusion: np.ndarray            # [[tn, fp], [fn, tp]]
    phi: float                       # benign FP rate at the operating point
    precision: float                 # B6 primary: precision at the matched-φ operating point
    arl0: float                      # mean run length between false trips (s)
    arl0_censored: bool              # True ⇒ arl0 is a right-censored lower bound
    arl1: float                      # mean time-to-detection after onset (s)
    roc_curve: tuple                 # (fpr, tpr)
    pr_curve: tuple                  # (precision, recall)


def _confusion_and_f1(y: np.ndarray, flags: np.ndarray) -> tuple[np.ndarray, float]:
    cm = confusion_matrix(y, flags, labels=[False, True])
    f1 = f1_score(y, flags, zero_division=0)
    return cm, float(f1)


def measure_arl0_cctx(
    detector: Detector,
    benign_test: pd.DataFrame,
) -> tuple[float, bool]:
    """ARL₀ on the **real benign TEST** stream: mean time between false trips (s).

    If the detector raises ≥1 benign flag, ARL₀ = mean inter-trip gap in seconds
    (with the trailing tail to stream-end as a censored final gap). If it never
    trips, ARL₀ is the full benign duration as a **right-censored lower bound**
    (ARL₀ ≥ duration), exactly as Phase 12 reported. Higher is better.
    """
    scores, flags = detector.score(benign_test)
    tsec = benign_test["t_sec"].to_numpy(dtype=float)
    duration = float(tsec[-1] - tsec[0]) if len(tsec) > 1 else 0.0
    trip_times = tsec[flags]
    if trip_times.size == 0:
        return duration, True  # fully censored lower bound
    # Gaps: start→first trip, between trips, last trip→end.
    boundaries = np.concatenate(([tsec[0]], np.sort(trip_times), [tsec[-1]]))
    gaps = np.diff(boundaries)
    gaps = gaps[gaps > 0]
    if gaps.size == 0:
        return duration, True
    return float(np.mean(gaps)), False


def measure_arl1_cctx(
    detector: Detector,
    splits: CctxSplits,
    scale: LogScale,
    onset_label: str = "incident:ronin",
) -> float:
    """ARL₁ = mean time-to-detection (s) after a real incident ONSET on TEST.

    Replays the benign TEST traffic up to the first incident row of ``onset_label``
    (warm-up), then continues through the incident rows and records the elapsed
    seconds from incident onset to the detector's first trip. If the detector never
    trips on the incident, returns ``+inf`` (so any ARL₁<ARL₀ claim fails loudly).
    Lower is better. This is the empirical D on real data; it complements the Phase-12
    generator-based ``measure_arl1`` (= 480 s).
    """
    test = splits.test
    inc_mask = (test["label"] == onset_label).to_numpy()
    if not inc_mask.any():
        return float("inf")
    onset_idx = int(np.argmax(inc_mask))
    onset_t = float(test["t_sec"].iloc[onset_idx])

    # Score the WHOLE test stream once (single code path) and read the first trip at
    # or after onset. Using the full-stream flags keeps per-counterparty warm-up
    # state identical to the metrics run.
    scores, flags = detector.score(test)
    tsec = test["t_sec"].to_numpy(dtype=float)
    # First trip at index >= onset_idx (the incident or anything after onset).
    after = np.where(flags & (np.arange(len(flags)) >= onset_idx))[0]
    if after.size == 0:
        return float("inf")
    first_trip_t = float(tsec[after[0]])
    return max(0.0, first_trip_t - onset_t)


def evaluate_detector(
    detector: Detector,
    splits: CctxSplits,
    scale: LogScale,
) -> DetectorMetrics:
    """Full metric suite for one detector on the held-out TEST split (task 16.4)."""
    y = splits.y_test
    scores, flags = detector.score(splits.test)

    auc_roc = float(roc_auc_score(y, scores))
    auc_pr = float(average_precision_score(y, scores))
    fpr, tpr, _ = roc_curve(y, scores)
    prec, rec, _ = precision_recall_curve(y, scores)

    cm, f1 = _confusion_and_f1(y, flags)
    benign = splits.test[~y]
    benign_flags = flags[~y]
    phi = float(benign_flags.mean()) if benign_flags.size else 0.0
    n_flagged = int(cm[1, 1] + cm[0, 1])
    precision = (float(cm[1, 1]) / n_flagged) if n_flagged else 0.0

    arl0, censored = measure_arl0_cctx(detector, benign)
    arl1 = measure_arl1_cctx(detector, splits, scale)

    return DetectorMetrics(
        name=detector.name,
        auc_roc=auc_roc,
        auc_pr=auc_pr,
        f1=f1,
        confusion=cm,
        phi=phi,
        precision=precision,
        arl0=arl0,
        arl0_censored=censored,
        arl1=arl1,
        roc_curve=(fpr, tpr),
        pr_curve=(prec, rec),
    )


# ===========================================================================
# V2 2.5. Cross-incident temporal holdout: calibrate strictly BEFORE each onset
# ===========================================================================
@dataclass
class IncidentHoldout:
    label: str                 # "incident:ronin" | "incident:nomad"
    detector: str              # "sequential-cpd" | "value-zscore" | "xchainwatcher-rules"
    onset_ts: "pd.Timestamp"
    calibration_max_ts: "pd.Timestamp"  # max timestamp of the calibration set (leak assert below)
    n_calibration: int         # benign rows strictly before onset used to (re)fit
    n_pos: int
    recall: float
    recall_ci: "RecallCI"
    precision: float
    phi_window: float          # benign flag rate inside the incident window


def cross_incident_holdout(all_rows: pd.DataFrame, *, guard_s: float = 3600.0,
                           horizon_s: float = 7 * 86400.0, seed: int = 42) -> list[IncidentHoldout]:
    """Cross-incident temporal holdout (V2 2.5): "calibrate strictly before the
    incident era, test on the incident".

    For EACH incident label on the reassembled full timeline (train + test in true
    time order): onset = the incident's first row; calibration = **benign-only**
    rows strictly before ``onset − guard_s``; ``LogScale``, ``fast_path_from_train``
    and ``select_params_on_train`` are all REFIT on that calibration set only (no
    future information); then the window ``[onset, onset + horizon_s]`` (benign +
    incident rows in true order) is streamed. Stronger than the single time split
    because *each* incident gets its own no-future-information calibration.

    Reports per (incident × detector): recall over that incident's rows, a
    ``RecallCI`` via ``per_incident_recall_ci``, precision inside the window and
    the benign flag rate φ inside the window. ``detector`` covers the sequential
    detector, the value z-score baseline (same refit scale + fast-path threshold)
    and the xchainwatcher-rules comparator (rule-based, needs no calibration;
    its ~perfect recall is labels-by-construction; see the V2 2.4 note).
    """
    lab_all = all_rows["label"].astype(str)
    is_pos_all = lab_all.str.startswith("incident").to_numpy()
    out: list[IncidentHoldout] = []
    for label in sorted(lab_all[is_pos_all].unique()):
        onset_ts = all_rows.loc[(lab_all == label).to_numpy(), "timestamp"].iloc[0]

        # --- benign-only calibration strictly before onset − guard (no leakage) ---
        calib = all_rows[
            (~is_pos_all)
            & (all_rows["timestamp"] < onset_ts - pd.Timedelta(seconds=guard_s)).to_numpy()
        ].copy()
        calib.sort_values("timestamp", inplace=True, kind="mergesort")
        calib.reset_index(drop=True, inplace=True)
        calib["t_sec"] = (
            (calib["timestamp"] - calib["timestamp"].iloc[0]).dt.total_seconds().astype(float)
        )
        calibration_max_ts = calib["timestamp"].max()

        # --- REFIT scale, fast path and (δ, λ, cap) on the calibration set only ---
        scale_c = LogScale.fit(calib)
        fp = fast_path_from_train(calib, scale_c, q=0.999)
        sel = select_params_on_train(calib, scale_c, seed=seed)

        # --- stream the incident window [onset, onset + horizon] in true order ---
        win = all_rows[
            (all_rows["timestamp"] >= onset_ts).to_numpy()
            & (all_rows["timestamp"] <= onset_ts + pd.Timedelta(seconds=horizon_s)).to_numpy()
        ].copy()
        win.sort_values("timestamp", inplace=True, kind="mergesort")
        win.reset_index(drop=True, inplace=True)
        win["t_sec"] = (
            (win["timestamp"] - win["timestamp"].iloc[0]).dt.total_seconds().astype(float)
        )

        seq = SequentialChangePointDetector.from_baseline(
            calib,
            window_seconds=W0,
            drift=sel.drift,
            threshold=sel.threshold,
            contribution_cap=sel.cap,
            fast_path_z=fp,
        )
        # B4: the value baseline's flag threshold is FPR-matched on THIS incident's
        # calibration set to the same budget the (δ, λ, cap) selection used;
        # previously it flagged at the seq fast-path quantile (a 0.1% budget),
        # an unmatched operating point.
        z_thr = _fpr_matched_threshold(
            np.abs(scale_c.z(calib["value"].to_numpy())), sel.fpr_budget
        )
        z_abs = np.abs(scale_c.z(win["value"].to_numpy()))
        scored: dict[str, np.ndarray] = {
            "sequential-cpd": score_sequential(seq, win, scale_c)[1],
            "value-zscore": (z_abs > z_thr),
            "xchainwatcher-rules": XChainWatcherRules().score_frame(win)[1],
        }

        pos = win["label"].astype(str).str.startswith("incident").to_numpy()
        this = (win["label"].astype(str) == label).to_numpy()
        for dname, flags in scored.items():
            flags = np.asarray(flags, dtype=bool)
            cis = per_incident_recall_ci(win["label"], flags, seed=seed)
            ci = next(c for c in cis if c.label == label)
            tp = int((flags & pos).sum())
            n_flag = int(flags.sum())
            out.append(IncidentHoldout(
                label=label,
                detector=dname,
                onset_ts=onset_ts,
                calibration_max_ts=calibration_max_ts,
                n_calibration=int(len(calib)),
                n_pos=int(this.sum()),
                recall=float(flags[this].mean()) if this.any() else 0.0,
                recall_ci=ci,
                precision=(tp / n_flag) if n_flag else 0.0,
                phi_window=float(flags[~pos].mean()) if (~pos).any() else 0.0,
            ))
    return out


# ===========================================================================
# 16.5. Low-and-slow win: sequential detector catches it, z-score misses
# ===========================================================================
@dataclass
class LowAndSlowResult:
    per_tx_value_usd: float
    per_tx_logz: float
    benign_logz_p99: float
    zscore_catches_per_tx: bool
    legacy_compute_score: float       # monitor.anomaly.compute_score on the injected tx
    legacy_catches: bool              # did the REAL repo value-threshold baseline alarm?
    seq_detects_after_events: Optional[int]
    seq_recall: float                 # per-tx recall on the injected drain
    zscore_recall: float
    # B2(c): H1 as a TESTED hypothesis on a stream where BOTH detectors can
    # plausibly fire: McNemar on the MIXED stream (real benign TEST rows + the
    # injected drain, merged in time order; y = injected mask). The earlier
    # injected-only y=all-True design structurally guaranteed n10=0 (the baseline
    # can never be "right where seq is wrong" when every row is positive and the
    # baseline never fires); that variant is demoted to the illustration counts
    # below, carried with NO p-value.
    h1_mcnemar_mixed: "McNemarResult"
    h1_mixed_n_rows: int              # rows in the mixed stream (benign + injected)
    h1_mixed_n_benign: int            # benign rows in the mixed stream
    h1_injected_n01: int              # illustration ONLY: injected-only discordants
    h1_injected_n10: int              # (n10 = 0 by construction there; no p-value)
    h1_direction_holds: bool          # = seq_recall > zscore_recall
    # Real Nomad structuring subset (honest contrast: mixed, NOT a pure low-and-slow drain)
    nomad_seq_recall_tx: float
    nomad_zscore_recall_tx: float
    nomad_seq_recall_dest: float
    nomad_zscore_recall_dest: float
    nomad_dust_fraction: float        # fraction of structuring rows that are dust (< DUST_USD)
    n_nomad_structuring_dests: int
    # V2 2.6: cluster bootstrap (1000 resamples, seeded) over the structuring
    # DESTINATIONS (resample the destination list with replacement; recompute the
    # per-tx recall over the union of the resampled destinations' rows).
    nomad_seq_recall_tx_ci: tuple[float, float]
    nomad_zscore_recall_tx_ci: tuple[float, float]
    # V2 2.6: dust sub-cohort (value < DUST_USD rows in the COMMON USD
    # denomination; value thresholds are blind here BY CONSTRUCTION, so any
    # nonzero sequential recall is genuine real-data complement evidence). Same
    # cluster bootstrap, restricted to dust rows. NOTE: under the corrected
    # units this cohort may be (and is) near-empty; the previous "88% dust"
    # cohort was a mixed-decimals artifact (~$200 stablecoin transfers read as
    # 2e-7 "ETH"), not real dust.
    nomad_dust_seq_recall: float
    nomad_dust_zscore_recall: float
    nomad_dust_seq_recall_ci: tuple[float, float]
    nomad_dust_zscore_recall_ci: tuple[float, float]
    nomad_dust_n_rows: int
    # V2 2.6. Per-destination ARL1: delay (s) from each structuring destination's
    # first incident tx to the detector's first trip attributable to it; +inf if
    # never detected (REPORTED alongside, never silently dropped). The CI is a
    # percentile bootstrap over the finite per-destination delays.
    arl1_dest_delays_s: list[float]
    arl1_dest_ci: tuple[float, float]
    arl1_dest_n_never: int            # count of never-detected (inf) destinations


def _structuring_destinations(test: pd.DataFrame, min_txs: int = 3) -> list[str]:
    """Real Nomad structuring subset: destinations receiving ≥``min_txs`` incident
    txs (the genuine many-small-transfers-to-one-payee pattern in the CCTX Nomad
    drain). These are the per-counterparty repeats a value threshold ignores."""
    nomad = test[test["label"] == "incident:nomad"]
    counts = nomad["destination"].value_counts()
    return counts[counts >= min_txs].index.tolist()


def _cluster_bootstrap_recall_ci(
    dests: np.ndarray,
    flags: np.ndarray,
    dest_list: Sequence[str],
    n_boot: int = 1000,
    seed: int = 7,
) -> tuple[float, float]:
    """Cluster bootstrap 95% CI for per-tx recall over structuring DESTINATIONS (V2 2.6).

    The destination is the exchangeable unit (rows within one payee are NOT
    independent; that is the whole structuring point), so the destination list is
    resampled with replacement ``n_boot`` times and the per-tx recall is recomputed
    over the union of the resampled destinations' rows each time. Returns the
    2.5/97.5 percentiles of that resampling distribution.
    """
    rng = np.random.default_rng(seed)
    idx_by_dest = {d: np.where(dests == d)[0] for d in dest_list}
    n_dest = len(dest_list)
    stats: list[float] = []
    for _ in range(n_boot):
        sample = rng.choice(n_dest, size=n_dest, replace=True)
        idx = np.concatenate([idx_by_dest[dest_list[j]] for j in sample])
        if idx.size:
            stats.append(float(flags[idx].mean()))
    if not stats:
        return (float("nan"), float("nan"))
    return (float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5)))


def build_injected_drain(
    benign: pd.DataFrame,
    scale: LogScale,
    sigma_above: float,
    n_events: int,
    inter_arrival_s: float = 120.0,
    seed: int = 7,
) -> tuple[pd.DataFrame, float]:
    """One synthetic same-counterparty drain on the REAL benign TEST cadence.

    per-tx value = 10^(μ_log + σ·σ_log); event times = cumsum of real benign
    inter-arrival gaps sampled with a seeded RNG (identical construction to the
    canonical case A, factored out so the B2(b) σ sweep evaluates the SAME
    schedule shape at every σ and isolates the per-tx-magnitude axis).
    Returns ``(slow_df, per_tx_value_usd)``.
    """
    per_tx_value = float(10 ** (scale.mu + sigma_above * scale.sigma))
    rng = np.random.default_rng(seed)
    benign_t = np.sort(benign["t_sec"].to_numpy())
    real_gaps = np.diff(benign_t)
    real_gaps = real_gaps[(real_gaps > 0) & (real_gaps < inter_arrival_s * 10)]
    if real_gaps.size:
        gaps = rng.choice(real_gaps, size=n_events)
    else:
        gaps = np.full(n_events, inter_arrival_s)
    times = np.cumsum(gaps)
    attacker = "0x" + "a" * 40
    slow_df = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(times, unit="s", origin="2022-06-01"),
            "value": np.full(n_events, per_tx_value),
            "destination": [attacker] * n_events,
            "t_sec": times.astype(float),
        }
    )
    return slow_df, per_tx_value


def low_and_slow_win(
    splits: CctxSplits,
    scale: LogScale,
    detectors: list[Detector],
    n_events: int = EVAL_DRAIN_EVENTS,
    sigma_above: float = EVAL_DRAIN_SIGMA,
    inter_arrival_s: float = 120.0,
    seed: int = 7,
) -> LowAndSlowResult:
    """Construct + evaluate the H1 low-and-slow complement evidence (task 16.5 + V2 2.6).

    Three views, presented honestly:

    A. **Injected canonical drain (ILLUSTRATIVE: synthetic schedule on the real
       benign cadence).** Many
       same-counterparty withdrawals, each only ``sigma_above`` log-σ above benign,
       individually *below* the benign 99th-percentile deviation (so a value
       threshold never alarms per-tx) yet accumulating on one key. Injected on the
       REAL benign TEST cadence (sampled real inter-arrival gaps). The sequential
       detector trips via per-counterparty accumulation while the value z-score's
       per-tx recall is 0. We ALSO confirm the actual repo value-threshold baseline
       ``monitor.anomaly.compute_score`` scores the same tx NORMAL, which corroborates
       H1 with the real baseline function, not only the log-scaled comparator.

    B. **Real Nomad structuring subset (honest contrast, NOT a detector win).**
       Destinations that received ≥3 incident transfers in the actual Nomad drain:
       a mixed pattern (repeated mid-6-figure USD transfers to one payee), NOT a
       pure low-and-slow upward drain. Reported transparently (per-tx and
       per-destination recall, dust fraction, plus V2 2.6 cluster bootstrap CIs
       over the destinations) to avoid cherry-picking; the H1 claim rests on the
       injected canonical case (A), not on (B).

    C. **Dust sub-cohort of (B)** (rows with value < ``DUST_USD`` in the common
       USD denomination): drain-direction (large-value) thresholds are blind here
       by construction (the two-sided |log-z| comparator can still flag dust as
       anomalously SMALL), so any nonzero sequential recall would be genuine
       real-data complement evidence; the observed value is reported honestly
       either way, with a cluster CI. Under the corrected units this cohort may
       be near-empty: the former "88% dust" reading was a mixed-decimals artifact.
       Also computes per-destination ARL₁ delays with a bootstrap CI
       (never-detected destinations reported as +inf, not dropped), the honest
       distributional statement behind the n≈1 Nomad-onset ARL₁ point estimate.
    """
    seq = next(d for d in detectors if d.kind == "sequential")
    zsc = next(d for d in detectors if d.kind == "value-zscore")

    # --- A. Injected low-and-slow on the real benign cadence ---
    # B2(a): this (σ, n_events) evaluation geometry is DISJOINT from the
    # TRAIN-only selection family (σ ∈ TRAIN_DRAIN_SIGMAS × TRAIN_DRAIN_EVENTS)
    # that picked (δ, λ, cap); the detector was never tuned to this exact attack.
    assert sigma_above not in TRAIN_DRAIN_SIGMAS and n_events not in TRAIN_DRAIN_EVENTS, (
        "low_and_slow_win called with a geometry inside the param-selection family "
        "— that would re-introduce the B2a circularity"
    )
    benign = splits.test[~splits.y_test]
    slow_df, per_tx_value = build_injected_drain(
        benign, scale, sigma_above, n_events, inter_arrival_s, seed
    )
    per_tx_logz = float(scale.z(np.array([per_tx_value]))[0])
    benign_logz_p99 = float(np.quantile(np.abs(scale.z(benign["value"].to_numpy())), 0.99))
    zscore_catches_per_tx = abs(per_tx_logz) >= benign_logz_p99

    # Corroborate with the REAL repo value-threshold baseline (monitor.anomaly): does
    # the dissertation's own composite scorer alarm on this low-and-slow tx? (It does
    # not: on real heavy-tailed CCTX its raw σ collapses the value_z term.)
    from monitor.anomaly import ALERT_THRESHOLD, compute_score

    legacy_baseline = splits.train[["timestamp", "value", "destination"]]
    legacy_score = float(
        compute_score(
            {"value": per_tx_value, "destination": "0x" + "a" * 40,
             "timestamp": benign["timestamp"].iloc[0]},
            legacy_baseline,
        )
    )
    legacy_catches = legacy_score >= ALERT_THRESHOLD

    # Sequential detector on the injected drain: when does it first trip? recall?
    _, seq_flags = seq.score(slow_df)
    seq_trips = np.where(seq_flags)[0]
    seq_detect_after = int(seq_trips[0]) + 1 if seq_trips.size else None
    seq_recall = float(seq_flags.mean())

    # Value z-score on the injected drain: per-tx recall (each tx below benign p99).
    _, z_flags = zsc.score(slow_df)
    zscore_recall = float(z_flags.mean())

    # B2(c): the HEADLINE paired test. The earlier revision ran McNemar on the
    # injected drain ALONE with y = all-True: with the value baseline 0-recall by
    # construction at this σ, n10 = 0 was GUARANTEED and the p-value was theater.
    # The test now runs on a MIXED stream, the real benign TEST rows with the
    # injected drain merged in time order (y = injected mask), where both
    # detectors can plausibly fire and benign false positives count AGAINST each
    # side, so the discordant pairs are informative in both directions.
    b_cols = benign[["timestamp", "value", "destination", "t_sec"]].copy()
    b_cols["_injected"] = False
    s_cols = slow_df.copy()
    s_cols["_injected"] = True
    mixed = pd.concat([b_cols, s_cols], ignore_index=True)
    mixed.sort_values("t_sec", inplace=True, kind="mergesort")
    mixed.reset_index(drop=True, inplace=True)
    y_mixed = mixed["_injected"].to_numpy(dtype=bool)
    _, seq_mixed_flags = seq.score(mixed)
    _, z_mixed_flags = zsc.score(mixed)
    h1_mcnemar_mixed = mcnemar_test(y_mixed, seq_mixed_flags, z_mixed_flags)

    # Injected-only discordant counts: ILLUSTRATION ONLY (y=all-True design makes
    # n10 = 0 structural whenever the baseline misses every event; no p-value).
    h1_injected_n01 = int((seq_flags & ~z_flags).sum())
    h1_injected_n10 = int((~seq_flags & z_flags).sum())
    h1_direction_holds = seq_recall > zscore_recall

    # --- B. Real Nomad structuring subset (honest contrast) ---
    struct_dests = _structuring_destinations(splits.test, min_txs=3)
    nomad = splits.test[splits.test["label"] == "incident:nomad"]
    struct_rows = nomad[nomad["destination"].isin(struct_dests)].copy()
    if len(struct_rows):
        struct_rows.sort_values("timestamp", inplace=True, kind="mergesort")
        struct_rows.reset_index(drop=True, inplace=True)
        t0 = struct_rows["timestamp"].iloc[0]
        struct_rows["t_sec"] = (struct_rows["timestamp"] - t0).dt.total_seconds().astype(float)
        _, seq_sf = seq.score(struct_rows)
        _, z_sf = zsc.score(struct_rows)
        nomad_seq_recall_tx = float(seq_sf.mean())
        nomad_zscore_recall_tx = float(z_sf.mean())
        dests = struct_rows["destination"].to_numpy()
        n_dest = len(struct_dests)
        nomad_seq_recall_dest = len(set(dests[seq_sf])) / n_dest
        nomad_zscore_recall_dest = len(set(dests[z_sf])) / n_dest
        nomad_dust_fraction = float((struct_rows["value"] < DUST_USD).mean())

        # --- V2 2.6(a): cluster bootstrap CIs over the structuring destinations ---
        nomad_seq_recall_tx_ci = _cluster_bootstrap_recall_ci(
            dests, seq_sf, struct_dests, seed=seed)
        nomad_zscore_recall_tx_ci = _cluster_bootstrap_recall_ci(
            dests, z_sf, struct_dests, seed=seed)

        # --- V2 2.6(b): dust sub-cohort (value < DUST_USD in the common USD
        #     denomination; value thresholds blind by construction; clusters =
        #     destinations that have >=1 dust row). May be empty post-units-fix. ---
        dust_mask = (struct_rows["value"] < DUST_USD).to_numpy()
        nomad_dust_n_rows = int(dust_mask.sum())
        if nomad_dust_n_rows:
            dust_dests_rows = dests[dust_mask]
            dust_seq_sf = seq_sf[dust_mask]
            dust_z_sf = z_sf[dust_mask]
            nomad_dust_seq_recall = float(dust_seq_sf.mean())
            nomad_dust_zscore_recall = float(dust_z_sf.mean())
            dust_dest_list = [d for d in struct_dests if (dust_dests_rows == d).any()]
            nomad_dust_seq_recall_ci = _cluster_bootstrap_recall_ci(
                dust_dests_rows, dust_seq_sf, dust_dest_list, seed=seed)
            nomad_dust_zscore_recall_ci = _cluster_bootstrap_recall_ci(
                dust_dests_rows, dust_z_sf, dust_dest_list, seed=seed)
        else:
            nomad_dust_seq_recall = nomad_dust_zscore_recall = 0.0
            nomad_dust_seq_recall_ci = (float("nan"), float("nan"))
            nomad_dust_zscore_recall_ci = (float("nan"), float("nan"))

        # --- V2 2.6(c): per-destination ARL1 delays on the real structuring replay:
        #     delay = t(first seq trip attributable to the destination) −
        #             t(that destination's first incident tx); +inf if never
        #     detected; REPORTED alongside, never silently dropped. ---
        tsec = struct_rows["t_sec"].to_numpy(dtype=float)
        arl1_dest_delays_s = []
        for d in struct_dests:
            d_mask = dests == d
            t_first = float(tsec[d_mask][0])
            trip_mask = d_mask & seq_sf
            if trip_mask.any():
                arl1_dest_delays_s.append(max(0.0, float(tsec[trip_mask][0]) - t_first))
            else:
                arl1_dest_delays_s.append(float("inf"))
        arl1_dest_n_never = int(sum(1 for x in arl1_dest_delays_s if not np.isfinite(x)))
        finite_delays = np.asarray(
            [x for x in arl1_dest_delays_s if np.isfinite(x)], dtype=float)
        if finite_delays.size:
            rng_arl = np.random.default_rng(seed)
            boot_means = [
                float(np.mean(rng_arl.choice(finite_delays, size=finite_delays.size,
                                             replace=True)))
                for _ in range(1000)
            ]
            arl1_dest_ci = (float(np.percentile(boot_means, 2.5)),
                            float(np.percentile(boot_means, 97.5)))
        else:
            arl1_dest_ci = (float("nan"), float("nan"))
    else:
        nomad_seq_recall_tx = nomad_zscore_recall_tx = 0.0
        nomad_seq_recall_dest = nomad_zscore_recall_dest = 0.0
        nomad_dust_fraction = 0.0
        nomad_seq_recall_tx_ci = (float("nan"), float("nan"))
        nomad_zscore_recall_tx_ci = (float("nan"), float("nan"))
        nomad_dust_seq_recall = nomad_dust_zscore_recall = 0.0
        nomad_dust_seq_recall_ci = (float("nan"), float("nan"))
        nomad_dust_zscore_recall_ci = (float("nan"), float("nan"))
        nomad_dust_n_rows = 0
        arl1_dest_delays_s = []
        arl1_dest_ci = (float("nan"), float("nan"))
        arl1_dest_n_never = 0

    return LowAndSlowResult(
        per_tx_value_usd=per_tx_value,
        per_tx_logz=per_tx_logz,
        benign_logz_p99=benign_logz_p99,
        zscore_catches_per_tx=zscore_catches_per_tx,
        legacy_compute_score=legacy_score,
        legacy_catches=legacy_catches,
        seq_detects_after_events=seq_detect_after,
        seq_recall=seq_recall,
        zscore_recall=zscore_recall,
        h1_mcnemar_mixed=h1_mcnemar_mixed,
        h1_mixed_n_rows=int(len(mixed)),
        h1_mixed_n_benign=int((~y_mixed).sum()),
        h1_injected_n01=h1_injected_n01,
        h1_injected_n10=h1_injected_n10,
        h1_direction_holds=h1_direction_holds,
        nomad_seq_recall_tx=nomad_seq_recall_tx,
        nomad_zscore_recall_tx=nomad_zscore_recall_tx,
        nomad_seq_recall_dest=nomad_seq_recall_dest,
        nomad_zscore_recall_dest=nomad_zscore_recall_dest,
        nomad_dust_fraction=nomad_dust_fraction,
        n_nomad_structuring_dests=len(struct_dests),
        nomad_seq_recall_tx_ci=nomad_seq_recall_tx_ci,
        nomad_zscore_recall_tx_ci=nomad_zscore_recall_tx_ci,
        nomad_dust_seq_recall=nomad_dust_seq_recall,
        nomad_dust_zscore_recall=nomad_dust_zscore_recall,
        nomad_dust_seq_recall_ci=nomad_dust_seq_recall_ci,
        nomad_dust_zscore_recall_ci=nomad_dust_zscore_recall_ci,
        nomad_dust_n_rows=nomad_dust_n_rows,
        arl1_dest_delays_s=arl1_dest_delays_s,
        arl1_dest_ci=arl1_dest_ci,
        arl1_dest_n_never=arl1_dest_n_never,
    )


# ===========================================================================
# B2(b). Low-and-slow σ sweep: show the seq-vs-value CROSSOVER, not one point
# ===========================================================================
@dataclass
class LowSlowSweepPoint:
    sigma: float                      # per-tx log-σ above benign (= |log-z| of each tx)
    per_tx_value_usd: float
    seq_recall: float
    zscore_recall: float
    seq_first_trip_event: Optional[int]
    is_eval_point: bool               # σ == EVAL_DRAIN_SIGMA (the headline geometry)


def lowslow_sigma_sweep(
    splits: CctxSplits,
    scale: LogScale,
    detectors: list[Detector],
    sigmas: Sequence[float] = LOWSLOW_SWEEP_SIGMAS,
    n_events: int = EVAL_DRAIN_EVENTS,
    seed: int = 7,
) -> list[LowSlowSweepPoint]:
    """Per-tx σ sweep of the injected drain (B2b).

    The single-point comparison at σ=1.5 was rigged in the seq detector's favour:
    the drain was injected BELOW the value baseline's threshold, so the value
    baseline's 0.000 recall was true by construction. This sweep evaluates the
    SAME drain schedule at σ levels from well below to well ABOVE the value
    threshold (train-matched ≈ the 1−budget quantile of TRAIN |log-z|), so the
    reader sees the full trade: the sequential detector catches the drain at every
    σ via accumulation, while the value baseline is blind below its threshold and
    only matches the seq detector once each individual tx is large enough to flag
    on its own. Same seed per σ → identical cadence, which isolates the magnitude axis.
    """
    seq = next(d for d in detectors if d.kind == "sequential")
    zsc = next(d for d in detectors if d.kind == "value-zscore")
    benign = splits.test[~splits.y_test]
    out: list[LowSlowSweepPoint] = []
    for sigma in sigmas:
        slow_df, per_tx = build_injected_drain(benign, scale, sigma, n_events, seed=seed)
        _, sf = seq.score(slow_df)
        _, zf = zsc.score(slow_df)
        trips = np.where(sf)[0]
        out.append(LowSlowSweepPoint(
            sigma=float(sigma),
            per_tx_value_usd=per_tx,
            seq_recall=float(sf.mean()),
            zscore_recall=float(zf.mean()),
            seq_first_trip_event=(int(trips[0]) + 1) if trips.size else None,
            is_eval_point=bool(np.isclose(sigma, EVAL_DRAIN_SIGMA)),
        ))
    return out


def sweep_crossover_sigma(sweep: list[LowSlowSweepPoint]) -> Optional[float]:
    """Smallest swept σ at which the value baseline attains nonzero recall."""
    hits = [p.sigma for p in sweep if p.zscore_recall > 0.0]
    return min(hits) if hits else None


def write_lowslow_sweep_figure(sweep: list[LowSlowSweepPoint], z_thresh: float) -> None:
    """figures/lowslow_sweep.png: recall vs per-tx σ with the crossover shown."""
    FIG_LOWSLOW.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    xs = [p.sigma for p in sweep]
    ax.plot(xs, [p.seq_recall for p in sweep], "o-", color="tab:blue",
            label="sequential-cpd (accumulation)")
    ax.plot(xs, [p.zscore_recall for p in sweep], "s-", color="tab:orange",
            label="value-zscore (per-tx threshold)")
    ax.axvline(z_thresh, color="tab:red", ls="--", lw=1.2,
               label=f"value threshold (TRAIN-matched) = {z_thresh:.2f} log-σ")
    for p in sweep:
        if p.is_eval_point:
            ax.axvline(p.sigma, color="gray", ls=":", lw=1.0)
            ax.annotate("eval point σ=1.5\n(disjoint from selection\nfamily σ∈{1.0, 2.0})",
                        xy=(p.sigma, 0.5), fontsize=7, ha="left",
                        xytext=(p.sigma + 0.05, 0.42))
    ax.set_xlabel("per-tx drain magnitude σ (log-σ above benign μ_log)")
    ax.set_ylabel(f"recall on the injected {EVAL_DRAIN_EVENTS}-event drain")
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8, loc="center right")
    ax.set_title("B2b — low-and-slow σ sweep: value baseline blind below its threshold,\n"
                 "sequential detector catches the drain at every σ (crossover shown)",
                 fontsize=9)
    plt.tight_layout()
    plt.savefig(FIG_LOWSLOW, dpi=300)
    plt.close(fig)
    print(f"Figure saved: {FIG_LOWSLOW}")


# ===========================================================================
# 16.6. Confidence intervals (B5: ≥1000 stratified bootstrap resamples)
# ===========================================================================
@dataclass
class CISummary:
    name: str
    auc_roc_mean: float
    auc_roc_lo: float
    auc_roc_hi: float
    auc_pr_mean: float
    auc_pr_lo: float
    auc_pr_hi: float
    f1_mean: float
    f1_lo: float
    f1_hi: float
    phi_mean: float
    phi_lo: float
    phi_hi: float
    n_boot: int                      # B5: bootstrap RESAMPLES (never "seeds")


def _ci95(samples: Sequence[float]) -> tuple[float, float, float]:
    arr = np.asarray(samples, dtype=float)
    mean = float(np.mean(arr))
    lo = float(np.percentile(arr, 2.5))
    hi = float(np.percentile(arr, 97.5))
    return mean, lo, hi


def bootstrap_cis(
    detector: Detector,
    splits: CctxSplits,
    n_boot: int = N_BOOT,
    seed: int = BOOT_SEED,
) -> CISummary:
    """Stratified bootstrap CI for AUC-ROC / AUC-PR / F1 / φ on TEST (task 16.6).

    **B5 (CI construction):** an earlier revision drew only 12 resamples and
    called them "12 seeds"; they were 12 bootstrap draws of ONE deterministic
    detector output (never independent replicates), and the 2.5th percentile of
    12 points is just the sample minimum, so those bands were not credible 95%
    intervals. This version draws ``n_boot`` (default 1000, asserted ≥1000 in
    main) stratified resamples from a single seeded RNG.

    **Stratified TWO-SIDED bootstrap.** Each resample draws BOTH classes with
    replacement: the incident POSITIVES *and* the benign background are each
    drawn (with replacement) to their own size, which preserves the rare-positive
    class ratio per resample. This is the standard rare-positive bootstrap: it lets the
    small incident set vary so the reported AUC-ROC / AUC-PR / F1 CIs HONESTLY
    bracket the sampling variability of the rare class the whole evaluation hinges
    on, rather than freezing the positives (which artificially narrows exactly
    those headline bands). φ's CI comes from the benign resample (φ is a
    benign-only quantity, so its positives draw is immaterial).

    The detector's continuous scores and binary flags are computed ONCE on the full
    test stream (the streaming temporal state is deterministic, so re-running the
    detector per resample would be the wrong randomisation); the bootstrap resamples
    which rows of each class enter the metric. Reports mean ± 95% percentile CI.
    """
    y = splits.y_test
    scores, flags = detector.score(splits.test)
    pos_idx = np.where(y)[0]
    neg_idx = np.where(~y)[0]

    rng = np.random.default_rng(int(seed))
    auc_rocs, auc_prs, f1s, phis = [], [], [], []
    for _ in range(n_boot):
        # Resample BOTH classes with replacement (stratified two-sided bootstrap),
        # so the rare positives vary too and the AUC-PR/F1/AUC-ROC CIs are honest.
        boot_pos = rng.choice(pos_idx, size=pos_idx.size, replace=True)
        boot_neg = rng.choice(neg_idx, size=neg_idx.size, replace=True)
        idx = np.concatenate([boot_pos, boot_neg])
        yb = y[idx]
        sb = scores[idx]
        fb = flags[idx]
        auc_rocs.append(roc_auc_score(yb, sb))
        auc_prs.append(average_precision_score(yb, sb))
        f1s.append(f1_score(yb, fb, zero_division=0))
        phis.append(float(fb[~yb].mean()) if (~yb).any() else 0.0)

    ar_m, ar_lo, ar_hi = _ci95(auc_rocs)
    ap_m, ap_lo, ap_hi = _ci95(auc_prs)
    f_m, f_lo, f_hi = _ci95(f1s)
    p_m, p_lo, p_hi = _ci95(phis)
    return CISummary(
        name=detector.name,
        auc_roc_mean=ar_m, auc_roc_lo=ar_lo, auc_roc_hi=ar_hi,
        auc_pr_mean=ap_m, auc_pr_lo=ap_lo, auc_pr_hi=ap_hi,
        f1_mean=f_m, f1_lo=f_lo, f1_hi=f_hi,
        phi_mean=p_m, phi_lo=p_lo, phi_hi=p_hi,
        n_boot=n_boot,
    )


# ===========================================================================
# 16.6. Sensitivity sweep over {T, B, r, W, Δ}
# ===========================================================================
@dataclass
class SensitivityPoint:
    axis: str
    value: float
    auc_roc: float
    phi: float
    arl1: float


def sensitivity_sweep(
    splits: CctxSplits,
    scale: LogScale,
    seed: int = 42,
    *,
    drift: float = LEGACY_PARAMS[0],
    threshold: float = LEGACY_PARAMS[1],
    contribution_cap: float = LEGACY_PARAMS[2],
) -> dict[str, list[SensitivityPoint]]:
    """How detection metrics move as each of {T, B, r, W, Δ} varies (task 16.6).

    The detector's own knob is the window **W** (it re-bins the per-counterparty
    accumulator). **T, B, r, Δ** are limiter/breaker/latency parameters that govern
    the *response* path: they do not change the detector's per-row scores but they
    change the realised ARL₁ the system delivers, because the pause only becomes
    EFFECTIVE at the signal time + Δ and the bucket/threshold gate the residual drain.
    We therefore report:

    * **W**  → re-fit the detector at each window and recompute AUC-ROC, φ, ARL₁ on
      the held-out test (a true detector-side sensitivity).
    * **T, B, r, Δ** → hold the detector fixed and report the *effective* time-to-halt
      ``D_eff`` the limiter/breaker/Δ stack adds on top of the detector signal, using
      the Phase-14 patient-bound timing (signal at D, pause effective at D+Δ). AUC/φ
      are detector-side and unchanged along these axes (reported flat), so the
      separation between detection power and response latency stays explicit.
    """
    out: dict[str, list[SensitivityPoint]] = {}

    # --- W axis: genuine detector-side sensitivity (re-fit per window) ---
    w_grid = [900.0, 1800.0, 3600.0, 7200.0, 14400.0]
    pts_w = []
    for w in w_grid:
        fp = fast_path_from_train(splits.train, scale, q=0.999)
        seq = SequentialChangePointDetector.from_baseline(
            splits.train, window_seconds=w, drift=drift, threshold=threshold,
            contribution_cap=contribution_cap, fast_path_z=fp,
        )
        det = Detector("seq", lambda df, _s=seq: score_sequential(_s, df, scale), "sequential")
        scores, flags = det.score(splits.test)
        auc = float(roc_auc_score(splits.y_test, scores))
        phi = float(flags[~splits.y_test].mean())
        arl1 = measure_arl1_cctx(det, splits, scale)
        pts_w.append(SensitivityPoint("W", w, auc, phi, arl1))
    out["W"] = pts_w

    # Baseline detector AUC/φ (fixed) for the response-path axes.
    fp = fast_path_from_train(splits.train, scale, q=0.999)
    seq0 = SequentialChangePointDetector.from_baseline(
        splits.train, window_seconds=W0, drift=drift, threshold=threshold,
        contribution_cap=contribution_cap, fast_path_z=fp,
    )
    det0 = Detector("seq", lambda df: score_sequential(seq0, df, scale), "sequential")
    s0, f0 = det0.score(splits.test)
    auc0 = float(roc_auc_score(splits.y_test, s0))
    phi0 = float(f0[~splits.y_test].mean())
    # Detector signal time on real data (ARL1 from onset, seconds).
    d_signal = measure_arl1_cctx(det0, splits, scale)
    if not np.isfinite(d_signal):
        d_signal = D0  # fall back to the published generator D if no real-onset trip

    def response_arl1(delta: float, B: float, r: float, T: float) -> float:
        """Effective time-to-halt = detector signal + Δ (pause effective at D+Δ),
        the Phase-14 patient-regime timing. B, r, T do not move the *time* of the
        signal here (they bound the *value* extracted, per the BOLT bound), so the
        time axis is dominated by Δ; we surface that explicitly."""
        return float(d_signal + delta)

    # --- Δ axis: response latency directly lengthens effective ARL₁ ---
    out["Delta"] = [
        SensitivityPoint("Delta", d, auc0, phi0, response_arl1(d, B0, R0, T0))
        for d in [12.0, 24.0, 60.0, 120.0, 300.0]
    ]
    # --- T, B, r axes: detector-side AUC/φ flat (response-path knobs); ARL₁ at Δ0 ---
    out["T"] = [
        SensitivityPoint("T", t, auc0, phi0, response_arl1(DELTA0, B0, R0, t))
        for t in [1000.0, 2500.0, 5000.0, 10000.0, 20000.0]
    ]
    out["B"] = [
        SensitivityPoint("B", b, auc0, phi0, response_arl1(DELTA0, b, R0, T0))
        for b in [250.0, 500.0, 1000.0, 2000.0, 4000.0]
    ]
    out["r"] = [
        SensitivityPoint("r", rr, auc0, phi0, response_arl1(DELTA0, B0, rr, T0))
        for rr in [0.25, 0.5, 1.0, 2.0, 4.0]
    ]
    return out


# ===========================================================================
# V2 2.3. Ablation grids (evaluation-only; selection never saw TEST)
# ===========================================================================
def cusum_ablation_grid(
    splits: CctxSplits,
    scale: LogScale,
    selected: SelectedParams,
) -> list[dict]:
    """Evaluate the FULL 45-config (λ, δ, cap) selection grid on TEST.

    Evaluation-only: the selection (``select_params_on_train``) saw TRAIN only;
    this grid shows, per config, the TEST AUC-ROC and benign φ plus Δ columns vs
    the selected config, so the reader can see how sensitive the headline numbers
    are to the train-selected triple (and where the legacy hand-picked triple sits).
    """
    fp = fast_path_from_train(splits.train, scale, q=0.999)
    y = splits.y_test
    rows: list[dict] = []
    for lam, d, c in selection_grid():
        seq = SequentialChangePointDetector.from_baseline(
            splits.train, window_seconds=W0, drift=d, threshold=lam,
            contribution_cap=c, fast_path_z=fp,
        )
        det = Detector("seq-ablate", lambda df, _s=seq: score_sequential(_s, df, scale),
                       "sequential")
        scores, flags = det.score(splits.test)
        rows.append({
            "lambda": lam, "drift": d, "cap": c,
            "auc_roc": float(roc_auc_score(y, scores)),
            "phi": float(flags[~y].mean()),
            "selected": (d, lam, c) == (selected.drift, selected.threshold, selected.cap),
            "legacy": (d, lam, c) == (LEGACY_PARAMS[0], LEGACY_PARAMS[1], LEGACY_PARAMS[2]),
        })
    sel_row = next(r for r in rows if r["selected"])
    for r in rows:
        r["d_auc"] = r["auc_roc"] - sel_row["auc_roc"]
        r["d_phi"] = r["phi"] - sel_row["phi"]
    return rows


# Composite-weight ablation grid (dissertation weights are the delta reference).
WEIGHT_GRID = [
    (1.0, 0.0, 0.0),
    (0.8, 0.1, 0.1),
    (0.6, 0.3, 0.1),
    (0.5, 0.3, 0.2),       # dissertation §11.2.3 default
    (0.4, 0.4, 0.2),
    (1 / 3, 1 / 3, 1 / 3),
]
ALERT_AXIS = (2.0, 3.0, 4.0, 6.0)  # 3.0 = dissertation-fixed operating point


def _composite_components(splits: CctxSplits) -> tuple[np.ndarray, float, np.ndarray]:
    """Vectorised ``monitor.anomaly.compute_score`` components on TEST vs TRAIN.

    Exactly the one-shot (window=None) mode: raw-value mean/σ z, the constant
    single-tx-hour vol_z, and destination novelty vs the TRAIN destination set.
    Verified below against the real ``compute_score`` on sample rows (the loop
    version is O(train) per call, so scoring 25k TEST rows × 6 weight configs is
    only tractable vectorised).
    """
    from monitor.anomaly import compute_score

    baseline = splits.train[["timestamp", "value", "destination"]]
    test = splits.test
    mean_val = baseline["value"].mean()
    std_val = baseline["value"].std()
    value_z = (test["value"].to_numpy(dtype=float) - mean_val) / max(std_val, 1e-9)

    hourly = baseline.groupby(baseline["timestamp"].dt.floor("h")).size()
    vol_z = float((1 - hourly.mean()) / max(hourly.std(), 1e-9))

    known = set(baseline["destination"])
    dest_novelty = (~test["destination"].isin(known)).to_numpy(dtype=float)

    # Fidelity check: the vectorised composite must equal compute_score exactly
    # (same formulas, same defaults) on a deterministic sample of rows.
    idx = np.linspace(0, len(test) - 1, num=5, dtype=int)
    for i in idx:
        tx = {
            "value": float(test["value"].iloc[i]),
            "destination": test["destination"].iloc[i],
            "timestamp": test["timestamp"].iloc[i],
        }
        expect = compute_score(tx, baseline)
        got = 0.5 * value_z[i] + 0.3 * vol_z + 0.2 * dest_novelty[i]
        assert np.isclose(expect, got, rtol=1e-9, atol=1e-9), (
            f"vectorised composite diverges from compute_score at row {i}: "
            f"{got} != {expect}"
        )
    return value_z, vol_z, dest_novelty


def weight_ablation_grid(splits: CctxSplits, scale: LogScale) -> list[dict]:
    """Composite-weight ablation: score every TEST row one-shot with
    ``compute_score(tx, train_baseline, weights=w)`` (vectorised equivalent,
    fidelity-asserted), report AUC-ROC / φ / recall at ALERT=3.0 per weight
    vector, with Δ columns vs the dissertation default (0.5, 0.3, 0.2).

    The weights are dissertation-fixed (§11.2.3): this grid ABLATES them for
    transparency; it does not (and must not) select them.
    """
    from monitor.anomaly import ALERT_THRESHOLD

    value_z, vol_z, dest_novelty = _composite_components(splits)
    y = splits.y_test
    rows: list[dict] = []
    for w in WEIGHT_GRID:
        s = w[0] * value_z + w[1] * vol_z + w[2] * dest_novelty
        flags = s >= ALERT_THRESHOLD
        rows.append({
            "weights": w,
            "auc_roc": float(roc_auc_score(y, s)),
            "phi": float(flags[~y].mean()),
            "recall": float(flags[y].mean()),
            "default": np.allclose(w, (0.5, 0.3, 0.2)),
        })
    base = next(r for r in rows if r["default"])
    for r in rows:
        r["d_auc"] = r["auc_roc"] - base["auc_roc"]
        r["d_phi"] = r["phi"] - base["phi"]
    return rows


def alert_threshold_axis(splits: CctxSplits, scale: LogScale) -> list[dict]:
    """ALERT-threshold axis at the DEFAULT weights (0.5, 0.3, 0.2).

    AUC is threshold-free, so this axis carries operating-point φ + recall only,
    at ALERT ∈ {2.0, 3.0, 4.0, 6.0} (3.0 = the dissertation-fixed operating point;
    6.0 doubles as the CRITICAL threshold).
    """
    value_z, vol_z, dest_novelty = _composite_components(splits)
    y = splits.y_test
    s = 0.5 * value_z + 0.3 * vol_z + 0.2 * dest_novelty
    rows: list[dict] = []
    for thr in ALERT_AXIS:
        flags = s >= thr
        rows.append({
            "alert": thr,
            "phi": float(flags[~y].mean()),
            "recall": float(flags[y].mean()),
            "dissertation_fixed": thr == 3.0,
        })
    return rows


def write_ablations_md(
    selected: SelectedParams,
    cusum_rows: list[dict],
    weight_rows: list[dict],
    thresh_rows: list[dict],
) -> None:
    """Render the three ablation tables + the parameter-provenance header."""
    FIG_ABLATIONS_MD.parent.mkdir(parents=True, exist_ok=True)
    L: list[str] = []
    L.append("# BOLT ablations — detector & composite parameters (V2 task 2.3)")
    L.append("")
    L.append("Generated by `scenarios/scenario_6_detection_eval.py` (`make detector-eval`).")
    L.append("")
    L.append("## Provenance — every parameter, its selection procedure or citation")
    L.append("")
    L.append("| Parameter | Value | Provenance |")
    L.append("|---|---|---|")
    L.append(
        f"| δ (drift), λ (threshold), cap | ({selected.drift:g}, {selected.threshold:g}, "
        f"{selected.cap:g}) | **Train-selected** — {selected.procedure} "
        f"(φ_train={selected.phi_train:.5f}, power_train={selected.power_train:.3f}) |"
    )
    L.append(
        f"| legacy δ/λ/cap | ({LEGACY_PARAMS[0]:g}, {LEGACY_PARAMS[1]:g}, "
        f"{LEGACY_PARAMS[2]:g}) | Phase-12 hand-picked; retained ONLY as the ablation "
        "delta reference below |"
    )
    L.append(
        f"| W (window) | {W0:g} s | Ledger-locked (docs/bolt/theorem.md); "
        "sensitivity-swept in scenario_6 (900–14400 s axis) |"
    )
    L.append(
        "| fast_path_z | train q=0.999 quantile | Train-derived "
        "(`fast_path_from_train`), never tuned on TEST |"
    )
    L.append(
        "| composite weights (w_val, w_vol, w_dest) | (0.5, 0.3, 0.2) | "
        "Dissertation §11.2.3 constant — ablated below, never train-selected |"
    )
    L.append(
        "| ALERT / CRITICAL | 3.0 / 6.0 | Dissertation §11.2.3 constant — "
        "see justification below |"
    )
    L.append(
        f"| B, r, T, D | {B0:g} ETH, {R0:g} ETH/s, {T0:g} ETH, {D0:g} s | "
        "Ledger-locked (.superpowers/PROGRESS.md); response-path, not detector knobs |"
    )
    L.append("")
    L.append("**δ/λ/cap selection (design decision, V2 2.3):** TRAIN is 100% benign, so")
    L.append("Youden-J is not computable on TRAIN alone. We adopt the **FPR-budget**")
    L.append("procedure: grid-search (λ, δ, cap) ∈ {4, 6, 8, 12, 16} × {0.25, 0.5, 1.0} ×")
    L.append("{1.5, 2.0, 3.0} (skipping cap ≤ δ); constraint φ_train ≤ 0.01 (benign flag")
    L.append("rate on the TRAIN stream); among admissible configs maximise power on")
    L.append("canonical drains *injected into the TRAIN cadence* (never TEST); tie-break on")
    L.append("lowest φ_train. Alternative (Youden-J on TRAIN+injections) rejected in one")
    L.append("line: it optimises a synthetic mixture ratio we would have to invent, whereas")
    L.append("the FPR budget is an operational quantity the reframed 2.1 claim already")
    L.append("commits to.")
    L.append("")
    L.append("**Composite operating point (ALERT=3.0 / CRITICAL=6.0):** these two thresholds")
    L.append("are dissertation-fixed (§11.2.3) and deliberately kept out of the")
    L.append("train-selection scope — their FPR behaviour is already characterised")
    L.append("empirically by scenario_4 (`scenarios/scenario_4_fpr_sweep.py` probes the")
    L.append("alert/critical thresholds across four synthetic buckets). To meet the \"every")
    L.append("parameter has a documented selection procedure\" acceptance line honestly, the")
    L.append("ablation below adds an explicit ALERT-threshold axis (threshold ∈")
    L.append("{2.0, 3.0, 4.0, 6.0} at the default weights, φ + recall reported).")
    L.append("")
    L.append("## Table 1 — CUSUM (λ, δ, cap) grid on TEST")
    L.append("")
    L.append("*Evaluation-only: selection never saw TEST.* Δ columns vs the **selected**")
    L.append(f"config (δ={selected.drift:g}, λ={selected.threshold:g}, cap={selected.cap:g});")
    L.append("`legacy` marks the old hand-picked triple (0.5, 8.0, 2.0).")
    L.append("")
    L.append("| λ | δ | cap | AUC-ROC | φ | ΔAUC vs selected | Δφ vs selected | note |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in cusum_rows:
        note = "**selected**" if r["selected"] else ("legacy" if r["legacy"] else "")
        L.append(
            f"| {r['lambda']:g} | {r['drift']:g} | {r['cap']:g} | {r['auc_roc']:.4f} | "
            f"{r['phi']:.4f} | {r['d_auc']:+.4f} | {r['d_phi']:+.4f} | {note} |"
        )
    L.append("")
    L.append("## Table 2 — composite-weight grid on TEST (weights dissertation-fixed; ablated, not selected)")
    L.append("")
    L.append("Every TEST row scored one-shot with `compute_score(tx, train_baseline,")
    L.append("weights=w)` (vectorised equivalent, fidelity-asserted against the real")
    L.append("function); operating point ALERT=3.0. Δ columns vs the dissertation default")
    L.append("(0.5, 0.3, 0.2).")
    L.append("")
    L.append("| (w_val, w_vol, w_dest) | AUC-ROC | φ @3.0 | recall @3.0 | ΔAUC vs default | Δφ vs default | note |")
    L.append("|---|---|---|---|---|---|---|")
    for r in weight_rows:
        w = r["weights"]
        note = "**dissertation default**" if r["default"] else ""
        L.append(
            f"| ({w[0]:.3g}, {w[1]:.3g}, {w[2]:.3g}) | {r['auc_roc']:.4f} | "
            f"{r['phi']:.4f} | {r['recall']:.4f} | {r['d_auc']:+.4f} | "
            f"{r['d_phi']:+.4f} | {note} |"
        )
    L.append("")
    L.append("## Table 3 — ALERT-threshold axis at the default weights (0.5, 0.3, 0.2)")
    L.append("")
    L.append("AUC is threshold-free, so this axis carries operating-point φ/recall only.")
    L.append("")
    L.append("| ALERT threshold | φ | recall | note |")
    L.append("|---|---|---|---|")
    for r in thresh_rows:
        note = "**dissertation-fixed operating point**" if r["dissertation_fixed"] else (
            "= CRITICAL threshold" if r["alert"] == 6.0 else ""
        )
        L.append(f"| {r['alert']:g} | {r['phi']:.4f} | {r['recall']:.4f} | {note} |")
    L.append("")
    FIG_ABLATIONS_MD.write_text("\n".join(L) + "\n")
    print(f"Ablations written: {FIG_ABLATIONS_MD}")


# ===========================================================================
# Figures
# ===========================================================================

# --- publication display names -------------------------------------------
# xchainwatcher-rules scores the very rules the corpus labels were built from,
# so its near-perfect recall is labels-by-construction, not an independent
# result. The figure legend says so, since figures travel without their caption.
_DISPLAY_NAME = {
    "xchainwatcher-rules": "xchainwatcher-rules (labels-by-construction)",
}


def _disp(name: str) -> str:
    return _DISPLAY_NAME.get(name, name)

def write_roc_pr_figure(metrics: list[DetectorMetrics], n_pos: int, n_test: int) -> None:
    FIG_ROC_PR.parent.mkdir(parents=True, exist_ok=True)
    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(13, 5.2))
    colors = plt.cm.tab10(np.linspace(0, 1, len(metrics)))
    for m, c in zip(metrics, colors):
        fpr, tpr = m.roc_curve
        ax_roc.plot(fpr, tpr, color=c, lw=1.8, label=f"{_disp(m.name)} (AUC={m.auc_roc:.3f})")
        prec, rec = m.pr_curve
        ax_pr.plot(rec, prec, color=c, lw=1.8, label=f"{_disp(m.name)} (AP={m.auc_pr:.3f})")
    ax_roc.plot([0, 1], [0, 1], "--", color="gray", lw=1, label="chance")
    ax_roc.set_xlabel("false positive rate")
    ax_roc.set_ylabel("true positive rate")
    ax_roc.set_title("ROC — real CCTX test split (incident:* vs benign)")
    ax_roc.legend(loc="lower right", fontsize=8)
    ax_roc.grid(True, alpha=0.3)

    # Positive prevalence reference line for PR.
    ax_pr.set_xlabel("recall")
    ax_pr.set_ylabel("precision")
    ax_pr.set_title(f"Precision–Recall — rare positives ({n_pos} incident / {n_test:,})")
    ax_pr.legend(loc="upper right", fontsize=8)
    ax_pr.grid(True, alpha=0.3)
    # internal run title removed; the LaTeX caption carries this context
    plt.tight_layout()
    plt.savefig(FIG_ROC_PR, dpi=300)
    plt.close(fig)
    print(f"Figure saved: {FIG_ROC_PR}")


def write_arl_figure(metrics: list[DetectorMetrics], lns: LowAndSlowResult) -> None:
    FIG_ARL.parent.mkdir(parents=True, exist_ok=True)
    fig, (ax_arl, ax_lns) = plt.subplots(1, 2, figsize=(13, 5.2))

    names = [m.name for m in metrics]
    x = np.arange(len(names))
    arl0 = [m.arl0 for m in metrics]
    arl1 = [m.arl1 if np.isfinite(m.arl1) else np.nan for m in metrics]
    width = 0.38
    ax_arl.bar(x - width / 2, arl0, width, label="ARL₀ (benign run length, ↑ better)",
               color="tab:green", alpha=0.8)
    ax_arl.bar(x + width / 2, arl1, width, label="ARL₁ (time-to-detect, ↓ better)",
               color="tab:red", alpha=0.8)
    for i, m in enumerate(metrics):
        if m.arl0_censored:
            ax_arl.text(i - width / 2, m.arl0, "≥", ha="center", va="bottom", fontsize=10)
        if not np.isfinite(m.arl1):
            ax_arl.text(i + width / 2, 1.0, "∞", ha="center", va="bottom", fontsize=12, color="tab:red")
    ax_arl.set_yscale("log")
    ax_arl.set_xticks(x)
    ax_arl.set_xticklabels(names, rotation=20, ha="right", fontsize=8)
    ax_arl.set_ylabel("seconds (log)")
    ax_arl.set_title("ARL₀ vs ARL₁ on real CCTX (ARL₀ '≥' = right-censored lower bound)")
    ax_arl.legend(fontsize=8)
    ax_arl.grid(True, which="both", alpha=0.3)

    # Low-and-slow recall panel: sequential vs z-score. The HEADLINE is the injected
    # canonical drain (left); the real Nomad subset (right) is an honest contrast: it
    # is mixed (huge + dust), not a pure low-and-slow drain, so the value threshold
    # does better there. Both shown to avoid cherry-picking.
    groups = ["injected\nlow-and-slow\n(H1 headline)", "real Nomad\nstructuring\n(mixed; contrast)"]
    seq_vals = [lns.seq_recall, lns.nomad_seq_recall_tx]
    z_vals = [lns.zscore_recall, lns.nomad_zscore_recall_tx]
    xg = np.arange(len(groups))
    ax_lns.bar(xg - width / 2, seq_vals, width, label="sequential-cpd", color="tab:blue")
    ax_lns.bar(xg + width / 2, z_vals, width, label="value-zscore", color="tab:orange")
    ax_lns.set_xticks(xg)
    ax_lns.set_xticklabels(groups, fontsize=8)
    ax_lns.set_ylabel("recall @ operating point")
    ax_lns.set_ylim(0, 1.05)
    ax_lns.set_title("H1 low-and-slow recall (detector vs value threshold)", fontsize=10)
    ax_lns.legend(fontsize=8)
    ax_lns.grid(True, axis="y", alpha=0.3)
    # internal run title removed; the LaTeX caption carries this context
    plt.tight_layout()
    plt.savefig(FIG_ARL, dpi=300)
    plt.close(fig)
    print(f"Figure saved: {FIG_ARL}")


def write_sensitivity_figure(sens: dict[str, list[SensitivityPoint]]) -> None:
    FIG_SENS.parent.mkdir(parents=True, exist_ok=True)
    axes_order = ["T", "B", "r", "W", "Delta"]
    fig, axarr = plt.subplots(1, len(axes_order), figsize=(19, 4.0))
    for ax, axis in zip(axarr, axes_order):
        pts = sens[axis]
        xs = [p.value for p in pts]
        auc = [p.auc_roc for p in pts]
        arl1 = [p.arl1 for p in pts]
        ax.plot(xs, auc, "o-", color="tab:blue", label="AUC-ROC")
        ax.set_xlabel(axis)
        ax.set_ylabel("AUC-ROC", color="tab:blue")
        ax.set_ylim(0, 1.0)
        ax.tick_params(axis="y", labelcolor="tab:blue")
        ax2 = ax.twinx()
        ax2.plot(xs, arl1, "s--", color="tab:red", label="ARL₁ (s)")
        ax2.set_ylabel("ARL₁ (s)", color="tab:red")
        ax2.tick_params(axis="y", labelcolor="tab:red")
        ax.set_title(f"sensitivity to {axis}")
        ax.grid(True, alpha=0.3)
    fig.suptitle(
        "BOLT Phase 16 — detection sensitivity over {T, B, r, W, Δ} "
        "(W is detector-side; T,B,r,Δ are response-path → ARL₁)"
    )
    plt.tight_layout()
    plt.savefig(FIG_SENS, dpi=300)
    plt.close(fig)
    print(f"Figure saved: {FIG_SENS}")


# ===========================================================================
# Log
# ===========================================================================
def write_log(
    splits: CctxSplits,
    scale: LogScale,
    selected: SelectedParams,
    metrics: list[DetectorMetrics],
    cis: list[CISummary],
    lns: LowAndSlowResult,
    sens: dict[str, list[SensitivityPoint]],
    elapsed_s: float,
    arl1_nomad_seq: float,
    delong_rows: list[tuple[str, DeLongResult]],
    mcnemar_rows: list[tuple[str, McNemarResult]],
    incident_cis: list[tuple[str, list[RecallCI]]],
    holdouts: list[IncidentHoldout],
    sweep: list["LowSlowSweepPoint"],
    z_thresh_matched: float,
    auc_rm: float,
    ap_rm: float,
    default_rows: list[tuple[str, float, float, float]],
    calibrations: list[tuple[str, str]],
) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    L: list[str] = []
    L.append("# BOLT Phase 16 — real-CCTX detection evaluation (scenario_6)")
    L.append("# contribution C1-eval; closes gap G3 (circular '0% FPR') — non-circular evaluation")
    L.append("#")
    L.append("# ANTI-CIRCULARITY NOTE (the whole point of Phase 16):")
    L.append("#   thresholds/location-scale for EVERY detector are calibrated on the TRAIN split")
    L.append("#   (data/cctx/train.parquet, 100% benign). ALL metrics (ROC/PR/AUC/F1/phi/ARL) are")
    L.append("#   measured on the HELD-OUT TEST split (data/cctx/test.parquet), which is where the")
    L.append("#   incident rows live. train != test; the threshold-setting data is NEVER scored.")
    L.append(f"#   train rows={len(splits.train)} (benign), test rows={len(splits.test)} "
             f"(benign + {int(splits.y_test.sum())} incident).")
    L.append(f"#   sha256 verified: train={splits.sha_verified['train']} test={splits.sha_verified['test']}")
    L.append(f"#   positive labels: {splits.positive_labels}")
    L.append("#")
    L.append("# UNITS: the raw CCTX 'value' is the on-chain amount in token BASE UNITS with MIXED")
    L.append("#   per-token decimals (18-dec ETH-class next to 6-dec USDC / 8-dec WBTC) — NOT")
    L.append("#   cross-token comparable, so all detectors score value_usd (upstream per-tx USD")
    L.append("#   valuation, the one common denomination). Verified on the Ronin drain row:")
    L.append(f"#   1.736e23 base units = {RONIN_ETH:,.0f} ETH and value_usd = {RONIN_USD:,.0f} USD.")
    L.append("# SCALE: heavy-tailed value scored as signed log-z (log10(value)-mu_log)/sigma_log,")
    L.append(f"#   mu_log={scale.mu:.4f} sigma_log={scale.sigma:.4f} calibrated on TRAIN benign;")
    L.append("#   identical scale for the detector's value_z feature and the value baselines.")
    L.append(f"# runtime: {elapsed_s:.1f}s  (node-less; pure Python/data)")
    L.append("#")
    L.append("# PARAMETER SELECTION (V2 2.3 — train-only, non-circular):")
    L.append(f"#   SelectedParams: drift(δ)={selected.drift:g} threshold(λ)={selected.threshold:g} "
             f"cap={selected.cap:g}")
    L.append(f"#   phi_train={selected.phi_train:.5f} power_train={selected.power_train:.3f} "
             f"fpr_budget={selected.fpr_budget:g} grid_size={selected.grid_size}")
    L.append(f"#   procedure: {selected.procedure}")
    if (selected.drift, selected.threshold, selected.cap) != LEGACY_PARAMS:
        L.append(f"#   NOTE: the selected triple differs from the legacy hand-picked "
                 f"(δ,λ,cap)={LEGACY_PARAMS} — the headline sequential-cpd φ/AUC below")
        L.append("#   SUPERSEDE the previous (legacy-triple) log/ledger values. Ablation deltas:")
        L.append("#   docs/bolt/ablations.md (Table 1 marks both configs).")
    L.append("#   Composite weights (0.5,0.3,0.2) and ALERT=3.0/CRITICAL=6.0 stay")
    L.append("#   dissertation-fixed (§11.2.3) — ablated in docs/bolt/ablations.md, never")
    L.append("#   train-selected; their FPR behaviour is characterised by scenario_4.")
    L.append("#")
    L.append("# GEOMETRY DISJOINTNESS (B2a): the (delta,lambda,cap) selection maximises power over a")
    L.append(f"#   TRAIN-only attack-geometry family sigma={TRAIN_DRAIN_SIGMAS} x events={TRAIN_DRAIN_EVENTS}")
    L.append(f"#   (drains on the TRAIN cadence); the low-and-slow claim is evaluated at")
    L.append(f"#   sigma={EVAL_DRAIN_SIGMA}/{EVAL_DRAIN_EVENTS} events on the TEST cadence — a geometry in NEITHER")
    L.append("#   coordinate of the selection family, so the params were never tuned to the")
    L.append("#   exact attack they are scored against. The sigma sweep below shows the full")
    L.append("#   seq-vs-value trade including the crossover.")
    L.append("#")
    L.append("# SCORE SEMANTICS (B6): the sequential detector's per-row ROC/PR score below is the")
    L.append("#   INSTANTANEOUS Page-Hinkley statistic at each row. The previous headline used the")
    L.append("#   RUNNING MAX of that statistic — monotone non-decreasing along the stream, so its")
    L.append("#   AUC partly ranks rows by TIME-ORDER (later rows outrank earlier ones regardless")
    L.append("#   of content), an artifact for a per-row separability metric. Both are reported:")
    seq_m_hdr = next(m for m in metrics if m.name.startswith("sequential"))
    L.append(f"#     instantaneous (PRIMARY per-row score): AUC-ROC={seq_m_hdr.auc_roc:.4f} "
             f"AUC-PR={seq_m_hdr.auc_pr:.4f}")
    L.append(f"#     running-max  (ANNOTATED ARTIFACT):     AUC-ROC={auc_rm:.4f} AUC-PR={ap_rm:.4f}")
    L.append("#   Change-point-native metrics (detection delay, ARL, precision at the matched")
    L.append("#   phi budget) are the PRIMARY metrics for this detector class and lead the log;")
    L.append("#   per-row ROC/PR is secondary either way.")
    L.append("#")
    L.append("# OPERATING POINTS (B4): every baseline's flag threshold is FPR-MATCHED on the")
    L.append(f"#   benign TRAIN stream to the same budget the sequential detector's selection uses")
    L.append(f"#   (phi_train <= {FPR_BUDGET:g}); realized TEST phi is reported per row (train->test")
    L.append("#   drift means it can exceed the train budget — reported, not hidden). The old")
    L.append("#   'as-published/default' operating points (value-zscore at the q=0.999 fast-path")
    L.append("#   quantile, robust-MAD k=3.5, IsolationForest contamination='auto') appear ONLY in")
    L.append("#   the clearly-labelled secondary table.")
    L.append("")

    # --- B6 PRIMARY: change-point-native metrics lead the log ---
    L.append("=" * 108)
    L.append("PRIMARY METRICS (B6) — change-point-native: detection delay / run lengths / precision")
    L.append("     at the matched phi budget, on the HELD-OUT REAL TEST split")
    L.append("=" * 108)
    L.append("A streaming change-point detector is judged by WHEN it fires (delay after onset,")
    L.append("run length between false alarms) and WHAT its alarms are worth (precision at a")
    L.append("fixed benign-FPR budget) — not by per-row population AUC (secondary table below).")
    L.append("")
    L.append(
        f"{'detector':22s} {'ARL0(s)':>14s} {'ARL1(s)':>10s} {'prec@op':>8s} "
        f"{'phi(test)':>10s} {'target(train)':>14s}"
    )
    L.append("-" * 108)
    for m in metrics:
        arl0_s = (f">={m.arl0:,.0f}" if m.arl0_censored else f"{m.arl0:,.0f}")
        arl1_s = ("inf" if not np.isfinite(m.arl1) else f"{m.arl1:,.0f}")
        target = ("rule-based (n/a)" if m.name.startswith("xchainwatcher")
                  else f"<={FPR_BUDGET:g}")
        L.append(
            f"{m.name:22s} {arl0_s:>14s} {arl1_s:>10s} {m.precision:8.4f} "
            f"{m.phi:10.4f} {target:>14s}"
        )
    L.append("-" * 108)
    L.append("ARL0 = mean run length between FALSE trips on benign TEST (seconds; '>=' = right-censored")
    L.append("       lower bound when the detector never false-trips, as Phase 12 reported).")
    L.append("ARL1 = mean time-to-detection (seconds) after the real Ronin incident onset on TEST.")
    L.append("       NOTE: a sequential-detector Ronin ARL1 of 0 s reflects the Ronin row tripping the")
    L.append("       fast path on its OWN event (its signed-log-z exceeds the train fast-path quantile) — a")
    L.append("       single-event catch IDENTICAL to a value threshold, NOT a sequential-accumulation")
    L.append("       result. The representative time-to-detection for the accumulating/low-and-slow")
    nomad_s = ("inf" if not np.isfinite(arl1_nomad_seq) else f"{arl1_nomad_seq:,.0f}")
    L.append(f"       regime is the NOMAD-onset ARL1 = {nomad_s} s (per-counterparty accumulation, the")
    L.append("       genuine sequential capability the detector is sold on).")
    L.append("prec@op = precision at the flag operating point (every operating point calibrated on")
    L.append(f"       TRAIN to the same benign-FPR budget {FPR_BUDGET:g} — B4; see calibration lines below).")
    L.append("phi  = realized benign false-positive rate at that operating point on HELD-OUT TEST.")
    L.append("")
    L.append("Per-destination detection delay (sequential detector, real Nomad structuring")
    L.append("destinations — the distributional PRIMARY delay statement; full detail in 16.5):")
    n_dest_total = len(lns.arl1_dest_delays_s)
    n_dest_det = n_dest_total - lns.arl1_dest_n_never
    fin = [x for x in lns.arl1_dest_delays_s if np.isfinite(x)]
    fin_mean = float(np.mean(fin)) if fin else float("nan")
    L.append(f"  detected {n_dest_det}/{n_dest_total} destinations; mean finite delay = {fin_mean:,.0f} s,")
    L.append(f"  bootstrap 95% CI [{lns.arl1_dest_ci[0]:,.0f}, {lns.arl1_dest_ci[1]:,.0f}] s; "
             f"never detected: {lns.arl1_dest_n_never} (reported, not dropped).")
    L.append("")
    L.append("Operating-point calibration provenance (B4):")
    for dname, cal in calibrations:
        L.append(f"  {dname:22s} {cal}")
    L.append("")

    # --- Comparison table (task 16.4), now SECONDARY per-row population metrics ---
    L.append("=" * 108)
    L.append("SECONDARY (16.4) — per-row population metrics: sequential detector vs 3 FPR-matched")
    L.append("     baselines + published-rules comparator on the HELD-OUT REAL TEST split")
    L.append("=" * 108)
    L.append("Per-row scores: sequential = INSTANTANEOUS Page-Hinkley statistic (B6; the legacy")
    L.append(f"running-max artifact is quantified in the header: AUC-ROC {auc_rm:.4f} running-max vs")
    L.append(f"{seq_m_hdr.auc_roc:.4f} instantaneous). A streaming detector is not a per-row classifier;")
    L.append("this table exists for transparency, not as the headline.")
    L.append("")
    L.append(
        f"{'detector':22s} {'AUC-ROC':>8s} {'AUC-PR':>8s} {'F1':>7s} "
        f"{'phi(FP)':>9s} {'ARL0(s)':>14s} {'ARL1(s)':>12s}"
    )
    L.append("-" * 108)
    for m in metrics:
        arl0_s = (f">={m.arl0:,.0f}" if m.arl0_censored else f"{m.arl0:,.0f}")
        arl1_s = ("inf" if not np.isfinite(m.arl1) else f"{m.arl1:,.0f}")
        L.append(
            f"{m.name:22s} {m.auc_roc:8.4f} {m.auc_pr:8.4f} {m.f1:7.4f} "
            f"{m.phi:9.4f} {arl0_s:>14s} {arl1_s:>12s}"
        )
    L.append("-" * 108)
    L.append("")
    L.append("SECONDARY — 'as-published/default' operating points (B4; NOT budget-matched, kept only")
    L.append("to show what the unmatched defaults would have reported; same continuous scores, so")
    L.append("AUC columns are identical to the primary rows):")
    L.append(f"  {'detector':22s} {'default rule':34s} {'phi(test)':>10s} {'F1':>8s} {'prec@op':>8s}")
    L.append("  " + "-" * 88)
    default_rules = {
        "value-zscore": "|log-z| > fast-path q0.999",
        "iforest-corrected": "contamination='auto' predict",
        "robust-mad": f"robust-z > k={MAD_K:g} (Iglewicz-Hoaglin)",
    }
    for dname, dphi, df1, dprec in default_rows:
        rule = default_rules.get(dname, "default")
        L.append(f"  {dname:22s} {rule:34s} {dphi:10.4f} {df1:8.4f} {dprec:8.4f}")
    L.append("")
    # Confusion matrices.
    L.append("Confusion matrices at the operating point [[TN, FP], [FN, TP]] (rows=truth, cols=pred):")
    for m in metrics:
        cm = m.confusion
        L.append(f"  {m.name:22s} TN={cm[0,0]:6d} FP={cm[0,1]:6d} | FN={cm[1,0]:5d} TP={cm[1,1]:4d}")
    L.append("")
    L.append("Note (honest): the value baselines attain high value-ROC but pathological operating")
    L.append("points (e.g. iforest-corrected flags a large benign fraction at 'auto' contamination):")
    L.append("in the common USD denomination, benign whale transfers are of the same order as the")
    L.append("largest drain rows (only the single biggest Ronin leg exceeds every benign transfer,")
    L.append("and the Nomad rows sit well inside the benign bulk) — no per-tx value")
    L.append("threshold separates incidents on value alone. The sequential detector's contribution is")
    L.append("the low-and-slow recall + near-zero phi below, not the raw per-row AUC (a streaming")
    L.append("change-point detector is not a per-row population classifier).")
    L.append("")
    L.append("Note (V2 2.4, published-rules comparator — read before comparing rows): the")
    L.append("xchainwatcher-rules row re-implements XChainWatcher's core cross-chain soundness rules")
    L.append("(Augusto et al., arXiv:2410.02029) over the parquet's deposit<->withdrawal linkage")
    L.append("columns. TWO caveats: (a) the CCTX incident labels were DERIVED BY XChainWatcher's")
    L.append("unmatched-withdrawal analysis, so its ~perfect incident recall here is BY CONSTRUCTION")
    L.append("— this is a capability/deployment-cost comparison (both chains instrumented +")
    L.append("protocol-specific rules vs BOLT's destination-stream-only detector), NOT a fair")
    L.append("same-information classifier shoot-out; (b) its continuous score has only 3 levels")
    L.append("(1.0 unmatched / 0.5 finality violation / 0.0 clean), so its AUC-ROC/AUC-PR are COARSE")
    L.append("and not comparable to the continuous scorers — its PRIMARY numbers are the")
    L.append("operating-point recall/precision/phi (per-incident table below), not AUC.")
    L.append("")

    # --- CIs (task 16.6) ---
    L.append("=" * 100)
    L.append(f"16.6 BOOTSTRAP 95% CONFIDENCE INTERVALS — {cis[0].n_boot} stratified bootstrap resamples")
    L.append("     (B5; TWO-SIDED: both classes drawn with replacement, single seeded RNG)")
    L.append("=" * 100)
    L.append(f"Both the {int(splits.y_test.sum())} incident positives AND the benign background are resampled with")
    L.append("replacement each resample (rare-positive two-sided bootstrap), so AUC-PR/F1/AUC-ROC")
    L.append("CIs honestly bracket the small incident set's sampling variability (not frozen).")
    L.append("B5 note: the previous log's '12 seeds' were 12 resamples of one deterministic")
    L.append("output — never independent replicates; the 2.5th percentile of 12 points is the")
    L.append(f"sample minimum. These bands use {cis[0].n_boot} resamples.")
    L.append(f"{'detector':22s} {'AUC-ROC [95% CI]':>26s} {'AUC-PR [95% CI]':>26s}")
    L.append("-" * 100)
    for c in cis:
        L.append(
            f"{c.name:22s} "
            f"{c.auc_roc_mean:6.4f} [{c.auc_roc_lo:.4f},{c.auc_roc_hi:.4f}]    "
            f"{c.auc_pr_mean:6.4f} [{c.auc_pr_lo:.4f},{c.auc_pr_hi:.4f}]"
        )
    L.append("-" * 100)
    L.append(f"{'detector':22s} {'F1 [95% CI]':>26s} {'phi [95% CI]':>26s}")
    L.append("-" * 100)
    for c in cis:
        L.append(
            f"{c.name:22s} "
            f"{c.f1_mean:6.4f} [{c.f1_lo:.4f},{c.f1_hi:.4f}]    "
            f"{c.phi_mean:6.4f} [{c.phi_lo:.4f},{c.phi_hi:.4f}]"
        )
    L.append("")

    # --- phi headline (the number Phase 17 consumes) ---
    seq_ci = next(c for c in cis if c.name.startswith("sequential"))
    L.append("=" * 80)
    L.append("phi (benign false-positive rate) — the H1 term consumed by Phase 17")
    L.append("=" * 80)
    L.append("MEASURED ON THE HELD-OUT REAL BENIGN CCTX TEST ROWS (not the threshold-setting")
    L.append("generator) — this is the anti-circular phi.")
    L.append(f"  sequential-cpd phi = {seq_ci.phi_mean:.5f}  95% CI [{seq_ci.phi_lo:.5f}, {seq_ci.phi_hi:.5f}]")
    for c in cis:
        if not c.name.startswith("sequential"):
            L.append(f"  {c.name:22s} phi = {c.phi_mean:.5f}  95% CI [{c.phi_lo:.5f}, {c.phi_hi:.5f}]")
    L.append("")

    # --- low-and-slow complement evidence (task 16.5 + V2 2.6) ---
    L.append("=" * 90)
    L.append("16.5 LOW-AND-SLOW COMPLEMENT (H1) — sequential detector catches what the value z-score misses")
    L.append("=" * 90)
    L.append("A. Canonical injected drain (ILLUSTRATIVE — synthetic schedule on real benign cadence):")
    L.append(f"   per-tx value      = {lns.per_tx_value_usd:,.2f} USD  "
             f"({lns.per_tx_logz:.2f} log-sigma above benign)")
    L.append(f"   benign |log-z| p99 = {lns.benign_logz_p99:.3f}  "
             f"-> the log-scaled value threshold {'CATCHES' if lns.zscore_catches_per_tx else 'MISSES'} each tx")
    L.append(f"   monitor.anomaly.compute_score (the REAL repo value-threshold baseline) on this tx "
             f"= {lns.legacy_compute_score:.4f} -> {'ALERT' if lns.legacy_catches else 'NORMAL'} "
             f"({'catches' if lns.legacy_catches else 'MISSES'})")
    seqd = ("never" if lns.seq_detects_after_events is None
            else f"after {lns.seq_detects_after_events} events")
    L.append(f"   sequential detector trips {seqd} on the same-counterparty drain")
    L.append(f"   recall @ operating point:  sequential={lns.seq_recall:.3f}   value-zscore={lns.zscore_recall:.3f}")
    win = lns.seq_recall - lns.zscore_recall
    L.append(f"   => low-and-slow recall gap (detector - z-score) = {win:+.3f}  <-- the H1 result")
    L.append(f"   (B2a: evaluation geometry sigma={EVAL_DRAIN_SIGMA}/{EVAL_DRAIN_EVENTS} events is DISJOINT from the")
    L.append(f"   selection family sigma={TRAIN_DRAIN_SIGMAS} x events={TRAIN_DRAIN_EVENTS} — header note.)")
    L.append("")
    L.append("A'. SIGMA SWEEP (B2b) — same drain schedule at per-tx magnitudes from below to ABOVE")
    L.append("    the value threshold, so the seq-vs-value crossover is SHOWN, not a single point")
    L.append("    where the value baseline is 0-recall by construction:")
    L.append(f"    value-zscore threshold (TRAIN-matched, {FPR_BUDGET:.0%} budget) = "
             f"{z_thresh_matched:.3f} log-sigma")
    L.append(f"    {'sigma':>6s} {'per-tx USD':>14s} {'seq recall':>11s} {'zscore recall':>14s} "
             f"{'seq 1st trip':>13s} {'note':s}")
    L.append("    " + "-" * 76)
    for p in sweep:
        first = ("never" if p.seq_first_trip_event is None
                 else f"event {p.seq_first_trip_event}")
        notes = []
        if p.is_eval_point:
            notes.append("<- eval point (case A)")
        if p.sigma > z_thresh_matched and all(
            q.sigma <= z_thresh_matched for q in sweep if q.sigma < p.sigma
        ):
            notes.append("<- first level above value threshold")
        L.append(
            f"    {p.sigma:6.2f} {p.per_tx_value_usd:14,.0f} {p.seq_recall:11.3f} "
            f"{p.zscore_recall:14.3f} {first:>13s} {' '.join(notes)}"
        )
    cross = sweep_crossover_sigma(sweep)
    cross_s = ("none within sweep" if cross is None else f"sigma = {cross:g}")
    L.append(f"    crossover (smallest swept sigma with nonzero value-baseline recall): {cross_s}")
    L.append("    READ: below its threshold the value baseline is blind BY CONSTRUCTION (0 recall);")
    L.append("    above it, each tx flags on its own and both detectors catch the drain. The")
    L.append("    sequential detector's contribution is the sub-threshold band, where accumulation")
    L.append("    is the ONLY signal — the value baseline matching it above the crossover is")
    L.append("    expected and reported, not hidden. Figure: figures/lowslow_sweep.png")
    L.append("")
    L.append("B. HONEST CONTRAST — real Nomad structuring subset (destinations with >=3 incident txs):")
    L.append(f"   structuring destinations = {lns.n_nomad_structuring_dests}; "
             f"dust fraction (< {DUST_USD:g} USD rows) = {lns.nomad_dust_fraction:.2f}")
    L.append("   In the common USD denomination this subset is repeated mid-6-figure transfers to a")
    L.append("   few payees, NOT a pure low-and-slow upward drain. Reported")
    L.append("   transparently — the H1 claim rests on the canonical case (A), not on this subset.")
    L.append("   95% CIs are CLUSTER bootstraps (1000 resamples) over the structuring DESTINATIONS")
    L.append("   (rows within one payee are not independent — the destination is the resampling unit).")
    L.append(f"   per-tx recall:        sequential={lns.nomad_seq_recall_tx:.3f} "
             f"[{lns.nomad_seq_recall_tx_ci[0]:.3f},{lns.nomad_seq_recall_tx_ci[1]:.3f}]   "
             f"value-zscore={lns.nomad_zscore_recall_tx:.3f} "
             f"[{lns.nomad_zscore_recall_tx_ci[0]:.3f},{lns.nomad_zscore_recall_tx_ci[1]:.3f}]")
    L.append(f"   per-destination recall: sequential={lns.nomad_seq_recall_dest:.3f}   "
             f"value-zscore={lns.nomad_zscore_recall_dest:.3f}")
    L.append("")
    L.append("C. DUST SUB-COHORT (real Nomad, value-invisible rows) — structuring rows with value")
    L.append(f"   < {DUST_USD:g} USD in the COMMON USD denomination:")
    L.append(f"   n_dust_rows = {lns.nomad_dust_n_rows} "
             f"({lns.nomad_dust_fraction:.0%} of the structuring subset).")
    L.append("   UNITS-FIX NOTE: the earlier '88% dust' cohort was a mixed-token-decimals ARTIFACT")
    L.append("   (a blanket /1e18 read ~$200 six-decimal stablecoin transfers as ~2e-7 'ETH');")
    L.append("   scored in the common USD denomination the cohort is re-derived from scratch.")
    if lns.nomad_dust_n_rows == 0:
        L.append("   observed: the dust sub-cohort is EMPTY under the corrected units — no structuring")
        L.append("   row is genuinely below the per-tx dust cutoff, so this cohort contributes no")
        L.append("   evidence in either direction; the H1 complement claim rests on the canonical")
        L.append("   injected case (A), carried with its ILLUSTRATIVE label.")
    else:
        L.append("   DRAIN-DIRECTION (large-value) thresholds are BLIND here BY CONSTRUCTION — every")
        L.append("   row sits far below any per-tx value trip. The two-sided |log-z| comparator can")
        L.append("   still flag dust as anomalously SMALL (small-direction outliers, NOT drain-value")
        L.append("   evidence) — that is what its nonzero recall below measures. Any NONZERO")
        L.append("   sequential recall here is genuine real-data complement evidence; the observed")
        L.append("   value is reported honestly either way, with its cluster CI.")
        L.append(f"   per-tx recall (dust): sequential={lns.nomad_dust_seq_recall:.3f} "
                 f"[{lns.nomad_dust_seq_recall_ci[0]:.3f},{lns.nomad_dust_seq_recall_ci[1]:.3f}]   "
                 f"value-zscore={lns.nomad_dust_zscore_recall:.3f} "
                 f"[{lns.nomad_dust_zscore_recall_ci[0]:.3f},{lns.nomad_dust_zscore_recall_ci[1]:.3f}]")
        if lns.nomad_dust_seq_recall > 0.0:
            L.append("   observed: NONZERO sequential recall on dust — genuine real-data complement evidence")
            L.append("   (per-tx value rules cannot see these repeats in the drain direction).")
        else:
            L.append("   observed: sequential recall on dust is ZERO in this run — the accumulator does not")
            L.append("   trip on these sub-cutoff repeats, so the dust sub-cohort contributes NO complement")
            L.append("   evidence here; the H1 complement claim rests on the canonical injected case (A),")
            L.append("   carried with its ILLUSTRATIVE label. Reported so the claim cannot overreach.")
    L.append("")
    L.append("ARL1 caveat + per-destination delay bootstrap (V2 2.6):")
    nomad_arl_s = ("inf" if not np.isfinite(arl1_nomad_seq) else f"{arl1_nomad_seq:,.0f}")
    L.append(f"   Nomad-onset ARL1 = {nomad_arl_s} s is a single onset (n~=1); the per-destination")
    L.append("   bootstrap below is the only distributional statement we can honestly make.")
    n_finite = len(lns.arl1_dest_delays_s) - lns.arl1_dest_n_never
    finite_sorted = sorted(x for x in lns.arl1_dest_delays_s if np.isfinite(x))
    finite_mean = (float(np.mean(finite_sorted)) if finite_sorted else float("nan"))
    L.append(f"   per-destination delay (first incident tx -> first attributable seq trip), "
             f"{len(lns.arl1_dest_delays_s)} structuring destinations:")
    L.append(f"     detected: {n_finite} destinations, delays (s) = "
             f"{['%.0f' % x for x in finite_sorted]}")
    L.append(f"     NEVER detected (delay = inf, reported, not dropped): "
             f"{lns.arl1_dest_n_never} of {len(lns.arl1_dest_delays_s)} destinations")
    L.append(f"     mean finite delay = {finite_mean:,.0f} s; bootstrap 95% CI over destinations "
             f"(1000 resamples of the finite delays) = "
             f"[{lns.arl1_dest_ci[0]:,.0f}, {lns.arl1_dest_ci[1]:,.0f}] s")
    L.append("")

    # --- sensitivity (task 16.6) ---
    L.append("=" * 90)
    L.append("16.6 SENSITIVITY SWEEP over {T, B, r, W, Delta}")
    L.append("=" * 90)
    L.append("W is the genuine detector-side knob (re-fit per window); T,B,r,Delta are response-path")
    L.append("(limiter/breaker/latency) knobs that move the effective ARL1 (signal time + Delta), not")
    L.append("the detector's per-row scores. AUC/phi along T,B,r,Delta are detector-side (flat).")
    for axis in ["T", "B", "r", "W", "Delta"]:
        L.append(f"  --- {axis} ---")
        L.append(f"    {'value':>10s} {'AUC-ROC':>9s} {'phi':>8s} {'ARL1(s)':>12s}")
        for p in sens[axis]:
            arl1_s = ("inf" if not np.isfinite(p.arl1) else f"{p.arl1:,.0f}")
            L.append(f"    {p.value:>10.4g} {p.auc_roc:>9.4f} {p.phi:>8.4f} {arl1_s:>12s}")
    L.append("")

    # --- statistical hypothesis tests (V2 2.2) ---
    L.append("=" * 100)
    L.append("## Statistical tests (V2 2.2)")
    L.append("=" * 100)
    L.append("No bare inequalities: every comparison below carries a test statistic, a p-value")
    L.append("and (for recall) a confidence interval, via monitor/stats_tests.py.")
    L.append("")
    L.append("DeLong correlated-AUC tests on the FULL held-out TEST split (pooled per-row scores),")
    L.append("sequential-cpd (A) vs each baseline (B):")
    L.append(f"  {'comparison':38s} {'AUC_A':>8s} {'AUC_B':>8s} {'dAUC':>9s} {'z':>8s} {'p':>11s}")
    L.append("  " + "-" * 88)
    for bname, dl in delong_rows:
        L.append(
            f"  seq vs {bname:31s} {dl.auc_a:8.4f} {dl.auc_b:8.4f} "
            f"{dl.delta:+9.4f} {dl.z:+8.2f} {dl.p_value:11.2e}"
        )
    L.append("")
    # Data-driven direction summary (no hardcoded sign: the 2.3-selected params can
    # move dAUC either way, and NO per-row superiority is claimed in either case).
    sig_lower = [b for b, dl in delong_rows if dl.delta < 0 and dl.p_value < 0.05]
    sig_higher = [b for b, dl in delong_rows if dl.delta > 0 and dl.p_value < 0.05]
    L.append("READ THIS CORRECTLY (direction computed from this run's DeLong rows):")
    if sig_higher:
        L.append(f"  pooled per-row AUC significantly HIGHER than: {', '.join(sig_higher)}"
                 " (dAUC > 0, p < 0.05)")
    if sig_lower:
        L.append(f"  pooled per-row AUC significantly LOWER than: {', '.join(sig_lower)}"
                 " (dAUC < 0, p < 0.05)")
    L.append("Neither direction is a claim: per the reframed thesis (V2 2.1) the sequential")
    L.append("detector is NOT sold as a better per-row population classifier — its contribution is")
    L.append("the low-and-slow COMPLEMENT (McNemar below) at a near-zero benign flag rate phi.")
    L.append("The DeLong rows are reported for statistical transparency only.")
    L.append("")
    L.append("McNemar paired flag tests on the FULL TEST split at each operating point")
    L.append("(n01 = seq correct where baseline wrong; n10 = baseline correct where seq wrong):")
    L.append(f"  {'comparison':38s} {'n01':>6s} {'n10':>6s} {'stat':>9s} {'p':>11s} {'method':>9s}")
    L.append("  " + "-" * 88)
    for bname, mc in mcnemar_rows:
        L.append(
            f"  seq vs {bname:31s} {mc.n01:6d} {mc.n10:6d} "
            f"{mc.statistic:9.2f} {mc.p_value:11.2e} {mc.method:>9s}"
        )
    L.append("")
    h1 = lns.h1_mcnemar_mixed
    L.append("H1 HEADLINE TEST (B2c) — McNemar on the MIXED stream (real benign TEST rows +")
    L.append(f"injected canonical drain merged in time order; {lns.h1_mixed_n_rows} rows =")
    L.append(f"{lns.h1_mixed_n_benign} benign + {lns.h1_mixed_n_rows - lns.h1_mixed_n_benign} injected; y = injected mask). Both detectors")
    L.append("can plausibly fire here — benign false positives count against each side, so the")
    L.append("discordant pairs are informative in BOTH directions (n10 is not structurally 0):")
    L.append(
        f"  seq vs value-zscore  n01={h1.n01} n10={h1.n10} statistic={h1.statistic:.2f} "
        f"p={h1.p_value:.2e} method={h1.method}"
    )
    L.append(
        f"  direction holds (seq drain recall {lns.seq_recall:.3f} > z-score {lns.zscore_recall:.3f}): "
        f"{lns.h1_direction_holds}; asserted at p < 0.01."
    )
    L.append("")
    L.append("ILLUSTRATION ONLY (demoted, B2c) — injected-drain-only paired flags (y=all-True):")
    L.append(f"  n01={lns.h1_injected_n01} n10={lns.h1_injected_n10}. With every row positive and the value baseline")
    L.append("  below threshold by construction, n10=0 is GUARANTEED — a McNemar p-value on this")
    L.append("  design is theater and is intentionally NOT reported.")
    L.append("")
    L.append("Per-incident recall at the operating point, with CI (Clopper-Pearson exact for n<30,")
    L.append("percentile bootstrap otherwise). Reminder: xchainwatcher-rules recall ~1.0 is")
    L.append("labels-by-construction (the incident labels ARE its unmatched-withdrawal output);")
    L.append("these are its primary operating-point numbers, per the V2 2.4 note above:")
    L.append(f"  {'detector':22s} {'incident':18s} {'n':>6s} {'recall':>8s} "
             f"{'95% CI':>19s} {'method':>16s}")
    L.append("  " + "-" * 94)
    for dname, cis_rows in incident_cis:
        for ci in cis_rows:
            ci_s = f"[{ci.lo:.3f},{ci.hi:.3f}]"
            L.append(
                f"  {dname:22s} {ci.label:18s} {ci.n:6d} {ci.recall:8.3f} "
                f"{ci_s:>19s} {ci.method:>16s}"
            )
    L.append("")

    # --- cross-incident temporal holdout (V2 2.5) ---
    L.append("=" * 108)
    L.append("## Per-incident results (temporal holdout)")
    L.append("=" * 108)
    L.append("Protocol: for EACH incident, calibration = benign-only rows strictly before")
    L.append("onset - 1 h on the reassembled FULL timeline (train + test in true time order);")
    L.append("LogScale, the fast-path z (q=0.999) and the (delta, lambda, cap) selection are all")
    L.append("REFIT on that calibration only (no future information); the window")
    L.append("[onset, onset + 7 d] is then streamed in true order. Stronger than the single")
    L.append("time split: each incident gets its own no-future-information calibration.")
    L.append("")
    L.append(f"  {'incident':16s} {'detector':20s} {'n_pos':>5s} {'recall':>7s} "
             f"{'95% CI':>15s} {'method':>16s} {'prec':>6s} {'phi_win':>8s} {'n_calib':>8s}")
    L.append("  " + "-" * 106)
    for h in holdouts:
        ci_s = f"[{h.recall_ci.lo:.3f},{h.recall_ci.hi:.3f}]"
        L.append(
            f"  {h.label:16s} {h.detector:20s} {h.n_pos:5d} {h.recall:7.3f} "
            f"{ci_s:>15s} {h.recall_ci.method:>16s} {h.precision:6.3f} "
            f"{h.phi_window:8.4f} {h.n_calibration:8d}"
        )
    L.append("  " + "-" * 106)
    L.append("Leak check (asserted in main): every incident's calibration_max_ts < onset_ts:")
    seen = set()
    for h in holdouts:
        if h.label in seen:
            continue
        seen.add(h.label)
        L.append(f"  {h.label:16s} onset={h.onset_ts}  calibration_max_ts={h.calibration_max_ts}")
    L.append("")
    L.append("READ THIS CORRECTLY (the honest shape this table exists to SHOW, not to improve):")
    L.append(f"the {int(splits.y_test.sum())} pooled positives are really ~one Nomad event + one two-row Ronin event, so")
    L.append("pooled metrics are dominated by Nomad and the effective incident-level n is 2.")
    L.append("Ronin (n=2): ANY recall estimate carries a WIDE Clopper-Pearson CI — two rows prove")
    L.append("little on their own. Nomad: the sequential detector's per-row recall is LOW under")
    L.append("this stricter per-incident calibration (consistent with the pooled FN majority) —")
    L.append("its catch is event-level accumulation at near-zero phi, not per-row coverage.")
    L.append("xchainwatcher-rules recall ~1.0 remains labels-by-construction (V2 2.4 note above).")
    L.append("Per-incident is the honest unit of analysis.")
    L.append("")
    L.append("Figures: figures/roc_pr_curves.png, figures/arl_curves.png, figures/sensitivity.png,")
    L.append("         figures/lowslow_sweep.png")
    LOG_PATH.write_text("\n".join(L) + "\n")
    print(f"Log written: {LOG_PATH}")


# ===========================================================================
# main
# ===========================================================================
def main() -> int:
    t_start = time.perf_counter()
    print("[mode] real-CCTX detection evaluation (node-less; pure Python/data)")

    # 16.3: load + verify + unit-fix + anti-circular split.
    splits = load_cctx()
    print(
        f"[16.3] loaded CCTX: train={len(splits.train)} (benign) "
        f"test={len(splits.test)} (benign + {int(splits.y_test.sum())} incident); "
        f"sha train={splits.sha_verified['train']} test={splits.sha_verified['test']}; "
        f"positives={splits.positive_labels}"
    )
    scale = LogScale.fit(splits.train)
    print(f"[16.3] log-scale calibrated on TRAIN: mu_log={scale.mu:.4f} sigma_log={scale.sigma:.4f}")

    # V2 2.3: train-only FPR-budget parameter selection (δ/λ/cap). Non-circular:
    # consumes the 100%-benign TRAIN split only; TEST is never touched.
    SELECTED = select_params_on_train(splits.train, scale)
    print(
        f"[2.3] SelectedParams: drift(δ)={SELECTED.drift:g} threshold(λ)={SELECTED.threshold:g} "
        f"cap={SELECTED.cap:g} phi_train={SELECTED.phi_train:.5f} "
        f"power_train={SELECTED.power_train:.3f} fpr_budget={SELECTED.fpr_budget:g} "
        f"grid_size={SELECTED.grid_size} :: {SELECTED.procedure}"
    )
    if (SELECTED.drift, SELECTED.threshold, SELECTED.cap) != LEGACY_PARAMS:
        print(
            f"[2.3] NOTE: selected triple != legacy hand-picked {LEGACY_PARAMS} — headline "
            "phi/AUC below supersede the legacy-triple values (see docs/bolt/ablations.md)"
        )

    # Build the detector + 3 baselines through one shared interface. B4: every
    # baseline's flag threshold is FPR-matched on TRAIN to the same budget the
    # (δ, λ, cap) selection used.
    detectors = build_detectors(
        splits.train, scale,
        drift=SELECTED.drift, threshold=SELECTED.threshold, contribution_cap=SELECTED.cap,
        fpr_budget=FPR_BUDGET,
    )
    print(f"[16.4] detectors: {[d.name for d in detectors]}")
    for d in detectors:
        if d.calibration:
            print(f"[B4]   {d.name:22s} operating point: {d.calibration}")

    # 16.4: metrics for each detector on the held-out TEST split.
    metrics = [evaluate_detector(d, splits, scale) for d in detectors]
    for m in metrics:
        arl0_s = (f">={m.arl0:,.0f}" if m.arl0_censored else f"{m.arl0:,.0f}")
        arl1_s = ("inf" if not np.isfinite(m.arl1) else f"{m.arl1:,.0f}")
        print(
            f"[16.4] {m.name:22s} AUC-ROC={m.auc_roc:.4f} AUC-PR={m.auc_pr:.4f} "
            f"F1={m.f1:.4f} phi={m.phi:.4f} prec@op={m.precision:.4f} "
            f"ARL0={arl0_s}s ARL1={arl1_s}s"
        )

    # B6: quantify the legacy running-max ROC artifact next to the primary
    # instantaneous score (the running max is monotone along the stream, so its
    # AUC partly ranks by time-order; reported honestly, whichever way it goes).
    y = splits.y_test
    seq_det0 = next(d for d in detectors if d.kind == "sequential")
    rm_scores, _rm_flags = seq_det0.score_running_max(splits.test)
    auc_rm = float(roc_auc_score(y, rm_scores))
    ap_rm = float(average_precision_score(y, rm_scores))
    seq_m0 = next(m for m in metrics if m.name.startswith("sequential"))
    print(
        f"[B6]   sequential-cpd per-row score semantics: instantaneous "
        f"AUC-ROC={seq_m0.auc_roc:.4f} AUC-PR={seq_m0.auc_pr:.4f} (PRIMARY) vs "
        f"running-max AUC-ROC={auc_rm:.4f} AUC-PR={ap_rm:.4f} (annotated artifact)"
    )

    # B4: secondary "as-published/default" operating points (same continuous
    # scores; only the flag rule differs), reported next to the matched rows.
    default_rows: list[tuple[str, float, float, float]] = []
    for d in detectors:
        if d.default_flags is None:
            continue
        dflags = np.asarray(d.default_flags(splits.test), dtype=bool)
        dcm, df1 = _confusion_and_f1(y, dflags)
        dphi = float(dflags[~y].mean())
        n_flagged = int(dcm[1, 1] + dcm[0, 1])
        dprec = (float(dcm[1, 1]) / n_flagged) if n_flagged else 0.0
        default_rows.append((d.name, dphi, df1, dprec))
        print(f"[B4]   {d.name:22s} default (as-published) operating point: "
              f"phi={dphi:.4f} F1={df1:.4f} prec={dprec:.4f} (secondary)")

    # V2 2.2: statistical hypothesis tests on the full TEST split. ONE
    # detector.score(splits.test) pass per detector (deterministic streaming state),
    # reused for the DeLong AUC contrasts, the paired McNemar flag contrasts and the
    # per-incident recall CIs below.
    test_scored = {d.name: d.score(splits.test) for d in detectors}
    seq_name = next(d.name for d in detectors if d.kind == "sequential")
    scores_seq, flags_seq = test_scored[seq_name]
    baseline_names = [d.name for d in detectors if d.name != seq_name]
    delong_rows: list[tuple[str, DeLongResult]] = []
    mcnemar_rows: list[tuple[str, McNemarResult]] = []
    for bname in baseline_names:
        scores_b, flags_b = test_scored[bname]
        dl = delong_test(splits.y_test, scores_seq, scores_b)
        mc = mcnemar_test(splits.y_test, flags_seq, flags_b)
        delong_rows.append((bname, dl))
        mcnemar_rows.append((bname, mc))
        print(
            f"[2.2] DeLong seq vs {bname:22s} dAUC={dl.delta:+.4f} z={dl.z:+.2f} "
            f"p={dl.p_value:.2e} | McNemar n01={mc.n01} n10={mc.n10} "
            f"stat={mc.statistic:.2f} p={mc.p_value:.2e} ({mc.method})"
        )
    incident_cis: list[tuple[str, list[RecallCI]]] = [
        (d.name, per_incident_recall_ci(splits.test["label"], test_scored[d.name][1]))
        for d in detectors
    ]

    # V2 2.5. Cross-incident temporal holdout: reassemble the FULL timeline and,
    # per incident, calibrate on benign rows strictly before that incident's onset
    # (guard 1 h), refit scale/fast-path/(δ,λ,cap) on the calibration only, then
    # stream [onset, onset + 7 d]. Per-incident is the honest unit of analysis.
    holdouts = cross_incident_holdout(
        pd.concat([splits.train, splits.test]).sort_values("timestamp")
    )
    for h in holdouts:
        print(
            f"[2.5] holdout {h.label:16s} {h.detector:20s} n_pos={h.n_pos:3d} "
            f"recall={h.recall:.3f} CI[{h.recall_ci.lo:.3f},{h.recall_ci.hi:.3f}] "
            f"({h.recall_ci.method}) precision={h.precision:.3f} "
            f"phi_win={h.phi_window:.4f} n_calib={h.n_calibration}"
        )

    # ARL1 by onset: the headline Ronin-onset ARL1 (above) is a fast-path single-event
    # catch (= a value threshold); the NOMAD-onset ARL1 is the genuine per-counterparty
    # ACCUMULATION time-to-detection, reported alongside so ARL1 is not misread as a
    # sequential result when it is really the fast path firing on the Ronin row itself.
    seq_det = next(d for d in detectors if d.name.startswith("sequential"))
    arl1_nomad_seq = measure_arl1_cctx(seq_det, splits, scale, onset_label="incident:nomad")
    arl1_nomad_s = ("inf" if not np.isfinite(arl1_nomad_seq) else f"{arl1_nomad_seq:,.0f}")
    arl1_ronin_seq = next(m.arl1 for m in metrics if m.name.startswith("sequential"))
    arl1_ronin_s = ("inf" if not np.isfinite(arl1_ronin_seq) else f"{arl1_ronin_seq:,.0f}")
    print(
        f"[16.4] sequential-cpd ARL1 by onset: ronin={arl1_ronin_s}s (fast-path single-event, "
        f"= value threshold) nomad={arl1_nomad_s}s (per-counterparty accumulation — the "
        f"representative sequential time-to-detection)"
    )

    # 16.5: low-and-slow win (evaluation geometry disjoint from selection, B2a).
    lns = low_and_slow_win(splits, scale, detectors)
    print(
        f"[16.5] low-and-slow (canonical injected): per-tx={lns.per_tx_value_usd:,.1f} USD "
        f"(|logz|={abs(lns.per_tx_logz):.2f} vs benign p99={lns.benign_logz_p99:.2f}); "
        f"seq recall={lns.seq_recall:.3f} vs z-score recall={lns.zscore_recall:.3f}; "
        f"real compute_score MISSES it={'no' if lns.legacy_catches else 'yes'}; "
        f"[contrast] real-nomad-struct per-tx seq={lns.nomad_seq_recall_tx:.3f} z={lns.nomad_zscore_recall_tx:.3f}"
    )
    h1mx = lns.h1_mcnemar_mixed
    print(
        f"[B2c]  H1 mixed-stream McNemar (benign+injected, {lns.h1_mixed_n_rows} rows): "
        f"n01={h1mx.n01} n10={h1mx.n10} stat={h1mx.statistic:.2f} p={h1mx.p_value:.2e} "
        f"({h1mx.method}); injected-only counts n01={lns.h1_injected_n01} "
        f"n10={lns.h1_injected_n10} kept as ILLUSTRATION (no p-value; n10=0 structural)"
    )

    # B2(b): σ sweep of the injected drain, including levels above the value
    # threshold, so the crossover is shown rather than one rigged point.
    z_thresh_matched = _fpr_matched_threshold(
        np.abs(scale.z(splits.train["value"].to_numpy())), FPR_BUDGET
    )
    sweep = lowslow_sigma_sweep(splits, scale, detectors)
    cross = sweep_crossover_sigma(sweep)
    print(
        f"[B2b]  sigma sweep {[p.sigma for p in sweep]}: value threshold "
        f"(train-matched)={z_thresh_matched:.3f} log-sigma; crossover at "
        f"{'none' if cross is None else f'sigma={cross:g}'}; "
        f"seq recalls={[round(p.seq_recall, 3) for p in sweep]}; "
        f"zscore recalls={[round(p.zscore_recall, 3) for p in sweep]}"
    )

    # 16.6. CIs (B5: >=1000 stratified bootstrap resamples) + sensitivity + phi.
    cis = [bootstrap_cis(d, splits) for d in detectors]
    for c in cis:
        print(
            f"[16.6] {c.name:22s} AUC-ROC={c.auc_roc_mean:.4f}[{c.auc_roc_lo:.4f},{c.auc_roc_hi:.4f}] "
            f"F1={c.f1_mean:.4f}[{c.f1_lo:.4f},{c.f1_hi:.4f}] "
            f"phi={c.phi_mean:.5f}[{c.phi_lo:.5f},{c.phi_hi:.5f}] "
            f"({c.n_boot} bootstrap resamples)"
        )
    sens = sensitivity_sweep(
        splits, scale,
        drift=SELECTED.drift, threshold=SELECTED.threshold, contribution_cap=SELECTED.cap,
    )
    print(f"[16.6] sensitivity axes swept: {list(sens.keys())}")

    # V2 2.3: ablation grids (evaluation-only) → docs/bolt/ablations.md.
    cusum_rows = cusum_ablation_grid(splits, scale, SELECTED)
    weight_rows = weight_ablation_grid(splits, scale)
    thresh_rows = alert_threshold_axis(splits, scale)
    print(
        f"[2.3] ablations: cusum grid={len(cusum_rows)} configs, "
        f"weight grid={len(weight_rows)}, ALERT axis={len(thresh_rows)}"
    )
    write_ablations_md(SELECTED, cusum_rows, weight_rows, thresh_rows)

    # Figures + log (task 16.9a).
    write_roc_pr_figure(metrics, n_pos=int(splits.y_test.sum()), n_test=len(splits.test))
    write_arl_figure(metrics, lns)
    write_sensitivity_figure(sens)
    write_lowslow_sweep_figure(sweep, z_thresh_matched)
    elapsed = time.perf_counter() - t_start
    calibrations = [(d.name, d.calibration) for d in detectors if d.calibration]
    write_log(splits, scale, SELECTED, metrics, cis, lns, sens, elapsed, arl1_nomad_seq,
              delong_rows, mcnemar_rows, incident_cis, holdouts,
              sweep, z_thresh_matched, auc_rm, ap_rm, default_rows, calibrations)

    # ---- Core assertions (the never-drop guarantees this scenario must uphold) ----
    seq_m = next(m for m in metrics if m.name.startswith("sequential"))
    seq_c = next(c for c in cis if c.name.startswith("sequential"))

    # (1) Anti-circularity: train and test are disjoint and positives live only in test.
    assert int(splits.y_test.sum()) > 0, "TEST split must contain the incident positives"
    assert not _align_labels(splits.train).any(), (
        "TRAIN split must be 100% benign — calibration must never see an attack row"
    )
    # (2) The low-and-slow complement claim must hold as a TESTED hypothesis, not a
    # bare inequality. METRIC-DEFINITION CHANGE (B2c, justified): the McNemar now
    # runs on the MIXED benign+injected stream (y = injected mask) instead of the
    # injected drain alone with y=all-True; the old design structurally
    # guaranteed n10=0 (the baseline could never be "correct where seq is wrong"),
    # making its p-value tautological. The mixed design lets benign false
    # positives count against each detector, so p<0.01 is a real requirement.
    assert lns.h1_direction_holds and lns.h1_mcnemar_mixed.p_value < 0.01, (
        f"H1 low-and-slow complement failed: seq recall {lns.seq_recall:.3f} vs "
        f"z-score {lns.zscore_recall:.3f}; mixed-stream McNemar "
        f"n01={lns.h1_mcnemar_mixed.n01} n10={lns.h1_mcnemar_mixed.n10} "
        f"p={lns.h1_mcnemar_mixed.p_value:.2e} (need p<0.01)"
    )
    # (3) phi must be measured (finite) on real benign test; and the detector keeps it low.
    assert np.isfinite(seq_c.phi_mean), "phi must be measured on real benign CCTX"
    assert seq_m.phi <= 0.05, (
        f"sequential detector benign phi {seq_m.phi} unexpectedly high on real CCTX"
    )
    # (4) ARL ordering on real data: time-to-detect < benign run length.
    assert seq_m.arl1 < seq_m.arl0, (
        f"ARL1 ({seq_m.arl1}) must be < ARL0 ({seq_m.arl0}) for the sequential detector"
    )
    # (5) CI construction. METRIC-DEFINITION CHANGE (B5, justified): the old
    # ">=10 seeds" floor described 12 resamples of one deterministic output
    # mislabelled as seeds (the 2.5th percentile of 12 points is the sample
    # minimum, not a CI endpoint). The floor is now >=1000 stratified bootstrap
    # RESAMPLES, a strictly stronger requirement.
    assert seq_c.n_boot >= 1000, (
        f"CI construction needs >=1000 bootstrap resamples, got {seq_c.n_boot}"
    )
    # (6) Per-incident reporting: pooled numbers must never be the only view (V2 2.5).
    assert {h.label for h in holdouts} == {"incident:ronin", "incident:nomad"}, (
        "cross-incident temporal holdout must cover every incident label"
    )
    for h in holdouts:
        assert h.onset_ts > h.calibration_max_ts, "calibration leaked past incident onset"
    # (7) Low-and-slow evidence must be CI-carrying real data + labelled-illustrative synthetic (V2 2.6).
    assert lns.nomad_seq_recall_tx_ci[0] <= lns.nomad_seq_recall_tx <= lns.nomad_seq_recall_tx_ci[1]
    assert len(lns.arl1_dest_delays_s) >= 1 and np.isfinite(lns.arl1_dest_ci[0]), (
        "ARL1 must carry a per-destination bootstrap, not a bare n~1 point estimate"
    )

    print(
        f"\n[done] {elapsed:.1f}s  detectors={len(detectors)}  bootstrap resamples={N_BOOT}  "
        f"seq AUC-ROC={seq_m.auc_roc:.3f} (instantaneous; running-max artifact {auc_rm:.3f}) "
        f"AUC-PR={seq_m.auc_pr:.3f} phi={seq_m.phi:.4f} (real benign CCTX)  "
        f"low-and-slow recall @ eval sigma: seq={lns.seq_recall:.2f} vs z={lns.zscore_recall:.2f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
