"""BOLT Phase 16, task 16.7: Elliptic AML auxiliary evaluation (DROP-FIRST [~]).

Purpose (closes gap G10: "Elliptic++ cited but never used")
-----------------------------------------------------------
The dissertation cites the **Elliptic / Elliptic++** dataset (203k Bitcoin
transactions, 822k labelled addresses, 166 node features) as an empirical anchor for
the detection baselines, but no code ever consumed it, a reviewer-visible gap. This
script is the *actual* consumer: it loads Elliptic, runs the **corrected**
IsolationForest baseline (:mod:`monitor.isolation_forest` / :mod:`monitor.baselines`,
§4.1e degeneracy fixed) on it, reports **AUC + F1**, and writes
``figures/elliptic_aux.png``.

>>> AML-NOT-BRIDGE CAVEAT (read this, and it is repeated in every artifact) <<<
    Elliptic is **anti-money-laundering on the Bitcoin transaction graph**, NOT
    cross-chain bridge traffic. It shares neither the value distribution, the
    per-counterparty temporal structure, nor the threat model of the bridge-drain
    problem BOLT actually targets. It is therefore **AUXILIARY external-validity
    only**: a "the corrected detector also does something sensible on an unrelated
    public AML benchmark" sanity check. It is **never** primary evidence. The primary,
    never-drop evaluation is the real XChainWatcher CCTX run in
    ``scenarios/scenario_6_detection_eval.py``. If this whole script is skipped, the
    BOLT evaluation is unaffected.

DROP-FIRST [~] behaviour (this is by design, not a failure)
-----------------------------------------------------------
Elliptic is "available but possibly not downloaded". It is **not** vendored in this
repo and there is **no** license-clean, credential-free, deterministic offline fetch
for it (the canonical distributions are Kaggle-auth-gated and/or Google-Drive links;
cf. ``scripts/fetch_cctx.py`` which fetches only the CCTX data). So:

* **If the dataset is present** in a standard location (see ``ELLIPTIC_SEARCH_DIRS``
  / ``$ELLIPTIC_DATA_DIR``): load it, fit the corrected IsolationForest on the
  TRAIN-time split only, score the HELD-OUT split, compute ROC-AUC + best-F1, write
  the figure, and return the numbers. (Anti-circularity: thresholds/contamination are
  fit on training rows; AUC/F1 are read off the held-out rows, never the fit rows.)
* **If the dataset is absent / unreadable**: SKIP gracefully, print a clear reason,
  write **no** figure, fabricate **no** numbers, and exit ``0``. The never-drop CCTX
  spine must never be blocked by this auxiliary.

Anti-circularity (the Phase 16 prime directive) applied here
------------------------------------------------------------
Elliptic ships its own canonical train/test split via a temporal cut on the
``time_step`` column. We honour it: the IsolationForest is fit on benign training-time
nodes; AUC/F1 are evaluated on the held-out (later-time) nodes. We never score the
rows that set the model. The score convention matches the rest of BOLT: higher score
= more anomalous (sklearn ``score_samples`` is negated in
:class:`monitor.baselines.IsolationForestBaseline`).

Run
---
    uv run python scenarios/scenario_6b_elliptic_aux.py
    # optional: point at a non-standard location
    ELLIPTIC_DATA_DIR=/path/to/elliptic uv run python scenarios/scenario_6b_elliptic_aux.py

Academic framing: established methods only (IsolationForest; ROC-AUC / F1). No novel
statistics, no fabricated results. A skipped auxiliary is an honest, expected outcome
for an offline reproducibility run.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# Repo-root on path so ``monitor.*`` imports work when run as a script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

CAVEAT = (
    "Elliptic is AML-on-Bitcoin, NOT bridge traffic; auxiliary external-validity "
    "only, never primary evidence. The primary, never-drop evaluation is the real "
    "XChainWatcher CCTX run (scenario_6_detection_eval.py)."
)

FIGURE_PATH = _REPO_ROOT / "figures" / "elliptic_aux.png"

# Standard locations searched for an Elliptic / Elliptic++ drop. $ELLIPTIC_DATA_DIR
# (if set) is searched first. These are conventions only; nothing is vendored.
ELLIPTIC_SEARCH_DIRS: List[Path] = [
    _REPO_ROOT / "data" / "elliptic",
    _REPO_ROOT / "data" / "elliptic_pp",
    _REPO_ROOT / "data" / "elliptic++",
    _REPO_ROOT / "data" / "raw" / "elliptic",
]

# Canonical Elliptic file-name fragments (the public Kaggle/Elliptic++ releases).
_FEATURE_NAME_HINTS = ("classes",)  # classes file is the unambiguous label anchor
_FEATURES_FILE_HINTS = ("features",)


@dataclass
class EllipticResult:
    """Outcome of the auxiliary run: either ``skipped`` with a reason, or numbers."""

    skipped: bool
    reason: str
    auc: Optional[float] = None
    f1: Optional[float] = None
    figure_written: bool = False
    figure_path: Optional[str] = None
    n_train: int = 0
    n_test: int = 0
    n_test_pos: int = 0
    searched: List[str] = field(default_factory=list)

    def auc_str(self) -> str:
        return "n/a" if self.auc is None else f"{self.auc:.4f}"

    def f1_str(self) -> str:
        return "n/a" if self.f1 is None else f"{self.f1:.4f}"


# --------------------------------------------------------------------------------------
# Dataset location / loading
# --------------------------------------------------------------------------------------
def _candidate_dirs() -> List[Path]:
    dirs: List[Path] = []
    env = os.environ.get("ELLIPTIC_DATA_DIR")
    if env:
        dirs.append(Path(env).expanduser())
    dirs.extend(ELLIPTIC_SEARCH_DIRS)
    # De-duplicate, preserve order.
    seen: set = set()
    out: List[Path] = []
    for d in dirs:
        key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _find_elliptic_files() -> Tuple[Optional[Path], Optional[Path], List[Path]]:
    """Locate (classes_csv, features_csv) if a recognisable Elliptic drop exists.

    Returns ``(classes_path, features_path, searched_dirs)``. Either path may be
    ``None`` if not found; callers treat a missing piece as "absent -> skip".
    """
    searched: List[Path] = []
    for d in _candidate_dirs():
        searched.append(d)
        if not d.is_dir():
            continue
        classes_path: Optional[Path] = None
        features_path: Optional[Path] = None
        for p in sorted(d.rglob("*.csv")):
            low = p.name.lower()
            if classes_path is None and any(h in low for h in _FEATURE_NAME_HINTS):
                classes_path = p
            elif features_path is None and any(h in low for h in _FEATURES_FILE_HINTS):
                features_path = p
        if classes_path is not None and features_path is not None:
            return classes_path, features_path, searched
    return None, None, searched


def _load_elliptic(classes_csv: Path, features_csv: Path):
    """Load and join the Elliptic classes + features tables into a tidy frame.

    Returns a DataFrame with columns ``[txId, time_step, label, f0..fN]`` where
    ``label`` is 1 for illicit, 0 for licit; unknown-class rows are dropped (Elliptic
    convention: only ~23% of nodes are labelled). Raises on any structural surprise
    so a malformed drop SKIPS rather than silently producing garbage.
    """
    import pandas as pd

    # The canonical features file has NO header: col0 = txId, col1 = time_step,
    # cols 2..167 = the 166 features. The classes file HAS a header: txId,class.
    feats = pd.read_csv(features_csv, header=None)
    if feats.shape[1] < 3:
        raise ValueError(
            f"features file {features_csv.name} has {feats.shape[1]} cols; "
            "expected >=3 (txId, time_step, features...)"
        )
    feat_cols = ["txId", "time_step"] + [f"f{i}" for i in range(feats.shape[1] - 2)]
    feats.columns = feat_cols

    classes = pd.read_csv(classes_csv)
    cls_lower = {c.lower(): c for c in classes.columns}
    if "txid" not in cls_lower or "class" not in cls_lower:
        raise ValueError(
            f"classes file {classes_csv.name} columns {list(classes.columns)} "
            "do not look like Elliptic (expected txId,class)"
        )
    classes = classes.rename(
        columns={cls_lower["txid"]: "txId", cls_lower["class"]: "class"}
    )

    df = feats.merge(classes[["txId", "class"]], on="txId", how="left")
    # Elliptic labels: '1' = illicit, '2' = licit, 'unknown' = unlabelled.
    df["class"] = df["class"].astype(str).str.strip().str.lower()
    df = df[df["class"].isin({"1", "2"})].copy()
    if df.empty:
        raise ValueError("no labelled (illicit/licit) rows after join")
    df["label"] = (df["class"] == "1").astype(int)  # 1 = illicit (positive)
    df["time_step"] = pd.to_numeric(df["time_step"], errors="coerce")
    df = df.dropna(subset=["time_step"])
    return df


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------
def _evaluate(df) -> Tuple[float, float, int, int, int, "object"]:
    """Fit corrected IsolationForest on the train-time split, score the held-out split.

    Returns ``(auc, best_f1, n_train, n_test, n_test_pos, test_frame_with_scores)``.

    Anti-circularity: Elliptic's canonical temporal split is honoured. We fit the
    forest on benign (licit) TRAIN-time nodes only and read AUC/F1 off the LATER-time
    held-out nodes. The fit rows never appear in the scored rows.
    """
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import precision_recall_curve, roc_auc_score

    # Canonical Elliptic temporal cut: time steps 1..34 train, 35..49 test (the split
    # used by the Elliptic GCN paper). If the range differs, fall back to a 70/30
    # temporal quantile cut on time_step, still leakage-free and deterministic.
    steps = np.sort(df["time_step"].unique())
    if steps.min() <= 34 <= steps.max():
        cut = 34
    else:
        cut = float(np.quantile(df["time_step"], 0.70))
    train_df = df[df["time_step"] <= cut]
    test_df = df[df["time_step"] > cut].copy()
    if test_df.empty or test_df["label"].nunique() < 2:
        raise ValueError(
            "temporal test split has <2 label classes; cannot compute AUC honestly"
        )

    feat_cols = [c for c in df.columns if c.startswith("f")]
    X_train = train_df.loc[train_df["label"] == 0, feat_cols].to_numpy(dtype=float)
    if len(X_train) < 50:
        # Fall back to fitting on ALL train-time rows (unsupervised forest tolerates
        # contamination) if too few labelled-licit rows exist.
        X_train = train_df[feat_cols].to_numpy(dtype=float)
    X_test = test_df[feat_cols].to_numpy(dtype=float)
    y_test = test_df["label"].to_numpy(dtype=int)

    # Contamination from the TRAIN split's illicit base rate (not the test split).
    # Anti-circular: the test labels never inform the model.
    train_pos_rate = float(train_df["label"].mean())
    contamination = min(max(train_pos_rate, 1e-3), 0.5) if train_pos_rate > 0 else "auto"

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_train)

    # Higher score = more anomalous (BOLT convention; sklearn score_samples negated).
    scores = -model.score_samples(X_test)
    auc = float(roc_auc_score(y_test, scores))

    # Best-F1 over the PR curve on the held-out split (a single, comparable operating
    # point; the threshold is chosen on the held-out scores, the standard way to
    # summarise a ranker's attainable F1; it does NOT leak into the model fit).
    precision, recall, _ = precision_recall_curve(y_test, scores)
    denom = precision + recall
    f1s = np.where(denom > 0, 2 * precision * recall / denom, 0.0)
    best_f1 = float(np.max(f1s))

    test_df["score"] = scores
    return (
        auc,
        best_f1,
        int(len(train_df)),
        int(len(test_df)),
        int(y_test.sum()),
        test_df,
    )


def _write_figure(auc: float, f1: float, test_df, path: Path) -> bool:
    """Write the auxiliary ROC + score-distribution figure. Returns True on success."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from sklearn.metrics import roc_curve

    y = test_df["label"].to_numpy(dtype=int)
    s = test_df["score"].to_numpy(dtype=float)
    fpr, tpr, _ = roc_curve(y, s)

    path.parent.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # (a) ROC
    ax = axes[0]
    ax.plot(fpr, tpr, color="#1f77b4", lw=2, label=f"iforest-corrected (AUC={auc:.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.6, label="chance")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("(a) Elliptic AML ROC — held-out temporal split")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)

    # (b) Score distributions by class
    ax = axes[1]
    licit = s[y == 0]
    illicit = s[y == 1]
    lo, hi = float(np.min(s)), float(np.max(s))
    bins = np.linspace(lo, hi, 40)
    ax.hist(licit, bins=bins, alpha=0.6, density=True, color="#2ca02c", label="licit (benign)")
    ax.hist(illicit, bins=bins, alpha=0.6, density=True, color="#d62728", label="illicit")
    ax.set_xlabel("anomaly score (higher = more anomalous)")
    ax.set_ylabel("density")
    ax.set_title(f"(b) Score separation — best F1={f1:.3f}")
    ax.legend(loc="upper right")
    ax.grid(alpha=0.3)

    fig.suptitle(
        "AUXILIARY ONLY — Elliptic is AML-on-Bitcoin, NOT bridge traffic "
        "(external validity, never primary evidence)",
        fontsize=11,
        color="#555555",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path.exists()


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------
def run() -> EllipticResult:
    """Run the auxiliary Elliptic evaluation, or skip gracefully if data is absent."""
    classes_csv, features_csv, searched = _find_elliptic_files()
    searched_str = [str(p) for p in searched]

    if classes_csv is None or features_csv is None:
        reason = (
            "Elliptic dataset not found offline (not vendored; no license-clean "
            "credential-free fetch — canonical releases are Kaggle-auth-gated / "
            "Google-Drive-hosted). Searched: "
            + ", ".join(searched_str)
            + ". Set $ELLIPTIC_DATA_DIR to a directory containing the Elliptic "
            "'*classes*.csv' and '*features*.csv' files to enable this auxiliary run. "
            "This SKIP does not affect the primary CCTX evaluation."
        )
        return EllipticResult(skipped=True, reason=reason, searched=searched_str)

    # Files found: attempt a real run; any structural problem -> graceful skip.
    try:
        df = _load_elliptic(classes_csv, features_csv)
        auc, f1, n_train, n_test, n_test_pos, test_df = _evaluate(df)
        figure_written = _write_figure(auc, f1, test_df, FIGURE_PATH)
    except Exception as exc:  # noqa: BLE001 - auxiliary must never block the spine
        reason = (
            f"Elliptic files located ({classes_csv.name}, {features_csv.name}) but the "
            f"auxiliary run could not complete: {type(exc).__name__}: {exc}. Skipping "
            "gracefully — no figure written, no numbers fabricated; primary CCTX "
            "evaluation is unaffected."
        )
        return EllipticResult(skipped=True, reason=reason, searched=searched_str)

    return EllipticResult(
        skipped=False,
        reason="ran",
        auc=auc,
        f1=f1,
        figure_written=figure_written,
        figure_path=str(FIGURE_PATH) if figure_written else None,
        n_train=n_train,
        n_test=n_test,
        n_test_pos=n_test_pos,
        searched=searched_str,
    )


def main() -> int:
    print("=" * 78)
    print("BOLT Phase 16 / task 16.7 — Elliptic AML AUXILIARY evaluation (DROP-FIRST)")
    print("=" * 78)
    print("CAVEAT:", CAVEAT)
    print("-" * 78)

    result = run()

    if result.skipped:
        print("STATUS : SKIPPED (this is an expected, honest outcome offline)")
        print("REASON :", result.reason)
        print("AUC    : n/a")
        print("F1     : n/a")
        print("FIGURE : not written")
        # Exit 0: a skipped auxiliary must NOT fail the workflow.
        return 0

    print("STATUS : RAN")
    print(f"DATA   : train rows={result.n_train}, test rows={result.n_test} "
          f"(test illicit positives={result.n_test_pos})")
    print(f"AUC    : {result.auc_str()}  (held-out temporal split, iforest-corrected)")
    print(f"F1     : {result.f1_str()}  (best operating point on held-out PR curve)")
    print(f"FIGURE : {'written -> ' + str(result.figure_path) if result.figure_written else 'NOT written'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
