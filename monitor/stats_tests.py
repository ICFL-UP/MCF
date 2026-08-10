"""Statistical hypothesis tests for the detection evaluation (V2 task 2.2).

DeLong (fast, Sun & Xu 2014 midrank formulation) for correlated-AUC differences;
McNemar (exact binomial for small discordance, chi-square with continuity
correction otherwise) for paired flag decisions; per-incident recall CIs
(exact Clopper-Pearson for tiny n, e.g. Ronin's n=2; bootstrap percentile
otherwise). No bare inequalities: every comparison downstream must report
(statistic, p-value, CI) from this module.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy import stats


@dataclass(frozen=True)
class DeLongResult:
    auc_a: float
    auc_b: float
    delta: float
    z: float
    p_value: float


def _midrank(x: np.ndarray) -> np.ndarray:
    order = np.argsort(x)
    z = x[order]
    n = len(x)
    t = np.zeros(n, dtype=float)
    i = 0
    while i < n:
        j = i
        while j < n and z[j] == z[i]:
            j += 1
        t[i:j] = 0.5 * (i + j - 1) + 1
        i = j
    out = np.empty(n, dtype=float)
    out[order] = t
    return out


def _delong_auc_cov(y: np.ndarray, scores: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """AUCs + DeLong covariance for k score vectors (rows of `scores`)."""
    pos = scores[:, y]
    neg = scores[:, ~y]
    m, n = pos.shape[1], neg.shape[1]
    k = scores.shape[0]
    tx = np.empty((k, m)); ty = np.empty((k, n)); tz = np.empty((k, m + n))
    for r in range(k):
        tx[r] = _midrank(pos[r])
        ty[r] = _midrank(neg[r])
        tz[r] = _midrank(np.concatenate([pos[r], neg[r]]))
    aucs = tz[:, :m].sum(axis=1) / (m * n) - (m + 1.0) / (2.0 * n)
    v01 = (tz[:, :m] - tx) / n
    v10 = 1.0 - (tz[:, m:] - ty) / m
    s01 = np.cov(v01)
    s10 = np.cov(v10)
    cov = s01 / m + s10 / n
    return aucs, np.atleast_2d(cov)


def delong_test(y_true: np.ndarray, scores_a: np.ndarray, scores_b: np.ndarray) -> DeLongResult:
    y = np.asarray(y_true, dtype=bool)
    if not y.any() or y.all():
        raise ValueError("delong_test needs both classes present")
    aucs, cov = _delong_auc_cov(y, np.vstack([scores_a, scores_b]))
    delta = float(aucs[0] - aucs[1])
    var = float(cov[0, 0] + cov[1, 1] - 2.0 * cov[0, 1])
    if var <= 0.0:  # identical (or perfectly correlated) scorers
        z = 0.0
        p = 1.0
    else:
        z = delta / np.sqrt(var)
        p = float(2.0 * stats.norm.sf(abs(z)))
    return DeLongResult(auc_a=float(aucs[0]), auc_b=float(aucs[1]),
                        delta=delta, z=float(z), p_value=p)


@dataclass(frozen=True)
class McNemarResult:
    n01: int
    n10: int
    statistic: float
    p_value: float
    method: str


def mcnemar_test(y_true: np.ndarray, flags_a: np.ndarray, flags_b: np.ndarray) -> McNemarResult:
    y = np.asarray(y_true, dtype=bool)
    a_ok = np.asarray(flags_a, dtype=bool) == y
    b_ok = np.asarray(flags_b, dtype=bool) == y
    n01 = int(np.sum(a_ok & ~b_ok))   # A correct, B wrong
    n10 = int(np.sum(~a_ok & b_ok))   # B correct, A wrong
    n_disc = n01 + n10
    if n_disc == 0:
        return McNemarResult(0, 0, 0.0, 1.0, "exact")
    if n_disc < 25:
        p = float(stats.binomtest(min(n01, n10), n_disc, 0.5).pvalue)
        return McNemarResult(n01, n10, float(min(n01, n10)), p, "exact")
    chi2 = (abs(n01 - n10) - 1.0) ** 2 / n_disc
    p = float(stats.chi2.sf(chi2, df=1))
    return McNemarResult(n01, n10, float(chi2), p, "chi2-cc")


@dataclass(frozen=True)
class RecallCI:
    label: str
    n: int
    recall: float
    lo: float
    hi: float
    method: str


def per_incident_recall_ci(labels: pd.Series, flags: np.ndarray,
                           n_boot: int = 1000, seed: int = 42) -> list[RecallCI]:
    """Per-incident-label recall with a CI. Exact Clopper-Pearson for n < 30
    (Ronin has n=2; a bootstrap there is meaningless), percentile bootstrap
    otherwise. `labels`/`flags` are aligned to the SAME rows (incident rows only,
    or a full test frame; benign rows are ignored)."""
    lab = labels.astype(str)
    flg = np.asarray(flags, dtype=bool)
    out: list[RecallCI] = []
    for name in sorted(l for l in lab.unique() if l.startswith("incident")):
        mask = (lab == name).to_numpy()
        n = int(mask.sum())
        hits = int(flg[mask].sum())
        rec = hits / n
        if n < 30:
            lo = float(stats.beta.ppf(0.025, hits, n - hits + 1)) if hits > 0 else 0.0
            hi = float(stats.beta.ppf(0.975, hits + 1, n - hits)) if hits < n else 1.0
            out.append(RecallCI(name, n, rec, lo, hi, "clopper-pearson"))
        else:
            rng = np.random.default_rng(seed)
            f = flg[mask]
            boots = [rng.choice(f, size=n, replace=True).mean() for _ in range(n_boot)]
            out.append(RecallCI(name, n, rec,
                                float(np.percentile(boots, 2.5)),
                                float(np.percentile(boots, 97.5)), "bootstrap"))
    return out
