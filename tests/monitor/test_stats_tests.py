import numpy as np
import pandas as pd
import pytest

from monitor.stats_tests import (
    DeLongResult, McNemarResult, RecallCI,
    delong_test, mcnemar_test, per_incident_recall_ci,
)


def test_delong_identical_scores_p_near_one():
    rng = np.random.default_rng(0)
    y = np.array([0] * 200 + [1] * 50, dtype=bool)
    s = rng.normal(size=250) + y * 1.0
    res = delong_test(y, s, s)
    assert res.delta == pytest.approx(0.0)
    assert res.p_value == pytest.approx(1.0, abs=1e-9)


def test_delong_detects_obvious_auc_gap():
    rng = np.random.default_rng(1)
    y = np.array([0] * 500 + [1] * 100, dtype=bool)
    good = rng.normal(size=600) + y * 3.0     # near-perfect separator
    bad = rng.normal(size=600)                # uninformative
    res = delong_test(y, good, bad)
    assert res.auc_a > 0.95 and abs(res.auc_b - 0.5) < 0.1
    assert res.p_value < 1e-6
    assert res.z > 0  # sign convention: positive z when auc_a > auc_b


def test_mcnemar_exact_one_sided_discordance():
    # A correct on 12 rows where B is wrong; B never uniquely correct -> n01=12, n10=0.
    y = np.ones(12, dtype=bool)
    flags_a = np.ones(12, dtype=bool)
    flags_b = np.zeros(12, dtype=bool)
    res = mcnemar_test(y, flags_a, flags_b)
    assert (res.n01, res.n10) == (12, 0)
    assert res.method == "exact"
    assert res.p_value == pytest.approx(2 * 0.5 ** 12, rel=1e-6)


def test_mcnemar_symmetric_is_insignificant():
    y = np.ones(20, dtype=bool)
    flags_a = np.array([True] * 10 + [False] * 10)
    flags_b = np.array([False] * 10 + [True] * 10)
    res = mcnemar_test(y, flags_a, flags_b)
    assert res.n01 == res.n10 == 10
    assert res.p_value > 0.5


def test_per_incident_recall_clopper_pearson_tiny_n():
    # Ronin-like: n=2, both caught -> exact CP lower bound = (alpha/2)^(1/n) = 0.025^0.5.
    labels = pd.Series(["incident:ronin", "incident:ronin"])
    flags = np.array([True, True])
    (ci,) = per_incident_recall_ci(labels, flags)
    assert ci.method == "clopper-pearson" and ci.n == 2
    assert ci.recall == 1.0
    assert ci.lo == pytest.approx(0.025 ** 0.5, rel=1e-3)
    assert ci.hi == 1.0


def test_per_incident_recall_bootstrap_large_n():
    labels = pd.Series(["incident:nomad"] * 200)
    flags = np.array([True] * 50 + [False] * 150)
    (ci,) = per_incident_recall_ci(labels, flags, n_boot=500, seed=1)
    assert ci.method == "bootstrap" and ci.n == 200
    assert ci.lo < 0.25 < ci.hi
