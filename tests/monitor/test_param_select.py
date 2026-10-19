import numpy as np
import pytest

from monitor.generator import generate
from monitor.param_select import (
    EVAL_DRAIN_EVENTS,
    EVAL_DRAIN_SIGMA,
    TRAIN_DRAIN_EVENTS,
    TRAIN_DRAIN_SIGMAS,
    SelectedParams,
    _train_geometry_drains,
    select_params_on_train,
)


class _IdScale:
    """Log-z stand-in: identity over log10 (enough for selection plumbing)."""
    def z(self, v):
        v = np.asarray(v, dtype=float)
        lv = np.log10(np.clip(v, 1e-9, None))
        return (lv - self._mu) / self._sd
    def fit(self, train):
        lv = np.log10(np.clip(train["value"].to_numpy(float), 1e-9, None))
        self._mu, self._sd = lv.mean(), max(lv.std(), 1e-9)
        return self


def test_selection_respects_fpr_budget_and_reports_provenance():
    train = generate(seed=42, n=4000)
    train = train.assign(t_sec=(train["timestamp"] - train["timestamp"].iloc[0]).dt.total_seconds())
    scale = _IdScale().fit(train)
    sel = select_params_on_train(train, scale, fpr_budget=0.01, seed=42)
    assert isinstance(sel, SelectedParams)
    assert sel.phi_train <= 0.01                       # hard budget
    assert sel.cap > sel.drift                          # detector invariant
    assert sel.grid_size >= 30                          # a real grid, not a point
    assert "FPR-budget" in sel.procedure and "TRAIN" in sel.procedure


def test_selection_is_deterministic():
    train = generate(seed=42, n=4000)
    train = train.assign(t_sec=(train["timestamp"] - train["timestamp"].iloc[0]).dt.total_seconds())
    scale = _IdScale().fit(train)
    a = select_params_on_train(train, scale, seed=42)
    b = select_params_on_train(train, scale, seed=42)
    assert (a.drift, a.threshold, a.cap) == (b.drift, b.threshold, b.cap)


# ---------------------------------------------------------------------------
# B2(a): the selection attack-geometry family must stay DISJOINT from the
# scenario_6 evaluation point, or the low-and-slow evaluation is circular
# (params tuned on the exact geometry they are later scored against).
# ---------------------------------------------------------------------------
def test_selection_geometry_family_disjoint_from_eval_point():
    assert EVAL_DRAIN_SIGMA not in TRAIN_DRAIN_SIGMAS
    assert EVAL_DRAIN_EVENTS not in TRAIN_DRAIN_EVENTS
    # The eval point must be BRACKETED by the family (interpolation, not
    # extrapolation), so the disjointness is not achieved by moving the eval
    # geometry outside the region the selection ever saw.
    assert min(TRAIN_DRAIN_SIGMAS) < EVAL_DRAIN_SIGMA < max(TRAIN_DRAIN_SIGMAS)
    assert min(TRAIN_DRAIN_EVENTS) < EVAL_DRAIN_EVENTS < max(TRAIN_DRAIN_EVENTS)


def test_train_geometry_drains_cover_full_family_and_never_eval_geometry():
    train = generate(seed=42, n=2000)
    train = train.assign(t_sec=(train["timestamp"] - train["timestamp"].iloc[0]).dt.total_seconds())
    drains = _train_geometry_drains(train, seed=42)
    # 2 sigmas x 2 event-counts x N_DRAINS_PER_GEOM drains, unique attacker keys.
    assert len(drains) == len(TRAIN_DRAIN_SIGMAS) * len(TRAIN_DRAIN_EVENTS) * 3
    assert len({attacker for attacker, _t, _v in drains}) == len(drains)
    # Every drain's event count is a family member, never the 60-event eval count.
    counts = {len(times) for _a, times, _v in drains}
    assert counts == set(TRAIN_DRAIN_EVENTS)
    assert EVAL_DRAIN_EVENTS not in counts
    # Per-tx values realise exactly the family sigmas (via the train log stats),
    # never the eval sigma.
    lv = np.log10(np.clip(train["value"].to_numpy(float), 1e-9, None))
    mu, sd = lv.mean(), max(lv.std(), 1e-9)
    sigmas = {round((np.log10(v) - mu) / sd, 6) for _a, _t, v in drains}
    assert sigmas == {round(float(s), 6) for s in TRAIN_DRAIN_SIGMAS}


def test_procedure_string_documents_the_disjoint_family():
    train = generate(seed=42, n=4000)
    train = train.assign(t_sec=(train["timestamp"] - train["timestamp"].iloc[0]).dt.total_seconds())
    scale = _IdScale().fit(train)
    sel = select_params_on_train(train, scale, seed=42)
    assert "DISJOINT" in sel.procedure
    assert str(EVAL_DRAIN_SIGMA) in sel.procedure
