"""Tests for the BOLT Phase 15 full-knowledge adaptive adversary (C3-eval core).

The adversary is a *white-box* attacker that KNOWS the Phase-12 sequential
change-point detector (params, thresholds) and the Phase-13 rate
limiter/breaker (B, r, T, W). It searches its problem-space action space
(Pierazzi et al.), namely {chunk size, inter-arrival spacing, #destinations,
destination reuse}, for the CHEAPEST feasible schedule, subject to a budget
{total ETH, max #tx, max horizon}, that keeps detection probability below a
target. Robustness is reported as the BEST the adaptive attack achieves
(Carlini adaptive-attack rule), not accuracy against one fixed attack.

These tests are written BEFORE the implementation (strict TDD, task 15.1):
  (a) on a toy/known detector the search FINDS a schedule that keeps detection
      probability below a target while exfiltrating >= the budget target;
  (b) every returned schedule RESPECTS the constraints (<= max #tx, <= horizon,
      total exfiltrated >= target) OR is reported infeasible;
  (c) the search is genuinely ADAPTIVE: tightening the detector (lower
      threshold) forces a measurably more-evasive / cheaper-rate schedule, i.e.
      the search responds to detector knowledge rather than emitting a fixed
      output.
"""
from __future__ import annotations

import pandas as pd
import pytest

from monitor.adversary import AdaptiveAdversary, Budget, Schedule
from monitor.sequential_detector import SequentialChangePointDetector


# A small benign baseline calibration consistent with the generator/ledger.
BENIGN_MEAN = 43.0
BENIGN_STD = 79.0


def _detector(threshold: float = 8.0) -> SequentialChangePointDetector:
    """A detector with explicit baseline stats so tests don't depend on a heavy
    generator draw. threshold (λ) is the adversary's white-box knowledge knob."""
    return SequentialChangePointDetector(
        baseline_mean=BENIGN_MEAN,
        baseline_std=BENIGN_STD,
        window_seconds=3600.0,
        drift=0.5,
        threshold=threshold,
        contribution_cap=2.0,
        fast_path_z=100.0,
    )


# ---------------------------------------------------------------------------
# 15.1(a): the adaptive search finds an evasive-yet-feasible schedule
# ---------------------------------------------------------------------------
def test_search_finds_evasive_feasible_schedule():
    """On a known detector, the search must return a FEASIBLE schedule that keeps
    detection probability below the target while exfiltrating >= the budget."""
    det = _detector(threshold=8.0)
    adv = AdaptiveAdversary(seeds=[0, 1, 2])
    budget = Budget(total_eth=3000.0, max_tx=4000, horizon_secs=30 * 24 * 3600.0)

    sched = adv.search(
        detector_factory=lambda: _detector(threshold=8.0),
        budget=budget,
        target_detection_prob=0.5,
    )

    assert isinstance(sched, Schedule)
    assert sched.feasible, "a feasible evasive schedule must exist for this budget"
    assert sched.total_exfiltrated >= budget.total_eth - 1e-6
    assert sched.estimated_detection_prob < 0.5
    # Concrete event list the Phase-12 detector can ingest directly.
    assert len(sched.events) == sched.n_tx >= 1
    ts, val, dest = sched.events[0]
    assert isinstance(val, float) and val > 0
    assert isinstance(dest, str) and dest.startswith("0x")


# ---------------------------------------------------------------------------
# 15.1(b): the returned schedule respects ALL budget constraints
# ---------------------------------------------------------------------------
def test_schedule_respects_constraints():
    """No returned (feasible) schedule may exceed max #tx or horizon; the total
    exfiltrated must meet the target (else it must be flagged infeasible)."""
    det_factory = lambda: _detector(threshold=8.0)
    adv = AdaptiveAdversary(seeds=[0, 1])
    budget = Budget(total_eth=2000.0, max_tx=500, horizon_secs=10 * 24 * 3600.0)

    sched = adv.search(
        detector_factory=det_factory,
        budget=budget,
        target_detection_prob=0.5,
    )

    if sched.feasible:
        assert sched.n_tx <= budget.max_tx
        assert sched.horizon <= budget.horizon_secs + 1e-6
        assert sched.total_exfiltrated >= budget.total_eth - 1e-6
        # events sorted by time and within the horizon
        times = [e[0] for e in sched.events]
        assert times == sorted(times)
        assert max(times) - min(times) <= budget.horizon_secs + 1e-6
    else:
        # Infeasible must be reported honestly, not faked with a violating schedule.
        assert sched.total_exfiltrated < budget.total_eth or sched.n_tx == 0


def test_infeasible_when_budget_too_tight():
    """If the constraints cannot admit the target evasively, report infeasible;
    never return a constraint-violating schedule to make the search 'succeed'."""
    adv = AdaptiveAdversary(seeds=[0])
    # Want a large amount but only a handful of tx and a tiny horizon: impossible
    # to do evasively (would need huge chunks that trip, or many tx we can't make).
    budget = Budget(total_eth=100_000.0, max_tx=3, horizon_secs=120.0)

    sched = adv.search(
        detector_factory=lambda: _detector(threshold=8.0),
        budget=budget,
        target_detection_prob=0.5,
    )
    assert not sched.feasible


# ---------------------------------------------------------------------------
# 15.1(c): the search is genuinely ADAPTIVE to detector knowledge
# ---------------------------------------------------------------------------
def test_stricter_detector_forces_more_evasive_schedule():
    """A STRICTER detector (lower λ) must force the adaptive search into a
    measurably more-evasive / more-stretched schedule: a lower effective rate
    (or more destinations / smaller chunks). This proves the search optimises
    against the detector it is given rather than emitting a fixed schedule."""
    adv = AdaptiveAdversary(seeds=[0, 1, 2])
    budget = Budget(total_eth=3000.0, max_tx=8000, horizon_secs=30 * 24 * 3600.0)

    loose = adv.search(
        detector_factory=lambda: _detector(threshold=12.0),  # easier to evade
        budget=budget,
        target_detection_prob=0.5,
    )
    strict = adv.search(
        detector_factory=lambda: _detector(threshold=4.0),   # harder to evade
        budget=budget,
        target_detection_prob=0.5,
    )

    assert loose.feasible and strict.feasible

    # The stricter detector forces a more-evasive posture. We accept ANY of the
    # action-space dimensions moving the evasive direction, but the headline
    # invariant is the effective extraction RATE must not be higher under the
    # stricter detector, and must be STRICTLY lower along at least one axis.
    assert strict.effective_rate <= loose.effective_rate + 1e-9, (
        "a stricter detector must not permit a HIGHER effective extraction rate"
    )
    more_evasive = (
        strict.effective_rate < loose.effective_rate - 1e-9
        or strict.n_destinations > loose.n_destinations
        or strict.chunk_eth < loose.chunk_eth - 1e-9
        or strict.horizon > loose.horizon + 1e-9
    )
    assert more_evasive, (
        "tightening the detector must change the schedule toward more evasion "
        f"(loose: rate={loose.effective_rate}, dests={loose.n_destinations}, "
        f"chunk={loose.chunk_eth}, horizon={loose.horizon}; "
        f"strict: rate={strict.effective_rate}, dests={strict.n_destinations}, "
        f"chunk={strict.chunk_eth}, horizon={strict.horizon})"
    )


# ---------------------------------------------------------------------------
# 15.3: events are exactly what the real Phase-12 detector ingests
# ---------------------------------------------------------------------------
def test_schedule_events_drive_real_detector():
    """The returned events must be (timestamp, value, destination) tuples the real
    SequentialChangePointDetector.update() accepts unchanged."""
    adv = AdaptiveAdversary(seeds=[0])
    budget = Budget(total_eth=2000.0, max_tx=4000, horizon_secs=30 * 24 * 3600.0)
    sched = adv.search(
        detector_factory=lambda: _detector(threshold=8.0),
        budget=budget,
        target_detection_prob=0.5,
    )
    det = _detector(threshold=8.0)
    # Must not raise: update(counterparty, value, t) is the exact ingest signature.
    for (t, value, dest) in sched.events:
        stat, tripped = det.update(dest, value, t)
        assert isinstance(tripped, bool)


# ---------------------------------------------------------------------------
# Greedy refinement (B3): grid + coordinate-descent local search.
# ---------------------------------------------------------------------------
def test_refinement_improves_or_equals_grid_optimum():
    """The greedy refinement (default ``refine=True``) is a strict-improvement
    hill-climb seeded AT the grid optimum, so the refined schedule must NEVER be worse
    than the grid-only optimum under the attacker's objective. In evasive mode the
    objective is the effective extraction rate (higher = cheaper for the attacker), and
    the refined schedule must remain feasible AND evasive."""
    det_factory = lambda: _detector(threshold=8.0)
    adv = AdaptiveAdversary(seeds=[0, 1, 2])
    budget = Budget(total_eth=5000.0, max_tx=8000, horizon_secs=30 * 24 * 3600.0,
                    max_destinations=4)

    grid_only = adv.search(det_factory, budget, target_detection_prob=0.5, refine=False)
    refined = adv.search(det_factory, budget, target_detection_prob=0.5, refine=True)

    assert grid_only.feasible and refined.feasible
    # Refined is a best-response within the schedule family: never a lower rate.
    assert refined.effective_rate >= grid_only.effective_rate - 1e-9
    # It stays evasive (below the detection target); refinement never trades evasion
    # away for a higher rate.
    assert refined.estimated_detection_prob < 0.5
    # And it still exfiltrates the budget target.
    assert refined.total_exfiltrated >= budget.total_eth - 1e-6


def test_refinement_is_deterministic():
    """The refinement uses a fixed neighbour order, memoised evaluations and
    strict-improvement acceptance, so repeated searches return byte-identical
    action-space coordinates + metrics."""
    det_factory = lambda: _detector(threshold=6.0)
    budget = Budget(total_eth=4000.0, max_tx=8000, horizon_secs=30 * 24 * 3600.0,
                    max_destinations=4)
    a = AdaptiveAdversary(seeds=[0, 1, 2]).search(det_factory, budget, 0.5)
    b = AdaptiveAdversary(seeds=[0, 1, 2]).search(det_factory, budget, 0.5)
    assert (a.chunk_eth, a.spacing_secs, a.n_destinations) == (
        b.chunk_eth, b.spacing_secs, b.n_destinations)
    assert a.effective_rate == b.effective_rate
    assert a.estimated_detection_prob == b.estimated_detection_prob
    assert a.total_exfiltrated == b.total_exfiltrated


def test_refinement_can_beat_the_coarse_grid():
    """Sanity that refinement is not a no-op on a budget where the coarse grid leaves
    rate on the table: at least one search over the budget sweep must yield a STRICTLY
    higher effective rate after refinement (otherwise the coarse grid already sat at a
    local optimum for every budget, which the fixed grids do not)."""
    det_factory = lambda: _detector(threshold=8.0)
    adv = AdaptiveAdversary(seeds=[0])
    budgets = [
        Budget(total_eth=t, max_tx=20_000, horizon_secs=30 * 24 * 3600.0,
               max_destinations=4)
        for t in (2500.0, 5000.0, 10_000.0, 25_000.0)
    ]
    strictly_better = 0
    for b in budgets:
        g = adv.search(det_factory, b, 0.5, refine=False)
        r = adv.search(det_factory, b, 0.5, refine=True)
        assert r.effective_rate >= g.effective_rate - 1e-9  # never worse
        if r.effective_rate > g.effective_rate + 1e-9:
            strictly_better += 1
    assert strictly_better >= 1, "refinement improved no budget — it is a no-op"
