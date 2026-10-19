"""BOLT Phase 15: full-knowledge adaptive adversary (contribution C3-eval core).

This module builds the *white-box, adaptive* attacker that the cost-to-evade
curve and the bound-composition check (Phase 15 scenario) are measured against.
It follows two established evaluation methodologies, by reference:

* **Problem-space action space** (Pierazzi et al., "Intriguing Properties of
  Adversarial ML Attacks in the Problem Space", IEEE S&P 2020). The attacker does
  not perturb an abstract feature vector; it manipulates the *concrete*, realisable
  withdrawal schedule. The action space is

      {chunk size (ETH/tx), inter-arrival spacing (s), #destinations, reuse pattern}

  and every candidate maps to a concrete list of ``(timestamp, value, destination)``
  withdrawal events that the Phase-12 ``SequentialChangePointDetector.update`` ingests
  unchanged.

* **Adaptive / best-of-attack reporting** (Carlini et al., "On Evaluating
  Adversarial Robustness", 2019). The attacker KNOWS the detector (params,
  thresholds) and the limiter/breaker (B, r, T, W). Robustness must be reported as
  the BEST the adaptive attack achieves at each budget, never as accuracy against a
  single fixed attack. So :meth:`AdaptiveAdversary.search` runs a real search
  (grid + greedy refinement) and returns the *cheapest feasible* schedule that keeps
  detection probability below the target. Detection probability is evaluated by
  RUNNING each candidate through the real detector over a benign background
  (:func:`monitor.generator.generate`), averaged over seeds, not a hand-coded
  heuristic the real detector would not match.

Why the action space evades the Phase-12 detector
-------------------------------------------------
The Phase-12 detector is a *per-counterparty* Page-Hinkley accumulator: it trips
when one counterparty's windowed accumulation of (capped) per-event deviation
exceeds ``λ``. A white-box attacker therefore evades by (i) keeping each chunk's
``value_z`` low so per-event contribution is small, and (ii) SPREADING the chunks
across many destinations so no single counterparty's accumulator reaches ``λ``
inside the window ``W``, and (iii) STRETCHING inter-arrival spacing so within-window
contribution-per-key stays under ``λ``. The search trades these off against the
budget {total ETH, max #tx, horizon}: more destinations / smaller chunks / wider
spacing reduce detection but lower the effective extraction rate. A STRICTER
detector (lower ``λ``) forces the search into a more-evasive, lower-rate schedule,
which is exactly the adaptivity the methodology requires and the tests assert.

Composition with the bound (Phase 14)
-------------------------------------
This module produces schedules only. The Phase-15 scenario drives every schedule
the search ever evaluates through the Phase-13 limiter+breaker+Δ simulation and
asserts realised extraction ≤ the Phase-14 bound. NOTE (J16): the fast-regime
comparator ``T + r·Δ`` was REFUTED as an upper bound (docs/bolt/theorem.md §14.1);
the proved deterministic statement is the arrival-curve envelope
``X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`` = 4,660 ETH, and ``T + r·Δ`` survives in
the harness only as a limiter-only reference level. The patient bound
``B + r·D + r·Δ`` is unaffected. If any schedule violates the bound that is a genuine finding: the
scenario fails loud; this module never weakens it.

Academic framing: a design specification, not a tested production system. The
detection probabilities are empirical estimates on synthetic benign traffic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

import numpy as np

from monitor.generator import generate
from monitor.sequential_detector import SequentialChangePointDetector

# An event is exactly what SequentialChangePointDetector.update ingests:
# (timestamp_seconds, value_eth, destination_address).
Event = Tuple[float, float, str]

DetectorFactory = Callable[[], SequentialChangePointDetector]


# ---------------------------------------------------------------------------
# Budget / constraints (problem-space feasibility).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Budget:
    """Attacker budget / constraints. A schedule is FEASIBLE only if it exfiltrates
    >= ``total_eth`` using <= ``max_tx`` withdrawals within <= ``horizon_secs``.

    ``max_destinations`` caps how many distinct destination addresses the attacker
    may use. This is a problem-space cost (Pierazzi et al.): minting/maintaining
    fresh destinations to spread outflow across the per-counterparty detector is
    NOT free: KYC-clean cash-out addresses are scarce and reused addresses
    re-accumulate detector mass. Capping it stops destination-spreading from being a
    cost-free evasion, so a stricter detector genuinely collapses the attacker's
    effective extraction RATE (the cost-to-evade narrative) instead of being dodged
    by minting unbounded addresses. ``None`` means unbounded (legacy behaviour).
    """

    total_eth: float          # target value to exfiltrate (>=)
    max_tx: int               # maximum number of withdrawals
    horizon_secs: float       # maximum wall-clock horizon of the schedule
    max_destinations: Optional[int] = None  # cap on distinct destinations (None = unbounded)


# ---------------------------------------------------------------------------
# A concrete candidate point in the action space + its evaluated schedule.
# ---------------------------------------------------------------------------
@dataclass
class Schedule:
    """A concrete attack schedule: the action-space point plus its realised events
    and the metrics the cost-to-evade curve / bound-composition check consume."""

    # --- action-space dimensions (Pierazzi problem space) ---
    chunk_eth: float                 # value per withdrawal (ETH/tx)
    spacing_secs: float              # inter-arrival spacing (s)
    n_destinations: int              # number of distinct destination addresses
    reuse: str                       # destination reuse pattern: "round_robin"

    # --- realised schedule ---
    events: List[Event] = field(default_factory=list)

    # --- metrics ---
    estimated_detection_prob: float = 1.0
    total_exfiltrated: float = 0.0
    n_tx: int = 0
    horizon: float = 0.0             # max(t) - min(t) over events [s]
    feasible: bool = False

    @property
    def effective_rate(self) -> float:
        """Effective extraction rate (ETH/s) = total / horizon. The lower this is,
        the more the attacker has been forced to stretch the theft."""
        if self.horizon <= 0:
            # Single-event (or instantaneous) schedule: rate is the chunk itself.
            return self.total_exfiltrated
        return self.total_exfiltrated / self.horizon


# ---------------------------------------------------------------------------
# The adaptive adversary.
# ---------------------------------------------------------------------------
class AdaptiveAdversary:
    """Full-knowledge adaptive adversary that searches the problem-space action
    space for the cheapest schedule keeping detection probability below a target.

    Parameters
    ----------
    seeds:
        Seeds for the benign background streams; detection probability is the
        fraction of seeds on which the detector trips while the attacker's schedule
        is interleaved with that benign traffic. Averaging over seeds keeps the
        estimate stable (Carlini: report the attack's *expected* evasion).
    benign_n:
        Number of benign background events per seed to interleave the attack into,
        so detection is measured against realistic traffic, not silence.
    """

    # Address namespace for attacker destinations, distinct from the generator's
    # universe so attacker keys never alias benign hot addresses.
    _DEST_PREFIX = 0xA77ACC  # "attacc(k)" tag in the high bits

    # ------------------------------------------------------------------ refinement
    # Greedy / coordinate-descent local search knobs (deterministic). After the grid
    # picks the best cell, the refinement perturbs ONE action-space axis at a time by
    # the fixed multiplicative factors / integer deltas below, in this fixed order,
    # moving to the first STRICTLY-better feasible (and, in evasive mode, still-evasive)
    # neighbour. Being a strict-improvement hill-climb seeded AT the grid optimum, the
    # returned schedule is provably >= the grid optimum under the active objective,
    # never worse (a test asserts this). Bounded passes keep it cheap + terminating.
    _REFINE_CHUNK_FACTORS = (0.5, 0.75, 1.25, 1.5, 2.0)
    _REFINE_SPACING_FACTORS = (0.5, 0.75, 1.25, 1.5, 2.0)
    _REFINE_DEST_DELTAS = (-1, 1)
    _MAX_REFINE_PASSES = 8

    def __init__(self, seeds: Sequence[int] = (0, 1, 2), benign_n: int = 400) -> None:
        self.seeds = list(seeds)
        self.benign_n = int(benign_n)

    # ----------------------------------------------------------- destinations
    def _dest(self, i: int) -> str:
        """Deterministic attacker destination address for index ``i``."""
        return f"0x{(self._DEST_PREFIX << 64) + i:040x}"

    # ----------------------------------------------------- build a schedule
    def build_schedule(
        self,
        chunk_eth: float,
        spacing_secs: float,
        n_destinations: int,
        reuse: str,
        budget: Budget,
        start_t: float = 0.0,
    ) -> Schedule:
        """Materialise one action-space point into a concrete event list, capped by
        the budget {total ETH, max #tx, horizon}.

        ``reuse="round_robin"`` cycles destinations 0,1,...,n-1,0,1,... so the
        attacker reuses each address every ``n_destinations`` withdrawals: this is
        the per-counterparty accumulation the Phase-12 detector watches, and the
        knob that trades detection against #addresses.
        """
        if reuse != "round_robin":
            raise ValueError(f"unsupported reuse pattern: {reuse!r}")
        n_destinations = max(1, int(n_destinations))
        # Problem-space cost: the attacker may not use more distinct destinations than
        # the budget allows. A schedule that would need more is INFEASIBLE (we do not
        # silently clamp it to look evasive; we honestly mark it infeasible below).
        exceeds_dest_cap = (
            budget.max_destinations is not None
            and n_destinations > int(budget.max_destinations)
        )

        # How many tx are needed to reach the target, capped by max_tx and horizon.
        need = int(np.ceil(budget.total_eth / chunk_eth)) if chunk_eth > 0 else 0
        n_tx = min(need, budget.max_tx)
        if spacing_secs > 0:
            max_by_horizon = int(budget.horizon_secs // spacing_secs) + 1
            n_tx = min(n_tx, max_by_horizon)
        n_tx = max(n_tx, 0)

        events: List[Event] = []
        for i in range(n_tx):
            t = start_t + i * spacing_secs
            dest = self._dest(i % n_destinations)
            events.append((float(t), float(chunk_eth), dest))

        total = sum(v for (_t, v, _d) in events)
        horizon = (events[-1][0] - events[0][0]) if len(events) > 1 else 0.0
        feasible = (
            total >= budget.total_eth - 1e-6
            and len(events) <= budget.max_tx
            and horizon <= budget.horizon_secs + 1e-6
            and len(events) > 0
            and not exceeds_dest_cap
        )
        return Schedule(
            chunk_eth=float(chunk_eth),
            spacing_secs=float(spacing_secs),
            n_destinations=int(n_destinations),
            reuse=reuse,
            events=events,
            total_exfiltrated=float(total),
            n_tx=len(events),
            horizon=float(horizon),
            feasible=feasible,
        )

    # ------------------------------------------------ detection probability
    def estimate_detection_prob(
        self,
        schedule: Schedule,
        detector_factory: DetectorFactory,
    ) -> float:
        """Fraction of benign-background seeds on which the detector trips when the
        attacker's events are interleaved with benign traffic.

        The attacker's events are merged (by timestamp) into a benign generator
        stream and fed to a FRESH detector per seed; the trip is what the real
        Phase-12 detector signals. This is the white-box-evaluated detection
        probability the search minimises, not a hand-coded surrogate.
        """
        if not schedule.events:
            return 1.0  # an empty schedule extracts nothing; treat as 'detected'/useless

        trips = 0
        for seed in self.seeds:
            det = detector_factory()
            if self._run_interleaved(det, schedule.events, seed):
                trips += 1
        return trips / max(1, len(self.seeds))

    def _run_interleaved(
        self,
        detector: SequentialChangePointDetector,
        attack_events: Sequence[Event],
        seed: int,
    ) -> bool:
        """Interleave attack events with a benign stream by timestamp; return True
        if the detector trips at any point. The attack is overlaid starting at the
        benign stream's origin so it competes against realistic concurrent traffic.
        """
        benign = generate(seed=int(seed), n=self.benign_n)
        t0 = benign["timestamp"].iloc[0]
        benign_events: List[Event] = [
            (
                float((row.timestamp - t0).total_seconds()),
                float(row.value),
                str(row.destination),
            )
            for row in benign.itertuples(index=False)
        ]
        # Merge by time (stable). Attack events use absolute seconds from 0, the same
        # origin as the benign relative timeline.
        merged = sorted(
            list(benign_events) + list(attack_events), key=lambda e: e[0]
        )
        for (t, value, dest) in merged:
            _stat, tripped = detector.update(dest, value, t)
            if tripped:
                return True
        return False

    # ----------------------------------------------------- greedy refinement
    @staticmethod
    def _evasive_key(s: Schedule) -> Tuple[float, int]:
        """Ranking key for the evasive-mode objective: cheapest = highest effective
        rate (least stretched), tie-break toward fewer destinations."""
        return (s.effective_rate, -s.n_destinations)

    @staticmethod
    def _fallback_key(s: Schedule) -> Tuple[float, float]:
        """Ranking key for the no-evasion-available fallback: least detectable, then
        highest rate (maximise this tuple)."""
        return (-s.estimated_detection_prob, s.effective_rate)

    def _refine(
        self,
        start: Schedule,
        detector_factory: DetectorFactory,
        budget: Budget,
        target_detection_prob: float,
        cap_b: float,
        dest_cap: Optional[int],
        evasive_mode: bool,
    ) -> Schedule:
        """Coordinate-descent local search seeded at the grid optimum ``start``.

        Perturbs one action-space axis at a time (chunk / spacing / #destinations) by
        the fixed factors/deltas, evaluating each neighbour with the REAL detector, and
        greedily moves to the first strictly-better feasible neighbour. Deterministic:
        fixed neighbour order, memoised evaluations, strict-improvement acceptance (so
        ties never move). Returns a schedule >= ``start`` under the active objective.
        """
        cache: dict = {}

        def evaluate(chunk: float, spacing: float, ndest: int) -> Schedule:
            chunk = min(max(float(chunk), 1e-9), cap_b)
            spacing = max(float(spacing), 1.0)
            ndest = max(1, int(ndest))
            if dest_cap is not None:
                ndest = min(ndest, int(dest_cap))
            key = (round(chunk, 6), round(spacing, 6), ndest)
            if key in cache:
                return cache[key]
            s = self.build_schedule(
                chunk_eth=chunk, spacing_secs=spacing, n_destinations=ndest,
                reuse="round_robin", budget=budget,
            )
            if s.feasible:
                s.estimated_detection_prob = self.estimate_detection_prob(s, detector_factory)
            cache[key] = s
            return s

        def is_better(cand: Schedule, incumbent: Schedule) -> bool:
            if not cand.feasible:
                return False
            if evasive_mode:
                if cand.estimated_detection_prob >= target_detection_prob:
                    return False
                return self._evasive_key(cand) > self._evasive_key(incumbent)
            return self._fallback_key(cand) > self._fallback_key(incumbent)

        best = start
        for _ in range(self._MAX_REFINE_PASSES):
            improved = False
            # Fixed neighbour order: chunk axis, then spacing axis, then dest axis.
            neighbours: List[Tuple[float, float, int]] = []
            for f in self._REFINE_CHUNK_FACTORS:
                neighbours.append((best.chunk_eth * f, best.spacing_secs, best.n_destinations))
            for f in self._REFINE_SPACING_FACTORS:
                neighbours.append((best.chunk_eth, best.spacing_secs * f, best.n_destinations))
            for d in self._REFINE_DEST_DELTAS:
                neighbours.append((best.chunk_eth, best.spacing_secs, best.n_destinations + d))
            for (chunk, spacing, ndest) in neighbours:
                cand = evaluate(chunk, spacing, ndest)
                if is_better(cand, best):
                    best = cand
                    improved = True
            if not improved:
                break
        return best

    # ------------------------------------------------------------- search
    def search(
        self,
        detector_factory: DetectorFactory,
        budget: Budget,
        target_detection_prob: float = 0.5,
        limiter_params: Optional[dict] = None,
        chunk_grid: Optional[Sequence[float]] = None,
        spacing_grid: Optional[Sequence[float]] = None,
        dest_grid: Optional[Sequence[int]] = None,
        refine: bool = True,
    ) -> Schedule:
        """Full-knowledge adaptive search for the CHEAPEST feasible schedule whose
        estimated detection probability is below ``target_detection_prob``.

        "Cheapest" = highest effective extraction rate (least stretched) among the
        evasive-and-feasible candidates: the attacker wants the target value out as
        fast as possible while staying below the detector. The search is a grid over
        the action space {chunk, spacing, #destinations} with round-robin reuse, each
        candidate evaluated by running the REAL detector over benign traffic, FOLLOWED
        BY (``refine=True``, default) a deterministic greedy / coordinate-descent local
        refinement seeded at the best grid cell (:meth:`_refine`), so the returned
        schedule is a best-response within the schedule family, not merely the best
        node on a coarse grid. Because the refinement is a strict-improvement hill-climb
        seeded at the grid optimum, its result is always >= the grid optimum under the
        active objective (a test asserts improve-or-equal + determinism). Set
        ``refine=False`` to obtain the grid-only optimum (used by tests to measure the
        refinement delta).

        Returns the best evasive-feasible schedule, or, if none is both feasible and
        below the detection target, the best-effort least-detectable feasible
        schedule with ``feasible`` reflecting whether the budget was met at all.
        ``limiter_params`` (B, r, T, W) is accepted for white-box completeness and
        used to cap a single chunk at the per-block burst ``B`` so the schedule cannot
        request a same-block escape the limiter would never admit (assumption 4).
        """
        # Action-space grids. Chosen to span low-and-slow (small chunk, many dests,
        # wide spacing) to aggressive (large chunk, one dest, tight spacing). The
        # search picks among these; a stricter detector pushes the choice toward the
        # evasive end (smaller chunk / more dests), which lowers effective_rate.
        cap_b = float(limiter_params["B"]) if limiter_params and "B" in limiter_params else 1000.0

        if chunk_grid is None:
            chunk_grid = [25.0, 50.0, 100.0, 200.0, 400.0, 800.0]
        chunk_grid = [min(c, cap_b) for c in chunk_grid]
        if spacing_grid is None:
            spacing_grid = [60.0, 300.0, 900.0, 1800.0]
        if dest_grid is None:
            dest_grid = [1, 4, 16, 64, 256]
        # Respect the budget's destination cap (problem-space cost): never search
        # destination counts the attacker cannot actually provision. Keep at least
        # {1} so the grid is non-empty.
        if budget.max_destinations is not None:
            cap_d = int(budget.max_destinations)
            dest_grid = [d for d in dest_grid if d <= cap_d] or [1]

        feasible_evasive: List[Schedule] = []
        feasible_any: List[Schedule] = []

        for chunk in chunk_grid:
            for spacing in spacing_grid:
                for ndest in dest_grid:
                    sched = self.build_schedule(
                        chunk_eth=chunk,
                        spacing_secs=spacing,
                        n_destinations=ndest,
                        reuse="round_robin",
                        budget=budget,
                    )
                    if not sched.feasible:
                        continue
                    p = self.estimate_detection_prob(sched, detector_factory)
                    sched.estimated_detection_prob = p
                    feasible_any.append(sched)
                    if p < target_detection_prob:
                        feasible_evasive.append(sched)

        dest_cap = int(budget.max_destinations) if budget.max_destinations is not None else None

        if feasible_evasive:
            # Cheapest = highest effective rate (least stretched) among evasive ones;
            # tie-break toward fewer destinations (operationally cheaper).
            best = max(feasible_evasive, key=self._evasive_key)
            if refine:
                best = self._refine(
                    best, detector_factory, budget, target_detection_prob,
                    cap_b, dest_cap, evasive_mode=True,
                )
            return best

        if feasible_any:
            # Budget met but nothing got below the detection target: return the
            # LEAST-detectable feasible schedule (still honestly feasible=True), so
            # callers see the attacker's best evasion even when it can't beat target.
            best = min(
                feasible_any,
                key=lambda s: (s.estimated_detection_prob, -s.effective_rate),
            )
            if refine:
                best = self._refine(
                    best, detector_factory, budget, target_detection_prob,
                    cap_b, dest_cap, evasive_mode=False,
                )
            return best

        # Nothing feasible at all: report infeasible with the closest attempt's
        # action-space coordinates for diagnostics.
        probe = self.build_schedule(
            chunk_eth=chunk_grid[0],
            spacing_secs=spacing_grid[0],
            n_destinations=dest_grid[0],
            reuse="round_robin",
            budget=budget,
        )
        probe.feasible = False
        probe.estimated_detection_prob = 1.0
        return probe
