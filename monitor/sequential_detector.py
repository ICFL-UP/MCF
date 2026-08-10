"""BOLT Phase 12: sequential change-point detector (closes gap G2).

Motivation
----------
The production composite scorer (:func:`monitor.anomaly.compute_score`) is, in
practice, a *univariate threshold on transaction value*: the 0.5 ``value_z`` term
dominates, so a single large outflow trips it but a low-and-slow / **structuring**
attack does not. In a structuring attack the adversary drains a bridge via many
same-counterparty withdrawals each only ~1.5σ above the benign mean: invisible
per event, yet they accumulate.

This module adds a **Page-Hinkley / CUSUM** sequential test over a *per-counterparty*
sliding window of cumulative outflow. The Page-Hinkley statistic accumulates the
per-event deviation (``value_z``-like) above an allowed slack ``δ``; when the
accumulation since its running minimum exceeds ``λ`` the detector trips. Because
the accumulator is *per counterparty* and bounded to a sliding window of length
``W`` seconds, the same total value spread across many DISTINCT counterparties (or
arriving as one-off normal txs) never accumulates and does not trip.

Design properties
------------------
* **O(active-counterparties-within-window) state, O(1) amortised per event.**
  Each counterparty keeps a small struct (running cumulative deviation, running
  minimum, and a *bounded* deque of ``(t, deviation)`` entries used only to expire
  contributions older than ``W``). No unbounded list of all values is retained,
  and the per-key deque is bounded by window occupancy. Crucially, *dormant*
  counterparties, keys whose last event has aged past the window ``W``, are
  evicted by a periodic amortised sweep (every ``sweep_every`` events), so on the
  project's OPEN, GROWING address universe total state tracks the number of
  counterparties *active within the window*, not the number ever seen. The
  per-event amortised cost is O(1).
* **value_z kept as a feature, not the whole detector.** Each event contributes a
  per-tx deviation ``value_z = (value − μ) / σ`` (computed from a baseline, or
  passed in explicitly). The detector consumes that one feature; it does not
  reimplement or depend on :mod:`monitor.anomaly` internals.
* **Ronin fast path preserved.** A single 173,600-ETH withdrawal produces a
  ``value_z`` so large that one event alone exceeds ``λ`` → it trips immediately
  (regression invariant).

ARL accounting
--------------
The class exposes :meth:`measure_arl0` (mean run length, in *seconds*, between
false trips under a benign :func:`monitor.generator.generate` stream; want LARGE)
and :meth:`measure_arl1` ( ``= D`` ; mean time-to-detection, in seconds, after a
structuring onset; want SMALL). Phase 12 publishes these empirical numbers for
the Phase 14 patient-attacker bound (``X_slow ≤ B + r·D + r·Δ``) and Phase 15.

Both estimators are **censored** and both return that fact rather than hiding it.
A benign stream that never false-trips gives ARL₀ a right-censored run length, so
:meth:`measure_arl0` reports ``all_censored`` and its value is a *lower* bound.
Symmetrically, a structuring trial that never trips has an unobserved (unbounded)
detection delay, so :meth:`measure_arl1` returns an :class:`Arl1Estimate` whose
``mean_delay`` is conditional on detection (again a *lower* bound on the true
mean), carried alongside ``n_detected``/``n_trials``. Any consumer of ``D``
(notably the Phase 14 bound) inherits that optimism and must report the detection
fraction with the number.

Academic framing: this is a *design specification*. The drift ``δ`` and threshold
``λ`` are calibrated against a synthetic generator, not real bridge traffic; the
ARL numbers are empirical estimates on that synthetic stream. Honest caveat:
false-positive behaviour on real data is unmeasured.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

import numpy as np
import pandas as pd

from monitor.generator import generate


@dataclass
class _CounterpartyState:
    """O(1)-amortised Page-Hinkley accumulator for one counterparty.

    ``cum`` is the windowed sum of per-event deviations above the slack ``δ``.
    ``cum_min`` tracks the running minimum of the cumulative path; the
    Page-Hinkley statistic is ``cum − cum_min``. ``buf`` holds only the
    ``(t, contribution)`` entries still inside the window so they can be expired;
    it is bounded by the window occupancy, never by the whole stream.
    """

    cum: float = 0.0
    cum_min: float = 0.0
    buf: deque = field(default_factory=deque)
    last_t: float = 0.0  # time of the most recent event, used to evict dormant keys


@dataclass(frozen=True)
class Arl1Estimate:
    """Empirical ARL₁ = D together with the censoring bookkeeping behind it.

    ``mean_delay`` is the mean detection delay **conditional on detection**: it
    averages only the trials that actually tripped. Trials that never trip are
    right-censored (their true delay is unobserved and unbounded), so
    ``mean_delay`` is a **lower bound** on the true mean detection delay whenever
    ``n_detected < n_trials``. This mirrors the lower-bound semantics of
    :meth:`SequentialChangePointDetector.measure_arl0` (whose value is a lower
    bound when benign runs are censored); the two therefore read consistently.

    Callers must report ``n_detected``/``n_trials`` (or
    :attr:`detection_rate`) alongside ``mean_delay``: a bare mean over the
    survivors silently drops the slowest trials and understates ``D``, and any
    bound of the form ``B + r·D + r·Δ`` built on it inherits that optimism. The
    type deliberately does NOT convert to ``float`` implicitly: a caller that
    wants the number must reach for ``.mean_delay`` explicitly.
    """

    mean_delay: float
    n_detected: int
    n_trials: int

    @property
    def detection_rate(self) -> float:
        """Fraction of trials that detected (0.0 when no trial was run)."""
        if self.n_trials <= 0:
            return 0.0
        return self.n_detected / self.n_trials

    @property
    def censored(self) -> bool:
        """True when at least one trial never detected (``mean_delay`` is a
        lower bound). Fully censored (``n_detected == 0``) ⇒ ``mean_delay`` is
        ``inf``."""
        return self.n_detected < self.n_trials

    def __str__(self) -> str:  # reporting helper: keeps the fraction attached
        return (
            f"D={self.mean_delay:.1f} s "
            f"(detected {self.n_detected}/{self.n_trials})"
        )


class SequentialChangePointDetector:
    """Per-counterparty windowed Page-Hinkley / CUSUM change-point detector.

    Parameters
    ----------
    baseline_mean, baseline_std:
        Mean / std of the benign value distribution, used to turn each raw value
        into a per-tx deviation ``value_z = (value − μ) / σ``. Prefer
        :meth:`from_baseline` to derive these from a generator stream.
    window_seconds:
        ``W``: sliding window length in **seconds**. Contributions older than
        ``W`` are expired from each counterparty's accumulator.
    drift:
        ``δ``: allowed slack per event, in baseline-σ units. Only deviation in
        excess of ``δ`` accumulates, so a benign stream (mean deviation ≈ 0)
        drifts down, not up.
    threshold:
        ``λ``: trip threshold on the Page-Hinkley statistic ``cum − cum_min``.
    contribution_cap:
        Per-event saturation on the deviation feature *before* it enters the
        accumulator. This is what makes the detector a *structuring* detector
        rather than a value threshold: a single huge benign log-normal tx (whose
        raw ``value_z`` can be 20–30σ) contributes at most ``contribution_cap``,
        so it cannot drive the accumulator on its own; only *sustained*
        same-counterparty drift (many events each above the slack ``δ``)
        accumulates to ``λ``. The Ronin single-shot drain is handled separately by
        the uncapped fast path (``fast_path_z``).
    fast_path_z:
        Single-event ``value_z`` at/above which the detector trips immediately
        (the Ronin 173,600-ETH regression invariant, a value_z of ~2193σ). This
        keeps the fast-attack case while ``contribution_cap`` enables low-and-slow
        detection.
    """

    def __init__(
        self,
        baseline_mean: float,
        baseline_std: float,
        window_seconds: float = 3600.0,
        drift: float = 0.5,
        threshold: float = 8.0,
        contribution_cap: float = 2.0,
        fast_path_z: float = 100.0,
        sweep_every: int = 1000,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds (W) must be positive")
        if threshold <= 0:
            raise ValueError("threshold (λ) must be positive")
        if contribution_cap <= drift:
            raise ValueError("contribution_cap must exceed drift δ to ever accumulate")
        if sweep_every <= 0:
            raise ValueError("sweep_every must be positive")
        self.baseline_mean = float(baseline_mean)
        self.baseline_std = max(float(baseline_std), 1e-9)
        self.window_seconds = float(window_seconds)
        self.drift = float(drift)
        self.threshold = float(threshold)
        self.contribution_cap = float(contribution_cap)
        self.fast_path_z = float(fast_path_z)
        self.sweep_every = int(sweep_every)
        self._state: dict[str, _CounterpartyState] = {}
        self._events_since_sweep = 0

    # ------------------------------------------------------------------ helpers
    @classmethod
    def from_baseline(
        cls,
        baseline: pd.DataFrame,
        window_seconds: float = 3600.0,
        drift: float = 0.5,
        threshold: float = 8.0,
        contribution_cap: float = 2.0,
        fast_path_z: float = 100.0,
        sweep_every: int = 1000,
    ) -> "SequentialChangePointDetector":
        """Build a detector with ``value_z`` calibrated to ``baseline['value']``."""
        mean = float(baseline["value"].mean())
        std = float(baseline["value"].std())
        return cls(
            baseline_mean=mean,
            baseline_std=std,
            window_seconds=window_seconds,
            drift=drift,
            threshold=threshold,
            contribution_cap=contribution_cap,
            fast_path_z=fast_path_z,
            sweep_every=sweep_every,
        )

    def value_z(self, value: float) -> float:
        """Per-tx value deviation feature, the same notion as ``compute_score``'s
        ``value_z``, exposed here without importing :mod:`monitor.anomaly`."""
        return (float(value) - self.baseline_mean) / self.baseline_std

    # -------------------------------------------------------------------- update
    def update(
        self,
        counterparty: str,
        value: float,
        t: float,
        value_z: Optional[float] = None,
    ) -> tuple[float, bool]:
        """Feed one withdrawal; return ``(statistic, tripped)``.

        Parameters
        ----------
        counterparty:
            Destination / payee address, the accumulation key.
        value:
            Withdrawal value (ETH). Ignored if ``value_z`` is supplied.
        t:
            Event time in **seconds** (monotonic non-decreasing within a stream).
        value_z:
            Optional pre-computed deviation feature. When omitted it is computed
            from ``value`` and the baseline.
        """
        z = self.value_z(value) if value_z is None else float(value_z)

        st = self._state.get(counterparty)
        if st is None:
            st = _CounterpartyState()
            self._state[counterparty] = st
        st.last_t = t

        # Amortised eviction of dormant counterparties whose last event has aged
        # past the window W. Runs once every ``sweep_every`` events so total state
        # tracks counterparties active-within-window, not all ever seen (the
        # address universe is open and growing). O(1) amortised per event.
        self._events_since_sweep += 1
        if self._events_since_sweep >= self.sweep_every:
            self._sweep(t)
            self._events_since_sweep = 0

        # Fast path (Ronin regression): a single event whose raw value_z is
        # extreme trips immediately, independent of the accumulator. This keeps
        # the fast-attack case while the capped accumulator handles low-and-slow.
        if z >= self.fast_path_z:
            return float(z), True

        # Page-Hinkley contribution: deviation in excess of the slack δ, with the
        # per-event feature SATURATED at ``contribution_cap`` so a single large
        # benign log-normal tx cannot drive the accumulator; only sustained
        # same-counterparty drift accumulates to λ.
        contribution = min(z, self.contribution_cap) - self.drift

        # Expire contributions older than the window W BEFORE adding the new one.
        self._expire(st, t)

        st.cum += contribution
        st.buf.append((t, contribution))
        if st.cum < st.cum_min:
            st.cum_min = st.cum

        statistic = st.cum - st.cum_min
        tripped = statistic > self.threshold
        return statistic, tripped

    def _expire(self, st: _CounterpartyState, t: float) -> None:
        """Drop contributions whose timestamp is older than ``t − W``.

        Rebuilds ``cum_min`` from the surviving suffix so the Page-Hinkley
        minimum reflects only the current window. This keeps state O(window
        occupancy), never O(stream length).
        """
        cutoff = t - self.window_seconds
        if not st.buf:
            return
        expired = False
        while st.buf and st.buf[0][0] < cutoff:
            _t_old, contrib_old = st.buf.popleft()
            st.cum -= contrib_old
            expired = True
        if expired:
            # Recompute the running minimum over the surviving window. The buffer
            # is bounded by window occupancy, so this is bounded work, not O(n).
            running = st.cum - sum(c for _, c in st.buf)  # cum at window start
            st.cum_min = running
            acc = running
            for _t_e, contrib in st.buf:
                acc += contrib
                if acc < st.cum_min:
                    st.cum_min = acc
            if st.cum < st.cum_min:
                st.cum_min = st.cum

    def _sweep(self, t: float) -> None:
        """Evict counterparties whose most recent event has aged past ``W``.

        A dormant key's entire window has expired, so it can contribute nothing to
        any future statistic; dropping it bounds total state to the
        active-within-window set even on an open, growing address universe.
        """
        cutoff = t - self.window_seconds
        dormant = [k for k, s in self._state.items() if s.last_t < cutoff]
        for k in dormant:
            del self._state[k]

    def active_counterparties(self) -> int:
        """Number of counterparties currently retained in state (diagnostics)."""
        return len(self._state)

    def reset(self) -> None:
        """Forget all per-counterparty state."""
        self._state.clear()
        self._events_since_sweep = 0

    # ----------------------------------------------------------------- ARL API
    @staticmethod
    def _run_lengths_benign(
        detector_factory,
        seeds: Sequence[int],
        n: int,
    ) -> tuple[list[float], int]:
        """Time (seconds) until a (false) trip on each benign generator stream.

        The benign baseline is not a parameter here: each stream is drawn from
        :func:`monitor.generator.generate` by ``seed``, and the baseline
        calibration is already baked into the detector by ``detector_factory``.

        A stream that never trips contributes its full observed duration as a
        right-censored lower bound on the run length (conservative for ARL₀).
        Returns ``(run_lengths, n_tripped)`` where ``n_tripped`` is the count of
        streams that actually false-tripped (0 ⇒ the mean is fully censored).
        """
        run_lengths: list[float] = []
        n_tripped = 0
        for seed in seeds:
            stream = generate(seed=int(seed), n=n)
            t0 = stream["timestamp"].iloc[0]
            det = detector_factory()
            tripped_at: Optional[float] = None
            last_t = 0.0
            for _, row in stream.iterrows():
                t = (row["timestamp"] - t0).total_seconds()
                last_t = t
                _stat, tripped = det.update(
                    row["destination"], float(row["value"]), t
                )
                if tripped:
                    tripped_at = t
                    break
            if tripped_at is not None:
                n_tripped += 1
            run_lengths.append(tripped_at if tripped_at is not None else last_t)
        return run_lengths, n_tripped

    @classmethod
    def measure_arl0(
        cls,
        window_seconds: float,
        drift: float,
        threshold: float,
        baseline: pd.DataFrame,
        seeds: Sequence[int],
        n: int = 4000,
        return_censored: bool = False,
    ):
        """Empirical ARL₀: mean run length (seconds) between false trips on the
        BENIGN generator stream. Want LARGE.

        When no benign stream trips, every run length is right-censored at the
        stream duration, so the returned mean is a conservative **lower bound**
        (``ARL₀ ≥ value``), not a point estimate. Set ``return_censored=True`` to
        get ``(value, all_censored)`` so downstream bounds (Phase 14) can carry the
        lower-bound semantics honestly.
        """

        def factory() -> "SequentialChangePointDetector":
            return cls.from_baseline(
                baseline=baseline,
                window_seconds=window_seconds,
                drift=drift,
                threshold=threshold,
            )

        rls, n_tripped = cls._run_lengths_benign(factory, seeds, n)
        value = float(np.mean(rls))
        if return_censored:
            return value, n_tripped == 0
        return value

    @classmethod
    def measure_arl1(
        cls,
        window_seconds: float,
        drift: float,
        threshold: float,
        baseline: pd.DataFrame,
        structuring_value: float,
        inter_arrival_seconds: float,
        seeds: Sequence[int],
        max_events: int = 500,
        warmup_benign: int = 200,
    ) -> Arl1Estimate:
        """Empirical ARL₁ = D: mean time-to-detection (seconds) AFTER a
        structuring onset, averaged over the supplied seeds. Want SMALL.

        Each trial replays ``warmup_benign`` benign events on unrelated
        counterparties, then injects a single attacker on a FRESH key. Because the
        accumulator is per-counterparty, the attacker key starts cold regardless of
        warmup, so D is the conservative *cold-start* detection delay (onset-to-trip
        on a key with no prior history), which is the quantity Phase 14 needs.

        **Censoring.** A trial that does not trip within ``max_events`` is
        *right-censored*: its detection delay is unobserved and unbounded, and it
        is precisely the slowest kind of trial. Such trials are therefore excluded
        from the mean rather than imputed, which makes the returned
        :attr:`Arl1Estimate.mean_delay` a mean **conditional on detection** and
        hence a **lower bound** on the true mean detection delay, the same
        lower-bound register as :meth:`measure_arl0`, whose value is a lower bound
        when the benign run lengths are censored. Callers must report
        ``n_detected``/``n_trials`` alongside the mean; a bare conditional mean
        understates ``D`` and any bound built on it (``B + r·D + r·Δ``) inherits
        that optimism. When NO trial detects, ``mean_delay`` is ``float("inf")``
        so any ``arl1 < arl0`` assertion fails loudly instead of quietly passing.
        """
        detect_times: list[float] = []
        n_trials = 0
        for seed in seeds:
            n_trials += 1
            det = cls.from_baseline(
                baseline=baseline,
                window_seconds=window_seconds,
                drift=drift,
                threshold=threshold,
            )
            stream = generate(seed=int(seed), n=warmup_benign)
            t0 = stream["timestamp"].iloc[0]
            t_last = 0.0
            for _, row in stream.iterrows():
                t = (row["timestamp"] - t0).total_seconds()
                t_last = t
                det.update(row["destination"], float(row["value"]), t)

            attacker = "0x" + "a" * 40
            onset = t_last + inter_arrival_seconds
            detected: Optional[float] = None
            for i in range(max_events):
                t = onset + i * inter_arrival_seconds
                _stat, tripped = det.update(attacker, structuring_value, t)
                if tripped:
                    detected = t - onset
                    break
            if detected is not None:
                detect_times.append(detected)
        if not detect_times:
            # Fully censored: no trial detected. Report +inf so any ARL₁<ARL₀
            # assertion fails loudly rather than passing on a survivor mean.
            return Arl1Estimate(
                mean_delay=float("inf"), n_detected=0, n_trials=n_trials
            )
        # Conditional-on-detection mean; n_detected < n_trials ⇒ lower bound.
        return Arl1Estimate(
            mean_delay=float(np.mean(detect_times)),
            n_detected=len(detect_times),
            n_trials=n_trials,
        )
