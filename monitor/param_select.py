"""Train-only detector parameter selection (V2 task 2.3: FPR-budget procedure).

Why FPR-budget and not Youden-J
--------------------------------
TRAIN (``data/cctx/train.parquet``) is 100% benign, so Youden-J is not computable
on TRAIN alone; Youden-J on TRAIN + injections would optimise a synthetic mixture
ratio we would have to invent, whereas the FPR budget is an operational quantity
the reframed detector claim (V2 2.1) already commits to. Procedure:

1. Grid-search (λ, δ, cap) ∈ {4, 6, 8, 12, 16} × {0.25, 0.5, 1.0} × {1.5, 2.0, 3.0}
   (skipping cap ≤ δ, the detector invariant), 45 configs.
2. For each config, stream the benign TRAIN rows through
   :class:`monitor.sequential_detector.SequentialChangePointDetector` (fast-path z
   = the q=0.999 TRAIN quantile of the signed log-z, same construction as
   scenario_6) and record φ_train = benign flag rate.
3. Constraint: φ_train ≤ ``fpr_budget`` (default 1%).
4. Among admissible configs, maximise **power** over a TRAIN-only **attack-geometry
   FAMILY** of seeded low-and-slow drains injected into the real TRAIN cadence:
   σ ∈ ``TRAIN_DRAIN_SIGMAS`` × event-count ∈ ``TRAIN_DRAIN_EVENTS``
   (per-tx value = μ_log + σ·σ_log). See the geometry-disjointness note below.
5. Tie-break on lowest φ_train (then a fixed grid order for full determinism).

Geometry disjointness (phase-22 B2a: de-circularized selection)
----------------------------------------------------------------
An earlier revision selected (δ, λ, cap) to maximise recall on canonical drains
with σ = 1.5 and 60 events, the IDENTICAL geometry scenario_6 later evaluates the
low-and-slow claim on, which made that evaluation partly circular (params tuned to
the exact attack they were then scored against). The selection family is now
**disjoint from the evaluation point in BOTH coordinates**:

* selection (TRAIN cadence):  σ ∈ {1.0, 2.0} × events ∈ {30, 90}
* evaluation (scenario_6, TEST cadence):  σ = ``EVAL_DRAIN_SIGMA`` = 1.5,
  events = ``EVAL_DRAIN_EVENTS`` = 60

The eval σ is bracketed by (but never a member of) the selection σ set, and the
eval event count is bracketed by (but never a member of) the selection counts, so
the selected triple generalises ACROSS the family rather than memorising the test
geometry. A module-level assert enforces the disjointness so it cannot silently
regress. scenario_6 additionally sweeps σ at evaluation time (including levels
above the value-baseline threshold) so the seq-vs-value crossover is shown, not a
single point.

Everything here consumes TRAIN only; the held-out TEST split is never touched, so
the selection is non-circular by construction. The composite weights (0.5, 0.3, 0.2)
and ALERT=3.0/CRITICAL=6.0 are deliberately OUT of scope: they stay
dissertation-fixed (§11.2.3) and are *ablated* (scenario_6 → docs/bolt/ablations.md),
never train-selected.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from monitor.sequential_detector import SequentialChangePointDetector

# The 2.3 selection grid, 45 configs after the cap>δ filter (here: no config drops).
GRID_LAMBDA = (4.0, 6.0, 8.0, 12.0, 16.0)
GRID_DRIFT = (0.25, 0.5, 1.0)
GRID_CAP = (1.5, 2.0, 3.0)

WINDOW_SECONDS = 3600.0   # W is ledger-locked; selection covers λ/δ/cap only.
FAST_PATH_Q = 0.999       # same train-derived fast-path quantile as scenario_6.

# --- B2(a): TRAIN-only attack-geometry family, DISJOINT from the eval point ---
# Selection power is averaged over σ ∈ TRAIN_DRAIN_SIGMAS × events ∈
# TRAIN_DRAIN_EVENTS (drains injected into the TRAIN cadence). scenario_6
# evaluates the low-and-slow claim at (EVAL_DRAIN_SIGMA, EVAL_DRAIN_EVENTS) on
# the TEST cadence, a geometry the selection NEVER optimised (see module
# docstring). The asserts make the disjointness a hard invariant.
TRAIN_DRAIN_SIGMAS = (1.0, 2.0)
TRAIN_DRAIN_EVENTS = (30, 90)
EVAL_DRAIN_SIGMA = 1.5      # scenario_6's held-out evaluation geometry …
EVAL_DRAIN_EVENTS = 60      # … (consumed by scenario_6, never by selection)
N_DRAINS_PER_GEOM = 3       # seeded drains per (σ, events) cell → 2×2×3 = 12
DRAIN_GAP_CEILING_S = 1200.0  # = inter_arrival_s * 10 in scenario_6's construction

assert EVAL_DRAIN_SIGMA not in TRAIN_DRAIN_SIGMAS, (
    "B2a geometry-disjointness violated: eval σ is in the selection family"
)
assert EVAL_DRAIN_EVENTS not in TRAIN_DRAIN_EVENTS, (
    "B2a geometry-disjointness violated: eval event count is in the selection family"
)


@dataclass(frozen=True)
class SelectedParams:
    drift: float
    threshold: float
    cap: float
    phi_train: float          # benign flag rate of the winning config on TRAIN
    power_train: float        # recall on drains injected into TRAIN cadence
    fpr_budget: float
    grid_size: int
    procedure: str            # human-readable provenance string


def selection_grid() -> list[tuple[float, float, float]]:
    """(λ, δ, cap) grid in a fixed deterministic order, skipping cap ≤ δ.

    Public so scenario_6's ``cusum_ablation_grid`` evaluates the *same* 45 configs
    on TEST (evaluation-only) that the selection saw on TRAIN.
    """
    return [
        (lam, d, c)
        for lam in GRID_LAMBDA
        for d in GRID_DRIFT
        for c in GRID_CAP
        if c > d
    ]


def _fast_path_z(train: pd.DataFrame, scale) -> float:
    """Train-derived fast-path z (q=0.999 TRAIN quantile of the scaled feature)."""
    tz = np.asarray(scale.z(train["value"].to_numpy()), dtype=float)
    return float(np.quantile(tz, FAST_PATH_Q))


def _train_geometry_drains(
    train: pd.DataFrame, seed: int
) -> list[tuple[str, np.ndarray, float]]:
    """Seeded low-and-slow drains over the TRAIN-only geometry family (B2a).

    For each (σ, n_events) in ``TRAIN_DRAIN_SIGMAS × TRAIN_DRAIN_EVENTS`` (a
    family DISJOINT from scenario_6's evaluation geometry; see module docstring),
    builds ``N_DRAINS_PER_GEOM`` drains: per-tx value = 10^(μ_log + σ·σ_log)
    with μ_log/σ_log fit on TRAIN (the same log-stats every scale implementation
    fits), event times = cumsum of real TRAIN inter-arrival gaps sampled with a
    seeded RNG. Returns [(attacker_key, event_times_seconds, per_tx_value), …].
    """
    lv = np.log10(np.clip(train["value"].to_numpy(dtype=float), 1e-9, None))
    mu_log, sd_log = float(lv.mean()), float(max(lv.std(), 1e-9))

    tsec = np.sort(train["t_sec"].to_numpy(dtype=float))
    gaps = np.diff(tsec)
    gaps = gaps[(gaps > 0) & (gaps < DRAIN_GAP_CEILING_S)]

    rng = np.random.default_rng(seed)
    drains: list[tuple[str, np.ndarray, float]] = []
    k = 0
    for sigma in TRAIN_DRAIN_SIGMAS:
        per_tx_value = float(10 ** (mu_log + sigma * sd_log))
        for n_events in TRAIN_DRAIN_EVENTS:
            for _ in range(N_DRAINS_PER_GEOM):
                if gaps.size:
                    g = rng.choice(gaps, size=n_events)
                else:
                    g = np.full(n_events, 120.0)
                times = np.cumsum(g).astype(float)
                attacker = "0x" + format(0xA0 + k, "x").rjust(40, "a")
                drains.append((attacker, times, per_tx_value))
                k += 1
    return drains


def select_params_on_train(
    train: "pd.DataFrame",
    scale,
    *,
    fpr_budget: float = 0.01,
    seed: int = 42,
) -> SelectedParams:
    """FPR-budget parameter selection on the benign TRAIN stream (never TEST).

    ``scale`` must expose ``z(values) -> ndarray`` (e.g. scenario_6's ``LogScale``).
    Selection ordering: admissibility (φ_train ≤ budget) → max mean power over the
    TRAIN-only attack-geometry family (σ ∈ {1.0, 2.0} × events ∈ {30, 90}, drains
    on the TRAIN cadence; DISJOINT from scenario_6's σ=1.5/60 evaluation point,
    see module docstring) → lowest φ_train → fixed grid order.
    """
    if "t_sec" not in train.columns:
        raise KeyError("train needs a 't_sec' column (seconds since stream start)")

    grid = selection_grid()
    fast_path = _fast_path_z(train, scale)

    dests = train["destination"].to_numpy()
    vals = train["value"].to_numpy(dtype=float)
    tsec = train["t_sec"].to_numpy(dtype=float)
    zsig = np.asarray(scale.z(vals), dtype=float)

    drains = _train_geometry_drains(train, seed)
    z_by_value = {
        v: float(np.asarray(scale.z(np.array([v])), dtype=float)[0])
        for v in {d[2] for d in drains}
    }

    rows: list[tuple[float, float, float, float, float]] = []  # (lam, d, c, phi, power)
    for lam, d, c in grid:
        det = SequentialChangePointDetector.from_baseline(
            train,
            window_seconds=WINDOW_SECONDS,
            drift=d,
            threshold=lam,
            contribution_cap=c,
            fast_path_z=fast_path,
        )
        # φ_train: benign flag rate on the TRAIN stream.
        n_flags = 0
        for i in range(len(vals)):
            _stat, tripped = det.update(
                dests[i], float(vals[i]), float(tsec[i]), value_z=float(zsig[i])
            )
            if tripped:
                n_flags += 1
        phi = n_flags / max(len(vals), 1)

        # power_train: mean per-drain trip rate over the TRAIN-only geometry
        # family (B2a: σ ∈ {1.0, 2.0} × events ∈ {30, 90}; NEVER the σ=1.5/60
        # evaluation geometry).
        trip_rates = []
        for attacker, times, per_tx_value in drains:
            det.reset()
            flagged = 0
            for t in times:
                _stat, tripped = det.update(
                    attacker, per_tx_value, float(t), value_z=z_by_value[per_tx_value]
                )
                if tripped:
                    flagged += 1
            trip_rates.append(flagged / len(times))
        power = float(np.mean(trip_rates))
        rows.append((lam, d, c, phi, power))

    admissible = [r for r in rows if r[3] <= fpr_budget]
    if not admissible:
        raise ValueError(
            f"no (λ, δ, cap) config meets the φ_train ≤ {fpr_budget} budget "
            f"(min φ_train on the grid = {min(r[3] for r in rows):.5f})"
        )
    # budget → power (max) → φ (min) → fixed grid order (deterministic).
    lam, d, c, phi, power = min(admissible, key=lambda r: (-r[4], r[3]))

    procedure = (
        f"FPR-budget<={fpr_budget:.4g} on TRAIN benign stream; "
        f"power over TRAIN-only geometry family sigma={TRAIN_DRAIN_SIGMAS} x "
        f"events={TRAIN_DRAIN_EVENTS} ({len(drains)} drains on TRAIN cadence; "
        f"DISJOINT from the sigma={EVAL_DRAIN_SIGMA}/{EVAL_DRAIN_EVENTS}-event "
        f"eval point); grid {len(grid)} configs; seed {seed}"
    )
    return SelectedParams(
        drift=d,
        threshold=lam,
        cap=c,
        phi_train=phi,
        power_train=power,
        fpr_budget=fpr_budget,
        grid_size=len(grid),
        procedure=procedure,
    )
