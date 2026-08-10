"""J15 (item 5): rebuild the cost-to-evade figure (Fig8) with the annotated level fixed.

The published Fig8 annotates a single horizontal line labelled "rate-limiter floor
T+r·Delta = 4,060 ETH" and the scenario described it as a level an attacker can never
beat within a window -- the exact form Theorem 1 refutes. `scenario_7_cost_to_evade.py`
now plots the PROVED envelope B + r(W + Delta) as the bound and keeps T + r·Delta,
dashed, as the limiter-only reference level it is.

Re-running scenario 7 end to end requires the CCTX parquet corpus (and therefore
`pyarrow`). This harness rebuilds ONLY the figure, from the committed cost-to-evade
curve in `docs/logs/scenario_7_cost_to_evade.log`, by calling scenario 7's own
`write_cost_figure` -- not a copy of it. Nothing about the curve changes; only the
annotation and the output DPI do.

The parse is checked two ways: the section header's ledger parameters must match the
ALT_TRIP ledger the figure was built from, and the floor printed in the log must equal
`analytic_bound("fast", DELTA, ALT_TRIP)` recomputed here.

Usage (from the repository root):

    python3 scenarios/rederive_j15_cost_figure.py

Writes: figures/cost_to_evade.png
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from scenarios.scenario_5_bound_validation import ALT_TRIP, analytic_bound  # noqa: E402
from scenarios.scenario_7_cost_to_evade import (  # noqa: E402
    DELTA,
    FIG_COST,
    write_cost_figure,
)

SRC_LOG = Path("docs/logs/scenario_7_cost_to_evade.log")
SECTION = "## ledger[alt-trip]"          # the PRIMARY section the figure is built from
CURVE = "### Cost-to-evade curve [alt-trip]"

ROW = re.compile(
    r"^\s*([\d,]+)\s+"          # budget
    r"([\d.]+)\s+([\d.]+)\s+"   # det_prob mean, CI half-width
    r"([\d.]+)\s+([\d.]+)\s+"   # eff_rate mean, CI half-width
    r"([\d,.]+)\s+([\d,.]+)\s+" # realised mean, CI
    r"([\d,.]+)\s+"             # bound
    r"(\w+)\s+"                 # regime
    r"([\d,]+)\s+([\d,]+)\s+"   # n_tx, horizon
    r"(\S+)\s*$"                # evasion?
)
FLOOR = re.compile(r"# rate-limiter FLOOR \(T\+r\*Δ\):\s*([\d,.]+) ETH")
PARAMS = re.compile(r"# B=([\d.]+) r=([\d.]+) T=([\d.]+) W=([\d.]+) D=([\d.]+)")


def _f(x: str) -> float:
    return float(x.replace(",", ""))


def main() -> int:
    if not SRC_LOG.exists():
        raise FileNotFoundError(f"{SRC_LOG} not found")
    text = SRC_LOG.read_text(encoding="utf-8")

    i = text.index(SECTION)
    j = text.index(CURVE, i)
    header, body = text[i:j], text[j:]

    mp = PARAMS.search(header)
    if not mp:
        raise ValueError("ledger parameter line not found in the alt-trip section")
    B, r, T, W, D = (_f(mp.group(k)) for k in range(1, 6))
    if (B, r, T, W, D) != (ALT_TRIP.B, ALT_TRIP.r, ALT_TRIP.T, ALT_TRIP.W, ALT_TRIP.D):
        raise ValueError(
            f"log ledger (B={B} r={r} T={T} W={W} D={D}) != ALT_TRIP {ALT_TRIP}")

    mf = FLOOR.search(header)
    floor = _f(mf.group(1)) if mf else analytic_bound("fast", DELTA, ALT_TRIP)
    expect = analytic_bound("fast", DELTA, ALT_TRIP)
    if abs(floor - expect) > 1e-6:
        raise ValueError(f"logged floor {floor} != recomputed T + r·Δ {expect}")

    targets, det_mean, det_half, rate_mean, rate_half = [], [], [], [], []
    for line in body.splitlines():
        if line.startswith("#") or line.startswith("###") or "budget(ETH)" in line:
            continue
        m = ROW.match(line)
        if not m:
            if targets:            # the curve block has ended
                break
            continue
        targets.append(_f(m.group(1)))
        det_mean.append(float(m.group(2)))
        det_half.append(float(m.group(3)))
        rate_mean.append(float(m.group(4)))
        rate_half.append(float(m.group(5)))

    if len(targets) < 2:
        raise ValueError(f"parsed only {len(targets)} curve rows from {SRC_LOG}")

    det_mean_a = np.array(det_mean)
    det_half_a = np.array(det_half)
    rate_mean_a = np.array(rate_mean)
    rate_half_a = np.array(rate_half)
    ci_is_degenerate = bool(
        np.allclose(det_half_a, 0.0) and np.allclose(rate_half_a, 0.0))

    print(f"parsed {len(targets)} budgets from {SRC_LOG} [alt-trip]")
    print(f"  floor (superseded T + r·Δ): {floor:,.0f} ETH")
    print(f"  PROVED envelope B + r(W + Δ): "
          f"{analytic_bound('envelope', DELTA, ALT_TRIP):,.0f} ETH")
    print(f"  ci_is_degenerate = {ci_is_degenerate}")

    write_cost_figure(np.array(targets, dtype=float), det_mean_a, det_half_a,
                      rate_mean_a, rate_half_a, floor, None, ci_is_degenerate,
                      ledger=ALT_TRIP)
    print(f"Figure rebuilt: {FIG_COST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
