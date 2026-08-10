"""Scenario 4: Synthetic False-Positive / False-Negative Sweep, B3.

Probes the z-score detector at the alert (3.0) and critical (6.0) thresholds
on four synthetic buckets:

1. **Clean baseline**: sample 1,000 txs from the same distribution that built
   the 30-day baseline. Expected: low alert rate (this is the synthetic FPR).
2. **Value-shifted +20%**: re-sample with mean shifted by 20%. Expected:
   modest alert lift; should not flood CRITICAL.
3. **Value-shifted +80%**: re-sample with mean shifted by 80%. Expected:
   visible alert and some critical hits; this is the operational sensitivity
   boundary.
4. **Open destination set**: 1,000 baseline-shaped values to *novel* addresses
   not in the closed baseline destination set. Expected: novelty term lifts the
   composite by 0.2 across the bucket.

Provenance: this is **synthetic FPR on the single calibrated regime**. The 30-day
baseline comes from `monitor.baseline.build_baseline`, which delegates to
`monitor/generator.py` (log-normal heavy-tailed values, Poisson arrivals, Zipf
open destination set), the same data-generating process used by every other
scenario in the repo (the toy Gaussian baseline is retired; V2 task 2.8). The
distribution parameters are illustrative defaults, not fitted to a specific
bridge, so the absolute rates are not transferable to production; real-traffic
FPR is measured on the CCTX data in scenario 6. The point here is a *measured*
synthetic characterisation rather than the previous *"FPR is unmeasured"* framing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd

from monitor.anomaly import ALERT_THRESHOLD, CRITICAL_THRESHOLD, classify, compute_score
from monitor.baseline import build_baseline

N_PER_BUCKET = 1_000


def sweep_bucket(
    label: str,
    samples: pd.DataFrame,
    baseline: pd.DataFrame,
) -> dict:
    alert_hits = 0
    critical_hits = 0
    for _, row in samples.iterrows():
        tx = {
            "value": float(row["value"]),
            "destination": row["destination"],
            "timestamp": row["timestamp"],
        }
        score = compute_score(tx, baseline)
        level = classify(score)
        if level == "CRITICAL":
            critical_hits += 1
        elif level == "ALERT":
            alert_hits += 1
    n = len(samples)
    return {
        "bucket": label,
        "n": n,
        "alert_pct": 100.0 * alert_hits / n,
        "critical_pct": 100.0 * critical_hits / n,
        "alert_count": alert_hits,
        "critical_count": critical_hits,
    }


def make_samples(rng: np.random.Generator, mean: float, std: float, dests: list[str], n: int) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "value": rng.normal(mean, std, n).clip(min=0.1),
            "destination": rng.choice(dests, n),
            "timestamp": [pd.Timestamp.now()] * n,
        }
    )


def main() -> None:
    baseline = build_baseline(days=30, seed=42)
    print(
        f"Baseline: n={len(baseline)} txs, mean={baseline['value'].mean():.1f} ETH, "
        f"std={baseline['value'].std():.1f} ETH"
    )
    print(f"Thresholds: alert={ALERT_THRESHOLD}, critical={CRITICAL_THRESHOLD}\n")

    rng = np.random.default_rng(seed=12345)
    base_mean = float(baseline["value"].mean())
    base_std = float(baseline["value"].std())
    known_dests = list(baseline["destination"].unique())
    novel_dests = [f"0x{i + 100:040x}" for i in range(20)]

    rows = [
        sweep_bucket(
            "Clean baseline",
            make_samples(rng, base_mean, base_std, known_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Value-shifted +80%",
            make_samples(rng, base_mean * 1.8, base_std, known_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Value mean=500 (known)",
            make_samples(rng, 500.0, base_std, known_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Value mean=500 (novel dest)",
            make_samples(rng, 500.0, base_std, novel_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Value mean=1000 (known)",
            make_samples(rng, 1000.0, base_std, known_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Severe outliers (mean=2000)",
            make_samples(rng, 2000.0, base_std * 4, known_dests, N_PER_BUCKET),
            baseline,
        ),
        sweep_bucket(
            "Open destination set (mean=baseline)",
            make_samples(rng, base_mean, base_std, novel_dests, N_PER_BUCKET),
            baseline,
        ),
    ]

    print(f"{'Bucket':<25} {'n':>6} {'alert %':>10} {'critical %':>12}")
    print("-" * 60)
    for r in rows:
        print(
            f"{r['bucket']:<25} {r['n']:>6} {r['alert_pct']:>9.2f}% {r['critical_pct']:>11.2f}%"
        )

    Path("docs/logs").mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    main()
