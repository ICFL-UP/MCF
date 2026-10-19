"""
Phase 9b: Side-by-side comparison of z-score (monitor.anomaly) and IsolationForest
(monitor.isolation_forest) detectors on three transactions:

1. Normal:  45 ETH to a known destination (baseline distribution)
2. Ronin:   173,600 ETH to a novel destination (the §11.2.3 headline case)
3. Edge:    500 ETH to a known destination (large but not Ronin-scale)

The aim is to confirm both detectors agree on extremes and to surface any divergence
in the middle (which the dissertation flags as the harder-to-tune regime).
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd

from monitor.anomaly import (
    ALERT_THRESHOLD,
    CRITICAL_THRESHOLD,
    classify,
    compute_score,
)
from monitor.baseline import build_baseline
from monitor.isolation_forest import (
    classify_iforest,
    score_iforest,
    train_iforest,
)


def main() -> None:
    baseline = build_baseline(days=30, seed=42)
    print(f"Baseline: n={len(baseline)} txs, mean={baseline['value'].mean():.1f} ETH, "
          f"std={baseline['value'].std():.1f} ETH")

    t0 = time.perf_counter()
    iforest = train_iforest(baseline, seed=42)
    train_ms = (time.perf_counter() - t0) * 1000
    print(f"IsolationForest train time: {train_ms:.2f} ms\n")

    txs = [
        {
            "label": "Normal (45 ETH, known dest)",
            "tx": {"value": 45.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()},
        },
        {
            "label": "Ronin (173,600 ETH, novel dest)",
            "tx": {"value": 173600.0, "destination": "0xdead" + "0" * 36, "timestamp": pd.Timestamp.now()},
        },
        {
            "label": "Edge (500 ETH, known dest)",
            "tx": {"value": 500.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()},
        },
    ]

    print(f"{'Case':<40} {'z-score':>10} {'class':>10} | {'iforest':>10} {'class':>10}")
    print("-" * 90)
    for entry in txs:
        z = compute_score(entry["tx"], baseline)
        z_label = classify(z)
        i = score_iforest(iforest, entry["tx"], baseline)
        i_label = classify_iforest(iforest, entry["tx"], baseline)
        print(f"{entry['label']:<40} {z:>10.3f} {z_label:>10} | {i:>10.4f} {i_label:>10}")

    print(f"\nThresholds: z-score alert={ALERT_THRESHOLD}, critical={CRITICAL_THRESHOLD}")
    print("IsolationForest: score_samples < 0 => predicted ANOMALY (lower = more anomalous).")


if __name__ == "__main__":
    main()
