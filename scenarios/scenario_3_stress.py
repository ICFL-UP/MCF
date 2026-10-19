"""Scenario 3: Stress Tests, INFO_PACK §9"""
import sys
from pathlib import Path
# Ensure project root is on sys.path when run as a script
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from monitor.baseline import build_baseline
from monitor.anomaly import compute_score, classify

def main():
    baseline = build_baseline(days=30, seed=42)
    known_dest = baseline["destination"].iloc[0]
    results = []

    # Sub-scenario A: high-value to known destination
    tx_a = {"value": 5000.0, "destination": known_dest, "timestamp": pd.Timestamp.now()}
    score_a = compute_score(tx_a, baseline)
    results.append(("High-value to known dest (5000 ETH)", score_a, classify(score_a)))

    # Sub-scenario B: anomalous volume. Pass a window of 30 prior txs in the
    # current hour so vol_z reflects the elevated count, not a single-tx hour.
    # This is the B1-a fix to the previously-degenerate sub-scenario.
    tx_b = {"value": 50.0, "destination": known_dest, "timestamp": pd.Timestamp.now()}
    window_b = pd.DataFrame(
        {
            "value": [50.0] * 30,
            "destination": [known_dest] * 30,
            "timestamp": [pd.Timestamp.now()] * 30,
        }
    )
    score_b = compute_score(tx_b, baseline, window=window_b)
    results.append(("Anomalous volume day (window=30)", score_b, classify(score_b)))

    # Sub-scenario C: structuring attack (100 small txs each 1736 ETH summing to ~173,600 ETH)
    struct_tx = {"value": 1736.0, "destination": "0x" + "cc" * 20, "timestamp": pd.Timestamp.now()}
    score_c = compute_score(struct_tx, baseline)
    results.append(("Structuring attack (1736 ETH each)", score_c, classify(score_c)))

    print(f"{'Sub-scenario':<45} {'Score':>8} {'Level'}")
    print("-" * 65)
    for name, score, level in results:
        print(f"{name:<45} {score:>8.3f} {level}")

    # Figure
    Path("figures").mkdir(exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 4))
    names = [r[0][:30] for r in results]
    scores = [r[1] for r in results]
    colors = ["green" if s < 3 else "orange" if s < 6 else "red" for s in scores]
    bars = ax.barh(names, scores, color=colors)
    ax.axvline(3.0, color="orange", linestyle="--", label="Alert (3.0)")
    ax.axvline(6.0, color="red", linestyle="--", label="Critical (6.0)")
    ax.set_xlabel("Anomaly Score")
    ax.set_title("Stress Test Results")
    ax.legend()
    plt.tight_layout()
    plt.savefig("figures/stress_test_scores.png", dpi=150)
    print("\nFigure saved: figures/stress_test_scores.png")

    Path("docs/logs").mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    main()
