"""30-day rolling baseline for the composite scorer.

V2 task 2.8: the toy Gaussian(50, 30) regime is RETIRED. The baseline is now the
single calibrated synthetic regime (monitor/generator.py: log-normal values,
Poisson arrivals, Zipf destinations) used everywhere else in the repo, so the
scenario-2/3/4 headline numbers and the scenario-6/7 evaluations rest on the
same data-generating process. Signature and columns are unchanged.
"""
import pandas as pd

from monitor.generator import generate


def build_baseline(days: int = 30, seed: int = 42) -> pd.DataFrame:
    n = days * 200
    df = generate(seed=seed, n=n)
    # Re-anchor the generator's Poisson timeline onto the requested rolling window
    # ending today (compute_score only uses hourly grouping + the destination set).
    span = df["timestamp"].iloc[-1] - df["timestamp"].iloc[0]
    target_end = pd.Timestamp.now().normalize()
    scale = pd.Timedelta(days=days) / span
    offsets = (df["timestamp"] - df["timestamp"].iloc[0]) * scale
    df = df.assign(timestamp=target_end - pd.Timedelta(days=days) + offsets)
    return df.reset_index(drop=True)
