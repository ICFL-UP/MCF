import pandas as pd
import pytest

from monitor.baseline import build_baseline
from monitor.isolation_forest import classify_iforest, score_iforest, train_iforest

BASELINE = build_baseline(days=30, seed=42)
MODEL = train_iforest(BASELINE, seed=42)


def test_train_returns_fitted_model():
    assert MODEL is not None
    assert hasattr(MODEL, "predict")
    assert hasattr(MODEL, "score_samples")


def test_normal_transaction_classified_as_inlier():
    tx = {"value": 45.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()}
    label = classify_iforest(MODEL, tx, BASELINE)
    assert label == "NORMAL", f"Expected NORMAL for 45 ETH known dest, got {label}"


def test_ronin_scale_transaction_classified_as_outlier():
    tx = {
        "value": 173600.0,
        "destination": "0xdeadbeef" + "0" * 32,
        "timestamp": pd.Timestamp.now(),
    }
    label = classify_iforest(MODEL, tx, BASELINE)
    assert label == "ANOMALY", f"Expected ANOMALY for 173,600 ETH novel dest, got {label}"


def test_score_iforest_ronin_more_anomalous_than_normal():
    normal = {"value": 45.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()}
    ronin = {
        "value": 173600.0,
        "destination": "0xdeadbeef" + "0" * 32,
        "timestamp": pd.Timestamp.now(),
    }
    s_normal = score_iforest(MODEL, normal, BASELINE)
    s_ronin = score_iforest(MODEL, ronin, BASELINE)
    # Lower score_samples = more anomalous
    assert s_ronin < s_normal, f"Expected Ronin score < normal score, got {s_ronin} vs {s_normal}"
