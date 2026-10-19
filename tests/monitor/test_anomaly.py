import pytest
import pandas as pd
from monitor.baseline import build_baseline
from monitor.anomaly import compute_score, classify, ALERT_THRESHOLD, CRITICAL_THRESHOLD

BASELINE = build_baseline(days=30, seed=42)

def test_normal_transaction_score_below_alert():
    tx = {"value": 45.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()}
    score = compute_score(tx, BASELINE)
    assert score < ALERT_THRESHOLD, f"Expected score < {ALERT_THRESHOLD}, got {score}"

def test_ronin_scale_transaction_score_critical():
    tx = {"value": 173600.0, "destination": "0xdeadbeef" + "0" * 32, "timestamp": pd.Timestamp.now()}
    score = compute_score(tx, BASELINE)
    assert score >= CRITICAL_THRESHOLD, f"Expected score >= {CRITICAL_THRESHOLD}, got {score}"

def test_classify_normal():
    assert classify(1.0) == "NORMAL"

def test_classify_alert():
    assert classify(3.5) == "ALERT"

def test_classify_critical():
    assert classify(7.0) == "CRITICAL"


def test_volume_window_elevates_score():
    """Passing a window of prior txs in the same hour must lift vol_z above the
    single-tx baseline (B1-a). Confirms the 0.3 vol_z weight contributes
    discriminating signal in batch mode."""
    tx = {"value": 50.0, "destination": "0x" + "0" * 40, "timestamp": pd.Timestamp.now()}
    score_single = compute_score(tx, BASELINE)
    # Synthesise a window of 30 prior txs in the same hour
    window = pd.DataFrame(
        {
            "value": [50.0] * 30,
            "destination": ["0x" + "0" * 40] * 30,
            "timestamp": [pd.Timestamp.now()] * 30,
        }
    )
    score_with_window = compute_score(tx, BASELINE, window=window)
    assert score_with_window > score_single, (
        f"Windowed score {score_with_window:.3f} should exceed single-tx {score_single:.3f}"
    )
