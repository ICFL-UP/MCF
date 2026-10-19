import numpy as np
import pandas as pd
import pytest

from monitor.xchainwatcher_rules import RuleAudit, XChainWatcherRules


def _frame():
    return pd.DataFrame({
        "value": [10.0, 20.0, 30.0, 40.0],
        "matched": [True, False, True, True],
        "finality_gap_s": [120.0, np.nan, -5.0, 60.0],
    })


def test_unmatched_withdrawal_is_flagged_highest():
    scores, flags = XChainWatcherRules().score_frame(_frame())
    assert scores.tolist() == [0.0, 1.0, 0.5, 0.0]
    assert flags.tolist() == [False, True, True, False]


def test_audit_counts():
    audit = XChainWatcherRules().audit(_frame())
    assert audit == RuleAudit(n_unmatched=1, n_finality_violation=1, n_clean=2)


def test_missing_linkage_columns_raise_actionable_error():
    with pytest.raises(KeyError, match="make data"):
        XChainWatcherRules().score_frame(pd.DataFrame({"value": [1.0]}))
