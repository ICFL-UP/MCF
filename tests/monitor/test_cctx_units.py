"""Units-normalization lock for the CCTX pipeline (Phase 22, task A1).

The XChainWatcher CCTX ``value`` column is the raw on-chain ``amount`` in token
BASE UNITS with MIXED per-token decimals (18-dec ETH-class next to 6-dec USDC /
8-dec WBTC). A blanket ``/1e18`` therefore shrinks every low-decimal token by
>=1e10, the bug these tests lock out forever:

  * Ronin's 25.5M-USDC leg (raw ``2.55e13``, 6 decimals) became a
    value-invisible ``2.55e-05`` "ETH";
  * ~200-unit stablecoin transfers in the Nomad drain (raw ``2e8``) read as
    ``2e-7`` "ETH"; 88% of the Nomad positives landed below the 1-unit "dust"
    cutoff as pure decimal artifacts.

The fix: ``scripts/fetch_cctx.py`` carries upstream's per-transaction USD
valuation (``value_usd``, the dataset's one common denomination) into the
parquet, and ``scenario_6``'s loader scores on it (keeping the raw amount as
``value_base_units`` for audit). These tests pin:

  (1) the fetch pipeline propagates ``value_usd`` for both benign and attack rows;
  (2) the loader scores the USD column: a USDC-decimals row keeps its true
      magnitude and is NOT classified as dust;
  (3) the loader REFUSES a parquet without ``value_usd`` (no silent fallback to
      the broken base-unit scale);
  (4) the loader's two-way Ronin unit check fires when ``value_usd`` is wrong;
  (5) (if the real parquet is present) the Nomad positives are NOT a dust
      cohort in the common denomination.

Offline, node-less (pure Python/pandas).
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

import scenarios.scenario_6_detection_eval as s6

# Import the fetch pipeline the same way it runs as a script.
import importlib.util

_FETCH_PATH = Path(__file__).resolve().parents[2] / "scripts" / "fetch_cctx.py"
_spec = importlib.util.spec_from_file_location("fetch_cctx", _FETCH_PATH)
fetch_cctx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_cctx)

# The actual Ronin attack rows (upstream attacks.csv, verbatim): the 173,600 ETH
# leg (18 decimals) and the 25.5M USDC leg (6 decimals). Same-file rows whose raw
# base-unit amounts differ by 10 orders of magnitude while their true (USD)
# magnitudes differ by ~20x, the mixed-decimals hazard in two lines.
RONIN_ATTACKS_CSV = """\
dst_chain_id,dst_timestamp,dst_transaction_hash,withdrawal_id,dst_token,beneficiary,amount,value_usd,date
1,1648042149,0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7,2000000,0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2,0x098b716b8aaf21512996dc57eb0615e2383e2f96,173600000000000000000000,539884275.7504,2022-03-23 13:29
1,1648042264,0xed2c72ef1a552ddaec6dd1f5cddf0b59a8f37f82bdda5257d9c7c37db7bb9b08,2000001,0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48,0x098b716b8aaf21512996dc57eb0615e2383e2f96,25500000000000,25492489.0005,2022-03-23 13:31
"""

USDC_LEG_RAW = 25_500_000_000_000.0  # 25.5M USDC in 6-decimal base units
USDC_LEG_USD = 25_492_489.0005


# ---------------------------------------------------------------------------
# (1) fetch pipeline propagates value_usd
# ---------------------------------------------------------------------------
def test_normalise_attacks_carries_value_usd_and_raw_base_units():
    df = fetch_cctx._normalise_attacks(RONIN_ATTACKS_CSV, "ronin")
    assert "value_usd" in fetch_cctx.CANONICAL_COLUMNS
    assert "value_usd" in df.columns
    usdc = df.iloc[1]
    # Raw base units preserved for audit; USD magnitude carried alongside.
    assert usdc["value"] == pytest.approx(USDC_LEG_RAW)
    assert usdc["value_usd"] == pytest.approx(USDC_LEG_USD)
    # The two legs are ~20x apart in USD, NOT ~1e10 apart as base units suggest.
    ratio_usd = df.iloc[0]["value_usd"] / df.iloc[1]["value_usd"]
    assert 10 < ratio_usd < 30


def test_synthetic_fallback_matches_canonical_schema():
    df = fetch_cctx._build_synthetic(n=100)
    for col in fetch_cctx.CANONICAL_COLUMNS:
        assert col in df.columns, f"synthetic fallback missing canonical column {col}"
    # Synthetic values are a single common unit already: identity mapping.
    assert (df["value_usd"] == df["value"]).all()


# ---------------------------------------------------------------------------
# (2)-(4) scenario_6 loader scores the common USD denomination
# ---------------------------------------------------------------------------
def _mini_frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def _write_splits(tmp_path: Path, monkeypatch, train: pd.DataFrame, test: pd.DataFrame):
    train_pq = tmp_path / "train.parquet"
    test_pq = tmp_path / "test.parquet"
    train.to_parquet(train_pq, index=False)
    test.to_parquet(test_pq, index=False)
    monkeypatch.setattr(s6, "TRAIN_PARQUET", train_pq)
    monkeypatch.setattr(s6, "TEST_PARQUET", test_pq)


def _benign_train() -> pd.DataFrame:
    return _mini_frame(
        [
            {"timestamp": "2022-01-01T00:00:00Z", "value": 1e18, "value_usd": 3000.0,
             "source": "1", "destination": "0x" + "b" * 40, "label": "benign",
             "provenance": "XChainWatcher"},
            {"timestamp": "2022-01-01T01:00:00Z", "value": 2e8, "value_usd": 200.0,
             "source": "1", "destination": "0x" + "c" * 40, "label": "benign",
             "provenance": "XChainWatcher"},
        ]
    )


def _real_test_rows() -> pd.DataFrame:
    return _mini_frame(
        [
            # The 173,600 ETH Ronin leg, which anchors the loader's two-way unit check.
            {"timestamp": "2022-03-23T13:29:00Z", "value": 1.736e23,
             "value_usd": 539_884_275.7504, "source": "1",
             "destination": "0x" + "a" * 40, "label": "incident:ronin",
             "provenance": "XChainWatcher"},
            # The 25.5M USDC leg (6 decimals): raw 2.55e13 base units.
            {"timestamp": "2022-03-23T13:31:00Z", "value": USDC_LEG_RAW,
             "value_usd": USDC_LEG_USD, "source": "1",
             "destination": "0x" + "a" * 40, "label": "incident:ronin",
             "provenance": "XChainWatcher"},
            # A ~200-unit stablecoin Nomad-style transfer: raw 2e8 base units.
            {"timestamp": "2022-08-01T21:32:00Z", "value": 2e8, "value_usd": 200.0,
             "source": "1", "destination": "0x" + "d" * 40,
             "label": "incident:nomad", "provenance": "XChainWatcher"},
        ]
    )


def test_loader_scores_usd_and_usdc_row_is_not_dust(tmp_path, monkeypatch):
    """A USDC-decimals row must keep its true magnitude: 25.5M USD scored, not the
    2.55e-05 'ETH' the blanket /1e18 produced. A ~$200 stablecoin transfer must
    likewise NOT land below the dust cutoff as a decimal artifact."""
    _write_splits(tmp_path, monkeypatch, _benign_train(), _real_test_rows())
    splits = s6.load_cctx()

    usdc = splits.test[splits.test["value_base_units"] == USDC_LEG_RAW].iloc[0]
    # Scored value IS the USD valuation (true magnitude), not a /1e18 artifact.
    assert usdc["value"] == pytest.approx(USDC_LEG_USD)
    assert usdc["value"] > s6.DUST_USD  # value-visible, not dust

    stable = splits.test[splits.test["label"] == "incident:nomad"].iloc[0]
    assert stable["value"] == pytest.approx(200.0)
    assert stable["value"] >= s6.DUST_USD, (
        "a ~200-unit 6-decimal stablecoin transfer must not be classified as dust"
    )
    # Raw base units retained for audit.
    assert stable["value_base_units"] == pytest.approx(2e8)
    # All incident rows positive.
    assert splits.y_test.sum() == 3


def test_loader_rejects_parquet_without_value_usd(tmp_path, monkeypatch):
    """No silent fallback to the broken mixed-decimals base-unit scale."""
    train = _benign_train().drop(columns=["value_usd"])
    test = _real_test_rows().drop(columns=["value_usd"])
    _write_splits(tmp_path, monkeypatch, train, test)
    with pytest.raises(ValueError, match="value_usd"):
        s6.load_cctx()


def test_loader_unit_check_fires_on_wrong_ronin_usd(tmp_path, monkeypatch):
    """If the scored Ronin value were the blanket-/1e18 artifact instead of the
    upstream USD valuation, the two-way unit check must fail loudly."""
    test = _real_test_rows()
    # Corrupt the scored column with exactly the old bug's output.
    test["value_usd"] = test["value"] / 1e18
    _write_splits(tmp_path, monkeypatch, _benign_train(), test)
    with pytest.raises(ValueError, match="unit check FAILED"):
        s6.load_cctx()


# ---------------------------------------------------------------------------
# (5) real-artifact regression (skipped when the gitignored parquet is absent)
# NOTE: the sidecar-verification tests for verify_against_committed_sidecars()
# live in tests/data/test_fetch_sidecars.py so that this frozen monitor suite
# stays at its canonical 117-test count.
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (Path("data/cctx/test.parquet").exists()), reason="real CCTX parquet not built"
)
def test_real_nomad_positives_are_not_a_dust_cohort():
    """On the real artifact the Nomad positives are ~$200k-median transfers; the
    old 88%-below-dust reading was a decimal artifact and must never return."""
    test = pd.read_parquet("data/cctx/test.parquet")
    if not (test["provenance"] == "XChainWatcher").all():
        pytest.skip("synthetic fallback parquet — real-data regression not applicable")
    nomad = test[test["label"] == "incident:nomad"]
    assert len(nomad) > 0
    dust_frac = float((nomad["value_usd"] < s6.DUST_USD).mean())
    assert dust_frac < 0.10, (
        f"{dust_frac:.0%} of Nomad positives below the dust cutoff in the common "
        "denomination — the mixed-decimals units bug has regressed"
    )
    assert float(nomad["value_usd"].median()) > 1_000.0
