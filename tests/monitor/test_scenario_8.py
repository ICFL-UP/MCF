"""Tests for the Phase-22 B1 benign-utility harness (scenario_8).

Three layers:

  (1) SIMULATOR CORE vs contract semantics: the TokenBucketSim and
      BucketedBreakerSim models are pinned to known behaviours of
      contracts/RateLimiter.sol and contracts/CircuitBreaker.sol (start-full bucket,
      refill clamp, atomic-revert consume; 61-slot bucketed window with the
      one-bucket-width over-approximation at the window edge, fresh-breach latch
      that does NOT record, latch-until-reset, reset clears latch AND window).
  (2) REPLAY SEMANTICS: denial of > B transfers, FIFO refill delay arithmetic,
      benign-halt latching + reset-delay wait, bucket debit persisting on a
      blocked (breached) withdrawal (BridgeV2 commit-not-revert order).
  (3) SMOKE: main() end-to-end on a tiny synthetic parquet with EVERY output and
      input path monkeypatched to tmp_path (the A2-clobber lesson: a test must never
      write the committed log/figure artifacts).

All offline, deterministic, fast (no real parquets, no node).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

import scenarios.scenario_8_benign_utility as s8
from scenarios.scenario_8_benign_utility import (
    BucketedBreakerSim,
    LedgerETH,
    LedgerUSD,
    TokenBucketSim,
    replay_benign_stream,
    value_coverage_table,
)


# ---------------------------------------------------------------------------
# (1a) Token bucket vs RateLimiter.sol semantics.
# ---------------------------------------------------------------------------
def test_bucket_starts_full_and_admits_up_to_capacity():
    b = TokenBucketSim(capacity=1000.0, rate=1.0, t0=0.0)
    assert b.available(0.0) == pytest.approx(1000.0)  # constructor: _tokens = _capacity
    assert b.consume(1000.0, 0.0) is True
    assert b.available(0.0) == pytest.approx(0.0)


def test_bucket_refills_at_r_and_clamps_at_capacity():
    b = TokenBucketSim(capacity=1000.0, rate=2.0, t0=0.0)
    assert b.consume(1000.0, 0.0)
    # after 100 s at r=2: 200 tokens; after 10,000 s: clamped at capacity.
    assert b.available(100.0) == pytest.approx(200.0)
    assert b.available(10_000.0) == pytest.approx(1000.0)


def test_bucket_consume_reverts_atomically_when_short():
    """RateLimiter.consume REVERTS when short: no partial debit, no state change."""
    b = TokenBucketSim(capacity=1000.0, rate=1.0, t0=0.0)
    assert b.consume(600.0, 0.0)
    assert b.consume(600.0, 0.0) is False          # only 400 left -> revert
    assert b.available(0.0) == pytest.approx(400.0)  # nothing debited by the failure


# ---------------------------------------------------------------------------
# (1b) 61-slot bucketed breaker vs CircuitBreaker.sol semantics.
# ---------------------------------------------------------------------------
def test_breaker_requires_bucket_divisible_window():
    with pytest.raises(ValueError):
        BucketedBreakerSim(threshold=100.0, window=3601.0)  # constructor require


def test_breaker_records_under_threshold_and_breaches_over():
    cb = BucketedBreakerSim(threshold=100.0, window=3600.0)
    assert cb.check_and_record(60.0, 10.0) == "ok"
    assert cb.window_outflow(10.0) == pytest.approx(60.0)
    # 60 + 50 = 110 > 100 -> FRESH breach: latches, returns breach, does NOT record.
    assert cb.check_and_record(50.0, 20.0) == "breach"
    assert cb.tripped is True
    # already latched -> synchronous block ("breaker: tripped" revert path).
    assert cb.check_and_record(1.0, 30.0) == "tripped"


def test_breach_does_not_record_the_breaching_amount():
    """Contract: on a fresh breach the amount is NOT added to the window (the value
    never moved); after reset the window restarts from zero."""
    cb = BucketedBreakerSim(threshold=100.0, window=3600.0)
    assert cb.check_and_record(60.0, 0.0) == "ok"
    assert cb.check_and_record(50.0, 0.0) == "breach"
    cb.reset()
    assert cb.window_outflow(0.0) == pytest.approx(0.0)  # reset cleared 60 too
    assert cb.check_and_record(100.0, 0.0) == "ok"       # fresh T available


def test_breaker_window_edge_matches_contract_61_slot_over_approximation():
    """Contract vector: WINDOW_BUCKETS=60, bucketWidth=W/60=60 s. A record in epoch 0
    is summed while `oldest = epoch - 60 <= 0`, i.e. up to epoch 60 (t < 3660): the
    61-slot span OVER-approximates the exact window by <= one bucket width. From
    epoch 61 (t >= 3660) the record ages out."""
    cb = BucketedBreakerSim(threshold=1_000.0, window=3600.0)
    assert cb.bucket_width == 60
    assert cb.check_and_record(100.0, 0.0) == "ok"          # epoch 0
    # exactly one window later (t = W = 3600 -> epoch 60): STILL counted.
    assert cb.window_outflow(3600.0) == pytest.approx(100.0)
    assert cb.window_outflow(3659.0) == pytest.approx(100.0)  # last second of epoch 60
    # epoch 61 (t = 3660): oldest = 1 -> the epoch-0 record has aged out.
    assert cb.window_outflow(3660.0) == pytest.approx(0.0)


def test_breaker_slot_reclaim_on_epoch_wraparound():
    """Contract vector: epoch e and epoch e+61 share slot e % 61; recording in the
    later epoch lazily zeroes the stale slot (no ghost accumulation)."""
    cb = BucketedBreakerSim(threshold=10_000.0, window=3600.0)
    assert cb.check_and_record(100.0, 0.0) == "ok"            # epoch 0, slot 0
    t_wrap = 61 * 60.0                                        # epoch 61, slot 61%61 = 0
    assert cb.check_and_record(7.0, t_wrap) == "ok"
    # slot 0 must now hold ONLY the new 7.0 (stale 100 reclaimed), and epoch 0 is
    # outside the summed span anyway.
    assert cb.window_outflow(t_wrap) == pytest.approx(7.0)


def test_breaker_latch_persists_until_reset_then_full_clear():
    cb = BucketedBreakerSim(threshold=100.0, window=3600.0)
    assert cb.check_and_record(101.0, 0.0) == "breach"
    assert cb.tripped
    assert cb.check_and_record(0.5, 10_000.0) == "tripped"  # latch never self-clears
    cb.reset()
    assert not cb.tripped
    assert cb.window_outflow(10_000.0) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# (2) Replay semantics.
# ---------------------------------------------------------------------------
LEDGER = LedgerUSD(name="test", B=1000.0, r=1.0, T=5000.0, W=3600.0)


def test_replay_denies_transfers_larger_than_B_without_state_change():
    arrivals = np.array([0, 10], dtype=np.int64)
    amounts = np.array([1500.0, 1000.0])  # first > B -> denied; second unaffected
    res = replay_benign_stream(arrivals, amounts, LEDGER)
    assert len(res.denied) == 1
    assert res.denied[0].deny_reason == "exceeds_bucket_capacity_B"
    assert res.halts == 0                       # limiter revert never latches anything
    second = res.outcomes[1]
    assert second.served and second.delay == 0  # full bucket still available


def test_replay_refill_delay_arithmetic():
    """After a full-B transfer empties the bucket, an immediate follower of size a
    waits exactly ceil(a / r) seconds for refill (FIFO, shared bucket)."""
    arrivals = np.array([0, 0], dtype=np.int64)
    amounts = np.array([1000.0, 250.0])
    res = replay_benign_stream(arrivals, amounts, LEDGER)
    first, second = res.outcomes
    assert first.served and first.delay == 0
    assert second.served
    assert second.delay == pytest.approx(250.0)  # (250 - 0) / r=1, ceil -> 250 s


def test_replay_fifo_delay_propagates():
    """A third transfer arriving during the second's refill wait queues behind it."""
    arrivals = np.array([0, 0, 100], dtype=np.int64)
    amounts = np.array([1000.0, 250.0, 100.0])
    res = replay_benign_stream(arrivals, amounts, LEDGER)
    third = res.outcomes[2]
    # second served at t=250 leaving 0 tokens; third needs 100 -> served t=350.
    assert third.served
    assert third.delay == pytest.approx(250.0)  # 350 - arrival 100


def test_replay_benign_breach_halts_and_waits_for_reset():
    """Cumulative benign traffic crossing T latches the breaker: one halt, and the
    breaching transfer waits for the governance reset (RESET_DELAY) then serves."""
    ledger = LedgerUSD(name="tight", B=1000.0, r=10.0, T=1500.0, W=3600.0)
    arrivals = np.array([0, 200, 400], dtype=np.int64)
    amounts = np.array([900.0, 700.0, 100.0])  # 900+700 = 1600 > T=1500 -> breach
    res = replay_benign_stream(arrivals, amounts, ledger, reset_delay=3600.0)
    assert res.halts == 1
    second = res.outcomes[1]
    assert second.served
    # breach at t=200; reset at 200+3600; window cleared -> served at reset.
    assert second.delay == pytest.approx(3600.0)
    third = res.outcomes[2]
    assert third.served and third.delay >= 3000.0  # blocked behind the latch


def test_replay_bucket_debited_on_blocked_breach():
    """BridgeV2 commit-not-revert: the breaching (blocked) withdrawal still burns
    bucket tokens; the retry after reset needs a REFILLED bucket, so its service
    time reflects both the reset wait and the re-consume."""
    ledger = LedgerUSD(name="debit", B=1000.0, r=1.0, T=1500.0, W=3600.0)
    arrivals = np.array([0, 0], dtype=np.int64)
    amounts = np.array([900.0, 700.0])
    res = replay_benign_stream(arrivals, amounts, ledger, reset_delay=100.0)
    assert res.halts == 1
    second = res.outcomes[1]
    assert second.served
    # Timeline: t=0 first serves (bucket 1000->100), window=900. Second waits
    # (700-100)/r = 600 s, consumes at t=600 (DEBIT: bucket -> 0), breaches
    # (900+700 = 1600 > 1500) -> halt latches; reset at 700 clears the window.
    # The burned tokens STAND: at t=700 only 100 have refilled, so it waits 600
    # more and serves at t=1300. (Without the faithful debit it would have served
    # at t=700 with the pre-breach tokens rolled back: delay 700, not 1300.)
    assert second.delay == pytest.approx(1_300.0)


def test_replay_accounting_identity():
    """Every input transfer is exactly one outcome (served XOR denied)."""
    rng = np.random.default_rng(7)  # fixed seed: deterministic test stream
    n = 500
    arrivals = np.sort(rng.integers(0, 100_000, size=n)).astype(np.int64)
    amounts = rng.lognormal(mean=4.0, sigma=2.0, size=n)
    res = replay_benign_stream(arrivals, amounts, LEDGER)
    assert len(res.outcomes) == n
    assert len(res.denied) + sum(1 for o in res.outcomes if o.served) == n
    assert res.total_value == pytest.approx(amounts.sum())


def test_value_coverage_table_monotone_and_correct():
    amounts = np.array([1.0, 1.0, 1.0, 1.0, 96.0])  # whale carries 96% of value
    table = value_coverage_table(amounts, coverages=(0.5, 0.9, 0.99))
    bs = [b for (_, b) in table]
    assert bs == sorted(bs)
    # any coverage above 4% requires admitting the whale.
    assert all(b == pytest.approx(96.0) for (c, b) in table if c > 0.04)


# ---------------------------------------------------------------------------
# (3) Smoke test: EVERY input/output path monkeypatched (A2-clobber lesson).
# ---------------------------------------------------------------------------
def _tiny_parquet(path, n, t0, label="benign", seed=0):
    rng = np.random.default_rng(seed)
    ts = pd.to_datetime(t0, utc=True) + pd.to_timedelta(
        np.sort(rng.integers(0, 30 * 86400, size=n)), unit="s")
    df = pd.DataFrame({
        "timestamp": ts.astype("datetime64[ms, UTC]"),
        "value_usd": rng.lognormal(mean=6.0, sigma=2.5, size=n),
        "label": [label] * n,
    })
    df.to_parquet(path)
    return df


def test_main_smoke_all_paths_redirected(tmp_path, monkeypatch):
    """main() end-to-end on a tiny synthetic stream. ALL paths (parquets in, log +
    figure out) are monkeypatched to tmp_path so the committed artifacts
    (docs/logs/scenario_8_benign_utility.log, figures/benign_utility_pareto.png)
    are NEVER touched by the test suite."""
    train = tmp_path / "train.parquet"
    test = tmp_path / "test.parquet"
    _tiny_parquet(train, n=300, t0="2022-01-01", seed=1)
    _tiny_parquet(test, n=100, t0="2022-02-15", seed=2)

    log = tmp_path / "s8.log"
    fig = tmp_path / "s8.png"
    monkeypatch.setattr(s8, "TRAIN_PARQUET", train)
    monkeypatch.setattr(s8, "TEST_PARQUET", test)
    monkeypatch.setattr(s8, "LOG_PATH", log)
    monkeypatch.setattr(s8, "FIG_PATH", fig)
    # Shrink the sweep so the smoke test stays fast.
    monkeypatch.setattr(s8, "sweep_grid", lambda: [
        LedgerETH("B1000_r1_T5000", B=1000.0, r=1.0, T=5000.0),
        LedgerETH("B5000_r10_T20000", B=5000.0, r=10.0, T=20_000.0),
    ])

    assert s8.main() == 0
    assert log.exists() and fig.exists()
    text = log.read_text()
    assert "denomination" in text                 # the stated conversion assumption
    assert "Pareto sweep" in text
    assert "parameter-scaling rule" in text
    assert "benign-triggered breaker halts" in text


def test_main_smoke_is_deterministic(tmp_path, monkeypatch):
    """Two runs over the same inputs produce byte-identical logs (no wall-clock, no
    unseeded randomness anywhere in the harness)."""
    train = tmp_path / "train.parquet"
    test = tmp_path / "test.parquet"
    _tiny_parquet(train, n=200, t0="2022-01-01", seed=3)
    _tiny_parquet(test, n=50, t0="2022-02-15", seed=4)
    monkeypatch.setattr(s8, "TRAIN_PARQUET", train)
    monkeypatch.setattr(s8, "TEST_PARQUET", test)
    monkeypatch.setattr(s8, "FIG_PATH", tmp_path / "s8.png")
    monkeypatch.setattr(s8, "sweep_grid", lambda: [
        LedgerETH("B1000_r1_T5000", B=1000.0, r=1.0, T=5000.0),
    ])
    logs = []
    for name in ("a.log", "b.log"):
        monkeypatch.setattr(s8, "LOG_PATH", tmp_path / name)
        assert s8.main() == 0
        logs.append((tmp_path / name).read_text())
    assert logs[0] == logs[1]
