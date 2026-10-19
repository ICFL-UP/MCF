"""Integration tests for the BOLT Phase 12 detector wiring in MonitoringService.

The detector is unit-tested in isolation in ``test_sequential_detector.py``; these
tests exercise the *wiring* the gate review flagged as untested: a structuring drip
fed through ``MonitoringService.process_event`` must take the SAME pause path as a
CRITICAL classification (``detector_tripped -> _pause_bridge``), a benign one-off
stream must NOT pause, the new ``ProcessedEvent`` fields must flow through, and the
default JSON log must emit them. Uses light fakes for ``w3``/``bridge`` so no live
node is required.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest

from monitor.generator import generate
from monitor.service import MonitoringService, ProcessedEvent


# --------------------------------------------------------------------------- fakes
class _FakeEth:
    def __init__(self) -> None:
        self.block_number = 1

    def wait_for_transaction_receipt(self, _tx_hash):
        # Each pause mines a block.
        self.block_number += 1
        return {"blockNumber": self.block_number}


class _FakeW3:
    def __init__(self) -> None:
        self.eth = _FakeEth()

    @staticmethod
    def from_wei(value_wei: int, unit: str) -> float:
        assert unit == "ether"
        return value_wei / 1e18


class _PauseFn:
    def __init__(self, bridge: "_FakeBridge") -> None:
        self._bridge = bridge

    def transact(self, _opts):
        self._bridge.paused_flag = True
        self._bridge.pause_calls += 1
        return b"\xde\xad\xbe\xef"


class _PausedFn:
    def __init__(self, bridge: "_FakeBridge") -> None:
        self._bridge = bridge

    def call(self) -> bool:
        return self._bridge.paused_flag


class _Functions:
    def __init__(self, bridge: "_FakeBridge") -> None:
        self._bridge = bridge

    def paused(self) -> _PausedFn:
        return _PausedFn(self._bridge)

    def pause(self) -> _PauseFn:
        return _PauseFn(self._bridge)


class _FakeBridge:
    def __init__(self) -> None:
        self.paused_flag = False
        self.pause_calls = 0
        self.functions = _Functions(self)


# --------------------------------------------------------------------------- helpers
def _baseline() -> pd.DataFrame:
    # Calibrated benign baseline (same generator the detector calibrates against).
    return generate(seed=42, n=3000)


def _event(to: str, value_eth: float, idx: int) -> dict:
    return {
        "args": {
            "to": to,
            "value": int(value_eth * 1e18),
            "txHash": bytes([idx & 0xFF, (idx >> 8) & 0xFF, 0xAB, 0xCD]),
        },
        "blockNumber": 100 + idx,
    }


def _service(baseline: pd.DataFrame) -> MonitoringService:
    return MonitoringService(
        w3=_FakeW3(),
        bridge=_FakeBridge(),
        monitor_account="0xmonitor",
        baseline=baseline,
        on_event=lambda e: None,  # silence default stdout logging
    )


# ----------------------------------------------------------------------------- tests
def test_structuring_drip_trips_detector_and_pauses_bridge():
    """Many same-counterparty sub-threshold withdrawals -> detector trip -> pause,
    even though no single event reaches the CRITICAL z-score."""
    baseline = _baseline()
    svc = _service(baseline)
    mean = baseline["value"].mean()
    std = baseline["value"].std()
    drip = float(mean + 1.5 * std)  # ~1.5σ: structuring, not a CRITICAL outlier

    attacker = "0xAttackerCounterparty00000000000000000001"
    tripped_event = None
    for i in range(40):
        ev = svc.process_event(_event(attacker, drip, i))
        # None of these should be CRITICAL on the z-score alone.
        assert ev.level != "CRITICAL"
        if ev.detector_tripped:
            tripped_event = ev
            break

    assert tripped_event is not None, "structuring drip never tripped the detector"
    assert tripped_event.detector_tripped is True
    assert tripped_event.detector_stat > 0.0
    # Same pause path as CRITICAL: bridge.pause() was called and a block recorded.
    assert tripped_event.paused_block is not None
    assert svc.bridge.pause_calls == 1
    assert svc.bridge.paused_flag is True


def test_benign_oneoff_stream_does_not_pause():
    """Distinct one-off counterparties at benign values never accumulate -> no trip,
    no pause."""
    baseline = _baseline()
    svc = _service(baseline)
    mean = float(baseline["value"].mean())

    for i in range(50):
        to = f"0xBenign{i:034d}"
        ev = svc.process_event(_event(to, mean, i))
        assert ev.detector_tripped is False
        assert ev.paused_block is None

    assert svc.bridge.pause_calls == 0
    assert svc.bridge.paused_flag is False


def test_ronin_outlier_pauses_via_critical_or_detector():
    """The single 173,600 ETH withdrawal must pause the bridge (fast path)."""
    baseline = _baseline()
    svc = _service(baseline)
    ev = svc.process_event(_event("0xRoninDrain0000000000000000000000000001", 173_600.0, 1))
    assert ev.paused_block is not None
    assert svc.bridge.pause_calls == 1
    # Fast path: the detector flags the single extreme value_z.
    assert ev.detector_tripped is True


def test_processed_event_fields_backward_compatible():
    """ProcessedEvent constructs without the Phase 12 fields (safe defaults)."""
    ev = ProcessedEvent(
        tx_hash="0x1",
        to="0xabc",
        value_eth=1.0,
        score=0.0,
        level="NORMAL",
        block_emitted=1,
        wall_clock_ms=0.0,
    )
    assert ev.detector_stat == 0.0
    assert ev.detector_tripped is False


def test_default_json_log_emits_detector_fields(capsys):
    """The default structured log includes detector_stat / detector_tripped."""
    baseline = _baseline()
    svc = MonitoringService(
        w3=_FakeW3(),
        bridge=_FakeBridge(),
        monitor_account="0xmonitor",
        baseline=baseline,
        on_event=None,  # exercise the real JSON logger
    )
    svc.process_event(_event("0xLogTarget000000000000000000000000000001", float(baseline["value"].mean()), 1))
    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert "detector_stat" in payload
    assert "detector_tripped" in payload
