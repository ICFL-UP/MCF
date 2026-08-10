"""
Real-time bridge monitoring runtime.

`MonitoringService` connects to a running EVM node, watches `WithdrawalRequested`
events emitted by `MockBridge`, scores each withdrawal against a 30-day rolling
baseline, and (on a CRITICAL classification) calls `MockBridge.pause()` from a
configured monitor account. This is the off-chain half of the Detect gate from
§11.2.4 of the dissertation.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import pandas as pd
from web3 import Web3
from web3.contract import Contract

from monitor.anomaly import classify, compute_score
from monitor.baseline import build_baseline
from monitor.sequential_detector import SequentialChangePointDetector


@dataclass
class ProcessedEvent:
    tx_hash: str
    to: str
    value_eth: float
    score: float
    level: str
    block_emitted: int
    wall_clock_ms: float
    paused_block: int | None = None
    # BOLT Phase 12: sequential change-point detector outputs. Optional with
    # safe defaults so existing construction sites keep working unchanged.
    detector_stat: float = 0.0
    detector_tripped: bool = False


@dataclass
class MonitoringService:
    """Off-chain Detect-gate runtime.

    Parameters
    ----------
    w3 : Web3
        Connected Web3 client.
    bridge : Contract
        Deployed `MockBridge` contract object (with ABI).
    monitor_account : Any
        Account / address authorised to call `bridge.pause()`. Must match the
        `monitor` address set in the bridge constructor.
    baseline : pd.DataFrame
        30-day baseline used for scoring. Defaults to `build_baseline()`.
    on_event : Callable[[ProcessedEvent], None] | None
        Optional hook invoked after each processed event (used by tests / scenarios
        for assertion). The default writes a JSON line to stdout.
    """

    w3: Web3
    bridge: Contract
    monitor_account: Any
    baseline: pd.DataFrame = field(default_factory=build_baseline)
    on_event: Callable[[ProcessedEvent], None] | None = None
    detector: SequentialChangePointDetector | None = None
    _seen: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # BOLT Phase 12: a per-counterparty sequential change-point detector runs
        # alongside the composite z-score to catch low-and-slow / structuring
        # attacks the value-dominated score misses (gap G2). Calibrated to the
        # same baseline used for scoring.
        if self.detector is None:
            self.detector = SequentialChangePointDetector.from_baseline(self.baseline)

    def _log(self, event: ProcessedEvent) -> None:
        if self.on_event is not None:
            self.on_event(event)
            return
        print(
            json.dumps(
                {
                    "tx_hash": event.tx_hash,
                    "to": event.to,
                    "value_eth": event.value_eth,
                    "score": round(event.score, 3),
                    "level": event.level,
                    "block_emitted": event.block_emitted,
                    "wall_clock_ms": round(event.wall_clock_ms, 3),
                    "paused_block": event.paused_block,
                    "detector_stat": round(event.detector_stat, 3),
                    "detector_tripped": event.detector_tripped,
                }
            ),
            flush=True,
        )

    def process_event(self, event_log: Any) -> ProcessedEvent:
        """Score one `WithdrawalRequested` event log; pause bridge if CRITICAL.

        Returns a `ProcessedEvent`. Idempotent on repeated calls with the same
        `txHash`: subsequent calls return the cached score and do not re-pause.
        """
        args = event_log["args"]
        to = args["to"]
        value_wei = args["value"]
        tx_hash_bytes = args["txHash"]
        tx_hash = tx_hash_bytes.hex() if hasattr(tx_hash_bytes, "hex") else str(tx_hash_bytes)
        block_emitted = event_log.get("blockNumber", 0)
        value_eth = float(self.w3.from_wei(value_wei, "ether"))

        if tx_hash in self._seen:
            return ProcessedEvent(
                tx_hash=tx_hash,
                to=to,
                value_eth=value_eth,
                score=0.0,
                level="DUPLICATE",
                block_emitted=block_emitted,
                wall_clock_ms=0.0,
            )
        self._seen.add(tx_hash)

        t_start = time.perf_counter()
        tx = {
            "value": value_eth,
            "destination": to.lower(),
            "timestamp": pd.Timestamp.now(),
        }
        # One-shot scoring: no `window` is passed, so the volume term is the
        # constant handicap documented in monitor/anomaly.py (vol_z = -2.5424,
        # a fixed -0.7627 on every score at DEFAULT_WEIGHTS) rather than a volume
        # signal. Effective crossings on the calibrated seed-42 baseline:
        # ALERT at 654.95 ETH (known destination) / 622.46 ETH (novel),
        # CRITICAL at 1,142.35 ETH / 1,109.86 ETH.
        score = compute_score(tx, self.baseline)
        level = classify(score)

        # BOLT Phase 12: feed the withdrawal to the per-counterparty sequential
        # change-point detector (counterparty = recipient, value = ETH, t in
        # seconds). A trip is treated as a circuit-breaker trip (same pause path
        # as a CRITICAL classification), so a structuring drip that never reaches
        # the CRITICAL z-score still pauses the bridge.
        assert self.detector is not None  # set in __post_init__
        detector_stat, detector_tripped = self.detector.update(
            counterparty=to.lower(),
            value=value_eth,
            t=time.time(),
        )

        wall_clock_ms = (time.perf_counter() - t_start) * 1000.0

        paused_block: int | None = None
        if level == "CRITICAL" or detector_tripped:
            paused_block = self._pause_bridge()

        result = ProcessedEvent(
            tx_hash=tx_hash,
            to=to,
            value_eth=value_eth,
            score=score,
            level=level,
            block_emitted=block_emitted,
            wall_clock_ms=wall_clock_ms,
            paused_block=paused_block,
            detector_stat=detector_stat,
            detector_tripped=detector_tripped,
        )
        self._log(result)
        return result

    def _pause_bridge(self) -> int:
        """Send `bridge.pause()` from the monitor account; return the block in which it mined."""
        if self.bridge.functions.paused().call():
            return self.w3.eth.block_number
        from_addr = (
            self.monitor_account.address
            if hasattr(self.monitor_account, "address")
            else self.monitor_account
        )
        tx_hash = self.bridge.functions.pause().transact({"from": from_addr})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt["blockNumber"]

    def poll(self, timeout_seconds: float = 5.0, poll_interval: float = 0.05) -> list[ProcessedEvent]:
        """Poll for new `WithdrawalRequested` events for up to `timeout_seconds`.

        Returns the list of processed events. Stops early once any event is
        classified CRITICAL (the pause has already been broadcast and there is
        nothing useful to keep doing).
        """
        event_filter = self.bridge.events.WithdrawalRequested.create_filter(
            from_block="latest"
        )
        deadline = time.perf_counter() + timeout_seconds
        seen: list[ProcessedEvent] = []
        while time.perf_counter() < deadline:
            for log in event_filter.get_new_entries():
                processed = self.process_event(log)
                seen.append(processed)
                if processed.level == "CRITICAL" or processed.detector_tripped:
                    return seen
            time.sleep(poll_interval)
        return seen


# Backwards-compatible thin facade for the previous test surface.
def evaluate(tx: dict, baseline: pd.DataFrame | None = None) -> dict:
    """Score a single transaction without a live bridge connection.

    Useful for unit tests and ad-hoc scoring; the production runtime is
    `MonitoringService.process_event`.
    """
    if baseline is None:
        baseline = build_baseline()
    # One-shot scoring, as in `process_event`: the volume term is the constant
    # -0.7627 handicap documented in monitor/anomaly.py, so ALERT is first crossed
    # at 654.95 ETH (known destination) / 622.46 ETH (novel) on the seed-42 baseline.
    score = compute_score(tx, baseline)
    return {"score": round(score, 3), "level": classify(score), "tx": tx}
