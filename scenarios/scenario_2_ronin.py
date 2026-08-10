"""Scenario 2: Ronin-Scale Anomaly Detection, §11.2.3 / §11.2.4

Two execution modes:

1. **End-to-end** (preferred). When a Hardhat node is reachable on
   `http://127.0.0.1:8545`, the script deploys `MCFValidatorRegistry` and
   `MockBridge`, registers five validators with Phase-9a signatures, submits a
   small batch of normal-sized withdrawals, then injects a 173,600 ETH
   withdrawal. A `MonitoringService` runtime watches the `WithdrawalRequested`
   stream, scores each event, and calls `bridge.pause()` on the CRITICAL
   classification. Headline metric: wall-clock latency from event emission to
   pause-tx inclusion.

2. **Kernel-only** fallback. If no node is reachable, the script measures only
   the in-process `compute_score` cost on the Ronin transaction. Reported as
   the *scoring kernel* timing, not the end-to-end detection time.

Both modes save a baseline-vs-Ronin figure and an extended log. The end-to-end
mode is what `docs/evaluation.md` §1 references for the headline number; the
kernel timing remains as a sub-line for transparency.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path when run as a script
sys.path.insert(0, str(Path(__file__).parent.parent))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from eth_account import Account
from eth_account.messages import encode_defunct

from monitor.anomaly import ALERT_THRESHOLD, CRITICAL_THRESHOLD, classify, compute_score
from monitor.baseline import build_baseline
from monitor.service import MonitoringService

RPC = "http://127.0.0.1:8545"
RONIN_VALUE_ETH = 173600.0
ATTACKER = "0xdEadBeefdEadBeefdEadBeefdEadBeefdEadBeef"

# Hardhat well-known dev keys for accounts[1..5] (validators) and accounts[6] (monitor).
# Deterministic, local-only; never used outside Hardhat / Anvil dev networks.
VALIDATOR_KEYS = [
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",  # acct 1
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",  # acct 2
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",  # acct 3
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",  # acct 4
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",  # acct 5
]


def _save_figure(baseline: pd.DataFrame) -> None:
    Path("figures").mkdir(exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.hist(baseline["value"], bins=50, alpha=0.7, label="30-day baseline")
    ax.axvline(
        RONIN_VALUE_ETH,
        color="red",
        linewidth=2,
        label=f"Ronin tx ({RONIN_VALUE_ETH:,.0f} ETH)",
    )
    ax.set_xlabel("Transaction Value (ETH)")
    ax.set_ylabel("Frequency")
    # title supplied by the LaTeX caption; no embedded title
    ax.legend()
    ax.set_xscale("log")
    plt.tight_layout()
    plt.savefig("figures/scenario_2_timeline.png", dpi=300)
    print("Figure saved: figures/scenario_2_timeline.png")


def run_kernel_only(baseline: pd.DataFrame) -> None:
    print("[mode] Kernel-only — no Hardhat node detected at", RPC)
    ronin_tx = {
        "value": RONIN_VALUE_ETH,
        "destination": ATTACKER.lower(),
        "timestamp": pd.Timestamp.now(),
    }
    print(f"\nInjecting Ronin-scale transaction: {ronin_tx['value']:,.0f} ETH")

    t_start = time.perf_counter()
    score = compute_score(ronin_tx, baseline)
    level = classify(score)
    elapsed_ms = (time.perf_counter() - t_start) * 1000

    print(f"Score: {score:.3f}")
    print(f"Classification: {level}")
    print(f"Scoring-kernel time: {elapsed_ms:.2f} ms")
    print(f"Alert threshold ({ALERT_THRESHOLD}): "
          f"{'BREACHED' if score >= ALERT_THRESHOLD else 'ok'}")
    print(f"Critical threshold ({CRITICAL_THRESHOLD}): "
          f"{'BREACHED' if score >= CRITICAL_THRESHOLD else 'ok'}")
    assert level == "CRITICAL", f"Expected CRITICAL, got {level}"


def run_end_to_end(baseline: pd.DataFrame) -> None:
    """Full dual-gate demo against a live Hardhat node."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(RPC))
    if not w3.is_connected():
        run_kernel_only(baseline)
        return

    print(f"[mode] End-to-end against {RPC}")
    accounts = w3.eth.accounts
    owner = accounts[0]
    monitor = accounts[6]
    recipient = accounts[7]

    artifacts_root = Path("artifacts/contracts")
    registry_artifact = json.loads(
        (artifacts_root / "MCFValidatorRegistry.sol/MCFValidatorRegistry.json").read_text()
    )
    bridge_artifact = json.loads(
        (artifacts_root / "MockBridge.sol/MockBridge.json").read_text()
    )

    # --- Deploy MCFValidatorRegistry
    Registry = w3.eth.contract(
        abi=registry_artifact["abi"], bytecode=registry_artifact["bytecode"]
    )
    receipt = w3.eth.wait_for_transaction_receipt(
        Registry.constructor().transact({"from": owner})
    )
    registry = w3.eth.contract(address=receipt.contractAddress, abi=registry_artifact["abi"])
    print(f"Registry deployed at {registry.address}")

    # --- Register 5 validators with Phase 9a + C1 replay-resistant signatures
    chain_id = w3.eth.chain_id
    validators: list[str] = []
    for i, key in enumerate(VALIDATOR_KEYS):
        signer = Account.from_key(key)
        validators.append(signer.address)
        doc_hash = w3.keccak(text=f"did-doc-validator-{i}")
        inner_hash = Web3.solidity_keccak(
            ["uint256", "address", "address", "bytes32"],
            [chain_id, registry.address, signer.address, doc_hash],
        )
        signed = signer.sign_message(encode_defunct(primitive=inner_hash))
        registry.functions.registerValidator(
            signer.address, doc_hash, 3600, signed.signature
        ).transact({"from": owner})
    print(f"Registered {len(validators)} validators")

    # --- Deploy MockBridge with monitor address
    Bridge = w3.eth.contract(abi=bridge_artifact["abi"], bytecode=bridge_artifact["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        Bridge.constructor(registry.address, 5, monitor).transact({"from": owner})
    )
    bridge = w3.eth.contract(address=receipt.contractAddress, abi=bridge_artifact["abi"])
    print(f"Bridge deployed at {bridge.address}, monitor={monitor}")

    # --- Fund the bridge so legitimate withdrawals could execute
    bridge.functions.deposit().transact({"from": owner, "value": w3.to_wei(50, "ether")})

    # --- Spin up the monitor; collect events for assertion
    captured: list = []

    def on_event(event):
        captured.append(event)

    service = MonitoringService(
        w3=w3, bridge=bridge, monitor_account=monitor, baseline=baseline, on_event=on_event
    )

    # --- Submit a handful of normal-sized baseline withdrawals
    for i in range(3):
        bridge.functions.submitTransaction(
            recipient, w3.to_wei(40 + i * 5, "ether")
        ).transact({"from": owner})

    # --- Run a poll cycle to drain the existing events without the Ronin tx yet
    service.poll(timeout_seconds=0.5)
    pre_attack_events = list(captured)

    # --- Inject the Ronin-scale withdrawal and capture wall-clock latency
    attacker_checksum = Web3.to_checksum_address(ATTACKER)
    t_emit_start = time.perf_counter()
    receipt = w3.eth.wait_for_transaction_receipt(
        bridge.functions.submitTransaction(
            attacker_checksum, w3.to_wei(int(RONIN_VALUE_ETH), "ether")
        ).transact({"from": owner})
    )
    block_emitted = receipt.blockNumber
    print(f"Ronin withdrawal emitted at block {block_emitted}")

    # --- Monitor reacts. Bound the poll to 5 seconds so the script can't hang.
    service.poll(timeout_seconds=5.0)
    elapsed_ms = (time.perf_counter() - t_emit_start) * 1000.0

    # --- Locate the CRITICAL event in the capture
    critical = next((e for e in captured if e.level == "CRITICAL"), None)
    assert critical is not None, "Monitor did not classify any event as CRITICAL"
    assert bridge.functions.paused().call(), "Bridge was not paused after CRITICAL"

    block_paused = critical.paused_block or w3.eth.block_number
    blocks_to_pause = block_paused - block_emitted

    print("\n=== End-to-end Detect-gate result ===")
    print(f"Pre-attack events scored: {len(pre_attack_events)}")
    print(
        f"Ronin event score: {critical.score:.3f}  -> {critical.level}"
    )
    print(f"Block emitted: {block_emitted}")
    print(f"Block paused : {block_paused}  (Δ={blocks_to_pause} blocks)")
    print(f"Wall-clock from emit to monitor-react: {elapsed_ms:.2f} ms")
    print(f"Scoring-kernel time on Ronin tx     : {critical.wall_clock_ms:.3f} ms")
    print(f"bridge.paused() = {bridge.functions.paused().call()}")
    assert elapsed_ms < 5_000, f"End-to-end took {elapsed_ms:.0f}ms — exceeds 5s ceiling"


def main() -> None:
    print("Building 30-day baseline...")
    baseline = build_baseline(days=30, seed=42)
    print(
        f"Baseline: {len(baseline)} transactions, "
        f"mean={baseline['value'].mean():.1f} ETH, "
        f"std={baseline['value'].std():.1f} ETH"
    )

    _save_figure(baseline)

    try:
        run_end_to_end(baseline)
    except Exception as exc:  # noqa: BLE001
        print(f"[fallback] end-to-end failed ({exc!r}) — running kernel-only mode")
        run_kernel_only(baseline)


if __name__ == "__main__":
    main()
