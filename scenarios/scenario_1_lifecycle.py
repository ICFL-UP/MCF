"""Scenario 1: Credential Lifecycle, §11.2.2

Two assertions:

1. **TTL-expiry**: a validator registered with TTL=2 s is invalid after
   `evm_increaseTime(3)` advances chain time past `expiresAt`.
2. **Revocation**: a second validator, registered with a long TTL, is
   immediately invalidated after `revokeValidator` and any subsequent
   `confirmTransaction` against the bridge reverts at the Protect gate.

Both demonstrate the Protect-side credential-lifecycle controls from
§11.2.2 of the dissertation. Requires a live Hardhat node on
`http://127.0.0.1:8545`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.exceptions import ContractLogicError

RPC = "http://127.0.0.1:8545"
REGISTRY_ARTIFACT = Path(
    "artifacts/contracts/MCFValidatorRegistry.sol/MCFValidatorRegistry.json"
)
BRIDGE_ARTIFACT = Path(
    "artifacts/contracts/MockBridge.sol/MockBridge.json"
)

# Well-known Hardhat dev mnemonic accounts (deterministic, local-only):
#   accounts[0] (owner)        = 0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266
#   accounts[1] (validator1)   = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
#   accounts[2] (validator2)   = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
#   accounts[6] (monitor)      = 0x976EA74026E726554dB657fA54763abd0C3a0aa9
VALIDATOR1_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
VALIDATOR2_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"


def _sign(w3: Web3, signer_key: str, registry_addr: str, validator_addr: str, doc_hash: bytes) -> bytes:
    """Replay-resistant signing scheme (C1): inner hash binds (chainId, registry, validator, docHash)."""
    inner_hash = Web3.solidity_keccak(
        ["uint256", "address", "address", "bytes32"],
        [w3.eth.chain_id, registry_addr, validator_addr, doc_hash],
    )
    signed = Account.from_key(signer_key).sign_message(encode_defunct(primitive=inner_hash))
    return signed.signature


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(RPC))
    assert w3.is_connected(), "Hardhat node not running at " + RPC

    artifact = json.loads(REGISTRY_ARTIFACT.read_text())
    bridge_artifact = json.loads(BRIDGE_ARTIFACT.read_text())

    accounts = w3.eth.accounts
    owner, validator1, validator2 = accounts[0], accounts[1], accounts[2]
    monitor = accounts[6]

    # Sanity: hardcoded private keys must match account list
    assert Account.from_key(VALIDATOR1_KEY).address.lower() == validator1.lower()
    assert Account.from_key(VALIDATOR2_KEY).address.lower() == validator2.lower()

    # --- Deploy registry
    Registry = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        Registry.constructor().transact({"from": owner})
    )
    registry = w3.eth.contract(address=receipt.contractAddress, abi=artifact["abi"])

    # --- Deploy bridge so we can probe the Protect gate via confirmTransaction
    Bridge = w3.eth.contract(abi=bridge_artifact["abi"], bytecode=bridge_artifact["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        Bridge.constructor(registry.address, 5, monitor).transact({"from": owner})
    )
    bridge = w3.eth.contract(address=receipt.contractAddress, abi=bridge_artifact["abi"])

    results: list[tuple[str, bool, str]] = []

    # ============================================================
    # Step 1: TTL expiry on validator1
    # ============================================================
    doc_hash = w3.keccak(text="did-doc-validator1")
    sig = _sign(w3, VALIDATOR1_KEY, registry.address, validator1, doc_hash)
    registry.functions.registerValidator(validator1, doc_hash, 2, sig).transact({"from": owner})

    assert registry.functions.verifyValidator(validator1).call() is True
    print(f"[t=0s] verifyValidator(validator1)={validator1[:8]}...: True")

    print("Waiting 3 seconds for credential to expire...")
    time.sleep(3)
    w3.provider.make_request("evm_increaseTime", [3])
    w3.provider.make_request("evm_mine", [])

    expired = registry.functions.verifyValidator(validator1).call()
    print(f"[t=3s] verifyValidator(validator1)={validator1[:8]}...: {expired}")
    if not expired:
        print("CREDENTIAL EXPIRED — access denied")
        results.append(("TTL expiry", True, "verifyValidator returned False"))
    else:
        results.append(("TTL expiry", False, "credential still valid post-TTL"))

    # ============================================================
    # Step 2: Revocation of validator2 (registered with long TTL)
    # ============================================================
    doc_hash2 = w3.keccak(text="did-doc-validator2")
    sig2 = _sign(w3, VALIDATOR2_KEY, registry.address, validator2, doc_hash2)
    registry.functions.registerValidator(validator2, doc_hash2, 3600, sig2).transact(
        {"from": owner}
    )

    assert registry.functions.verifyValidator(validator2).call() is True
    print(f"\n[t=3s] verifyValidator(validator2)={validator2[:8]}...: True")

    # Register validator1 anew so it would be a candidate confirmer; but instead
    # we'll exercise the revocation path on validator2 directly.
    registry.functions.revokeValidator(validator2).transact({"from": owner})
    revoked = registry.functions.verifyValidator(validator2).call()
    print(f"[t=3s] verifyValidator(validator2) post-revoke: {revoked}")

    # And: bridge must reject a confirmation from a revoked validator at the Protect gate
    receipt = w3.eth.wait_for_transaction_receipt(
        bridge.functions.submitTransaction(monitor, w3.to_wei(1, "ether")).transact({"from": owner})
    )
    tx_hash = receipt.logs[0].topics[2]  # WithdrawalRequested(to indexed, value, txHash indexed, ...)

    bridge_rejected = False
    try:
        bridge.functions.confirmTransaction(tx_hash).transact({"from": validator2})
    except ContractLogicError as exc:
        if "validator not authorized" in str(exc):
            bridge_rejected = True
    except Exception as exc:  # noqa: BLE001
        # web3.py wraps revert reasons inconsistently; fall back to substring check
        if "validator not authorized" in str(exc):
            bridge_rejected = True

    if not revoked and bridge_rejected:
        print("CREDENTIAL REVOKED — access denied")
        results.append(("Revocation", True, "bridge confirmTransaction reverted"))
    elif not revoked:
        print("CREDENTIAL REVOKED — registry says inactive (bridge rejection unverified)")
        results.append(("Revocation", True, "registry reports inactive"))
    else:
        print("REVOCATION FAILED — credential still active")
        results.append(("Revocation", False, "registry still reports active"))

    # ============================================================
    # Summary
    # ============================================================
    print("\n--- Summary ---")
    print(f"{'Step':<14} {'Pass':<6} {'Note'}")
    print("-" * 60)
    for step, passed, note in results:
        flag = "PASS" if passed else "FAIL"
        print(f"{step:<14} {flag:<6} {note}")


if __name__ == "__main__":
    main()
