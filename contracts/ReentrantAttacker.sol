// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IBridgeV2Withdraw {
    function withdraw(
        address payable recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external;
}

/**
 * @title ReentrantAttacker
 * @notice Malicious withdrawal recipient that attempts to re-enter BridgeV2.withdraw on
 *         ETH receipt. Used only by bridgev2.spec.ts to prove the nonReentrant guard +
 *         checks-effects-interactions ordering hold. Test helper, not production code.
 */
contract ReentrantAttacker {
    IBridgeV2Withdraw public immutable bridge;

    // Replay payload captured for the re-entrant attempt.
    uint256 public storedNonce;
    uint256 public storedDeadline;
    bytes[] public storedSigs;
    bool public attacked;

    constructor(address _bridge) {
        bridge = IBridgeV2Withdraw(_bridge);
    }

    function arm(uint256 nonce, uint256 deadline, bytes[] calldata sigs) external {
        storedNonce = nonce;
        storedDeadline = deadline;
        delete storedSigs;
        for (uint256 i = 0; i < sigs.length; i++) {
            storedSigs.push(sigs[i]);
        }
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            // Re-enter with the same nonce; must revert (nonReentrant + nonce used).
            bridge.withdraw(payable(address(this)), msg.value, storedNonce, storedDeadline, storedSigs);
        }
    }
}
