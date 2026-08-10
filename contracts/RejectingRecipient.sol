// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title RejectingRecipient
/// @notice Test-only helper (V2 task 1.3 coverage): a recipient that rejects any ETH
///         transfer, used to exercise BridgeV2's "bridge: transfer failed" branch.
///         ReentrantAttacker does not serve here: its receive() only reverts
///         indirectly via its own failed re-entrant withdraw call.
contract RejectingRecipient {
    receive() external payable {
        revert("reject");
    }
}
