// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeHandler} from "./BridgeHandler.sol";

/// V2 task 1.4 + C4: spec invariants checked against the real bytecode.
/// PRIMARY instance: the ALT_TRIP ledger (T=4000, matching task 19.2), where
/// B + r*W = 4600 > T so the value-trip path is reachable and nothing here is
/// vacuous. (Optionally add a second, clearly-labelled LOCKED instance
/// (T=5000 ether) for continuity; its trip path is structurally UNREACHABLE
/// and it must be commented as vacuous for the breach-related invariants.)
contract BridgeInvariants is Test {
    BridgeHandler handler;

    function setUp() public {
        // ALT_TRIP: B=1000 ether, r=1 ether/s, T=4000 ether, W=3600 s.
        handler = new BridgeHandler(1000 ether, 1 ether, 4000 ether, 3600);
        targetContract(address(handler));
    }

    /// "window outflow never exceeds T", SLIDING form (C4). The exact contract-level
    /// guarantee asserted: within one reset epoch, the sum of REALISED outflows over
    /// every exact closed window [t - W, t] ending at a recorded outflow is <= T, with
    /// no single-tx overshoot (a breaching withdraw commits but moves ZERO value). This
    /// is implied by, never stricter than, the bytecode: the breaker's 61-slot
    /// integer-epoch accumulator sums [t - (W + bucketWidth), t], a SUPERSET of the
    /// exact window, so it can only trip EARLIER than a perfect sliding window would.
    /// Windows spanning a governance reset() carry no guarantee (reset clears the
    /// buckets, the C3 finding), so the ghost re-arms with the contract. The handler
    /// checks the window ending at EVERY recorded outflow via a moving left pointer
    /// (ghostOutTime/ghostOutAmount push in nondecreasing timestamp order).
    function invariant_slidingWindowOutflowNeverExceedsT() public view {
        assertFalse(handler.ghostSlidingWindowExceeded());
        // recorded-state corollary: the breaker's own bucketed view stays <= T too
        assertLe(handler.breaker().windowOutflow(), handler.T());
    }

    /// "token bucket never exceeds B"
    function invariant_bucketNeverExceedsB() public view {
        assertLe(handler.limiter().available(), handler.B());
    }

    /// "nonce never reused"
    function invariant_nonceNeverReused() public view {
        assertFalse(handler.ghostReplaySucceeded());
    }

    /// "revoked signer never authorises a withdrawal"
    function invariant_revokedSignerNeverAuthorises() public view {
        assertFalse(handler.ghostRevokedSignerSucceeded());
    }

    /// "expired signer never authorises a withdrawal": the SHORT_TTL validator's
    /// credential lapses inside a run (warpPastShortExpiry) and withdrawWithExpired
    /// then presents its signature.
    function invariant_expiredSignerNeverAuthorises() public view {
        assertFalse(handler.ghostExpiredSignerSucceeded());
    }

    /// "governed reinstate restores validity": after executeReinstate (C1),
    /// verifyValidator must be true again; revoke/reinstate cycles are fuzzed.
    function invariant_reinstateRestoresValidity() public view {
        assertFalse(handler.ghostReinstateNotValid());
    }

    /// "while latched, no withdraw moves value": checkAndRecord reverts synchronously
    /// when tripped (monitor trip OR value-latch), so no realised transfer can land
    /// between trip and reset.
    function invariant_noWithdrawWhileTripped() public view {
        assertFalse(handler.ghostWithdrawWhileTripped());
    }

    /// "reset clears the latch and re-arms a FRESH window": immediately after
    /// reset(), tripped is false and windowOutflow() is zero (C3-documented
    /// semantics: governance reset grants a fresh T budget).
    function invariant_resetRearmsFreshWindow() public view {
        assertFalse(handler.ghostResetNotRearmed());
    }

    /// "only the monitor trips; only the owner resets"
    function invariant_breakerAuthEnforced() public view {
        assertFalse(handler.ghostUnauthorizedBreakerAction());
    }

    /// "totalOut ghost accounting is exact". Every realised wei is accounted:
    /// recipient gained exactly ghostTotalOut and the bridge lost exactly that
    /// (blocked-but-committed withdrawals burn a nonce and bucket but move nothing).
    function invariant_totalOutAccountingExact() public view {
        assertEq(handler.recipient().balance, handler.ghostTotalOut());
        assertEq(address(handler.bridge()).balance, handler.DEPOSIT() - handler.ghostTotalOut());
    }

    /// Meaningfulness guard 1: the campaign must actually move value. A suite
    /// whose every call reverts OR lands blocked-but-committed (zero transfer)
    /// would pass all invariants vacuously. ghostSuccessfulWithdrawals counts
    /// only balance-verified transfers.
    function test_smoke_handlerCanWithdraw() public {
        handler.withdrawClean(uint96(1 ether), 30);
        assertEq(handler.ghostSuccessfulWithdrawals(), 1);
    }

    /// Meaningfulness guard 2 (V2 1.2 non-vacuity, on-bytecode): the breach path
    /// must be reachable by the handler's own action space. Burst B then drain at
    /// ~r: admitted outflow crosses T_alt=4000 inside one window (t = 3000 s < W),
    /// so checkAndRecord latches and BridgeV2 blocks; ghostBreachObserved flips.
    function test_smoke_breachPathReachable() public {
        handler.withdrawClean(uint96(uint256(1000 ether)), 500); // burst B
        for (uint256 i = 0; i < 12 && !handler.ghostBreachObserved(); i++) {
            handler.withdrawClean(uint96(uint256(500 ether)), 500); // drain at r
        }
        assertTrue(
            handler.ghostBreachObserved(),
            "value-trip path unreachable: invariants would be vacuous (V2 1.2)"
        );
    }

    /// Meaningfulness guard 3: trip blocks value in-path, reset restores liveness.
    function test_smoke_tripResetCycle() public {
        handler.tripViaMonitor();
        assertTrue(handler.breaker().tripped());
        handler.withdrawClean(uint96(1 ether), 30);
        assertEq(handler.ghostSuccessfulWithdrawals(), 0);
        assertFalse(handler.ghostWithdrawWhileTripped());
        handler.resetViaGovernance();
        assertFalse(handler.breaker().tripped());
        handler.withdrawClean(uint96(1 ether), 30);
        assertEq(handler.ghostSuccessfulWithdrawals(), 1);
    }

    /// Meaningfulness guard 4: the expiry path is reachable (SHORT_TTL lapses, the
    /// expired signature is rejected) and the remaining 8 validators keep the
    /// bridge live afterwards.
    function test_smoke_expiryPathReachable() public {
        handler.warpPastShortExpiry();
        assertGt(block.timestamp, handler.shortExpiry());
        handler.withdrawWithExpired(uint96(1 ether));
        assertFalse(handler.ghostExpiredSignerSucceeded());
        handler.withdrawClean(uint96(1 ether), 30);
        assertEq(handler.ghostSuccessfulWithdrawals(), 1);
    }

    /// Meaningfulness guard 5 (C1): revoke -> reinstate -> revoke again, where govNonce
    /// gives each round a fresh opId, so the cycle never dead-ends.
    function test_smoke_revokeReinstateCycle() public {
        handler.revokeOne(2);
        uint256 idx = handler.revokedIdx();
        assertTrue(idx != type(uint256).max);
        handler.withdrawWithRevoked(uint96(1 ether));
        assertFalse(handler.ghostRevokedSignerSucceeded());
        handler.reinstateRevoked();
        assertEq(handler.revokedIdx(), type(uint256).max);
        assertFalse(handler.ghostReinstateNotValid());
        handler.revokeOne(uint8(idx));
        assertEq(handler.revokedIdx(), idx);
    }
}
