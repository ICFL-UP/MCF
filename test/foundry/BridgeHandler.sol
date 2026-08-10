// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {RegistryV2} from "../../contracts/RegistryV2.sol";
import {RateLimiter} from "../../contracts/RateLimiter.sol";
import {CircuitBreaker} from "../../contracts/CircuitBreaker.sol";
import {BridgeV2} from "../../contracts/BridgeV2.sol";

/// V2 task 1.4 handler: fuzzed attacker/operator actions against the REAL bytecode.
/// Ledger is CONSTRUCTOR-PARAMETERISED (B, r, T, W). The invariant suite instantiates
/// the ALT_TRIP config from task 19.2 (B=1000, r=1/s, T=4000, W=3600: B+r*W=4600 > T,
/// so the value-trip/breach path is REACHABLE and the invariants are non-vacuous;
/// under the LOCKED ledger T=5000 the trip is structurally unreachable, the exact
/// vacuity V2 1.2 exists to eliminate). k=5, n=9.
///
/// The handler stands in for BOTH privileged roles it deployed: it is the breaker's
/// authorised monitor (trip) and its Ownable owner (governance reset), just as the
/// registry actions prank the m-of-n governors.
contract BridgeHandler is Test {
    uint256 public constant K = 5;
    uint256 public constant N_VALS = 9;
    uint256 public constant M_GOV = 3;
    uint256 public immutable B;                  // bucket capacity
    uint256 public immutable RATE;               // refill, per second
    uint256 public immutable T;                  // window threshold
    uint256 public immutable W;                  // window length, seconds
    uint256 public constant FAR_DEADLINE = 2**63; // post-0.3 signed deadline; expiry is unit-tested in Hardhat (18/0.3.1)
    uint256 public constant DEPOSIT = 500_000 ether;
    uint256 public constant SHORT_TTL = 30 days;   // one validator carries this, so credential
    uint256 public constant LONG_TTL = 3650 days;  // expiry is reachable inside a fuzz run
    uint256 public constant SHORT_IDX = N_VALS - 1; // sorted index of the short-TTL validator

    RegistryV2 public registry;
    RateLimiter public limiter;
    CircuitBreaker public breaker;
    BridgeV2 public bridge;

    address[] public governors;
    uint256[] public validatorPks;               // sorted ascending by vm.addr(pk)
    address payable public recipient = payable(address(0xBEEF));

    uint256 public nextNonce = 1;
    uint256[] public usedNonces;
    uint256 public shortExpiry;                  // current expiresAt of the SHORT_IDX validator

    // ---- ghosts read by the invariants ----
    uint256 public ghostSuccessfulWithdrawals;   // value actually moved
    uint256 public ghostTotalOut;                // realised (balance-verified) value, cumulative
    bool public ghostBreachObserved;             // a fresh value trip latched (blocked-but-committed withdraw)
    bool public ghostReplaySucceeded;
    bool public ghostRevokedSignerSucceeded;
    bool public ghostExpiredSignerSucceeded;
    bool public ghostReinstateNotValid;          // governed reinstate left the validator invalid
    bool public ghostWithdrawWhileTripped;       // value moved while the latch was set
    bool public ghostResetNotRearmed;            // reset left the latch set or the window non-empty
    bool public ghostUnauthorizedBreakerAction;  // non-monitor trip or non-owner reset went through
    uint256 public revokedIdx = type(uint256).max;

    // ---- sliding ghost window (C4) ----
    // The breaker's 61-slot integer-epoch accumulator sums the span
    // [t - (W + bucketWidth), t] (a SUPERSET of the exact sliding window [t - W, t])
    // and a fresh breach commits with ZERO value moved (two-phase trip). The
    // contract-level guarantee is therefore: within one reset epoch, the sum of
    // REALISED outflows over every exact closed window [t - W, t] ending at a recorded
    // outflow is <= T, with NO single-tx overshoot. `reset()` clears the buckets, so a
    // window spanning a reset carries no cross-reset guarantee (the C3 finding);
    // the ghost re-arms with the contract. Timestamps only move forward, so a moving
    // left pointer checks every such window exactly, in amortised O(1).
    uint256[] public ghostOutTime;
    uint256[] public ghostOutAmount;
    uint256 public ghostResetEpoch;
    uint256 internal slidingLeft;
    uint256 internal slidingSum;
    bool public ghostSlidingWindowExceeded;

    constructor(uint256 _b, uint256 _rate, uint256 _t, uint256 _w) {
        B = _b;
        RATE = _rate;
        T = _t;
        W = _w;

        address[] memory govs = new address[](M_GOV);
        for (uint256 i = 0; i < M_GOV; i++) {
            governors.push(vm.addr(1000 + i));
            govs[i] = governors[i];
        }
        registry = new RegistryV2(govs, M_GOV);

        for (uint256 i = 0; i < N_VALS; i++) validatorPks.push(2000 + i);
        _sortPksByAddress();
        for (uint256 i = 0; i < N_VALS; i++) {
            _register(validatorPks[i], i == SHORT_IDX ? SHORT_TTL : LONG_TTL);
        }
        shortExpiry = block.timestamp + SHORT_TTL;

        limiter = new RateLimiter(B, RATE, address(0)); // post-0.4 3-arg: T/W live only on CircuitBreaker
        breaker = new CircuitBreaker(T, W, address(0), address(this));
        bridge = new BridgeV2(address(registry), address(limiter), address(breaker), K);
        limiter.setConsumer(address(bridge));
        breaker.setGate(address(bridge));

        vm.deal(address(this), 1_000_000 ether);
        bridge.deposit{value: DEPOSIT}();
    }

    // ---- fuzzed actions ----

    function withdrawClean(uint96 amountSeed, uint16 warpSeed) external {
        uint256 amount = bound(uint256(amountSeed), 0.01 ether, B);
        vm.warp(block.timestamp + bound(uint256(warpSeed), 1, 900));
        bool wasTripped = breaker.tripped();
        uint256 nonce = nextNonce++;
        bytes[] memory sigs = _sigsFromActive(amount, nonce);
        uint256 balBefore = recipient.balance;
        try bridge.withdraw(recipient, amount, nonce, FAR_DEADLINE, sigs) {
            // Post-0.1 two-phase trip: a value-BREACHING withdraw also lands here;
            // it COMMITS (checkAndRecord returned breached=true, BridgeV2 emitted
            // WithdrawalBlocked) but moves ZERO value. Only count realised
            // extraction when the recipient balance actually increased; otherwise
            // record that the breach/latch path fired.
            if (recipient.balance > balBefore) {
                if (wasTripped) ghostWithdrawWhileTripped = true;
                usedNonces.push(nonce);
                ghostSuccessfulWithdrawals++;
                ghostTotalOut += amount;
                _recordSlidingOutflow(amount);
            } else {
                ghostBreachObserved = true; // blocked-but-committed: breaker latched
            }
        } catch {}
    }

    function replayNonce(uint96 amountSeed, uint16 idxSeed) external {
        if (usedNonces.length == 0) return;
        uint256 nonce = usedNonces[bound(uint256(idxSeed), 0, usedNonces.length - 1)];
        uint256 amount = bound(uint256(amountSeed), 0.01 ether, B);
        bytes[] memory sigs = _sigsFromActive(amount, nonce);
        try bridge.withdraw(recipient, amount, nonce, FAR_DEADLINE, sigs) {
            ghostReplaySucceeded = true; // invariant_nonceNeverReused fails
        } catch {}
    }

    function revokeOne(uint8 idxSeed) external {
        if (revokedIdx != type(uint256).max) return; // at most one revoked at a time; reinstateRevoked re-opens
        uint256 idx = bound(uint256(idxSeed), 0, N_VALS - 1);
        address addr = vm.addr(validatorPks[idx]);
        bytes32 opId = registry.computeOpId(RegistryV2.OpType.Revoke, addr, bytes32(0), 0);
        for (uint256 i = 0; i < M_GOV; i++) {
            vm.prank(governors[i]);
            registry.approve(opId);
        }
        vm.prank(governors[0]);
        registry.executeRevoke(addr);
        revokedIdx = idx;
    }

    /// C1 lifecycle closure: governed reinstate of the currently-revoked validator with
    /// a fresh key-control proof + NEW docHash. govNonce advanced on every execute, so
    /// the next revokeOne round computes a fresh opId (no collision with the consumed one).
    function reinstateRevoked() external {
        if (revokedIdx == type(uint256).max) return;
        uint256 idx = revokedIdx;
        address addr = vm.addr(validatorPks[idx]);
        bytes32 docHash = keccak256(abi.encodePacked("doc-reinstate", addr, block.timestamp));
        uint256 ttl = idx == SHORT_IDX ? SHORT_TTL : LONG_TTL;
        bytes32 opId = registry.computeOpId(RegistryV2.OpType.Reinstate, addr, docHash, ttl);
        for (uint256 i = 0; i < M_GOV; i++) {
            vm.prank(governors[i]);
            registry.approve(opId);
        }
        bytes32 inner = keccak256(abi.encodePacked(block.chainid, address(registry), addr, docHash));
        (uint8 v, bytes32 rSig, bytes32 sSig) = vm.sign(validatorPks[idx], MessageHashUtils.toEthSignedMessageHash(inner));
        vm.prank(governors[0]);
        registry.executeReinstate(addr, docHash, ttl, abi.encodePacked(rSig, sSig, v));
        if (!registry.verifyValidator(addr)) ghostReinstateNotValid = true;
        if (idx == SHORT_IDX) shortExpiry = block.timestamp + ttl;
        revokedIdx = type(uint256).max;
    }

    function withdrawWithRevoked(uint96 amountSeed) external {
        if (revokedIdx == type(uint256).max) return;
        uint256 amount = bound(uint256(amountSeed), 0.01 ether, B);
        uint256 nonce = nextNonce++;
        uint256[] memory chosen = new uint256[](K);
        if (revokedIdx < K) {
            for (uint256 i = 0; i < K; i++) chosen[i] = i;
        } else {
            for (uint256 i = 0; i < K - 1; i++) chosen[i] = i;
            chosen[K - 1] = revokedIdx; // ascending order preserved
        }
        bytes[] memory sigs = new bytes[](K);
        bytes32 digest = bridge.withdrawalDigest(recipient, amount, nonce, FAR_DEADLINE);
        for (uint256 i = 0; i < K; i++) {
            (uint8 v, bytes32 rSig, bytes32 sSig) = vm.sign(validatorPks[chosen[i]], digest);
            sigs[i] = abi.encodePacked(rSig, sSig, v);
        }
        try bridge.withdraw(recipient, amount, nonce, FAR_DEADLINE, sigs) {
            ghostRevokedSignerSucceeded = true; // invariant fails
        } catch {}
    }

    function withdrawWithExpired(uint96 amountSeed) external {
        if (block.timestamp <= shortExpiry) return; // credential still live
        uint256 amount = bound(uint256(amountSeed), 0.01 ether, B);
        uint256 nonce = nextNonce++;
        uint256[] memory chosen = new uint256[](K);
        uint256 filled = 0;
        for (uint256 i = 0; i < SHORT_IDX && filled < K - 1; i++) {
            if (i == revokedIdx) continue;
            chosen[filled++] = i;
        }
        chosen[K - 1] = SHORT_IDX; // largest sorted index: ascending order preserved
        bytes[] memory sigs = new bytes[](K);
        bytes32 digest = bridge.withdrawalDigest(recipient, amount, nonce, FAR_DEADLINE);
        for (uint256 i = 0; i < K; i++) {
            (uint8 v, bytes32 rSig, bytes32 sSig) = vm.sign(validatorPks[chosen[i]], digest);
            sigs[i] = abi.encodePacked(rSig, sSig, v);
        }
        try bridge.withdraw(recipient, amount, nonce, FAR_DEADLINE, sigs) {
            ghostExpiredSignerSucceeded = true; // invariant fails
        } catch {}
    }

    /// δ_detect response path: the authorised monitor (this handler) latches the breaker.
    function tripViaMonitor() external {
        breaker.trip();
    }

    /// Governance path: the breaker's Ownable owner (this handler) clears the latch AND
    /// the window (CircuitBreaker.reset semantics, C3); the sliding ghost re-arms with it.
    function resetViaGovernance() external {
        breaker.reset();
        if (breaker.tripped() || breaker.windowOutflow() != 0) ghostResetNotRearmed = true;
        ghostResetEpoch++;
        slidingSum = 0;
        slidingLeft = ghostOutTime.length;
    }

    function unauthorizedTripOrReset(uint8 addrSeed) external {
        address intruder = vm.addr(3000 + bound(uint256(addrSeed), 0, 15));
        vm.prank(intruder);
        try breaker.trip() {
            ghostUnauthorizedBreakerAction = true; // onlyMonitor bypassed
        } catch {}
        vm.prank(intruder);
        try breaker.reset() {
            ghostUnauthorizedBreakerAction = true; // owner check bypassed
        } catch {}
    }

    function warpTime(uint16 secsSeed) external {
        vm.warp(block.timestamp + bound(uint256(secsSeed), 1, 2 * W));
    }

    function warpPastShortExpiry() external {
        if (block.timestamp > shortExpiry) return;
        vm.warp(shortExpiry + 1);
    }

    // ---- internals ----

    function _recordSlidingOutflow(uint256 amount) internal {
        uint256 t = block.timestamp;
        ghostOutTime.push(t);
        ghostOutAmount.push(amount);
        while (slidingLeft + 1 < ghostOutTime.length && ghostOutTime[slidingLeft] + W < t) {
            slidingSum -= ghostOutAmount[slidingLeft];
            slidingLeft++;
        }
        slidingSum += amount;
        if (slidingSum > T) ghostSlidingWindowExceeded = true;
    }

    function _sigsFromActive(uint256 amount, uint256 nonce) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](K);
        bytes32 digest = bridge.withdrawalDigest(recipient, amount, nonce, FAR_DEADLINE);
        uint256 filled = 0;
        for (uint256 i = 0; i < N_VALS && filled < K; i++) {
            if (i == revokedIdx) continue; // skip preserves ascending order
            if (i == SHORT_IDX && block.timestamp > shortExpiry) continue; // expired credential
            (uint8 v, bytes32 rSig, bytes32 sSig) = vm.sign(validatorPks[i], digest);
            sigs[filled++] = abi.encodePacked(rSig, sSig, v);
        }
    }

    function _register(uint256 pk, uint256 ttl) internal {
        address addr = vm.addr(pk);
        bytes32 docHash = keccak256(abi.encodePacked("doc", addr));
        bytes32 opId = registry.computeOpId(RegistryV2.OpType.Register, addr, docHash, ttl);
        for (uint256 i = 0; i < M_GOV; i++) {
            vm.prank(governors[i]);
            registry.approve(opId);
        }
        bytes32 inner = keccak256(abi.encodePacked(block.chainid, address(registry), addr, docHash));
        (uint8 v, bytes32 rSig, bytes32 sSig) = vm.sign(pk, MessageHashUtils.toEthSignedMessageHash(inner));
        vm.prank(governors[0]);
        registry.executeRegister(addr, docHash, ttl, abi.encodePacked(rSig, sSig, v));
    }

    function _sortPksByAddress() internal {
        // insertion sort over 9 keys: BridgeV2 requires strictly-increasing signers
        for (uint256 i = 1; i < validatorPks.length; i++) {
            uint256 key = validatorPks[i];
            uint256 j = i;
            while (j > 0 && vm.addr(validatorPks[j - 1]) > vm.addr(key)) {
                validatorPks[j] = validatorPks[j - 1];
                j--;
            }
            validatorPks[j] = key;
        }
    }
}
