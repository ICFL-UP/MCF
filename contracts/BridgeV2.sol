// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IRegistryV2 {
    function verifyValidator(address addr) external view returns (bool);
}

interface IRateLimiter {
    function consume(uint256 amount) external;
}

interface ICircuitBreaker {
    function checkAndRecord(uint256 amount) external returns (bool breached);
}

/**
 * @title BridgeV2
 * @notice BOLT Phase 13 bridge: the atomic, instrumented value-bearing exit path
 *         (assumption 1). Supersedes MockBridge, closing G4: authentication is now
 *         k-of-n ECDSA over the withdrawal tuple instead of `msg.sender`, so signature
 *         theft is modelable and the on-chain bounded response is in-path.
 *
 *         Security invariants (the review focus):
 *           - withdraw verifies `k` valid, DISTINCT ECDSA signatures over
 *             keccak256(recipient, amount, nonce, deadline, chainId, address(this)). Binding
 *             `block.chainid` AND this contract address stops cross-chain and
 *             cross-contract replay. Distinctness is enforced by requiring strictly
 *             increasing recovered signer addresses (no duplicate signer).
 *           - EVERY signer must pass RegistryV2.verifyValidator (active ∧ !expired ∧
 *             !revoked) on EVERY withdrawal; a stolen-but-revoked key is rejected
 *             every time (closes G6).
 *           - The value exit routes through the RateLimiter (token bucket, ≤ B/block,
 *             assumption 4) and the synchronous CircuitBreaker (window cap T / monitor
 *             trip). Either can block the withdrawal IN-PATH.
 *           - checks-effects-interactions + nonReentrant: the nonce is marked used and
 *             the limiter/breaker are updated BEFORE the external ETH `.call`, which is
 *             performed LAST.
 *
 *         Design specification, not a tested production system.
 */
contract BridgeV2 is ReentrancyGuard {
    using MessageHashUtils for bytes32;

    IRegistryV2 public immutable registry;
    IRateLimiter public immutable limiter;
    ICircuitBreaker public immutable breaker;
    uint256 public immutable threshold; // k

    mapping(uint256 => bool) public usedNonce;

    event Deposit(address indexed from, uint256 amount);
    event Withdrawal(address indexed recipient, uint256 amount, uint256 indexed nonce);
    event WithdrawalBlocked(address indexed recipient, uint256 amount, uint256 indexed nonce, string reason);

    constructor(
        address _registry,
        address _limiter,
        address _breaker,
        uint256 _threshold
    ) {
        require(_threshold > 0, "k must be > 0");
        registry = IRegistryV2(_registry);
        limiter = IRateLimiter(_limiter);
        breaker = ICircuitBreaker(_breaker);
        threshold = _threshold;
    }

    function deposit() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }

    /// @dev The signed message digest for a withdrawal. Bound to chainId + this contract
    ///      + a signature deadline (V2 0.3): stale signatures expire.
    ///      EIP-191 personal-sign rather than EIP-712 typed data (PoC scope): the domain is
    ///      already bound via chainId + address(this) inside the digest, so typed data would
    ///      add wallet-display ergonomics, not a security delta, for this single-contract PoC.
    function withdrawalDigest(
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 raw = keccak256(
            abi.encodePacked(recipient, amount, nonce, deadline, block.chainid, address(this))
        );
        return raw.toEthSignedMessageHash();
    }

    /**
     * @notice Execute a k-of-n withdrawal. `signatures` must be ordered by ascending
     *         recovered signer address (this guarantees distinct signers in one pass).
     *
     *         Checks-effects-interactions:
     *           checks:      verify >= k distinct, authorised ECDSA sigs;
     *           effects:     mark nonce used; consume the rate-limiter bucket; record
     *                        the outflow in the breaker (which may latch/trip);
     *           interaction: transfer ETH LAST via `.call`, under nonReentrant.
     */
    function withdraw(
        address payable recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata signatures
    ) external nonReentrant {
        // --- checks ---
        require(recipient != address(0), "bridge: zero recipient");
        require(amount > 0, "bridge: zero amount");
        require(block.timestamp <= deadline, "bridge: expired deadline");
        require(!usedNonce[nonce], "bridge: nonce used");
        require(signatures.length >= threshold, "bridge: insufficient signatures");

        bytes32 digest = withdrawalDigest(recipient, amount, nonce, deadline);

        address last = address(0);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(digest, signatures[i]);
            // Strictly increasing => distinct signers, no duplicates.
            require(signer > last, "bridge: duplicate or unordered signer");
            last = signer;
            // Per-withdrawal status check (G6): active ∧ !expired ∧ !revoked.
            require(registry.verifyValidator(signer), "bridge: signer not authorized");
        }
        // NOTE (V2 0.3): the former post-loop `require(valid >= threshold)` was dead:
        // signatures.length >= threshold is checked above and the loop reverts on any
        // invalid signature, so it could never fail. Removed.

        // --- effects (before the external call) ---
        usedNonce[nonce] = true;
        // Token bucket: admits <= B per block; reverts if exhausted (assumption 4).
        limiter.consume(amount);
        // Synchronous circuit breaker, two-phase value trip (V2 0.1, Option A): on a
        // fresh window-cap breach checkAndRecord LATCHES tripped=true and returns true
        // WITHOUT reverting. We skip the transfer and COMMIT this transaction so the
        // latch persists on-chain; reverting here would roll the latch back (the
        // original defect). Nonce stays burned + bucket stays consumed: conservative.
        bool breached = breaker.checkAndRecord(amount);
        if (breached) {
            emit WithdrawalBlocked(recipient, amount, nonce, "window threshold exceeded");
            return;
        }

        // --- interaction (LAST) ---
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "bridge: transfer failed");

        emit Withdrawal(recipient, amount, nonce);
    }
}
