// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title RateLimiter
 * @notice BOLT Phase 13 token-bucket rate limiter: the in-path "rate term" of the
 *         BOLT bound (docs/bolt/theorem.md). A token bucket of capacity `B` refills
 *         continuously at rate `r` (value/second). Each value-bearing withdrawal must
 *         `consume(amount)` tokens BEFORE the ETH leaves the bridge; if the bucket
 *         cannot cover the amount the call REVERTS (we choose revert over queue so the
 *         choke point is atomic, per assumption 1, and gives a clean same-block bound).
 *
 *         Locked symbols (theorem.md):
 *           B = capacity      [value]            (max admitted per block; assumption 4)
 *           r = refillRate    [value/second]
 *           (T = windowThreshold and W = windowLength live ONLY on CircuitBreaker:
 *            single source of truth, V2 task 0.4; this contract has no copy.)
 *
 *         Assumption 4 (no same-block escape): because `consume` is bounded by the
 *         current bucket level and the bucket only refills as `block.timestamp`
 *         advances, the total admitted within a single block is at most `B`.
 *
 *         Design specification, not a tested production system.
 */
contract RateLimiter is Ownable {
    uint256 public immutable capacity; // B  [value]
    uint256 public immutable refillRate; // r  [value/second]

    address public consumer; // authorised in-path caller (the bridge)

    uint256 private _tokens; // current bucket level [value]
    uint256 private _lastRefill; // last timestamp the bucket was reconciled

    event Consumed(uint256 amount, uint256 remaining);
    event ConsumerUpdated(address indexed consumer);

    modifier onlyConsumer() {
        require(msg.sender == consumer, "rate limit: not consumer");
        _;
    }

    constructor(
        uint256 _capacity,
        uint256 _refillRate,
        address _consumer
    ) Ownable(msg.sender) {
        require(_capacity > 0, "B must be > 0");
        capacity = _capacity;
        refillRate = _refillRate;
        consumer = _consumer;
        _tokens = _capacity; // start full
        _lastRefill = block.timestamp;
    }

    /// @notice Set/replace the authorised consumer (the bridge). Owner-only wiring helper.
    function setConsumer(address _consumer) external onlyOwner {
        consumer = _consumer;
        emit ConsumerUpdated(_consumer);
    }

    /// @dev Pure view of the bucket level reconciled to `block.timestamp`, clamped to B.
    function available() public view returns (uint256) {
        uint256 elapsed = block.timestamp - _lastRefill;
        uint256 refilled = _tokens + elapsed * refillRate;
        return refilled > capacity ? capacity : refilled;
    }

    /// @dev Reconcile the stored bucket level to now.
    function _refill() internal {
        _tokens = available();
        _lastRefill = block.timestamp;
    }

    /**
     * @notice Consume `amount` tokens for an in-path withdrawal. Reverts if the bucket
     *         (after refill) cannot cover the amount; this is the atomic choke point.
     */
    function consume(uint256 amount) external onlyConsumer {
        _refill();
        require(amount <= _tokens, "rate limit: bucket exhausted");
        _tokens -= amount;
        emit Consumed(amount, _tokens);
    }
}
