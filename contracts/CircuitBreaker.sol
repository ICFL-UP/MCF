// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title CircuitBreaker
 * @notice BOLT Phase 13 synchronous / IN-PATH circuit breaker: the "value-threshold"
 *         term of the BOLT bound (docs/bolt/theorem.md). It trips when cumulative
 *         outflow within the sliding window `W` exceeds the threshold `T`, OR when the
 *         authorised monitor signals (`trip`). When tripped, `checkAndRecord` REVERTS in
 *         the same call path. This is NOT an async pause flag inspected later; the
 *         value-bearing call cannot complete while the breaker is tripped.
 *
 *         Locked symbols (theorem.md):
 *           T = threshold     [value]   (trips when window outflow > T)
 *           W = windowLength  [seconds]
 *
 *         The monitor `trip()` is what gives the `δ_detect` response: a detector off
 *         chain can halt the exit synchronously on the next call. Governance/owner
 *         `reset()` clears the breaker.
 *
 *         Sliding window: outflow is accumulated into a fixed 61-slot time-bucket
 *         accumulator (bucket width = W/60; 61 slots so the summed span always covers
 *         at least the full exact window). Each checkAndRecord touches exactly one slot
 *         and sums a constant 61 slots, so gas is CONSTANT in traffic volume (V2 1.7).
 *         The bucketed window spans [t - (W + bucketWidth), t], a superset of the exact
 *         sliding window [t - W, t]: it OVER-approximates by at most one bucket width,
 *         so the breaker can only trip EARLIER than the exact-window version, which
 *         is conservative; the bound X <= T + r*Δ is preserved.
 *
 *         Design specification, not a tested production system.
 */
contract CircuitBreaker is Ownable {
    uint256 public immutable threshold; // T  [value]
    uint256 public immutable windowLength; // W  [seconds]

    address public gate; // authorised in-path caller (the bridge)
    address public monitor; // authorised detector that can trip

    bool public tripped;

    uint256 private constant WINDOW_BUCKETS = 60;               // = windowLength / bucketWidth
    uint256 private constant BUCKET_COUNT = WINDOW_BUCKETS + 1; // 61 slots: +1 so the summed span covers >= the full W
    uint256 public immutable bucketWidth; // = windowLength / WINDOW_BUCKETS (constructor: require divisible)

    uint256[BUCKET_COUNT] private _bucketTotal;
    uint256[BUCKET_COUNT] private _bucketEpoch; // epoch id owning each slot's total

    event Recorded(uint256 amount, uint256 windowOutflow);
    event Tripped(address indexed by, string reason);
    event Reset(address indexed by);
    event GateUpdated(address indexed gate);
    event MonitorUpdated(address indexed monitor);

    modifier onlyGate() {
        require(msg.sender == gate, "breaker: not gate");
        _;
    }

    modifier onlyMonitor() {
        require(msg.sender == monitor, "breaker: not monitor");
        _;
    }

    constructor(
        uint256 _threshold,
        uint256 _windowLength,
        address _gate,
        address _monitor
    ) Ownable(msg.sender) {
        require(_windowLength % WINDOW_BUCKETS == 0, "breaker: W not bucket-divisible");
        threshold = _threshold;
        windowLength = _windowLength;
        bucketWidth = _windowLength / WINDOW_BUCKETS;
        gate = _gate;
        monitor = _monitor;
    }

    function setGate(address _gate) external onlyOwner {
        gate = _gate;
        emit GateUpdated(_gate);
    }

    function setMonitor(address _monitor) external onlyOwner {
        monitor = _monitor;
        emit MonitorUpdated(_monitor);
    }

    /// @dev Sum of buckets in epochs [epoch - WINDOW_BUCKETS, epoch]: 61 slots, O(61),
    ///      constant, independent of traffic volume. The summed span covers
    ///      [t - (W + bucketWidth), t], a SUPERSET of the exact sliding window [t - W, t]
    ///      (a record at exactly t - W lands in epoch - WINDOW_BUCKETS, still summed).
    ///      So this OVER-approximates the exact window by at most one bucketWidth: the
    ///      breaker can only trip EARLIER than the exact-window version (conservative;
    ///      the bound X <= T + r*Δ is preserved). NOTE: 60 slots summing
    ///      [epoch-59, epoch] would UNDER-approximate (span 3599 s) and let the trip
    ///      fire late; do not "optimise" the extra slot away.
    function windowOutflow() public view returns (uint256 total) {
        uint256 epoch = block.timestamp / bucketWidth;
        uint256 oldest = epoch >= WINDOW_BUCKETS ? epoch - WINDOW_BUCKETS : 0;
        for (uint256 i = 0; i < BUCKET_COUNT; i++) {
            if (_bucketEpoch[i] >= oldest && _bucketEpoch[i] <= epoch) {
                total += _bucketTotal[i];
            }
        }
    }

    /// @dev O(1) record: touches exactly one bucket slot and lazily reclaims it if the
    ///      slot's owning epoch has aged out of the summed span.
    function _recordOutflow(uint256 amount) internal {
        uint256 epoch = block.timestamp / bucketWidth;
        uint256 idx = epoch % BUCKET_COUNT;
        if (_bucketEpoch[idx] != epoch) {
            _bucketTotal[idx] = 0; // lazily reclaim the stale slot
            _bucketEpoch[idx] = epoch;
        }
        _bucketTotal[idx] += amount;
    }

    /**
     * @notice In-path check + record for a value-bearing outflow of `amount`.
     *         Two-phase trip (V2 task 0.1, Option A):
     *           - ALREADY tripped (latched or monitor-tripped): REVERTS synchronously;
     *             no value can move while tripped.
     *           - FRESH breach (recording `amount` would push the window total over T):
     *             latches `tripped = true` and returns `breached = true` WITHOUT
     *             reverting. The gate (BridgeV2) must then SKIP the value transfer and
     *             COMMIT its transaction so the latch SSTORE persists. Reverting here
     *             would atomically roll the latch back, the exact defect this design
     *             fixes: a latch written inside a reverting transaction never existed.
     *           - Otherwise records the outflow and returns false.
     */
    function checkAndRecord(uint256 amount) external onlyGate returns (bool breached) {
        // Already-latched breaker blocks synchronously, in this very call.
        require(!tripped, "breaker: tripped");

        uint256 newTotal = windowOutflow() + amount;
        if (newTotal > threshold) {
            tripped = true;
            emit Tripped(msg.sender, "window threshold exceeded");
            return true;
        }

        _recordOutflow(amount);
        emit Recorded(amount, newTotal);
        return false;
    }

    /// @notice Authorised monitor trips the breaker (the δ_detect response path).
    function trip() external onlyMonitor {
        tripped = true;
        emit Tripped(msg.sender, "monitor signal");
    }

    /// @notice Governance/owner resets the breaker and clears the window.
    function reset() external {
        require(msg.sender == owner(), "breaker: not governance");
        tripped = false;
        for (uint256 i = 0; i < BUCKET_COUNT; i++) {
            _bucketTotal[i] = 0;
            _bucketEpoch[i] = 0;
        }
        emit Reset(msg.sender);
    }
}
