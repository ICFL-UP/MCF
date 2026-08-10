// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import "./MCFValidatorRegistry.sol";

/**
 * @title MockBridge
 * @notice Minimal cross-chain-bridge mock used to demonstrate the dual-gate pipeline
 *         from §11.2.4 of the MCF dissertation. Holds ETH, accepts withdrawal requests,
 *         requires k-of-n validator confirmations before execution. The off-chain
 *         monitoring service can pause the bridge by calling `pause()`; pausing blocks
 *         both further confirmations and withdrawal execution.
 *
 *         Intentional simplifications (PoC scope, INFO_PACK §10):
 *         - validators submit confirmations directly (`msg.sender`) rather than
 *           aggregating ECDSA signatures off-chain;
 *         - withdrawal proofs / cross-chain message verification are omitted;
 *         - re-entrancy guards beyond what the EVM provides are not added.
 * @dev  INTENTIONALLY-KEPT v1 BASELINE; superseded by BridgeV2.sol (k-of-n ECDSA,
 *       RateLimiter + CircuitBreaker in-path). Paired with the vulnerable
 *       MCFValidatorRegistry as the "before" artifact (V2 task 0.2, decision (b)).
 */
contract MockBridge {
    MCFValidatorRegistry public registry;
    address public monitor;
    uint256 public threshold;
    uint256 public nonce;

    bool public paused;

    mapping(bytes32 => mapping(address => bool)) public confirmations;
    mapping(bytes32 => uint256) public confirmationCount;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => address) public txTo;
    mapping(bytes32 => uint256) public txValue;

    event WithdrawalRequested(address indexed to, uint256 value, bytes32 indexed txHash, uint256 nonce);
    event TransactionConfirmed(bytes32 indexed txHash, address indexed validator);
    event TransactionExecuted(bytes32 indexed txHash, address indexed to, uint256 value);
    event BridgePaused(address indexed by);

    modifier onlyMonitor() {
        require(msg.sender == monitor, "not monitor");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "bridge paused");
        _;
    }

    constructor(address registryAddr, uint256 _threshold, address _monitor) {
        registry = MCFValidatorRegistry(registryAddr);
        threshold = _threshold;
        monitor = _monitor;
    }

    /// @notice Fund the bridge. Required so `executeTransaction` has ETH to send.
    function deposit() external payable {}

    /// @notice Receive ETH directly (e.g. plain sends).
    receive() external payable {}

    /// @notice Submit a withdrawal request. Emits `WithdrawalRequested`, which the
    ///         off-chain monitor subscribes to. Returns the deterministic txHash.
    function submitTransaction(address to, uint256 value) external returns (bytes32) {
        bytes32 txHash = keccak256(abi.encodePacked(to, value, nonce));
        txTo[txHash] = to;
        txValue[txHash] = value;
        emit WithdrawalRequested(to, value, txHash, nonce);
        nonce++;
        return txHash;
    }

    /// @notice Validator confirms a withdrawal. Reverts unless the caller has an
    ///         active, unexpired DID credential. Reverts if the bridge is paused.
    function confirmTransaction(bytes32 txHash) external whenNotPaused {
        require(registry.verifyValidator(msg.sender), "validator not authorized");
        require(!confirmations[txHash][msg.sender], "already confirmed");
        confirmations[txHash][msg.sender] = true;
        confirmationCount[txHash]++;
        emit TransactionConfirmed(txHash, msg.sender);
    }

    /// @notice Execute a withdrawal. Requires k-of-n confirmations and the bridge to be
    ///         unpaused. Transfers `value` ETH to the recipient.
    function executeTransaction(bytes32 txHash) external whenNotPaused {
        require(confirmationCount[txHash] >= threshold, "insufficient confirmations");
        require(!executed[txHash], "already executed");
        require(txTo[txHash] != address(0), "unknown txHash");
        executed[txHash] = true;
        uint256 value = txValue[txHash];
        address to = txTo[txHash];
        (bool ok, ) = to.call{value: value}("");
        require(ok, "transfer failed");
        emit TransactionExecuted(txHash, to, value);
    }

    /// @notice Pause the bridge. Callable only by the configured monitor address. Once
    ///         paused, no further confirmations or executions are permitted; this is
    ///         the integration point for the Detect-side gate (§11.2.4).
    ///         One-way: there is no unpause; recovery is redeployment (PoC scope).
    function pause() external onlyMonitor {
        paused = true;
        emit BridgePaused(msg.sender);
    }

    function isExecutable(bytes32 txHash) external view returns (bool) {
        return !paused && !executed[txHash] && confirmationCount[txHash] >= threshold;
    }
}
