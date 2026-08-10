// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title RegistryV2
 * @notice BOLT Phase 13 validator identity registry. Supersedes MCFValidatorRegistry,
 *         closing two gaps:
 *
 *         G6 (register-time / boolean revocation -> per-withdrawal, revocation-aware):
 *           `verifyValidator(signer)` returns active ∧ !expired ∧ !revoked and is meant
 *           to be called on EVERY signer of EVERY withdrawal. An ERC-1812-style status /
 *           revocation registry (`isRevoked`) makes revocation effective IMMEDIATELY;
 *           a stolen-but-revoked key is rejected on the next call.
 *
 *         G7 (Ownable / fake multisig -> real m-of-n threshold governance):
 *           Lifecycle ops (register / revoke / renew / reinstate) require `m` approvals from the
 *           set of `n` governors. A single governor cannot act alone. Approvals are
 *           bound to an op id that commits the action + parameters, so they cannot be
 *           replayed for a different action.
 *
 *         DID format: did:ethr:<chainId>:<validatorAddress> (ERC-1056 style), with a
 *         Verifiable-Credential document hash bound to the validator key at register
 *         time (ECDSA proof of key possession, as in v1).
 *
 *         Governance scope: the governor set is immutable and approvals are
 *         irrevocable BY DESIGN-SPEC CHOICE; the compromised/stuck-governor case is
 *         explicitly out of scope; see docs/bolt/threat_model.md, "Governance scope".
 *
 *         Design specification, not a tested production system.
 */
contract RegistryV2 {
    using MessageHashUtils for bytes32;

    enum OpType {
        Register,
        Revoke,
        Renew,
        Reinstate
    }

    struct ValidatorDID {
        string did;
        address validatorAddr;
        bytes32 didDocumentHash; // VC document hash
        uint256 registeredAt;
        uint256 expiresAt;
        bool active;
    }

    // --- identity / status registry ---
    mapping(address => ValidatorDID) public validators;
    mapping(address => bool) public isRevoked; // ERC-1812-style status registry

    // --- m-of-n governance ---
    mapping(address => bool) public isGovernor;
    address[] public governors;
    uint256 public immutable threshold; // m

    // opId => governor => approved
    mapping(bytes32 => mapping(address => bool)) public approved;
    // opId => count of distinct approvals
    mapping(bytes32 => uint256) public approvalCount;
    // opId => already executed (prevents re-execution / approval reuse)
    mapping(bytes32 => bool) public executed;
    // per-validator monotonic governance nonce, folded into every opId so the SAME
    // logical action (e.g. a second Revoke after a reinstatement) yields a FRESH opId
    // each round. Old opIds stay executed (replay-safe); new rounds never collide.
    mapping(address => uint256) public govNonce;

    event GovernorApproval(bytes32 indexed opId, address indexed governor, uint256 count);
    event ValidatorRegistered(address indexed validatorAddr, string did, uint256 expiresAt);
    event ValidatorRevoked(address indexed validatorAddr);
    event ValidatorRenewed(address indexed validatorAddr, uint256 newExpiresAt);
    event ValidatorReinstated(address indexed validatorAddr, bytes32 docHash, uint256 expiresAt);

    modifier onlyGovernor() {
        require(isGovernor[msg.sender], "gov: not governor");
        _;
    }

    constructor(address[] memory _governors, uint256 _threshold) {
        require(_governors.length > 0, "gov: no governors");
        require(_threshold > 0 && _threshold <= _governors.length, "gov: bad threshold");
        for (uint256 i = 0; i < _governors.length; i++) {
            address g = _governors[i];
            require(g != address(0), "gov: zero governor");
            require(!isGovernor[g], "gov: dup governor");
            isGovernor[g] = true;
            governors.push(g);
        }
        threshold = _threshold;
    }

    function governorCount() external view returns (uint256) {
        return governors.length;
    }

    // -------------------------------------------------------------------------
    // m-of-n governance
    // -------------------------------------------------------------------------

    /// @notice Deterministic id binding an op type to its parameters. Approvals for one
    ///         opId cannot authorise a different action.
    function computeOpId(
        OpType opType,
        address validatorAddr,
        bytes32 docHash,
        uint256 ttl
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    block.chainid,
                    address(this),
                    opType,
                    validatorAddr,
                    docHash,
                    ttl,
                    govNonce[validatorAddr]
                )
            );
    }

    /// @notice A governor approves an op id. Distinct governors accumulate toward `m`.
    /// @dev `opId` is opaque: this function binds an approval to a 32-byte hash, not to a
    ///      human-readable action, and the contract cannot verify that the approver ever
    ///      inspected the operation the hash encodes. Approving a bare `opId` is therefore
    ///      blind signing, and governor diligence is an ASSUMPTION, not an enforced
    ///      property. Governors MUST reconstruct the pre-image off-chain [recompute
    ///      `computeOpId(opType, addr, docHash, ttl)` from the parameters they intend to
    ///      authorise and compare it to `opId`] BEFORE calling this function. Two
    ///      compounding properties: (1) approvals are irrevocable and never expire (there
    ///      is no withdrawal path; irrevocability is a design-spec choice, see the
    ///      contract-level governance-scope note above), so a mistaken approval cannot be
    ///      taken back before execution; (2) `govNonce[validatorAddr]` is folded into every
    ///      opId and advances on EVERY executed op for that validator, so an unrelated op
    ///      executing first silently voids the whole pending approval set for that
    ///      validator and forces a fresh m-of-n round, a liveness quirk that matters most
    ///      for emergency revocation. Disclosed in docs/bolt/limitations.md L12 and
    ///      docs/bolt/threat_model.md (Governance scope).
    function approve(bytes32 opId) external onlyGovernor {
        require(!approved[opId][msg.sender], "gov: already approved");
        approved[opId][msg.sender] = true;
        approvalCount[opId] += 1;
        emit GovernorApproval(opId, msg.sender, approvalCount[opId]);
    }

    function _consume(bytes32 opId) internal {
        require(!executed[opId], "gov: already executed");
        require(approvalCount[opId] >= threshold, "gov: insufficient approvals");
        executed[opId] = true;
    }

    // -------------------------------------------------------------------------
    // lifecycle ops (each requires m-of-n approvals on the matching opId)
    // -------------------------------------------------------------------------

    /// @notice Register a validator. Requires m approvals on the Register opId, plus an
    ///         ECDSA proof that `addr` controls its key (binds chainId+contract+addr).
    function executeRegister(
        address addr,
        bytes32 docHash,
        uint256 ttl,
        bytes calldata signature
    ) external onlyGovernor {
        bytes32 opId = computeOpId(OpType.Register, addr, docHash, ttl);
        _consume(opId);

        // Registration is once per address; a revoked address is brought back via
        // executeReinstate, never by re-registering over the existing record.
        require(validators[addr].registeredAt == 0, "already registered");

        bytes32 signingHash = keccak256(
            abi.encodePacked(block.chainid, address(this), addr, docHash)
        );
        address recovered = ECDSA.recover(signingHash.toEthSignedMessageHash(), signature);
        require(recovered == addr, "invalid signature");

        string memory did = string.concat(
            "did:ethr:",
            Strings.toString(block.chainid),
            ":",
            _toHexString(addr)
        );
        uint256 expiresAt = block.timestamp + ttl;

        validators[addr] = ValidatorDID({
            did: did,
            validatorAddr: addr,
            didDocumentHash: docHash,
            registeredAt: block.timestamp,
            expiresAt: expiresAt,
            active: true
        });
        isRevoked[addr] = false;

        govNonce[addr] += 1; // advance so the next op on this addr uses a fresh opId
        emit ValidatorRegistered(addr, did, expiresAt);
    }

    /// @notice Revoke a validator. Requires m approvals on the Revoke opId. The status
    ///         registry flips immediately, so verifyValidator is false on the next call.
    function executeRevoke(address addr) external onlyGovernor {
        bytes32 opId = computeOpId(OpType.Revoke, addr, bytes32(0), 0);
        _consume(opId);

        require(validators[addr].registeredAt != 0, "not registered");
        validators[addr].active = false;
        isRevoked[addr] = true;

        govNonce[addr] += 1; // a re-compromised, reinstated key can be revoked again
        emit ValidatorRevoked(addr);
    }

    /// @notice Renew a validator's credential. Requires m approvals on the Renew opId.
    function executeRenew(address addr, uint256 newTtl) external onlyGovernor {
        bytes32 opId = computeOpId(OpType.Renew, addr, bytes32(0), newTtl);
        _consume(opId);

        require(validators[addr].registeredAt != 0, "not registered");
        // A renewal extends an expired-but-trusted credential; it MUST NOT silently
        // reinstate a REVOKED (compromised) key. Reinstating revoked identity is a
        // distinct, intentional governance action (executeReinstate), not a renewal.
        require(!isRevoked[addr], "revoked: cannot renew");
        validators[addr].expiresAt = block.timestamp + newTtl;
        validators[addr].active = true;

        govNonce[addr] += 1;
        emit ValidatorRenewed(addr, validators[addr].expiresAt);
    }

    /// @notice Reinstate a REVOKED validator. Requires m approvals on the Reinstate
    ///         opId, plus a FRESH ECDSA key-control proof over a NEW credential
    ///         document: a reinstated credential is a new binding, not a
    ///         resurrection of the revoked one. `registeredAt` is kept as the
    ///         historical first-registration timestamp.
    function executeReinstate(
        address addr,
        bytes32 docHash,
        uint256 ttl,
        bytes calldata signature
    ) external onlyGovernor {
        bytes32 opId = computeOpId(OpType.Reinstate, addr, docHash, ttl);
        _consume(opId);

        require(validators[addr].registeredAt != 0, "not registered");
        require(isRevoked[addr], "not revoked");
        require(ttl > 0, "zero ttl");

        bytes32 signingHash = keccak256(
            abi.encodePacked(block.chainid, address(this), addr, docHash)
        );
        address recovered = ECDSA.recover(signingHash.toEthSignedMessageHash(), signature);
        require(recovered == addr, "invalid signature");

        ValidatorDID storage v = validators[addr];
        v.didDocumentHash = docHash;
        v.expiresAt = block.timestamp + ttl;
        v.active = true;
        isRevoked[addr] = false;

        govNonce[addr] += 1; // advance so the next op on this addr uses a fresh opId
        emit ValidatorReinstated(addr, docHash, v.expiresAt);
    }

    // -------------------------------------------------------------------------
    // per-withdrawal verification (G6): active ∧ !expired ∧ !revoked
    // -------------------------------------------------------------------------

    function verifyValidator(address addr) external view returns (bool) {
        ValidatorDID storage v = validators[addr];
        return v.active && !isRevoked[addr] && block.timestamp < v.expiresAt;
    }

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(42);
        result[0] = "0";
        result[1] = "x";
        uint160 value = uint160(addr);
        for (uint256 i = 41; i >= 2; i--) {
            result[i] = hexChars[value & 0xf];
            value >>= 4;
        }
        return string(result);
    }
}
