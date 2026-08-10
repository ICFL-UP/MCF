// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title MCFValidatorRegistry
 * @notice DID-based validator identity registry for the Metaverse Cybersecurity Framework.
 *         Implements credential lifecycle: register, revoke, renew, and verify.
 *         DID format: did:ethr:<chainId>:<validatorAddress>  (ERC-1056 style)
 * @dev  INTENTIONALLY-VULNERABLE v1 BASELINE; superseded by RegistryV2.sol.
 *       Kept as the "before" artifact for the Ronin motivation (V2 task 0.2,
 *       decision (b)): `renewValidator` re-activates a REVOKED key (no revoked
 *       check at line 105, the exact Ronin persistence failure), and every
 *       lifecycle op is single-owner (`Ownable`), not m-of-n. Demonstrated by
 *       registry.spec.ts "VULNERABLE BY DESIGN". Do NOT wire this registry to
 *       any value-bearing path; the hardened system is RegistryV2 + BridgeV2.
 */
contract MCFValidatorRegistry is Ownable {
    using MessageHashUtils for bytes32;
    struct ValidatorDID {
        string did;
        address validatorAddr;
        bytes32 didDocumentHash;
        uint256 registeredAt;
        uint256 expiresAt;
        bool active;
    }

    mapping(address => ValidatorDID) public validators;

    event ValidatorRegistered(address indexed validatorAddr, string did, uint256 expiresAt);
    event ValidatorRevoked(address indexed validatorAddr, string did);
    event ValidatorRenewed(address indexed validatorAddr, uint256 newExpiresAt);
    event MultisigConfirmation(address indexed owner, bytes32 txHash);

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Register a new validator with a DID bound to their address.
     * @param addr       The validator's Ethereum address.
     * @param docHash    Keccak-256 hash of the off-chain DID document.
     * @param ttl        Time-to-live in seconds from now.
     * @param signature  EIP-191 personal_sign signature of `docHash` by `addr`.
     *                   The contract recovers the signer from `(docHash, signature)`
     *                   and reverts unless it equals `addr`. This proves that the
     *                   address being registered actually controls the corresponding
     *                   secp256k1 private key (Phase 9a: closes the gap where the
     *                   owner could otherwise bind any address to a docHash without
     *                   key-possession proof).
     */
    function registerValidator(
        address addr,
        bytes32 docHash,
        uint256 ttl,
        bytes calldata signature
    ) external onlyOwner {
        require(validators[addr].registeredAt == 0, "already registered");

        // C1: bind signature to (chainId, contract, validator) so a sig obtained on
        // one chain / instance cannot be replayed against another.
        bytes32 signingHash = keccak256(
            abi.encodePacked(block.chainid, address(this), addr, docHash)
        );
        bytes32 ethSignedHash = signingHash.toEthSignedMessageHash();
        address recovered = ECDSA.recover(ethSignedHash, signature);
        require(recovered == addr, "invalid signature");

        // C2: chainId in the DID string reflects the deployment chain (ERC-1056).
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

        emit ValidatorRegistered(addr, did, expiresAt);
    }

    /**
     * @notice Revoke a validator's credential (sets active = false).
     * @param addr The validator's Ethereum address.
     */
    function revokeValidator(address addr) external onlyOwner {
        require(validators[addr].active, "not active");
        validators[addr].active = false;
        emit ValidatorRevoked(addr, validators[addr].did);
    }

    /**
     * @notice Renew a validator's credential with a new TTL.
     * @param addr    The validator's Ethereum address.
     * @param newTtl  New time-to-live in seconds from now.
     */
    function renewValidator(address addr, uint256 newTtl) external onlyOwner {
        require(validators[addr].registeredAt != 0, "not registered");
        uint256 newExpiresAt = block.timestamp + newTtl;
        validators[addr].expiresAt = newExpiresAt;
        validators[addr].active = true;
        emit ValidatorRenewed(addr, newExpiresAt);
    }

    /**
     * @notice Verify whether a validator's credential is currently valid.
     * @param addr The validator's Ethereum address.
     * @return True if the credential is active and not expired.
     */
    function verifyValidator(address addr) external view returns (bool) {
        ValidatorDID storage v = validators[addr];
        return v.active && block.timestamp < v.expiresAt;
    }

    /**
     * @notice Record a governance multisig confirmation on-chain.
     * @param txHash Identifier of the governance action being confirmed.
     */
    function confirmGovernanceAction(bytes32 txHash) external onlyOwner {
        emit MultisigConfirmation(msg.sender, txHash);
    }

    /**
     * @dev Convert an address to its lowercase "0x..." hex string representation.
     */
    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(42); // "0x" + 40 hex chars

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
