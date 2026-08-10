import { expect } from "chai";
import { ethers } from "hardhat";
import { MCFValidatorRegistry } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

async function signDocHash(
  signer: SignerWithAddress,
  docHash: string,
  registryAddress: string,
  validatorAddress: string
): Promise<string> {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const innerHash = ethers.solidityPackedKeccak256(
    ["uint256", "address", "address", "bytes32"],
    [chainId, registryAddress, validatorAddress, docHash]
  );
  return signer.signMessage(ethers.getBytes(innerHash));
}

describe("MCFValidatorRegistry", () => {
  let registry: MCFValidatorRegistry;
  let owner: SignerWithAddress;
  let nonOwner: SignerWithAddress;
  let validator1: SignerWithAddress;

  async function deployRegistry() {
    const [ownerSigner, nonOwnerSigner, validatorSigner] =
      await ethers.getSigners();
    const Registry = await ethers.getContractFactory("MCFValidatorRegistry");
    const reg = (await Registry.deploy()) as MCFValidatorRegistry;
    return {
      registry: reg,
      owner: ownerSigner,
      nonOwner: nonOwnerSigner,
      validator1: validatorSigner,
    };
  }

  beforeEach(async () => {
    ({ registry, owner, nonOwner, validator1 } = await deployRegistry());
  });

  // Test 1: Register validator → verifyValidator returns true
  it("registers a validator and verifyValidator returns true", async () => {
    const ttl = 365 * 24 * 3600; // 1 year in seconds
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-1"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);
    expect(await registry.verifyValidator(validator1.address)).to.equal(true);
  });

  // Test 2: Expired credential → verifyValidator returns false
  it("returns false for an expired credential", async () => {
    const ttl = 100; // 100 seconds
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-2"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);

    // Advance time past expiry
    await ethers.provider.send("evm_increaseTime", [ttl + 1]);
    await ethers.provider.send("evm_mine", []);

    expect(await registry.verifyValidator(validator1.address)).to.equal(false);
  });

  // Test 3: Revoked credential → verifyValidator returns false
  it("returns false for a revoked credential", async () => {
    const ttl = 365 * 24 * 3600;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-3"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);
    await registry.revokeValidator(validator1.address);
    expect(await registry.verifyValidator(validator1.address)).to.equal(false);
  });

  // Test 4: Renew credential → verifyValidator returns true after renewal
  it("renews an expired credential and verifyValidator returns true", async () => {
    const shortTtl = 100; // 100 seconds
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-4"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, shortTtl, sig);

    // Advance time past expiry
    await ethers.provider.send("evm_increaseTime", [shortTtl + 1]);
    await ethers.provider.send("evm_mine", []);

    // Confirm it's expired
    expect(await registry.verifyValidator(validator1.address)).to.equal(false);

    // Renew with a new TTL
    const newTtl = 365 * 24 * 3600;
    await registry.renewValidator(validator1.address, newTtl);

    expect(await registry.verifyValidator(validator1.address)).to.equal(true);
  });

  // Test 5: Register same address twice → revert
  it("reverts when registering the same address twice", async () => {
    const ttl = 365 * 24 * 3600;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-5"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);
    await expect(
      registry.registerValidator(validator1.address, docHash, ttl, sig)
    ).to.be.revertedWith("already registered");
  });

  // Test 6: Non-owner revoke → revert with OwnableUnauthorizedAccount
  it("reverts when non-owner tries to revoke a validator", async () => {
    const ttl = 365 * 24 * 3600;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-6"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);
    await expect(
      registry.connect(nonOwner).revokeValidator(validator1.address)
    ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
  });

  // Test 7: confirmGovernanceAction emits MultisigConfirmation
  it("emits MultisigConfirmation when owner calls confirmGovernanceAction", async () => {
    const txHash = ethers.keccak256(ethers.toUtf8Bytes("governance-tx-1"));
    await expect(registry.confirmGovernanceAction(txHash))
      .to.emit(registry, "MultisigConfirmation")
      .withArgs(owner.address, txHash);
  });

  // Test 8 (B2 boundary): expiry uses strict less-than, not <=
  it("returns false at exactly the expiry timestamp (strict <)", async () => {
    const ttl = 100;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-boundary"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);

    // Advance time to exactly the expiry second (not ttl + 1).
    await ethers.provider.send("evm_increaseTime", [ttl]);
    await ethers.provider.send("evm_mine", []);

    expect(await registry.verifyValidator(validator1.address)).to.equal(false);
  });

  // Test 9 (Phase 9a): signature mismatch → revert
  it("reverts when signature does not recover to validator address", async () => {
    const ttl = 365 * 24 * 3600;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-bad-sig"));
    // nonOwner signs the docHash; recovers to nonOwner, not validator1
    const wrongSig = await signDocHash(nonOwner, docHash, await registry.getAddress(), validator1.address);
    await expect(
      registry.registerValidator(validator1.address, docHash, ttl, wrongSig)
    ).to.be.revertedWith("invalid signature");
  });

  // Test 10 (V2 0.2): the v1 "before"-baseline vulnerability, demonstrated ON PURPOSE.
  // v1 + MockBridge are KEPT as the intentionally-vulnerable baseline for the Ronin
  // motivation. The hardened path is RegistryV2.executeRenew, which reverts
  // "revoked: cannot renew" (see registryv2.spec.ts "renew cannot reinstate revoked").
  it("VULNERABLE BY DESIGN: renewValidator silently reactivates a REVOKED key (Ronin failure mode; fixed in RegistryV2)", async () => {
    const ttl = 365 * 24 * 3600;
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("did-doc-revoked-renew"));
    const sig = await signDocHash(validator1, docHash, await registry.getAddress(), validator1.address);
    await registry.registerValidator(validator1.address, docHash, ttl, sig);

    await registry.revokeValidator(validator1.address); // key compromised -> revoked
    expect(await registry.verifyValidator(validator1.address)).to.equal(false);

    // A single owner "renews" the revoked key; v1 has no revoked check (:105).
    await registry.renewValidator(validator1.address, ttl);
    // ← the defect, preserved as baseline evidence: the revoked key is live again.
    expect(await registry.verifyValidator(validator1.address)).to.equal(true);
  });
});
