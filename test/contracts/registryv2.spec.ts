import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

// BOLT Phase 13: RegistryV2
// did:ethr + Verifiable Credential; ERC-1812-style status/revocation registry
// (revocation effective immediately); m-of-n THRESHOLD governance for lifecycle ops.
// verifyValidator(signer) -> active ∧ !expired ∧ !revoked, designed for PER-WITHDRAWAL use.

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

// Governance op type ids must match the contract.
const OP_REGISTER = 0;
const OP_REVOKE = 1;
const OP_RENEW = 2;
const OP_REINSTATE = 3;

async function deployRegistryV2(m: number, governorCount: number) {
  const all = await ethers.getSigners();
  const governors = all.slice(0, governorCount);
  const validators = all.slice(governorCount);
  const RegistryV2 = await ethers.getContractFactory("RegistryV2");
  const registry = await RegistryV2.deploy(
    governors.map((g) => g.address),
    m
  );
  return { registry, governors, validators };
}

// Helper: collect m approvals for an op and execute it.
async function governedRegister(
  registry: any,
  governors: SignerWithAddress[],
  m: number,
  validator: SignerWithAddress,
  ttl: number
) {
  const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-" + validator.address));
  const sig = await signDocHash(validator, docHash, await registry.getAddress(), validator.address);
  // op id binds the action params so approvals can't be replayed for a different op.
  const opId = await registry.computeOpId(OP_REGISTER, validator.address, docHash, ttl);
  for (let i = 0; i < m; i++) {
    await registry.connect(governors[i]).approve(opId);
  }
  await registry.connect(governors[0]).executeRegister(validator.address, docHash, ttl, sig);
  return { docHash, opId };
}

// Helper: collect m approvals for a Revoke op and execute it.
async function governedRevoke(
  registry: any,
  governors: SignerWithAddress[],
  m: number,
  validator: SignerWithAddress
) {
  const opId = await registry.computeOpId(OP_REVOKE, validator.address, ethers.ZeroHash, 0);
  for (let i = 0; i < m; i++) {
    await registry.connect(governors[i]).approve(opId);
  }
  await registry.connect(governors[0]).executeRevoke(validator.address);
  return opId;
}

// Helper: collect m approvals for a Reinstate op and execute it with a FRESH
// key-control signature over a NEW credential document.
async function governedReinstate(
  registry: any,
  governors: SignerWithAddress[],
  m: number,
  validator: SignerWithAddress,
  ttl: number,
  docLabel: string
) {
  const docHash = ethers.keccak256(ethers.toUtf8Bytes(docLabel));
  const sig = await signDocHash(validator, docHash, await registry.getAddress(), validator.address);
  const opId = await registry.computeOpId(OP_REINSTATE, validator.address, docHash, ttl);
  for (let i = 0; i < m; i++) {
    await registry.connect(governors[i]).approve(opId);
  }
  await registry.connect(governors[0]).executeReinstate(validator.address, docHash, ttl, sig);
  return { docHash, opId };
}

describe("RegistryV2", () => {
  it("m-of-n: a single governor cannot register alone (needs m approvals)", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-solo"));
    const sig = await signDocHash(v, docHash, await registry.getAddress(), v.address);
    const ttl = 3600;
    const opId = await registry.computeOpId(OP_REGISTER, v.address, docHash, ttl);
    // Only one governor approves.
    await registry.connect(governors[0]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeRegister(v.address, docHash, ttl, sig)
    ).to.be.revertedWith("gov: insufficient approvals");
  });

  it("m-of-n: a non-governor cannot approve", async () => {
    const { registry, validators } = await deployRegistryV2(3, 5);
    const opId = ethers.keccak256(ethers.toUtf8Bytes("any-op"));
    await expect(
      registry.connect(validators[0]).approve(opId)
    ).to.be.revertedWith("gov: not governor");
  });

  it("m-of-n: m distinct governors register a validator and verifyValidator is true", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);
    expect(await registry.verifyValidator(v.address)).to.equal(true);
  });

  it("verifyValidator returns false for an EXPIRED validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 100);
    expect(await registry.verifyValidator(v.address)).to.equal(true);
    await ethers.provider.send("evm_increaseTime", [101]);
    await ethers.provider.send("evm_mine", []);
    expect(await registry.verifyValidator(v.address)).to.equal(false);
  });

  it("verifyValidator returns false for a REVOKED validator and revocation is immediate", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const ttl = 365 * 24 * 3600;
    await governedRegister(registry, governors, m, v, ttl);
    expect(await registry.verifyValidator(v.address)).to.equal(true);

    // Governed revoke via the status registry: m approvals.
    const opId = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    for (let i = 0; i < m; i++) {
      await registry.connect(governors[i]).approve(opId);
    }
    await registry.connect(governors[0]).executeRevoke(v.address);

    // Immediate: the very next call is false (ERC-1812-style status registry).
    expect(await registry.verifyValidator(v.address)).to.equal(false);
    expect(await registry.isRevoked(v.address)).to.equal(true);
  });

  it("m-of-n: a single governor cannot revoke alone", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);
    const opId = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    await registry.connect(governors[0]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeRevoke(v.address)
    ).to.be.revertedWith("gov: insufficient approvals");
  });

  it("m-of-n governed renew restores validity after expiry", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 100);
    await ethers.provider.send("evm_increaseTime", [101]);
    await ethers.provider.send("evm_mine", []);
    expect(await registry.verifyValidator(v.address)).to.equal(false);

    const newTtl = 365 * 24 * 3600;
    const opId = await registry.computeOpId(OP_RENEW, v.address, ethers.ZeroHash, newTtl);
    for (let i = 0; i < m; i++) {
      await registry.connect(governors[i]).approve(opId);
    }
    await registry.connect(governors[0]).executeRenew(v.address, newTtl);
    expect(await registry.verifyValidator(v.address)).to.equal(true);
  });

  it("renew CANNOT silently reinstate a revoked (compromised) key", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const ttl = 365 * 24 * 3600;
    await governedRegister(registry, governors, m, v, ttl);

    // Governed revoke.
    const revId = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(revId);
    await registry.connect(governors[0]).executeRevoke(v.address);
    expect(await registry.verifyValidator(v.address)).to.equal(false);

    // A fully-approved renew MUST NOT un-revoke the key: reinstating a revoked
    // identity is a distinct intentional action, not a renewal (G6).
    const newTtl = 365 * 24 * 3600;
    const renId = await registry.computeOpId(OP_RENEW, v.address, ethers.ZeroHash, newTtl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(renId);
    await expect(
      registry.connect(governors[0]).executeRenew(v.address, newTtl)
    ).to.be.revertedWith("revoked: cannot renew");

    expect(await registry.verifyValidator(v.address)).to.equal(false);
    expect(await registry.isRevoked(v.address)).to.equal(true);
  });

  it("govNonce: the same op gets a fresh opId each round — a validator is not unrevokable after one revoke", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 365 * 24 * 3600);

    // First governed revoke.
    const id1 = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(id1);
    await registry.connect(governors[0]).executeRevoke(v.address);

    // The nonce advanced, so the SAME params now hash to a new opId (old one stays
    // consumed, replay-safe). A second governance round can revoke again rather than
    // reverting 'gov: already executed' (the lifetime-burn bug).
    const id2 = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    expect(id2).to.not.equal(id1);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(id2);
    await registry.connect(governors[0]).executeRevoke(v.address);
    expect(await registry.isRevoked(v.address)).to.equal(true);
  });

  // ----- V2 1.3: coverage gap tests (constructor guards + lifecycle negatives) -----
  // NOTE on "gov: already executed": with the per-validator govNonce folded into every
  // opId, a SUCCESSFUL execute always advances the nonce, so computeOpId never returns
  // an already-executed opId again; the guard is defence-in-depth and its revert
  // direction is unreachable through the public API. It is documented (not tested).

  it("constructor rejects an empty governor set", async () => {
    const RegistryV2 = await ethers.getContractFactory("RegistryV2");
    await expect(RegistryV2.deploy([], 1)).to.be.revertedWith("gov: no governors");
  });

  it("constructor rejects a zero or oversized threshold", async () => {
    const [g1, g2] = await ethers.getSigners();
    const RegistryV2 = await ethers.getContractFactory("RegistryV2");
    await expect(
      RegistryV2.deploy([g1.address, g2.address], 0)
    ).to.be.revertedWith("gov: bad threshold");
    await expect(
      RegistryV2.deploy([g1.address, g2.address], 3)
    ).to.be.revertedWith("gov: bad threshold");
  });

  it("constructor rejects a zero-address governor", async () => {
    const [g1] = await ethers.getSigners();
    const RegistryV2 = await ethers.getContractFactory("RegistryV2");
    await expect(
      RegistryV2.deploy([g1.address, ethers.ZeroAddress], 2)
    ).to.be.revertedWith("gov: zero governor");
  });

  it("constructor rejects a duplicate governor", async () => {
    const [g1] = await ethers.getSigners();
    const RegistryV2 = await ethers.getContractFactory("RegistryV2");
    await expect(
      RegistryV2.deploy([g1.address, g1.address], 2)
    ).to.be.revertedWith("gov: dup governor");
  });

  it("a governor cannot approve the same opId twice", async () => {
    const { registry, governors } = await deployRegistryV2(3, 5);
    const opId = ethers.keccak256(ethers.toUtf8Bytes("double-approve"));
    await registry.connect(governors[0]).approve(opId);
    await expect(
      registry.connect(governors[0]).approve(opId)
    ).to.be.revertedWith("gov: already approved");
  });

  it("a non-governor cannot execute lifecycle ops", async () => {
    const { registry, validators } = await deployRegistryV2(3, 5);
    const v = validators[0];
    await expect(
      registry.connect(v).executeRevoke(v.address)
    ).to.be.revertedWith("gov: not governor");
    await expect(
      registry.connect(v).executeRenew(v.address, 3600)
    ).to.be.revertedWith("gov: not governor");
  });

  it("executeRegister rejects an ALREADY-registered validator (fresh opId round)", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const { docHash } = await governedRegister(registry, governors, m, v, 3600);
    // govNonce advanced, so the same params hash to a NEW opId: approve that round
    // fully; the execute must then fail on the already-registered guard.
    const sig = await signDocHash(v, docHash, await registry.getAddress(), v.address);
    const opId2 = await registry.computeOpId(OP_REGISTER, v.address, docHash, 3600);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId2);
    await expect(
      registry.connect(governors[0]).executeRegister(v.address, docHash, 3600, sig)
    ).to.be.revertedWith("already registered");
  });

  it("executeRegister rejects a signature that does not recover to the validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const impostor = validators[1];
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-forged"));
    // Signed by the WRONG key: recovery cannot yield v.address.
    const badSig = await signDocHash(impostor, docHash, await registry.getAddress(), v.address);
    const ttl = 3600;
    const opId = await registry.computeOpId(OP_REGISTER, v.address, docHash, ttl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeRegister(v.address, docHash, ttl, badSig)
    ).to.be.revertedWith("invalid signature");
  });

  it("executeRevoke rejects an UNREGISTERED validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const ghost = validators[3]; // never registered
    const opId = await registry.computeOpId(OP_REVOKE, ghost.address, ethers.ZeroHash, 0);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeRevoke(ghost.address)
    ).to.be.revertedWith("not registered");
  });

  it("executeRenew rejects an UNREGISTERED validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const ghost = validators[3]; // never registered
    const newTtl = 3600;
    const opId = await registry.computeOpId(OP_RENEW, ghost.address, ethers.ZeroHash, newTtl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeRenew(ghost.address, newTtl)
    ).to.be.revertedWith("not registered");
  });

  // ----- V2 reinstatement: revoked keys come back only via a distinct governed op -----

  it("revoke then governed reinstate makes the validator valid again", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);
    await governedRevoke(registry, governors, m, v);
    expect(await registry.verifyValidator(v.address)).to.equal(false);

    const newTtl = 7200;
    const { docHash } = await governedReinstate(registry, governors, m, v, newTtl, "doc-reinstate");
    expect(await registry.verifyValidator(v.address)).to.equal(true);
    expect(await registry.isRevoked(v.address)).to.equal(false);
    const rec = await registry.validators(v.address);
    expect(rec.didDocumentHash).to.equal(docHash);
    const block = await ethers.provider.getBlock("latest");
    expect(rec.expiresAt).to.equal(BigInt(block!.timestamp) + BigInt(newTtl));
  });

  it("m-of-n: a single governor cannot reinstate alone", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);
    await governedRevoke(registry, governors, m, v);

    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-solo-reinstate"));
    const sig = await signDocHash(v, docHash, await registry.getAddress(), v.address);
    const ttl = 3600;
    const opId = await registry.computeOpId(OP_REINSTATE, v.address, docHash, ttl);
    await registry.connect(governors[0]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeReinstate(v.address, docHash, ttl, sig)
    ).to.be.revertedWith("gov: insufficient approvals");
  });

  it("executeReinstate rejects an ACTIVE (non-revoked) validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);

    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-active-reinstate"));
    const sig = await signDocHash(v, docHash, await registry.getAddress(), v.address);
    const ttl = 3600;
    const opId = await registry.computeOpId(OP_REINSTATE, v.address, docHash, ttl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeReinstate(v.address, docHash, ttl, sig)
    ).to.be.revertedWith("not revoked");
  });

  it("executeReinstate rejects a NEVER-registered validator", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const ghost = validators[3]; // never registered
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-ghost-reinstate"));
    const sig = await signDocHash(ghost, docHash, await registry.getAddress(), ghost.address);
    const ttl = 3600;
    const opId = await registry.computeOpId(OP_REINSTATE, ghost.address, docHash, ttl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeReinstate(ghost.address, docHash, ttl, sig)
    ).to.be.revertedWith("not registered");
  });

  it("executeReinstate rejects a stale/wrong key-control signature", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    const impostor = validators[1];
    const { docHash: oldDocHash } = await governedRegister(registry, governors, m, v, 3600);
    await governedRevoke(registry, governors, m, v);

    const newDocHash = ethers.keccak256(ethers.toUtf8Bytes("doc-fresh"));
    const ttl = 3600;

    // Stale: a signature over the OLD credential document does not authorise the
    // NEW binding: recovery yields the wrong address for newDocHash.
    const staleSig = await signDocHash(v, oldDocHash, await registry.getAddress(), v.address);
    const opId1 = await registry.computeOpId(OP_REINSTATE, v.address, newDocHash, ttl);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId1);
    await expect(
      registry.connect(governors[0]).executeReinstate(v.address, newDocHash, ttl, staleSig)
    ).to.be.revertedWith("invalid signature");

    // Wrong key: signed by an impostor, recovery cannot yield v.address.
    const badSig = await signDocHash(impostor, newDocHash, await registry.getAddress(), v.address);
    await expect(
      registry.connect(governors[0]).executeReinstate(v.address, newDocHash, ttl, badSig)
    ).to.be.revertedWith("invalid signature");
  });

  it("executeReinstate rejects a zero ttl", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);
    await governedRevoke(registry, governors, m, v);

    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-zero-ttl"));
    const sig = await signDocHash(v, docHash, await registry.getAddress(), v.address);
    const opId = await registry.computeOpId(OP_REINSTATE, v.address, docHash, 0);
    for (let i = 0; i < m; i++) await registry.connect(governors[i]).approve(opId);
    await expect(
      registry.connect(governors[0]).executeReinstate(v.address, docHash, 0, sig)
    ).to.be.revertedWith("zero ttl");
  });

  it("full cycle register -> revoke -> reinstate -> revoke again (opId freshness)", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 3600);

    // First revoke at nonce k.
    const revId1 = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    await governedRevoke(registry, governors, m, v);

    await governedReinstate(registry, governors, m, v, 3600, "doc-cycle");
    expect(await registry.verifyValidator(v.address)).to.equal(true);

    // Both revoke and reinstate advanced the nonce, so the second Revoke opId is
    // fresh; the cycle never collides with a consumed opId.
    const revId2 = await registry.computeOpId(OP_REVOKE, v.address, ethers.ZeroHash, 0);
    expect(revId2).to.not.equal(revId1);
    await governedRevoke(registry, governors, m, v);
    expect(await registry.isRevoked(v.address)).to.equal(true);
    expect(await registry.verifyValidator(v.address)).to.equal(false);
  });

  it("expiry after reinstate honors the NEW ttl, not the original one", async () => {
    const m = 3;
    const { registry, governors, validators } = await deployRegistryV2(m, 5);
    const v = validators[0];
    await governedRegister(registry, governors, m, v, 365 * 24 * 3600);
    await governedRevoke(registry, governors, m, v);

    const newTtl = 100;
    await governedReinstate(registry, governors, m, v, newTtl, "doc-short-ttl");
    expect(await registry.verifyValidator(v.address)).to.equal(true);

    await ethers.provider.send("evm_increaseTime", [101]);
    await ethers.provider.send("evm_mine", []);
    expect(await registry.verifyValidator(v.address)).to.equal(false);
  });
});
