import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { signWithdrawalSingle } from "./helpers";

// BOLT Phase 13: BridgeV2 (the value-bearing exit path)
// k-of-n ECDSA over keccak256(recipient, amount, nonce, deadline, chainId, address(this));
// per-withdrawal RegistryV2.verifyValidator on EVERY signer; nonce replay protection;
// nonReentrant; checks-effects-interactions; routed through RateLimiter + CircuitBreaker.

const B = ethers.parseEther("1000");
const r = ethers.parseEther("1");
const T = ethers.parseEther("5000");
const W = 3600n;
const K = 5; // compromised threshold (Ronin 5-of-9)
const N = 9; // validator set size
const M = 3; // governance threshold (m-of-n)
const FAR_DEADLINE = 2n ** 63n; // effectively-infinite deadline for tests not about expiry

const OP_REGISTER = 0;
const OP_REVOKE = 1;

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

// The k-of-n withdrawal digest construction lives in ./helpers (signWithdrawalSingle,
// extracted in Phase 21 task 21.1.1: single source of truth, do not re-inline it).

async function setupFixture() {
  const all = await ethers.getSigners();
  const governors = all.slice(0, M); // m-of-n governors
  const validators = all.slice(M, M + N); // n validators
  const monitor = all[M + N];
  const recipient = all[M + N + 1];

  const chainId = (await ethers.provider.getNetwork()).chainId;

  // RegistryV2 with m-of-n governance.
  const RegistryV2 = await ethers.getContractFactory("RegistryV2");
  const registry = await RegistryV2.deploy(governors.map((g) => g.address), M);
  const registryAddr = await registry.getAddress();

  // Register all n validators via governed register.
  for (const v of validators) {
    const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc-" + v.address));
    const sig = await signDocHash(v, docHash, registryAddr, v.address);
    const ttl = 365 * 24 * 3600;
    const opId = await registry.computeOpId(OP_REGISTER, v.address, docHash, ttl);
    for (let i = 0; i < M; i++) await registry.connect(governors[i]).approve(opId);
    await registry.connect(governors[0]).executeRegister(v.address, docHash, ttl, sig);
  }

  // RateLimiter + CircuitBreaker (consumer/gate set to the bridge after deploy).
  const RateLimiter = await ethers.getContractFactory("RateLimiter");
  const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
  const limiter = await RateLimiter.deploy(B, r, ethers.ZeroAddress);
  const breaker = await CircuitBreaker.deploy(T, W, ethers.ZeroAddress, monitor.address);

  // BridgeV2.
  const BridgeV2 = await ethers.getContractFactory("BridgeV2");
  const bridge = await BridgeV2.deploy(
    registryAddr,
    await limiter.getAddress(),
    await breaker.getAddress(),
    K
  );
  const bridgeAddr = await bridge.getAddress();

  // Wire the bridge as the authorised consumer/gate.
  await limiter.setConsumer(bridgeAddr);
  await breaker.setGate(bridgeAddr);

  // Fund the bridge.
  await bridge.connect(all[0]).deposit({ value: ethers.parseEther("500") });

  return {
    registry, limiter, breaker, bridge, bridgeAddr, registryAddr,
    governors, validators, monitor, recipient, chainId, all,
  };
}

// Produce `count` signatures, ORDERED by ascending signer address (BridgeV2 requires
// strictly-increasing signers to guarantee distinctness in one pass).
async function kSigs(
  validators: SignerWithAddress[],
  bridgeAddr: string,
  recipient: string,
  amount: bigint,
  nonce: number,
  chainId: bigint,
  deadline: bigint = FAR_DEADLINE,
  count = K
) {
  const chosen = validators.slice(0, count);
  const sorted = [...chosen].sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
  );
  const sigs: string[] = [];
  for (const v of sorted) {
    sigs.push(await signWithdrawalSingle(v, bridgeAddr, recipient, amount, nonce, deadline, chainId));
  }
  return sigs;
}

// Sort an arbitrary set of (signer, signature) so signatures are in ascending-signer order.
async function sortedSigsFor(
  signers: SignerWithAddress[],
  bridgeAddr: string,
  recipient: string,
  amount: bigint,
  nonce: number,
  chainId: bigint,
  deadline: bigint = FAR_DEADLINE
) {
  const sorted = [...signers].sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
  );
  const sigs: string[] = [];
  for (const v of sorted) {
    sigs.push(await signWithdrawalSingle(v, bridgeAddr, recipient, amount, nonce, deadline, chainId));
  }
  return sigs;
}

describe("BridgeV2", () => {
  it("executes a withdrawal with k valid ECDSA sigs and transfers ETH", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 1;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId);

    const before = await ethers.provider.getBalance(f.recipient.address);
    await f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs);
    const after = await ethers.provider.getBalance(f.recipient.address);
    expect(after - before).to.equal(amount);
  });

  it("reverts with FEWER than k sigs", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 2;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId, FAR_DEADLINE, K - 1);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("bridge: insufficient signatures");
  });

  it("reverts on a DUPLICATE signer", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 3;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId);
    sigs[K - 1] = sigs[0]; // duplicate the first signer's signature
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("bridge: duplicate or unordered signer");
  });

  it("reverts on a WRONG / non-registered signer", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 4;
    // k signers but one is a non-registered signer (a governor, not a validator).
    const set = [...f.validators.slice(0, K - 1), f.governors[0]];
    const sigs = await sortedSigsFor(set, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("bridge: signer not authorized");
  });

  it("reverts on a REPLAYED nonce", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 5;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId);
    await f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("bridge: nonce used");
  });

  it("reverts on a WRONG chainId", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 6;
    const wrongChain = f.chainId + 1n;
    // Sigs are over the WRONG chainId, so on-chain recovery yields different addresses
    // (not registered validators) -> rejected. Provide them in valid k-count, sorted by
    // the (wrong) signing, but ordering is by RECOVERED address on-chain, which will be
    // garbage; to isolate the chainId failure we just send k sigs from k validators.
    const sigs = await sortedSigsFor(
      f.validators.slice(0, K), f.bridgeAddr, f.recipient.address, amount, nonce, wrongChain
    );
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.reverted; // wrong chainId -> recovered addrs unauthorized / unordered

  });

  it("rejects a reentrancy attempt by a malicious recipient", async () => {
    const f = await setupFixture();
    const Attacker = await ethers.getContractFactory("ReentrantAttacker");
    const attacker = await Attacker.deploy(f.bridgeAddr);
    const attackerAddr = await attacker.getAddress();

    const amount = ethers.parseEther("10");
    const nonce = 7;
    const sigs = await kSigs(f.validators, f.bridgeAddr, attackerAddr, amount, nonce, f.chainId);
    await attacker.arm(nonce, FAR_DEADLINE, sigs);
    // The recipient re-enters on receive; nonReentrant + nonce-used must make it revert.
    await expect(
      f.bridge.withdraw(attackerAddr, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.reverted;
  });

  // ----- rate limiter wiring -----
  it("routes the value exit through the RateLimiter (exceeding the bucket reverts)", async () => {
    const f = await setupFixture();
    // Drain the bucket: withdraw B in one go, then try more before refill.
    const nonce1 = 10;
    const sigs1 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, B, nonce1, f.chainId);
    // Bridge funded with 500 ETH only; B=1000. Top it up so the limiter (not balance) is the binding constraint.
    await f.bridge.connect(f.all[0]).deposit({ value: ethers.parseEther("1000") });
    await f.bridge.withdraw(f.recipient.address, B, nonce1, FAR_DEADLINE, sigs1); // bucket -> 0

    const nonce2 = 11;
    const amount2 = ethers.parseEther("100");
    const sigs2 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount2, nonce2, f.chainId);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount2, nonce2, FAR_DEADLINE, sigs2)
    ).to.be.revertedWith("rate limit: bucket exhausted");
  });

  // ----- circuit breaker wiring -----
  it("a monitor trip blocks withdrawals synchronously in-path", async () => {
    const f = await setupFixture();
    await f.breaker.connect(f.monitor).trip();
    const amount = ethers.parseEther("10");
    const nonce = 20;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("breaker: tripped");
  });

  // ----- 13.9 (G6 hole): stolen-but-revoked key rejected on EVERY withdrawal -----
  it("rejects a withdrawal signed by a stolen-but-revoked key (G6)", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");

    // First withdrawal succeeds with validators[0..K-1].
    const nonceA = 30;
    const sigsA = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonceA, f.chainId);
    await f.bridge.withdraw(f.recipient.address, amount, nonceA, FAR_DEADLINE, sigsA);

    // Now revoke validators[0] mid-flight via m-of-n governance (key compromised).
    const victim = f.validators[0];
    const opId = await f.registry.computeOpId(OP_REVOKE, victim.address, ethers.ZeroHash, 0);
    for (let i = 0; i < M; i++) await f.registry.connect(f.governors[i]).approve(opId);
    await f.registry.connect(f.governors[0]).executeRevoke(victim.address);

    // A new withdrawal whose signer set still includes the revoked validators[0] must
    // be rejected: verifyValidator is checked PER WITHDRAWAL.
    const nonceB = 31;
    const sigsB = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonceB, f.chainId);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonceB, FAR_DEADLINE, sigsB)
    ).to.be.revertedWith("bridge: signer not authorized");

    // But a fresh signer set EXCLUDING the revoked key (validators[1..K]) still works.
    const nonceC = 32;
    const fresh = f.validators.slice(1, 1 + K);
    const sigsC = await kSigs(fresh, f.bridgeAddr, f.recipient.address, amount, nonceC, f.chainId);
    await f.bridge.withdraw(f.recipient.address, amount, nonceC, FAR_DEADLINE, sigsC);
  });

  // ----- V2 0.3: input validation + signature deadline -----
  it("reverts a withdrawal past its signature deadline", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("10");
    const nonce = 40;
    const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
    const deadline = now + 100n;
    const sigs = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, amount, nonce, f.chainId, deadline);
    await ethers.provider.send("evm_increaseTime", [101]);
    await ethers.provider.send("evm_mine", []);
    await expect(
      f.bridge.withdraw(f.recipient.address, amount, nonce, deadline, sigs)
    ).to.be.revertedWith("bridge: expired deadline");
  });

  it("reverts on a ZERO recipient", async () => {
    const f = await setupFixture();
    await expect(
      f.bridge.withdraw(ethers.ZeroAddress, ethers.parseEther("10"), 41, FAR_DEADLINE, [])
    ).to.be.revertedWith("bridge: zero recipient");
  });

  it("reverts on a ZERO amount", async () => {
    const f = await setupFixture();
    await expect(
      f.bridge.withdraw(f.recipient.address, 0, 42, FAR_DEADLINE, [])
    ).to.be.revertedWith("bridge: zero amount");
  });

  // ----- V2 1.3: coverage gap tests -----
  it("receive(): plain ETH transfers to the bridge emit Deposit", async () => {
    const f = await setupFixture();
    const amount = ethers.parseEther("5");
    await expect(
      f.all[0].sendTransaction({ to: f.bridgeAddr, value: amount })
    )
      .to.emit(f.bridge, "Deposit")
      .withArgs(f.all[0].address, amount);
  });

  it("reverts 'bridge: transfer failed' when the recipient rejects ETH", async () => {
    const f = await setupFixture();
    const rejecter = await (
      await ethers.getContractFactory("RejectingRecipient")
    ).deploy();
    const rejecterAddr = await rejecter.getAddress();
    const amount = ethers.parseEther("1");
    const nonce = 999;
    const sigs = await kSigs(f.validators, f.bridgeAddr, rejecterAddr, amount, nonce, f.chainId);
    await expect(
      f.bridge.withdraw(rejecterAddr, amount, nonce, FAR_DEADLINE, sigs)
    ).to.be.revertedWith("bridge: transfer failed");
  });

  // ----- V2 0.4: single source of truth for the theorem symbols T, W -----
  it("T and W have a single on-chain source of truth (the CircuitBreaker)", async () => {
    const f = await setupFixture();
    // The theorem's window symbols exist exactly once in the deployed system…
    expect(await f.breaker.threshold()).to.equal(T);
    expect(await f.breaker.windowLength()).to.equal(W);
    // …and the RateLimiter no longer duplicates them (dead-config removal):
    // a mis-wired deploy cannot have two disagreeing (T, W) copies.
    expect((f.limiter as any).windowThreshold).to.equal(undefined);
    expect((f.limiter as any).windowLength).to.equal(undefined);
  });
});
