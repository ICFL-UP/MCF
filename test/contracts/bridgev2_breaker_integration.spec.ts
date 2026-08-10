import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

// V2 task 0.1: the latch-rollback defect. Drives a VALUE-BREACHING sequence through
// BridgeV2.withdraw (the production path) across two transactions and asserts the
// breaker latch PERSISTS after the blocked tx.
//
// TEST-LOCAL params (NOT the locked ledger): B=3000 makes the value trip reachable
// through the bridge (B + r·W = 3000 + 3600 = 6600 > T = 5000). Under the canonical
// B=1000 the trip is structurally unreachable (4600 < 5000); re-parameterising the
// EVALUATION config is V2 task 1.2 / phase 19, not this test.
const B = ethers.parseEther("3000");
const r = ethers.parseEther("1");
const T = ethers.parseEther("5000");
const W = 3600n;
const K = 5; // bridge signature threshold (Ronin 5-of-9)
const N = 9; // validator set size
const M = 3; // governance threshold
const FAR_DEADLINE = 2n ** 63n; // effectively-infinite deadline for tests not about expiry

const OP_REGISTER = 0;

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

// k-of-n withdrawal message: keccak256(recipient, amount, nonce, deadline, chainId, bridge)
async function signWithdrawal(
  signer: SignerWithAddress,
  bridgeAddress: string,
  recipient: string,
  amount: bigint,
  nonce: number,
  deadline: bigint,
  chainId: bigint
): Promise<string> {
  const msgHash = ethers.solidityPackedKeccak256(
    ["address", "uint256", "uint256", "uint256", "uint256", "address"],
    [recipient, amount, nonce, deadline, chainId, bridgeAddress]
  );
  return signer.signMessage(ethers.getBytes(msgHash));
}

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

  // Fund the bridge. Funded from all[14] (an otherwise-unused signer): when the FULL
  // suite runs on one shared node, earlier specs drain all[0] below the 6500 ETH
  // needed here.
  await bridge.connect(all[14]).deposit({ value: ethers.parseEther("6500") });

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
    sigs.push(await signWithdrawal(v, bridgeAddr, recipient, amount, nonce, deadline, chainId));
  }
  return sigs;
}

describe("BridgeV2 × CircuitBreaker integration (value trip through withdraw)", () => {
  it("latch persists after a value-breaching withdraw; all later withdrawals blocked until reset", async () => {
    const f = await setupFixture();

    // tx1: drain the full burst B=3000; window outflow 3000 <= T, no trip.
    const sigs1 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, B, 1, f.chainId);
    await f.bridge.withdraw(f.recipient.address, B, 1, FAR_DEADLINE, sigs1);
    expect(await f.breaker.tripped()).to.equal(false);

    // Refill the bucket (3001 s * 1 ETH/s >= 3000) while staying inside the window
    // (3001 < W=3600), so tx1's record still counts toward the window outflow.
    await ethers.provider.send("evm_increaseTime", [3001]);
    await ethers.provider.send("evm_mine", []);

    // tx2: another 3000 pushes window outflow to 6000 > T=5000, the value breach.
    // (a) BLOCKED: the tx COMMITS (no revert) but transfers no ETH.
    const before = await ethers.provider.getBalance(f.recipient.address);
    const sigs2 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, B, 2, f.chainId);
    await expect(f.bridge.withdraw(f.recipient.address, B, 2, FAR_DEADLINE, sigs2))
      .to.emit(f.bridge, "WithdrawalBlocked")
      .withArgs(f.recipient.address, B, 2, "window threshold exceeded");
    expect(await ethers.provider.getBalance(f.recipient.address)).to.equal(before);
    // Conservative by design: the blocked attempt still burns its nonce.
    expect(await f.bridge.usedNonce(2)).to.equal(true);

    // (b) THE DEFECT UNDER TEST: the latch must survive the blocked tx.
    expect(await f.breaker.tripped()).to.equal(true);

    // (c) EVERY subsequent withdrawal reverts until governance reset.
    // Refill margin first: at exactly 1 block after tx2 the bucket holds ~1 ETH, a
    // zero-margin equality with the 1-ETH tx3 that could fail early with
    // "rate limit: bucket exhausted" under block-interval/timestamp drift. 10 s of
    // headroom removes that; the breaker's require(!tripped) is time-independent,
    // so the "breaker: tripped" assertion is unaffected.
    await ethers.provider.send("evm_increaseTime", [10]);
    await ethers.provider.send("evm_mine", []);
    const small = ethers.parseEther("1");
    const sigs3 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, small, 3, f.chainId);
    await expect(f.bridge.withdraw(f.recipient.address, small, 3, FAR_DEADLINE, sigs3))
      .to.be.revertedWith("breaker: tripped");

    // Governance reset (owner = deployer = default signer) clears latch + window;
    // advance past W so the bucket refills and old records age out; flow resumes.
    await f.breaker.reset();
    await ethers.provider.send("evm_increaseTime", [3601]);
    await ethers.provider.send("evm_mine", []);
    const sigs4 = await kSigs(f.validators, f.bridgeAddr, f.recipient.address, small, 4, f.chainId);
    await f.bridge.withdraw(f.recipient.address, small, 4, FAR_DEADLINE, sigs4);
  });
});
