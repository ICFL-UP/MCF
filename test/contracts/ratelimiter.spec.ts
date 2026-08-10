import { expect } from "chai";
import { ethers } from "hardhat";

// BOLT Phase 13: RateLimiter (token bucket)
// Symbols (locked): B = burst capacity [value], r = refill rate [value/second].
// T/W (per-window threshold/window length) live ONLY on the CircuitBreaker:
// single source of truth (V2 task 0.4); this contract has no copy.
// Defaults under test: B = 1000 ETH, r = 1 ETH/s.

const B = ethers.parseEther("1000"); // burst capacity (value)
const r = ethers.parseEther("1"); // refill rate (value / second)

async function deployLimiter() {
  const [owner, consumer, other] = await ethers.getSigners();
  const Limiter = await ethers.getContractFactory("RateLimiter");
  // constructor(B, r, consumer)
  const limiter = await Limiter.deploy(B, r, consumer.address);
  return { limiter, owner, consumer, other };
}

describe("RateLimiter", () => {
  it("exposes the locked parameters B and r (T, W live only on the CircuitBreaker)", async () => {
    const { limiter } = await deployLimiter();
    expect(await limiter.capacity()).to.equal(B);
    expect(await limiter.refillRate()).to.equal(r);
    // Dead-config removal (V2 0.4): no duplicated window symbols on the limiter.
    expect((limiter as any).windowThreshold).to.equal(undefined);
    expect((limiter as any).windowLength).to.equal(undefined);
  });

  it("admits a withdrawal within the bucket", async () => {
    const { limiter, consumer } = await deployLimiter();
    const amount = ethers.parseEther("100");
    await expect(limiter.connect(consumer).consume(amount)).to.not.be.reverted;
    expect(await limiter.available()).to.equal(B - amount);
  });

  it("admits at most B within a block — no same-block escape via refill (assumption 4)", async () => {
    const { limiter, consumer } = await deployLimiter();
    // Drain the full capacity B in one block.
    await limiter.connect(consumer).consume(B);
    // In the IMMEDIATELY following block (1s later) the bucket has refilled by at most
    // r * 1s = r, NOT a fresh full B. So an attacker cannot escape with > B per block:
    // attempting to consume more than the tiny refill reverts.
    await ethers.provider.send("evm_setNextBlockTimestamp", [
      (await ethers.provider.getBlock("latest"))!.timestamp + 1,
    ]);
    await ethers.provider.send("evm_mine", []);
    // available is now exactly r (1 ETH); consuming far more than the few seconds of
    // refill (100 ETH) must revert: the bucket has NOT refilled a fresh B.
    expect(await limiter.available()).to.equal(r);
    await expect(
      limiter.connect(consumer).consume(ethers.parseEther("100"))
    ).to.be.revertedWith("rate limit: bucket exhausted");
  });

  it("reverts a single oversized withdrawal larger than B", async () => {
    const { limiter, consumer } = await deployLimiter();
    await expect(
      limiter.connect(consumer).consume(B + ethers.parseEther("1"))
    ).to.be.revertedWith("rate limit: bucket exhausted");
  });

  it("refills at rate r over elapsed time", async () => {
    const { limiter, consumer } = await deployLimiter();
    await limiter.connect(consumer).consume(B); // empty the bucket
    expect(await limiter.available()).to.equal(0n);

    // Advance 200 seconds -> r * 200 = 200 ETH should be refilled.
    await ethers.provider.send("evm_increaseTime", [200]);
    await ethers.provider.send("evm_mine", []);
    expect(await limiter.available()).to.equal(ethers.parseEther("200"));
  });

  it("caps refill at capacity B (does not overfill)", async () => {
    const { limiter, consumer } = await deployLimiter();
    await limiter.connect(consumer).consume(ethers.parseEther("10"));
    // Advance a very long time; refill must clamp to B.
    await ethers.provider.send("evm_increaseTime", [10_000_000]);
    await ethers.provider.send("evm_mine", []);
    expect(await limiter.available()).to.equal(B);
  });

  it("only the authorised consumer can consume", async () => {
    const { limiter, other } = await deployLimiter();
    await expect(
      limiter.connect(other).consume(ethers.parseEther("1"))
    ).to.be.revertedWith("rate limit: not consumer");
  });

  // ----- V2 1.3: coverage gap tests (setConsumer auth + constructor guard) -----
  it("only the owner can set the consumer; owner update emits ConsumerUpdated", async () => {
    const { limiter, owner, other } = await deployLimiter();
    await expect(
      limiter.connect(other).setConsumer(other.address)
    ).to.be.revertedWithCustomError(limiter, "OwnableUnauthorizedAccount");
    await expect(limiter.connect(owner).setConsumer(other.address))
      .to.emit(limiter, "ConsumerUpdated")
      .withArgs(other.address);
    expect(await limiter.consumer()).to.equal(other.address);
  });

  it("constructor rejects a zero capacity B", async () => {
    const [, consumer] = await ethers.getSigners();
    const Limiter = await ethers.getContractFactory("RateLimiter");
    await expect(Limiter.deploy(0, r, consumer.address)).to.be.revertedWith(
      "B must be > 0"
    );
  });
});
