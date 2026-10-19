import { expect } from "chai";
import { ethers } from "hardhat";

// BOLT Phase 13: CircuitBreaker (synchronous / in-path)
// Trips when cumulative sliding-window outflow > T, OR when the authorised monitor
// signals. When tripped, checkAndRecord() reverts in the SAME call path (not an async
// pause flag inspected later). Governance/owner can reset.

const T = ethers.parseEther("5000"); // per-window threshold (value)
const W = 3600n; // window length (seconds)

async function deployBreaker() {
  const [owner, gate, monitor, other] = await ethers.getSigners();
  const Breaker = await ethers.getContractFactory("CircuitBreaker");
  // constructor(T, W, gate, monitor): gate = authorised in-path caller (the bridge)
  const breaker = await Breaker.deploy(T, W, gate.address, monitor.address);
  return { breaker, owner, gate, monitor, other };
}

describe("CircuitBreaker", () => {
  it("exposes T and W and starts untripped", async () => {
    const { breaker } = await deployBreaker();
    expect(await breaker.threshold()).to.equal(T);
    expect(await breaker.windowLength()).to.equal(W);
    expect(await breaker.tripped()).to.equal(false);
  });

  it("an untripped path flows normally (outflow <= T)", async () => {
    const { breaker, gate } = await deployBreaker();
    await expect(breaker.connect(gate).checkAndRecord(ethers.parseEther("1000")))
      .to.not.be.reverted;
    expect(await breaker.tripped()).to.equal(false);
    expect(await breaker.windowOutflow()).to.equal(ethers.parseEther("1000"));
  });

  it("trips when cumulative window outflow exceeds T and blocks further execution in the same path", async () => {
    const { breaker, gate } = await deployBreaker();
    await breaker.connect(gate).checkAndRecord(ethers.parseEther("3000"));
    // Two-phase trip (V2 0.1): the breaching call LATCHES tripped=true and returns
    // breached=true WITHOUT reverting; the gate (BridgeV2) skips the transfer and
    // COMMITS, so the latch persists. Direct EOA call here: the tx simply commits.
    expect(
      await breaker.connect(gate).checkAndRecord.staticCall(ethers.parseEther("3000"))
    ).to.equal(true);
    await breaker.connect(gate).checkAndRecord(ethers.parseEther("3000"));
    expect(await breaker.tripped()).to.equal(true);
    // Once latched, any subsequent record is blocked SYNCHRONOUSLY in the same path.
    await expect(
      breaker.connect(gate).checkAndRecord(ethers.parseEther("1"))
    ).to.be.revertedWith("breaker: tripped");
  });

  it("an authorised monitor signal also trips it", async () => {
    const { breaker, gate, monitor } = await deployBreaker();
    await breaker.connect(monitor).trip();
    expect(await breaker.tripped()).to.equal(true);
    // In-path execution is now blocked synchronously.
    await expect(
      breaker.connect(gate).checkAndRecord(ethers.parseEther("1"))
    ).to.be.revertedWith("breaker: tripped");
  });

  it("an unauthorised caller cannot trip", async () => {
    const { breaker, other } = await deployBreaker();
    await expect(breaker.connect(other).trip()).to.be.revertedWith(
      "breaker: not monitor"
    );
  });

  it("an unauthorised caller cannot reset; owner can reset", async () => {
    const { breaker, owner, monitor, other, gate } = await deployBreaker();
    await breaker.connect(monitor).trip();
    await expect(breaker.connect(other).reset()).to.be.revertedWith(
      "breaker: not governance"
    );
    await breaker.connect(owner).reset();
    expect(await breaker.tripped()).to.equal(false);
    // Flows again after reset.
    await expect(breaker.connect(gate).checkAndRecord(ethers.parseEther("1")))
      .to.not.be.reverted;
  });

  it("only the authorised gate can record outflow", async () => {
    const { breaker, other } = await deployBreaker();
    await expect(
      breaker.connect(other).checkAndRecord(ethers.parseEther("1"))
    ).to.be.revertedWith("breaker: not gate");
  });

  it("forgets outflow older than the window W (sliding window)", async () => {
    const { breaker, gate } = await deployBreaker();
    await breaker.connect(gate).checkAndRecord(ethers.parseEther("4000"));
    // Advance past the window so the prior outflow ages out.
    await ethers.provider.send("evm_increaseTime", [Number(W) + 60]); // + one bucketWidth: with 61 slots that is exactly the summed-span length, so full expiry is guaranteed
    await ethers.provider.send("evm_mine", []);
    // A fresh 4000 now should NOT trip (old 4000 has aged out): 4000 <= T.
    await expect(breaker.connect(gate).checkAndRecord(ethers.parseEther("4000")))
      .to.not.be.reverted;
    expect(await breaker.tripped()).to.equal(false);
  });

  // ----- V2 1.3: coverage gap tests (setGate/setMonitor auth + constructor guard) -----
  it("only the owner can set the gate; owner update emits GateUpdated", async () => {
    const { breaker, owner, other } = await deployBreaker();
    await expect(
      breaker.connect(other).setGate(other.address)
    ).to.be.revertedWithCustomError(breaker, "OwnableUnauthorizedAccount");
    await expect(breaker.connect(owner).setGate(other.address))
      .to.emit(breaker, "GateUpdated")
      .withArgs(other.address);
    expect(await breaker.gate()).to.equal(other.address);
  });

  it("only the owner can set the monitor; owner update emits MonitorUpdated", async () => {
    const { breaker, owner, other } = await deployBreaker();
    await expect(
      breaker.connect(other).setMonitor(other.address)
    ).to.be.revertedWithCustomError(breaker, "OwnableUnauthorizedAccount");
    await expect(breaker.connect(owner).setMonitor(other.address))
      .to.emit(breaker, "MonitorUpdated")
      .withArgs(other.address);
    expect(await breaker.monitor()).to.equal(other.address);
  });

  it("constructor rejects a window length that does not divide into the 60 buckets", async () => {
    const [, gate, monitor] = await ethers.getSigners();
    const Breaker = await ethers.getContractFactory("CircuitBreaker");
    await expect(
      Breaker.deploy(T, 3601n, gate.address, monitor.address)
    ).to.be.revertedWith("breaker: W not bucket-divisible");
  });

  it("bucketed window over-approximates: record retained up to one bucketWidth past W", async () => {
    const [, gate, monitor] = await ethers.getSigners();
    const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
    const breaker = await CircuitBreaker.deploy(T, W, gate.address, monitor.address);

    const tx = await breaker.connect(gate).checkAndRecord(ethers.parseEther("100"));
    const receipt = await tx.wait();
    const t0 = (await ethers.provider.getBlock(receipt!.blockNumber))!.timestamp;

    // At exactly t0 + W the record sits in epoch (current − WINDOW_BUCKETS), still
    // inside the 61-slot summed span; the exact-window version would be at the
    // boundary. Pin the timestamp (not evm_increaseTime) to avoid epoch drift.
    await ethers.provider.send("evm_setNextBlockTimestamp", [t0 + Number(W)]);
    await ethers.provider.send("evm_mine", []);
    expect(await breaker.windowOutflow()).to.equal(ethers.parseEther("100"));

    // One more bucketWidth (60 s): the slot ages out of the summed span entirely.
    await ethers.provider.send("evm_setNextBlockTimestamp", [t0 + Number(W) + 60]);
    await ethers.provider.send("evm_mine", []);
    expect(await breaker.windowOutflow()).to.equal(0n);
  });
});
