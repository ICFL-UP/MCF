import { expect } from "chai";
import { ethers, network } from "hardhat";

// V2 1.7: per-withdrawal gas must be CONSTANT under sustained load (no unbounded
// array scan). Fails against the array-pruning implementation, passes for buckets.
const T = ethers.parseEther("5000");
const W = 3600n;

describe("CircuitBreaker gas bound", () => {
  it("checkAndRecord gas is constant under sustained load", async () => {
    const [owner, gate, monitor] = await ethers.getSigners();
    const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
    const breaker = await CircuitBreaker.deploy(T, W, gate.address, monitor.address);

    const gasAt = async (): Promise<bigint> => {
      const tx = await breaker.connect(gate).checkAndRecord(ethers.parseEther("1"));
      return (await tx.wait())!.gasUsed;
    };

    // warm-up + spread 400 small records across ~2 windows of EVM time.
    // "early" samples record 250: past one full window (250*17 s > W + bucketWidth),
    // i.e. steady state, where all 61 bucket slots are populated. Sampling before
    // steady state (e.g. record 10) measures the one-time cold-start ramp of the
    // fixed accumulator, not growth in traffic volume.
    let early = 0n;
    let late = 0n;
    for (let i = 0; i < 400; i++) {
      await network.provider.send("evm_increaseTime", [17]);
      const g = await gasAt();
      if (i === 250) early = g;
      if (i === 399) late = g;
    }
    // constant-bound: the 400th record costs no more than the 250th (+10% slack for
    // cold/warm slot variance) and stays under an absolute per-call ceiling.
    // Ceiling calibrated to the EVM cost model of the 61-slot accumulator: each call
    // reads <= 122 cold storage slots (~256k gas) + base/writes/event ≈ 315k measured,
    // constant in traffic volume. The unbounded array implementation measures
    // ~1,106,000 gas by record 400 (and grows without bound), so 350k still fails it.
    expect(late).to.be.lessThanOrEqual((early * 110n) / 100n);
    expect(late).to.be.lessThan(350_000n);
  });
});
