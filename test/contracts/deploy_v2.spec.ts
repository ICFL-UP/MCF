import { expect } from "chai";
import { ethers } from "hardhat";
import { deployV2, LEDGER } from "../../scripts/deploy_v2";
import { signWithdrawal } from "./helpers"; // extracted in this task; see plan 21.1.1

describe("deploy_v2 script", () => {
  it("deploys and wires the full v2 stack; limiter/breaker share T and W", async () => {
    const d = await deployV2();
    // Post-0.4, T and W live ONLY on the breaker (phase-18 0.4: limiter's dead T/W
    // fields removed; 0.4's "shared parameters match" acceptance is discharged by the
    // fixture test phase-18 itself added). The reads below are a config read-back
    // smoke check on the freshly deployed stack: they pin that deployV2 wired the
    // ledger values, not a limiter-vs-breaker cross-check (impossible post-0.4).
    expect(await d.breaker.threshold()).to.equal(LEDGER.T);
    expect(await d.breaker.windowLength()).to.equal(LEDGER.W);
    expect(await d.limiter.capacity()).to.equal(LEDGER.B);
    expect(await d.limiter.refillRate()).to.equal(LEDGER.r);
    // all 9 validators registered and verifiable
    for (const v of d.validators) {
      expect(await d.registry.verifyValidator(v.address)).to.equal(true);
    }
  });

  it("a k-signed withdrawal succeeds through the freshly deployed stack", async () => {
    const d = await deployV2();
    await d.bridge.connect(d.deployer).deposit({ value: ethers.parseEther("100") });
    const recipient = (await ethers.getSigners())[16];
    const amount = ethers.parseEther("10");
    // signWithdrawal comes from ./helpers (extracted from bridgev2.spec.ts, per the plan note).
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const sigs = await signWithdrawal(d.validators, d.bridge, recipient.address, amount, 1n, deadline);
    await expect(d.bridge.withdraw(recipient.address, amount, 1n, deadline, sigs))
      .to.changeEtherBalance(recipient, amount);
  });
});
