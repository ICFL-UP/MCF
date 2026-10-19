import { expect } from "chai";
import { ethers } from "hardhat";
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

async function deployRegistryWithValidators(count: number) {
  const [owner, ...signers] = await ethers.getSigners();
  const Registry = await ethers.getContractFactory("MCFValidatorRegistry");
  const registry = await Registry.deploy();
  const registryAddress = await registry.getAddress();
  const docHash = ethers.keccak256(ethers.toUtf8Bytes("doc"));
  for (let i = 0; i < count; i++) {
    const sig = await signDocHash(signers[i], docHash, registryAddress, signers[i].address);
    await registry.registerValidator(signers[i].address, docHash, 3600, sig);
  }
  return { registry, owner, signers };
}

async function deployBridge(registry: any, threshold: number, monitor: string) {
  const Bridge = await ethers.getContractFactory("MockBridge");
  return Bridge.deploy(await registry.getAddress(), threshold, monitor);
}

describe("MockBridge", () => {
  it("is executable after 5 valid confirmations", async () => {
    const { registry, signers } = await deployRegistryWithValidators(5);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    const recipient = signers[5];
    const value = ethers.parseEther("1.0");

    const receipt = await (await bridge.submitTransaction(recipient.address, value)).wait();
    const hash = receipt!.logs[0].topics[2]; // WithdrawalRequested(to indexed, value, txHash indexed, nonce)
    for (let i = 0; i < 5; i++) {
      await bridge.connect(signers[i]).confirmTransaction(hash);
    }
    expect(await bridge.isExecutable(hash)).to.be.true;
  });

  it("reverts when expired validator confirms", async () => {
    const { registry, signers } = await deployRegistryWithValidators(1);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    const receipt = await (
      await bridge.submitTransaction(signers[1].address, ethers.parseEther("1.0"))
    ).wait();
    const hash = receipt!.logs[0].topics[2];

    await ethers.provider.send("evm_increaseTime", [3601]);
    await ethers.provider.send("evm_mine", []);

    await expect(bridge.connect(signers[0]).confirmTransaction(hash)).to.be.revertedWith(
      "validator not authorized"
    );
  });

  it("is not executable with fewer than threshold confirmations", async () => {
    const { registry, signers } = await deployRegistryWithValidators(4);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    const receipt = await (
      await bridge.submitTransaction(signers[4].address, ethers.parseEther("1.0"))
    ).wait();
    const hash = receipt!.logs[0].topics[2];
    for (let i = 0; i < 4; i++) {
      await bridge.connect(signers[i]).confirmTransaction(hash);
    }
    expect(await bridge.isExecutable(hash)).to.be.false;
  });

  it("transfers ETH on executeTransaction once threshold is met", async () => {
    const { registry, signers, owner } = await deployRegistryWithValidators(5);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    const recipient = signers[6];
    const value = ethers.parseEther("2.5");

    await bridge.connect(owner).deposit({ value: ethers.parseEther("10") });

    const receipt = await (await bridge.submitTransaction(recipient.address, value)).wait();
    const hash = receipt!.logs[0].topics[2];
    for (let i = 0; i < 5; i++) {
      await bridge.connect(signers[i]).confirmTransaction(hash);
    }

    const balanceBefore = await ethers.provider.getBalance(recipient.address);
    await bridge.executeTransaction(hash);
    const balanceAfter = await ethers.provider.getBalance(recipient.address);

    expect(balanceAfter - balanceBefore).to.equal(value);
    expect(await bridge.executed(hash)).to.be.true;
  });

  it("rejects pause from non-monitor caller", async () => {
    const { registry, signers } = await deployRegistryWithValidators(1);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    await expect(bridge.connect(signers[0]).pause()).to.be.revertedWith("not monitor");
  });

  it("blocks confirmTransaction once paused", async () => {
    const { registry, signers } = await deployRegistryWithValidators(2);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);
    const receipt = await (
      await bridge.submitTransaction(signers[5].address, ethers.parseEther("1.0"))
    ).wait();
    const hash = receipt!.logs[0].topics[2];

    await bridge.connect(signers[0]).confirmTransaction(hash); // pre-pause confirm OK
    await bridge.connect(monitor).pause();
    await expect(bridge.connect(signers[1]).confirmTransaction(hash)).to.be.revertedWith(
      "bridge paused"
    );
    expect(await bridge.paused()).to.be.true;
  });

  it("blocks executeTransaction once paused even with sufficient confirmations", async () => {
    const { registry, signers, owner } = await deployRegistryWithValidators(5);
    const monitor = signers[8];
    const bridge = await deployBridge(registry, 5, monitor.address);

    await bridge.connect(owner).deposit({ value: ethers.parseEther("10") });
    const receipt = await (
      await bridge.submitTransaction(signers[6].address, ethers.parseEther("1.0"))
    ).wait();
    const hash = receipt!.logs[0].topics[2];
    for (let i = 0; i < 5; i++) {
      await bridge.connect(signers[i]).confirmTransaction(hash);
    }

    await bridge.connect(monitor).pause();
    await expect(bridge.executeTransaction(hash)).to.be.revertedWith("bridge paused");
    expect(await bridge.executed(hash)).to.be.false;
  });
});
