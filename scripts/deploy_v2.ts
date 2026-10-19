import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// ---- Locked ledger constants (docs/bolt/theorem.md symbol table; PROGRESS.md).
export interface DeployConfig {
  B: bigint; r: bigint; T: bigint; W: bigint; K: number; N: number; M: number;
}
export const LEDGER: DeployConfig = {
  B: ethers.parseEther("1000"),  // token-bucket burst capacity
  r: ethers.parseEther("1"),     // refill rate (ETH/s)
  T: ethers.parseEther("5000"),  // breaker window cap
  W: 3600n,                      // breaker window length (s)
  K: 5, N: 9, M: 3,              // bridge k, validator n, governance threshold m
};
// Task 1.2 alt config: mirrors phase-19 task 19.2's ALT_TRIP (ONLY T lowered to 4000;
// every other symbol unchanged). B + r·W = 1000 + 3600 = 4600 > T_alt = 4000 → value
// trip REACHABLE. The numbers MUST stay identical to the ALT_TRIP Ledger instance
// phase-19 added to scenarios/scenario_5_bound_validation.py (and threads through
// scenario_7_cost_to_evade.py); re-read those files before changing anything here.
export const LEDGER_ALT: DeployConfig = {
  ...LEDGER, T: ethers.parseEther("4000"),
};

export interface Deployment {
  registry: any; limiter: any; breaker: any; bridge: any;
  deployer: any; monitor: any; governors: any[]; validators: any[];
  gasUsed: Record<string, bigint>;
}

async function track(gas: Record<string, bigint>, label: string, txOrContract: any) {
  const receipt = txOrContract.deploymentTransaction
    ? await txOrContract.deploymentTransaction().wait()
    : await txOrContract.wait();
  gas[label] = (gas[label] ?? 0n) + receipt.gasUsed;
}

export async function deployV2(cfg: DeployConfig = LEDGER): Promise<Deployment> {
  const signers = await ethers.getSigners();
  const deployer = signers[0];
  const monitor = signers[1];
  const governors = signers.slice(2, 7);            // 5 governors, threshold M=3
  const validators = signers.slice(7, 7 + cfg.N);   // 9 validators
  const gasUsed: Record<string, bigint> = {};

  const Registry = await ethers.getContractFactory("RegistryV2", deployer);
  const registry = await Registry.deploy(governors.map((g) => g.address), cfg.M);
  await track(gasUsed, "RegistryV2.deploy", registry);

  // RateLimiter consumer / CircuitBreaker gate are set to the deployer first, then
  // re-pointed at the bridge once its address exists (setConsumer / setGate).
  const Limiter = await ethers.getContractFactory("RateLimiter", deployer);
  // Post-0.4 3-arg constructor: T/W live only on CircuitBreaker (phase-18 0.4).
  const limiter = await Limiter.deploy(cfg.B, cfg.r, deployer.address);
  await track(gasUsed, "RateLimiter.deploy", limiter);

  const Breaker = await ethers.getContractFactory("CircuitBreaker", deployer);
  const breaker = await Breaker.deploy(cfg.T, cfg.W, deployer.address, monitor.address);
  await track(gasUsed, "CircuitBreaker.deploy", breaker);

  const Bridge = await ethers.getContractFactory("BridgeV2", deployer);
  const bridge = await Bridge.deploy(
    await registry.getAddress(), await limiter.getAddress(),
    await breaker.getAddress(), cfg.K,
  );
  await track(gasUsed, "BridgeV2.deploy", bridge);

  await track(gasUsed, "RateLimiter.setConsumer", await limiter.setConsumer(await bridge.getAddress()));
  await track(gasUsed, "CircuitBreaker.setGate", await breaker.setGate(await bridge.getAddress()));

  // Config read-back smoke check, NOT phase-18 0.4's acceptance (that is discharged
  // by 0.4's own fixture test, and post-0.4 there is no second T/W copy left to
  // cross-check). Re-read the deployed contracts' parameters against cfg so a
  // mis-passed or swapped constructor argument fails loudly at deploy time.
  const readback: Array<[string, bigint, bigint]> = [
    ["breaker.threshold", await breaker.threshold(), cfg.T],
    ["breaker.windowLength", await breaker.windowLength(), cfg.W],
    ["limiter.capacity", await limiter.capacity(), cfg.B],
    ["limiter.refillRate", await limiter.refillRate(), cfg.r],
  ];
  for (const [label, got, want] of readback) {
    if (got !== want) throw new Error(`config read-back mismatch: ${label} = ${got}, expected ${want}`);
  }

  // Register the n validators through the real m-of-n governance flow.
  // Digest construction MUST mirror test/contracts/registryv2.spec.ts exactly
  // (read it before editing this block; the spec is the source of truth).
  const ttl = 365n * 24n * 3600n;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  for (const v of validators) {
    const docHash = ethers.keccak256(
      ethers.toUtf8Bytes(`did:ethr:31337:${v.address.toLowerCase()}`),
    );
    const opId = await registry.computeOpId(0 /* OpType.Register */, v.address, docHash, ttl);
    for (const g of governors.slice(0, cfg.M)) {
      await track(gasUsed, "RegistryV2.approve", await registry.connect(g).approve(opId));
    }
    // Proof-of-possession: RegistryV2.executeRegister (contracts/RegistryV2.sol:153-157)
    // recovers over keccak256(abi.encodePacked(block.chainid, address(this), addr, docHash))
    // via toEthSignedMessageHash; this mirrors registryv2.spec.ts's signDocHash exactly.
    const inner = ethers.solidityPackedKeccak256(
      ["uint256", "address", "address", "bytes32"],
      [chainId, await registry.getAddress(), v.address, docHash],
    );
    const sig = await v.signMessage(ethers.getBytes(inner));
    await track(gasUsed, "RegistryV2.executeRegister",
      await registry.connect(governors[0]).executeRegister(v.address, docHash, ttl, sig));
  }

  return { registry, limiter, breaker, bridge, deployer, monitor, governors, validators, gasUsed };
}

export function deploymentReport(d: Deployment): string {
  const rows = Object.entries(d.gasUsed)
    .map(([label, g]) => `| ${label} | ${g.toString()} |`).join("\n");
  return `| Operation | Gas |\n|---|---|\n${rows}`;
}

// CLI entry: `npx hardhat run scripts/deploy_v2.ts` (21.2 wraps this with FORK_URL).
async function main() {
  const d = await deployV2();
  const net = await ethers.provider.getNetwork();
  const block = await ethers.provider.getBlock("latest");
  const lines = [
    `# BOLT v2 deployment — ${new Date().toISOString()}`,
    `chainId=${net.chainId} forkBlock=${block!.number}`,
    `RegistryV2=${await d.registry.getAddress()}`,
    `RateLimiter=${await d.limiter.getAddress()}`,
    `CircuitBreaker=${await d.breaker.getAddress()}`,
    `BridgeV2=${await d.bridge.getAddress()}`,
    ``, deploymentReport(d), ``,
  ].join("\n");
  const out = path.join(__dirname, "..", "docs", "logs", "deployment_fork.log");
  fs.writeFileSync(out, lines);
  console.log(lines);
}

if (require.main === module) {
  main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
}
