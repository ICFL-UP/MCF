import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { deployV2, deploymentReport, LEDGER, LEDGER_ALT } from "./deploy_v2";
import { signWithdrawal } from "../test/contracts/helpers";

const TAU_BLOCK = 12; // mainnet block time, seconds (ledger: δ_include ≤ k·τ_block)
const D_ARL1 = 480;   // detector ARL₁, seconds (PROGRESS.md ledger, Phase 12)
// δ_detect: per-event monitor wall-clock, parsed AT RUNTIME from the post-phase-20
// regenerated docs/logs/scenario_2.log ("Wall-clock from emit to monitor-react" metric).
// Never hard-code it: phase-20 retires the pre-calibration "score 3014.843 / 41.07 ms"
// headline pair and re-measures latency on the calibrated generator, so any constant
// baked in here would republish a retired number (violating DoD line 3).
const scenario2Log = fs.readFileSync(
  path.join(__dirname, "..", "docs", "logs", "scenario_2.log"), "utf8",
);
const detectMatch = scenario2Log.match(/Wall-clock from emit to monitor-react\s*:\s*([\d.]+)\s*ms/);
if (!detectMatch) {
  throw new Error("δ_detect metric not found in docs/logs/scenario_2.log — regenerate it (phase-20) before running");
}
const DELTA_DETECT_MS = Number(detectMatch[1]);

async function minedAt(txResponse: any) {
  const r = await txResponse.wait();
  const b = await ethers.provider.getBlock(r.blockNumber);
  return { block: r.blockNumber as number, ts: b!.timestamp as number };
}

async function main() {
  const rows: string[] = [];

  // ---- Path A: on-chain value trip (LEDGER_ALT, reachable: B + r·W = 4600 > T_alt = 4000)
  const d = await deployV2(LEDGER_ALT);
  await (await d.bridge.connect(d.deployer).deposit({ value: ethers.parseEther("9000") })).wait();
  const recipient = (await ethers.getSigners())[16].address;
  // Breach schedule (see plan arithmetic): 1000 ETH at t=0, then 800 ETH every 850 s.
  const amounts = ["1000", "800", "800", "800", "800"].map((a) => ethers.parseEther(a));
  let lastOk = { block: 0, ts: 0 };
  let breach = { block: 0, ts: 0 };
  for (let i = 1; i <= 5; i++) {
    const amount = amounts[i - 1];
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 7200;
    const sigs = await signWithdrawal(d.validators, d.bridge, recipient, amount, BigInt(i), deadline);
    if (i < 5) {
      lastOk = await minedAt(await d.bridge.withdraw(recipient, amount, BigInt(i), deadline, sigs));
      await network.provider.send("evm_increaseTime", [850]);
      await network.provider.send("evm_mine");
    } else {
      // 5th withdrawal breaches (window outflow 4200 > 4000). Per phase-18 0.1
      // Option A the breach tx COMMITS: checkAndRecord latches tripped=true and
      // BridgeV2 skips the transfer, emits WithdrawalBlocked, and returns: no ETH
      // moves, no revert (a fresh-breach revert would roll the latch back, the exact
      // 0.1 defect). The catch branch is only a defensive guard for the already-
      // tripped `"breaker: tripped"` revert path, which should be unreachable here.
      try {
        breach = await minedAt(await d.bridge.withdraw(recipient, amount, BigInt(i), deadline, sigs));
      } catch {
        const b = await ethers.provider.getBlock("latest");
        breach = { block: b!.number, ts: b!.timestamp };
      }
    }
  }
  // Latch must be visible from the NEXT block onward (the 0.1 fix under test in prod shape).
  await network.provider.send("evm_mine");
  const tripped = await d.breaker.tripped();
  if (!tripped) throw new Error("value trip did not persist — 0.1 regression, aborting");
  const tripBlocks = breach.block - lastOk.block;
  rows.push(`| CircuitBreaker value trip (on-chain) | 5th withdrawal, window outflow 4200 > T_alt 4000 | ${tripBlocks} | ${breach.ts - lastOk.ts} (schedule) / ≤ ${tripBlocks * TAU_BLOCK} (mainnet cadence) |`);

  // ---- Path B: monitor-initiated trip (canonical config)
  const d2 = await deployV2(LEDGER);
  const before = await ethers.provider.getBlock("latest");
  const trip = await minedAt(await d2.breaker.connect(d2.monitor).trip());
  rows.push(`| Monitor trip() mined (on-chain half of Δ) | off-chain CRITICAL → trip tx | ${trip.block - before!.number} | ${trip.block - before!.number} × τ = ${(trip.block - before!.number) * TAU_BLOCK} |`);

  // ---- Path C: off-chain terms (ledger values, reported for the composed Δ)
  rows.push(`| Off-chain detector scoring δ_detect | per-event wall-clock (scenario_2) | — | ${(DELTA_DETECT_MS / 1000).toFixed(3)} |`);
  rows.push(`| Inclusion delay δ_include ≤ k·τ_block | k = ${LEDGER.K} confirmations | ≤ ${LEDGER.K} | ≤ ${LEDGER.K * TAU_BLOCK} |`);
  rows.push(`| Patient-attacker detection D = ARL₁ | structuring drain (Phase 12 ledger) | ${Math.ceil(D_ARL1 / TAU_BLOCK)} | ${D_ARL1} |`);

  const net = await ethers.provider.getNetwork();
  const md = [
    `# BOLT v2 deployment & latency report (V2 task 3.2, HighGuard-style)`,
    ``,
    `Network: Hardhat mainnet-fork (chainId ${net.chainId}); FORK_URL supplied at run time;`,
    `fork base recorded in docs/logs/deployment_fork.log. τ_block = ${TAU_BLOCK} s assumed for`,
    `block→second conversion. Gas below is from the LEDGER_ALT run; canonical-config gas is in`,
    `docs/bolt/gas_report.md and docs/logs/deployment_fork.log.`,
    ``,
    `## Addresses (LEDGER_ALT run)`,
    ``,
    `| Contract | Address |`, `|---|---|`,
    `| RegistryV2 | ${await d.registry.getAddress()} |`,
    `| RateLimiter | ${await d.limiter.getAddress()} |`,
    `| CircuitBreaker | ${await d.breaker.getAddress()} |`,
    `| BridgeV2 | ${await d.bridge.getAddress()} |`,
    ``,
    `## Gas`,
    ``, deploymentReport(d), ``,
    `## Detection / response latency (blocks and seconds)`,
    ``,
    `| Mechanism | Trigger | Latency (blocks) | Latency (seconds) |`, `|---|---|---|---|`,
    ...rows,
    ``,
    `Composed: Δ = δ_detect + δ_include ≤ ${(DELTA_DETECT_MS / 1000).toFixed(3)} + ${LEDGER.K * TAU_BLOCK} ≈ ${(DELTA_DETECT_MS / 1000 + LEDGER.K * TAU_BLOCK).toFixed(0)} s (≤ ${LEDGER.K + 1} blocks),`,
    `vs the 6-day (≈ 43,200-block) Ronin detection lag. The value-trip row uses the task-1.2`,
    `reachable config (ALT_TRIP: only T lowered — B+r·W = 4600 > T_alt = 4000); under the canonical`,
    `ledger the value trip is structurally unreachable (4600 < 5000) and response is carried by the`,
    `limiter + monitor path.`,
  ].join("\n");
  fs.writeFileSync(path.join(__dirname, "..", "docs", "bolt", "deployment.md"), md);
  console.log(md);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
