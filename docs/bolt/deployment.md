# BOLT v2 deployment & latency report (V2 task 3.2, HighGuard-style)

Network: Hardhat mainnet-fork (chainId 31337); FORK_URL supplied at run time;
fork base recorded in docs/logs/deployment_fork.log. τ_block = 12 s assumed for
block→second conversion. Gas below is from the LEDGER_ALT run; canonical-config gas is in
docs/bolt/gas_report.md and docs/logs/deployment_fork.log.

## Addresses (LEDGER_ALT run)

| Contract | Address |
|---|---|
| RegistryV2 | 0x6f058a2abc238D775531e1d391d7E0337d024Df7 |
| RateLimiter | 0xF9C0092ae1f3B2E08D07ceAD0C2927318e7B3E21 |
| CircuitBreaker | 0xaC10e29fFc0e2Ba64c0D91db7EA31fE45FE43E68 |
| BridgeV2 | 0x53fa102681e10C680cb1EdEe1A15ea5630e61Ac5 |

## Gas

| Operation | Gas |
|---|---|
| RegistryV2.deploy | 1539197 |
| RateLimiter.deploy | 433516 |
| CircuitBreaker.deploy | 663138 |
| BridgeV2.deploy | 827216 |
| RateLimiter.setConsumer | 30067 |
| CircuitBreaker.setGate | 30134 |
| RegistryV2.approve | 1605087 |
| RegistryV2.executeRegister | 2478468 |

## Detection / response latency (blocks and seconds)

| Mechanism | Trigger | Latency (blocks) | Latency (seconds) |
|---|---|---|---|
| CircuitBreaker value trip (on-chain) | 5th withdrawal, window outflow 4200 > T_alt 4000 | 2 | 852 (schedule) / ≤ 24 (mainnet cadence) |
| Monitor trip() mined (on-chain half of Δ) | off-chain CRITICAL → trip tx | 1 | 1 × τ = 12 |
| Off-chain detector scoring δ_detect | per-event wall-clock (scenario_2) | — | 0.036 |
| Inclusion delay δ_include ≤ k·τ_block | k = 5 confirmations | ≤ 5 | ≤ 60 |
| Patient-attacker mean detection delay D = ARL₁ (a mean, not a per-run cap; feeds the expectation bound `E[X_slow] ≤ B + r·D + r·Δ`) | structuring drain (Phase 12 ledger) | 40 | 480 |

Composed: Δ = δ_detect + δ_include ≤ 0.036 + 60 ≈ 60 s (≤ 6 blocks),
vs the 6-day (≈ 43,200-block) Ronin detection lag. The value-trip row uses the task-1.2
reachable config (ALT_TRIP: only T lowered — B+r·W = 4600 > T_alt = 4000); under the canonical
ledger the value trip is structurally unreachable (4600 < 5000) and response is carried by the
limiter + monitor path.