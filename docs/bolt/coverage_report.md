# Solidity coverage report (V2 task 1.3)

Regenerate: `make coverage` (runs `npx hardhat coverage`; solidity-coverage ships with
`@nomicfoundation/hardhat-toolbox`). Raw Istanbul output (`coverage/`, `coverage.json`)
is gitignored; this summary is the committed artifact.

## Target scope

The **≥90% statements and branches target applies to the four v2 contracts**:
`BridgeV2.sol`, `RegistryV2.sol`, `RateLimiter.sol`, `CircuitBreaker.sol`.
The v1 contracts (`MCFValidatorRegistry`, `MockBridge`) and the test-only helpers
(`ReentrantAttacker`, `RejectingRecipient`) are reported but **out of target**:
they are retained for dissertation continuity (v1) or exist purely to drive
adversarial branches in the v2 suites (helpers).

## Per-file summary (75 passing Hardhat tests)

| File | % Stmts | % Branch | % Funcs | % Lines | Uncovered lines | In ≥90% target |
|------|---------|----------|---------|---------|-----------------|----------------|
| **BridgeV2.sol** | **100** | **95.45** | 100 | 100 | — | yes ✅ |
| **CircuitBreaker.sol** | **100** | **96.15** | 100 | 100 | — | yes ✅ |
| **RateLimiter.sol** | **100** | **100** | 100 | 100 | — | yes ✅ |
| **RegistryV2.sol** | **97.44** | **94.12** | 90.91 | 98.28 | 97 (`governorCount()` view) | yes ✅ |
| MCFValidatorRegistry.sol (v1) | 100 | 68.75 | 100 | 100 | — | no (v1, out of target) |
| MockBridge.sol (v1) | 100 | 77.27 | 100 | 100 | — | no (v1, out of target) |
| ReentrantAttacker.sol (helper) | 100 | 50 | 100 | 100 | — | no (test helper) |
| RejectingRecipient.sol (helper) | 100 | 100 | 100 | 100 | — | no (test helper) |
| **All files** | 99.26 | 88.81 | 97.96 | 99.54 | | |

All four v2 contracts meet the ≥90% target on **both** statements and branches.

## Gap tests added to reach the target (appended to EXISTING suites, no new spec files)

Baseline before this task: CircuitBreaker 80.77% branch, RateLimiter 83.33% branch,
RegistryV2 61.76% branch. Added:

- `test/contracts/circuitbreaker.spec.ts`: `setGate`/`setMonitor` negative-auth +
  owner-update branches; constructor `W not bucket-divisible` guard.
- `test/contracts/ratelimiter.spec.ts`: `setConsumer` negative-auth + owner-update
  branches; constructor zero-capacity guard.
- `test/contracts/registryv2.spec.ts`: constructor guards (empty governor set,
  zero/oversized threshold, zero-address governor, duplicate governor); double-approve;
  non-governor `executeRevoke`/`executeRenew`; `executeRegister` `already registered`
  (fresh govNonce opId round) and `invalid signature`; `executeRevoke`/`executeRenew`
  `not registered`.
- `test/contracts/bridgev2.spec.ts`: `receive()` plain-ETH `Deposit`; the
  `"bridge: transfer failed"` branch via the new minimal helper
  `contracts/RejectingRecipient.sol` (ReentrantAttacker does not serve: its `receive()`
  only reverts indirectly via its own failed re-entrant `withdraw`).

## Known residual gaps (justified)

- `RegistryV2.sol` line 97 / funcs 90.91%: the `governorCount()` convenience view is
  unexercised by the suites: no logic, no branches.
- `RegistryV2` `"gov: already executed"` guard (`_consume`): its revert direction is
  **unreachable through the public API**: every successful execute advances the
  per-validator `govNonce` folded into `computeOpId`, so an already-executed opId can
  never be recomputed. Defence-in-depth; documented, not testable.
- `CircuitBreaker.windowOutflow()` `oldest = 0` ternary arm requires
  `block.timestamp < W` (chain younger than one window): unreachable on a realistic
  clock; conservative-by-construction either way.
