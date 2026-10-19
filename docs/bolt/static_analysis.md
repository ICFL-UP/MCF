# Static analysis: Slither triage (V2 task 1.3)

Regenerate: `make static`. Tool: slither-analyzer 0.11.5 over solc 0.8.24
(Hardhat compilation pipeline, optimizer settings from `hardhat.config.ts`).
Raw checklist output: `docs/bolt/slither_report.md` (39 findings, IDs below match it).
Scope: all `contracts/*.sol`; `node_modules` filtered. The four **v2 contracts**
(`BridgeV2`, `RegistryV2`, `RateLimiter`, `CircuitBreaker`) are the assurance target;
v1 contracts (`MCFValidatorRegistry`, `MockBridge`) and test helpers
(`ReentrantAttacker`, `RejectingRecipient`) are triaged but out of the v2 target scope.

Verdict vocabulary: `fixed` (code change linked), `false-positive` (why the detector is
wrong here), `accepted` (justified residual). **Every finding has a verdict row.**

## Triage table

| # | Detector | Location | Severity | Verdict | Rationale / fix commit |
|---|----------|----------|----------|---------|------------------------|
| ID-0 | arbitrary-send-eth | BridgeV2.withdraw (contracts/BridgeV2.sol#L104-L153) | High | false-positive | Sending ETH to a caller-supplied recipient IS the bridge's function. The recipient is bound into the k-of-n ECDSA digest (recipient, amount, nonce, deadline, chainId, contract); every signer must pass `RegistryV2.verifyValidator` per withdrawal; the exit is gated in-path by RateLimiter + CircuitBreaker; `nonReentrant` + checks-effects-interactions with the `.call` last. |
| ID-1 | weak-prng | CircuitBreaker._recordOutflow (contracts/CircuitBreaker.sol#L113) | High | false-positive | `idx = epoch % BUCKET_COUNT` is a ring-buffer slot index for the 61-slot time-bucket accumulator, not a source of randomness. Nothing security-relevant is derived from "entropy" here. |
| ID-2 | locked-ether | ReentrantAttacker (contracts/ReentrantAttacker.sol#L20-L49) | Medium | accepted | Test-only attack harness used by `bridgev2.spec.ts` to prove `nonReentrant`; never part of a deployment. ETH it captures in a test run is expendable Hardhat test ETH. |
| ID-3 | locked-ether | RejectingRecipient (contracts/RejectingRecipient.sol#L9-L13) | Medium | false-positive | Test-only helper whose `receive()` unconditionally reverts: ether can never enter the contract, so none can be locked. Exists solely to exercise BridgeV2's `"bridge: transfer failed"` branch (V2 1.3 coverage). |
| ID-4 | missing-zero-check | MockBridge.constructor `_monitor` (contracts/MockBridge.sol#L51) | Low | accepted | v1 contract, out of v2 target scope; retained frozen for dissertation continuity. A zero monitor only disables the (superseded) pause path. |
| ID-5 | missing-zero-check | CircuitBreaker.constructor `_gate` (contracts/CircuitBreaker.sol#L69) | Low | accepted | Deploy-time wiring parameter. A zero gate is FAIL-CLOSED: `checkAndRecord` reverts `"breaker: not gate"` for every caller, so no value can exit; the deploy scripts/fixtures deliberately deploy with `address(0)` and wire via `setGate` after the bridge exists. |
| ID-6 | missing-zero-check | CircuitBreaker.constructor `_monitor` (contracts/CircuitBreaker.sol#L70) | Low | accepted | Same wiring pattern; a zero monitor only disables the monitor-trip path; the value-threshold trip (the bound's T term) is unaffected. |
| ID-7 | missing-zero-check | RateLimiter.constructor `_consumer` (contracts/RateLimiter.sol#L47) | Low | accepted | Same wiring pattern; a zero consumer is fail-closed (`consume` reverts `"rate limit: not consumer"`), used intentionally by the fixtures before `setConsumer(bridge)`. |
| ID-8 | missing-zero-check | RateLimiter.setConsumer (contracts/RateLimiter.sol#L58) | Low | accepted | `onlyOwner` setter; setting zero disables consumption fail-closed (it cannot open an exit). Rewiring to zero is an owner action equivalent to pausing the bridge. |
| ID-9 | missing-zero-check | CircuitBreaker.setGate (contracts/CircuitBreaker.sol#L80) | Low | accepted | Same as ID-8: `onlyOwner`, fail-closed. |
| ID-10 | missing-zero-check | CircuitBreaker.setMonitor (contracts/CircuitBreaker.sol#L85) | Low | accepted | Same as ID-8: `onlyOwner`; zero only disables the monitor-trip path. |
| ID-11 | calls-loop | BridgeV2.withdraw → registry.verifyValidator (contracts/BridgeV2.sol#L127) | Low | accepted | By design: the per-signer, per-withdrawal `verifyValidator` call is exactly the G6 revocation check the design exists to prove. The loop is bounded by the signature count (k=5 of n=9); the callee is the trusted, immutable registry (a view function): no external-party gas/DoS surface. |
| ID-12 | reentrancy-events | MockBridge.executeTransaction (contracts/MockBridge.sol#L86-L96) | Low | accepted | v1 contract, superseded by BridgeV2 (which emits after the call but is `nonReentrant` and CEI-ordered). Event-ordering only; no state at risk. Frozen for continuity. |
| ID-13 | timestamp | CircuitBreaker._recordOutflow (contracts/CircuitBreaker.sol#L111-L119) | Low | accepted | By design: the breaker's sliding window is TIME-defined (W=3600 s in 60 s buckets). Miner timestamp drift (seconds) is negligible at bucket granularity, and the 61-slot summed span over-approximates the exact window; the breaker can only trip EARLIER (conservative; bound preserved). |
| ID-14 | timestamp | RateLimiter.consume (contracts/RateLimiter.sol#L80-L85) | Low | accepted | The token bucket refills as `block.timestamp` advances; that is the definition of the rate term r. Drift of seconds changes the refill by r·(drift), negligible vs B=1000 ETH; assumption 4 (≤B per block) is unaffected since refill needs timestamp advance. |
| ID-15 | timestamp | BridgeV2.withdraw deadline check (contracts/BridgeV2.sol#L114) | Low | accepted | Signature expiry (`block.timestamp <= deadline`) is the intended V2 0.3 semantics; deadlines are minutes-to-hours scale, drift is seconds. Standard pattern (cf. Uniswap-style deadlines). |
| ID-16 | timestamp | MCFValidatorRegistry.verifyValidator (contracts/MCFValidatorRegistry.sol#L121-L124) | Low | accepted | Credential expiry with TTLs of hours-to-days; second-scale drift immaterial. v1 contract, out of v2 scope. |
| ID-17 | timestamp | RateLimiter.available (contracts/RateLimiter.sol#L64-L68) | Low | accepted | Same as ID-14: refill reconciliation clamped to B. |
| ID-18 | timestamp | MCFValidatorRegistry.registerValidator (contracts/MCFValidatorRegistry.sol#L55-L91) | Low | accepted | Detector over-match: the flagged comparison is `registeredAt == 0` (a sentinel check); `block.timestamp` is only STORED. v1, out of scope. |
| ID-19 | timestamp | MCFValidatorRegistry.revokeValidator (contracts/MCFValidatorRegistry.sol#L97-L101) | Low | accepted | Same class as ID-18 (`active` boolean require). v1, out of scope. |
| ID-20 | timestamp | MCFValidatorRegistry.renewValidator (contracts/MCFValidatorRegistry.sol#L108-L114) | Low | accepted | Same class as ID-18. v1, out of scope. |
| ID-21 | timestamp | RegistryV2.executeRenew (contracts/RegistryV2.sol#L200-L214) | Low | accepted | `block.timestamp + newTtl` sets the new expiry (TTL days-scale); the flagged require is the `registeredAt != 0` sentinel. Drift immaterial. |
| ID-22 | timestamp | RegistryV2.verifyValidator (contracts/RegistryV2.sol#L220-L223) | Low | accepted | The `block.timestamp < expiresAt` credential-expiry check IS the design (automatic invalidation of expired credentials; dissertation claim 2). TTL scale (days) dwarfs drift (seconds). |
| ID-23 | timestamp | RegistryV2.executeRegister (contracts/RegistryV2.sol#L146-L183) | Low | accepted | Same class as ID-21: sentinel require + expiry assignment. |
| ID-24 | timestamp | CircuitBreaker.windowOutflow (contracts/CircuitBreaker.sol#L99-L107) | Low | accepted | Same as ID-13: epoch arithmetic on the bucketed window, conservative over-approximation. |
| ID-25 | timestamp | RegistryV2.executeRevoke (contracts/RegistryV2.sol#L187-L197) | Low | accepted | Same class as ID-21: `registeredAt != 0` sentinel only. |
| ID-26 | low-level-calls | MockBridge.executeTransaction (contracts/MockBridge.sol#L93) | Informational | accepted | `.call{value:}` with checked return is the post-EIP-1884 recommended ETH transfer. v1, out of scope. |
| ID-27 | low-level-calls | BridgeV2.withdraw (contracts/BridgeV2.sol#L149) | Informational | accepted | Same pattern; return value checked (`require(ok, "bridge: transfer failed")`; branch covered by the RejectingRecipient test), performed LAST under `nonReentrant`. |
| ID-28 | missing-inheritance | BridgeV2 ← IBridgeV2Withdraw (contracts/ReentrantAttacker.sol#L4-L12) | Informational | accepted | Inheriting would make a production contract depend on an interface declared in a TEST-ONLY helper: a dependency inversion with no behavioural gain. |
| ID-29 | missing-inheritance | RateLimiter ← IRateLimiter (contracts/BridgeV2.sol#L12-L14) | Informational | accepted | The minimal local interfaces in BridgeV2.sol exist to decouple compile units; the concrete contracts are wired by address at deploy time. Structural nicety only; ABI compatibility is exercised by every integration test. |
| ID-30 | missing-inheritance | RegistryV2 ← IRegistryV2 (contracts/BridgeV2.sol#L8-L10) | Informational | accepted | Same as ID-29. |
| ID-31 | missing-inheritance | CircuitBreaker ← ICircuitBreaker (contracts/BridgeV2.sol#L16-L18) | Informational | accepted | Same as ID-29. |
| ID-32 | missing-inheritance | MCFValidatorRegistry ← IRegistryV2 (contracts/BridgeV2.sol#L8-L10) | Informational | accepted | Spurious: v1 registry predates and does not implement the v2 interface contract (that is the point of RegistryV2). Out of scope. |
| ID-33 | naming-convention | RateLimiter.setConsumer `_consumer` (contracts/RateLimiter.sol#L58) | Informational | accepted | Underscore-prefixed constructor/setter parameters are the project-wide convention (consistent with the OZ-style v1 code). Cosmetic. |
| ID-34 | naming-convention | CircuitBreaker.setGate `_gate` (contracts/CircuitBreaker.sol#L80) | Informational | accepted | Same as ID-33. |
| ID-35 | naming-convention | CircuitBreaker.setMonitor `_monitor` (contracts/CircuitBreaker.sol#L85) | Informational | accepted | Same as ID-33. |
| ID-36 | immutable-states | MockBridge.registry (contracts/MockBridge.sol#L23) | Optimization | accepted | v1 contract frozen for dissertation continuity; gas-only suggestion. Changing v1 now would perturb the committed gas/scenario artifacts for zero assurance gain. |
| ID-37 | immutable-states | MockBridge.threshold (contracts/MockBridge.sol#L25) | Optimization | accepted | Same as ID-36. |
| ID-38 | immutable-states | MockBridge.monitor (contracts/MockBridge.sol#L24) | Optimization | accepted | Same as ID-36. |

**Summary:** 39 findings, of which 0 `fixed` (no true positive at Medium+ on the v2 contracts),
4 `false-positive`, 35 `accepted` (justified residuals; 13 of them on out-of-scope v1 /
test-helper code). The two High findings are both detector misreads of intentional
design (a bridge pays out ETH; a ring-buffer index is not a PRNG).

## Coverage

See `docs/bolt/coverage_report.md`: all four v2 contracts ≥90% statements AND branches
(BridgeV2 100/95.45, CircuitBreaker 100/96.15, RateLimiter 100/100,
RegistryV2 97.44/94.12). Regenerate: `make coverage`.

## SMTChecker

Full command + verbatim output + interpretation: `docs/bolt/smtchecker_report.txt`.

- Engine: CHC (Horn solver z3 4.12, supplied by the pinned `z3-solver` dev dependency;
  `--evm-version cancun` needed for OZ v5's `mcopy`), 60 s per-query timeout, targets
  `assert,overflow,underflow,divByZero`, over all four v2 contracts.
- **Result: 0 violated targets, 0 unproved targets**; solc exited 0 with no CHC
  diagnostics, which for this engine means every generated verification condition was
  proved safe (unproved targets produce an explicit "could not be proved" summary
  warning; a missing solver produces "CHC analysis was not possible": both loudly
  observable, neither present).
- Feasibility: the run costs ~50 min CPU; a `--model-checker-show-proved-safe`
  enumeration re-run was infeasible in interactive time and the pass/fail outcome is
  the committed evidence. The stateful bound properties (window ≤ T; extraction ≤
  T + r·Δ, a limiter-only reference level superseded as a bound by the envelope
  `B + r·(W + Δ)` (see [[theorem]] §14.1); revoked-never-authorises; bucket ≤ B;
  nonce-never-reused) are checked at
  bytecode level by the Foundry invariant suite (V2 1.4, `make invariants`).
