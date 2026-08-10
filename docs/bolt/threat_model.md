# BOLT: Threat Model

> Adversary definition and the four assumptions underwriting the [[theorem]].
> This is a **design specification**, not a tested system.

Related contract documents: [[hypothesis]] · [[theorem]]

---

## 1. Adversary

We adopt a **problem-space** adversary in the sense of Pierazzi et al. (2020), in
which the attacker manipulates real, admissible bridge actions (withdrawals with
chosen amounts and timing) and not abstract feature vectors, combined with a
**full-knowledge** (white-box, worst-case) adversary in the sense of Carlini &
Wagner: the attacker knows the detector, its parameters, the limiter
configuration, and the response pipeline, and optimises against them.

Concretely, the adversary:

- **Controls `k`-of-`n` valid validator keys.** Calibrated to the Ronin Bridge
  hack (March 2022): **5-of-9** signing keys compromised. With `k`-of-`n` the
  attacker can *authorise* withdrawals that pass consensus.
- **Cannot forge consensus** beyond what `k` valid keys provide (no signature
  forgery, no spoofing of honest validators).
- **Cannot rewrite the limiter** (token-bucket / circuit-breaker logic is
  immutable to the attacker; no upgrade/admin key in the attacker's hands).
- **Cannot suppress the pause faster than Δ.** Once a trip or monitor signal
  occurs, the pause/revoke transaction is included within the bounded latency
  `Δ = δ_detect + δ_include` (see [[theorem]] for symbols).

### Action space

The attacker freely chooses, per withdrawal and across the campaign:

- **chunk size**: value per withdrawal transaction;
- **inter-arrival spacing**: time between withdrawal transactions;
- **number of destinations**: how many recipient addresses are used;
- **destination reuse**: whether destinations are reused or rotated.

### Budget and binding constraint

The attacker operates under a budget:

- **total ETH to exfiltrate** (target value);
- **max number of transactions**;
- **max time horizon**.

**Binding constraint:** the campaign is only a "win" for the attacker if it still
**exfiltrates ≥ the target value**. A strategy that evades detection but extracts
less than target is a defender win. This constraint is what makes the two bound
regimes adversarially meaningful.

### Regimes

- **Fast attack**: maximise extraction per unit time; saturate the limiter and
  the per-window threshold `T`. Bounded by the arrival-curve envelope
  `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)` (see [[theorem]] §14.1; the earlier
  `X_max ≤ T + r·Δ` was refuted and is now only a limiter-only reference level).
- **Patient / low-and-slow**: keep each sliding window's outflow **below `T`** to
  stay under the static value-threshold baseline, trading rate for stealth. This
  is the regime a value-threshold baseline misses and that sequential detection
  is designed to catch; bounded **in expectation** by
  `E[X_slow] ≤ B + r·D + r·Δ`, since `D = ARL₁` is a *mean* detection delay
  (the burst `B` is counted once because the token bucket starts full at attack
  onset; see [[theorem]] §14.2). **Sub-drift caveat:** an attacker who holds the
  drift below the detector's detectability threshold is outside this bound:
  extraction is then floored only by the limiter envelope `B + r·t`, linear in
  time ([[theorem]] §14.2.1).

---

## 2. The four theorem assumptions

These are stated **identically** in [[theorem]]. Reviewers require them explicit.

1. **Atomic choke point.** ALL value-bearing exit paths route through the
   rate-limited function (the Ronin lesson: no un-instrumented withdrawal).

2. **Liveness/inclusion bound.** The pause/revoke transaction is included within
   `k` blocks (no indefinite censorship); `Δ` is finite and bounded, with
   `δ_include ≤ k·τ_block`.

   **Assumption 2: escrow-chain censorship resistance (explicit argument).**
   This assumption requires that the chain on which the `CircuitBreaker` is
   deployed (the "escrow chain") cannot indefinitely delay or censor the pause
   transaction after a trip event. The argument for treating this as an
   admissible assumption, rather than an open attack surface, has three parts.

   *Why censorship resistance is a standard-practice assumption.* Production
   bridge deployments target Ethereum mainnet or equivalent chains whose
   consensus mechanisms (Proof-of-Stake with finality gadgets, or BFT-style
   BFT with 2/3 honest validators) provide liveness under the same honest
   supermajority assumption that all transaction inclusion depends on. Treating
   that assumption as available to BOLT is consistent with the practice of
   every existing bridge: the Ronin hack itself was not a censorship attack;
   the pause was simply never submitted. If the escrow chain cannot guarantee
   transaction inclusion in principle, no on-chain safety mechanism of any kind
   is possible, and BOLT is not the appropriate line of defence.

   *What breaks if Assumption 2 is violated.* An escrow chain that halts
   entirely (e.g. all validators offline) or that an attacker can compel to
   censor the pause transaction indefinitely would make `δ_include` unbounded,
   blowing up the `r·Δ` slack in both bound regimes:
   `X ≤ B + r·(t_trip + Δ)` grows without a ceiling and
   `E[X_slow] ≤ B + r·D + r·Δ` similarly. In practical terms the attacker
   continues extracting at rate `r` through the limiter's refill indefinitely,
   the same limiter-envelope floor `B + r·t` that applies under sub-drift
   conditions (§14.2.1). This is not a corner case; it is why Assumption 2 is
   a load-bearing hypothesis rather than a footnote: the bounds degrade
   **linearly in the true latency**, so a censoring attack on the pause path
   is an effective attack on the bound's tightness even if the attacker cannot
   forge keys.

   *Why this is out of scope.* Designing censorship resistance for the escrow
   chain itself (e.g. cross-chain redundancy of the pause signal, or
   posting the pause to an L1 and having it relayed) is an orthogonal
   engineering problem whose solution is independent of the limiter/breaker/
   detector composition this work formalises. BOLT is scoped to the
   **single-chain, single-epoch** case (see [[theorem]] Setup and Objection 4);
   cross-chain pause propagation is explicitly flagged as future work there.
   The relevant residual risk is therefore: if the escrow chain is itself
   compromised or halted, the `B + r·(t_trip + Δ)` and `E[X_slow]` bounds cannot be
   enforced on-chain, and the fallback is the same as for any oracle-based
   system: off-chain monitoring, manual governance, or migration to a
   redundant chain. Honest acknowledgement: Assumption 2 cannot be "proven"
   for a live deployment; it is an operating condition that must be monitored.

3. **Attacker model.** The attacker controls `k`-of-`n` valid keys (Ronin 5-of-9);
   cannot forge consensus, cannot rewrite the limiter, and cannot suppress the
   pause faster than `Δ`.

4. **No same-block escape.** Within a single block the attacker's admitted
   outflow is at most the bucket capacity `B` (no same-block escape from the rate
   term).

---

## 3. Design-level note: TSS / MPC key custody (not implemented)

A complementary **Protect** hardening (not implemented in this PoC, stated
honestly as design-level only) is **threshold-signature / MPC custody** of the
validator key material. Under a `(t, n)` TSS/MPC model, no single party (and no
small colluding subset below `t`) ever reconstructs a usable signing key; signing
is a distributed protocol producing a single on-chain signature. This raises the
practical cost of reaching the `k`-of-`n` compromise the [[threat_model]] assumes,
shifting the attacker from "exfiltrate `k` private keys" to "subvert `t` MPC
participants during signing." Production bridges using this class of custody
include **tBTC v2** (threshold ECDSA via the GG18/GG20 protocol family over a
randomly sampled 100-of-N signer wallet, with signing distributed so no node holds
a full key) and **THORChain** (GG20-based TSS for vault key management, with
periodic *churn* rotating the active validator set and re-sharing key material).

**This PoC does NOT implement production TSS/MPC.** BOLT instruments and bounds
the *response* path with k separate on-chain ECDSA signatures (one per validator),
which is functionally equivalent for the bound's purpose but is not the
production key-custody design. The BOLT bound is proven under the explicit
`k`-of-`n` compromise assumption in §2 above; TSS/MPC is **modelled and cited at
design level only** to characterise the realistic key-custody hardening that a
production deployment would layer underneath the same bound. No novel cryptography
is introduced here. See [[hypothesis]] for the Protect mapping.

> **References (design-level citations).**
> - tBTC v2 / Threshold Network: threshold ECDSA (GG18/GG20), randomly sampled
>   signer wallets; <https://docs.threshold.network/>.
> - THORChain: TSS-based vault custody with validator churn / key re-sharing;
>   <https://docs.thorchain.org/> and the GG20 threshold-signature scheme
>   (Gennaro & Goldfeder, *One Round Threshold ECDSA with Identifiable Abort*).

## Governance scope: compromised or stuck governor (explicit exclusion, V2 task 1.5)

RegistryV2's governor set is immutable at construction (contracts/RegistryV2.sol:79-90);
approvals are irrevocable (:123-128) and there is no timelock. Consequently a
compromised governor cannot be evicted, an approval cannot be withdrawn before
execution, and a lost governor key permanently consumes liveness margin (the m-of-n
threshold must be met by the remaining keys).

This is an EXPLICIT out-of-scope boundary, not an oversight:

1. **The claims do not depend on it.** H1 and the loss bound `X ≤ B + r·(t_trip + Δ)`
   (registered as `X ≤ T + r·Δ`, since superseded) concern the
   validator key-compromise path (k-of-n withdrawal signatures), the Ronin failure
   mode. Governor rotation machinery changes neither bound.
2. **Assumption symmetry.** The theorem assumes registry-lifecycle governance honesty
   the same way it does NOT assume validator honesty; this section pins that
   asymmetry down explicitly.
3. **Deliberate scope lock.** Governed addGovernor/removeGovernor + approval expiry +
   timelock is standard, audited engineering (e.g. OpenZeppelin TimelockController)
   with no research content; adding it to a design-specification PoC widens the audit
   surface without strengthening any tested claim. Production deployments should use
   an audited governance framework, recorded as future work.

**Residual risk accepted:** a single compromised governor can approve ops but cannot
execute alone (m-of-n, m=3 in all fixtures); m simultaneously compromised governors
defeat the registry: identical to any m-of-n multisig, and outside this threat model.

**Reinstate-digest replay (production hardening item):** the `executeReinstate` digest
folds no `OpType` discriminator, so an m-of-n approval set gathered for a register op
over the same `(validator, docHash)` pair is structurally replayable as reinstate
evidence. Mitigated in practice by the m-of-n quorum itself and the fresh-`docHash`
convention (a new `docHash` per reinstate makes the register digest stale); folding an
`OpType` salt into the signed digest is the correct engineering fix and is recorded
here, alongside the governance framework above, as a production hardening item. Full
consequence/mitigation catalogue: `docs/bolt/limitations.md` L1.

**Blind approval of an opaque `opId` (governor diligence is assumed, not enforced):** `approve(bytes32 opId)`
binds a governor's approval to a 32-byte hash rather than to a human-readable action, and the contract has no
way to verify that the approver reconstructed the pre-image before signing. The operating assumption is
therefore explicit: *governors are assumed to recompute `computeOpId(opType, addr, docHash, ttl)` off-chain
from the parameters they intend to authorise and to compare it against `opId` before approving; the contract
cannot enforce that they did.* Two properties compound the exposure: approvals are irrevocable and never
expire, so a mistaken approval cannot be withdrawn before execution; and `govNonce[validatorAddr]` advances on
every executed op for that validator, so an unrelated op executing first silently voids the pending approval
set and forces a fresh m-of-n round, which matters most for emergency revocation. This is a conventional
multisig governance-UX weakness rather than a novel one, and it is recorded here because it was previously
undisclosed. Emitting decoded operation parameters in the `Proposed` event, approval expiry and a timelock are
the standard fixes; they belong with the audited governance framework already scoped out above. Full
consequence/mitigation catalogue: `docs/bolt/limitations.md` L12.


---

## Availability and griefing (B8)

The bound in [[theorem]] is a **confidentiality/integrity** bound on value exfiltrated;
it says nothing about **availability**. Detector parameters are public (§1, full-knowledge
adversary) and `CircuitBreaker.trip()` latches until an owner `reset()`. An adversary who
cannot *steal* (holds no k-of-n withdrawal keys) may still be able to *halt* the bridge.
This section names the pause semantics precisely, quantifies benign false-halt frequency,
prices the cheapest griefing action, and names a liveness cost the bound omits. Every
contract behaviour below is cross-checked against the current Solidity.

### A. Precise pause semantics (what stops, who resets)

Three distinct "stop" events exist; they are not interchangeable.

| Event | Trigger | Site | Effect | Clears via |
|---|---|---|---|---|
| **Detector flag** (score/level) | per-event composite z-score `level` or sequential statistic | `monitor/service.py:133-146` (off-chain) | none on its own: a flag is only data | n/a |
| **Monitor signal trip** | off-chain detector fires `trip()` | `CircuitBreaker.trip()` (`onlyMonitor`, sol:151-154); driven by `service.py:151` `level=="CRITICAL" or detector_tripped` | sets `tripped=true` | `reset()` |
| **Breaker value trip** | in-path: `windowOutflow()+amount > T` | `CircuitBreaker.checkAndRecord` (`onlyGate`, sol:134-148) | latches `tripped=true`, returns `breached` | `reset()` |

Once `tripped=true`, **every** subsequent `checkAndRecord` reverts on
`require(!tripped)` (sol:136), so **all** value-bearing withdrawals through `BridgeV2`
halt (`withdraw` calls the breaker at sol:142). Deposits are unaffected (`deposit()`/
`receive()` never touch the breaker), and the `RateLimiter` keeps refilling at `r`
throughout the halt. Only the **owner** (governance) clears the latch:
`reset()` requires `msg.sender == owner()` (sol:157-158) and additionally zeroes the
window buckets. There is **no timeout, no self-clear, and no rate-limit on the
trip→reset cycle**: the latch persists indefinitely until an m-of-n governance reset.

Critical distinction for the frequency analysis: a **flag is not a trip**. The score
`level` is computed on every event, but only a `CRITICAL` composite classification *or*
a sequential-detector trip actually invokes the pause path (`service.py:151`). The
false-positive rate that matters for availability is therefore the **trip** rate, not
the flag rate.

**On the LOCKED ledger the value-trip path is structurally unreachable.** The limiter
admits at most `B + r·W` over any window `W` (assumption 4 + continuous refill):
`B + r·W = 1000 + 1·3600 = 4600 < T = 5000`. So `windowOutflow()`, which counts only
limiter-admitted outflow, can never exceed `T`, and `checkAndRecord` never returns
`breached` (confirmed in `deployment.md`: "under the canonical ledger the value trip is
structurally unreachable"). On LOCKED the **only reachable auto-halt is the monitor
signal trip.** The value trip becomes reachable only under the `ALT_TRIP` ledger
(`T = 4000 < 4600`), used precisely to exercise that path in `scenario_5`. This is a
deliberate layered-defence choice, foregrounded in [[theorem]] §14.1.2: under LOCKED
the value trip is defense-in-depth headroom (it binds only if the limiter envelope is
weakened) and the monitor signal trip is the live response path.

### B. Benign false-halt frequency

The reachable auto-halt on LOCKED is the monitor signal trip, driven by the sequential
change-point detector (`sequential-cpd`). Its false-trip rate on the **held-out real
benign** CCTX cadence is measured in `docs/logs/scenario_6_detection_eval.log` (post-A1,
USD-denominated):

- `ARL₀ = 371,868 s`: mean run length between false trips (right-censored lower bound;
  the detector rarely false-trips), and
- `φ = 62 / 24,539 = 0.002527` per benign event (confusion matrix `FP=62, TN=24,477`).

Convert `ARL₀` to halts per 30-day month (`30 × 86,400 = 2,592,000 s ≈ 2.59×10⁶ s`):

```
halts/month = 2,592,000 s / 371,868 s ≈ 6.97
```

**≈ 7.0 benign-caused halts per month** on real benign cadence (a lower-bound-derived
*upper estimate* of halt frequency, since ARL₀ is a censored lower bound → the true rate
is ≤ 7.0/month). Because `ARL₀` already integrates the benign inter-arrival cadence, this
is the correct per-time figure; the per-event `φ = 0.0025` is the same phenomenon
un-normalised by cadence (expected FP over the 24,539-row test split = 24,539 × 0.002527
= 62, matching the matrix). **Honest delta (Phase-22 B2):** this figure **doubled** from
≈3.5/month when the de-circularized parameter selection replaced cap=1.5 with cap=2.0
(φ 0.0013 → 0.0025): the availability cost of not tuning the detector on the geometry
it is evaluated against.

Two caveats. (i) This counts the **sequential** trip path only. The composite
`CRITICAL` path (`service.py:151`) is a *second* trip trigger whose benign rate is
characterised separately by `scenario_4` and is **not** folded into 7.0/month: the true
benign halt rate is `7.0/month + (composite-CRITICAL rate)`, so 7.0 is a floor on the
sequential contribution, not the total. (ii) For scale, the budget-matched
`value-zscore` baseline (ARL₀ = 22,648 s at the same 1% train budget) would give
`2,592,000 / 22,648 ≈ 114 halts/month`: an unusable availability profile; the
sequential detector's near-zero `φ` is what makes latching tolerable at all.

### C. Griefing cost (cheapest halt)

**C1 (keyless griefer): cannot halt.** The value trip is the only halt an attacker
without keys could hope to drive, and (i) it is unreachable on LOCKED (§A), and (ii) it
records **outflow**, which requires a *withdrawal*, which requires k-of-n signatures.
Deposits do not move the breaker. A keyless adversary has no reachable halt path.

**C2: keyholder griefer (structuring the monitor).** An attacker holding k-of-n keys
can feed the sequential detector a structuring pattern to force a monitor trip *without
a value-threshold breach*. With the train-selected params (`δ=0.25, λ=4, cap=2.0`,
scenario_6 log), each same-counterparty event contributes `min(z, cap) − δ` to the
Page-Hinkley statistic (at most `cap − δ = 1.75`), and a trip needs statistic `> λ = 4`.
The cheapest illustrated schedule keeps each event *below* the cap at signed-log-z
= 1.5 (contribution `1.5 − 0.25 = 1.25`):

```
events to trip = smallest n with n·1.25 > 4  →  n = 4  (statistic = 5.0)
```

(The cap change from the Phase-22 re-selection does not alter this schedule; it binds
only above z = 2.0.) Each event at signed-log-z `≥ 1.5`; inverting the train scale
(`μ_log = 2.8902, σ_log = 1.0894`):

```
log10(value_usd) ≥ 2.8902 + 1.5·1.0894 = 4.5243  →  value_usd ≥ 10^4.5243 ≈ $33,443
total transited  = 4 × $33,443 ≈ $133,770  (within one W = 3600 s window, one destination)
```

But this ~$134k is transited to a destination the attacker chooses (recoverable to their
own address), so **capital-at-risk ≈ $0**; the real barrier is the k-of-n key control,
which is *already* the theft precondition. A keyholder who can grief can steal, so
griefing is a strictly weaker goal for this actor and adds no new capability.

**C3: monitor-key compromise (the cheapest halt, and a single point of availability
failure).** `CircuitBreaker.trip()` is `onlyMonitor` and takes no arguments (sol:151-154).
A compromised **monitor** key can call `trip()` directly:

```
cost of one halt = gas of one trip() tx (one SSTORE + event) ≈ 3×10⁴ gas ≈ $0 capital
```

The monitor key **cannot move value** (it is not a k-of-n withdrawal signer), so it does
*not* widen the theft bound, but it can halt the bridge with a single ~$0 transaction,
and because there is no cool-down on the trip→reset cycle (§A), it can **re-trip
immediately after every reset**, forcing the bridge into an availability tarpit bounded
only by how fast governance can reset. This makes the monitor key a **single point of
availability failure**: one compromised key, no capital, unbounded downtime. This is the
headline griefing finding.

### D. Recovery path and expected downtime

`reset()` is `onlyOwner` (sol:157). In every fixture the owner is an m-of-n governance
(m = 3). Recovery is therefore: (1) off-chain gather m signatures; (2) submit one
`reset()` tx. The **on-chain** cost is a single transaction: inclusion ≈ 1 block ≈
`τ_block = 12 s` (deployment.md). The **binding** downtime is step (1): human m-of-3
multisig coordination has **no bound in the current design** (minutes to hours in
practice, and *unbounded* against a C3 re-trip attacker who trips again the moment the
reset mines). Expected downtime per halt ≈ `t_coordinate(m-of-3) + 12 s`, with
`t_coordinate` operationally the dominant, unbounded term.

### E. Blocked-breach liveness cost (named explicitly)

When a fresh value-trip breach fires (reachable only on `ALT_TRIP`, §A), `BridgeV2`
(sol:134-146) takes the two-phase Option-A path: it **commits** the transaction with the
value transfer skipped. Three liveness costs are incurred with **zero value moved**:

1. **Nonce burn**: `usedNonce[nonce] = true` (sol:134) runs before the breach check.
   The legitimate withdrawal that nonce authorised is permanently dead; it must be
   re-signed by k validators under a fresh nonce.
2. **Rate-limiter bucket debit**: `limiter.consume(amount)` (sol:136) executes before
   the breach check and is **not** rolled back. The bucket is drained by `amount` as if
   value had left, even though the transfer was skipped. After reset, legitimate
   withdrawals face a bucket already down by `amount`; refilling that headroom costs an
   extra `amount / r` seconds of throttling (up to `B / r = 1000/1 = 1000 s` if
   `amount ≈ B`) *on top of* the halt itself.
3. **Whole-bridge halt**: the latch (sol:140) reverts all subsequent withdrawals until
   reset (§A).

Cost (2), the bucket debit for zero value moved, is the previously **un-named** liveness
cost: the token bucket, the assumption-4 throughput reserve, is spent by a blocked
breach that delivered nothing, so post-reset throughput is throttled beyond the pure
downtime. This is a design cost of the reachable-trip (`ALT_TRIP`) configuration a
production deployment would adopt to keep the value trip active; on LOCKED it is
unreachable and therefore incurred zero times.

### F. Operational reset policy (Tier C C3)

The trip→reset cycle has no cool-down, which is what makes the C3 monitor-key tarpit and
the C-series re-trip attack unbounded. Two contract facts drive the recommendation:

1. **`reset()` re-arms a fresh `T` mid-incident.** `reset()` clears **both** the latch
   **and** the window buckets (sol:157-165, §A), so a premature reset does not merely
   resume service on the interrupted window; it hands an in-progress attacker a
   **fresh `T = 5,000 ETH` of value-trip headroom per premature reset under LOCKED**
   (and a zeroed window under any ledger).
2. **On-chain mechanisms bound rate, not cumulative loss.** Absent any trip, a patient
   attacker extracts up to `min(T, B + r·W)` per window indefinitely; cumulative loss
   is bounded only by the detector via the patient bound
   `E[X_slow] ≤ B + r·ARL₁ + r·Δ` ([[theorem]] §14.2, §14.2.1), so a reset policy
   that repeatedly forgives trips without diagnosis converts the detector's bounded
   expected loss back into an unbounded drip.

**Recommendation** (operational, not implemented in the PoC contracts):

- **Reset cool-down ≥ one full window `W`** (≥ 3,600 s on LOCKED) after any latch:
  guarantees at least one clean window of telemetry between halt and re-arm, and
  bounds the halt duty cycle a compromised monitor (C3 above) can impose when combined
  with gating further monitor `trip()` calls (or requiring a higher governance quorum
  to re-trip) during the cool-down `τ_cool`.
- **Post-incident review gate**: `reset()` only after an explicit m-of-n-signed review
  verdict that the trip cause is understood (benign false positive vs. attack), never
  as a reflexive service-restoration action: because of fact 1, every premature reset
  is a fresh-`T` grant.

This is an availability control, orthogonal to the value bound, and is recorded as
deployment guidance.
