# BOLT: Theorem (symbols + statement)

> Statement and symbol table only. **Proof is Phase 14**; see the placeholder
> section below. This is a **design specification**, not a tested system.

Related contract documents: [[hypothesis]] · [[threat_model]]

---

## Symbol table (locked)

| Symbol | Meaning | Units |
|--------|---------|-------|
| `B` | Token-bucket burst capacity | value (e.g. ETH) |
| `r` | Token-bucket refill rate | value / second |
| `T` | Per-window outflow threshold (breaker trips when window outflow > `T`) | value |
| `W` | Sliding window length | seconds |
| `Δ` | Response latency, `Δ = δ_detect + δ_include` | seconds |
| `δ_detect` | Time from attack onset to monitor signal | seconds |
| `δ_include` | Time to include pause/revoke tx, `δ_include ≤ k·τ_block` | seconds |
| `τ_block` | Block time | seconds |
| `D` | `ARL₁`: change-point detector **mean** time to detection for the attacker's chosen drift (an average, **not** a per-run worst case); defined only for drift at or above the detector's detectability threshold | seconds |
| `D_q` | `q`-quantile of the detection-delay distribution for the attacker's chosen drift (used in the probabilistic companion form) | seconds |
| `n` | Total number of validators | count |
| `k` | Compromised threshold (Ronin: 5-of-9) | count |
| `X_max` | Worst-case extraction, fast-attack regime (deterministic bound) | value |
| `X_slow` | Extraction, patient / low-and-slow regime (bounded **in expectation**; see Claim) | value |

---

## Setup

Withdrawals pass a **token bucket** (capacity `B`, refill rate `r`). A **circuit
breaker** trips when cumulative outflow in the sliding window `W` exceeds `T`,
**OR** when the monitor signals. After a trip, the pause is effective within

  `Δ = δ_detect + δ_include`,  with  `δ_include ≤ k·τ_block`.

## Assumptions

Assumptions 1–4 are stated **identically** in [[threat_model]] and are the
load-bearing hypotheses of the Phase-14 proof, which is stated in ideal
(exact) time. Assumption 5 (Phase-22 addition) makes explicit the clock model
under which the deployed contracts realise the rate term `r` and the window
`W`, and quantifies the degradation when on-chain time is `block.timestamp`.

1. **Atomic choke point.** ALL value-bearing exit paths route through the
   rate-limited function (the Ronin lesson: no un-instrumented withdrawal).

2. **Liveness/inclusion bound.** The pause/revoke transaction is included within
   `k` blocks (no indefinite censorship); `Δ` is finite and bounded, with
   `δ_include ≤ k·τ_block`.

3. **Attacker model.** The attacker controls `k`-of-`n` valid keys (Ronin 5-of-9).
   The attacker is otherwise **white-box** (the mechanism, its parameters and the
   detector's configuration are known) and **may choose the attack's start time**
   (this clause is load-bearing: it is what makes the full initial burst `B`
   available in §14.2 Step 2). Further,
   cannot forge consensus, cannot rewrite the limiter, and cannot suppress the
   pause faster than `Δ`.

4. **No same-block escape.** Within a single block the attacker's admitted
   outflow is at most the bucket capacity `B` (no same-block escape from the rate
   term).

5. **Timestamp trust (clock model).** The on-chain realisations of the rate
   term and the window run on `block.timestamp`: the token bucket refills as
   `block.timestamp` advances (`RateLimiter.consume` / `available`) and the
   breaker's sliding window ages by `block.timestamp` epochs
   (`CircuitBreaker._recordOutflow` / `windowOutflow`). We assume proposer
   timestamp manipulation is bounded to `drift` **seconds** (consensus-enforced
   monotonicity plus seconds-scale validity: the same trust the Slither triage
   accepts for the thirteen timestamp findings, IDs 13–25 in
   [[static_analysis]]). **Degradation corollary:** a proposer who advances the
   clock by `drift` mints at most `r·drift` of extra bucket refill, so each
   bound weakens **additively by at most `r·drift`**:
   `X ≤ B + r·(t_trip + Δ + drift)` and `E[X_slow] ≤ B + r·(D + Δ + drift)`.
   At the ledger rate `r = 1 ETH/s` and seconds-scale drift this is single-digit
   ETH against thresholds of thousands. A **second channel** acts on the window
   rather than the bucket and is stated separately: because the trailing window
   ages on the same clock, a proposer who advances it retires earlier outflow
   sooner and frees headroom against `T`. That channel cannot loosen §14.1,
   whose envelope does not involve `T`, but it does mean the in-path check is
   not a reliable second line under adversarial timestamps, so `T` must not be
   relied on to tighten the envelope where proposers are untrusted. The bucketed
   window itself errs conservative against a *benign* clock: the 61-slot
   accumulator over-approximates the exact `W`, so the value trip fires
   **earlier**, never later ([[static_analysis]] ID-13/ID-24).

---

## Claim (two regimes)

Under Assumptions 1–4 (and, for the on-chain instantiation, the clock model of
Assumption 5, which costs at most an additive `r·drift`), attacker extraction
is bounded:

- **Fast-drain regime** (deterministic, per-run worst case; the **arrival-curve
  envelope**), for a trip within the first window (`t_trip ≤ W`):

  `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`

  At both the LOCKED and the ALT_TRIP ledgers this is `1000 + 1·(3600 + 60) =`
  **`4,660 ETH`**; the breaker threshold `T` does not appear, so the constant is
  identical under the two configurations. Beyond one window the same envelope
  applies with `t_trip` in place of `W` and grows linearly, without a constant cap.

  > **This supersedes the earlier `X_max ≤ T + r·Δ`, which was REFUTED.** That form
  > implicitly holds the trailing window still across the response latency. The
  > deployed window slides: outflow admitted early retires from it as time passes,
  > and if the halt lands after retirement has begun the freed headroom re-opens.
  > §14.1 gives an explicit admissible schedule extracting **4,648 ETH** under
  > ALT_TRIP against the **4,060 ETH** that `T + r·Δ` permits. `T + r·Δ` is retained
  > throughout this repository only as a **limiter-only reference level**, never as
  > a bound. See `journal/THEOREM_1_COUNTEREXAMPLE.md` and `main.tex` Appendix A.

- **Patient (low-and-slow) regime** (attacker keeps each window's outflow below
  `T` to evade the value-threshold baseline; **an expectation bound, not a
  per-run worst case**):

  `E[X_slow] ≤ B + r·D + r·Δ`,  with  `D = ARL₁`

  The expectation is over the detector's detection delay `t_trip`; `ARL₁` is a
  **mean** detection delay, so it can only support a bound on **mean**
  extraction. Individual realisations of the detection delay have a right tail,
  and per-run extraction inherits that tail; the patient regime therefore has
  **no deterministic per-run analogue** of the fast bound. For per-run
  statements the probabilistic **companion (quantile) form** applies: for any
  `q ∈ (0, 1)`, with probability at least `q`,

  `X_slow ≤ B + r·D_q + r·Δ`,

  where `D_q` is the `q`-quantile of the detection-delay distribution for the
  attacker's chosen drift. The **expectation form is primary** in this work:
  it is what `ARL₁` (the quantity the Phase-12 detector characterises and the
  ledger carries as `D = 480 s`) actually supports; delay quantiles `D_q` are
  not measured here and quantifying them is future work.

  The patient bound carries the initial burst `B` once. The token bucket starts
  **full** at attack onset (capacity `B`), and a white-box attacker who chooses
  the start time may spend that initial reserve thinly across blocks (keeping
  every sliding window `≤ T` so the value trip never fires) while the detector
  takes (in mean) up to `D` to signal. The burst is therefore genuinely
  available to the patient attacker and must be counted; it follows directly
  from the pathwise arrival curve (AC) over `[0, t_trip + Δ)` (see §14.2). `B`
  is **not** removed by any of the load-bearing Assumptions 1–4, so counting it keeps the
  bound provable from Assumptions 1–4 alone (no hidden "depleted-at-onset"
  assumption).

- **Degenerate sub-drift case: scope limitation, stated up front.** The
  patient bound applies **only** to attack drifts at or above the detector's
  detectability threshold (the CUSUM/Page–Hinkley reference drift `δ`). An
  attacker who holds the outflow drift **below** that threshold is, by
  construction, invisible to the change-point detector: `ARL₁` for such a drift
  is effectively unbounded (it collapses toward the false-alarm rate `ARL₀`),
  so **no detection-based term applies at all**. In that regime the only
  operative control is the rate limiter itself, and extraction is bounded only
  by the limiter envelope

  `X_sub-drift(t) ≤ B + r·t`  (linear in elapsed time `t`),

  i.e. the attacker extracts at up to rate `r` indefinitely until some control
  outside this theorem (audit, governance, credential rotation) intervenes.
  This is a **scoping limitation of the patient claim**, not a corner case: the
  detector shrinks the loss for detectable drifts, and the limiter caps the
  *rate*, but nothing in this theorem caps *cumulative* sub-drift loss over
  unbounded time.

Both bounds are **TVL-independent**: they depend only on the limiter/breaker/
detector configuration and the response latency, not on total value locked.
The fast-drain envelope is deterministic; the patient bound holds **in
expectation** (quantile companion above), and drifts below detectability fall
outside it entirely (limiter envelope only).

### Units consistency

- `B + r·(W + Δ)` → `[value] + [value/second]·([second] + [second])` = `[value] + [value]` = **`[value]`** ✓
- `B + r·D + r·Δ` (bounding `E[X_slow]`) → `[value] + [value/second]·[second] + [value/second]·[second]` = **`[value]`** ✓

Both bounds resolve to `[value]` (e.g. ETH), as required.

---

## Positioning vs. prior bounded-bridge work

- **ERC-7265 (Circuit Breaker)**: specifies a rate-limit/circuit-breaker
  interface but provides **no proof** and **no explicit latency term**; it cannot
  state a closed-form worst-case extraction bound. BOLT's `Δ = δ_detect +
  δ_include` makes the response latency explicit and is what yields the additive
  `r·Δ` slack term in both regimes.
- **ASAS-BridgeAMM**: gives a **fraction-of-collateral** guarantee and is
  **AMM-coupled** (tied to the AMM curve, not to a generic rate-limited exit).
  *Correction (J6):* an earlier version of this note claimed ASAS has **no latency
  term**. That is wrong: cross-chain message latency is central to it, treated as
  a quantifiable execution risk. The real distinction is the **shape of the
  guarantee**: deterministic worst case in absolute value here, versus a
  probabilistic fraction of collateral there.

**Scope:** the bound is **per-chain-per-epoch** (one rate-limited exit choke
point, one limiter epoch). Cross-chain or multi-epoch composition is out of scope
for this statement.

---

## Proof: Phase 14

This is a rigorous **pen-and-paper** proof. A machine-checked formalisation is
**out of scope** (see *Future work* below). The argument is a **network-calculus**
(σ-ρ arrival-curve) treatment of the rate-limited withdrawal path, following the
deterministic-traffic calculus of Cruz (1991). The audience is an examiner /
journal reviewer; every step is justified and each of the four load-bearing
assumptions (1–4) is invoked **by name where it is used**. (Assumption 5 enters
only at the on-chain instantiation, as the additive `r·drift` degradation
stated with it; the proof below is in ideal time.)

### Preliminaries: the admitted-outflow process and its arrival curve

Fix one rate-limited exit choke point and one limiter epoch (the per-chain,
per-epoch scope stated above). Let the attack onset be time `t = 0`. For `t ≥ 0`
let

  `A(t)` = cumulative **admitted** outflow value over the half-open interval
  `[0, t)`, i.e. the total value the limiter has actually let leave the bridge.

`A` is non-negative and non-decreasing. Because **every** value-bearing exit is
mediated by the limiter (**Assumption 1**, atomic choke point), `A(t)` accounts
for *all* extraction; there is no un-instrumented side path that adds to the
attacker's take outside `A`. This is the load-bearing use of Assumption 1: it is
what lets a single scalar process `A` represent the attacker's *entire* gain, so a
bound on `A` is a bound on extraction.

The withdrawal path is a **token bucket** of capacity `B` and refill rate `r`.
By the standard token-bucket service discipline, outflow is admitted only when the
bucket holds sufficient tokens; the bucket starts with at most `B` tokens and
refills at rate `r`, capped at `B`. Therefore the admitted process obeys the
**σ-ρ arrival curve** of Cruz (1991) with burst `σ = B` and rate `ρ = r`: for all
`0 ≤ s ≤ t`,

  `A(t) − A(s) ≤ B + r·(t − s)`.   **(AC)**

In words: over *any* interval of length `t − s` the bucket can release at most the
tokens already accumulated (at most the capacity `B`) plus the tokens that refill
during the interval (`r·(t − s)`). The within-block special case of (AC), that a
single block cannot admit more than `B` regardless of how many `k`-of-`n`-signed
withdrawals the attacker packs into it, is exactly **Assumption 4 (no same-block
escape)**. Without Assumption 4 an attacker could try to defeat the *rate* term by
cramming one oversized block; Assumption 4 is what guarantees the burst contribution
to (AC) is capped at `B` and the `r·(t − s)` term genuinely governs sustained
outflow. (AC) holds for the attacker even though the attacker controls `k`-of-`n`
keys, because, by **Assumption 3** (attacker model), the attacker cannot rewrite the
limiter; the `k`-of-`n` keys *authorise* withdrawals but every authorised withdrawal
still passes through the same bucket and is still counted in `A`.

### The circuit breaker and the response latency

The breaker trips (and a pause becomes pending) at the first instant either of two
events occurs:

- **(value trip)** cumulative outflow inside the sliding window `W` first exceeds
  the threshold `T`; or
- **(signal trip)** the change-point monitor raises a signal.

Let `t_trip` be the time of the trip. The pause is not instantaneous: it is
effective at `t_trip + Δ`, where `Δ = δ_detect + δ_include` is finite and bounded
(**Assumption 2**, liveness/inclusion bound), with `δ_include ≤ k·τ_block` (the
pause/revoke transaction is included within `k` blocks; no indefinite censorship).
After `t_trip + Δ` the limiter admits nothing, so `A` is constant from that instant:

  `A(t) = A(t_trip + Δ)`  for all  `t ≥ t_trip + Δ`.   **(STOP)**

The attacker cannot push the effective-pause time later than `t_trip + Δ`:
**Assumption 3** states the attacker cannot suppress the pause faster than `Δ`,
i.e. cannot censor or delay the pause beyond the bounded `Δ`. Hence `Δ` is a true
upper bound on the residual admission window, not merely a nominal one.

Total extraction is `X = A(∞) = A(t_trip + Δ)` by (STOP). The two regimes differ
only in **which trip fires** and therefore in how `t_trip` is bounded.

---

### 14.1 Fast-drain regime: `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`

> **Supersession notice.** Until Wave 2 this section proved `X_max ≤ T + r·Δ`.
> Porting that argument into the journal appendix refuted it. The old Steps 1–3
> are withdrawn in full and replaced by the arrival-curve argument below, which
> is line-for-line the statement, assumption set and constant of `main.tex`
> Appendix A (`sec:proof-fast`). The standalone record of the refutation is
> `journal/THEOREM_1_COUNTEREXAMPLE.md`.

**Theorem 1 (fast-drain bound).** Consider a single rate-limited exit choke point
within one limiter epoch, under Assumptions 1–4. If the trip occurs within the
first window (`t_trip ≤ W`), total extraction between attack onset and effective
response satisfies

  `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`,   **(F)**

independently of the value locked in the bridge. Beyond one window the same
envelope applies with `t_trip` in place of `W`, and grows linearly without a
constant cap.

*Proof.* Apply the arrival curve (AC) over `[0, t_trip + Δ)`. Since `A(0) = 0`,

  `X = A(t_trip + Δ) ≤ B + r·(t_trip + Δ)`.

**Assumption 4** caps the burst contribution at `B`, so no block inflates it;
**Assumption 3** ensures the held quorum authorises withdrawals without bypassing
the limiter, so (AC) binds the attacker; **Assumption 2** makes `t_trip + Δ`
finite and **Assumption 3** prevents the attacker from extending it, so by (STOP)
nothing is admitted afterwards; and **Assumption 1** makes `A` account for the
entire take. Substituting `t_trip ≤ W` gives the constant form. ∎ (14.1)

**Why the threshold does not appear.** It is natural to ask why `T` is absent,
since the in-path check caps every trailing window at `T`. The reason is that
`V(t) ≤ T` constrains the **trailing window**, not cumulative extraction, and the
two coincide only while `t ≤ W`. Write `V(t) = A(t) − A(t − W)`: for `t > W` the
quantity omits everything admitted before `t − W`, so outflow **retires** from the
window as time advances and the headroom it occupied becomes available again. Any
argument concluding `X ≤ T + r·Δ` must implicitly hold the window still across the
latency interval, and against a sliding window that step is unavailable.

**The failure is concrete, not technical.** Take ALT_TRIP (`B = 1000`, `r = 1`,
`T = 4000`, `W = 3600`, `Δ = 60`, twelve-second blocks) and the following schedule,
admissible under Assumptions 1–4 throughout and driving no window above `T`:

1. Withdraw the full burst `B` in the block at `t = 0`.
2. Withdraw at exactly `r` until `t = 2,600`, reaching `A = 3,600`.
3. Idle until `t = 3,600`, refilling the bucket to capacity.
4. Let the monitor signal at `t_trip = 3,600`, so the pause is effective at `3,660`.
5. At `t = 3,612` the burst admitted at `t = 0` has just left the trailing window,
   which now stands at `2,600`, so the banked capacity can be released without
   breaching `T`; then continue at `r` until the pause lands.

Realised extraction is **4,628 ETH** on twelve-second blocks, against the
**4,060 ETH** that `T + r·Δ` would permit and within the **4,660 ETH** of (F).

The schedule is written this way because it isolates the mechanism (the banked
burst is released exactly as the original burst retires), but it is **not the
strongest witness**. A schedule that simply spends the bucket greedily from onset
(the construction of §14.1.1) realises **4,648 ETH** under ALT_TRIP, so a single
number serves as both the refutation and the attainment figure. Verify either with
`journal/verify_regime.py`'s `simulate(...)`:

```python
def greedy(i, tok, vw, T): return min(tok, max(0.0, T - vw))
simulate(1000, 1, 4000, 3600, 60, 12, t_signal=3600, plan=greedy)   # -> 4648.0
simulate(1000, 1, 5000, 3600, 60, 12, t_signal=3600, plan=greedy)   # -> 4648.0
```

Note the second line: greedy realises the same 4,648 under LOCKED, which is why the
same construction proves attainment there. The adversarial-search table in
`journal/THEOREM_1_COUNTEREXAMPLE.md` reports 4,640 at `t_trip = W`; that is the
worst value the **random** schedule family happened to sample, not the supremum. The
supremum over admissible schedules is 4,648, one block's refill below the envelope.
Violations occur for every `t_trip ∈ (W − Δ, W]`, with the violating interval
widening linearly in `Δ`.

**Consequence for the on-chain validation.** At the LOCKED parameters no violation
of `T + r·Δ` is possible, but only because `B + r·(W + Δ) = 4,660` happens to fall
below `T + r·Δ = 5,060`, the arithmetic of the parameter choice, not the strength
of the mechanism. The **forty LOCKED** schedules of scenario 5 therefore could not
have falsified `T + r·Δ` whatever they did, so their agreement with it was never
evidence for it. The **five ALT_TRIP** schedules could have in principle (there
`4,060 < 4,660`), but the synchronous in-path check halts them at `T = 4,000`, so
they never reach the region where the two forms differ. Agreement with the envelope,
which a greedy schedule approaches to within one block, is the statement the
evidence supports.

*Assumptions used in 14.1:* **1**: `A` accounts for all exits (Preliminaries);
**2**: `Δ` finite and bounded, so `t_trip + Δ` is finite; **3**: the attacker
cannot rewrite the limiter (so (AC) binds) nor suppress the pause beyond `Δ`
(STOP); **4**: no same-block escape of the rate term (the within-block case of
(AC)). Assumption 5 enters only at the on-chain instantiation, as the additive
`r·drift` of the degradation corollary.

#### 14.1.1 Attainment lemma: the envelope is reached to within one block

> **Replaces the withdrawn tightness lemma.** The earlier lemma constructed a
> schedule reaching `T + r·Δ − ε` and concluded that bound was not slack. Since
> `T + r·Δ` is no longer the bound, the construction proves nothing about (F).
> What follows is the corresponding statement for the envelope, and it is weaker
> in form: attainment to within one block's refill, not exact tightness.

**Lemma (envelope attainment).** Suppose `B + r·W ≤ T`, as at the LOCKED
parameters. Then for any `t_trip ≤ W` there is a schedule admissible under
Assumptions 1–4 realising `X = B + r·(t_trip + Δ) − ε`, with `ε` at most one
block's refill `r·τ_block`.

*Proof.* Because `B + r·W ≤ T`, the arrival curve caps any trailing window at
`B + r·W ≤ T`, so the value trip can never fire and no withdrawal is ever blocked
in-path. The only halt available is the monitor signal, and by **Assumption 2** it
takes effect at `t_trip + Δ`. Submit withdrawals greedily from onset, spending the
bucket whenever it holds tokens: the limiter admits the initial capacity `B` and
every subsequent refill, so admitted outflow tracks `B + r·t` to within the
granularity of block arrivals, and the shortfall is at most the refill accrued
during the final partial block before the pause lands. ∎ (14.1.1)

At the LOCKED parameters with `t_trip = W`, where the constant form
`B + r·(W + Δ)` is evaluated, this realises **4,648 ETH** against the **4,660 ETH**
permitted, a shortfall of exactly one twelve-second block's refill. The headline
constant is therefore attained to within block granularity and **cannot be
lowered** without strengthening the assumptions.

**Where the condition fails.** `B + r·W ≤ T` is what makes the construction simple,
and it is the deployed condition. Where it fails (ALT_TRIP: `4,600 > 4,000`) the
in-path check becomes active and can block a greedy schedule before the envelope is
reached; extraction is then capped by the threshold instead, which is the
configuration under which the on-chain harness records extraction of exactly
`T = 4,000 ETH` on all five tripping schedules
(`docs/logs/scenario_5_bound.log:56–60`; [[h1_scorecard]] row 4). Either way the
guarantee is (F), and the threshold only ever tightens it.

**Spec-to-code anchor.** The Foundry stateful invariant
`invariant_slidingWindowOutflowNeverExceedsT`
(`test/foundry/BridgeInvariants.t.sol:33`, run via `make invariants`) asserts the
`≤ T` cap over every exact sliding window `[t − W, t]` of realised outflow within a
reset epoch, with no single-tx overshoot, directly against deployed bytecode. Note
what it does and does not establish: it constrains the **window**, which is exactly
the quantity that does not bound cumulative extraction. It is evidence that the
in-path check behaves as specified, not evidence for (F).

#### 14.1.2 LOCKED-parameter reachability: the value trip is unreachable by construction (layered defence)

Under the LOCKED ledger the on-chain value trip is **structurally unreachable,
and this is arithmetic, not accident**: the limiter admits at most
`B + r·W = 1000 + 1·3600 = 4,600 ETH` over any window of length `W` ((AC) with
`t − s = W`), and `4,600 < T = 5,000`, so `windowOutflow()`, which counts only
limiter-admitted outflow, can never exceed `T`. All **40 LOCKED on-chain
schedule rows** in `docs/logs/scenario_5_bound.log` accordingly record
`trip=no`; this is a consequence of the parameter choice, not evidence that
attacks fail to reach the threshold. The configuration is a deliberate
**layered defence**:

- **Live response path.** Under LOCKED the **monitor signal trip** is the only
  reachable automatic halt: every halt in the LOCKED evidence is
  monitor-signalled, and the patient bound (§14.2) is the guarantee that path
  carries.
- **Defense-in-depth headroom.** The synchronous `checkAndRecord` value trip
  (≈ 282k gas per withdrawal, `docs/bolt/gas_report.md`) never fires under
  LOCKED; it is paid for as **headroom**, a fail-safe that binds only if the
  limiter envelope is weakened (parameter change, limiter bug or bypass) or if
  governance narrows `T` below `B + r·W`. It converts "limiter
  misconfiguration" from a silent loss of the bound into a reachable hard stop.
- **Non-vacuity witness.** The trip machinery and the bound are not vacuous:
  the ALT_TRIP ledger (only `T` lowered to `4,000 < 4,600`) makes the value
  trip reachable, and **5 on-chain rows realise it**: extraction exactly
  `T = 4,000 ETH` with margin against the bound exactly `r·Δ` (§14.1.1).
  ALT_TRIP is the configuration a deployment would adopt to keep the value
  trip active; LOCKED trades that reachability for zero benign value-trip
  halts (scenario_8: 0 halts over the full benign stream vs 6 under ALT_TRIP).

At LOCKED defaults, then: the fast-drain envelope `X ≤ B + r·(W + Δ) = 4,660 ETH`
is enforced by the **limiter alone** (the per-window admission `≤ 4,600 < T` is
precisely why the value trip is dormant headroom), and the live detect-and-halt
story is the monitor path.
We keep LOCKED as the canonical evaluation ledger and disclose this rather
than re-parameterising to manufacture on-chain trips.

---

### 14.2 Patient (low-and-slow) regime: `E[X_slow] ≤ B + r·D + r·Δ` (expectation bound)

Now the attacker deliberately holds **every** sliding window's outflow below `T`:

  `V(t) = A(t) − A(t − W) ≤ T`  for all `t`.   **(P0)**

By construction (P0) means the **value trip never fires**: the static
value-threshold baseline is, by design, *blind* to this regime. This is precisely
the regime the [[threat_model]] flags as the one a value-threshold baseline misses.
Extraction is therefore halted only by the **signal trip** from the Phase-12
sequential change-point detector.

**Step 1: the *mean* detection delay is bounded by `D = ARL₁`; this is an
expectation, not a per-run cap.** To still satisfy its budget ("exfiltrate ≥
target value", [[threat_model]]) while obeying (P0), the attacker must sustain a
positive mean outflow drift (a change in the outflow process' running mean away
from the benign baseline), and we require that drift to be **at or above the
detector's detectability threshold** (the sub-drift case is treated separately
in §14.2.1; it is outside this bound). The Phase-12 detector is a sequential
change-point test whose mean time to detection for the attacker's chosen
post-change drift is its `ARL₁`, i.e.

  `E[t_trip] ≤ D = ARL₁ = 480 s`   (Phase 12 ledger value).   **(P1)**

**Units of `D`, stated explicitly.** The detector's run length to alarm is measured
in **observations**, not seconds. Write `n₁` for the mean run length to alarm at the
attacker's drift and `λ` for the attacker's transaction rate on the monitored
stream; then

  `D = n₁ / λ`   (seconds); `main.tex` Theorem 2 states this form.

Two consequences follow and are not cosmetic. First, an attacker who lowers `λ`
stretches `D` proportionally and so widens the bound, which is the mechanism behind
the cost-to-evade rate collapse of scenario 7. Second, because the detector is
**per-counterparty**, an attacker who splits the drain across `m` distinct
counterparty streams divides `λ` by roughly `m` on each, multiplying `D` on each
stream by roughly `m`. The deployed configuration caps distinct cash-out
destinations, which is what makes the split costly rather than free; without such
a cap the patient bound degrades linearly in `m`. This is a scope condition on the
patient statement.

`D` is a **censored** empirical estimate: trials in which the detector never
trips are right-censored and excluded from the average, so the measured `D` is a
mean *conditional on detection* and hence a lower bound on the true mean delay,
and `E[X_slow] ≤ B + r·D + r·Δ` inherits that optimism whenever the reported
detection fraction is below 1 (see `measure_arl1` in
`monitor/sequential_detector.py`, which returns `n_detected`/`n_trials` with the
mean).

(P1) is a statement about the **mean** of the random detection delay `t_trip`,
not about every realisation: individual detection delays have a right tail, and
no step below converts (P1) into a deterministic per-run cap. `D` is the
operating-characteristic guarantee of the detector for the attacker's drift;
the white-box attacker of the [[threat_model]] who knows the detector and
minimises its drift (subject to detectability) to maximise stealth is exactly
the adversary against which `ARL₁` is the worst-case **mean** detection delay.
(The empirical Phase-15/16 harness validates that realised detection delays
concentrate at or below `D` for the calibrated drift; it does not, and cannot,
show that no realisation exceeds `D`.)

**Step 2 (pathwise): total outflow up to the effective pause is bounded by (AC)
over `[0, t_trip + Δ)`, counting the burst `B` once.** The patient attacker is
halted only by the signal trip at the (random) time `t_trip`, after which the
pause is effective within `Δ` (**Assumption 2**) and the attacker cannot delay
it (**Assumption 3**: cannot suppress the pause faster than `Δ`). By (STOP) the
entire take on any single realisation is `A(t_trip + Δ)`. We bound it by the
arrival curve **honestly**, making no claim that the bucket is depleted or in
"steady state": applying (AC) over `[0, t_trip + Δ)`,

  `X_slow = A(t_trip + Δ) ≤ B + r·(t_trip + Δ) = B + r·t_trip + r·Δ`.   **(P2)**

(P2) holds **pathwise** (on every realisation), but its right-hand side
contains the random delay `t_trip`, not the constant `D`. The token bucket
**starts full** at attack onset (capacity `B`; both the Phase-13 RateLimiter and the
fallback `_SimBucket(B, r, t0)` initialise `tokens = capacity` at `t = 0`). A
white-box attacker (**Assumption 3**) who chooses the start time may therefore
spend that initial `B`-reserve thinly across blocks. Doing so does **not**
violate (P0): spreading `B` across the window keeps every trailing-window sum below
`T`. Worked instance (the harness's `ronin-patient`): per-block trickle
`0.9·(T / 300) = 15 ETH`, and over `300` blocks per window the window sum is
`15 × 300 = 4500 ETH < T = 5000`, so (P0) holds, yet the sustained rate
`15 ETH / 12 s = 1.25 ETH/s > r = 1 ETH/s`, which is feasible *precisely because the
initial reserve `B` supplies the excess `0.25 ETH/s` until it is exhausted*. The
attacker thus drains the initial `B` over the detection interval without ever tripping
the value path. Removing `B` from the bound would require an additional assumption
("bucket depleted at onset") that is **not** among Assumptions 1–4 and cannot be
justified against a white-box attacker who picks the start time. We therefore keep `B`.

**Step 3 (no separate residual step needed).** (P2) already covers the whole
interval `[0, t_trip + Δ)` in one application of (AC), so the burst is counted
exactly once over the entire attack rather than re-introduced in a residual
sub-interval. (Assumption 4 still underwrites (AC): no same-block escape inflates the
burst beyond `B`.)

**Step 4: the expectation step (this is where the bound becomes an
expectation).** (P2) is pathwise but random on its right-hand side. Take
expectations of both sides of (P2): this is the **only probabilistic step in
the proof, and it is what makes the patient bound a mean-extraction bound
rather than a per-run guarantee**. By monotonicity and linearity of
expectation, then (P1):

  `E[X_slow] = E[A(t_trip + Δ)] ≤ B + r·E[t_trip] + r·Δ ≤ B + r·D + r·Δ`.

As in 14.1, **Assumption 1 (atomic choke point)** is what makes `A` capture the
attacker's entire take: were there an un-instrumented exit, the patient attacker
would simply drain through it and neither trip would matter. Hence under
Assumptions 1–4 (and **only** these, with no smuggled "steady-state" or
"depleted-bucket" extra assumption),

  **`E[X_slow] ≤ B + r·D + r·Δ`.**  ∎ (14.2)

**Quantile corollary (per-run companion form).** Because (P2) is pathwise, any
high-probability bound on the delay transfers directly to extraction: if
`Pr[t_trip ≤ D_q] ≥ q` (with `D_q` the `q`-quantile of the detection-delay
distribution for the attacker's drift), then with probability at least `q`,

  `X_slow ≤ B + r·D_q + r·Δ`.

This is the correct per-run form of the patient bound; it requires knowledge of
the delay distribution's quantiles, which `ARL₁` alone does not provide. This
work carries the **expectation form as primary** (it is what the measured
`ARL₁` supports) and does not claim empirical values for `D_q`.

*Assumptions used in 14.2:* **1**: `A` accounts for all exits (Steps 2–4); **3**:
attacker cannot suppress the pause faster than `Δ` and (being white-box) may pick the
start time so the full initial burst `B` is available (Step 2), and cannot rewrite the
limiter so (AC) holds; **2**: `Δ` finite/bounded so `t_trip + Δ` is finite on every
realisation with a detectable drift (Step 2); **4**: underwrites (AC) (no same-block
escape inflates the burst beyond `B`). The pathwise bound follows from (AC) over
`[0, t_trip + Δ)` directly; it does **not** rely on the bucket being empty at any
point. The conversion from delay to extraction happens **in expectation** (Step 4).

#### 14.2.1 Degenerate sub-drift case: limiter envelope only (scope limitation)

Both (P1) and the expectation step require the attacker's drift to be **at or
above the detector's detectability threshold** (the CUSUM/Page–Hinkley
reference drift `δ`). A white-box attacker who deliberately holds the outflow
drift **below** that threshold defeats the premise of Step 1: for sub-threshold
drift the detector's `ARL₁` is effectively unbounded (the "detection" time
degenerates toward the false-alarm time `ARL₀`), so `D` ceases to be a
meaningful bound and **no detection-based term applies**. In that regime the
value trip does not fire (P0), the signal trip is not expected to fire, and the
only surviving control is the arrival curve itself:

  `X_sub-drift(t) ≤ B + r·t`  for all `t ≥ 0`   (limiter envelope, linear in time).

Cumulative sub-drift extraction is therefore **unbounded in time** under this
theorem (floored only by the limiter's rate `r`) until a control outside the
theorem's assumptions (periodic audit, credential rotation, governance review)
intervenes. This is an explicit **scoping limitation** of the patient claim,
not a footnote: the patient bound shrinks expected loss only for drifts the
detector can see. (At the ledger rate `r = 1 ETH/s`, reaching Ronin scale
sub-drift would still take ≳ 2 days of sustained, unnoticed trickle, a
materially different attack from the historical 2-transaction drain, but the
theorem itself imposes no cumulative cap here.)

**Reset semantics and cumulative loss (governance caveat).** The sub-drift
envelope above is one face of a general fact: **on-chain mechanisms alone do
not bound *cumulative* loss**: the limiter caps the rate (`B + r·t`) and the
breaker caps one window's outflow, but absent a trip a patient attacker
extracts up to `min(T, B + r·W)` per window (4,600 ETH under LOCKED)
**indefinitely**; bounding the cumulative take is the detector's job, and the
patient bound `E[X_slow] ≤ B + r·ARL₁ + r·Δ` is exactly that statement for
detectable drifts. The caveat compounds through governance:
`CircuitBreaker.reset()` clears **both** the latch **and** the window buckets
(`contracts/CircuitBreaker.sol:157-165`), so a premature reset mid-incident
does not resume the interrupted window; it **re-arms a fresh `T` of
value-trip headroom (5,000 ETH per premature reset under LOCKED)** on top of
forfeiting the latch. Each trip→reset cycle restarts the extraction clock
rather than resuming it. The operational mitigation (reset cool-down ≥ one
full window `W`, plus a post-incident review gate before any reset) is
specified in [[threat_model]] §F.

Both bounds are **TVL-independent**: neither `B + r·(W + Δ)` nor `B + r·D + r·Δ`
(bounding `E[X_slow]`) contains total value locked: they depend only on the
limiter (`B`, `r`), the window (`W`), the detector (`D`), and the latency (`Δ`).
Note that the envelope does not depend on the breaker threshold `T` either. This
is the differentiator vs. ERC-7265 (no proof, no latency term) and ASAS-BridgeAMM
(a probabilistic fraction-of-collateral guarantee, AMM-coupled, though it does treat
latency; see the corrected positioning note above).

---

### 14.3 Ronin worked example: the `173,600`-ETH drain is impossible by construction

Ledger configuration: `T = 5000 ETH`, `B = 1000 ETH`, `r = 1 ETH/s`,
`D = 480 s`, `n = 9`, `k = 5`.

**(a) The single-block mega-drain is impossible.** The actual Ronin incident drained
`173,600 ETH` in essentially two transactions. Under BOLT, **Assumption 4** caps a
*single block* at `B = 1000 ETH`. So `173,600 ETH` in one block is impossible by
construction: it would require

  `173,600 / B = 173,600 / 1000 = 173.6` → at least **174 blocks** just to clear the
  bucket rate-limit, even ignoring the window threshold.

**(b) The single-window mega-drain is impossible.** The breaker trips when windowed
outflow exceeds `T = 5000 ETH`. To extract `173,600 ETH` the attacker must cross the
`T = 5000` threshold many times over:

  The binding statement is the **envelope**, not the threshold. Over one window plus
  the response latency the limiter can release at most
  `B + r·(W + Δ) = 4,660 ETH` (**1.6 orders of magnitude below** `173,600`), and
  that holds whether or not the value trip is reachable. At LOCKED it is *not*
  reachable (§14.1.2: `B + r·W = 4,600 < T = 5,000`), so the correct statement is
  the limiter one: the attacker is stopped by the arrival curve, and the threshold
  never enters. Under ALT_TRIP the threshold binds first and stops the attacker
  sooner still, at `T = 4,000`. Either way one window releases a small fraction of
  a percent of the Ronin drain.

Therefore the value-maximising attacker is **forced out of the fast-drain regime**
and into the patient regime, where the detector, not the value threshold, is the
binding control.

**(c) Numeric bounds.** Take an **illustrative response latency** `Δ = 60 s`. We
justify it via the inclusion bound: with `δ_include ≤ k·τ_block`, `k = 5`, and an
Ethereum-class block time `τ_block ≈ 12 s`, the inclusion component is
`δ_include ≤ 5 · 12 = 60 s`; taking `δ_detect` negligible relative to inclusion for
the value-trip path gives an illustrative `Δ ≈ 60 s` (a deliberately *pessimistic*
choice: it assumes the pause waits the full `k`-block inclusion budget).

- **Fast-drain regime (the envelope):**
  `X ≤ B + r·(W + Δ) = 1000 + 1·(3600 + 60) = 4660 ETH.`
  Ratio to the actual loss: `4660 / 173,600 ≈ 2.7%`, i.e. the worst-case fast-drain
  extraction is **~37× smaller** than what Ronin lost, and the halt lands inside one
  window plus the latency (`≤ 3,660 s`), not after **6 days**. The superseded
  `T + r·Δ = 5,060 ETH` (≈ 2.9%) is a limiter-only reference level and is recorded
  here only so older figures can be reconciled.

- **Patient regime (in expectation):**
  `E[X_slow] ≤ B + r·D + r·Δ = 1000 + 1·480 + 1·60 = 1540 ETH.`
  Ratio to the actual loss: `1540 / 173,600 ≈ 0.9%`, i.e. **~113× smaller** than
  Ronin's loss *in expectation*, detected in **mean** time
  `D + Δ = 480 + 60 = 540 s` (**under 10 minutes**), versus the actual **6-day**
  detection lag. These are expected values: individual patient runs can exceed
  them because the detection delay has a tail (§14.2 Step 4). The initial burst
  `B` reserve is counted honestly: a white-box attacker who picks the start time
  can spend it while holding every window below `T`, so it must appear in the
  bound. And if the attacker drifts **below** the detectability threshold, no
  detection term applies at all: extraction is floored only by the limiter
  envelope `B + r·t` (§14.2.1).

**(d) Summary table.**

| Quantity | Actual Ronin | BOLT envelope `B + r(W+Δ)` (deterministic) | BOLT patient `E[X_slow]` (expectation) |
|----------|-------------:|------------------:|----------------------:|
| Extraction (ETH) | 173,600 | ≤ 4,660 | ≤ 1,540 (mean) |
| Detection / halt time | ~6 days | ≤ ~1 window (≤ 3600 s) | ≤ 540 s (mean) |
| Fraction of Ronin loss | 100% | ~2.7% | ~0.9% (mean) |

Both BOLT bounds are **orders of magnitude** below `173,600 ETH` and both halt in
**seconds-to-minutes**, not **days**: the fast-drain envelope per-run, the patient
bound in expectation. The mega-drain is impossible by construction (Assumption 4
caps the block at `B` and the arrival curve caps the whole interval at
`B + r·(W + Δ)`; at LOCKED the breaker never binds at all), and the remaining
patient avenue, for detectable drifts, is bounded in expectation by the
detector at `B + r·D + r·Δ`; sub-detectability drift is bounded only by the
limiter envelope `B + r·t` (§14.2.1). This discharges the extraction clause of
H1 (see [[hypothesis]]) with the patient clause read as an expectation claim.

> **Honest caveats.** This is a *design specification*, not a tested system. `Δ`
> here is illustrative; the realised `Δ` and the realised detection delay vs. the
> mean `D = ARL₁` are validated empirically in later phases. `D` is a **mean**
> time to detection, not a per-run cap, which is why the patient bound is stated
> in expectation (§14.2 Step 4), with the quantile form `B + r·D_q + r·Δ` as the
> per-run companion; the empirical harness reports the realised distribution.
> Note also that the scenario-7 cost-to-evade composition **substitutes the
> assumed `D = 480 s`** wherever a schedule produces no empirical detector trip
> (its logs mark this verbatim: "NOT an empirical trip — raw det_prob is 0.0");
> measuring `D` on real onset data is future work. False-positive cost `φ` on
> benign traffic is **not** asserted here and is measured in Phase 16.

**Simulation scope (what ran where).** Two harnesses back the empirical claims
around this theorem, and they are not the same kind of evidence.
**scenario_5** (45 schedules, `docs/logs/scenario_5_bound.log`, header
`# mode(s): hardhat`) is validated **on-chain**: every schedule executes
against the deployed BridgeV2/RateLimiter/CircuitBreaker bytecode on a Hardhat
node, and realised extraction is read back from chain state. **scenario_7**
(the 4,392-schedule adaptive sweep,
`docs/logs/scenario_7_cost_to_evade.log`) is an **offline pure-Python
simulation** of the limiter/breaker/detector composition; it never touches a
chain (its log says so: `# mode: offline`). Any statement of the form "the
bound was never violated across the adaptive sweep" carries this scope:
on-chain validation covers exactly the 45 scenario-5 schedules; the
4,392-schedule sweep is simulation-only evidence.

---

## Objections answered

Four standard objections are raised against any "bounded bridge" guarantee. Each
is answered below by naming the specific assumption (or mechanism) that
neutralises it, and stating the **residual risk** honestly where the objection is
only partially resolved.

### Objection 1: Monitor as single point of failure

> *"If the change-point monitor is a single point of failure, an attacker who
> takes it down (DoS, crash, feed poisoning) defeats detection and the bound is
> void."*

**Answer.** The bound does **not** depend on the monitor in the fast regime. The
circuit breaker has **two independent trip conditions** (Setup; §14): a *value
trip* (windowed outflow `> T`) and a *signal trip* (monitor). The value trip is an
**in-path, synchronous** check evaluated by the limiter itself at withdrawal time:
it fires from on-chain state, with **no monitor in the loop**. By
**Assumption 1 (atomic choke point)** every value-bearing exit routes through this
limiter, so even with the monitor entirely dead the windowed outflow is still
measured and the value trip still fires. More importantly, the envelope of §14.1
does not reference the monitor at all (it follows from the arrival curve and the
bounded pause latency alone), so the monitor-free regime is still bounded:

  `X ≤ B + r·(t_trip + Δ)`  (holds with the monitor down; with no monitor the
  binding `t_trip` is the value trip, if that trip is reachable at all).

  This makes an honest caveat visible: with the monitor dead **and** the value trip
  unreachable (`B + r·W ≤ T`, the LOCKED case), nothing halts the attacker within
  the epoch, `t_trip` is unbounded, and the envelope degrades to the linear
  limiter-only form `B + r·t`. That is the same scope limit as §14.2.1, and it is
  why LOCKED is described as trading trip reachability for benign liveness rather
  than as strictly safer.

(Under the LOCKED ledger the value trip is additionally unreachable by
construction: the limiter alone caps any window at `B + r·W = 4,600 < T`, so
the fast bound holds a fortiori there; the trip is defense-in-depth headroom,
§14.1.2.)

The monitor's role is purely to **tighten** the patient regime from the
value-trip ceiling down to the expected-extraction bound `B + r·D + r·Δ`
(§14.2). Killing the monitor cannot
*raise* extraction above the value-trip ceiling; it only forfeits the slow-regime
improvement.

**Residual risk.** With the monitor down the defender **loses the `r·D` slow-regime
detection** and falls back to the value-threshold trip. A patient attacker who
holds every window below `T` (P0) is then bounded only by the static threshold per
window, not by `D`, i.e. the system degrades to a value-threshold baseline for as
long as the monitor is unavailable. The bound never *breaks*, but its tightness in
the patient regime is monitor-dependent. (Monitor availability/redundancy is an
operational concern outside the stated assumptions; honest future work.)

### Objection 2: Attacker races the pause

> *"The attacker simply drains everything in the `Δ` window between the trip and
> the effective pause; the latency gap is a free-for-all."*

**Answer.** The `Δ` window is **not** a free-for-all; the maximum extractable
during it is exactly the `r·Δ` slack term the bound **already accounts for**. Two
assumptions close this:

- **Assumption 4 (no same-block escape)** caps admitted outflow at `≤ B` in any
  single block, so the attacker cannot defeat the *rate* term by cramming one
  oversized block into the race window (§14.1 Step 1; the within-block case of the
  arrival curve (AC)).
- **Assumption 2 (liveness/inclusion bound)** makes `Δ = δ_detect + δ_include`
  **finite and bounded** (`δ_include ≤ k·τ_block`), so the race interval has a hard
  upper length.

Over that finite interval the arrival curve (AC) caps the residual admission. In
the **fast-drain** regime a single application of (AC) over `[0, t_trip + Δ)`
bounds the whole take at `B + r·(t_trip + Δ)`, counting the burst exactly once; the
race adds nothing beyond the `r·Δ` already inside that expression. We do **not**
rely on the bucket being empty at the trip, and, since the corrected argument no
longer routes through the breaker cap, we do not rely on the windowed-outflow
check either. In the **patient**
regime the whole interval `[0, t_trip + Δ)` is bounded in one (AC) application,
`A(t_trip + Δ) ≤ B + r·t_trip + r·Δ` pathwise (§14.2 Step 2), which in
expectation gives `E[X_slow] ≤ B + r·D + r·Δ` (§14.2 Step 4), counting the
full-at-onset burst `B` once and the refill over the whole attack; the race's
`r·Δ` is part of that single term, not a free addition. The race does not add
anything the proof has not already paid for.

**Residual risk.** The bound's tightness here is only as good as the **realised**
`Δ`. If `δ_include` exceeds `k·τ_block` (sustained censorship beyond the
inclusion assumption, which **Assumption 2 rules out by hypothesis**), or if
`δ_detect` is larger than modelled, the `r·Δ` term grows linearly in the true
latency. The bound's *form* is exact; its *numeric value* inherits whatever the
operational `Δ` actually is, validated empirically in later phases. None material
**under** Assumption 2; the residual lives entirely in whether Assumption 2 holds
in deployment.

### Objection 3: Benign-user friction

> *"Rate limits and circuit breakers punish legitimate users; this is a usability
> tax that real bridges will not accept."*

**Answer.** The limiter is sized as a **tail control, not a steady-state tax**. The
ledger values give legitimate throughput substantial headroom: `r = 1 ETH/s`
≈ **86,400 ETH/day** of sustained refill, and the per-window threshold
`T = 5000 ETH` over `W = 3600 s`. Honest flows that stay within this envelope
**never touch** either trip: the breaker is engineered to fire only on the
anomalous tail (a drain that crosses `T` in one window, or a detectable drift).
Because both bounds are **TVL-independent**, the headroom is set by configuration,
not by how much value sits in the bridge, so operators can size `r`, `B`, `T` to
their legitimate demand profile without weakening the guarantee.

**Residual risk.** A circuit breaker is a **liveness/safety
trade-off**: any genuinely large legitimate withdrawal burst that crosses `T` will
be paused alongside an attack, a **false positive** with a real cost (delayed
honest funds until governance review). This PoC **does not** assert a
false-positive rate `φ` on benign traffic; `φ` is **unknown here** and is measured
empirically in Phase 16 against the calibrated benign generator. The honest
position is: the *bound* is unconditional, but its *operational acceptability*
depends on a `φ` we have not yet quantified. This is a genuine residual, not
fully resolved by the stated assumptions (which concern safety, not benign cost).

### Objection 4: Cross-chain asynchrony

> *"The bound assumes a single synchronous chain, but bridges are inherently
> asynchronous and multi-chain; the guarantee does not survive composition."*

**Answer.** The bound is stated, deliberately and explicitly, as
**per-chain-per-epoch**: one rate-limited exit choke point, one limiter epoch
(Setup; *Positioning vs. prior bounded-bridge work*). **Assumption 1 (atomic choke
point)** is what scopes it: it asserts a *single* instrumented exit on the chain
the bound is quantified over. The proof makes **no claim** about composing bounds
across chains, across limiter epochs, or under inter-chain message asynchrony. A
multi-chain bridge that deploys BOLT applies the bound **independently per chain
per epoch**; the aggregate cross-chain guarantee is **not** the sum of per-chain
bounds without further argument.

**Residual risk.** Cross-chain / multi-epoch **composition is out of scope** for
this statement and is **honest future work**. Open questions a composed theorem
must address: epoch-boundary effects (does an attacker straddle two epochs to get
`2·r·Δ`?), asynchronous pause propagation across chains (one chain pauses while
another keeps admitting), and shared-collateral coupling between chains. None of
these is resolved here; the per-chain-per-epoch bound is exactly that and no
more. This is the clearest residual of the four: the objection is **acknowledged
as a scope boundary, not neutralised**.

### Red-team sign-off

> **Sign-off (red-team verdict, revised; Phase-14 review round 2).** The two
> bounds (`X_max ≤ T + r·Δ` deterministic, `E[X_slow] ≤ B + r·D + r·Δ` in
> expectation) hold under Assumptions 1–4.
> **[Superseded by round 6 below: the deterministic bound is now the envelope
> `X ≤ B + r(t_trip + Δ)`; `T + r·Δ` was refuted. This round-2 text is kept
> verbatim as a record of the review history, not as a current claim.]**
> The patient bound now **counts the initial burst `B`** that the (full-at-onset)
> token bucket makes available to a white-box attacker who picks the start time;
> the earlier `r·D + r·Δ` figure was **retracted** because it silently assumed a
> depleted/steady-state bucket, an unstated extra assumption the bundled harness
> refuted (patient schedules realised up to ~1029 ETH against a 540-ETH claim). The
> corrected bound follows from the pathwise arrival curve (AC) over
> `[0, t_trip + Δ)` plus one expectation step (§14.2 Step 4) strictly
> from Assumptions 1–4, with the burst counted **once**; the harness (scenario
> 5) now passes for **all** schedules (realised ≤ bound, every Δ, both regimes). The
> fast bound's residual term is re-derived from the breaker cap (F1) plus (AC)
> rather than the false "bucket depleted at trip" claim. All four standard
> objections are answered in-text and grounded in the specific neutralising
> assumption. Objections 1 and 2 are fully neutralised by the proof (value trip is
> monitor-free; the race extracts only the already-budgeted `r·Δ`). Objections 3
> (benign false-positive cost `φ`, unquantified) and 4 (cross-chain/multi-epoch
> composition, out of scope) carry **honest, explicitly-scoped residual risks**
> that do not break the stated per-chain-per-epoch safety bound but bound its
> operational generality. **Verdict: proof + objections hold together as a design
> specification; the patient bound is corrected to `B + r·D + r·Δ` (now read
> **in expectation**; see round 3 below); residuals are
> disclosed.**

> **Phase-22 revision (round 3: soundness of the patient statement).** The
> patient bound is restated **in expectation**: `E[X_slow] ≤ B + r·D + r·Δ`,
> because `D = ARL₁` is a *mean* detection delay and cannot support a
> deterministic per-run guarantee alongside the (genuinely deterministic)
> fast-drain bound, which round 6 below corrects from `T + r·Δ` to the envelope
> `B + r·(t_trip + Δ)`. The proof now separates the pathwise arrival-curve
> step (P2) from the single expectation step (§14.2 Step 4); a quantile
> companion form `X_slow ≤ B + r·D_q + r·Δ` (probability ≥ q) is stated for
> per-run use, with `D_q` unmeasured here. The **sub-drift degenerate case** is
> scoped explicitly (§14.2.1): drift below the detector's detectability
> threshold voids the detection term entirely and extraction is floored only by
> the limiter envelope `B + r·t`, linear in time. The scenario-7 composition's
> substitution of the assumed `D` where no empirical trip occurs is disclosed
> in the §14.3 caveats.

> **Phase-22 revision (round 4: tightness, clock model, and evidence scope).**
> (i) A **tightness lemma** (§14.1.1) exhibits an explicit attacker schedule
> achieving `T + r·Δ − ε` on the asynchronous halt path, matched on-chain by
> the ALT_TRIP rows realising exactly `T` with margin exactly `r·Δ`: the fast
> bound is proven, implemented, and tight. **[Withdrawn in round 6: with
> `T + r·Δ` refuted, this construction establishes nothing about the bound. It is
> replaced by the attainment lemma of §14.1.1.]** (ii) The lemma also pins down where
> the slack lives: the `r·Δ` term is **not consumable against the synchronous
> on-chain value trip** (realised `≤ T` structurally); it budgets the off-chain
> monitor path only. (iii) **Assumption 5 (timestamp trust)** is named
> explicitly: refill and window aging run on `block.timestamp`, and
> seconds-bounded proposer drift degrades each bound additively by at most
> `r·drift` ([[static_analysis]] IDs 13–25). (iv) The **simulation scope** of
> the empirical evidence is disclosed in §14.3: scenario_5's 45 schedules are
> on-chain (hardhat mode); scenario_7's 4,392-schedule adaptive sweep is
> offline pure-Python simulation.

> **Phase-22 revision (round 5: LOCKED reachability and reset semantics).**
> (i) §14.1.2 foregrounds that under LOCKED parameters the on-chain value trip
> is unreachable **by construction** (`B + r·W = 4,600 < T = 5,000`; all 40
> LOCKED rows trip=no), a deliberate layered-defence choice: the monitor
> signal trip is the live response path, `checkAndRecord` is defense-in-depth
> headroom, and ALT_TRIP (`T = 4,000`) is the non-vacuity witness (5 rows
> realise the trip and the bound margin exactly). (ii) §14.2.1 adds the
> reset/cumulative-loss caveat: on-chain mechanisms bound rate, not cumulative
> loss, and a premature `reset()` re-arms a fresh `T` (5,000 ETH under LOCKED)
> because it clears the window along with the latch; the operational
> cool-down + review-gate policy is specified in [[threat_model]] §F.

> **Wave-2 revision (round 6: Theorem 1 refuted and replaced).** Porting §14.1
> into the journal appendix did not confirm `X_max ≤ T + r·Δ`; it **refuted** it.
> That form implicitly holds the trailing window still across the response
> latency, but the deployed window slides: outflow admitted early retires from it
> and the freed headroom re-opens. An explicit admissible schedule extracts
> **4,648 ETH** under ALT_TRIP against the **4,060 ETH** the old form permits
> (§14.1; `journal/verify_regime.py` searches the family and finds violations for
> every `t_trip ∈ (W − Δ, W]`). The deterministic statement is now the
> **arrival-curve envelope** `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`, which is
> TVL-independent, **threshold-independent**, and identical (**4,660 ETH**) under
> both the LOCKED and ALT_TRIP ledgers. The **tightness lemma is withdrawn** and
> replaced by an **attainment lemma** (§14.1.1): a greedy schedule realises
> **4,648 ETH** against 4,660 (one block's refill short), so the constant cannot
> be lowered, but it is attainment to within block granularity, not exact
> tightness. Consequences propagated across this repository under J16: no file
> states 5,060 ETH or 2.9% as the bound, and every surviving `T + r·Δ` names
> itself as a superseded limiter-only reference level. The patient bound
> `E[X_slow] ≤ B + r·D + r·Δ` is **unaffected** (it never routed through `T`),
> and its `D = n₁/λ` decomposition is now stated explicitly.

---

### 14.4 Future work: mechanised proof

A fully **machine-checked** formalisation of this theorem (e.g. in **Coq** or
**Isabelle/HOL**) is **explicitly out of scope** for this work and is left as
future work. The present deliverable is a rigorous pen-and-paper proof plus an
empirical validation harness. A mechanised version would add, beyond what the
pen-and-paper argument establishes:

- a formal model of the admitted-outflow process `A` and the σ-ρ arrival curve (AC)
  as a checked inductive/coinductive object, with the token-bucket service
  discipline discharged as a lemma rather than asserted in prose;
- machine-verified case analysis over the trip events (value trip vs. signal trip),
  confirming that a single application of (AC) over `[0, t_trip + Δ)` counts the
  burst term `B` exactly once in each regime with no reliance on any
  bucket-depletion claim, and a checked treatment of the patient regime's
  expectation step (§14.2 Step 4) over the delay distribution;
- an explicit, checked encoding of each assumption as a hypothesis, so a
  reviewer can confirm by construction that no step uses an unstated assumption;
- mechanically-checked real-arithmetic for the units and the Ronin numerics.

This would raise the assurance level from "reviewed pen-and-paper" to
"machine-checked," at the cost of substantial formalisation effort; it does not
change the bounds, which are already units-checked and stated above.

See [[hypothesis]] for how these bounds discharge H1 and [[threat_model]] for the
adversary the proof is quantified over.

> **Reference.** R. L. Cruz, "A calculus for network delay, Part I: Network
> elements in isolation," *IEEE Transactions on Information Theory*, vol. 37, no. 1,
> pp. 114–131, 1991: the σ-ρ arrival-curve / token-bucket machinery used above.
