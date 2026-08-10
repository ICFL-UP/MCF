# BOLT — MCF Hypothesis H1

> **J16 SUPERSESSION NOTE (Wave 4, 2026-08-02).** The deterministic loss bound
> `X ≤ T + r·Δ` (5,060 ETH at the locked ledger, 4,060 alt-trip) was **refuted**:
> the trailing window slides, so outflow admitted early retires from it during the
> response latency and the freed headroom re-opens. An explicit admissible schedule
> extracts 4,648 ETH against the 4,060 that form permits. The proved statement is the
> arrival-curve envelope `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ) = 4,660 ETH`
> (**2.7%** of the Ronin loss) — TVL-independent, threshold-independent, and identical
> under both ledgers. Every `T + r·Δ` below is a **limiter-only reference level**,
> never a bound. The patient bound `E[X_slow] ≤ B + r·D + r·Δ = 1,540 ETH` is
> unaffected. See `docs/bolt/theorem.md` §14.1, `journal/manuscript/main.tex`
> Appendix A, and `journal/THEOREM_1_COUNTEREXAMPLE.md`.
> **This file is the pre-registration and is deliberately NOT edited.** Rewriting a
> registered hypothesis after the evidence is in would destroy its purpose. The
> Respond clause is scored as **refuted in its registered form** and re-scored
> against the envelope in `docs/bolt/h1_scorecard.md` row 4.

> **BOLT** = *Bounded On-chain Loss Threshold*. This document states the central
> falsifiable hypothesis the BOLT line of work (Phases 12–17) is built to test.
> It is a **design specification**, not a tested system; all empirical clauses
> are measured in later phases as noted.

Related contract documents: [[threat_model]] · [[theorem]]

---

## MCF Hypothesis H1 (verbatim, from dissertation Chapter 11)

> "An MCF-conformant bridge (Protect = DID-gated, revocation-aware validator
> identity; Detect = sequential anomaly detection; Respond = on-chain
> rate-limited circuit breaker) bounds worst-case attacker extraction to
> T + r·Δ and detects low-and-slow exfiltration that a value-threshold baseline
> misses, at a false-positive cost of ≤ φ on benign bridge traffic."

### Venue-neutral operative form (paper H1)

For journal review purposes the hypothesis is restated without MCF branding.
The fast-regime bound and the falsification conditions are those of the
verbatim form; the operative form additionally makes the patient-regime
clause explicit as an expectation bound (`E[X_slow] ≤ B + r·D + r·Δ`, stated
in dissertation §11.5.3) and states φ as measured rather than budgeted (see
the reframed detector claim below):

> **H1 (operative).** A DID-anchored validator registry with cryptographic
> credential binding and automatic expiry (Protect), combined with a windowed
> on-chain outflow bound and sequential change-point detector (Detect + Respond),
> bounds worst-case attacker extraction to `T + r·Δ` (fast regime, deterministic)
> and `E[X_slow] ≤ B + r·D + r·Δ` (patient regime, in expectation), and detects
> low-and-slow exfiltration that a static value-threshold baseline misses, at a
> measured benign false-positive cost φ.

**MCF provenance note.** The architecture (Protect / Detect / Respond functions,
DID format `did:ethr:<chainId>:<address>`, credential lifecycle) derives from the
author's MSc dissertation on the Metaverse Cybersecurity Framework (MCF, Chapter 11).
The dissertation is currently unpublished; all artifact code and evaluation data are
publicly available in the project repository. The paper's claims — both the formal
loss bound and the empirical measurements — stand independently of the MCF framing
and are verifiable from the artifacts alone.

---

## Mapping H1 to Protect / Detect / Respond

H1 binds the three MCF functions to concrete, falsifiable claims, each traceable
to the dissertation. **Protect** (DID-gated, revocation-aware validator identity;
dissertation §6.4, §11.2.1) ensures that only credential-holding validators can
authorise withdrawals and that revoked or expired credentials are invalidated
automatically — it does not by itself bound losses once `k`-of-`n` keys are
compromised, which is exactly the Ronin failure mode (see [[threat_model]]).
**Detect** (sequential anomaly / change-point detection; §6.5, §11.2.2) supplies
the `D = ARL₁` **mean** time to detection that makes the patient (low-and-slow)
regime **expectation bound** `E[X_slow] ≤ B + r·D + r·Δ` finite, and is what
lets MCF catch slow exfiltration a static value-threshold baseline misses. The
patient clause is an expected-extraction claim, not a per-run worst case (the
fast bound `T + r·Δ` remains deterministic); and it applies only to attack
drifts the detector can see — for drift below the detector's detectability
threshold no detection term applies and extraction is bounded only by the
limiter envelope `B + r·t`, linear in time ([[theorem]] §14.2, §14.2.1). **Respond**
(on-chain rate-limited circuit breaker: token bucket of capacity `B`, refill `r`,
per-window threshold `T` over window `W`; §6.6, §11.2.3) is what makes
extraction bounded at all, contributing the `T + r·Δ` fast-attack bound and the
`r·Δ` post-signal slack via the response latency `Δ = δ_detect + δ_include`. The
full symbol table and both bound regimes are stated in [[theorem]]; the four
theorem assumptions are stated identically in [[threat_model]] and [[theorem]].

The false-positive budget **φ** is the benign false-positive cost the Detect/
Respond pipeline imposes on legitimate bridge traffic (spurious trips / benign
volume). φ is **not** asserted a priori — it is **measured in Phase 16** on
benign bridge traffic, and the honest framing is that absolute false-positive
rates are unknown until that measurement. H1 is falsified if any of: (a) observed
extraction exceeds `T + r·Δ` on any fast run, or **mean** patient-run extraction
exceeds `B + r·D + r·Δ` (the patient clause is an expectation bound), under the
[[threat_model]] assumptions and for attack drifts at or above the detector's
detectability threshold; (b) the value-threshold baseline detects the
low-and-slow regime that MCF was claimed to catch exclusively; or (c) the
measured benign false-positive cost exceeds φ — where, for falsification
purposes, φ is instantiated as the pre-registered train-time false-positive
budget `fpr_budget ≤ 0.01` (the 1% budget the de-circularized Phase-22
parameter selection ran under), and the held-out measured value
(φ = 0.0025 [0.0019, 0.0031]) is compared against that budget. This is
exactly how `h1_scorecard.md` row 8 and its falsifier row (c) adjudicate the
clause (0.0025 ≤ 0.01 → not triggered).

## Reframed detector claim (journal revision — supersedes any "better classifier" reading)

> The sequential detector is a **low-false-positive streaming complement** that reduces
> response latency and catches structuring/low-and-slow drains that value thresholds miss;
> the loss guarantee is carried by the on-chain limiter/breaker, with the detector
> tightening the δ_detect term of Δ (and hence the `r·Δ` slack in `X ≤ T + r·Δ` and the
> `r·D` term in the expectation bound `E[X_slow] ≤ B + r·D + r·Δ`).

What this claim is NOT: a per-row classification-superiority claim. On pooled real-CCTX
test rows (USD-denominated per the Phase-22 units fix) the sequential detector's AUC-ROC
is 0.9700 on the honest **instantaneous** per-row statistic (its AUC-PR is only 0.3740;
the previously-headlined running-max pair 0.9562/0.5381 was partly a time-ordering
artifact and is retained as an annotated artifact only) under the de-circularized
train-selected (δ, λ, cap) = (0.25, 4, 2.0) — per the run log's DeLong rows
statistically *above* the FPR-matched value z-score (0.8716), robust-MAD (0.9214) and
the corrected IsolationForest (0.7822), and *below* only the labels-by-construction
xchainwatcher-rules (1.0) — and it still misses 318 of 382 incident rows at its
operating point. Those numbers are reported, not hidden, and **no per-row superiority is
asserted in either direction** (parameter, units and score-semantics provenance: the
SUPERSEDE NOTE in [[detection_eval]]). The detector's value is (a) a benign
false-positive rate φ = 0.0025 [0.0019, 0.0031] — ~22× lower than the budget-matched
value z-score's 0.0548, and the only detector that honours the 1% train budget
out-of-sample — cheap enough to wire into the *automatic* on-chain pause path, and
(b) per-counterparty accumulation that detects drains whose individual transactions are
value-invisible (sub-threshold band of the σ sweep; crossover σ = 3.0). Honest deltas
from the Phase-22 Tier-B overhaul, stated plainly: φ doubled (0.0013 → 0.0025) when the
selection stopped tuning on the evaluation geometry, and the headline AUC-PR fell
(0.5381 → 0.3740) under the honest statistic.
Every experiment in scenario_6/scenario_7 serves this claim.
