# BOLT related work: citation apparatus and positioning (Phase 17, task 17.3)

> **J16 SUPERSESSION NOTE (Wave 4).** Every `X ≤ T + r·Δ` below (5,060 ETH locked /
> 4,060 alt-trip) is **superseded**: that form was refuted, because the trailing
> window slides and the freed headroom re-opens. The proved deterministic statement
> is the arrival-curve envelope `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ) = 4,660 ETH`,
> which does not involve `T` and is identical under both ledgers ([[theorem]] §14.1;
> `main.tex` Appendix A). The positioning arguments below are **unaffected in
> substance**: the explicit latency term `r·Δ` is still what ERC-7265 and static
> caps lack; it now sits inside the envelope rather than beside `T`. One
> **factual correction** is applied inline: ASAS-BridgeAMM does *not* lack a latency
> term.

> **Role of this document.** This is the *full* related-work treatment for the paper.
> `docs/bolt/detection_eval.md` §"Published-tool comparison and positioning" is the
> **positioning seed** (one line per neighbouring system, plus the XChainWatcher
> comparator caveat) and deliberately does not carry the citation apparatus; this file
> is that apparatus. Nothing here contradicts the seed; it expands it. The formal-bound
> positioning paragraphs in `docs/bolt/theorem.md` ("Positioning vs. prior
> bounded-bridge work") are likewise summarised, not duplicated, here.

**Thesis of this section.** The cross-chain-bridge security literature is
detection-dominated. Plotting the field on four axes (*detection*, *on-chain
response*, *formal loss bound*, *adaptive-adversary evaluation*) leaves the joint
**response + formal bound + adaptive-adversary evaluation** cell empty. BOLT occupies
that cell. Its detector is deliberately **not** entered in the detection-accuracy race;
per the reframed claim ([`hypothesis.md`](hypothesis.md) §Reframed detector claim):

> The sequential detector is a **low-false-positive streaming complement** that reduces
> response latency and catches structuring/low-and-slow drains that value thresholds
> miss; the loss guarantee is carried by the on-chain limiter/breaker, with the detector
> tightening the δ_detect term of Δ (and hence the `r·Δ` slack in `X ≤ T + r·Δ` and the
> `r·D` term in the expectation bound `E[X_slow] ≤ B + r·D + r·Δ`).

No per-row classification-superiority claim is made anywhere in this document, in
either direction.

---

## 1. Detection-only systems

The canonical bridge SoK (Zhang et al., *SoK: Security of Cross-chain Bridges*,
RAID 2024, arXiv:2312.12573) taxonomises bridge attacks and defences and explicitly
lists attack **prevention** as an *open problem*; anomaly-reactive on-chain
auto-response does not appear in its defence taxonomy. That framing is the anchor for
everything below: each system in this subsection detects (or statically prevents
classes of) bridge attacks, and **none** couples detection to an on-chain response
with a proven loss bound.

- **Xscope** (Zhang et al., ASE 2022, arXiv:2208.07119). Security-property rules with
  Z3 constraint solving over four bridges; caught all known attacks in its corpus.
  Off-chain, post-hoc, no response mechanism.

- **XChainWatcher** (Augusto et al., arXiv:2410.02029). Datalog cross-chain soundness
  rules over an open ~81k-CCTX dataset spanning three chains and $4.2B of transfers;
  identified the Ronin ($611M) and Nomad ($190M) exploit flows. Its own abstract states
  that *"there are no safeguard mechanisms to protect bridges from such attacks"*: the clearest in-field statement of the gap BOLT fills. **Dual role in this work:**
  XChainWatcher is not only cited but *run* as scenario 6's fifth detector
  (`xchainwatcher-rules`, a re-implementation of its core unmatched-deposit /
  finality-order rules). Its recall 382/382 and φ = 0.0000 on our TEST split carry a
  mandatory caveat: the CCTX incident labels were **derived by XChainWatcher's own
  unmatched-withdrawal analysis**, so its ≈perfect recall is **labels-by-construction**,
  not a measured detection capability. The comparison is a capability/deployment-cost
  contrast (trusted, synchronized *both-chain* instrumentation plus per-bridge Datalog
  rules, versus BOLT's destination-chain-stream-only detector), not a fair
  same-information classifier shoot-out. Full treatment:
  [`detection_eval.md`](detection_eval.md) §"Published-tool comparison and positioning".

- **BridgeGuard** (arXiv:2410.14493). Two-stage global+local transaction-graph mining
  over 49 incidents (203 attack + ~40k normal CCTX); reports recall 86.5% (+36.3 pts),
  F1 89.2%. Presumes an indexed multi-chain graph view built offline; BOLT is a
  streaming detector with O(1) per-event state per counterparty.

- **BridgeShield** (arXiv:2508.20517). Heterogeneous graph attention over cross-chain
  event graphs from 51 real attack events; F1 92.6% (+24.4 pts). Both-chain data plus
  a trained model; BOLT is parameter-light (train-only calibrated δ/λ/cap) and
  auditable.

- **SmartAxe** (FSE 2024). Fine-grained static analysis of bridge contracts for
  cross-chain fund-transfer consistency; requires source-*and*-destination contract
  instrumentation and per-bridge cross-chain semantic modeling. Pre-deployment
  vulnerability detection, not runtime response; BOLT needs no contract
  instrumentation of the protected bridge's application logic.

- **HighGuard** (ASE 2024). Runtime monitoring of protocol-level invariants via DCR
  graph models, which demands that the bridge's protocol semantics be formally specified.
  BOLT assumes only a value stream. HighGuard's *reporting style*, however, is adopted:
  BOLT's deployment report ([`deployment.md`](deployment.md)) follows its
  blocks-to-detection latency-table convention (latency stated in blocks *and*
  seconds per mechanism).

**Honest detection position.** On pooled held-out real
CCTX rows (24,539 benign test rows, scored in the common USD denomination per the
Phase-22 units fix), BOLT's sequential detector attains AUC-ROC 0.9700 / AUC-PR 0.3740
on the honest **instantaneous** per-row statistic (the previously-headlined running-max
pair 0.9562/0.5381 was partly a time-ordering artifact and is annotated, not cited),
benign flag rate φ = 0.0025, under de-circularized train-selected parameters
(δ = 0.25, λ = 4, cap = 2.0) with every baseline FPR-matched to the same 1% train
budget. DeLong tests: ΔAUC +0.0984 vs the value z-score
(z = +16.64, p = 3.51e-62), +0.1878 vs the corrected IsolationForest (p = 1.13e-185)
and +0.0486 vs robust-MAD (p = 3.33e-21); significantly **lower** only than
xchainwatcher-rules (−0.0300, p = 5.74e-14), the latter with the
labels-by-construction caveat above. On the graph systems' own axis (per-incident
F1 ≈ 0.89–0.93) the graph systems lead. None of this is contested: BOLT's
contribution is on the axes where all of these systems are silent, with the detector
serving as the low-false-positive streaming complement (H1 canonical low-and-slow
drain, ILLUSTRATIVE-labelled, tested on the mixed benign+injected stream: McNemar
n01 = 1384, n10 = 45, p = 2.05e-274; sequential recall 0.950 where the value z-score
scores 0.000, with the σ-sweep crossover at 3.0; the same direction holds on the
real Nomad structuring cohort, per-tx 0.633 vs 0.245 at matched budgets, though
per-row Nomad recall stays honestly low overall: holdout 0.163 vs 0.029 for the
value z-score).

## 2. Circuit-breaker and rate-limit standards (response without proof)

- **ERC-7265 (Circuit Breaker standard)** (ethereum-magicians.org proposal). Specifies
  a DeFi circuit-breaker *interface*: token-bucket outflow accounting with a trip
  threshold. It provides **no proof and no explicit latency term**: it cannot state a
  closed-form worst-case extraction bound, because the quantity `r·Δ` (what leaks while
  detection and inclusion are in flight) is absent from the specification. BOLT's
  breaker is ERC-7265-shaped, but the envelope `X ≤ B + r·(t_trip + Δ)` makes exactly
  that missing term explicit ([`theorem.md`](theorem.md)).

- **Chainlink CCIP rate limits** (docs.chain.link). Production token-bucket rate
  limiting per token pool and per lane: operationally the closest deployed artifact to
  BOLT's `RateLimiter`. Documented as a risk-management feature; no adversarial model,
  no proven extraction bound, no coupling to an anomaly detector.

These standards supply the *response* column of the quadrant table but leave the
*formal bound* and *adaptive evaluation* columns empty.

**Post-2022 deployed practice: static rate limits as the production norm.** The
Ronin incident (March 2022, 173,600 ETH drained in two transactions with no on-chain
rate limiting) motivated a wave of post-incident hardening across production bridges.
Chainlink CCIP (launched on mainnet July 2023, general availability April 2024;
docs.chain.link/ccip/concepts/rate-limit-management) deploys token-bucket rate
limits per token pool and per lane (the same capacity-plus-refill-rate primitive as
BOLT's `RateLimiter`) as an operator-controlled "defensive mechanism" to "reduce
the blast radius of unexpected behavior" and "give operators time to react." ERC-7265
(Ethereum Magicians proposal, mid-2023) standardises a comparable circuit-breaker
interface for DeFi protocols broadly. These represent the current production state of
the art: **token-bucket rate limits with no adversarial model, no anomaly detector,
and no formal extraction bound**. The gap they leave is exactly what this work
addresses: BOLT's `X ≤ B + r·(t_trip + Δ)` adds the explicit `r·Δ` latency term that
static caps cannot state (the quantity that leaks between trip and effective pause), pairs
the limiter with an adaptive-adversary-priced sequential detector that shrinks the
patient-regime expectation from the limiter-only multi-window floor (88,581 ETH
under locked constants, `docs/logs/scenario_7_cost_to_evade.log` label
`DEPLOYED-PRACTICE`) to ≤ 1,506 ETH per detection interval (≤ the patient bound
1,540 ETH), and proves the combined guarantee from first principles under a
k-of-n key-compromise adversary model, none of which the deployed static caps
provide or claim.

## 3. ASAS-BridgeAMM: closest neighbour, cited and distinguished

**ASAS-BridgeAMM** (Shengwei You, Aditya Joshi, Andrey Kuehlkamp, Jarek Nabrzyski;
*"ASAS-BridgeAMM: Trust-Minimized Cross-Chain Bridge AMM with Failure Containment"*,
arXiv:2601.12434, submitted 18 January 2026) is, to our knowledge, the only prior
work combining a bridge, an on-chain graduated auto-response, and a formal bound
(18-month replay over 2+ chains; insolvency −73%; bad debt < 0.2%/epoch). It must be
cited up front, and it is **distinguished on three explicit axes**:

1. **Quantity bounded.** ASAS bounds **AMM bad-debt** arising from latency/oracle risk,
   as a **fraction of collateral**. BOLT bounds **valid-key withdrawal extraction**,
   the value a `k`-of-`n` key-holding attacker (the Ronin adversary, `k = 5`, `n = 9`)
   can pull through the bridge's exit before halt, in **absolute value units**
   (`X ≤ B + r·(W + Δ) = 4,660 ETH`; in expectation
   `E[X_slow] ≤ B + r·D + r·Δ = 1,540 ETH` under the locked ledger
   `B = 1000, r = 1, T = 5000, W = 3600, D = 480`). Different quantity,
   different threat. The sharper contrast is the **shape** of the guarantee:
   deterministic worst case in absolute units here, probabilistic
   fraction-of-collateral there.

2. **Bridge type.** ASAS's bound is **AMM-coupled**: tied to the AMM curve of an
   AMM-integrated bridge. BOLT's bound holds for a **generic multisig/lock-mint bridge**
   with one rate-limited exit choke point; no AMM exists in the model. BOLT's bounds
   are also **TVL-independent**: neither expression contains total value locked.

3. **Explicit latency composition.** ASAS's bound carries **no latency term**. BOLT's
   `Δ = δ_detect + δ_include` is decomposed and *measured*: δ_detect = 36.18 ms
   (parsed at runtime from the monitor react path) and δ_include ≤ k·τ_block = 60 s at
   5 confirmations, giving Δ ≈ 60 s (≤ 6 blocks) on a mainnet fork at
   forkBlock = 25482769, versus the ≈ 43,200-block (6-day) Ronin detection lag
   ([`deployment.md`](deployment.md), `docs/logs/deployment_fork.log`). The latency
   term is what turns a static rate limit into a provable end-to-end guarantee: it is
   the `r·Δ` slack in both regimes.

ASAS is therefore framed as **complementary**, not competing: it bounds a different
quantity on a different bridge class. What it does not provide, and what no system in
§1–§2 provides, is an **adaptive-adversary evaluation** of the deployed defence
(§4, last column).

## 4. The quadrant table

Legend: ✅ = provided; ● = partial (see footnote); — = absent.

| System | Detection | On-chain response | Formal loss bound | Adaptive-adversary eval |
|---|---|---|---|---|
| Xscope (ASE 2022, arXiv:2208.07119) | ✅ rules + Z3 | — | — | — |
| XChainWatcher (arXiv:2410.02029) | ✅ Datalog CCTX rules ¹ | — | — | — |
| BridgeGuard (arXiv:2410.14493) | ✅ graph mining | — | — | — |
| BridgeShield (arXiv:2508.20517) | ✅ graph attention | — | — | — |
| SmartAxe (FSE 2024) | ✅ static analysis (pre-deploy) | — | — | — |
| HighGuard (ASE 2024) | ✅ runtime invariants (DCR) | — | — | — |
| RAID'24 SoK (arXiv:2312.12573) | (taxonomy; names prevention as open) | — | — | — |
| ERC-7265 Circuit Breaker | — | ✅ breaker interface | — (no proof, no Δ term) | — |
| Chainlink CCIP rate limits | — | ✅ token-bucket limits | — | — |
| ASAS-BridgeAMM (arXiv:2601.12434) | ● price/latency trigger ² | ✅ graduated response | ● AMM bad-debt, probabilistic fraction-of-collateral, AMM-coupled ² (latency **is** modelled; earlier note corrected, J6) | — |
| **Static rate-limit only** (deployed practice ⁶) | — | ✅ token-bucket + value-trip breaker; NO detector | — (no proof; no latency term; no adaptive adversary model) ⁶ | — |
| **BOLT (this work)** | ✅ streaming sequential CPD, as low-FP complement ³ | ✅ limiter + breaker + revocation | ✅ `X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`, `E[X_slow] ≤ B + r·D + r·Δ` (patient bound in expectation): latency-explicit, TVL-independent, threshold-independent, hardhat-validated ⁴ | ✅ best-response adaptive attacker with cost-to-evade curves ⁵ |

¹ Also run as our comparator (`xchainwatcher-rules`); its recall 1.0 on our data is
labels-by-construction (§1).
² ASAS detects AMM price/latency degradation, not withdrawal anomalies; its bound is
AMM-coupled with no latency term (§3); hence ● not ✅ on the axes as defined here.
³ AUC-ROC 0.9700 (instantaneous statistic; running-max artifact 0.9562), φ = 0.0025 on
24,539 real held-out benign CCTX rows (USD-denominated); per-row AUC below the
labels-by-construction xchainwatcher-rules (§1).
No classification claim is entered in this column beyond the complement role.
⁴ Validated against the real contracts in hardhat mode (`docs/logs/scenario_5_bound.log`,
`# mode(s): hardhat`): the fast-drain envelope 4,660 ETH and expected patient bound
1,540 ETH never exceeded, but note that at LOCKED the superseded 5,060 ETH form was
unfalsifiable by construction (4,660 < 5,060), so those rows were never evidence for it
(patient schedules evaluated at the assumed D = 480 s);
tightest LOCKED-section margins +1,624.000 ETH (fast) / +766.667 ETH (patient,
near-T-window, Δ=300 s); ALT_TRIP margins go as low as +12.000 ETH and still PASS; trip
non-vacuity shown by the ALT_TRIP configuration (T = 4000: 5 trip=YES rows, vs 0 under
the locked ledger where `B + r·W = 4600 < T = 5000` makes the value trip structurally
unreachable by design).
⁵ `docs/logs/scenario_7_cost_to_evade.log` (grid + greedy-refinement adaptive search):
exfiltrating the Ronin-scale 173,600 ETH at best detection probability < 50% forces
174 transactions over 87,581 s (~1.0 day), an effective rate of 1.987 ETH/s (~503×
collapse from the 1,000 ETH/s achievable at the smallest budget); realised extraction
pinned ≤ 1,506 ETH per detection interval (D+Δ = 540 s), itself ≤ the expected patient
bound 1,540 ETH; ≥ 116 sequential detect-and-halt cycles to reach the target;
limiter-only reference levels `T + r·Δ` = 5,060 (locked) / 4,060 (alt-trip) ETH; these
are **not bounds** (an explicit schedule beats 4,060 with 4,648); the proved per-window
envelope is 4,660 ETH under both ledgers.
Halt regimes are attributed separately (empirical-trip MEASURED = limiter floor
3,531 alt-trip / 88,581 locked; assumed-D MODEL-BASED = 1,506 at D=480 s / 2,012 at
the real Nomad-onset D=1,408 s; deployed-practice limiter-only comparator).
Cost attribution is exact (`denied = limiter_borne + detector_marginal`; at 173,600 ETH:
locked 85,419 limiter-borne + 87,075 detector-marginal; alt-trip 170,469 + 2,025),
with detector_marginal > 0 on 5/8 budgets per configuration and the `d_halt_binds`
deviation documented verbatim ("NOT an empirical trip — raw det_prob is 0.0").
⁶ **Deployed-practice static-rate-limit-only baseline.** The row represents the
post-2022 production norm: a token-bucket + value-trip circuit breaker with **no
anomaly detector**. Its numbers come directly from the BOLT cost-to-evade harness
(`docs/logs/scenario_7_cost_to_evade.log`, label `DEPLOYED-PRACTICE`): against the
Ronin-scale 173,600 ETH budget, the limiter-only floor is **3,531 ETH (alt-trip
config) / 88,581 ETH (locked config)**, the minimum extraction an attacker can
achieve within one window when no detector fires (`denied = limiter_borne` only,
`detector_marginal = 0`). The locked-config floor of 88,581 ETH reflects that a
patient attacker can drain up to `min(T, B+r·W) = 4,600 ETH` per window
indefinitely without a detector, accumulating multi-window damage limited only by
governance intervention. This is the directly comparable baseline: same on-chain
infrastructure, same ledger constants, no detector layer.

**Reading the table.** The joint **response + formal bound + adaptive-adversary
evaluation** cell, the bottom-right corner, is occupied only by BOLT. ASAS-BridgeAMM
comes closest (response + a bound) but bounds a different quantity on an AMM-coupled
bridge with no latency term and no adaptive evaluation; every detection system's
response, bound and adaptive columns are empty; every response standard's bound and
adaptive columns are empty. The static-rate-limit-only baseline row represents
the post-2022 production norm (Chainlink CCIP, ERC-7265-shaped breakers): it has a
response mechanism but no formal bound, no latency term, and no adaptive evaluation:
the deployed-practice floor against which the BOLT composition is calibrated.

## 5. Summary: where BOLT sits

BOLT sits **in the same line of work as the detection systems, not in opposition**. On
their axis it reports its numbers and claims only the complement role. Its
defensible contribution is the previously empty quadrant:

- a **proven, latency-explicit, TVL-independent loss bound** for valid-key extraction
  on a generic multisig/lock-mint bridge: both regimes ≪ the 173,600 ETH Ronin loss
  (4,660 ETH deterministic fast-drain envelope, 1,540 ETH expected patient; the re-derived Ronin
  event scores 1067.695 → CRITICAL with
  monitor reaction in 36.18 ms wall-clock, `docs/logs/scenario_2.log`);
- an **on-chain response path that is affordable and measured**: `withdraw` at `k = 5`
  averages 323,090 gas (min 288,869 / max 354,167) with the breaker's `checkAndRecord`
  at a traffic-constant 282,091 gas (`docs/bolt/gas_report.md`, optimizer enabled,
  runs = 200, cancun);
- an **adaptive-adversary evaluation** in the Carlini et al. (arXiv:1902.06705) spirit
  (the defence is priced by its best-response evader, not by fixed replay traces),
  which none of the surveyed systems, ASAS included, provide.

---

*Cross-references:* [`hypothesis.md`](hypothesis.md) (reframed detector claim, H1),
[`theorem.md`](theorem.md) (bound statement, proof, ERC-7265/ASAS positioning),
[`detection_eval.md`](detection_eval.md) (comparator runs, positioning seed),
[`deployment.md`](deployment.md) (HighGuard-style latency table),
[`threat_model.md`](threat_model.md) (k-of-n adversary).

*Source URLs, verified against each record:*
arXiv 2312.12573, 2410.02029, 2410.14493, 2508.20517, 2208.07119, 2601.12434
(arXiv:2601.12434 = "ASAS-BridgeAMM: Trust-Minimized Cross-Chain Bridge AMM with
Failure Containment", You et al., 18 Jan 2026; VERIFIED live at
https://arxiv.org/abs/2601.12434), 1902.06705; ERC-7265:
ethereum-magicians.org/t/eip-7265-circuit-breaker-standard/14909; CCIP rate limits:
docs.chain.link/ccip/concepts/rate-limit-management/overview (mainnet launch Jul 2023,
GA Apr 2024). SmartAxe (FSE 2024) and HighGuard (ASE 2024) are cited by venue.
