# Parameter Choices and Justification

Every numeric default in this PoC traces to a specific source. The PoC has no novel
crypto and no tuned thresholds: all values come from the dissertation, the Ronin
incident, or fixed PoC simplifications.

## Table

| Parameter | Value | Source |
|-----------|-------|--------|
| Validator threshold (k-of-n) | 5-of-9 | Ronin original config; INFO_PACK §3, dissertation §9.2 (Halborn / Three Sigma post-mortems) |
| `ALERT_THRESHOLD` | 3.0 (composite score) | Dissertation §11.2.3. In one-shot mode (`window=None`) this is reached at an effective 7.5254σ of value deviation; see "Effective one-shot threshold" below |
| `CRITICAL_THRESHOLD` | 6.0 (composite score) | Dissertation §11.2.3. Effective one-shot equivalent 13.5254σ; see "Effective one-shot threshold" below |
| Value deviation weight | 0.5 | Dissertation §11.2.3 |
| Volume deviation weight | 0.3 | Dissertation §11.2.3 |
| Destination novelty weight | 0.2 | Dissertation §11.2.3 |
| Baseline window | 30 days | Dissertation §11.2.3 ("30-day rolling mean") |
| Baseline tx/day | ~200 (n=6,000 over 30d) | Synthetic calibration regime used by the composite z-score (scenarios 1–4 and the stress tests); the real-CCTX evaluation (scenarios 6–8) uses the XChainWatcher CCTX dataset (`data/cctx/*.parquet`, fetched by `make data`; real historical cross-chain transfer data, 83,067 rows) |
| Baseline value distribution | log-normal (calibrated: empirical mean ≈ 43.6 ETH, std ≈ 81.2 ETH), Poisson arrivals, Zipf open destination set | Current single calibrated regime in `monitor/generator.py`; replaces the retired Gaussian(50,30) toy baseline. The earlier plain-Gaussian figure produced the superseded score 3014.843; the current calibrated regime produces 1067.695. For the real CCTX evaluation (scenario 6 onwards) the detector is scored on the upstream USD valuation (`value_usd`), not ETH |
| Baseline destinations | Zipf open-growing address set | `monitor/generator.py` open-set Zipf; replaces the retired closed set of 20 fixed addresses used by the toy baseline |
| `numpy` seed | 42 | Reproducibility: identical results across runs |
| Scenario 1 TTL | 2 seconds | PoC demo timescale; `evm_increaseTime` advances chain by 3s to trigger expiry |
| DID format | `did:ethr:<chainId>:<address>` | ERC-1056 (Ethereum DID Method) |
| Solidity compiler | 0.8.24 (cancun) | Bumped from 0.8.20 in Phase 9a: required by `@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol` (^0.8.24) and `Bytes.sol` (uses `mcopy`, Cancun opcode). All contracts pin `pragma solidity 0.8.24` (exact, no caret). INFO_PACK §8 |
| Hardhat chainId | 31337 | Hardhat default local network |
| IsolationForest `n_estimators` | 100 | sklearn default (Phase 9b). Changing this would change the comparison numbers in `evaluation.md` §8 |
| IsolationForest `contamination` | `"auto"` | sklearn default: uses the original 2008 paper's offset of −0.5 on `score_samples`. Phase 9b |
| IsolationForest features | `[value, dest_novelty]` | Two features matching the dominant signals used by the z-score detector (value deviation, destination novelty). Volume is intentionally omitted; see `monitor/isolation_forest.py` docstring |

## Notes on the Synthetic Baseline

**Current calibrated regime** (`monitor/generator.py`, used by scenarios 1–4 and stress
tests): log-normal value distribution with empirical mean ≈ 43.6 ETH and std ≈ 81.2 ETH,
Poisson inter-arrival times, Zipf-distributed open growing destination set. Generated with
`numpy.random.default_rng(seed=42)`, n=6,000 transactions over 30 days. The resulting
composite score for a 173,600 ETH injection is **1067.695**, roughly 178× the critical
threshold of 6.0. This retires the earlier Gaussian(50,30) toy baseline that produced the
superseded 3014.843 score.

**Real CCTX data** is used for the primary detection evaluation (scenarios 6–8): the
XChainWatcher cross-chain transaction dataset (`data/cctx/{train,test}.parquet`), fetched
by `make data` (`scripts/fetch_cctx.py`), which downloads 83,079 real historical
cross-chain transfers from the Ronin and Nomad bridges (including the labelled incident
rows). The TRAIN split (58,146 benign rows) calibrates all detector thresholds; the
held-out TEST split (24,921 rows, 382 incident) yields the reported metrics. The real CCTX
data uses the upstream per-transaction USD valuation (`value_usd`) as the scoring
denomination (mixed per-token decimals make raw `value` base units non-comparable).
Parameters δ=0.25, λ=4, cap=2.0 were selected train-only over a disjoint attack-geometry
family (B2 de-circularization, `docs/bolt/detection_eval.md` §SUPERSEDE NOTE).

## Notes on Baseline Distribution Divergences from the Spec (retired context)

> **This section is retained for provenance only.** It described the *old* Gaussian(50,30)
> toy baseline, which was retired when the calibrated log-normal regime was introduced.
> The current baseline is described in "Notes on the Synthetic Baseline" above, and the
> primary evaluation uses real CCTX data (see that section).

INFO_PACK §8 specifies a log-normal value distribution, Poisson inter-arrival times, and a
Zipf-shaped destination distribution. The current `monitor/generator.py` implements exactly
these (log-normal values, Poisson arrivals, Zipf open-set destinations), calibrated to the
real XChainWatcher CCTX train distribution. The earlier Gaussian(50,30) closed-set
implementation was a simplification retained through Phase 9; it was replaced by the
current calibrated regime, which is documented in `docs/evaluation.md` §1 and
`docs/logs/scenario_2.log`. The retired Gaussian(50,30) figures (score 3014.843, 6,047σ
outlier) appear in `docs/evaluation.md` §7a.2 and §3 only as historical context marked
"superseded" and must not be cited as current results.

## Notes on the Composite Score Weights (0.5 / 0.3 / 0.2)

These weights come directly from §11.2.3. They have **not** been empirically tuned
against real bridge traffic. The PoC therefore does not claim a calibrated false-positive
rate. See `docs/evaluation.md` §4 (Limitations).

## Notes on the k-of-n Threshold

`MockBridge.sol` accepts `(registryAddr, _threshold, _monitor)` via constructor: there
is no validator-count parameter; `n` is whatever set of addresses holds active credentials
in the registry. The 5-of-9 default mirrors Ronin's production configuration at the time
of the March 2022 attack (§9.2). The contract does not enforce `_threshold == 5`; tests
exercise other (k, n) combinations. The 5-of-9 figure is documentation of the historical
fact, not a code constant. Note also that `MockBridge.pause()` is one-way: there is no
unpause, so recovery from a pause is redeployment (PoC scope).

## Notes on the Volume Window (B1-a)

`compute_score(tx, baseline, window=None)` accepts an optional `window`:
recently-observed transactions in the same hour as `tx`. When `window` is
supplied, `vol_z = (len(window) + 1 − hourly.mean()) / hourly.std()` so the
factor reflects the *elevated count*, not a fixed offset for a single-tx hour.
When `window=None`, the score behaves as the kernel-only path: the value
component dominates and the volume term is the offset for "one tx in the
current hour", which is the right mode for the headline 173,600 ETH outlier
where value alone saturates the score and any volume context is irrelevant.

Sub-scenario B in `scenarios/scenario_3_stress.py` uses `window` of 30 prior
txs to demonstrate that an elevated-volume day classifies CRITICAL even when
each individual transaction sits at the baseline mean.

### Effective one-shot threshold

That "offset for one tx in the current hour" is a fixed quantity, and it is worth
stating numerically because most of the repo scores in this mode:
`monitor/service.py` (`MonitoringService.process_event` and the `evaluate` facade,
the production monitoring path), `scenarios/scenario_2_ronin.py`,
`scenarios/scenario_2b_iforest_compare.py` and `scenarios/scenario_4_fpr_sweep.py`
all pass `window=None`. Only `scenarios/scenario_3_stress.py` sub-scenario B and
`tests/monitor/test_anomaly.py::test_volume_window_elevates_score` supply a window.

Against the calibrated seed-42 baseline (6,000 txs over 720 hours; hourly count
mean 8.3333, std 2.8844; value mean 43.6371 ETH, std 81.2334 ETH):

| Quantity | Value |
|-----------|-------|
| `vol_z` when `window=None` | constant `(1 − 8.3333) / 2.8844 = −2.5424` |
| Per-score contribution at `DEFAULT_WEIGHTS` | fixed `0.3 × −2.5424 = −0.7627` |
| Shift in the required value deviation | `0.7627 / 0.5 = 1.5254σ` |
| Effective ALERT crossing, known destination | 7.5254σ = **654.95 ETH** (nominal `0.5·value_z ≥ 3.0` would give 6.0σ = 531.04 ETH) |
| Effective ALERT crossing, novel destination | 7.1254σ = **622.46 ETH** (nominal 5.6σ = 498.54 ETH) |
| Effective CRITICAL crossing, known destination | 13.5254σ = **1,142.35 ETH** (nominal 12.0σ = 1,018.44 ETH) |
| Effective CRITICAL crossing, novel destination | 13.1254σ = **1,109.86 ETH** (nominal 11.6σ = 985.95 ETH) |

Reconciliation with the table above: `ALERT_THRESHOLD` and `CRITICAL_THRESHOLD`
are unchanged dissertation constants on the *composite* score (3.0 and 6.0); the σ
and ETH figures here are the value deviation required to reach them once the
constant volume contribution is carried, which is the only sense in which either
threshold has an ETH value. The ETH figures move with the baseline draw; the σ
figures do not.

Two properties follow. In one-shot mode the volume term is a constant handicap
rather than a feature: it can only lower a score, never raise one, and it says
nothing about the transaction being scored. And because it is the *same* constant
for every transaction, it is rank-invariant: score ordering and any ranking metric
(AUC-ROC, AUC-PR) are unaffected, while every fixed-threshold quantity is shifted.
The synthetic FPR / power characterisation in `scenarios/scenario_4_fpr_sweep.py`
is therefore measured at the effective crossings above, not at the nominal reading
(`docs/evaluation.md` §3.4.1).

**Provenance of the ≈668 ETH figure.** Figure 11.9
(`figures/dissertation_ch11/generate_ch11_figures.py`, `fig_11_9`) and the
manuscript prose derived from it quote ≈668 ETH for the known-destination alert
crossing, against the 654.95 ETH derived above. The difference is grid resolution,
not disagreement: `fig_11_9` scores a 160-point `np.logspace(1, log10(2500))` sweep
of transaction values, which steps 3.53% per point, and reports the first sample to
reach `ALERT_THRESHOLD`. Its adjacent samples bracket the analytic crossing
(645.31 ETH scores 2.941 and 668.11 ETH scores 3.081), so the readout is 668.11 ETH.
654.95 ETH is the crossing; ≈668 ETH is that figure's resolution of it, and the two
should be cited accordingly.

## Notes on Phase 9a Signature Verification

`registerValidator` now takes a fourth argument, `bytes calldata signature`, which must
be a personal_sign signature over `docHash` produced by the validator's private key.
The contract recovers the signer with `MessageHashUtils.toEthSignedMessageHash` +
`ECDSA.recover` and reverts with `"invalid signature"` unless it equals `addr`. This
closes the gap where the owner could otherwise bind any address to a docHash without
key-possession proof. Off-chain signing is `signer.signMessage(ethers.getBytes(docHash))`
in tests and `Account.sign_message(encode_defunct(primitive=docHash))` in
`scenarios/scenario_1_lifecycle.py`.

## Notes on `Ownable` vs. Multisig

`MCFValidatorRegistry.sol` (the intentionally-kept v1 baseline) uses OpenZeppelin's
`Ownable` for governance access control, a documented PoC simplification. Its successor,
`RegistryV2.sol`, replaces this with real m-of-n threshold governance (closing gap G7):
lifecycle ops (register / revoke / renew / reinstate) require `m` distinct approvals from
an immutable set of `n` governors, with approvals bound to an op id that commits the
action and its parameters. A production deployment would still likely use a Gnosis Safe
(or equivalent threshold-signature wallet) per §11.2.2 rather than the in-contract scheme.
See `docs/evaluation.md` §4.
