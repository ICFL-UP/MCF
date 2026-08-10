# BOLT: Reproducibility (Phase 17, task 17.6)

This document records everything needed to reproduce the paper's artifacts from a
clean checkout: environment pins (declared and actually-verified versions), the
one-command `make reproduce` chain, dataset provenance, a figure/table →
regenerating-command map, and the Zenodo archival checklist.

Interpretation note: all detector results regenerated below are to be read under
the reframed claim in `docs/bolt/hypothesis.md` §"Reframed detector claim":

> The sequential detector is a **low-false-positive streaming complement** that reduces
> response latency and catches structuring/low-and-slow drains that value thresholds miss;
> the loss guarantee is carried by the on-chain limiter/breaker, with the detector
> tightening the δ_detect term of Δ (and hence the `r·Δ` slack in `X ≤ T + r·Δ`
> [superseded: the slack now sits inside the envelope `B + r(t_trip + Δ)`; [[theorem]] §14.1] and the
> `r·D` term in the expectation bound `E[X_slow] ≤ B + r·D + r·Δ`).

It is **not** a per-row classification-superiority claim.

---

## 1. Environment pins

| Component | Declared pin (source) | Actual version verified on the evidence machine (2026-07-07) |
|---|---|---|
| Node.js | `>=20.0.0` (`package.json` → `engines.node`) | `v24.16.0` (`node --version`) |
| npm | `>=10.0.0` (`package.json` → `engines.npm`) | `11.13.0` (`npm --version`) |
| Python | `>=3.11` (`pyproject.toml` → `requires-python`) | `3.14.5` under `uv run python --version` (system `python3` is 3.11.2; `uv run` is the sanctioned interpreter path) |
| uv | — (any recent) | `0.11.19` (`uv --version`) |
| Hardhat | via `package-lock.json` | `2.28.6` (`npx hardhat --version`) |
| solc | **`0.8.24`** (pinned in `hardhat.config.ts` → `solidity.version`) | 0.8.24 (Hardhat downloads exactly the pinned compiler) |
| Foundry (forge) | install via `foundryup` (https://getfoundry.sh); required **only** by the invariant suite (`make invariants`, chained into `make all`); `make reproduce` needs no Foundry | `forge 1.7.1` (commit `4072e48`, `forge --version`); must be on `PATH` (e.g. `PATH="$HOME/.foundry/bin:$PATH"`) when running `make all` |

**Lock mechanism.** Exact dependency versions are pinned by two committed lock
files and nothing else:

- `uv.lock`: full Python dependency graph, consumed by `uv sync` (run by `make install`).
- `package-lock.json`: full Node dependency graph, consumed by `npm install` (run by `make install`).

All Python commands run via `uv run ...`; all contract commands via `npx hardhat ...`.
Everything targets the local Hardhat network except the single sanctioned
mainnet-fork target (`make deploy-fork` / `make latency`, §4).

**Locked framework constants** (docs/bolt/theorem.md ledger, held fixed across all
evidence): `B=1000`, `r=1`, `T=5000`, `W=3600`, `D=480`, validators `n=9`, threshold
`k=5`, governance `m=3`.

---

## 2. The `make reproduce` chain

One command reproduces the paper's computational artifacts from a clean checkout:

```
make reproduce
```

Recipe (Makefile, `reproduce:` target; landed in task 17.5):

1. `make install`: `npm install` (from `package-lock.json`) + `uv sync` (from `uv.lock`).
2. `make node-start` (**check-first** node orchestration): if something already
   answers `eth_chainId` on `127.0.0.1:8545` it is reused (no pid file written);
   otherwise an ephemeral `npx hardhat node` is started and its pid recorded in
   `.hardhat_node.pid`. This makes nesting safe (phase-21's `make all` wraps the
   same helpers without double-starting).
3. `make data`: build the CCTX dataset (§3) and run the generator self-check.
4. `npx hardhat test`: full contract suite.
5. `make detector-eval`: scenario_6 real-CCTX detection evaluation (node-less).
6. `make bound-check`: scenario_5 bound-validation harness. **This is the stage
   that needs the node**: with `:8545` up it writes a `# mode(s): hardhat` log;
   node-less it would silently regenerate `docs/logs/scenario_5_bound.log` in
   fallback-sim mode, clobbering the committed hardhat-mode evidence.
7. `make adversary`: scenario_7 adaptive-adversary cost-to-evade sweep (node-less).
8. `uv run python scenarios/scenario_2_ronin.py` and
   `uv run python scenarios/scenario_3_stress.py`: the two committed figures not
   produced by the eval targets.
9. `make node-stop`: kills only a node started in step 2 (pre-existing nodes are
   left running).
10. `make check-bound-log` (evidence guard): **fails the whole chain** if
    `docs/logs/scenario_5_bound.log` no longer begins `# mode(s): hardhat`, even
    when every stage exited 0. Recovery if it ever fires:
    `git checkout -- docs/logs/scenario_5_bound.log`, then re-run with a node up.

Verified run evidence (task 17.5, this machine): `make -n reproduce` parses;
`make install` resolved 72 / checked 68 Python packages; `make node-start` started an
ephemeral node and, on a second invocation, hit the reuse branch ("reusing Hardhat
node already answering on :8545"), no double start; `make data` printed
`SUMMARY provenance=XChainWatcher total_rows=83,079 ... labels={benign: 82695,
incident:nomad: 382, incident:ronin: 2}` with zero git diff under `data/cctx/`;
`npx hardhat test` reported `77 passing (4s)`, **superseded snapshot** (task-17.5
run, pre-Phase-22): the current suite is **85 passing** after the Phase-22 Tier-C
additions (current totals: 85 Hardhat + 117 pytest + 15 Foundry = 217).

`make test` is the lighter node-less default (contract tests, pytest, scenarios 2/2b/3/4,
bound-check, adversary, detector-eval); it requires `data/cctx/*.parquet` to be present
(run `make data` first on a clean clone; see Zenodo checklist §5). When bound-check runs
node-less (fallback-sim), output goes to `docs/logs/scenario_5_bound.fallback.log` so
the committed hardhat-mode evidence in `docs/logs/scenario_5_bound.log` is never
overwritten. Prefer `make reproduce` when regenerating paper evidence because of the
node-awareness in steps 2/6/10.

---

## 3. Dataset provenance

- **Source**: XChainWatcher cross-chain transaction (CCTX) dataset,
  arXiv:2410.02029: real Ronin and Nomad bridge traffic including the labelled
  drains (83,079 raw rows; 12 lacking an upstream USD valuation are dropped at
  build time, leaving 83,067: benign 82,685, `incident:nomad` 380,
  `incident:ronin` 2).
- **Build**: `make data` runs `scripts/fetch_cctx.py`, which downloads the real
  source, writes deterministic train/test parquet splits, and emits **sha256
  checksum sidecars** (`data/cctx/train.parquet.sha256`,
  `data/cctx/test.parquet.sha256`) so any regeneration can be byte-verified
  against the committed hashes. Raw per-bridge CSVs land under `data/cctx/raw/`.
- **Offline fallback**: if the network is unavailable, `make data` (or
  `make data OFFLINE=1` to force it) produces a clearly-labelled
  `SYNTHETIC_FALLBACK` stand-in. Paper evidence must be `provenance=XChainWatcher`;
  if a fallback run ever corrupts the committed data, restore with
  `git checkout -- data/cctx/`.
- **Full availability statement**: see `docs/bolt/data_availability.md`
  (created in this release cycle, task 21.5) for licensing, upstream URLs, and
  the checksum manifest.

---

## 4. Figure / table → regenerating command map

| Artifact | Regenerating command | Notes |
|---|---|---|
| `figures/roc_pr_curves.png` | `make detector-eval` | scenario_6; node-less (reads parquet) |
| `figures/arl_curves.png` | `make detector-eval` | |
| `figures/sensitivity.png` | `make detector-eval` | {T,B,r,W,Δ} sweep |
| `figures/lowslow_sweep.png` | `make detector-eval` | σ sweep with the seq-vs-value crossover (B2b) |
| `docs/logs/scenario_6_detection_eval.log` | `make detector-eval` | source of seq AUC-ROC 0.9700 / AUC-PR 0.3740 (instantaneous; running-max artifact 0.9562/0.5381), φ=0.0025 headline (de-circularized train-selected δ=0.25/λ=4/cap=2.0; USD-denominated; baselines FPR-matched) |
| `figures/bound_validation.png` | `make bound-check` | **run inside `make reproduce` or with :8545 up**; see log-clobber guard, §2 step 6/10 |
| `docs/logs/scenario_5_bound.log` | `make bound-check` (node up) | must read `# mode(s): hardhat`; includes the ALT_TRIP non-vacuous config |
| `figures/cost_to_evade.png` | `make adversary` | scenario_7; node-less |
| `figures/ablation.png` | `make adversary` | |
| `figures/cost_attribution.png` | `make adversary` | per-mechanism attribution, both ledgers |
| `docs/logs/scenario_7_cost_to_evade.log` | `make adversary` | |
| `figures/benign_utility_pareto.png`, `docs/logs/scenario_8_benign_utility.log` | `make benign-utility` | scenario_8 benign-utility replay + Pareto frontier; node-less |
| `figures/scenario_2_timeline.png`, `docs/logs/scenario_2.log` | `uv run python scenarios/scenario_2_ronin.py 2>&1 \| tee docs/logs/scenario_2.log` | Ronin replay (composite 1067.695 CRITICAL @ 36.18 ms); kernel-only fallback without a node. **Note:** scenario_2 prints to stdout only; the committed log was captured manually with `tee`. `figures/scenario_2_timeline.png` is produced automatically (a log-x histogram of the baseline distribution with the Ronin injection overlaid; filename is preserved for dissertation embeds). |
| `figures/stress_test_scores.png`, `docs/logs/scenario_3.log` | `uv run python scenarios/scenario_3_stress.py 2>&1 \| tee docs/logs/scenario_3.log` | node-less. **Note:** scenario_3 prints to stdout only; the committed log was captured manually with `tee`. The figure is produced automatically. |
| `docs/logs/scenario_4_fpr.log` | `uv run python scenarios/scenario_4_fpr_sweep.py 2>&1 \| tee docs/logs/scenario_4_fpr.log` | part of `make test`. **Note:** scenario_4 prints to stdout only; log was captured manually with `tee`. |
| `docs/logs/scenario_2b_iforest_compare.log` | `uv run python scenarios/scenario_2b_iforest_compare.py 2>&1 \| tee docs/logs/scenario_2b_iforest_compare.log` | part of `make test`. Prints to stdout only; log captured manually. |
| `docs/logs/scenario_1.log` | `make scenario-1 2>&1 \| tee docs/logs/scenario_1.log` | requires a running node (`make node-start` first). **Note:** scenario_1 prints to stdout only; the committed log was captured manually with `tee`. |
| `docs/bolt/gas_report_raw.txt` (+ table in `docs/bolt/gas_report.md`) | `make gas-report` | `REPORT_GAS=true npx hardhat test` |
| Solidity coverage | `make coverage` | target ≥90% on v2 contracts |
| `docs/bolt/slither_report.md` | `make static` | |
| Foundry invariants | `make invariants` | window≤T, extraction≤T+r·Δ (a *limiter-only reference level*, superseded as a bound by the envelope `B+r(W+Δ)`; [[theorem]] §14.1), revoked-never, bucket≤B, nonce-never-reused |
| `docs/bolt/deployment.md`, `docs/logs/deployment_fork.log` | `make deploy-fork FORK_URL=<rpc>` then `make latency FORK_URL=<rpc>` (`FORK_BLOCK=25482769`) | the ONE sanctioned non-local target; needs a free public RPC; **not** part of `make reproduce`. Measured Δ≈60 s (≤6 blocks) vs the 43,200-block Ronin lag |

---

## 5. Zenodo deposit checklist (user action)

Archival snapshot + DOI minting is a manual user step; no paid services and no
credentials live in this repo. Checklist:

- [ ] Verify a clean-machine run passes: `make install && make data && make test` (and
      `make reproduce` for the full evidence chain; `make test` fails fast if
      `data/cctx/*.parquet` are absent; run `make data` first).
- [ ] Confirm `docs/logs/scenario_5_bound.log` head still reads `# mode(s): hardhat`
      and `data/cctx/` has zero git diff (no `SYNTHETIC_FALLBACK` contamination).
- [ ] Create a new Zenodo deposit (zenodo.org → New upload), type "Software".
- [ ] Upload the repository archive at the release tag
      (`git archive --format=zip -o mcf-bolt-<tag>.zip <tag>`), including
      `uv.lock`, `package-lock.json`, `data/cctx/*.sha256`, `figures/`, and
      `docs/logs/`.
- [ ] Fill metadata: title, authors, license, related identifier
      arXiv:2410.02029 ("is derived from" for the dataset source).
- [ ] Publish the deposit to mint the DOI.
- [ ] Paste the minted DOI back into this file (below), the paper's data/code
      availability section, and `docs/bolt/data_availability.md`.

**DOI**: `[insert on deposit]`
