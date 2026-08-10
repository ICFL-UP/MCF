.PHONY: install test data data-check scenario-2-e2e scenario-1 bound-check adversary detector-eval benign-utility coverage gas-report invariants static clean deploy-fork latency all reproduce node-start node-stop check-bound-log

# V2 Definition of done, line 1: one-command reproduction. Strict superset of Phase 17's
# `reproduce` (paper chain; chained last here, closing DoD line 3): contracts + Python
# suites + scenarios/eval harnesses (via `test`) + coverage + static (Slither) + invariant
# suite + reproduce, from a clean checkout.
# Node-aware (phase-19 19.1 interlock): `test` and `reproduce` both run `bound-check`, and
# scenario_5 silently falls back to `fallback-sim` when nothing answers on :8545, which
# would clobber the committed `# mode(s): hardhat` log (V2 1.1 acceptance / DoD-line-2
# evidence). So `all` runs the whole chain under 17.5's check-first node-start/node-stop
# helpers and fails hard via check-bound-log if the regenerated log is not hardhat mode.
# Nesting is safe by construction: `reproduce`'s inner node-start sees :8545 already
# answering and reuses the outer node (writing no pid file), so no double-start; its
# inner node-stop then kills the outer node via the pid file after the last node-needing
# stage, leaving the outer node-stop a harmless no-op: no orphan node either way.
# Fork targets (deploy-fork, latency) are deliberately excluded: they need FORK_URL
# and network access (the one sanctioned 3.2 exception; not part of local reproduction).
all: install
	@$(MAKE) node-start
	@$(MAKE) data test coverage static invariants reproduce; status=$$?; \
	$(MAKE) node-stop; \
	$(MAKE) check-bound-log || exit 1; \
	exit $$status
	@echo "make all: contracts + Python + coverage + static (Slither) + invariants + reproduce — all green (hardhat-mode bound log preserved)"

install:
	# Use npm ci (lockfile-exact) for reproducible installs.
	# If package-lock.json is missing (e.g. first checkout without it), run
	# `npm install` once to generate it, then commit the lock file.
	npm ci
	uv sync

# Build the cross-chain-transaction (CCTX) dataset from the XChainWatcher source
# (arXiv:2410.02029). Tries the real download first; deterministically falls back
# to a clearly-labelled synthetic stand-in if the network is unavailable. Then
# runs a generator self-check so downstream phases have a known-good data source.
# Use `make data OFFLINE=1` to force the synthetic fallback.
data:
	uv run python scripts/fetch_cctx.py $(if $(OFFLINE),--offline,)
	uv run python -c "import monitor.generator as g; df=g.generate(seed=1,n=1000); print(df.shape, list(df.columns))"

# ---------------------------------------------------------------------------
# Node-orchestration helpers (BOLT 17.5; reused by phase-21 21.4's `all`).
# check-first semantics make nesting safe: if something already answers on
# :8545 (a user's node, or an outer `make all` that already ran node-start),
# node-start reuses it and writes NO pid file, so node-stop will not kill it.
# Only a node started HERE is recorded in .hardhat_node.pid and killed later.
node-start:
	@if curl -sf -X POST -H 'Content-Type: application/json' \
	    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
	    http://127.0.0.1:8545 >/dev/null 2>&1; then \
	  echo "node-start: reusing Hardhat node already answering on :8545 (no pid file; node-stop will leave it running)"; \
	else \
	  nohup npx hardhat node --hostname 127.0.0.1 >/dev/null 2>&1 & wrapper=$$!; \
	  for i in $$(seq 1 30); do \
	    curl -sf -X POST -H 'Content-Type: application/json' \
	      --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
	      http://127.0.0.1:8545 >/dev/null 2>&1 && break; \
	    test $$i -lt 30 || { echo "node-start: FAIL — ephemeral hardhat node never answered on :8545"; \
	      kill $$wrapper 2>/dev/null; exit 1; }; \
	    sleep 1; \
	  done; \
	  { lsof -ti tcp:8545 -sTCP:LISTEN 2>/dev/null || echo $$wrapper; } | head -1 > .hardhat_node.pid; \
	  echo "node-start: started ephemeral Hardhat node (pid $$(cat .hardhat_node.pid), the :8545 listener — $$! is the npx wrapper, whose node child survives a plain kill)"; \
	fi

node-stop:
	@if [ -f .hardhat_node.pid ]; then \
	  kill $$(cat .hardhat_node.pid) 2>/dev/null || true; \
	  rm -f .hardhat_node.pid; \
	  echo "node-stop: killed ephemeral Hardhat node"; \
	else \
	  echo "node-stop: no .hardhat_node.pid — nothing started here; pre-existing node (if any) left running"; \
	fi

# Evidence guard (phase-19 19.1 interlock): scenario_5 silently regenerates
# docs/logs/scenario_5_bound.log in fallback-sim mode when nothing answers on
# :8545, clobbering the committed hardhat-mode evidence (V2 1.1 acceptance).
# Fails hard if the log is no longer hardhat-mode.
check-bound-log:
	@grep -q '^# mode(s): hardhat' docs/logs/scenario_5_bound.log || \
	  { echo "check-bound-log: FAIL — docs/logs/scenario_5_bound.log is not '# mode(s): hardhat' (node orchestration broke; restore the committed evidence with: git checkout -- docs/logs/scenario_5_bound.log, then re-run with a node up)"; exit 1; }
	@echo "check-bound-log: docs/logs/scenario_5_bound.log still '# mode(s): hardhat' — committed evidence preserved"

# BOLT 17.5: one-command paper-reproduction chain (phase-17; phase-21 21.4's
# `all` is the wider superset and reuses node-start/node-stop/check-bound-log).
# Chain: install → data → contracts (npx hardhat test) → detector-eval →
# bound-check → adversary → benign-utility (Phase 22 B1 Pareto frontier) →
# remaining figure regen (scenario_2 timeline, scenario_3 stress, the only
# committed figures not produced by the eval targets;
# detector-eval/bound-check/adversary/benign-utility already regenerate
# roc_pr_curves, arl_curves, sensitivity, bound_validation, cost_to_evade,
# cost_attribution, ablation, benign_utility_pareto).
# Node-aware: bound-check's scenario_5 needs :8545 or it clobbers the
# committed hardhat-mode log, so the whole chain runs under node-start /
# node-stop and fails hard via check-bound-log even if every stage exits 0.
# Version pinning: uv.lock (Python, consumed by `uv sync`) and
# package-lock.json (Node, consumed by `npm ci`) are the pin mechanism;
# solc is pinned to 0.8.24 in hardhat.config.ts. No other pin files exist.
reproduce: install
	@$(MAKE) node-start
	@( $(MAKE) data \
	  && npx hardhat test \
	  && $(MAKE) detector-eval \
	  && $(MAKE) bound-check \
	  && $(MAKE) adversary \
	  && $(MAKE) benign-utility \
	  && uv run python scenarios/scenario_2_ronin.py \
	  && uv run python scenarios/scenario_3_stress.py ); status=$$?; \
	$(MAKE) node-stop; \
	$(MAKE) check-bound-log || exit 1; \
	exit $$status
	@echo "make reproduce: install + data + contracts + detector-eval + bound-check + adversary + figures — all green (hardhat-mode bound log preserved)"

# Fail-fast guard: errors immediately with an actionable message when the CCTX parquets
# are missing (clean clone; data/ is gitignored). CI runs 'make data' explicitly before
# 'make test', so it is never hit there. Locally the message tells you exactly what to run.
# Auto-fetch is intentionally NOT done here: data download needs network and can silently
# hang offline; the explicit 'make data' step is the right place for that.
data-check:
	@test -f data/cctx/train.parquet && test -f data/cctx/test.parquet || \
	  { echo "data-check: FAIL — data/cctx/*.parquet not found."; \
	    echo "  On a clean clone run: make install && make data && make test"; \
	    echo "  (or: make data OFFLINE=1 for a synthetic fallback when offline)"; \
	    exit 1; }
	@echo "data-check: data/cctx/*.parquet present"

# Default test target: does not require a running Hardhat node.
# scenario_2_ronin falls back to kernel-only mode when no node is reachable.
# scenario_5/bound-check (fallback-sim) now writes to docs/logs/scenario_5_bound.fallback.log
# instead of the committed docs/logs/scenario_5_bound.log, so hardhat-mode evidence is safe.
test: data-check
	npx hardhat test
	uv run pytest tests/monitor/ -v
	uv run pytest tests/data/ -q
	uv run python scenarios/scenario_2_ronin.py
	uv run python scenarios/scenario_2b_iforest_compare.py
	uv run python scenarios/scenario_3_stress.py
	uv run python scenarios/scenario_4_fpr_sweep.py
	$(MAKE) bound-check
	$(MAKE) adversary
	$(MAKE) detector-eval

# BOLT Phase 14: empirical bound-validation harness (docs/bolt/theorem.md).
# Sweeps fast + patient attack schedules and asserts realised extraction <= the
# analytic bound (fast: T+r*Δ ; patient: B+r*D+r*Δ) for EVERY schedule. Falls back to
# a faithful offline token-bucket+breaker+Δ simulation when no Hardhat node is up, so
# it is reproducible kernel-only. EXITS NON-ZERO if any schedule violates its bound.
bound-check:
	uv run python scenarios/scenario_5_bound_validation.py

# BOLT Phase 15: cost-to-evade curve + bound composition (the C3-eval headline).
# Drives the full-knowledge adaptive adversary (monitor/adversary.py) against the
# REAL Phase-12 detector + Phase-13 limiter+breaker+Δ across a budget sweep, over
# >=10 seeds (mean ± 95% CI). For EVERY schedule the search evaluates it asserts
# realised extraction <= the Phase-14 bound (fast T+r*Δ ; patient B+r*D+r*Δ),
# reusing scenario_5's limiter/breaker semantics. EXITS NON-ZERO on any violation.
# Produces figures/cost_to_evade.png + figures/ablation.png + the log. Node-less.
adversary:
	uv run python scenarios/scenario_7_cost_to_evade.py

# BOLT Phase 22 B1: benign-utility experiment + bound-vs-utility Pareto frontier.
# Replays the REAL benign CCTX stream (82,685 transfers) through faithful offline
# models of the deployed RateLimiter + CircuitBreaker at the LOCKED ledger and over a
# B/r/T grid; reports % benign VALUE denied/delayed, delay percentiles, benign-
# triggered halts, and a parameter-scaling rule. Answers the "bound purchased by
# throttling the bridge" objection. Deterministic, node-less (parquet on disk).
# Produces figures/benign_utility_pareto.png + docs/logs/scenario_8_benign_utility.log.
benign-utility: data-check
	uv run python scenarios/scenario_8_benign_utility.py

# BOLT Phase 16: real-CCTX detection evaluation (the C1-eval headline; closes gap G3).
# Runs the Phase-12 sequential change-point detector + 3 fairly-tuned baselines (value
# z-score, corrected IsolationForest, rolling-mean/3sigma) through ONE shared scoring path
# on the REAL XChainWatcher CCTX data (Ronin + Nomad drains present). NON-CIRCULAR by
# construction: thresholds calibrated on the TRAIN split, every metric (ROC/PR/AUC/F1/
# confusion/ARL0/ARL1/phi) measured on the held-out TEST split. Reports >=10-seed bootstrap
# 95% CIs, a {T,B,r,W,Delta} sensitivity sweep, the H1 low-and-slow recall win, and the
# benign false-positive rate phi (consumed by Phase 17). Produces figures/roc_pr_curves.png
# + figures/arl_curves.png + figures/sensitivity.png + the log. Node-less (parquet on disk).
detector-eval:
	uv run python scenarios/scenario_6_detection_eval.py

# BOLT V2 task 3.2: deploy the v2 stack (RegistryV2 + RateLimiter + CircuitBreaker +
# BridgeV2, 9 validators via m-of-n governance) onto a Hardhat MAINNET FORK and write
# docs/logs/deployment_fork.log (addresses + gas). The ONE sanctioned non-local network
# use in this repo. Requires FORK_URL (free public RPC or free-tier key), e.g.:
#   make deploy-fork FORK_URL=https://ethereum-rpc.publicnode.com
deploy-fork:
	@test -n "$(FORK_URL)" || (echo "FORK_URL is required, e.g. make deploy-fork FORK_URL=https://ethereum-rpc.publicnode.com" && exit 1)
	FORK_URL=$(FORK_URL) FORK_BLOCK=$(FORK_BLOCK) npx hardhat run scripts/deploy_v2.ts

# BOLT V2 task 3.2: gas + detection-latency table (blocks AND seconds, HighGuard-style)
# on the mainnet fork. Drives the task-1.2 reachable-trip config (B+r·W > T) through a
# value-breaching schedule, measures breaker/monitor/Δ latencies, writes
# docs/bolt/deployment.md. EXITS NON-ZERO if the value trip does not persist (0.1 guard).
latency:
	@test -n "$(FORK_URL)" || (echo "FORK_URL is required, e.g. make latency FORK_URL=https://ethereum-rpc.publicnode.com" && exit 1)
	FORK_URL=$(FORK_URL) FORK_BLOCK=$(FORK_BLOCK) npx hardhat run scripts/measure_latency.ts

# End-to-end scenarios that require `npx hardhat node` running in another terminal.
scenario-2-e2e:
	uv run python scenarios/scenario_2_ronin.py

scenario-1:
	uv run python scenarios/scenario_1_lifecycle.py

clean:
	rm -rf artifacts cache typechain-types dist

# V2 1.6: reproducible gas table. Writes docs/bolt/gas_report_raw.txt; paste-refresh
# the summary table in docs/bolt/gas_report.md from it.
gas-report:
	REPORT_GAS=true npx hardhat test

# V2 0.5: Solidity line/branch coverage (solidity-coverage ships with hardhat-toolbox).
# Consumed by CI and by V2 task 1.3 (publish coverage %, target >=90% on v2 contracts).
coverage:
	npx hardhat coverage

# V2 1.4: Foundry invariant suite (window<=T, extraction<=T+r*Δ, revoked-never,
# bucket<=B, nonce-never-reused). Primary bytecode-level answer to the bound claim.
invariants:
	forge test --match-path "test/foundry/*" -vv

# V2 1.3: static analysis (artifact under docs/bolt/)
static:
	uv run slither . --compile-force-framework hardhat --checklist --filter-paths "node_modules|contracts/Greeter.sol" > docs/bolt/slither_report.md || true
