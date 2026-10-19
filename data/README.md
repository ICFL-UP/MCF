# CCTX Dataset: Provenance & Reproduction

This directory holds the **cross-chain-transaction (CCTX)** dataset used by the
BOLT (Bounded On-chain Loss Threshold) detection experiments. It is produced
deterministically by [`scripts/fetch_cctx.py`](../scripts/fetch_cctx.py).

> **Academic framing.** This is a design-specification PoC (MSc -> journal). The
> dataset is a real, third-party open dataset where network access is available,
> and a clearly-labelled deterministic synthetic stand-in otherwise. Caveats
> are noted where they apply.

## Primary source

| | |
|---|---|
| Dataset | **XChainWatcher** open CCTX dataset (~81k reconstructed cross-chain transactions for the Ronin and Nomad bridges, with labelled attacks) |
| Repository | <https://github.com/AndreAugusto11/XChainWatcher> |
| Paper | *XChainWatcher: Monitoring and Identifying Attacks in Cross-Chain Bridges*, arXiv:**2410.02029** |
| Upstream commit pinned | `4cc1ff173c18f80d275d7af6cbd318cdd3906e77` (resolved 2026-07-09; see `UPSTREAM_REF` in `scripts/fetch_cctx.py`) |

### License

**license: MIT; see <https://github.com/AndreAugusto11/XChainWatcher/blob/main/LICENSE>, accessed 2026-07-09.**

The upstream repository (verified via the GitHub API on 2026-07-09) carries an
MIT licence (`spdx_id: MIT`). This project does **not** vendor (commit) the raw
upstream files; only reproducible checksum sidecars are tracked (see below), so
no upstream data is redistributed from this repo. Consult the upstream `LICENSE`
file for the full terms before any redistribution.

## Exact download / build command

```bash
make data            # try the real download, fall back to synthetic if offline
# equivalently:
uv run python scripts/fetch_cctx.py            # real (network required)
uv run python scripts/fetch_cctx.py --offline  # force synthetic fallback
make data OFFLINE=1                             # Makefile shortcut for --offline
```

The script downloads, for **each bridge** (`ronin`, `nomad`), from
`https://raw.githubusercontent.com/AndreAugusto11/XChainWatcher/4cc1ff173c18f80d275d7af6cbd318cdd3906e77/cross-chain-rules-validator/analysis/<bridge>-bridge/data/`:

- `combined_cctxs.csv`: reconstructed benign cross-chain transactions
- `attacks.csv`: the labelled malicious destination withdrawals for the incident

Raw downloads are mirrored to `data/cctx/raw/<bridge>__<file>.csv` for audit
(these are **git-ignored**, ~33 MB total).

## Canonical schema

Both `train.parquet` and `test.parquet` have exactly these columns:

| column | type | meaning |
|---|---|---|
| `timestamp` | `datetime64[ms, UTC]` | origin-tx time (`orig_timestamp`); for attack rows, the destination-tx time (`dst_timestamp`) |
| `value` | `float64` | raw transfer amount in **token base units** (the on-chain `amount`, mixed per-token decimals); audit only (see units caveat below) |
| `value_usd` | `float64` | upstream per-transaction **USD valuation**, the common denomination the detectors score on |
| `source` | `str` | origin chain id (benign) / destination chain id (attack rows) |
| `destination` | `str` | beneficiary address, lower-case hex |
| `label` | `str` | `benign`, `incident:ronin`, or `incident:nomad` |
| `provenance` | `str` | `XChainWatcher` or `SYNTHETIC_FALLBACK` |
| `matched` | `bool` | `True` = matched deposit↔withdrawal pair from `combined_cctxs.csv`; `False` = attack-file withdrawal with no matching deposit |
| `finality_gap_s` | `float64` | origin→destination delay (s) for matched rows (upstream `time_difference`); NaN unmatched |

**Units caveat.** `value` is the raw on-chain `amount` in token base units, which
mixes 18-decimal native/ERC-20 tokens with lower-decimal tokens (6-decimal USDC,
8-decimal WBTC). It is therefore **not cross-token comparable** and no single
rescale fixes it: a blanket `/1e18` shrinks every low-decimal token by ≥1e10
(the Ronin 25.5M-USDC leg, raw `2.55e13`, would read as `2.55e-05` "ETH", and
~200-unit stablecoin transfers would read as sub-dust). All value-based scoring
uses `value_usd` (upstream's per-transaction USD valuation), the dataset's one
common denomination; `value` is retained for audit and for the Ronin base-unit
round-trip check (`1.736e23` wei = 173,600 ETH). Rows lacking a `value_usd`
valuation (12 of 83,079, incl. 2 Nomad attack rows) are dropped at build time.

### How incidents are labelled

The upstream `attacks.csv` rows are **not** present in `combined_cctxs.csv` (the
attacks bypassed the normal reconstructed flow). The pipeline therefore appends
the `attacks.csv` rows directly as the labelled positive class
(`incident:<bridge>`), de-duplicated by destination tx hash. It also defensively
re-labels any benign row whose destination tx hash appears in the attack set, in
case a future upstream revision folds attacks into `combined_cctxs.csv`.

The 173,600 ETH Ronin drain (2022-03-23) is included as an `incident:ronin` row.

## Train/test split

**Deterministic and time-based** (not random): rows are stable-sorted by
`timestamp` and the earliest `TRAIN_FRACTION = 0.70` go to `train.parquet`, the
remainder to `test.parquet`. A time-based split is leakage-free for a temporal
anomaly-detection task and is a pure function of the (deterministic) input, so
the output and its sha256 are reproducible. Parquet is written with
`version="2.6"` and `compression=None` to keep the bytes (and thus the checksum)
stable across pyarrow patch releases.

## Committed artifact & checksums

The parquet files and raw downloads are **git-ignored** (they are reproducible
and multi-MB). Only these tiny, reviewable sidecars are tracked, so the dataset
is auditable from git alone:

- `data/cctx/train.parquet.sha256`
- `data/cctx/test.parquet.sha256`

### Current checksums: REAL XChainWatcher dataset

The artifact produced by `make data` with network access (`provenance=XChainWatcher`):

| file | rows | sha256 |
|---|---|---|
| `train.parquet` | 58,146 | `2e509859f00235796ef890f30ede1e4b405937303ed02e1e274e33bd9e380f86` |
| `test.parquet`  | 24,921 | `079e4c4d5b510e260d0f95128ad7883c7860141a764701617a6baf2fd47cd0d0` |

Totals: 83,067 rows, of which `benign` 82,685, `incident:ronin` 2, `incident:nomad` 380
(12 upstream rows lacking a `value_usd` valuation, including 2 Nomad attack
rows, are dropped at build time; the drop is printed by the pipeline).

Verify a local build matches:

```bash
make data
sha256sum -c data/cctx/train.parquet.sha256 data/cctx/test.parquet.sha256
```

> The sidecars in git always reflect whichever path last ran locally. If you ran
> `--offline`, they will be the synthetic checksums below; re-run `make data`
> with network access to restore the real ones before committing.

### Synthetic fallback checksums (for reference)

If the real download is unavailable, `scripts/fetch_cctx.py` prints a loud
warning and emits a **deterministic synthetic stand-in**
(`provenance=SYNTHETIC_FALLBACK`) built from `monitor/generator.py` (calibrated
heavy-tailed values, Poisson arrivals, open-set Zipf destinations) plus one
injected Ronin-scale and one Nomad-scale incident row. For reference, the
`--offline` build yields:

| file | rows | sha256 |
|---|---|---|
| `train.parquet` | 56,701 | `657043ce3e2dc28bd38460181b9cb92e5304088df089fccef36fa8604c60308e` |
| `test.parquet`  | 24,301 | `107db1174a82c14faf6bf59095cd7d6bbcd7eaf04cbdaeae507c6d32bd6ccf01` |

Totals: 81,002 rows, of which `benign` 81,000, `incident:ronin` 1, `incident:nomad` 1.

**Note.** If the committed sidecars match the synthetic values above, the
local dataset is the SYNTHETIC FALLBACK, **not** the real XChainWatcher data, and
any results derived from it are illustrative only. The `provenance` column in the
parquet makes this unambiguous at read time.
