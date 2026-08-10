#!/usr/bin/env python3
"""Deterministic cross-chain-transaction (CCTX) dataset pipeline.

Primary source: the **XChainWatcher** open CCTX dataset
(repo: https://github.com/AndreAugusto11/XChainWatcher, paper arXiv:2410.02029),
which publishes ~81k reconstructed cross-chain transactions for the Ronin and
Nomad bridges together with labelled attack transactions.

This script is fully **deterministic**: given the same inputs (the pinned
upstream files, or the ``--offline`` synthetic fallback) it always produces
byte-stable ``data/cctx/train.parquet`` / ``data/cctx/test.parquet`` and matching
``*.sha256`` checksum sidecars.

Two code paths, made obvious by the ``provenance`` field in the output and the
loud banner printed at runtime:

1. **REAL** (default). Download the XChainWatcher ``combined_cctxs.csv`` and
   ``attacks.csv`` for both bridges from raw.githubusercontent.com (pinned to a
   commit/ref), normalise to the canonical schema, label rows whose destination
   transaction hash matches a known attack as ``incident:<bridge>``, and split
   deterministically by time.

2. **SYNTHETIC_FALLBACK** (``--offline`` or on any network failure). Reuse the
   project's deterministic generator (``monitor.generator.generate``) to emit the
   *same canonical schema*, clearly marked ``source="SYNTHETIC_FALLBACK"`` /
   ``provenance="SYNTHETIC_FALLBACK"``. A loud warning is printed and recorded so
   no synthetic artifact is ever mistaken for the real dataset. This keeps the
   pipeline and all downstream phases unblocked in network-restricted sandboxes.

Canonical output schema (both parquet files):

    timestamp    : datetime64[ns, UTC]
    value        : float64   (raw on-chain ``amount`` in token BASE UNITS with
                              mixed per-token decimals; NOT cross-token
                              comparable, see data/README.md)
    value_usd    : float64   (upstream per-transaction USD valuation, the one
                              common denomination across tokens; detectors
                              score on this column)
    source       : str       (origin chain id/name)
    destination  : str       (beneficiary address, lower-case hex)
    label        : str       ("benign" | "incident:ronin" | "incident:nomad")
    provenance   : str       ("XChainWatcher" | "SYNTHETIC_FALLBACK")
    matched      : bool      (True = joined from combined_cctxs, i.e. a matched
                              deposit<->withdrawal pair; False = attack-file
                              withdrawal with no matching origin deposit)
    finality_gap_s : float64 (origin->destination delay in seconds for matched
                              rows, upstream ``time_difference``; NaN unmatched)

Usage:
    uv run python scripts/fetch_cctx.py            # try real, fall back if needed
    uv run python scripts/fetch_cctx.py --offline  # force synthetic fallback
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.error
import urllib.request
from io import StringIO
from pathlib import Path

import pandas as pd

# Project root on sys.path so we can import monitor.generator when run as a script.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Pinned upstream commit SHA (resolved 2026-07-09 from the XChainWatcher main
# branch HEAD via the GitHub API). Pinning a full SHA rather than a branch name
# makes the download byte-deterministic across any future branch rewrites.
# To update: resolve the desired ref to its commit SHA, update this constant,
# run `make data` with network access to regenerate the parquets, verify the
# new sha256 sidecars are correct, update data/README.md's checksum table, and
# commit the sidecar + README changes.
UPSTREAM_REF = "4cc1ff173c18f80d275d7af6cbd318cdd3906e77"
UPSTREAM_BASE = (
    "https://raw.githubusercontent.com/AndreAugusto11/XChainWatcher/"
    f"{UPSTREAM_REF}/cross-chain-rules-validator/analysis"
)

# (bridge_name, combined_cctxs_url, attacks_url)
UPSTREAM_FILES = {
    "ronin": (
        f"{UPSTREAM_BASE}/ronin-bridge/data/combined_cctxs.csv",
        f"{UPSTREAM_BASE}/ronin-bridge/data/attacks.csv",
    ),
    "nomad": (
        f"{UPSTREAM_BASE}/nomad-bridge/data/combined_cctxs.csv",
        f"{UPSTREAM_BASE}/nomad-bridge/data/attacks.csv",
    ),
}

DATA_DIR = _ROOT / "data" / "cctx"
RAW_DIR = DATA_DIR / "raw"
TRAIN_PATH = DATA_DIR / "train.parquet"
TEST_PATH = DATA_DIR / "test.parquet"

CANONICAL_COLUMNS = [
    "timestamp",
    "value",
    "value_usd",
    "source",
    "destination",
    "label",
    "provenance",
    "matched",
    "finality_gap_s",
]

# Deterministic time-based split fraction (earliest ``TRAIN_FRACTION`` of rows by
# timestamp -> train, remainder -> test). Time-based (not random) so the split is
# leakage-free for a temporal anomaly-detection task and trivially reproducible.
TRAIN_FRACTION = 0.7
DOWNLOAD_TIMEOUT_SECONDS = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _banner(line: str) -> None:
    bar = "=" * 78
    print(f"\n{bar}\n{line}\n{bar}", flush=True)


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_parquet_with_checksum(df: pd.DataFrame, path: Path) -> str:
    """Write a parquet deterministically and emit a ``<path>.sha256`` sidecar."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Stable column order + reset index so the byte content is reproducible.
    df = df[CANONICAL_COLUMNS].reset_index(drop=True)
    # Pin parquet version + uncompressed to avoid compressor-version drift in the
    # bytes (keeps the sha256 stable across pyarrow patch releases).
    df.to_parquet(path, engine="pyarrow", index=False, version="2.6", compression=None)
    digest = _sha256_of_file(path)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n")
    print(f"  wrote {path}  ({len(df):,} rows)\n        sha256={digest}", flush=True)
    return digest


def _read_committed_sidecar(path: Path) -> str | None:
    """Return the sha256 hex digest recorded in the committed sidecar, or None.

    The sidecar format is ``<hex>  <filename>`` (two spaces, BSD/GNU sha256sum
    compatible).  Returns ``None`` if the sidecar does not exist or is malformed.
    """
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if not sidecar.exists():
        return None
    line = sidecar.read_text().strip()
    parts = line.split(None, 1)
    if len(parts) < 1 or len(parts[0]) != 64:
        return None
    return parts[0].lower()


def verify_against_committed_sidecars(
    train_path: Path = TRAIN_PATH,
    test_path: Path = TEST_PATH,
    committed_digests: dict[Path, str | None] | None = None,
) -> None:
    """Verify freshly built parquets against committed sidecar checksums.

    Called automatically by ``run()`` after writing the parquets.  If committed
    sidecars exist and the newly written files do not match, raises
    ``RuntimeError`` so the build fails loudly instead of silently accepting a
    corrupt or mismatched artifact.

    ``committed_digests`` allows the caller to pass digests captured **before**
    the sidecars on disk were rewritten (``run()`` does this: the write step
    emits fresh sidecars, so reading them afterwards would always trivially
    match).  When ``None``, the sidecars are read from disk.

    This is a **no-op** when the sidecars are absent (e.g. on a clean clone
    before the first ``make data`` run); the caller already wrote new sidecars.
    """
    mismatches: list[str] = []
    for path in (train_path, test_path):
        if committed_digests is not None:
            committed = committed_digests.get(path)
        else:
            committed = _read_committed_sidecar(path)
        if committed is None:
            # No committed sidecar to compare against: nothing to verify.
            continue
        actual = _sha256_of_file(path)
        if actual.lower() != committed.lower():
            mismatches.append(
                f"  {path.name}: expected {committed}  got {actual}"
            )
    if mismatches:
        raise RuntimeError(
            "Parquet checksum mismatch — freshly built files do not match the "
            "committed sidecar checksums.  This means either the upstream data "
            "changed (pin drift), the build is not deterministic, or the sidecar "
            "was committed with a different dataset version.\n"
            + "\n".join(mismatches)
            + "\n\nTo fix: re-run `make data` from scratch with network access "
            "and verify the new checksums are intentional before committing them."
        )


def _deterministic_time_split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Earliest ``TRAIN_FRACTION`` of rows by timestamp -> train; rest -> test.

    Sort is a stable mergesort on timestamp so ties keep input order, making the
    split a pure function of the (already deterministic) input frame.
    """
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    cut = int(len(df) * TRAIN_FRACTION)
    return df.iloc[:cut].copy(), df.iloc[cut:].copy()


# ---------------------------------------------------------------------------
# REAL path: download + normalise XChainWatcher
# ---------------------------------------------------------------------------
def _mirror_path(url: str) -> Path:
    # Two bridges share file names; prefix with bridge dir to disambiguate mirror.
    bridge = "ronin" if "ronin-bridge" in url else "nomad"
    return RAW_DIR / f"{bridge}__{url.rsplit('/', 1)[-1]}"


def _download_text(url: str, from_raw: bool = False) -> str:
    """Download a URL to text, mirroring the bytes into data/cctx/raw/ for audit.

    With ``from_raw=True`` (the ``--from-raw`` flag) the previously mirrored bytes
    are read back instead of hitting the network, a byte-identical offline rebuild
    of the parquet artifact from the audited raw downloads.
    """
    mirror = _mirror_path(url)
    if from_raw:
        if not mirror.exists():
            raise OSError(f"--from-raw requested but mirror missing: {mirror}")
        return mirror.read_bytes().decode("utf-8")
    req = urllib.request.Request(url, headers={"User-Agent": "mcf-poc-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:
        raw = resp.read()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    mirror.write_bytes(raw)
    return raw.decode("utf-8")


def _normalise_combined(csv_text: str, bridge: str) -> pd.DataFrame:
    """Map an XChainWatcher ``combined_cctxs.csv`` to the canonical schema."""
    raw = pd.read_csv(StringIO(csv_text))
    df = pd.DataFrame()
    # orig_timestamp is a unix epoch (seconds).
    df["timestamp"] = pd.to_datetime(raw["orig_timestamp"], unit="s", utc=True)
    # ``amount`` is the on-chain token amount in token BASE UNITS with MIXED
    # per-token decimals (18-dec ETH-class next to 6-dec USDC / 8-dec WBTC), so it
    # is NOT cross-token comparable; kept for audit. ``value_usd`` is upstream's
    # per-tx USD valuation, the one common denomination the detectors score on.
    # See data/README.md for the units caveat.
    df["value"] = pd.to_numeric(raw["amount"], errors="coerce")
    df["value_usd"] = pd.to_numeric(raw["value_usd"], errors="coerce")
    df["source"] = raw["orig_chain_id"].astype(str)
    df["destination"] = raw["beneficiary"].astype(str).str.lower()
    df["label"] = "benign"
    df["provenance"] = "XChainWatcher"
    # Linkage columns for the XChainWatcher rule comparator: rows from
    # combined_cctxs.csv are matched deposit<->withdrawal pairs; the pair's
    # origin->destination delay (seconds) is upstream's ``time_difference``.
    df["matched"] = True
    df["finality_gap_s"] = pd.to_numeric(raw["time_difference"], errors="coerce")
    # Keep the destination tx hash for attack matching, dropped before output.
    df["_dst_tx_hash"] = raw["dst_tx_hash"].astype(str).str.lower()
    df["_bridge"] = bridge
    return df


def _attack_hashes(csv_text: str) -> set[str]:
    raw = pd.read_csv(StringIO(csv_text))
    return set(raw["dst_transaction_hash"].astype(str).str.lower())


def _normalise_attacks(csv_text: str, bridge: str) -> pd.DataFrame:
    """Map an XChainWatcher ``attacks.csv`` to canonical incident rows.

    The upstream ``attacks.csv`` enumerates the malicious destination
    withdrawals for each incident (e.g. the 173,600 ETH Ronin drain, the 382
    Nomad chaotic-drain withdrawals). These rows are *not* present in
    ``combined_cctxs.csv`` (the attacks bypassed the normal reconstructed flow),
    so they are appended directly as the labelled positive class.
    """
    raw = pd.read_csv(StringIO(csv_text))
    df = pd.DataFrame()
    df["timestamp"] = pd.to_datetime(raw["dst_timestamp"], unit="s", utc=True)
    # Same units contract as _normalise_combined: raw base-unit ``amount`` (mixed
    # per-token decimals, audit only) + the common-denomination ``value_usd``.
    df["value"] = pd.to_numeric(raw["amount"], errors="coerce")
    df["value_usd"] = pd.to_numeric(raw["value_usd"], errors="coerce")
    df["source"] = raw["dst_chain_id"].astype(str)
    df["destination"] = raw["beneficiary"].astype(str).str.lower()
    df["label"] = f"incident:{bridge}"
    df["provenance"] = "XChainWatcher"
    # Attack withdrawals are exactly the rows XChainWatcher found UNMATCHED
    # (no origin-chain deposit), hence matched=False and no finality gap.
    df["matched"] = False
    df["finality_gap_s"] = float("nan")
    df["_dst_tx_hash"] = raw["dst_transaction_hash"].astype(str).str.lower()
    df["_bridge"] = bridge
    return df


def _build_real(from_raw: bool = False) -> pd.DataFrame:
    """Download, normalise, label, and concatenate both bridges. Raises on failure.

    For each bridge we combine (a) the benign reconstructed CCTXs from
    ``combined_cctxs.csv`` with (b) the labelled malicious withdrawals from
    ``attacks.csv``. Any benign row whose destination tx hash also appears in the
    attack set is additionally re-labelled (defensive: handles future upstream
    revisions where attacks are folded into ``combined_cctxs.csv``).
    """
    frames: list[pd.DataFrame] = []
    verb = "reading mirrored" if from_raw else "downloading"
    for bridge, (combined_url, attacks_url) in UPSTREAM_FILES.items():
        print(f"  {verb} {bridge} combined_cctxs.csv ...", flush=True)
        combined_text = _download_text(combined_url, from_raw=from_raw)
        print(f"  {verb} {bridge} attacks.csv ...", flush=True)
        attacks_text = _download_text(attacks_url, from_raw=from_raw)

        benign = _normalise_combined(combined_text, bridge)
        attack_set = _attack_hashes(attacks_text)
        # Defensive in-place relabel if attacks ever appear inside combined.
        in_combined = benign["_dst_tx_hash"].isin(attack_set)
        benign.loc[in_combined, "label"] = f"incident:{bridge}"

        attacks = _normalise_attacks(attacks_text, bridge)
        # Drop attack rows already represented in combined (by dst tx hash) to
        # avoid double counting.
        attacks = attacks[~attacks["_dst_tx_hash"].isin(set(benign["_dst_tx_hash"]))]

        n_incident = int(in_combined.sum()) + len(attacks)
        print(
            f"    {bridge}: {len(benign):,} reconstructed + {len(attacks):,} "
            f"attack rows -> {n_incident:,} labelled incident rows",
            flush=True,
        )
        frames.append(benign)
        frames.append(attacks)

    combined = pd.concat(frames, ignore_index=True)
    # ``value_usd`` is required (it is the column the detectors score on); a
    # handful of upstream rows (~12 of ~83k, incl. 2 Nomad attack rows) carry no
    # USD valuation and are dropped; the drop is printed so it stays auditable.
    n_before = len(combined)
    combined = combined.dropna(subset=["timestamp", "value", "value_usd"])
    n_dropped = n_before - len(combined)
    if n_dropped:
        print(
            f"    dropped {n_dropped} row(s) lacking timestamp/value/value_usd "
            f"(of {n_before:,})",
            flush=True,
        )
    return combined.drop(columns=["_dst_tx_hash", "_bridge"])


# ---------------------------------------------------------------------------
# FALLBACK path: deterministic synthetic stand-in
# ---------------------------------------------------------------------------
def _build_synthetic(seed: int = 7, n: int = 81_000) -> pd.DataFrame:
    """Deterministic synthetic CCTX frame in the canonical schema.

    Reuses the project's calibrated heavy-tailed generator
    (``monitor.generator.generate``), which yields ``[timestamp, value,
    destination]``. We add a ``source`` column (deterministically derived from the
    destination, so it stays a pure function of the seed) and inject two
    incident-scale labelled rows mirroring the real Ronin/Nomad attacks.
    """
    import monitor.generator as g  # local import: only needed on the fallback path

    df = g.generate(seed=seed, n=n)
    df = df.copy()
    # Make timestamps UTC-aware to match the real path's schema exactly.
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    # Deterministic source from a stable hash of the destination address.
    chains = ["ethereum", "ronin", "nomad", "polygon", "bsc"]
    df["source"] = df["destination"].map(
        lambda a: chains[int(hashlib.sha256(a.encode()).hexdigest(), 16) % len(chains)]
    )
    df["label"] = "benign"
    df["provenance"] = "SYNTHETIC_FALLBACK"
    # The synthetic generator emits a single common unit already (ETH-class), so
    # the common-denomination column is the identity; it is kept only so the
    # fallback matches the canonical schema (real path: upstream per-tx USD
    # valuation).
    df["value_usd"] = df["value"]
    # Linkage columns mirroring the real schema: synthetic benign rows stand in
    # for matched pairs (zero gap); the incident rows are unmatched withdrawals.
    df["matched"] = True
    df["finality_gap_s"] = 0.0

    incidents = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(
                ["2022-03-23T13:29:00Z", "2022-08-01T21:32:00Z"], utc=True
            ),
            # 173,600 ETH Ronin drain; representative Nomad drain magnitude.
            "value": [173_600.0, 10_000.0],
            "value_usd": [173_600.0, 10_000.0],
            "source": ["ronin", "nomad"],
            "destination": [
                "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
                "0xf57113d8f6ff35747737f026fe0b37d4d7f42777",
            ],
            "label": ["incident:ronin", "incident:nomad"],
            "provenance": ["SYNTHETIC_FALLBACK", "SYNTHETIC_FALLBACK"],
            "matched": [False, False],
            "finality_gap_s": [float("nan"), float("nan")],
        }
    )
    return pd.concat([df, incidents], ignore_index=True)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run(offline: bool, from_raw: bool = False) -> str:
    """Build the dataset and write train/test parquet + checksums.

    Returns the provenance label that was actually used
    ("XChainWatcher" or "SYNTHETIC_FALLBACK"). ``from_raw`` rebuilds from the
    audited ``data/cctx/raw/`` mirror without any network access (still the REAL
    XChainWatcher bytes, so provenance stays "XChainWatcher").
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    used: str
    if offline:
        _banner(
            "WARNING: --offline set. Using DETERMINISTIC SYNTHETIC FALLBACK.\n"
            "         The committed artifact is NOT the real XChainWatcher dataset."
        )
        df = _build_synthetic()
        used = "SYNTHETIC_FALLBACK"
    else:
        if from_raw:
            _banner("Rebuilding REAL dataset from the local data/cctx/raw/ mirror (no network).")
        else:
            _banner(f"Attempting REAL download from XChainWatcher (ref={UPSTREAM_REF}).")
        try:
            df = _build_real(from_raw=from_raw)
            used = "XChainWatcher"
            print("  REAL download + processing succeeded.", flush=True)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            _banner(
                "WARNING: real download FAILED -> using DETERMINISTIC SYNTHETIC "
                f"FALLBACK.\n         reason: {type(exc).__name__}: {exc}\n"
                "         The committed artifact is NOT the real XChainWatcher dataset."
            )
            df = _build_synthetic()
            used = "SYNTHETIC_FALLBACK"

    # Guard the canonical schema before splitting.
    missing = [c for c in CANONICAL_COLUMNS if c not in df.columns]
    if missing:
        raise RuntimeError(f"internal error: missing canonical columns {missing}")

    train, test = _deterministic_time_split(df)
    _banner(f"Writing parquet (provenance={used})")
    # Capture the COMMITTED sidecar digests BEFORE the write below rewrites the
    # sidecar files; otherwise verification would read the just-written digests
    # back and trivially pass (rewrite, not verify).
    committed_digests = {
        TRAIN_PATH: _read_committed_sidecar(TRAIN_PATH),
        TEST_PATH: _read_committed_sidecar(TEST_PATH),
    }
    train_sha = _write_parquet_with_checksum(train, TRAIN_PATH)
    test_sha = _write_parquet_with_checksum(test, TEST_PATH)

    # Verify the freshly written parquets against committed sidecars (if any).
    # This catches upstream pin drift, non-deterministic builds, or accidental
    # sidecar/parquet version mismatches.  Fails loudly on any mismatch.
    verify_against_committed_sidecars(committed_digests=committed_digests)

    label_counts = df["label"].value_counts().to_dict()
    print(
        f"\nSUMMARY  provenance={used}  total_rows={len(df):,}  "
        f"train={len(train):,}  test={len(test):,}\n"
        f"         labels={label_counts}\n"
        f"         train.sha256={train_sha}\n"
        f"         test.sha256={test_sha}",
        flush=True,
    )
    if used == "SYNTHETIC_FALLBACK":
        print(
            "\nNOTE: committed dataset is the SYNTHETIC FALLBACK. See data/README.md "
            "for how to regenerate from the real source when network is available.",
            flush=True,
        )
    return used


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="force the deterministic synthetic fallback (no network access).",
    )
    parser.add_argument(
        "--from-raw",
        action="store_true",
        help="rebuild the REAL dataset from the audited data/cctx/raw/ mirror "
        "(no network access; requires a previous real download).",
    )
    args = parser.parse_args(argv)
    run(offline=args.offline, from_raw=args.from_raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
