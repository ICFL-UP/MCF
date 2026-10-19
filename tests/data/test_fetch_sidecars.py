"""Sidecar-verification tests for the CCTX fetch pipeline (Phase 22, Tier E4).

These pin ``scripts/fetch_cctx.py``'s ``verify_against_committed_sidecars()``:
a freshly built parquet must match the COMMITTED ``.sha256`` sidecar digest
(upstream-drift guard), the check must pass on a match, and it must be a
silent no-op on a clean clone with no sidecars yet.

They live in ``tests/data/`` (not ``tests/monitor/``) so that the frozen
canonical monitor suite (``pytest tests/monitor`` = 117 tests, part of the
217-test total cited in the dissertation) stays exactly reproducible.
``make test`` runs this directory as a separate step.

Offline, node-less (pure Python/pandas).
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

# scripts/ is not a package; load fetch_cctx by path.
import importlib.util

_FETCH_PATH = Path(__file__).resolve().parents[2] / "scripts" / "fetch_cctx.py"
_spec = importlib.util.spec_from_file_location("fetch_cctx", _FETCH_PATH)
fetch_cctx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_cctx)


def test_verify_against_committed_sidecars_fails_on_mismatch(tmp_path):
    """verify_against_committed_sidecars() must raise RuntimeError when a freshly
    built parquet's sha256 does not match the digest in the committed sidecar.
    This is a pure-function, node-less, network-less test."""
    # Write a tiny dummy parquet (two rows).
    dummy = pd.DataFrame({"x": [1, 2]})
    parquet_path = tmp_path / "train.parquet"
    dummy.to_parquet(parquet_path, index=False)

    # Write a sidecar that deliberately contains the WRONG digest.
    sidecar_path = parquet_path.with_suffix(parquet_path.suffix + ".sha256")
    sidecar_path.write_text("a" * 64 + "  train.parquet\n")

    # Also provide a matching test.parquet + sidecar so the function can run.
    test_path = tmp_path / "test.parquet"
    dummy.to_parquet(test_path, index=False)
    # Correct sidecar for test.parquet so only train triggers the mismatch.
    actual_digest = fetch_cctx._sha256_of_file(test_path)
    (tmp_path / "test.parquet.sha256").write_text(f"{actual_digest}  test.parquet\n")

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        fetch_cctx.verify_against_committed_sidecars(
            train_path=parquet_path,
            test_path=test_path,
        )


def test_verify_against_committed_sidecars_passes_on_match(tmp_path):
    """verify_against_committed_sidecars() must be a no-op when the committed
    sidecar matches the freshly built file."""
    dummy = pd.DataFrame({"x": [1, 2]})
    parquet_path = tmp_path / "train.parquet"
    dummy.to_parquet(parquet_path, index=False)
    actual_digest = fetch_cctx._sha256_of_file(parquet_path)
    (tmp_path / "train.parquet.sha256").write_text(f"{actual_digest}  train.parquet\n")

    test_path = tmp_path / "test.parquet"
    dummy.to_parquet(test_path, index=False)
    actual_test_digest = fetch_cctx._sha256_of_file(test_path)
    (tmp_path / "test.parquet.sha256").write_text(f"{actual_test_digest}  test.parquet\n")

    # Should not raise.
    fetch_cctx.verify_against_committed_sidecars(
        train_path=parquet_path,
        test_path=test_path,
    )


def test_verify_against_committed_sidecars_noop_when_no_sidecar(tmp_path):
    """verify_against_committed_sidecars() must be a silent no-op when no
    committed sidecars exist (e.g. clean clone before first `make data`)."""
    parquet_path = tmp_path / "train.parquet"
    test_path = tmp_path / "test.parquet"
    pd.DataFrame({"x": [1]}).to_parquet(parquet_path, index=False)
    pd.DataFrame({"x": [1]}).to_parquet(test_path, index=False)
    # No sidecar files written: should be a no-op.
    fetch_cctx.verify_against_committed_sidecars(
        train_path=parquet_path,
        test_path=test_path,
    )
