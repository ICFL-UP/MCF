"""Rule-engine comparator after XChainWatcher (Augusto et al., arXiv:2410.02029).

XChainWatcher's core cross-chain soundness rules, re-implemented over the
canonical CCTX parquet's linkage columns (``matched``, ``finality_gap_s``):

1. **Unmatched withdrawal**: a destination-chain withdrawal with no matching
   origin-chain deposit is unsound (score 1.0).
2. **Finality violation**: a matched deposit↔withdrawal pair whose destination
   event precedes its origin event (negative ``finality_gap_s`` beyond the
   configured finality window) violates finality (score 0.5).
3. Anything else is clean (score 0.0).

Honesty note (load-bearing, mirrored in docs/bolt/detection_eval.md): the CCTX
incident labels were *derived by* XChainWatcher's unmatched-withdrawal analysis,
so this rule engine attains ~perfect recall on the dataset **by construction**.
It is published as a capability/deployment-cost comparator (both chains
instrumented + protocol rules vs BOLT's destination-stream-only detector), not
as a fair same-information classifier baseline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

_LINKAGE_COLUMNS = ("matched", "finality_gap_s")


@dataclass(frozen=True)
class RuleAudit:
    """Per-frame tally of which rule (if any) each row triggered."""

    n_unmatched: int
    n_finality_violation: int
    n_clean: int


class XChainWatcherRules:
    """Rule-engine comparator after XChainWatcher (Augusto et al., arXiv:2410.02029):
    a destination-chain withdrawal with no matching origin-chain deposit is unsound;
    a matched pair whose destination event precedes its origin event violates finality."""

    def __init__(self, finality_window_s: float = 0.0):
        self.finality_window_s = float(finality_window_s)

    def _scores(self, df: "pd.DataFrame") -> np.ndarray:
        missing = [c for c in _LINKAGE_COLUMNS if c not in df.columns]
        if missing:
            raise KeyError(
                "linkage columns missing — regenerate the parquet with `make data`"
                f" (absent: {missing})"
            )
        matched = df["matched"].to_numpy(dtype=bool)
        gap = df["finality_gap_s"].to_numpy(dtype=float)
        # NaN gaps never compare True, so unmatched rows fall through to the
        # first branch and matched-but-gapless rows score clean.
        with np.errstate(invalid="ignore"):
            scores = np.where(
                ~matched, 1.0, np.where(gap < -self.finality_window_s, 0.5, 0.0)
            )
        return scores.astype(float)

    def score_frame(self, df: "pd.DataFrame") -> tuple[np.ndarray, np.ndarray]:
        """(scores, flags) per the scenario_6 Detector contract.
        score: 1.0 unmatched, 0.5 finality violation, 0.0 clean. flag = score > 0."""
        scores = self._scores(df)
        return scores, scores > 0.0

    def audit(self, df: "pd.DataFrame") -> RuleAudit:
        scores = self._scores(df)
        return RuleAudit(
            n_unmatched=int(np.sum(scores == 1.0)),
            n_finality_violation=int(np.sum(scores == 0.5)),
            n_clean=int(np.sum(scores == 0.0)),
        )
