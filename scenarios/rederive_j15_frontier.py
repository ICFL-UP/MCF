"""J15: re-derive the scenario-8 Pareto frontier against the PROVED extraction envelope.

WHY THIS FILE EXISTS
--------------------
`scenarios/scenario_8_benign_utility.py` ranked its 42-configuration sweep by
``T + r·Delta``, the form refuted in main.tex Sect. 4.2 / Appendix A. J15 replaces the
ordinate with the proved envelope ``B + r(W + Delta)``. The change touches ONLY the
ordinate: the abscissa (fraction of benign VALUE denied-or-delayed) is produced by
replaying the benign CCTX stream through the limiter/breaker models and depends on
(B, r, T) alone -- nothing in J15 alters that replay, so every x-value is unchanged by
construction.

This harness therefore re-derives the frontier WITHOUT re-reading the parquet corpus:
it parses the committed, published sweep table out of
``docs/logs/scenario_8_benign_utility.log`` for the x-values, halts and delays, and
recomputes y with ``LedgerETH.envelope_usd()`` from the patched scenario-8 module. It
then calls scenario 8's own ``mark_pareto``, ``sweep_report_lines`` and ``_write_figure``
-- not copies of them -- so the frontier logic and the figure are the production code
paths.

WHAT IT IS NOT
--------------
It is not a substitute for re-running scenario 8. Re-running the full scenario in an
environment with ``pyarrow`` MUST reproduce this file's y-values exactly and its
x-values bit-for-bit against the published log. If any x moves, the published log and
this re-derivation disagree and the discrepancy must be reconciled BEFORE the figure is
used -- do not update prose to match a moved number.

Usage (from the repository root):

    python3 scenarios/rederive_j15_frontier.py

Writes:
    docs/logs/j15_envelope_rederivation.log
    figures/benign_utility_pareto.png     (the new Fig9 -- envelope ordinate)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scenarios.scenario_8_benign_utility import (  # noqa: E402
    DELTA,
    LOCKED,
    sweep_grid,
    RONIN_DRAIN_USD,
    USD_PER_ETH,
    LedgerETH,
    ParetoPoint,
    _fmt_usd,
    _write_figure,
    mark_pareto,
    sweep_report_lines,
)

SRC_LOG = Path("docs/logs/scenario_8_benign_utility.log")
OUT_LOG = Path("docs/logs/j15_envelope_rederivation.log")

# "  B(ETH)  r  T  bound(USD)  denied%val  den-or-del%val  halts  p99delay  pareto"
ROW = re.compile(
    r"^\s+(\d+)\s+(\d+)\s+(\d+)\s+"        # B, r, T (ETH, integers in the published grid)
    r"(\$[\d.,]+[MB]?)\s+"                  # superseded bound, USD
    r"([\d.]+)\s+([\d.]+)\s+"               # denied%val, den-or-del%val
    r"(\d+)\s+(\d+)\s+"                     # halts, p99 delay
    r"(FRONTIER|-)\s*$"
)
RULE = re.compile(
    r"rule-derived ledger:\s*B=([\d,]+)\s*ETH.*?r=([\d,.]+)\s*ETH/s,\s*T=([\d,]+)\s*ETH"
)
RULE_X = re.compile(r"denied-or-delayed\s+([\d.]+)%\s+of benign value,\s+halts\s+(\d+)")


def _f(x: str) -> float:
    return float(x.replace(",", ""))


def parse_published_sweep(path: Path) -> tuple[list[ParetoPoint], ParetoPoint]:
    """Read the published sweep table and rule-derived point out of the scenario-8 log."""
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found -- run scenario_8_benign_utility.py first, or check the path")
    text = path.read_text(encoding="utf-8")

    points: list[ParetoPoint] = []
    for line in text.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        B, r, T = _f(m.group(1)), _f(m.group(2)), _f(m.group(3))
        led = LedgerETH(f"B{int(B)}_r{int(r)}_T{int(T)}", B=B, r=r, T=T)
        points.append(ParetoPoint(
            ledger=led,
            denial_delay_value_frac=float(m.group(6)) / 100.0,
            bound_usd=led.bound_usd(),
            envelope_usd=led.envelope_usd(),
            denied_value_frac=float(m.group(5)) / 100.0,
            halts=int(m.group(7)),
            p99_delay=float(m.group(8)),
        ))
    if not points:
        raise ValueError(f"no sweep rows parsed from {path}")

    # Parse check that is sensitive to B. The published superseded ordinate is
    # T + r*Delta and does NOT contain B, so recomputing that column would not
    # catch a B mis-parse -- the very parameter the new ordinate depends on most.
    # Compare the parsed (B, r, T) triples against the authoritative grid instead.
    parsed = sorted((p.ledger.B, p.ledger.r, p.ledger.T) for p in points)
    expected = sorted((g.B, g.r, g.T) for g in sweep_grid())
    if parsed != expected:
        raise ValueError(
            "parsed grid does not match sweep_grid(): "
            f"{len(parsed)} parsed vs {len(expected)} expected; "
            f"first mismatch {next((a, b) for a, b in zip(parsed, expected) if a != b)}")

    mr = RULE.search(text)
    mx = RULE_X.search(text)
    if not (mr and mx):
        raise ValueError(f"rule-derived ledger line not found in {path}")
    rule_led = LedgerETH("rule-derived", B=_f(mr.group(1)), r=_f(mr.group(2)),
                         T=_f(mr.group(3)))
    rule_pt = ParetoPoint(
        ledger=rule_led,
        denial_delay_value_frac=float(mx.group(1)) / 100.0,
        bound_usd=rule_led.bound_usd(),
        envelope_usd=rule_led.envelope_usd(),
        denied_value_frac=float("nan"),
        halts=int(mx.group(2)),
        p99_delay=float("nan"),
    )
    return points, rule_pt


def main() -> int:
    points, rule_pt = parse_published_sweep(SRC_LOG)
    mark_pareto(points)

    # The log prints x to two decimal places. Two configurations whose true x
    # differ in the third place therefore parse as an exact tie, which changes the
    # SUPERSEDED domination result (T + r*Delta ties are common) -- the published
    # log marks 9 frontier rows under that ordinate where recomputation from 2-dp x
    # finds 8. Take the superseded membership from the log's own `pareto` column,
    # which was computed at full precision, rather than recomputing it here.
    #
    # The ENVELOPE frontier is not exposed to this: every coincident group on it
    # has halts = 0 and p99 delay = 0, i.e. identical replays whose x-values are
    # equal exactly, not merely to two places.
    published_frontier = set()
    for line in SRC_LOG.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m and m.group(9) == "FRONTIER":
            published_frontier.add((_f(m.group(1)), _f(m.group(2)), _f(m.group(3))))
    for pt in points:
        key = (pt.ledger.B, pt.ledger.r, pt.ledger.T)
        pt.dominated_superseded = key not in published_frontier

    locked_pt = next(
        p for p in points
        if (p.ledger.B, p.ledger.r, p.ledger.T) == (LOCKED.B, LOCKED.r, LOCKED.T)
    )

    # Cross-check: the parsed superseded ordinate must reproduce the published column.
    # (ROW group 4 is the published string; recomputing it from (T, r) and re-formatting
    # is the check that the grid was parsed onto the right ledger.)
    published = re.findall(r"^\s+\d+\s+\d+\s+\d+\s+(\$[\d.,]+[MB]?)", SRC_LOG.read_text(
        encoding="utf-8"), flags=re.M)
    recomputed = [_fmt_usd(p.bound_usd) for p in points]
    mismatch = [(a, b) for a, b in zip(published, recomputed) if a != b]

    lines = [
        "# J15 — Pareto frontier re-derived against the PROVED envelope B + r(W + Δ)",
        f"# source of x-values: {SRC_LOG} (published sweep; x depends on (B, r, T) via the",
        "#   benign replay and is UNCHANGED by J15 — only the ordinate changes)",
        "# y recomputed by LedgerETH.envelope_usd(); frontier by scenario_8.mark_pareto()",
        f"# Δ = {DELTA:g} s, W = 3600 s, ${USD_PER_ETH:,.0f}/ETH, "
        f"Ronin drain {_fmt_usd(RONIN_DRAIN_USD)}",
        f"# parse check 1 (B-sensitive): parsed (B, r, T) grid == sweep_grid() for all "
        f"{len(points)} configs",
        f"# parse check 2: superseded-ordinate column reproduced "
        f"{'EXACTLY' if not mismatch else f'with {len(mismatch)} MISMATCH(ES) — INVESTIGATE'}",
        "# superseded-frontier membership is read from the log's own `pareto` column "
        "(full precision),",
        "#   not recomputed from the 2-dp x values printed in the table.",
        "#",
    ]
    lines += sweep_report_lines(points, len(points))
    lines += [
        "#",
        "## locked and rule-derived ledgers under the envelope",
        f"  LOCKED (B={LOCKED.B:,.0f}, r={LOCKED.r:,.0f}, T={LOCKED.T:,.0f} ETH): "
        f"envelope {_fmt_usd(locked_pt.envelope_usd)} "
        f"({locked_pt.envelope_usd / RONIN_DRAIN_USD * 100:.1f}% of Ronin) at "
        f"{locked_pt.denial_delay_value_frac * 100:.2f}% benign value denied-or-delayed"
        f"   [superseded T + r·Δ: {_fmt_usd(locked_pt.bound_usd)}]",
        f"  rule-derived (B={rule_pt.ledger.B:,.0f}, r={rule_pt.ledger.r:,.2f}, "
        f"T={rule_pt.ledger.T:,.0f} ETH): envelope {_fmt_usd(rule_pt.envelope_usd)} "
        f"({rule_pt.envelope_usd / RONIN_DRAIN_USD * 100:.1f}% of Ronin) at "
        f"{rule_pt.denial_delay_value_frac * 100:.2f}%"
        f"   [superseded T + r·Δ: {_fmt_usd(rule_pt.bound_usd)}]",
    ]

    OUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    OUT_LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nLog written: {OUT_LOG}")

    _write_figure(points, locked_pt, rule_pt)

    if mismatch:
        print(f"ERROR: {len(mismatch)} superseded-ordinate mismatches; first: {mismatch[0]}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
