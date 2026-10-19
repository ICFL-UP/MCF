"""Scenario 8: benign-utility experiment + bound-vs-utility Pareto frontier (Phase 22, B1).

THE QUESTION THIS ANSWERS (the IJIS critique's single biggest missing result):
"the extraction bound is small because the bridge is throttled; no bound-vs-utility
trade-off is shown." This harness replays the FULL real benign CCTX stream (XChainWatcher,
82,685 benign transfers, Jan–Dec 2022) through faithful offline Python models of the
deployed RateLimiter (token bucket B, r) and CircuitBreaker (61-slot bucketed sliding
window W, threshold T, latch-until-reset) and measures what the LOCKED ledger costs
legitimate users, then sweeps a B/r/T grid to draw the Pareto frontier between

    x = fraction of benign VALUE denied or delayed
    y = worst-case per-window extraction envelope  B + r·(W + Δ)   (Δ = 60 s composed,
        docs/bolt/deployment.md; W = 3600 s)

J15 CHANGE OF ORDINATE (2026-08-02).  This sweep was originally ranked by ``T + r·Δ``.
That form was refuted as an upper bound (main.tex Sect. 4.2 / Appendix A): the trailing
window slides, so outflow admitted early retires from it during the response latency and
the freed headroom re-opens.  The proved envelope is ``B + r(t_trip + Δ)``, maximised at
``t_trip = W``.  Three consequences matter for THIS figure and are reported in the log:

  1. **T drops out.**  Configurations differing only in T share an ordinate, so the
     42-config grid collapses onto 15 distinct y-values and coincident (x, y) points
     appear.  The frontier is reported both as a config count and as a count of
     distinct locations.
  2. **Frontier membership changes.**  It is not a relabelling: high-T configurations
     fall a long way down the axis, so points that were dominated under the old form
     can surface and vice versa.  The log prints the membership delta explicitly.
  3. **Configurations with B + r·W < T cannot trip the value breaker at all** (true of
     the LOCKED ledger: 4,600 < 5,000).  Their envelope comes from the window horizon,
     not from T, which is exactly why T's disappearance is principled rather than
     convenient.

``LedgerETH.bound_usd`` is retained UNCHANGED so the superseded figure stays
reproducible bit-for-bit; ``LedgerETH.envelope_usd`` is the quantity now plotted.

DENOMINATION ASSUMPTION (stated once, applied everywhere):
The ledger parameters are specified in ETH (theorem.md symbol table: B=1000 ETH,
r=1 ETH/s, T=5000 ETH, W=3600 s). Post-A1 the CCTX data is scored in the upstream
common-denomination ``value_usd`` column (the raw ``value`` column is token base units
with mixed decimals and is NOT cross-token comparable). We therefore scale the ledger
to USD with a single incident-era conversion rate:

    USD_PER_ETH = 3110.0

Source: the dataset's OWN valuation of the main Ronin drain row, 173,600 ETH valued
at $539,884,300 by XChainWatcher (test.parquet, label=incident:ronin), i.e.
$3,109.9/ETH, consistent with the 2022-03-23 market price (CoinGecko daily close
≈ $3.0–3.1k). Using the dataset's internal rate keeps the drain row and the ledger on
the same scale by construction. SENSITIVITY: the locked-params headline is re-computed
at $2,500 and $3,500 per ETH; the qualitative result is insensitive to the choice
because the dominant utility cost comes from benign whales 100×+ above B.
(Option (b), replaying only ETH-native rows in ETH, is NOT implementable from the
canonical schema: there is no token column, so ETH-native rows cannot be identified
without re-deriving upstream valuations. The price sensitivity covers the same
robustness concern.)

FAITHFUL CONTRACT SEMANTICS mirrored here (contracts/RateLimiter.sol,
contracts/CircuitBreaker.sol, contracts/BridgeV2.sol; commit-not-revert):

* RateLimiter: bucket starts FULL at B; refills continuously at r, clamped at B;
  ``consume`` reverts (no debit) if the bucket cannot cover the amount.
* CircuitBreaker: fixed 61-slot time-bucket accumulator, bucket width = W/60; the
  summed span [t-(W+width), t] OVER-approximates the exact sliding window by ≤ one
  width (conservative: can only trip earlier). A FRESH breach (window total + amount
  > T) LATCHES ``tripped`` and blocks the transfer WITHOUT reverting: the nonce stays
  burned and, crucially for benign users, the BUCKET STAYS DEBITED (BridgeV2.sol
  consume-then-checkAndRecord order; the liveness cost named in the critique's B8).
  While latched, every withdrawal reverts until governance ``reset()``, which clears
  BOTH the latch and the window.

REPLAY / DELAY MODEL (stated assumptions):
* Transfers are replayed in timestamp order at their real arrival times (integer
  Unix seconds, matching the contracts' integer-second arithmetic).
* A transfer the limiter cannot yet cover RETRIES until the bucket refills; users
  queue FIFO behind earlier waiting transfers (the bucket is a shared resource; FIFO
  is the simple deterministic contention model and is conservative for aggregate
  delay). delay = service_time − arrival_time.
* A transfer larger than B can NEVER be admitted (the bucket clamps at B) → counted
  as DENIED outright; no state is touched (consume reverts atomically).
* A transfer larger than T always breaches an empty window → DENIED at the breaker;
  it burns bucket tokens and latches a halt (only possible when T < B; the swept grid
  keeps T ≥ B so this is a guard, not a path the locked ledger exercises).
* RESET ASSUMPTION: after a benign-traffic latch, governance resets the breaker
  RESET_DELAY = 3600 s (one window W) later, an optimistic operational response;
  every transfer arriving while latched waits for the reset. Each latch is counted
  as one benign-triggered HALT.

Deterministic: pure replay of the committed parquets; no randomness, no wall-clock.
Self-logs to docs/logs/scenario_8_benign_utility.log and writes
figures/benign_utility_pareto.png. Node-less (offline). Exits non-zero on internal
consistency violations (accounting identity: every transfer is served or denied).

Academic framing: a design specification, not a tested production system.
"""
from __future__ import annotations

import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Ensure project root is on sys.path when run as a script.
sys.path.insert(0, str(Path(__file__).parent.parent))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants (all documented in the module docstring).
# ---------------------------------------------------------------------------
USD_PER_ETH = 3110.0          # dataset-internal Ronin-row valuation ($539.88M / 173,600 ETH)
USD_PER_ETH_SENSITIVITY = (2500.0, 3110.0, 3500.0)
DELTA = 60.0                  # composed response latency Δ [s] (docs/bolt/deployment.md)
RESET_DELAY = 3600.0          # governance reset latency after a benign latch [s] (= W)
RONIN_DRAIN_USD = 539_884_300.0  # 173,600 ETH at the dataset's own valuation

DATA_DIR = Path("data/cctx")
TRAIN_PARQUET = DATA_DIR / "train.parquet"
TEST_PARQUET = DATA_DIR / "test.parquet"
LOG_PATH = Path("docs/logs/scenario_8_benign_utility.log")
FIG_PATH = Path("figures/benign_utility_pareto.png")


@dataclass(frozen=True)
class LedgerETH:
    """One (B, r, T, W) instantiation in ETH (theorem.md symbol table)."""

    name: str
    B: float   # bucket capacity [ETH]
    r: float   # refill rate [ETH/s]
    T: float   # breaker window threshold [ETH]
    W: float = 3600.0  # window length [s]

    def usd(self, usd_per_eth: float = USD_PER_ETH) -> "LedgerUSD":
        return LedgerUSD(
            name=self.name,
            B=self.B * usd_per_eth,
            r=self.r * usd_per_eth,
            T=self.T * usd_per_eth,
            W=self.W,
        )

    def bound_usd(self, delta: float = DELTA, usd_per_eth: float = USD_PER_ETH) -> float:
        """Limiter-only reference level T + r·Delta, in USD.

        SUPERSEDED -- DO NOT READ AS A BOUND.  T + r*Delta was refuted as an upper
        bound on per-window extraction (main.tex Sect. 4.2 / Appendix A): the
        trailing window slides, so outflow admitted early retires from it and the
        freed headroom re-opens.  The proved envelope is B + r*(t_trip + Delta),
        maximised at B + r*(W + Delta).  This function is retained ONLY so the
        published Pareto figure remains reproducible bit-for-bit; the frontier it
        ranks is therefore ordered by a superseded quantity.  Re-deriving the sweep
        against the envelope is tracked as J15 in journal/REMEDIATION_TASKLIST.md
        and must land before submission -- note that T drops out of the envelope
        entirely, so configurations differing only in T collapse to one point, and
        configurations with B + r*W < T cannot trip the breaker at all.
        """
        return (self.T + self.r * delta) * usd_per_eth

    def envelope_eth(self, delta: float = DELTA) -> float:
        """Proved worst-case per-window extraction envelope B + r*(W + Delta), in ETH.

        This is Theorem 1 of the manuscript (main.tex, Appendix A) evaluated at the
        maximising trip time.  The general form is B + r*(t_trip + Delta) for a
        monitor signal at t_trip; the trailing-window constraint admits t_trip up to
        W, and the envelope is increasing in t_trip, so the worst case is t_trip = W.
        (Note W, not W - Delta: the constraint binds on when the monitor may signal,
        not on when the pause lands.)

        The breaker threshold T does not appear.  V(t) <= T constrains the TRAILING
        WINDOW, not cumulative extraction, and the two coincide only while t <= W;
        past that, outflow retires from the window and its headroom re-opens.  A
        configuration with B + r*W <= T can never trip the value breaker on any
        schedule, so for those configurations T is inert by construction.
        """
        return self.B + self.r * (self.W + delta)

    def envelope_usd(self, delta: float = DELTA, usd_per_eth: float = USD_PER_ETH) -> float:
        """`envelope_eth` denominated in USD at the stated conversion rate."""
        return self.envelope_eth(delta) * usd_per_eth


@dataclass(frozen=True)
class LedgerUSD:
    name: str
    B: float
    r: float
    T: float
    W: float


LOCKED = LedgerETH("locked", B=1000.0, r=1.0, T=5000.0, W=3600.0)
ALT_TRIP = LedgerETH("alt-trip", B=1000.0, r=1.0, T=4000.0, W=3600.0)


# ---------------------------------------------------------------------------
# Faithful simulator core (unit-tested against contract semantics in
# tests/monitor/test_scenario_8.py).
# ---------------------------------------------------------------------------
class TokenBucketSim:
    """Mirror of contracts/RateLimiter.sol: capacity B, continuous refill r,
    starts FULL; ``consume`` fails atomically (no debit) when short."""

    def __init__(self, capacity: float, rate: float, t0: float) -> None:
        self.capacity = capacity
        self.rate = rate
        self.tokens = capacity  # starts full (constructor: _tokens = _capacity)
        self.last = t0

    def available(self, now: float) -> float:
        """View of the bucket reconciled to `now`, clamped at capacity."""
        return min(self.capacity, self.tokens + (now - self.last) * self.rate)

    def consume(self, amount: float, now: float) -> bool:
        """True if admitted (bucket debited); False = revert (NO debit)."""
        refilled = self.available(now)
        if amount <= refilled * (1 + 1e-12) + 1e-9:
            self.tokens = refilled - amount
            self.last = now
            return True
        # revert: roll back everything, including the refill bookkeeping write
        # (a reverted contract call leaves no state change; recomputing the refill
        # from the old (tokens, last) later is arithmetically identical).
        return False


class BucketedBreakerSim:
    """Mirror of contracts/CircuitBreaker.sol: 61-slot bucketed sliding window.

    Slot arithmetic is INTEGER (epoch = now // bucket_width), exactly as on-chain;
    the summed span [t-(W+width), t] over-approximates the exact window by at most
    one bucket width (conservative: trips no later than the exact-window version).
    """

    WINDOW_BUCKETS = 60
    BUCKET_COUNT = WINDOW_BUCKETS + 1  # 61 slots

    def __init__(self, threshold: float, window: float) -> None:
        if int(window) % self.WINDOW_BUCKETS != 0:
            raise ValueError("breaker: W not bucket-divisible")  # constructor require
        self.threshold = threshold
        self.window = window
        self.bucket_width = int(window) // self.WINDOW_BUCKETS
        self.tripped = False
        self._bucket_total = [0.0] * self.BUCKET_COUNT
        self._bucket_epoch = [0] * self.BUCKET_COUNT

    def window_outflow(self, now: float) -> float:
        epoch = int(now) // self.bucket_width
        oldest = epoch - self.WINDOW_BUCKETS if epoch >= self.WINDOW_BUCKETS else 0
        return sum(
            self._bucket_total[i]
            for i in range(self.BUCKET_COUNT)
            if oldest <= self._bucket_epoch[i] <= epoch
        )

    def _record_outflow(self, amount: float, now: float) -> None:
        epoch = int(now) // self.bucket_width
        idx = epoch % self.BUCKET_COUNT
        if self._bucket_epoch[idx] != epoch:
            self._bucket_total[idx] = 0.0  # lazily reclaim the stale slot
            self._bucket_epoch[idx] = epoch
        self._bucket_total[idx] += amount

    def check_and_record(self, amount: float, now: float) -> str:
        """Contract's three outcomes:
        - "tripped": already latched; the call reverts (nothing recorded).
        - "breach":  FRESH breach; latches tripped=True, transfer blocked, but the
                     tx COMMITS (nonce burned, bucket debited by the caller).
        - "ok":      recorded; value moves.
        """
        if self.tripped:
            return "tripped"
        new_total = self.window_outflow(now) + amount
        if new_total > self.threshold:
            self.tripped = True
            return "breach"
        self._record_outflow(amount, now)
        return "ok"

    def reset(self) -> None:
        """Governance reset: clears the latch AND the whole window (contract :157-165)."""
        self.tripped = False
        self._bucket_total = [0.0] * self.BUCKET_COUNT
        self._bucket_epoch = [0] * self.BUCKET_COUNT


# ---------------------------------------------------------------------------
# Benign replay.
# ---------------------------------------------------------------------------
@dataclass
class TransferOutcome:
    arrival: float
    amount: float           # USD
    served: bool
    delay: float = 0.0      # seconds (0 for denied rows; excluded from delay stats)
    deny_reason: str = ""   # "exceeds_bucket_capacity_B" | "exceeds_window_threshold_T"


@dataclass
class ReplayResult:
    outcomes: list[TransferOutcome]
    halts: int                      # benign-triggered breaker latches
    halt_times: list[float] = field(default_factory=list)

    # -- aggregate metrics ---------------------------------------------------
    @property
    def total_value(self) -> float:
        return sum(o.amount for o in self.outcomes)

    @property
    def denied(self) -> list[TransferOutcome]:
        return [o for o in self.outcomes if not o.served]

    @property
    def delayed(self) -> list[TransferOutcome]:
        return [o for o in self.outcomes if o.served and o.delay > 0]

    @property
    def denied_value(self) -> float:
        return sum(o.amount for o in self.denied)

    @property
    def delayed_value(self) -> float:
        return sum(o.amount for o in self.delayed)

    @property
    def denied_or_delayed_value_frac(self) -> float:
        tv = self.total_value
        return (self.denied_value + self.delayed_value) / tv if tv > 0 else 0.0

    def delay_percentiles(self) -> dict[str, float]:
        """P50/P95/P99/max of per-transfer delay over ALL SERVED transfers."""
        d = np.array([o.delay for o in self.outcomes if o.served], dtype=float)
        if len(d) == 0:
            return {"p50": math.nan, "p95": math.nan, "p99": math.nan, "max": math.nan}
        return {
            "p50": float(np.percentile(d, 50)),
            "p95": float(np.percentile(d, 95)),
            "p99": float(np.percentile(d, 99)),
            "max": float(d.max()),
        }

    def largest_zero_delay(self) -> float:
        served_instant = [o.amount for o in self.outcomes if o.served and o.delay == 0]
        return max(served_instant) if served_instant else 0.0


def replay_benign_stream(
    arrivals: np.ndarray,
    amounts: np.ndarray,
    ledger: LedgerUSD,
    reset_delay: float = RESET_DELAY,
) -> ReplayResult:
    """Replay the benign stream through the faithful bucket+breaker models.

    `arrivals` are integer Unix seconds (sorted ascending); `amounts` are USD.
    See the module docstring for the FIFO / retry / reset assumptions.
    """
    assert len(arrivals) == len(amounts)
    t0 = float(arrivals[0]) if len(arrivals) else 0.0
    bucket = TokenBucketSim(ledger.B, ledger.r, t0)
    breaker = BucketedBreakerSim(ledger.T, ledger.W)

    outcomes: list[TransferOutcome] = []
    halts = 0
    halt_times: list[float] = []
    reset_at = -math.inf   # scheduled governance reset time (if latched)
    t_free = t0            # FIFO: earliest service time for the next transfer

    for arrival, amount in zip(arrivals, amounts):
        arrival = float(arrival)
        amount = float(amount)

        # Structurally inadmissible at the limiter: the bucket clamps at B, so no
        # amount of waiting ever admits a transfer > B. consume() reverts atomically
        # -> denied, no state touched, no halt.
        if amount > ledger.B * (1 + 1e-12):
            outcomes.append(TransferOutcome(arrival, amount, served=False,
                                            deny_reason="exceeds_bucket_capacity_B"))
            continue

        t = max(arrival, t_free)
        served = False
        for _attempt in range(3):  # ≤1 benign breach retry is possible; 3 is a guard
            # If latched, wait for the scheduled governance reset (clears latch+window).
            if breaker.tripped:
                t = max(t, reset_at)
                breaker.reset()

            # Wait for the shared bucket to cover the amount (integer-second ceil,
            # matching the contracts' integer timestamp arithmetic).
            avail = bucket.available(t)
            if amount > avail:
                t += math.ceil((amount - avail) / ledger.r)
            admitted = bucket.consume(amount, t)
            assert admitted, "internal: bucket must admit after the computed wait"

            outcome = breaker.check_and_record(amount, t)
            if outcome == "ok":
                served = True
                break
            if outcome == "breach":
                # Benign-triggered HALT: latch until governance reset. The tx COMMITS:
                # the bucket debit above STANDS (BridgeV2 consume-then-check order,
                # the liveness cost of a blocked withdrawal). The transfer retries
                # after the reset.
                halts += 1
                halt_times.append(t)
                reset_at = t + reset_delay
                if amount > ledger.T * (1 + 1e-12):
                    # Breaches even an empty window -> permanently inadmissible.
                    outcomes.append(TransferOutcome(
                        arrival, amount, served=False,
                        deny_reason="exceeds_window_threshold_T"))
                    break
                continue
            raise AssertionError("unreachable: latch handled before the attempt")

        if served:
            outcomes.append(TransferOutcome(arrival, amount, served=True,
                                            delay=t - arrival))
        t_free = t

    # Accounting identity: every transfer is exactly one outcome.
    assert len(outcomes) == len(arrivals), "internal: transfer lost in replay"
    return ReplayResult(outcomes=outcomes, halts=halts, halt_times=halt_times)


# ---------------------------------------------------------------------------
# Data loading.
# ---------------------------------------------------------------------------
def load_benign_stream() -> tuple[np.ndarray, np.ndarray]:
    """The FULL real benign CCTX stream (train + test benign rows), time-sorted.

    Returns (arrivals [int Unix seconds], amounts [USD]).
    """
    frames = []
    for p in (TRAIN_PARQUET, TEST_PARQUET):
        if not p.exists():
            raise FileNotFoundError(
                f"{p} not found — run `make data` first (data/ is gitignored)")
        df = pd.read_parquet(p, columns=["timestamp", "value_usd", "label"])
        frames.append(df[df["label"] == "benign"])
    b = pd.concat(frames).dropna(subset=["timestamp", "value_usd"])
    b = b[b["value_usd"] > 0].sort_values("timestamp")
    # Unit-safe epoch-seconds conversion (the column is datetime64[ms, UTC]; a raw
    # astype(int64) would yield MILLISECONDS and compress the stream 1000x).
    arrivals = (b["timestamp"].dt.as_unit("s").astype("int64")).to_numpy()
    amounts = b["value_usd"].to_numpy(dtype=float)
    return arrivals, amounts


# ---------------------------------------------------------------------------
# Pareto sweep + scaling rule.
# ---------------------------------------------------------------------------
@dataclass
class ParetoPoint:
    ledger: LedgerETH
    denial_delay_value_frac: float   # x: fraction of benign VALUE denied-or-delayed
    bound_usd: float                 # superseded ordinate: T + r·Δ  [USD] (retained)
    envelope_usd: float              # y: proved envelope B + r·(W + Δ)  [USD]
    denied_value_frac: float
    halts: int
    p99_delay: float
    dominated: bool = False          # domination under the PROVED envelope
    dominated_superseded: bool = False   # domination under T + r·Δ, for the delta report


def sweep_grid() -> list[LedgerETH]:
    """B/r/T grid (ETH). W is fixed at 3600 s (the breaker's slot geometry is locked).

    Constraint T ≥ B: a config with T < B lets a single admitted burst latch the
    breaker on benign traffic by construction; excluded as operationally incoherent.
    Grid anchors: B spans the LOCKED 1,000 ETH up to ~1.2× the largest benign whale
    (127,366 ETH = $396.1M / $3,110); r spans 1–100 ETH/s; T spans LOCKED 5,000 ETH
    up to 200,000 ETH (bound $622M ≈ 1.15× the Ronin drain).
    """
    B_grid = [1_000.0, 5_000.0, 20_000.0, 100_000.0, 150_000.0]
    r_grid = [1.0, 10.0, 100.0]
    T_grid = [5_000.0, 20_000.0, 100_000.0, 200_000.0]
    grid = [
        LedgerETH(f"B{int(B)}_r{int(r)}_T{int(T)}", B=B, r=r, T=T)
        for B in B_grid for r in r_grid for T in T_grid
        if T >= B
    ]
    return grid


def mark_pareto(points: list[ParetoPoint]) -> None:
    """Mark dominated points (another point is ≤ on BOTH axes and < on one).

    Marks BOTH orderings: `dominated` under the proved envelope B + r(W + Δ), which is
    what the figure and the paper now use, and `dominated_superseded` under the refuted
    T + r·Δ, kept only so the log can print the membership delta between them (J15).

    Exactly-coincident points do not dominate one another, so a group of configurations
    that collapse onto the same (x, y) under the envelope are all reported as frontier
    members. That is a faithful consequence of T dropping out, not a bug; the log
    separates config count from distinct-location count.
    """
    for p in points:
        p.dominated = any(
            (q.denial_delay_value_frac <= p.denial_delay_value_frac
             and q.envelope_usd <= p.envelope_usd
             and (q.denial_delay_value_frac < p.denial_delay_value_frac
                  or q.envelope_usd < p.envelope_usd))
            for q in points
        )
        p.dominated_superseded = any(
            (q.denial_delay_value_frac <= p.denial_delay_value_frac
             and q.bound_usd <= p.bound_usd
             and (q.denial_delay_value_frac < p.denial_delay_value_frac
                  or q.bound_usd < p.bound_usd))
            for q in points
        )


def stream_stats(arrivals: np.ndarray, amounts: np.ndarray) -> dict[str, float]:
    """Descriptive statistics of the benign stream that anchor the scaling rule."""
    ts = pd.to_datetime(arrivals, unit="s", utc=True)
    hourly = pd.Series(amounts, index=ts).resample("1h").sum()
    return {
        "n": float(len(amounts)),
        "total_usd": float(amounts.sum()),
        "xfer_p50": float(np.percentile(amounts, 50)),
        "xfer_p99": float(np.percentile(amounts, 99)),
        "xfer_p999": float(np.percentile(amounts, 99.9)),
        "xfer_max": float(amounts.max()),
        "hourly_mean": float(hourly.mean()),
        "hourly_p99": float(hourly.quantile(0.99)),
        "hourly_max": float(hourly.max()),
    }


def value_coverage_table(amounts: np.ndarray,
                         coverages: tuple[float, ...] = (0.5, 0.6, 0.75, 0.9, 0.99),
                         ) -> list[tuple[float, float]]:
    """For each target VALUE coverage c: the smallest bucket capacity B (USD) such
    that transfers of size ≤ B carry ≥ c of total benign value.

    This is the operator's REAL knob on a whale-dominated stream: count-quantiles of
    transfer size (p99.9 etc.) barely move the denied VALUE share, because value
    concentrates in a few huge transfers, so B must be chosen against the
    value-weighted size distribution, and the frontier prices that choice in bound.
    """
    sorted_amounts = np.sort(amounts)
    cum_value = np.cumsum(sorted_amounts)
    total = cum_value[-1]
    out = []
    for c in coverages:
        idx = int(np.searchsorted(cum_value, c * total, side="left"))
        idx = min(idx, len(sorted_amounts) - 1)
        out.append((c, float(sorted_amounts[idx])))
    return out


def scaling_rule_ledger(stats: dict[str, float], usd_per_eth: float = USD_PER_ETH,
                        q_admit: float = 0.999, t_mult: float = 3.0) -> LedgerETH:
    """PARAMETER-SCALING RULE derived from the observed benign stream, the answer to
    "how would a real bridge choose B/r/T":

      B = q-th percentile of single benign transfer size (q_admit = 99.9% here):
          every transfer up to the q-quantile is admissible without structural denial;
          the operator's residual whale tail (1-q of transfers) is the utility price.
      T = max(B, t_mult × p99 hourly benign volume): the window cap sits a small
          multiple above the heaviest observed benign hour, so cumulative benign
          traffic cannot approach a value trip (t_mult = 3 here).
      r = T / W: a full threshold-T window is sustainable at steady state, so the
          refill rate never binds before the window cap does.

    All three anchors are percentiles of OBSERVED benign traffic: an operator recomputes
    them from their own history; nothing is tuned on attack data.
    """
    B_usd = stats["xfer_p999"] * (1 / q_admit)  # tiny headroom above the exact quantile
    T_usd = max(B_usd, t_mult * stats["hourly_p99"])
    W = 3600.0
    r_usd = T_usd / W
    return LedgerETH("rule-derived", B=B_usd / usd_per_eth, r=r_usd / usd_per_eth,
                     T=T_usd / usd_per_eth, W=W)


# ---------------------------------------------------------------------------
# Outputs.
# ---------------------------------------------------------------------------
def _fmt_usd(x: float) -> str:
    if x >= 1e9:
        return f"${x / 1e9:,.2f}B"
    if x >= 1e6:
        return f"${x / 1e6:,.2f}M"
    return f"${x:,.0f}"


def _locked_section(name: str, res: ReplayResult, ledger: LedgerETH,
                    usd_per_eth: float) -> list[str]:
    pct = res.delay_percentiles()
    lu = ledger.usd(usd_per_eth)
    served = [o for o in res.outcomes if o.served]
    lines = [
        f"## ledger[{name}] — B={ledger.B:g} ETH ({_fmt_usd(lu.B)}), r={ledger.r:g} ETH/s "
        f"({_fmt_usd(lu.r)}/s), T={ledger.T:g} ETH ({_fmt_usd(lu.T)}), W={ledger.W:g} s "
        f"@ ${usd_per_eth:,.0f}/ETH",
        f"  transfers: {len(res.outcomes)}  served: {len(served)}  denied: {len(res.denied)}"
        f" ({len(res.denied) / len(res.outcomes) * 100:.3f}% of count)",
        f"  benign VALUE denied:            {_fmt_usd(res.denied_value)}"
        f"  ({res.denied_value / res.total_value * 100:.2f}% of {_fmt_usd(res.total_value)})",
        f"  benign VALUE delayed (>0 s):    {_fmt_usd(res.delayed_value)}"
        f"  ({res.delayed_value / res.total_value * 100:.2f}%)",
        f"  benign VALUE denied-or-delayed: {res.denied_or_delayed_value_frac * 100:.2f}%",
        f"  delay over served transfers: P50={pct['p50']:.0f}s  P95={pct['p95']:.0f}s  "
        f"P99={pct['p99']:.0f}s  max={pct['max']:.0f}s",
        f"  benign-triggered breaker halts: {res.halts}"
        + ("  (value trip structurally unreachable: B + r·W ≤ T)"
           if ledger.B + ledger.r * ledger.W <= ledger.T else ""),
        f"  largest transfer served with ZERO delay: {_fmt_usd(res.largest_zero_delay())}"
        f"  (theoretical instant-admission cap = B = {_fmt_usd(lu.B)})",
        f"  PROVED extraction envelope B + r·(W + Δ): "
        f"{_fmt_usd(ledger.envelope_usd(DELTA, usd_per_eth))}"
        f"  ({ledger.envelope_usd(DELTA, usd_per_eth) / RONIN_DRAIN_USD * 100:.1f}% of the "
        f"Ronin drain {_fmt_usd(RONIN_DRAIN_USD)})  [Theorem 1]",
        f"  superseded limiter-only level T + r·Δ: "
        f"{_fmt_usd(ledger.bound_usd(DELTA, usd_per_eth))}"
        f"  ({ledger.bound_usd(DELTA, usd_per_eth) / RONIN_DRAIN_USD * 100:.1f}% of Ronin)"
        f"  — NOT a bound; retained for continuity only",
    ]
    return lines


def _write_figure(points: list[ParetoPoint], locked_pt: ParetoPoint,
                  rule_pt: ParetoPoint) -> None:
    FIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(9, 6))

    dominated = [p for p in points if p.dominated]
    # Once T leaves the ordinate, configurations differing only in T land on the same
    # point. Draw the polyline through DISTINCT frontier locations (J15).
    frontier_all = sorted((p for p in points if not p.dominated),
                          key=lambda p: p.denial_delay_value_frac)
    frontier: list[ParetoPoint] = []
    for _p in frontier_all:
        if not any(abs(q.denial_delay_value_frac - _p.denial_delay_value_frac) < 1e-12
                   and abs(q.envelope_usd - _p.envelope_usd) < 1e-6 for q in frontier):
            frontier.append(_p)

    ax.scatter([p.denial_delay_value_frac * 100 for p in dominated],
               [p.envelope_usd for p in dominated],
               color="lightgray", s=30, alpha=0.8, label="dominated configs", zorder=2)
    ax.plot([p.denial_delay_value_frac * 100 for p in frontier],
            [p.envelope_usd for p in frontier],
            "o-", color="tab:blue", linewidth=2, markersize=6,
            label="Pareto frontier", zorder=3)

    ax.scatter([locked_pt.denial_delay_value_frac * 100], [locked_pt.envelope_usd],
               marker="*", s=350, color="crimson", zorder=5,
               label=f"LOCKED ledger (B=1000, r=1, T=5000 ETH)")
    ax.scatter([rule_pt.denial_delay_value_frac * 100], [rule_pt.envelope_usd],
               marker="D", s=120, color="tab:green", zorder=5,
               label="rule-derived (B=p99.9 xfer, T=3×p99 hourly, r=T/W)")

    ax.axhline(RONIN_DRAIN_USD, color="gray", linestyle=":", linewidth=1.2,
               label=f"Ronin drain ({_fmt_usd(RONIN_DRAIN_USD)})")
    ax.set_xlabel("benign VALUE denied or delayed (%) — real CCTX stream, 82k transfers")
    ax.set_ylabel("proved extraction envelope  B + r(W + \u0394)  (USD, \u0394 = 60 s)\n"
                  "Theorem 1 \u2014 independent of the breaker threshold T")
    ax.set_yscale("log")
    # title supplied by the LaTeX caption; no embedded title
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(loc="lower left", fontsize=8)
    plt.tight_layout()
    plt.savefig(FIG_PATH, dpi=300)
    plt.close(fig)
    print(f"Figure saved: {FIG_PATH}")


# ---------------------------------------------------------------------------
# J15 reporting: envelope collapse, frontier membership delta, claim re-check.
# Factored out of main() so scenarios/rederive_j15_frontier.py reuses exactly this
# code rather than a second implementation of it.
# ---------------------------------------------------------------------------
def sweep_report_lines(points: list[ParetoPoint], n_grid: int) -> list[str]:
    """Log lines for the envelope-ranked sweep. `points` must already be marked."""
    lines: list[str] = []
    env_groups: dict[float, list[ParetoPoint]] = {}
    for p in points:
        env_groups.setdefault(round(p.envelope_usd, 6), []).append(p)
    collapsed = {k: v for k, v in env_groups.items() if len(v) > 1}
    front_env = {(p.ledger.B, p.ledger.r, p.ledger.T) for p in points if not p.dominated}
    front_sup = {(p.ledger.B, p.ledger.r, p.ledger.T)
                 for p in points if not p.dominated_superseded}
    gained = sorted(front_env - front_sup)
    lost = sorted(front_sup - front_env)
    distinct_locs = {(round(p.denial_delay_value_frac, 12), round(p.envelope_usd, 6))
                     for p in points if not p.dominated}

    lines += [
        "## Pareto sweep (x = benign value denied-or-delayed, "
        "y = PROVED envelope B + r·(W + Δ), Δ=60 s)",
        "#  J15: ranked by the proved envelope. T does not appear in it, so configs",
        "#  differing only in T share an ordinate. The superseded T + r·Δ column is kept",
        "#  alongside for continuity; it is NOT a bound (main.tex Sect. 4.2 / Appendix A).",
        f"  grid: {n_grid} configs (B x r x T, T >= B, W=3600 s fixed)",
        f"  envelope collapse: {n_grid} configs -> {len(env_groups)} distinct envelope "
        f"values; {len(collapsed)} values are shared by >1 config "
        f"({sum(len(v) for v in collapsed.values())} configs affected)",
        "  B(ETH)     r(ETH/s)  T(ETH)     envelope(USD)   [T+r·Δ]        denied%val  "
        "den-or-del%val  halts  p99delay(s)  pareto",
    ]
    for p in sorted(points, key=lambda q: (q.envelope_usd, q.denial_delay_value_frac)):
        lines.append(
            f"  {p.ledger.B:9.0f} {p.ledger.r:8.0f} {p.ledger.T:9.0f}  "
            f"{_fmt_usd(p.envelope_usd):>14s}  {_fmt_usd(p.bound_usd):>12s}  "
            f"{p.denied_value_frac * 100:9.2f}  "
            f"{p.denial_delay_value_frac * 100:13.2f}  {p.halts:5d}  {p.p99_delay:10.0f}"
            f"  {'FRONTIER' if not p.dominated else '-'}"
        )
    lines += [
        "#",
        "## frontier membership delta (proved envelope vs superseded T + r·Δ)",
        f"  frontier under the envelope:      {len(front_env)} configs at "
        f"{len(distinct_locs)} distinct (x, y) locations",
        f"  frontier under T + r·Δ (superseded): {len(front_sup)} configs",
        f"  ENTERED the frontier: {len(gained)}"
        + ("".join(f"\n    + B={b:,.0f} r={r:,.0f} T={t:,.0f}" for b, r, t in gained)
           if gained else "  (none)"),
        f"  LEFT the frontier:    {len(lost)}"
        + ("".join(f"\n    - B={b:,.0f} r={r:,.0f} T={t:,.0f}" for b, r, t in lost)
           if lost else "  (none)"),
    ]
    sub_ronin_single_digit = sorted(
        ((p.ledger.B, p.ledger.r, p.ledger.T, p.envelope_usd,
          p.denial_delay_value_frac) for p in points
         if p.envelope_usd < RONIN_DRAIN_USD and p.denial_delay_value_frac < 0.10),
        key=lambda q: q[3])
    n_sup = sum(1 for p in points
                if p.bound_usd < RONIN_DRAIN_USD and p.denial_delay_value_frac < 0.10)
    lines += [
        "#",
        "## claim re-check: is there a config with a sub-Ronin envelope AND single-digit denial?",
        f"  under the superseded T + r·Δ ordinate: {n_sup} config(s) qualified",
    ]
    if sub_ronin_single_digit:
        lines.append(
            f"  YES — {len(sub_ronin_single_digit)} config(s) qualify under the proved "
            "envelope; any claim written against the superseded ranking must be re-stated:")
        for b, r, t, env, x in sub_ronin_single_digit:
            lines.append(
                f"    B={b:,.0f} r={r:,.0f} T={t:,.0f}  envelope {_fmt_usd(env)} "
                f"({env / RONIN_DRAIN_USD * 100:.1f}% of Ronin)  "
                f"denied-or-delayed {x * 100:.2f}%")
    else:
        lines.append("  NO — the claim survives re-derivation against the proved envelope.")
    return lines


def main() -> int:
    arrivals, amounts = load_benign_stream()
    stats = stream_stats(arrivals, amounts)

    lines: list[str] = [
        "# BOLT Phase 22 B1 — benign-utility experiment + Pareto frontier (scenario_8)",
        "# mode: offline replay of the REAL benign CCTX stream (XChainWatcher) through",
        "# faithful Python models of RateLimiter (token bucket) + CircuitBreaker (61-slot",
        "# bucketed window, latch-until-reset). Deterministic; node-less.",
        f"# denomination: ledger ETH params scaled to USD at ${USD_PER_ETH:,.0f}/ETH — the",
        "# dataset's OWN Ronin-row valuation ($539,884,300 / 173,600 ETH); sensitivity at",
        f"# ${USD_PER_ETH_SENSITIVITY[0]:,.0f} and ${USD_PER_ETH_SENSITIVITY[-1]:,.0f} below.",
        f"# reset assumption: governance resets a benign latch after {RESET_DELAY:g} s (= W).",
        f"# delay model: FIFO retry-until-admitted; delay = service - arrival.",
        "#",
        "## benign stream",
        f"  transfers: {stats['n']:.0f}  total value: {_fmt_usd(stats['total_usd'])}",
        f"  single-transfer size: p50={_fmt_usd(stats['xfer_p50'])}  "
        f"p99={_fmt_usd(stats['xfer_p99'])}  p99.9={_fmt_usd(stats['xfer_p999'])}  "
        f"max={_fmt_usd(stats['xfer_max'])}",
        f"  hourly volume: mean={_fmt_usd(stats['hourly_mean'])}  "
        f"p99={_fmt_usd(stats['hourly_p99'])}  max={_fmt_usd(stats['hourly_max'])}",
        "#",
        "## locked-params results",
    ]

    # --- locked params (primary) + ALT_TRIP + price sensitivity -------------
    locked_res: dict[float, ReplayResult] = {}
    for price in USD_PER_ETH_SENSITIVITY:
        res = replay_benign_stream(arrivals, amounts, LOCKED.usd(price))
        locked_res[price] = res
        lines += _locked_section(LOCKED.name, res, LOCKED, price)
        lines.append("")
    alt_res = replay_benign_stream(arrivals, amounts, ALT_TRIP.usd(USD_PER_ETH))
    lines += _locked_section(ALT_TRIP.name, alt_res, ALT_TRIP, USD_PER_ETH)
    lines.append("")

    # --- Pareto sweep --------------------------------------------------------
    def point_for(ledger: LedgerETH) -> ParetoPoint:
        res = replay_benign_stream(arrivals, amounts, ledger.usd(USD_PER_ETH))
        return ParetoPoint(
            ledger=ledger,
            denial_delay_value_frac=res.denied_or_delayed_value_frac,
            bound_usd=ledger.bound_usd(),
            envelope_usd=ledger.envelope_usd(),
            denied_value_frac=res.denied_value / res.total_value,
            halts=res.halts,
            p99_delay=res.delay_percentiles()["p99"],
        )

    grid = sweep_grid()
    points = [point_for(led) for led in grid]
    mark_pareto(points)

    rule_ledger = scaling_rule_ledger(stats)
    rule_pt = point_for(rule_ledger)
    locked_pt = next(
        p for p in points
        if (p.ledger.B, p.ledger.r, p.ledger.T) == (LOCKED.B, LOCKED.r, LOCKED.T)
    )

    lines += sweep_report_lines(points, len(grid))
    lines += [
        "#",
        "## parameter-scaling rule (derived from the observed benign stream)",
        "  B = p99.9 of single benign transfer size; T = max(B, 3 x p99 hourly volume);",
        "  r = T / W  (a full-T window sustainable at steady state).",
        f"  rule-derived ledger: B={rule_ledger.B:,.0f} ETH ({_fmt_usd(rule_ledger.B * USD_PER_ETH)}), "
        f"r={rule_ledger.r:,.2f} ETH/s, T={rule_ledger.T:,.0f} ETH "
        f"({_fmt_usd(rule_ledger.T * USD_PER_ETH)})",
        f"  -> envelope {_fmt_usd(rule_pt.envelope_usd)} "
        f"({rule_pt.envelope_usd / RONIN_DRAIN_USD * 100:.1f}% of Ronin), "
        f"denied-or-delayed {rule_pt.denial_delay_value_frac * 100:.2f}% of benign value, "
        f"halts {rule_pt.halts}"
        f"   [superseded T + r·Δ: {_fmt_usd(rule_pt.bound_usd)}]",
        "#",
        "## value-coverage table (the operator's real knob on a whale-dominated stream)",
        "  smallest B admitting >= c of benign VALUE burst-free (count-quantiles of size",
        "  barely move denied VALUE, because value concentrates in a few whales):",
    ]
    for c, b_usd in value_coverage_table(amounts):
        b_eth = b_usd / USD_PER_ETH
        # Envelope floor implied by that B at the locked refill rate r = 1 ETH/s:
        # B + r*(W + Delta). T plays no part (J15).
        implied_env = (max(b_eth, 0.0) + 1.0 * (3600.0 + DELTA)) * USD_PER_ETH
        lines.append(
            f"    coverage {c * 100:5.1f}%  ->  B >= {_fmt_usd(b_usd)} ({b_eth:,.0f} ETH)"
            f"  ->  envelope floor B + r·(W + Δ) >= {_fmt_usd(implied_env)}"
            f"  ({implied_env / RONIN_DRAIN_USD * 100:.1f}% of Ronin)"
        )
    lines += [
        "#",
        "## honest summary",
        f"  LOCKED ledger: envelope {_fmt_usd(locked_pt.envelope_usd)} "
        f"({locked_pt.envelope_usd / RONIN_DRAIN_USD * 100:.1f}% of Ronin) is purchased at "
        f"{locked_pt.denial_delay_value_frac * 100:.2f}% of benign VALUE denied-or-delayed",
        "  — benign whale transfers far above B dominate the utility cost (largest benign",
        f"  transfer {_fmt_usd(stats['xfer_max'])} vs B = "
        f"{_fmt_usd(LOCKED.B * USD_PER_ETH)}). The Pareto frontier + scaling rule",
        "  quantify exactly what admitting them costs in bound.",
        "  — the ordinate is the PROVED envelope B + r·(W + Δ) (Theorem 1), which does not",
        "  involve T. See the claim re-check above before quoting any \"no configuration",
        "  achieves both\" statement from the earlier T + r·Δ ranking.",
    ]

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("\n".join(lines) + "\n")
    print(f"Log written: {LOG_PATH}")
    print("\n".join(lines))

    _write_figure(points, locked_pt, rule_pt)

    # Internal consistency (not results-tuning): metrics accounted, frontier non-empty.
    assert any(not p.dominated for p in points), "internal: empty Pareto frontier"
    for price, res in locked_res.items():
        assert len(res.outcomes) == len(arrivals), f"internal: lost transfers @ {price}"
    return 0


if __name__ == "__main__":
    sys.exit(main())
