"""Scenario 5: BOLT bound validation harness, Phase 14 (§docs/bolt/theorem.md).

This harness EMPIRICALLY validates the two BOLT worst-case-extraction bounds proved
pen-and-paper in ``docs/bolt/theorem.md`` across a broad sweep of attack schedules:

- **Fast-drain regime** (max-rate drain racing the breaker): the PROVED statement is
  the arrival-curve envelope ``X ≤ B + r·(t_trip + Δ) ≤ B + r·(W + Δ)`` = 4,660 ETH
  under both ledgers (``analytic_bound("envelope", ...)``). The regime named
  ``"fast"`` below returns ``X_max ≤ T + r·Δ``, which was **REFUTED** as an upper
  bound (theorem.md §14.1) and is retained UNCHANGED only so the committed
  Phase-14/15 evidence stays reproducible; read it as a limiter-only reference
  level, never as a bound.
- **Patient regime** (each window held ≤ T to dodge the value threshold; caught by
  the Phase-12 sequential change-point detector):       ``E[X_slow] ≤ B + r·D + r·Δ``
  (an EXPECTATION bound with D = ARL₁; the sub-drift degenerate case is limiter-only:
  theorem.md §14.2 / the post-A4 restatement)

  The patient bound counts the initial burst B once: the bucket starts full, so a
  white-box attacker who picks the start time drains that reserve thinly across
  blocks (keeping every window ≤ T) before the detector signals. By (AC) over
  [0, D+Δ) this is B + r·D + r·Δ, still TVL-independent.

Both bounds are **TVL-independent**; they depend only on the limiter/breaker/detector
config and the response latency Δ, NOT on total value locked. Locked ledger values
(theorem.md symbol table): ``B=1000 ETH, r=1 ETH/s, T=5000 ETH, W=3600 s, D=480 s``.

Two execution modes (mirrors scenario_2_ronin.py):

1. **End-to-end** (preferred). If a Hardhat node is reachable on
   ``http://127.0.0.1:8545``, deploy RegistryV2 + RateLimiter + CircuitBreaker +
   BridgeV2 from ``artifacts/contracts/*.json``, register k-of-n validators, and
   drive each schedule's withdrawals through the REAL ``BridgeV2.withdraw`` (k
   distinct ECDSA sigs over keccak256(recipient,amount,nonce,chainId,bridge),
   per-withdrawal ``RegistryV2.verifyValidator``, ``RateLimiter.consume``,
   ``CircuitBreaker.checkAndRecord``). Measure how much ETH actually leaves before
   the limiter/breaker/pause halts the attacker.

2. **Fallback simulation**. If NO node is reachable, run a faithful Python model of
   the SAME token-bucket + sliding-window-breaker + Δ-latency semantics so the
   scenario is reproducible offline. Prints which mode ran (mirrors scenario_2).

The CORE ASSERTION, written before the harness logic (strict TDD), is: for EVERY
schedule, ``realised_extraction ≤ analytic_bound``. The script EXITS NON-ZERO if any
schedule violates its bound (that would be a genuine finding: the bound or the
contracts are wrong; we do NOT weaken the assertion to make it pass).

Academic framing: a design specification, not a tested production system.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Ensure project root is on sys.path when run as a script.
sys.path.insert(0, str(Path(__file__).parent.parent))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

@dataclass(frozen=True)
class Ledger:
    """One (B, r, T, W, D) instantiation of the theorem's symbol table."""
    name: str
    B: float
    r: float
    T: float
    W: float
    D: float


LOCKED = Ledger("locked", B=1000.0, r=1.0, T=5000.0, W=3600.0, D=480.0)
# V2 task 1.2: reachable value trip. ONLY T differs from LOCKED:
# B + r*W = 4600 > T_alt = 4000, so a burst-B-then-drain-at-r schedule crosses T
# at t = (4000-1000)/1 = 3000 s < W = 3600 s and the breaker value-trips in-window.
ALT_TRIP = Ledger("alt-trip", B=1000.0, r=1.0, T=4000.0, W=3600.0, D=480.0)

# --- Locked ledger values (docs/bolt/theorem.md symbol table). DO NOT change. ---
# Module-level aliases kept for scenario_7's imports; the harness itself is
# parameterised by `Ledger` (LOCKED primary-locked, ALT_TRIP primary-non-vacuous).
B, r, T, W, D = LOCKED.B, LOCKED.r, LOCKED.T, LOCKED.W, LOCKED.D
TAU_BLOCK = 12.0   # Ethereum-class block time [s]
K = 5          # compromised threshold (Ronin 5-of-9)
N = 9          # validator set size

RONIN_TARGET_ETH = 173_600.0   # actual Ronin drain (detected after 6 days)

RPC = "http://127.0.0.1:8545"
FAR_DEADLINE = 2**63  # e2e driver signs far-future deadlines; expiry behavior is unit-tested in Hardhat
LOG_PATH = Path("docs/logs/scenario_5_bound.log")          # hardhat-mode evidence (committed)
FALLBACK_LOG_PATH = Path("docs/logs/scenario_5_bound.fallback.log")  # fallback-sim output (separate; never overwrites the hardhat log)
FIG_PATH = Path("figures/bound_validation.png")
FALLBACK_FIG_PATH = Path("figures/bound_validation.fallback.png")  # fallback-sim figure (separate; never overwrites committed evidence)


def analytic_bound(regime: str, delta: float, ledger: Ledger = LOCKED) -> float:
    """The worst-case extraction level for a regime at latency Δ=`delta`,
    instantiated for `ledger`'s symbol table (default: the LOCKED ledger).

    envelope: X_max    ≤ B + r·(W + Δ) (theorem.md §14.1, Theorem 1: THE PROVED BOUND)
    fast:     X_max    ≤ T + r·Δ       (SUPERSEDED, see below)
    patient:  E[X_slow] ≤ B + r·D + r·Δ (theorem.md §14.2, expectation; D=ARL₁)

    SUPERSESSION NOTICE (J1/J16).  ``fast`` returns T + r·Δ, which was REFUTED as an
    upper bound on per-window extraction: the trailing window slides, so outflow
    admitted early in an attack retires from it during the response latency and the
    freed headroom re-opens. An explicit admissible schedule extracts 4,640 ETH under
    the ALT_TRIP ledger against the 4,060 ETH this form permits (main.tex Sect. 4.2 /
    Appendix A; journal/THEOREM_1_COUNTEREXAMPLE.md). The regime is retained UNCHANGED
    so the committed Phase-14/15 evidence stays reproducible, but it is a limiter-only
    REFERENCE LEVEL, not a bound. Use ``envelope`` for the proved statement.

    The envelope B + r·(t_trip + Δ) is maximised at the largest admissible trip time
    t_trip = W, and T does not appear in it at all, which is why a configuration with
    B + r·W ≤ T (true of LOCKED: 4,600 ≤ 5,000) can never value-trip yet is still
    bounded.

    The patient bound carries the initial burst term B because the token bucket
    starts FULL at attack onset (both the Phase-13 RateLimiter and _SimBucket set
    tokens=capacity at t=0). By the arrival curve (AC) A(t)-A(s) ≤ B + r·(t-s),
    over [0, D+Δ) the correct bound is B + r·(D+Δ). A white-box attacker who picks
    the start time drains that initial reserve thinly enough to keep every window
    ≤ T, so the burst is genuinely available and MUST be counted. The bound stays
    TVL-independent (depends only on B, r, D, Δ; not on total value locked).
    """
    if regime == "envelope":
        return ledger.B + ledger.r * (ledger.W + delta)
    if regime == "fast":
        return ledger.T + ledger.r * delta
    if regime == "patient":
        return ledger.B + ledger.r * ledger.D + ledger.r * delta
    raise ValueError(f"unknown regime: {regime!r}")


@dataclass
class Schedule:
    """One attack schedule the harness drives end-to-end or simulates."""

    name: str
    regime: str          # "fast" | "patient"
    delta: float         # response latency Δ [s] implied by this schedule
    target_eth: float    # how much the attacker WANTS to extract
    per_block_eth: float        # attacker's intended outflow per block (fast: -> B)
    n_blocks: int               # number of blocks the attacker runs before halt window
    note: str = ""


@dataclass
class Result:
    schedule: Schedule
    realised: float
    bound: float
    # V2 1.2: True iff the breaker VALUE trip fired (window outflow > T) for this
    # schedule. Sourced from the value-trip latch ONLY (sim `_SimBreaker.tripped` /
    # on-chain `breaker.tripped()` read taken before any monitor trip), NEVER from
    # `t_trip is not None`, which would conflate detector SIGNAL trips with value trips.
    tripped: bool = False

    @property
    def margin(self) -> float:
        return self.bound - self.realised

    @property
    def ok(self) -> bool:
        return self.realised <= self.bound + 1e-9  # tiny float slack


def build_schedules() -> list[Schedule]:
    """14.7: a BROAD sweep spanning BOTH regimes.

    Vary Δ (incl. δ_include ≤ k·τ_block = 5·12 = 60 s), attacker rate (fast: ≥ r and
    bursting toward B; patient: just under T per window), and number of windows/blocks.
    Includes the Ronin-scale attempt (target 173,600 ETH) in BOTH regimes to show
    realised extraction is bounded far below it. ≥ 20 schedules so the figure is
    meaningful.
    """
    schedules: list[Schedule] = []

    # Δ values to sweep. 60 s is the proof's illustrative Δ (δ_include ≤ k·τ_block).
    deltas = [12.0, 24.0, 60.0, 120.0, 300.0]

    # --- FAST schedules: max-rate drain, bursting toward the per-block cap B, racing
    #     the breaker. Vary per-block burst (B and a fraction of B) and #blocks. ---
    fast_targets = [
        # (label, per_block, n_blocks, target)
        ("ronin-fast", B, 200, RONIN_TARGET_ETH),        # Ronin-scale attempt, full B/block
        ("burst-full-B", B, 50, 50 * B),                 # full burst every block
        ("burst-half-B", B / 2.0, 80, 80 * (B / 2.0)),   # half-B bursts
        ("burst-200", 200.0, 60, 60 * 200.0),            # modest per-block
    ]
    for label, per_block, n_blocks, target in fast_targets:
        for delta in deltas:
            schedules.append(
                Schedule(
                    name=f"{label}",
                    regime="fast",
                    delta=delta,
                    target_eth=target,
                    per_block_eth=per_block,
                    n_blocks=n_blocks,
                    note="max-rate drain racing the window threshold T",
                )
            )

    # --- PATIENT schedules: hold every sliding window's outflow <= T to evade the
    #     value threshold; halted only by the detector at t_trip <= D. Vary the
    #     per-block trickle (all keep windows < T) and #blocks (>= D worth). ---
    # A per-window budget just under T spread across the W-second window. With
    # τ_block=12 s there are W/τ_block = 300 blocks per window; per-block trickle must
    # keep the trailing-window sum <= T. We pick trickles well under T/window.
    blocks_per_window = int(W / TAU_BLOCK)  # 300
    patient_specs = [
        # (label, per_block, n_blocks, target)
        ("ronin-patient", 0.9 * (T / blocks_per_window), 4000, RONIN_TARGET_ETH),
        ("slow-trickle", 0.5 * (T / blocks_per_window), 2000, RONIN_TARGET_ETH),
        ("near-T-window", 0.95 * (T / blocks_per_window), 1000, 50_000.0),
        ("low-and-slow", 0.25 * (T / blocks_per_window), 3000, 100_000.0),
    ]
    for label, per_block, n_blocks, target in patient_specs:
        for delta in deltas:
            schedules.append(
                Schedule(
                    name=f"{label}",
                    regime="patient",
                    delta=delta,
                    target_eth=target,
                    per_block_eth=per_block,
                    n_blocks=n_blocks,
                    note="each window held <= T; caught by the change-point detector at <= D",
                )
            )

    return schedules


def build_alt_schedules() -> list[Schedule]:
    """V2 1.2: fast schedules under ALT_TRIP where the value trip is REACHABLE.

    Burst B then sustain the refill rate r: admitted outflow B + r*t crosses
    T_alt = 4000 at t = 3000 s < W, so the breaker value-trips inside one window.
    Realised must stay <= T_alt + r*delta (the fast bound, now non-vacuous).
    """
    scheds = [
        Schedule(
            name=f"alt-sustained-d{int(delta)}", regime="fast", delta=delta,
            target_eth=10_000.0, per_block_eth=ALT_TRIP.B,
            n_blocks=int((ALT_TRIP.W + delta) / TAU_BLOCK) + 10,
            note="ALT_TRIP (T=4000): B+r*W=4600 > T — value trip reachable",
        )
        for delta in (12.0, 60.0, 120.0, 300.0)
    ]
    scheds.append(
        Schedule(
            name="alt-ronin-fast", regime="fast", delta=60.0,
            target_eth=RONIN_TARGET_ETH, per_block_eth=ALT_TRIP.B,
            n_blocks=800, note="Ronin-scale attempt under ALT_TRIP",
        )
    )
    return scheds


# ---------------------------------------------------------------------------
# Faithful Python simulation of the contract semantics (fallback mode).
# ---------------------------------------------------------------------------
class _SimBucket:
    """Mirror of RateLimiter: capacity B, refill r, starts full, consume reverts if short."""

    def __init__(self, capacity: float, rate: float, t0: float) -> None:
        self.capacity = capacity
        self.rate = rate
        self.tokens = capacity
        self.last = t0

    def _refill(self, now: float) -> None:
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def consume(self, amount: float, now: float) -> bool:
        """Return True if admitted (mirrors consume); False if 'bucket exhausted'."""
        self._refill(now)
        if amount <= self.tokens + 1e-12:
            self.tokens -= amount
            return True
        return False


class _SimBreaker:
    """Mirror of CircuitBreaker: sliding window W, trips when window outflow > T."""

    def __init__(self, threshold: float, window: float) -> None:
        self.threshold = threshold
        self.window = window
        self.tripped = False
        self.records: list[tuple[float, float]] = []  # (timestamp, amount)

    def _window_outflow(self, now: float) -> float:
        cutoff = now - self.window
        return sum(a for (ts, a) in self.records if ts >= cutoff)

    def check_and_record(self, amount: float, now: float) -> bool:
        """Return True if the outflow is recorded (admitted); False if it trips/blocks."""
        if self.tripped:
            return False
        # prune
        cutoff = now - self.window
        self.records = [(ts, a) for (ts, a) in self.records if ts >= cutoff]
        new_total = self._window_outflow(now) + amount
        if new_total > self.threshold:
            self.tripped = True  # latch; breaching withdrawal is blocked (no value moves) and the latch persists
            return False
        self.records.append((now, amount))
        return True


@dataclass
class SimOutcome:
    """Outcome of one simulated schedule: realised extraction + the value-trip flag.

    `value_tripped` is sourced from the `_SimBreaker` latch ONLY (set solely on a
    window-cap breach), NOT from `t_trip is not None`, which for patient schedules
    is set at the detector SIGNAL and would mislabel signal trips as value trips.
    """

    realised: float
    value_tripped: bool


def _simulate_schedule(sch: Schedule, ledger: Ledger = LOCKED) -> SimOutcome:
    """Faithfully simulate ONE schedule against the bucket+breaker+Δ semantics.

    Time advances in τ_block-second blocks (assumption 4: <= B admitted per block).
    A withdrawal is *realised* only if BOTH limiter.consume AND breaker.checkAndRecord
    admit it (mirrors BridgeV2.withdraw: consume then checkAndRecord then transfer; if
    the breaker latches on this block the transfer reverts and nothing leaves).

    Trip handling:
      - fast regime: the breaker trips when a block's outflow would push the trailing
        window over T (value trip). t_trip is that block's time.
      - patient regime: the value trip never fires (windows held <= T); the detector
        signals at t_trip = D (signal trip), the worst-case mean detection time.
    After t_trip, the pause is effective at t_trip + Δ; during [t_trip, t_trip+Δ] the
    attacker keeps trying to extract but is limited by the (depleted) token bucket.
    """
    t0 = 0.0
    bucket = _SimBucket(ledger.B, ledger.r, t0)
    breaker = _SimBreaker(ledger.T, ledger.W)
    realised = 0.0
    t_trip: float | None = None
    detector_D = ledger.D  # patient signal-trip time

    now = t0
    for blk in range(sch.n_blocks):
        now = t0 + blk * TAU_BLOCK

        # Determine whether the pause is effective yet.
        if t_trip is not None and now >= t_trip + sch.delta:
            break  # pause effective: limiter admits nothing further (STOP)

        # Patient detector signal-trip at D (independent of the value path).
        if sch.regime == "patient" and t_trip is None and now >= detector_D:
            t_trip = now  # signal trip; breaker latched by the monitor

        want = sch.per_block_eth
        # If the breaker is latched, no withdrawal can complete in-path (revert).
        if breaker.tripped:
            continue

        # Attacker may pack multiple signed withdrawals into the block, but assumption 4
        # caps the TOTAL admitted per block at B; the bucket enforces that here.
        admit = bucket.consume(want, now)
        if not admit:
            # bucket exhausted this block; attacker takes whatever the bucket allows.
            # Mirror by consuming exactly the available tokens (max admissible).
            avail = bucket.tokens  # already refilled inside consume() attempt
            if avail > 1e-12:
                bucket.tokens -= avail
                want = avail
                admit = True
            else:
                continue

        # Breaker check (value trip for fast; patient stays under T by construction).
        recorded = breaker.check_and_record(want, now)
        if not recorded:
            # Breaker latched on this block -> the breaching withdrawal reverts; nothing
            # leaves on this block. Mark the value trip time and continue draining ONLY
            # the refilled tokens during the residual Δ window.
            if t_trip is None:
                t_trip = now
            continue

        realised += want

    # Source the flag from the VALUE-trip latch only (see SimOutcome docstring).
    return SimOutcome(realised=realised, value_tripped=breaker.tripped)


# ---------------------------------------------------------------------------
# End-to-end mode: drive the REAL Phase 13 contracts (mirrors scenario_2_ronin.py).
# ---------------------------------------------------------------------------
def _run_end_to_end(schedules: list[Schedule], ledger: Ledger = LOCKED) -> list[Result] | None:
    """Drive the real BridgeV2 if a node is up; else return None to trigger fallback."""
    try:
        from web3 import Web3
    except Exception:  # noqa: BLE001
        return None

    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 2}))
    try:
        if not w3.is_connected():
            return None
    except Exception:  # noqa: BLE001
        return None

    print(f"[mode] hardhat (end-to-end) against {RPC}")
    from eth_account import Account
    from eth_account.messages import encode_defunct

    accounts = w3.eth.accounts
    chain_id = w3.eth.chain_id
    M = 3  # governance threshold (m-of-n), matches the spec fixture
    governors = accounts[:M]
    owner = accounts[0]
    monitor = accounts[M + N]
    recipient = accounts[M + N + 1]

    artifacts_root = Path("artifacts/contracts")

    def load(name: str):
        art = json.loads((artifacts_root / f"{name}.sol/{name}.json").read_text())
        return art["abi"], art["bytecode"]

    reg_abi, reg_bc = load("RegistryV2")
    rl_abi, rl_bc = load("RateLimiter")
    cb_abi, cb_bc = load("CircuitBreaker")
    br_abi, br_bc = load("BridgeV2")

    # Validator keys: derive from Hardhat's deterministic mnemonic accounts M..M+N.
    # We need the PRIVATE keys to sign withdrawals; use the well-known Hardhat keys.
    hardhat_keys = _hardhat_keys()
    validator_keys = hardhat_keys[M : M + N]
    validators = [Account.from_key(k) for k in validator_keys]

    results: list[Result] = []

    def deploy(abi, bc, *args):
        C = w3.eth.contract(abi=abi, bytecode=bc)
        rcpt = w3.eth.wait_for_transaction_receipt(C.constructor(*args).transact({"from": owner}))
        return w3.eth.contract(address=rcpt.contractAddress, abi=abi)

    # Deploy the stack ONCE and reuse it across schedules. Between schedules we advance
    # EVM time past max(B/r, W) so the limiter bucket refills to full AND the breaker
    # window clears, then call breaker.reset(). Each schedule thus starts in a state
    # equivalent to a fresh deployment, without 40 redeploys. The recipient is the OWNER
    # so withdrawn ETH cycles straight back; we top the bridge up to a fixed buffer
    # before each run, so the deployer's balance is never drained across the sweep.
    recipient = owner
    registry = deploy(reg_abi, reg_bc, governors, M)
    OP_REGISTER = 0
    for v in validators:
        doc_hash = w3.keccak(text=f"doc-{v.address}")
        inner = Web3.solidity_keccak(
            ["uint256", "address", "address", "bytes32"],
            [chain_id, registry.address, v.address, doc_hash],
        )
        sig = v.sign_message(encode_defunct(primitive=inner)).signature
        ttl = 365 * 24 * 3600
        op_id = registry.functions.computeOpId(OP_REGISTER, v.address, doc_hash, ttl).call()
        for g in governors:
            registry.functions.approve(op_id).transact({"from": g})
        registry.functions.executeRegister(v.address, doc_hash, ttl, sig).transact({"from": governors[0]})

    limiter = deploy(rl_abi, rl_bc, _wei(ledger.B), _wei(ledger.r), "0x" + "00" * 20)
    breaker = deploy(cb_abi, cb_bc, _wei(ledger.T), int(ledger.W), "0x" + "00" * 20, monitor)
    bridge = deploy(br_abi, br_bc, registry.address, limiter.address, breaker.address, K)
    limiter.functions.setConsumer(bridge.address).transact({"from": owner})
    breaker.functions.setGate(bridge.address).transact({"from": owner})

    # Buffer must exceed the largest analytic bound so bridge balance is never the
    # binding constraint (which would artificially cap realised and mask a violation).
    buffer_eth = max(analytic_bound(s.regime, s.delta, ledger) for s in schedules) + 500.0
    refill_secs = int(max(ledger.B / ledger.r, ledger.W)) + 120  # past full-bucket refill AND window clear
    nonce = 1

    for sch in schedules:
        # Clean slate: ALWAYS reset (clears the breaker latch AND its _records array, so
        # the window-outflow scan can't accumulate across schedules and blow the gas cap),
        # then advance time so the bucket refills to full.
        breaker.functions.reset().transact({"from": owner})
        _advance_time(w3, refill_secs)
        # Top the bridge balance back up to the buffer (withdrawn ETH returned to owner).
        bal = w3.eth.get_balance(bridge.address)
        if bal < _wei(buffer_eth):
            bridge.functions.deposit().transact({"from": owner, "value": _wei(buffer_eth) - bal})

        realised, nonce, value_tripped = _drive_schedule_onchain(
            w3, bridge, limiter, breaker, validators, recipient, chain_id, sch, monitor, nonce, ledger
        )
        results.append(
            Result(
                schedule=sch,
                realised=realised,
                bound=analytic_bound(sch.regime, sch.delta, ledger),
                tripped=value_tripped,
            )
        )

    # Recover the buffer locked in the bridge back to the owner so re-running against a
    # long-lived node does not erode the deployer's balance (idempotent runs). Best-effort.
    nonce = _sweep_bridge_to_owner(w3, bridge, limiter, breaker, validators, owner, chain_id, monitor, nonce, ledger)
    return results


def _sweep_bridge_to_owner(w3, bridge, limiter, breaker, validators, owner, chain_id, monitor, nonce, ledger: Ledger = LOCKED) -> int:
    """Drain the bridge's residual balance back to the owner in ≤B chunks; resets the
    breaker and refills the bucket as needed. Recipient is the owner, so this just
    returns the run's funding buffer. Wrapped best-effort; never fails the validation."""
    from eth_account.messages import encode_defunct
    from web3 import Web3

    def sigs_for(amount_wei: int, n: int) -> list[bytes]:
        raw = Web3.solidity_keccak(
            ["address", "uint256", "uint256", "uint256", "uint256", "address"],
            [owner, amount_wei, n, FAR_DEADLINE, chain_id, bridge.address],
        )
        signed = sorted(
            ((v.address.lower(), v.sign_message(encode_defunct(primitive=raw)).signature) for v in validators[:K]),
            key=lambda x: x[0],
        )
        return [s for (_, s) in signed]

    try:
        for _ in range(60):
            bal = w3.eth.get_balance(bridge.address)
            if bal <= _wei(0.01):
                break
            if breaker.functions.tripped().call() or int(breaker.functions.windowOutflow().call()) >= _wei(ledger.T) - _wei(ledger.B):
                breaker.functions.reset().transact({"from": owner})
            _advance_time(w3, int(max(ledger.B / ledger.r, ledger.W)) + 120)  # refill bucket + clear window
            amt = min(int(limiter.functions.available().call()), bal, _wei(ledger.B))
            if amt <= _wei(0.01):
                continue
            w3.eth.wait_for_transaction_receipt(
                bridge.functions.withdraw(owner, amt, nonce, FAR_DEADLINE, sigs_for(amt, nonce)).transact(
                    {"from": w3.eth.accounts[0], "gas": 3_000_000}
                )
            )
            nonce += 1
    except Exception:  # noqa: BLE001 (recovery is best-effort; validation already done)
        pass
    return nonce


def _set_next_block_timestamp(w3, ts: int) -> None:
    """Pin the NEXT mined block's timestamp so the limiter refills at the modelled
    rate (r·τ_block per block). Without this, automine advances time by ~1 s and the
    on-chain bucket never refills as the proof assumes, the central faithfulness fix.
    """
    w3.provider.make_request("evm_setNextBlockTimestamp", [int(ts)])


def _advance_time(w3, secs: int) -> None:
    """Jump EVM time forward by `secs` and mine, so the limiter bucket refills and the
    breaker window clears between schedules (clean-slate reuse of one deployment)."""
    w3.provider.make_request("evm_increaseTime", [int(secs)])
    w3.provider.make_request("evm_mine", [])


def _drive_schedule_onchain(
    w3, bridge, limiter, breaker, validators, recipient, chain_id, sch, monitor, nonce_start,
    ledger: Ledger = LOCKED,
):
    """Execute a schedule's withdrawals through the REAL BridgeV2.withdraw, faithfully
    mirroring the proof's dynamics (token-bucket refill, synchronous value trip, and
    the residual-Δ leakage window) so the on-chain realised value is as tight as the
    fallback sim, not an under-driven lower bound.

    Per block (advanced by exactly τ_block of EVM time):
      * The attacker drains the MAX admissible this block, ``min(per_block, available())``,
        so the initial full bucket (burst B) is genuinely exercised, the term that
        the patient bound B+r·D+r·Δ exists to cover.
      * COMMIT-NOT-REVERT (post V2 0.1 two-phase trip): a FRESH value breach does NOT
        revert; ``checkAndRecord`` latches ``tripped = true`` and returns
        ``breached = true``; ``BridgeV2.withdraw`` skips the transfer, emits
        ``WithdrawalBlocked``, and COMMITS so the latch persists. ``try_withdraw``
        therefore treats a mined tx with no ``Withdrawal`` event as a failed drain,
        and a failure is diagnosed via a ``breaker.tripped()`` read after the tx
        (equivalently, the ``WithdrawalBlocked`` event on the mined receipt), NEVER
        by revert matching. Only *subsequent* withdrawals after the latch revert
        (string ``"breaker: tripped"``); a plain revert with no latch is a transient
        per-block limiter shortfall; advance time so the bucket refills and keep
        draining.
      * FAST: drive until the breaker value-trips (windowOutflow > T) in-path, or the
        bucket can no longer sustain the rate. The synchronous breaker IS the halt.
      * PATIENT: the value trip never fires (windows held ≤ T). The monitor SIGNALS at
        t=D but the pause is only EFFECTIVE at t=D+Δ (assumption 2, δ_include ≤ k·τ_block);
        the attacker keeps draining through the whole residual [D, D+Δ] window, then the
        pause lands (trip the breaker) and the final withdrawal reverts. realised must
        still be ≤ B + r·D + r·Δ.

    Post V2 1.7 the on-chain breaker window is BUCKETED (fixed 61-slot accumulator):
    it over-approximates the exact sliding window by ≤ one bucketWidth, so on-chain
    realised ≤ exact-window sim realised; the bound comparison is unaffected.
    """
    from eth_account.messages import encode_defunct
    from web3 import Web3

    def sigs_for(amount_wei: int, nonce: int) -> list[bytes]:
        # Sign the RAW packed pre-image; BridgeV2.withdrawalDigest already applies
        # toEthSignedMessageHash, and encode_defunct adds the SAME EIP-191 prefix once;
        # signing the contract's returned digest would double-prefix and mis-recover.
        raw = Web3.solidity_keccak(
            ["address", "uint256", "uint256", "uint256", "uint256", "address"],
            [recipient, amount_wei, nonce, FAR_DEADLINE, chain_id, bridge.address],
        )
        signed = []
        for v in validators[:K]:
            s = v.sign_message(encode_defunct(primitive=raw))
            signed.append((v.address.lower(), s.signature))
        signed.sort(key=lambda x: x[0])  # ascending signer => distinct, ordered (contract req)
        return [s for (_, s) in signed]

    def try_withdraw(amount_wei: int, nonce: int) -> str:
        """Three outcomes (V2 0.1 two-phase trip / commit-not-revert):
        - "ok":      tx mined and the Withdrawal event fired (value moved).
        - "blocked": tx MINED but no Withdrawal event; a fresh value breach latched
                     the breaker, WithdrawalBlocked was emitted and the tx COMMITTED,
                     so `usedNonce[nonce]` IS consumed even though no value moved.
        - "revert":  tx reverted (limiter shortfall or already-tripped breaker);
                     the nonce is NOT consumed.
        """
        try:
            rcpt = w3.eth.wait_for_transaction_receipt(
                bridge.functions.withdraw(
                    recipient, amount_wei, nonce, FAR_DEADLINE, sigs_for(amount_wei, nonce)
                ).transact({"from": w3.eth.accounts[0], "gas": 3_000_000})
            )
        except Exception:  # noqa: BLE001 (revert: limiter shortfall or already-tripped breaker)
            return "revert"
        from web3.logs import DISCARD
        if len(bridge.events.Withdrawal().process_receipt(rcpt, errors=DISCARD)) > 0:
            return "ok"
        return "blocked"

    realised = 0.0
    nonce = nonce_start
    value_tripped = False  # V2 1.2: breaker VALUE trip (window > T), never a monitor trip
    t0 = w3.eth.get_block("latest")["timestamp"]
    dust_wei = _wei(1e-6)

    # Pause becomes EFFECTIVE at t_trip + Δ. For patient, t_trip = D (signal); for fast
    # the in-path value trip is the halt, but we still bound the loop generously.
    if sch.regime == "patient":
        pause_effective_block = int((ledger.D + sch.delta + TAU_BLOCK - 1) // TAU_BLOCK) + 1
        max_blocks = min(sch.n_blocks, pause_effective_block + 2)
    else:
        # Fast attacker drains every block until the breaker value-trips (window > T) or
        # the schedule ends; it must NOT be cut off early, or e2e under-reports realised
        # (the trickle past the initial burst keeps leaking r·τ/block while window < T).
        # Cap at 400 to keep the breaker record-scan well under the per-tx gas cap while
        # still letting ALT_TRIP schedules reach the value trip: under T_alt=4000 the
        # window outflow B + r·τ·k crosses T at block ~251 > the old cap of 200 (LOCKED
        # fast schedules have n_blocks <= 200, so their behaviour is unchanged).
        max_blocks = min(sch.n_blocks, 400)  # runtime cap only

    for blk in range(max_blocks):
        # Advance EVM time by one τ_block so the bucket refills exactly r·τ_block.
        _set_next_block_timestamp(w3, t0 + (blk + 1) * TAU_BLOCK)
        now_rel = (blk + 1) * TAU_BLOCK

        # PATIENT: pause effective at D+Δ -> trip the breaker; the next withdraw reverts.
        if sch.regime == "patient" and now_rel >= ledger.D + sch.delta:
            try:
                if not breaker.functions.tripped().call():
                    breaker.functions.trip().transact({"from": monitor})
            except Exception:  # noqa: BLE001
                pass
            break

        # Attacker drains the most the bucket admits this block (exercises burst B).
        # available() is read at the LAST mined block; the withdraw mines τ_block later,
        # by when the bucket has refilled r·τ_block more. Project it so a block that
        # drained the bucket to exactly 0 still claims that refill (else realised stalls).
        available_wei = int(limiter.functions.available().call())
        projected_wei = min(_wei(ledger.B), available_wei + _wei(ledger.r * TAU_BLOCK))
        want_wei = min(_wei(min(sch.per_block_eth, ledger.B)), projected_wei)
        if want_wei <= dust_wei:
            w3.provider.make_request("evm_mine", [])  # advance time so the bucket refills
            continue

        outcome = try_withdraw(want_wei, nonce)
        if outcome == "ok":
            realised += want_wei / 1e18
            nonce += 1
            continue
        if outcome == "blocked":
            # Blocked-but-COMMITTED withdraw: the tx mined (WithdrawalBlocked), so the
            # nonce IS consumed on-chain; advance it or every later withdrawal would
            # revert "bridge: nonce used" and under-drive subsequent schedules.
            nonce += 1

        # Drain failed: either a blocked-but-COMMITTED withdraw (WithdrawalBlocked,
        # fresh value trip, no revert) or a plain revert (limiter shortfall /
        # already-tripped breaker). Diagnose via the tripped() latch read, not revert
        # matching: latched -> terminal (fast value trip). Else the per-block amount
        # briefly exceeded the limiter; let time advance and retry.
        # This read always happens BEFORE the patient branch's monitor trip() (that
        # branch breaks the loop immediately), so a True here is a pure VALUE trip,
        # equivalent to observing WithdrawalBlocked on the mined receipt (V2 1.2).
        if breaker.functions.tripped().call():
            value_tripped = True
            break
        # transient shortfall: skip this block, bucket refills on the next timestamp.

    return realised, nonce, value_tripped


def _wei(eth: float) -> int:
    return int(round(eth * 1e18))


def _hardhat_keys() -> list[str]:
    """Hardhat's deterministic dev private keys (accounts 0..14). Local-only."""
    return [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
        "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        "0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897",
        "0x701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82",
        "0xa267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1",
        "0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd",
        "0xc526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa",
    ]


def run_schedules(schedules: list[Schedule], ledger: Ledger = LOCKED) -> tuple[list[Result], list[str]]:
    """14.6: try end-to-end; fall back to a faithful Python simulation offline."""
    modes: list[str] = []
    results = _run_end_to_end(schedules, ledger)
    if results is not None:
        modes.append("hardhat")  # V2 1.1 acceptance: log must show `mode: hardhat`
        return results, modes

    print(f"[mode] Fallback-sim — no Hardhat node reachable at {RPC}")
    modes.append("fallback-sim")
    results = []
    for sch in schedules:
        out = _simulate_schedule(sch, ledger)
        results.append(
            Result(
                schedule=sch,
                realised=out.realised,
                bound=analytic_bound(sch.regime, sch.delta, ledger),
                tripped=out.value_tripped,
            )
        )
    return results, modes


def _write_log(sections: list[tuple[Ledger, list[Result]]], modes: list[str]) -> None:
    """Write the per-ledger log: LOCKED section first (vacuous fast bound, retained
    for continuity), then the ALT_TRIP section (primary non-vacuous config, V2 1.2).

    Sanity invariant for the committed artifact: the `trip` column reports the VALUE
    trip only (never a detector signal trip), so every LOCKED row, patient rows
    included, must read `trip=no`; `trip=YES` may appear only under ledger[alt-trip].

    Evidence-safety invariant (A3 fix): when running in fallback-sim mode (no Hardhat
    node reachable), output goes to FALLBACK_LOG_PATH instead of LOG_PATH so the
    committed hardhat-mode evidence in LOG_PATH is never overwritten by a node-less run.
    """
    is_fallback_only = modes == ["fallback-sim"]
    out_path = FALLBACK_LOG_PATH if is_fallback_only else LOG_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_total = sum(len(res_list) for (_, res_list) in sections)
    lines = [
        "# BOLT Phase 14 — bound-validation harness (scenario_5)",
        f"# mode(s): {', '.join(modes)}",
        f"# ledger: B={B} r={r} T={T} W={W} D={D}  (docs/bolt/theorem.md)",
        "# ledger[locked]:   B=1000 r=1 T=5000 W=3600 D=480  (B+r*W=4600 < T — value trip UNREACHABLE; fast bound VACUOUS here, retained for continuity)",
        "# ledger[alt-trip]: B=1000 r=1 T=4000 W=3600 D=480  (B+r*W=4600 > T — value trip REACHABLE; PRIMARY non-vacuous config, V2 1.2)",
        "# bounds: PROVED envelope X ≤ B+r·(W+Δ) (deterministic, Thm. 1) ; patient E[X_slow] ≤ B+r·D+r·Δ (expectation, D=ARL₁; theorem.md §14.2)  (TVL-independent)",
        "# NOTE: the per-row `bound` column below is the SUPERSEDED T+r·Δ for the fast regime — a limiter-only reference level, refuted as a bound (theorem.md §14.1). Rows are retained unchanged for continuity with the committed Phase-14/15 evidence.",
        "# trip column: the breaker VALUE trip only (window outflow > T), diagnosed via",
        "# WithdrawalBlocked / breaker.tripped() — a detector SIGNAL trip is never flagged.",
        f"# schedules: {n_total}",
    ]
    for ledger, results in sections:
        lines += [
            "#",
            f"## section ledger[{ledger.name}] — B={ledger.B} r={ledger.r} T={ledger.T} W={ledger.W} D={ledger.D}  ({len(results)} schedules)",
            "regime   schedule                       Δ(s)     realised(ETH)     bound(ETH)    margin(ETH)  result  trip",
        ]
        for res in results:
            s = res.schedule
            lines.append(
                f"{s.regime:8s} {s.name:28s} {s.delta:7.1f} {res.realised:16.3f} {res.bound:14.3f} "
                f"{res.margin:14.3f}  {'PASS' if res.ok else 'FAIL'}  trip={'YES' if res.tripped else 'no'}"
            )
    out_path.write_text("\n".join(lines) + "\n")
    print(f"Log written: {out_path}")
    if is_fallback_only:
        print(
            f"[evidence-safety] Fallback-sim output written to {FALLBACK_LOG_PATH}; "
            f"committed hardhat-mode evidence in {LOG_PATH} is untouched. "
            "Run with a Hardhat node on :8545 to regenerate the on-chain evidence log."
        )


def _write_figure(results: list[Result], alt_results: list[Result] | None = None,
                   fig_path: Path | None = None) -> None:
    fig_path = fig_path or FIG_PATH
    fig_path.parent.mkdir(parents=True, exist_ok=True)
    fast = [res for res in results if res.schedule.regime == "fast"]
    patient = [res for res in results if res.schedule.regime == "patient"]
    alt_results = alt_results or []

    n_panels = 3 if alt_results else 2
    fig, axes = plt.subplots(1, n_panels, figsize=(6.5 * n_panels, 5))
    ax1, ax2 = axes[0], axes[1]

    def _panel(ax, group, regime, title, ledger=LOCKED, colour=None):
        # x = Δ, ceiling line = bound(Δ), points = realised, coloured by regime.
        deltas = sorted({res.schedule.delta for res in group})
        bound_line = [analytic_bound(regime, d, ledger) for d in deltas]
        ax.plot(deltas, bound_line, "-", color="crimson", linewidth=2,
                label=("superseded level T+r·Δ (not a bound; see Thm. 1)"
                       if regime == "fast" else "bound E[X_slow] ≤ B+r·D+r·Δ"))
        xs = [res.schedule.delta for res in group]
        ys = [res.realised for res in group]
        default_colour = "tab:blue" if regime == "fast" else "tab:green"
        ax.scatter(xs, ys, color=(colour or default_colour),
                   alpha=0.7, s=40, label="realised extraction", zorder=3)
        ax.axhline(RONIN_TARGET_ETH, color="gray", linestyle=":", linewidth=1,
                   label=f"Ronin loss ({RONIN_TARGET_ETH:,.0f})")
        ax.set_xlabel("response latency Δ (s)")
        ax.set_ylabel("ETH")
        ax.set_title(title)
        ax.set_yscale("log")
        ax.legend(loc="center right", fontsize=8)
        ax.grid(True, which="both", alpha=0.3)

    _panel(ax1, fast, "fast", "Fast-drain regime (LOCKED): realised vs the superseded T + r·Δ\n(value trip unreachable; the proved envelope is B + r(W + \u0394) = 4,660 ETH)")
    _panel(ax2, patient, "patient", "Patient regime (LOCKED): realised vs E[X_slow] ≤ B + r·D + r·Δ")
    if alt_results:
        n_trips = sum(1 for res in alt_results if res.tripped)
        _panel(axes[2], alt_results, "fast",
               f"Fast regime (ALT_TRIP, T=4000): NON-vacuous — {n_trips}/{len(alt_results)} value trips fired",
               ledger=ALT_TRIP, colour="tab:orange")
    fig.suptitle("BOLT bound validation — realised extraction never exceeds the analytic bound (TVL-independent)")
    plt.tight_layout()
    plt.savefig(fig_path, dpi=300)
    print(f"Figure saved: {fig_path}")


def main() -> int:
    # V2 1.2. Run BOTH ledgers: LOCKED (continuity; fast bound vacuous there) and
    # ALT_TRIP (T=4000, so the value trip is reachable and the fast bound is non-vacuous).
    locked_results, modes = run_schedules(build_schedules(), ledger=LOCKED)
    alt_results, alt_modes = run_schedules(build_alt_schedules(), ledger=ALT_TRIP)
    assert any(res.tripped for res in alt_results), (
        "1.2 non-vacuity: no ALT_TRIP schedule fired the on-chain/sim value trip"
    )
    modes = list(dict.fromkeys(modes + alt_modes))
    results = locked_results + alt_results

    # Persist outputs FIRST so the log/figure exist even on a violating run.
    is_fallback_only = modes == ["fallback-sim"]
    _write_log([(LOCKED, locked_results), (ALT_TRIP, alt_results)], modes)
    # Evidence-safety (A3 extension): mirror log redirect for the figure.
    # Fallback-sim writes to FALLBACK_FIG_PATH so the committed bound_validation.png
    # (hardhat-mode evidence) is never overwritten by a node-less make-test run.
    _write_figure(locked_results, alt_results,
                  fig_path=FALLBACK_FIG_PATH if is_fallback_only else FIG_PATH)

    # ---- CORE ASSERTION (written FIRST, strict TDD): realised <= bound, EVERY run ----
    violations = [res for res in results if not res.ok]
    for res in results:
        status = "PASS" if res.ok else "FAIL"
        print(
            f"[{res.schedule.regime:7s}] {res.schedule.name:28s} "
            f"Δ={res.schedule.delta:6.1f}s  realised={res.realised:10.3f}  "
            f"bound={res.bound:10.3f}  margin={res.margin:10.3f}  {status}"
        )

    margins = [res.margin for res in results]
    if margins:
        tightest = min(results, key=lambda x: x.margin)
        print(
            f"\nSchedules: {len(results)}  modes: {', '.join(modes)}  "
            f"min margin (bound-realised): {tightest.margin:.3f} ETH "
            f"on {tightest.schedule.regime}/{tightest.schedule.name} (Δ={tightest.schedule.delta}s)"
        )

    assert not violations, (
        f"BOUND VIOLATED by {len(violations)} schedule(s): "
        + ", ".join(f"{v.schedule.name} (realised={v.realised} > bound={v.bound})" for v in violations)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
