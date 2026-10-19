"""V2 task 1.2: the fast bound must be exercised NON-vacuously.

LOCKED ledger: B + r*W < T  (value trip structurally unreachable, a documented vacuity).
ALT_TRIP ledger: B + r*W > T (value trip reachable; the primary non-vacuous config).
"""
from scenarios import scenario_5_bound_validation as s5


def test_locked_ledger_vacuity_is_as_documented():
    L = s5.LOCKED
    assert L.B + L.r * L.W < L.T  # 4600 < 5000


def test_alt_ledger_value_trip_reachable():
    A = s5.ALT_TRIP
    assert A.B + A.r * A.W > A.T  # 4600 > 4000
    # scenario_7 backwards-compat module aliases must stay bound to LOCKED:
    L = s5.LOCKED
    assert (s5.B, s5.r, s5.T, s5.W, s5.D) == (L.B, L.r, L.T, L.W, L.D)


def test_alt_fast_schedule_trips_and_respects_bound():
    A = s5.ALT_TRIP
    sch = s5.Schedule(
        name="alt-sustained-d60", regime="fast", delta=60.0,
        target_eth=10_000.0, per_block_eth=A.B,
        n_blocks=int((A.W + 60.0) / s5.TAU_BLOCK) + 10,
        note="ALT_TRIP: burst B then drain at r; crosses T_alt=4000 at ~3000 s",
    )
    out = s5._simulate_schedule(sch, ledger=A)
    assert out.value_tripped is True                      # NON-vacuous
    assert out.realised <= s5.analytic_bound("fast", 60.0, ledger=A) + 1e-9
