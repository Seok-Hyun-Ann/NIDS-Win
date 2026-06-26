from __future__ import annotations

import random

from nad.stats import Cusum, P2Quantile, RobustEwmaStat


def test_robust_median_tracks_level():
    s = RobustEwmaStat(alpha=0.1, warmup=50, init_size=16)
    for _ in range(500):
        s.update(100.0 + random.gauss(0, 5))
    assert s.warm
    assert abs(s.median - 100.0) < 5.0


def test_robust_scale_not_inflated_by_outliers():
    """A handful of huge spikes must barely move the MAD scale — the whole
    point of using median/MAD over mean/variance."""
    s = RobustEwmaStat(alpha=0.05, warmup=50, init_size=16, floor=0.1)
    for _ in range(800):
        s.update(50.0 + random.gauss(0, 2))
    scale_before = s.scale()
    # inject a few isolated spikes
    for _ in range(3):
        s.update(10_000.0)
        s.update(50.0)
    # scale should not have exploded the way variance would
    assert s.scale() < scale_before * 3.0


def test_robust_z_flags_real_deviation():
    s = RobustEwmaStat(alpha=0.05, warmup=50, init_size=16)
    for _ in range(500):
        s.update(20.0 + random.gauss(0, 1))
    # a genuine 50x level is many robust-sigmas out
    assert abs(s.robust_z(1000.0)) > 5.0
    # a normal value stays small
    assert abs(s.robust_z(21.0)) < 3.0


def test_p2_quantile_matches_numpy_free_reference():
    random.seed(1234)
    data = [random.gauss(0, 1) for _ in range(20_000)]
    est = P2Quantile(0.95)
    for x in data:
        est.update(x)
    exact = sorted(data)[int(0.95 * len(data))]
    assert abs(est.value - exact) < 0.1


def test_cusum_detects_persistent_small_drift():
    cu = Cusum(k=0.5, h=5.0)
    fired_at = None
    for i in range(1, 200):
        cu.update(1.0)            # a steady +1σ creep, each step sub-spike
        if cu.breached:
            fired_at = i
            break
    assert fired_at is not None
    assert cu.direction == "above"


def test_cusum_ignores_zero_mean_noise():
    random.seed(0)
    cu = Cusum(k=0.5, h=8.0)
    breached = False
    for _ in range(400):
        cu.update(random.gauss(0, 1))
        breached = breached or cu.breached
    assert not breached


def test_cusum_one_off_blip_does_not_accumulate():
    cu = Cusum(k=0.5, h=5.0)
    for _ in range(20):
        cu.update(0.0)
    cu.update(3.0)                # single blip
    for _ in range(20):
        cu.update(0.0)            # back to normal — should decay, never breach
    assert not cu.breached


def test_p2_quantile_warmup_returns_finite_after_five():
    est = P2Quantile(0.99)
    for x in [3.0, 1.0, 4.0, 1.0, 5.0]:
        est.update(x)
    assert est.value == 3.0  # middle marker of the 5 seeds (sorted: 1,1,3,4,5)
