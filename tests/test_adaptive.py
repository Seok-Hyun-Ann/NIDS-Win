from __future__ import annotations

import random
from datetime import datetime, timezone

from nad.adaptive import AdaptiveDetector
from nad.features import WindowFeatures


def _w(packet_count: float, hour: int, day: int = 1) -> WindowFeatures:
    dt = datetime(2026, 6, day, hour, 0, 0, tzinfo=timezone.utc)
    ts = int(dt.timestamp() * 1_000_000_000)
    pc = max(0.0, packet_count)
    return WindowFeatures(
        window_start_ns=ts, window_end_ns=ts, duration_s=1.0,
        packet_count=pc, bytes_total=pc * 100, avg_payload_size=64.0,
        unique_src_ips=1, unique_dst_ips=1, unique_dst_ports=1,
        tcp_count=pc, udp_count=0, icmp_count=0, other_count=0,
        top_src_ips={"10.0.0.1": int(pc)},
        top_dst_ips={"10.0.0.2": int(pc)},
        top_dst_ports={80: int(pc)},
    )


def _feed(det, count, pkts, hour, day=1, jitter=2.0):
    for _ in range(count):
        det.update(_w(pkts + random.gauss(0, jitter), hour, day))


def _det(**kw):
    base = dict(
        bucketing="hour", threshold_mode="robust", robust_k=3.5,
        warmup_windows=40, global_warmup=10, confirm_windows=3,
        cooldown_windows=0, alpha=0.05, tz=timezone.utc,
        features=("packet_count",),
    )
    base.update(kw)
    return AdaptiveDetector(**base)


def test_no_alert_before_global_warmup():
    det = _det(global_warmup=10)
    out = []
    for i in range(10):
        out += det.update(_w(10_000 if i == 5 else 10, hour=12))
    assert out == []


def test_sustained_spike_fires_after_confirm():
    random.seed(1)
    det = _det()
    _feed(det, 60, pkts=50, hour=12)
    a1 = det.update(_w(5000, hour=12))
    a2 = det.update(_w(5000, hour=12))
    a3 = det.update(_w(5000, hour=12))
    assert not a1 and not a2
    fired = [a for a in a3 if a.feature == "packet_count"]
    assert len(fired) == 1 and fired[0].direction == "above"


def test_single_blip_filtered():
    random.seed(2)
    det = _det()
    _feed(det, 60, pkts=50, hour=12)
    blip = det.update(_w(5000, hour=12))
    back = det.update(_w(50, hour=12))
    assert not blip and not back


def test_time_bucket_separates_day_from_night():
    """The headline behaviour: the *same* traffic level is normal at the busy
    hour but anomalous at the idle hour, because each hour has its own baseline.
    """
    random.seed(3)
    det = _det()
    # 21h = gaming: ~5000 pkts is normal here.  04h = idle: ~50 pkts is normal.
    _feed(det, 60, pkts=5000, hour=21, jitter=50)
    _feed(det, 60, pkts=50, hour=4, jitter=2)

    # 5000 pkts at the gaming hour -> not anomalous
    evening = []
    for _ in range(3):
        evening += det.update(_w(5000, hour=21))
    assert not [a for a in evening if a.feature == "packet_count"]

    # the same 5000 pkts at the idle hour -> anomalous
    night = []
    for _ in range(3):
        night += det.update(_w(5000, hour=4))
    fired = [a for a in night if a.feature == "packet_count"]
    assert len(fired) == 1
    assert fired[0].context["bucket"] == "04h"
    assert fired[0].context["used_fallback"] is False


def test_cooldown_suppresses_consecutive_alerts():
    random.seed(4)
    det = _det(confirm_windows=1, cooldown_windows=10)
    _feed(det, 60, pkts=50, hour=12)
    first = det.update(_w(5000, hour=12))
    second = det.update(_w(5000, hour=12))
    assert any(a.feature == "packet_count" for a in first)
    assert not any(a.feature == "packet_count" for a in second)


def test_cusum_detects_slow_ramp():
    """A gradual sub-threshold creep is caught by CUSUM, not the instantaneous
    path — the low-and-slow signature volume thresholds miss."""
    random.seed(11)
    det = _det(robust_k=5.0, cusum_h=6.0, cooldown_windows=0)
    _feed(det, 60, pkts=200, hour=12, jitter=8)
    fired = []
    val = 200.0
    for _ in range(40):
        val += 6.0
        fired += det.update(_w(val, hour=12))
        if fired:
            break
    assert any("완만한 지속" in a.category for a in fired)


def test_cusum_quiet_on_stable_traffic():
    random.seed(12)
    det = _det(robust_k=5.0)
    _feed(det, 60, pkts=200, hour=12, jitter=8)
    out = []
    for _ in range(100):
        out += det.update(_w(200 + random.gauss(0, 8), hour=12))
    assert not [a for a in out if "완만한" in a.category]


def test_snapshot_is_json_serialisable():
    import json
    random.seed(5)
    det = _det()
    _feed(det, 50, pkts=50, hour=12)
    json.dumps(det.state_snapshot())  # must not raise
