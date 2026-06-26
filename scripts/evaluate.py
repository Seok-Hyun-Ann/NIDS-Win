"""Offline evaluation: fixed-threshold vs adaptive vs full behavioural stack.

Unit tests prove the code behaves; this script answers the *research* question —
does each layer actually catch more, with fewer false alarms? Live traffic can't
answer it (no ground truth), so we synthesise a multi-day stream with a realistic
time-of-day rhythm *and destination identities*, inject attacks at known windows,
and score three detector stacks against the labels:

    1. Baseline (volume, fixed 3σ)            — the original detector
    2. Adaptive (volume + CUSUM)              — robust per-bucket + slow-drift
    3. Full (+ first-seen destinations)       — adds the behavioural identity axis

Each row of attacks shows which stack catches it, isolating the contribution of
CUSUM (low-and-slow) and first-seen (never-before-seen destination).

Run:
    python scripts/evaluate.py
    python scripts/evaluate.py --days 10 --seed 7

No packet capture / Npcap involved — detectors consume WindowFeatures directly.
"""
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nad.adaptive import AdaptiveDetector            # noqa: E402
from nad.behavioral import FirstSeenDetector         # noqa: E402
from nad.detect import BaselineDetector              # noqa: E402
from nad.features import WindowFeatures              # noqa: E402

TZ = timezone.utc
DAY_S = 86_400

# Recurring "normal" public destinations the host talks to every day (learned),
# plus the attacker's never-before-seen server used only in the A scenario.
POOL_PUBLIC = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "104.18.5.6", "140.82.112.3",
    "151.101.1.69", "172.217.16.14", "13.107.42.14", "52.84.150.10",
    "199.232.36.133", "204.79.197.200", "23.45.67.89", "34.120.0.1",
]
POOL_PRIVATE = ["192.168.0.1", "192.168.0.10"]
ATTACK_IP = "185.220.101.45"          # never appears in normal traffic

DAY_MOODS = {"quiet": 0.7, "normal": 1.0, "gaming": 1.35, "streaming": 1.2}


def _diurnal(hour: int, weekend: bool) -> float:
    if hour < 7:        base = 0.08
    elif hour < 9:      base = 0.25
    elif hour < 18:     base = 0.45
    elif hour < 23:     base = 0.85
    else:               base = 0.40
    if weekend:
        base *= 1.2 if hour >= 10 else 0.9
    return base


def _assign_dsts(rng: random.Random, activity: float) -> dict[str, int]:
    """A plausible set of destinations for one window, drawn from the pool."""
    k = max(2, int(2 + 6 * activity))
    chosen = rng.sample(POOL_PUBLIC, min(k, len(POOL_PUBLIC)))
    dsts = {ip: rng.randint(4, 60) for ip in chosen}
    for ip in POOL_PRIVATE:
        dsts[ip] = rng.randint(5, 30)
    return dsts


def _features_for(ts_ns: int, activity: float, rng: random.Random) -> WindowFeatures:
    a = max(0.02, activity)
    pkt = max(1.0, rng.gauss(600 * a + 20, 0.18 * (600 * a + 20)))
    udp = pkt * rng.uniform(0.35, 0.6)
    tcp = max(0.0, pkt - udp - rng.uniform(0, 5))
    payload = rng.gauss(300 + 400 * a, 60)
    bytes_total = pkt * max(40.0, payload)
    dsts = _assign_dsts(rng, a)
    # Normal traffic is download-heavy: most bytes flow inbound.
    egress_frac = min(0.9, max(0.05, rng.gauss(0.30, 0.08)))
    return _make_window(ts_ns, {
        "packet_count": pkt, "bytes_total": bytes_total,
        "avg_payload_size": bytes_total / pkt,
        "unique_src_ips": max(1.0, rng.gauss(8 + 18 * a, 3)),
        "unique_dst_ips": float(len(dsts)),
        "unique_dst_ports": max(1.0, rng.gauss(5 + 15 * a, 2)),
        "tcp_count": tcp, "udp_count": udp,
        "icmp_count": max(0.0, rng.gauss(1, 1)),
        "egress_bytes": bytes_total * egress_frac,
        "ingress_bytes": bytes_total * (1.0 - egress_frac),
    }, dsts)


def _make_window(ts_ns: int, f: dict, dsts: dict[str, int]) -> WindowFeatures:
    pkt = f["packet_count"]
    top = dict(sorted(dsts.items(), key=lambda kv: -kv[1])[:5])
    return WindowFeatures(
        window_start_ns=ts_ns, window_end_ns=ts_ns, duration_s=1.0,
        packet_count=pkt, bytes_total=f["bytes_total"],
        avg_payload_size=f["avg_payload_size"],
        unique_src_ips=f["unique_src_ips"], unique_dst_ips=f["unique_dst_ips"],
        unique_dst_ports=f["unique_dst_ports"],
        tcp_count=f["tcp_count"], udp_count=f["udp_count"],
        icmp_count=f["icmp_count"], other_count=0,
        top_dst_ips=top, top_dst_ports={443: int(max(1, pkt))},
        egress_bytes=int(f.get("egress_bytes", f["bytes_total"] // 2)),
        ingress_bytes=int(f.get("ingress_bytes", f["bytes_total"] // 2)),
        all_dst_ips=dict(dsts),
    )


def _rebuild(w: WindowFeatures, **overrides) -> WindowFeatures:
    """Rebuild a window overriding some numeric fields, preserving destinations."""
    f = dict(w.numeric())
    f["egress_bytes"] = overrides.pop("egress_bytes", w.egress_bytes)
    f["ingress_bytes"] = overrides.pop("ingress_bytes", w.ingress_bytes)
    f.update(overrides)
    return _make_window(w.window_end_ns, f, w.all_dst_ips)


@dataclass
class Episode:
    kind: str
    feature: str
    start_idx: int
    end_idx: int


@dataclass
class Timeline:
    windows: list[WindowFeatures]
    episodes: list[Episode]
    ts_to_idx: dict[int, int] = field(default_factory=dict)
    warmup_idx: int = 0
    neutral_idx: set[int] = field(default_factory=set)


def generate(days: int, step_seconds: int, seed: int,
             ramp_rate: float = 0.05) -> Timeline:
    rng = random.Random(seed)
    start = datetime(2026, 3, 2, 0, 0, 0, tzinfo=TZ)   # a Monday
    start_ns = int(start.timestamp() * 1e9)
    per_day = DAY_S // step_seconds
    moods = [rng.choice(list(DAY_MOODS)) for _ in range(days)]

    windows: list[WindowFeatures] = []
    for i in range(days * per_day):
        ts_ns = start_ns + i * step_seconds * 1_000_000_000
        dt = datetime.fromtimestamp(ts_ns / 1e9, TZ)
        act = _diurnal(dt.hour, dt.weekday() >= 5) * DAY_MOODS[moods[i // per_day]]
        windows.append(_features_for(ts_ns, act, rng))

    episodes: list[Episode] = []
    neutral: set[int] = set()
    warmup_idx = 2 * per_day
    span = max(6, per_day // 24 // 6)        # ~10 min of windows

    def at(day: int, hour: int) -> int:
        return day * per_day + hour * (per_day // 24)

    # 1) Off-hours volume: evening-level packet_count at 3am.
    s = at(3, 3)
    for j in range(s, s + span):
        windows[j] = _rebuild(windows[j], packet_count=560.0, tcp_count=360.0,
                              udp_count=190.0, bytes_total=560.0 * 520)
    episodes.append(Episode("off_hours_volume", "packet_count", s, s + span - 1))

    # 2) Port scan at 2am.
    s = at(4, 2)
    for j in range(s, s + span):
        windows[j] = _rebuild(windows[j], unique_dst_ports=850.0)
    episodes.append(Episode("port_scan", "unique_dst_ports", s, s + span - 1))

    # 3) Sudden data exfiltration at 4am.
    s = at(5, 4)
    for j in range(s, s + span):
        n = windows[j].numeric()
        windows[j] = _rebuild(windows[j], bytes_total=n["bytes_total"] * 18,
                              avg_payload_size=1400.0)
    episodes.append(Episode("exfiltration", "bytes_total", s, s + span - 1))

    # 4) Masking: legit burst inflates variance, then a moderate real attack.
    burst = at(6, 10)
    for j in range(burst, burst + 3):
        windows[j] = _rebuild(windows[j], packet_count=4000.0, tcp_count=2600.0,
                              udp_count=1400.0, bytes_total=4000.0 * 700)
        neutral.add(j)
    s = burst + 15
    for j in range(s, s + span):
        windows[j] = _rebuild(windows[j], packet_count=1150.0, tcp_count=760.0,
                              udp_count=390.0, bytes_total=1150.0 * 560)
    episodes.append(Episode("masked_spike", "packet_count", s, s + span - 1))

    # 5) [B / CUSUM] Low-and-slow: bytes_total creeps up gradually at 2pm — each
    #    step sub-threshold, so only cumulative tracking catches it.
    s = at(4, 14)
    ramp = max(span, per_day // 24 // 3)
    base_bytes = windows[s].numeric()["bytes_total"]
    for k, j in enumerate(range(s, s + ramp)):
        windows[j] = _rebuild(windows[j], bytes_total=base_bytes * (1.0 + ramp_rate * k))
    episodes.append(Episode("slow_ramp", "bytes_total", s, s + ramp - 1))

    # 7) [D / shape] Stealth exfil: total volume stays normal, but the traffic
    #    flips to almost entirely outbound — invisible to volume thresholds, but
    #    the egress-ratio shape feature stands out.
    s = at(6, 16)
    for j in range(s, s + span):
        bt = windows[j].numeric()["bytes_total"]
        windows[j] = _rebuild(windows[j], egress_bytes=int(bt * 0.95),
                              ingress_bytes=int(bt * 0.05))
    episodes.append(Episode("stealth_exfil", "egress_ratio", s, s + span - 1))

    # 6) [A / first-seen] Quiet exfil to a never-before-seen server in the evening
    #    — modest volume (invisible to thresholds), but a brand-new destination.
    s = at(5, 21)
    for j in range(s, s + span):
        dsts = dict(windows[j].all_dst_ips)
        dsts[ATTACK_IP] = 9            # small, steady
        windows[j] = _make_window(windows[j].window_end_ns,
                                   dict(windows[j].numeric()), dsts)
    episodes.append(Episode("new_dest_exfil", "new_destination", s, s + span - 1))

    ts_to_idx = {w.window_end_ns: i for i, w in enumerate(windows)}
    return Timeline(windows, episodes, ts_to_idx, warmup_idx, neutral)


# --------------------------------------------------------------------------- #
# Scoring                                                                      #
# --------------------------------------------------------------------------- #

@dataclass
class Score:
    name: str
    detected: int
    total_eps: int
    latencies: list[int]
    false_alarms: int
    eval_windows: int
    per_episode: list[tuple[str, bool, int | None]]

    @property
    def tpr(self) -> float:
        return self.detected / self.total_eps if self.total_eps else 0.0

    @property
    def fp_per_1k(self) -> float:
        return 1000 * self.false_alarms / self.eval_windows if self.eval_windows else 0.0

    @property
    def mean_latency(self) -> float | None:
        return sum(self.latencies) / len(self.latencies) if self.latencies else None


def evaluate(name: str, detectors: list, tl: Timeline, tolerance: int = 5) -> Score:
    alerts = []
    for w in tl.windows:
        for det in detectors:
            alerts.extend(det.update(w))

    def matches(alert, ep: Episode) -> bool:
        if alert.feature != ep.feature:
            return False
        idx = tl.ts_to_idx.get(alert.timestamp_ns)
        return idx is not None and ep.start_idx <= idx <= ep.end_idx + tolerance

    detected = 0
    latencies: list[int] = []
    per_episode = []
    for ep in tl.episodes:
        hit = [tl.ts_to_idx[a.timestamp_ns] for a in alerts if matches(a, ep)]
        if hit:
            detected += 1
            latencies.append(min(hit) - ep.start_idx)
            per_episode.append((ep.kind, True, min(hit) - ep.start_idx))
        else:
            per_episode.append((ep.kind, False, None))

    false_alarms = 0
    for a in alerts:
        idx = tl.ts_to_idx.get(a.timestamp_ns)
        if idx is None or idx < tl.warmup_idx or idx in tl.neutral_idx:
            continue
        if not any(matches(a, ep) for ep in tl.episodes):
            false_alarms += 1

    eval_windows = sum(1 for i in range(len(tl.windows)) if i >= tl.warmup_idx)
    return Score(name, detected, len(tl.episodes), latencies, false_alarms,
                 eval_windows, per_episode)


# --------------------------------------------------------------------------- #
# Report                                                                       #
# --------------------------------------------------------------------------- #

def _episode_latency(detectors, tl: Timeline, kind: str) -> int | None:
    s = evaluate("x", detectors, tl)
    for k, ep in enumerate(tl.episodes):
        if ep.kind == kind:
            _, hit, lat = s.per_episode[k]
            return lat if hit else None
    return None


def sweep(days: int, step_seconds: int, seed: int) -> None:
    """Confirm the low-and-slow detection never degrades to the baseline's: across
    a range of ramp steepnesses, CUSUM must catch the drift sooner than the fixed
    threshold (which only reacts once the ramp becomes a full-blown spike)."""
    per_day = DAY_S // step_seconds
    ramp_len = max(max(6, per_day // 24 // 6), per_day // 24 // 3)
    bucket_warmup = min(200, max(20, per_day // 24))
    rates = [0.010, 0.015, 0.02, 0.03, 0.05, 0.08]

    print("Low-and-slow ramp sweep — latency to detect (windows; lower is better)")
    print(f"ramp length = {ramp_len} windows; baseline reacts only as a spike\n")
    w = 16
    print(f"{'ramp/step':<12}{'x-fold':>10}{'Baseline':>{w}}{'Adaptive+CUSUM':>{w}}")
    print("-" * (12 + 10 + 2 * w))
    for rate in rates:
        tl = generate(days, step_seconds, seed, ramp_rate=rate)
        fold = 1.0 + rate * (ramp_len - 1)
        base = _episode_latency([BaselineDetector()], tl, "slow_ramp")
        cus = _episode_latency([AdaptiveDetector(threshold_mode="combined", tz=TZ,
                                warmup_windows=bucket_warmup, cusum=True)],
                               tl, "slow_ramp")
        fb = "MISS" if base is None else str(base)
        fc = "MISS" if cus is None else str(cus)
        print(f"{rate*100:>5.1f}%/step{fold:>10.1f}x{fb:>{w}}{fc:>{w}}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--step-seconds", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sweep", action="store_true",
                    help="Run the low-and-slow ramp-speed robustness sweep instead.")
    args = ap.parse_args()

    if args.sweep:
        sweep(args.days, args.step_seconds, args.seed)
        return

    tl = generate(args.days, args.step_seconds, args.seed)
    per_day = DAY_S // args.step_seconds
    bucket_warmup = min(200, max(20, per_day // 24))

    def adaptive(**kw):
        return AdaptiveDetector(threshold_mode="combined", tz=TZ,
                                warmup_windows=bucket_warmup, **kw)

    def firstseen():
        return FirstSeenDetector(store=None, learning_windows=tl.warmup_idx,
                                 min_consecutive=5, min_packets=3, tz=TZ)

    # The original detector saw only volume/count features; restrict the baseline
    # to those so the shape features' contribution (stealth_exfil) is visible.
    volume_only = ("packet_count", "bytes_total", "avg_payload_size",
                   "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
                   "tcp_count", "udp_count", "icmp_count")
    configs = [
        ("Baseline (volume, σ)",    [BaselineDetector(features=volume_only)]),
        ("Adaptive (+CUSUM+shape)", [adaptive(cusum=True)]),
        ("Full (+first-seen)",      [adaptive(cusum=True), firstseen()]),
    ]

    print(f"Synthetic timeline: {args.days} days, {len(tl.windows)} windows "
          f"({per_day}/day), {len(tl.episodes)} attacks")
    print(f"Warmup excluded from FPR: first {tl.warmup_idx} windows (2 days)\n")

    scores = [evaluate(name, dets, tl) for name, dets in configs]
    w = 24

    def row(label, cells):
        print(f"{label:<20}" + "".join(c.rjust(w) for c in cells))

    row("metric", [s.name for s in scores])
    print("-" * (20 + w * len(scores)))
    row("detection (TPR)", [f"{s.detected}/{s.total_eps} = {s.tpr:.0%}" for s in scores])
    row("false alarms", [str(s.false_alarms) for s in scores])
    row("false alarms /1k", [f"{s.fp_per_1k:.2f}" for s in scores])
    row("mean latency (win)",
        [f"{s.mean_latency:.1f}" if s.mean_latency is not None else "-" for s in scores])
    print()
    print("per-attack detection:")
    for k, ep in enumerate(tl.episodes):
        cells = []
        for s in scores:
            _, hit, lat = s.per_episode[k]
            cells.append(f"OK (lat={lat})" if hit else "MISS")
        row("  " + ep.kind, cells)


if __name__ == "__main__":
    main()
