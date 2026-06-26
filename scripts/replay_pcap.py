"""Replay a pcap through the *real* detection pipeline.

Unlike the per-flow CSV test, this reconstructs actual packets and feeds them
through exactly what the live service runs — WindowAggregator → AdaptiveDetector
(robust per-bucket Z + CUSUM + shape features) + FirstSeenDetector — so the full
stack is exercised on real traffic, just from a file instead of a live NIC.

Direction (for egress_ratio) is inferred: private->public is egress, the reverse
is ingress.

Run:  python scripts/replay_pcap.py Data/pcap/smallFlows.pcap
"""
from __future__ import annotations

import socket
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from nad.adaptive import AdaptiveDetector        # noqa: E402
from nad.behavioral import FirstSeenDetector, is_external  # noqa: E402
from nad.capture.base import Direction, Packet    # noqa: E402
from nad.features import WindowAggregator         # noqa: E402


def _direction(src: str, dst: str) -> Direction:
    s_ext, d_ext = is_external(src), is_external(dst)
    if not s_ext and d_ext:
        return Direction.EGRESS
    if s_ext and not d_ext:
        return Direction.INGRESS
    return Direction.UNKNOWN


def packets(path: str):
    with open(path, "rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            sport = dport = 0
            l4 = ip.data
            if isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                sport, dport = l4.sport, l4.dport
            payload = bytes(getattr(l4, "data", b"") or b"")[:256]
            yield Packet(
                timestamp_ns=int(ts * 1_000_000_000),
                src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                protocol=ip.p, direction=_direction(src, dst),
                payload=payload, total_len=int(ip.len),
            )


def concatenated(paths: list[str]):
    """Replay several pcaps back-to-back on one continuous clock, so an attack
    capture can be appended *after* a normal one has trained the baseline.

    Yields (packet, source_label, window_marker_for_new_file).
    """
    cursor: int | None = None      # next timeline timestamp (ns)
    for path in paths:
        first = None
        base = 0
        started = True
        for pkt in packets(path):
            if first is None:
                first = pkt.timestamp_ns
                base = (cursor + 1_000_000_000) if cursor is not None else first
            ts = base + (pkt.timestamp_ns - first)
            cursor = ts
            yield replace(pkt, timestamp_ns=ts), Path(path).name, started
            started = False


def main() -> None:
    paths = sys.argv[1:] or ["Data/pcap/smallFlows.pcap"]
    agg = WindowAggregator(window_seconds=1.0)
    det = AdaptiveDetector(threshold_mode="combined", warmup_windows=30,
                           global_warmup=20, confirm_windows=3, cusum=True)
    fs = FirstSeenDetector(store=None, learning_windows=60,
                           min_consecutive=3, min_packets=2)

    n_pkts = n_windows = 0
    alerts = []                    # (window_idx, source, alert)
    cats: Counter = Counter()
    boundaries: dict[str, int] = {}
    cur_src = ""

    def handle(w):
        nonlocal n_windows
        n_windows += 1
        for a in det.update(w) + fs.update(w):
            alerts.append((n_windows, cur_src, a))
            cats[a.category] += 1

    for pkt, src, is_new_file in concatenated(paths):
        n_pkts += 1
        if is_new_file:
            cur_src = src
            boundaries.setdefault(src, n_windows + 1)
        w = agg.add(pkt)
        if w is not None:
            handle(w)
    w = agg.flush()
    if w is not None:
        handle(w)

    print(f"pcaps: {', '.join(Path(p).name for p in paths)}")
    print(f"  packets processed : {n_pkts:,}")
    print(f"  1s windows         : {n_windows:,}")
    print(f"  file -> first window: " +
          ", ".join(f"{k}@{v}" for k, v in boundaries.items()))
    print(f"  alerts             : {len(alerts)}")
    if cats:
        print("\nalerts by category:")
        for c, k in cats.most_common():
            print(f"  {k:>3}  {c}")
    print("\nalerts (window · source · plain-language):")
    for idx, src, a in alerts:
        tag = "" if (a.baseline_std or a.baseline_mean) else " [behavioural]"
        print(f"\n  win {idx} · {src} · [{a.severity}] {a.category}{tag}")
        print(f"    {a.summary}")


if __name__ == "__main__":
    main()
