"""Time-window aggregation: packet stream → numeric feature vectors.

Higher layers (detection, dashboard) consume `WindowFeatures`. The aggregator
is allocation-light and single-threaded — wrap it from outside if you need
concurrency.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .capture.base import Direction, Packet


@dataclass(slots=True)
class WindowFeatures:
    window_start_ns: int
    window_end_ns: int
    duration_s: float
    packet_count: int
    bytes_total: int
    avg_payload_size: float
    unique_src_ips: int
    unique_dst_ips: int
    unique_dst_ports: int
    tcp_count: int
    udp_count: int
    icmp_count: int
    other_count: int
    top_src_ips: dict[str, int] = field(default_factory=dict)
    top_dst_ips: dict[str, int] = field(default_factory=dict)
    top_dst_ports: dict[int, int] = field(default_factory=dict)
    # Directional split (UNKNOWN-direction packets count toward neither). Used by
    # the behavioural classifier — e.g. egress-heavy bytes suggest exfiltration.
    egress_bytes: int = 0
    ingress_bytes: int = 0
    egress_packets: int = 0
    ingress_packets: int = 0
    # Full per-window destination IP counts (not just top-k) — the behavioural
    # first-seen detector needs every destination. Dropped from the dashboard API
    # to keep responses small; held only in memory for the current window.
    all_dst_ips: dict[str, int] = field(default_factory=dict)
    # Most ports contacted on any single destination this window — a vertical
    # port scan stands out here even when total ports look normal against busy
    # background traffic.
    max_ports_per_dst: int = 0

    def numeric(self) -> dict[str, float]:
        """Subset of fields the detector treats as time-series signals.

        Includes *shape* features (egress_ratio, fan_out) so that traffic whose
        volume looks normal but whose structure is off — e.g. a transfer that is
        almost entirely outbound (exfiltration), or one host fanning out to many
        destinations (scanning) — is anomalous in its own right, not only when it
        also spikes in volume.
        """
        directed = self.egress_bytes + self.ingress_bytes
        # Neutral 50 when direction is unavailable, so it never falsely fires.
        egress_ratio = 100.0 * self.egress_bytes / directed if directed else 50.0
        fan_out = self.unique_dst_ips / max(self.unique_src_ips, 1)
        return {
            "packet_count": float(self.packet_count),
            "bytes_total": float(self.bytes_total),
            "avg_payload_size": float(self.avg_payload_size),
            "unique_src_ips": float(self.unique_src_ips),
            "unique_dst_ips": float(self.unique_dst_ips),
            "unique_dst_ports": float(self.unique_dst_ports),
            "tcp_count": float(self.tcp_count),
            "udp_count": float(self.udp_count),
            "icmp_count": float(self.icmp_count),
            "egress_ratio": egress_ratio,
            "fan_out": float(fan_out),
            "max_ports_per_dst": float(self.max_ports_per_dst),
        }


class WindowAggregator:
    """Buckets packets into fixed-duration windows.

    `add(packet)` returns a `WindowFeatures` exactly when a packet's timestamp
    crosses into the next window — at most one closed window per call. Call
    `flush()` to drain the in-progress window (e.g. on shutdown).
    """

    def __init__(self, window_seconds: float = 1.0, top_k: int = 5) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_ns = int(window_seconds * 1_000_000_000)
        self.top_k = top_k
        self._window_start_ns: Optional[int] = None
        self._reset_buckets()

    def _reset_buckets(self) -> None:
        self._packet_count = 0
        self._bytes_total = 0
        self._payload_total = 0
        self._tcp = 0
        self._udp = 0
        self._icmp = 0
        self._other = 0
        self._egress_bytes = 0
        self._ingress_bytes = 0
        self._egress_pkts = 0
        self._ingress_pkts = 0
        self._src_ips: Counter[str] = Counter()
        self._dst_ips: Counter[str] = Counter()
        self._dst_ports: Counter[int] = Counter()
        self._ports_by_dst: dict[str, set[int]] = {}

    def _emit(self) -> WindowFeatures:
        assert self._window_start_ns is not None
        n = self._packet_count
        avg_payload = (self._payload_total / n) if n else 0.0
        feats = WindowFeatures(
            window_start_ns=self._window_start_ns,
            window_end_ns=self._window_start_ns + self.window_ns,
            duration_s=self.window_ns / 1_000_000_000,
            packet_count=n,
            bytes_total=self._bytes_total,
            avg_payload_size=avg_payload,
            unique_src_ips=len(self._src_ips),
            unique_dst_ips=len(self._dst_ips),
            unique_dst_ports=len(self._dst_ports),
            tcp_count=self._tcp,
            udp_count=self._udp,
            icmp_count=self._icmp,
            other_count=self._other,
            top_src_ips=dict(self._src_ips.most_common(self.top_k)),
            top_dst_ips=dict(self._dst_ips.most_common(self.top_k)),
            top_dst_ports=dict(self._dst_ports.most_common(self.top_k)),
            egress_bytes=self._egress_bytes,
            ingress_bytes=self._ingress_bytes,
            egress_packets=self._egress_pkts,
            ingress_packets=self._ingress_pkts,
            all_dst_ips=dict(self._dst_ips),
            max_ports_per_dst=max((len(s) for s in self._ports_by_dst.values()),
                                  default=0),
        )
        self._reset_buckets()
        return feats

    def add(self, packet: Packet) -> Optional[WindowFeatures]:
        ts = packet.timestamp_ns
        if self._window_start_ns is None:
            self._window_start_ns = ts - (ts % self.window_ns)

        emitted: Optional[WindowFeatures] = None
        if ts >= self._window_start_ns + self.window_ns:
            if self._packet_count > 0:
                emitted = self._emit()
            self._window_start_ns = ts - (ts % self.window_ns)

        self._packet_count += 1
        self._bytes_total += packet.total_len
        self._payload_total += len(packet.payload)
        proto = packet.protocol
        if proto == 6:
            self._tcp += 1
        elif proto == 17:
            self._udp += 1
        elif proto == 1:
            self._icmp += 1
        else:
            self._other += 1
        if packet.direction == Direction.EGRESS:
            self._egress_bytes += packet.total_len
            self._egress_pkts += 1
        elif packet.direction == Direction.INGRESS:
            self._ingress_bytes += packet.total_len
            self._ingress_pkts += 1
        self._src_ips[packet.src_ip] += 1
        self._dst_ips[packet.dst_ip] += 1
        if packet.dst_port:
            self._dst_ports[packet.dst_port] += 1
            self._ports_by_dst.setdefault(packet.dst_ip, set()).add(packet.dst_port)
        return emitted

    def flush(self) -> Optional[WindowFeatures]:
        if self._window_start_ns is None or self._packet_count == 0:
            return None
        feats = self._emit()
        self._window_start_ns = None
        return feats
