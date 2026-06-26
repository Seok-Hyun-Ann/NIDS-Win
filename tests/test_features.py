from __future__ import annotations

from nad.capture.base import Direction, Packet
from nad.features import WindowAggregator


def _pkt(ts_ns: int, src="10.0.0.1", dst="10.0.0.2", sp=1234, dp=80, proto=6, plen=64, total=120):
    return Packet(
        timestamp_ns=ts_ns, src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp,
        protocol=proto, direction=Direction.UNKNOWN, payload=b"\x00" * plen, total_len=total,
    )


def test_window_emits_when_boundary_crosses():
    agg = WindowAggregator(window_seconds=1.0)
    base = 1_000_000_000
    assert agg.add(_pkt(base + 0)) is None
    assert agg.add(_pkt(base + 500_000_000)) is None
    # crosses into next 1s window
    out = agg.add(_pkt(base + 1_000_000_000))
    assert out is not None
    assert out.packet_count == 2
    assert out.bytes_total == 240
    assert out.tcp_count == 2
    assert out.unique_src_ips == 1


def test_shape_features_in_numeric():
    from nad.features import WindowFeatures
    w = WindowFeatures(
        window_start_ns=0, window_end_ns=1, duration_s=1.0,
        packet_count=10, bytes_total=1000, avg_payload_size=64.0,
        unique_src_ips=2, unique_dst_ips=8, unique_dst_ports=3,
        tcp_count=10, udp_count=0, icmp_count=0, other_count=0,
        egress_bytes=900, ingress_bytes=100,
    )
    n = w.numeric()
    assert n["egress_ratio"] == 90.0          # 900 / (900+100) * 100
    assert n["fan_out"] == 4.0                # 8 dst / 2 src


def test_egress_ratio_neutral_without_direction():
    from nad.features import WindowFeatures
    w = WindowFeatures(
        window_start_ns=0, window_end_ns=1, duration_s=1.0,
        packet_count=10, bytes_total=1000, avg_payload_size=64.0,
        unique_src_ips=1, unique_dst_ips=1, unique_dst_ports=1,
        tcp_count=10, udp_count=0, icmp_count=0, other_count=0,
    )  # no egress/ingress -> neutral 50, never falsely fires
    assert w.numeric()["egress_ratio"] == 50.0


def test_window_top_k_counts():
    agg = WindowAggregator(window_seconds=1.0, top_k=3)
    base = 2_000_000_000
    for i in range(5):
        agg.add(_pkt(base + i * 1_000_000, dst=f"10.0.0.{i}"))
    out = agg.flush()
    assert out is not None
    assert out.unique_dst_ips == 5
    assert len(out.top_dst_ips) == 3


def test_protocol_buckets():
    agg = WindowAggregator(window_seconds=1.0)
    base = 3_000_000_000
    agg.add(_pkt(base, proto=6))     # tcp
    agg.add(_pkt(base, proto=17))    # udp
    agg.add(_pkt(base, proto=1))     # icmp
    agg.add(_pkt(base, proto=47))    # other
    out = agg.flush()
    assert out is not None
    assert out.tcp_count == 1
    assert out.udp_count == 1
    assert out.icmp_count == 1
    assert out.other_count == 1


def test_flush_returns_none_on_empty():
    agg = WindowAggregator(window_seconds=1.0)
    assert agg.flush() is None
