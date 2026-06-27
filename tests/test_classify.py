from __future__ import annotations

from datetime import datetime, timezone

from nad.classify import classify, severity_for
from nad.features import WindowFeatures


def _w(hour=12, egress_bytes=0, ingress_bytes=0, dst_ips=None, dst_ports=None):
    ts = int(datetime(2026, 6, 1, hour, tzinfo=timezone.utc).timestamp() * 1e9)
    return WindowFeatures(
        window_start_ns=ts, window_end_ns=ts, duration_s=1.0,
        packet_count=100, bytes_total=egress_bytes + ingress_bytes,
        avg_payload_size=64.0, unique_src_ips=1, unique_dst_ips=1,
        unique_dst_ports=1, tcp_count=100, udp_count=0, icmp_count=0,
        other_count=0, top_dst_ips=dst_ips or {}, top_dst_ports=dst_ports or {},
        egress_bytes=egress_bytes, ingress_bytes=ingress_bytes,
    )


def test_severity_bands():
    assert severity_for(4.0) == "주의"
    assert severity_for(6.5) == "경고"
    assert severity_for(12.0) == "심각"
    assert severity_for(-11.0) == "심각"   # magnitude, not sign


def test_port_scan_hypothesis():
    c = classify("unique_dst_ports", value=850, mean=8, z=9.0,
                 window=_w(dst_ports={22: 1, 23: 1, 80: 1}))
    assert c.category == "포트 스캔 의심"
    assert "포트" in c.summary
    assert c.recommendation


def test_exfiltration_needs_egress_heavy():
    eg = classify("bytes_total", value=5_000_000, mean=200_000, z=7.0,
                  window=_w(egress_bytes=5_000_000, ingress_bytes=10_000))
    assert eg.category == "데이터 유출 의심"
    # symmetric/inbound-heavy bytes spike is NOT labelled exfiltration
    inb = classify("bytes_total", value=5_000_000, mean=200_000, z=7.0,
                   window=_w(egress_bytes=10_000, ingress_bytes=5_000_000))
    assert inb.category != "데이터 유출 의심"


def test_egress_ratio_hypothesis():
    c = classify("egress_ratio", value=95, mean=30, z=8.0,
                 window=_w(egress_bytes=950000, ingress_bytes=50000))
    assert c.category == "데이터 유출 의심 (방향)"
    assert "나가는" in c.summary


def test_fan_out_hypothesis():
    c = classify("fan_out", value=40, mean=2, z=7.0, window=_w())
    assert c.category == "스캔/확산 의심"


def test_vertical_port_scan_hypothesis():
    c = classify("max_ports_per_dst", value=50, mean=3, z=8.0,
                 window=_w(dst_ips={"10.0.0.9": 50}))
    assert c.category == "포트 스캔 의심 (단일 호스트)"


def test_off_hours_activity():
    c = classify("packet_count", value=560, mean=40, z=8.0, window=_w(hour=3),
                 tz=timezone.utc)
    assert c.category == "비정상 시간대 활동"


def test_summary_has_no_jargon():
    """Plain-language summaries must not leak sigma or raw feature names."""
    for feat, z in [("unique_dst_ports", 9.0), ("bytes_total", 7.0),
                    ("packet_count", 5.0), ("udp_count", 6.0)]:
        c = classify(feat, value=1000, mean=50, z=z, window=_w())
        assert "σ" not in c.summary
        assert "_" not in c.summary          # no raw feature identifiers
        assert c.severity in ("관심", "주의", "경고", "심각")


def test_classify_never_raises_without_window():
    c = classify("packet_count", value=500, mean=50, z=5.0, window=None)
    assert c.summary and c.category
