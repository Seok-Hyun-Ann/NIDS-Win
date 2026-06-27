"""Turn a raw statistical anomaly into a plain-language, actionable hypothesis.

The detector knows *that* a feature deviated and by how many sigma — useful to an
analyst, opaque to everyone else. This module maps the deviating feature plus
window context (protocol mix, traffic direction, time of day, top talkers) to:

  * a **category** — a named guess at what kind of event this is (port scan,
    data exfiltration, off-hours activity, ...),
  * a **severity** — 관심 / 주의 / 경고 / 심각 (info → critical),
  * a **summary** — one or two everyday-Korean sentences with real numbers and
    *no* jargon (no "sigma", no raw feature names),
  * a **recommendation** — what a non-expert should actually do.

It is rule-based, not ML: transparent and easy to extend. This is the Stage-1.5
"what is it?" layer, deliberately lighter than a full signature engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import Optional

from .features import WindowFeatures


@dataclass(slots=True)
class Classification:
    category: str          # short label, e.g. "포트 스캔 의심"
    severity: str          # 관심 | 주의 | 경고 | 심각
    summary: str           # plain-language, with concrete numbers
    recommendation: str    # what to do


_SEVERITY_ICON = {"관심": "🟡", "주의": "🟡", "경고": "🟠", "심각": "🔴"}


def severity_for(z: float) -> str:
    az = abs(z)
    if az >= 10:
        return "심각"
    if az >= 6:
        return "경고"
    if az >= 4:
        return "주의"
    return "관심"


def _human_bytes(n: float) -> str:
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f}{unit}"
    return f"{n:.0f}B"


def _times_phrase(value: float, mean: float) -> str:
    """e.g. '평소의 약 18배' (above) or '평소의 약 30%로 감소' (below)."""
    if mean <= 0:
        return "평소엔 거의 없던 수준"
    r = value / mean
    if r >= 1.5:
        return f"평소의 약 {r:.0f}배" if r >= 3 else f"평소의 약 {r:.1f}배"
    if r <= 0.7:
        return f"평소의 약 {r * 100:.0f}%로 감소"
    return f"평소({mean:.0f}) 대비 변화"


def _top(d: Optional[dict], n: int = 3) -> str:
    if not d:
        return ""
    return ", ".join(str(k) for k in list(d.keys())[:n])


def _is_night(ts_ns: int, tz: tzinfo | None) -> bool:
    h = datetime.fromtimestamp(ts_ns / 1_000_000_000, tz).hour
    return h < 6 or h >= 23


def classify(
    feature: str,
    value: float,
    mean: float,
    z: float,
    window: WindowFeatures | None = None,
    tz: tzinfo | None = None,
) -> Classification:
    """Map an anomaly to a human-readable hypothesis. Never raises."""
    severity = severity_for(z)
    above = z > 0
    times = _times_phrase(value, mean)

    # Directionality (only meaningful when we have the window).
    eg = window.egress_bytes if window else 0
    ig = window.ingress_bytes if window else 0
    egress_heavy = eg > max(ig * 3, 1)
    ingress_heavy = ig > max(eg * 3, 1)
    night = window is not None and _is_night(window.window_end_ns, tz)
    dst_ips = _top(window.top_dst_ips if window else None)
    dst_ports = _top(window.top_dst_ports if window else None)

    # ----- rules: most specific first -----
    if feature == "egress_ratio" and above:
        return Classification(
            "데이터 유출 의심 (방향)", severity,
            f"전체 양은 평소와 비슷한데 **나가는 방향**의 비율이 비정상적으로 높습니다 "
            f"(현재 {value:.0f}%). 평소엔 받는 데이터가 많은데, 지금은 대부분 바깥으로 "
            f"나가고 있어 정보 유출일 수 있습니다." + (f" 주요 대상: {dst_ips}." if dst_ips else ""),
            "보낸 적 없는 업로드라면 즉시 연결을 끊고 점검하세요.")

    if feature == "fan_out" and above:
        return Classification(
            "스캔/확산 의심", severity,
            f"한 대가 평소보다 훨씬 많은 대상과 동시에 통신하고 있습니다(목적지 분산도 "
            f"{times}). 총량은 크지 않아도 네트워크 스캔이나 감염 확산일 수 있습니다.",
            "예상치 못한 동작이면 백신 검사를 권장합니다.")

    if feature == "max_ports_per_dst" and above:
        return Classification(
            "포트 스캔 의심 (단일 호스트)", severity,
            f"한 대상에 대해 짧은 시간에 많은 포트({value:.0f}개)로 접속을 시도했습니다 "
            f"({times}). 특정 기기의 열린 포트를 훑는 수직 포트 스캔일 수 있습니다."
            + (f" 대상: {dst_ips}." if dst_ips else ""),
            "의심되면 해당 대상과의 연결을 차단하고 점검하세요.")

    if feature == "unique_dst_ports" and above:
        return Classification(
            "포트 스캔 의심", severity,
            f"이 컴퓨터가 짧은 시간에 매우 많은 포트(통신 창구)에 접속을 시도했습니다 "
            f"({value:.0f}개, {times}). 누군가 열린 통로를 찾고 있거나 악성코드가 "
            f"퍼지려는 행동일 수 있습니다." + (f" 대상: {dst_ips}." if dst_ips else ""),
            "의심되면 네트워크 연결을 잠시 끊고 백신 검사를 실행하세요.")

    if feature == "unique_src_ips" and above:
        return Classification(
            "분산 공격(DDoS)/출발지 위조 의심", severity,
            f"갑자기 매우 많은 서로 다른 출발지에서 트래픽이 쏟아지고 있습니다 "
            f"({value:.0f}곳, {times}). 분산 서비스 거부(DDoS) 공격이나 출발지 "
            f"위조(spoofing)일 수 있습니다.",
            "지속되면 인터넷 연결을 차단하고 네트워크 관리자에게 알리세요.")

    if feature == "unique_dst_ips" and above:
        return Classification(
            "다수 호스트 접속", severity,
            f"평소보다 훨씬 많은 서버/기기와 통신했습니다 ({value:.0f}곳, {times}). "
            f"네트워크 스캔이나 감염 확산일 수 있습니다.",
            "예상치 못한 동작이면 백신 검사를 권장합니다.")

    if feature == "bytes_total" and above and egress_heavy:
        return Classification(
            "데이터 유출 의심", severity,
            f"밖으로 나가는 데이터가 {times} 많습니다(이번 구간 {_human_bytes(eg)} 전송). "
            f"파일이나 정보가 외부로 빠져나가는 중일 수 있습니다."
            + (f" 주요 대상: {dst_ips}." if dst_ips else ""),
            "보낸 적 없는 대용량 업로드라면 즉시 연결을 끊고 점검하세요.")

    if feature == "bytes_total" and above:
        return Classification(
            "데이터 사용량 급증", severity,
            f"주고받은 데이터 양이 {times} 많습니다(이번 구간 "
            f"{_human_bytes(value)}). 대용량 다운로드/업데이트일 수도, "
            f"비정상 전송일 수도 있습니다.",
            "방금 한 작업(다운로드/스트리밍)으로 설명되지 않으면 살펴보세요.")

    if feature == "avg_payload_size" and above:
        return Classification(
            "비정상적으로 큰 패킷", severity,
            f"오가는 데이터 한 덩어리의 크기가 {times} 큽니다. 대용량 전송이나 "
            f"숨겨진 터널 통신일 수 있습니다.",
            "원인이 분명치 않으면 어떤 프로그램이 통신 중인지 확인하세요.")

    if feature == "icmp_count" and above:
        return Classification(
            "ICMP 급증", severity,
            f"네트워크 점검용(핑 등) 신호가 {times} 늘었습니다. 네트워크 탐색이나 "
            f"비정상 통신의 신호일 수 있습니다.",
            "반복되면 네트워크 관리자에게 문의하세요.")

    if feature == "udp_count" and above:
        return Classification(
            "UDP 트래픽 폭주", severity,
            f"UDP 통신이 {times} 늘었습니다. 영상/게임 스트리밍일 수도, "
            f"공격(플러딩)일 수도 있습니다." + (f" 대상 포트: {dst_ports}." if dst_ports else ""),
            "스트리밍/게임 중이 아니라면 주의 깊게 살펴보세요.")

    if feature in ("packet_count", "tcp_count") and above and night:
        return Classification(
            "비정상 시간대 활동", severity,
            f"평소 한가한 시간대(심야)에 트래픽이 {times} 많습니다. 이 시간엔 "
            f"드문 활동이라 자동 작업이나 외부 침입을 의심할 수 있습니다."
            + (f" 대상: {dst_ips}." if dst_ips else ""),
            "예약 작업(백업/업데이트)이 아니라면 점검을 권장합니다.")

    if feature in ("packet_count", "tcp_count") and above:
        return Classification(
            "트래픽 급증", severity,
            f"전체 통신량이 {times} 많습니다. 평소와 다른 프로그램이 활발히 "
            f"통신하고 있을 수 있습니다.",
            "방금 한 작업으로 설명되지 않으면 살펴보세요.")

    if not above:
        return Classification(
            "트래픽 급감", severity,
            f"통신량이 {times}했습니다. 인터넷 연결 문제나 서비스 중단일 수 있습니다.",
            "인터넷 연결 상태를 확인하세요.")

    # fallback
    return Classification(
        "비정상 패턴", severity,
        f"네트워크 사용 패턴이 평소와 다릅니다 ({times}). 원인을 확인해 보세요.",
        "반복되거나 의심되면 백신 검사를 권장합니다.")


def severity_icon(severity: str) -> str:
    return _SEVERITY_ICON.get(severity, "🟡")
