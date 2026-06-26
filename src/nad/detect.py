"""Stage-1 statistical detector.

Per-feature online EWMA mean and variance. When a fresh window's value is
more than `z_threshold` standard deviations from its baseline, an `Alert` is
emitted with a templated explanation. Pure stdlib, no ML.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Iterable

from .classify import classify
from .features import WindowFeatures


@dataclass(slots=True)
class Alert:
    timestamp_ns: int
    feature: str
    value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    direction: str          # "above" or "below"
    explanation: str        # technical detail (sigma, feature name) — for analysts
    context: dict = field(default_factory=dict)
    # Plain-language layer for non-experts (filled by nad.classify).
    category: str = ""          # named hypothesis, e.g. "포트 스캔 의심"
    severity: str = ""          # 관심 | 주의 | 경고 | 심각
    summary: str = ""           # everyday-Korean, with real numbers, no jargon
    recommendation: str = ""    # what to do

    def to_dict(self) -> dict:
        return {
            "timestamp_ns": self.timestamp_ns,
            "feature": self.feature,
            "value": self.value,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "z_score": self.z_score,
            "direction": self.direction,
            "explanation": self.explanation,
            "context": self.context,
            "category": self.category,
            "severity": self.severity,
            "summary": self.summary,
            "recommendation": self.recommendation,
        }


class _EwmaStat:
    """Online EWMA mean/variance — West (1979) recurrence adapted for EWMA.

    Holds enough state for a Z-score after `warmup` updates.
    """
    __slots__ = ("alpha", "mean", "var", "n")

    def __init__(self, alpha: float) -> None:
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> None:
        if self.n == 0:
            self.mean = x
            self.var = 0.0
        else:
            delta = x - self.mean
            self.mean = (1 - self.alpha) * self.mean + self.alpha * x
            self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)
        self.n += 1

    def zscore(self, x: float) -> float:
        std = math.sqrt(self.var)
        # Floor std at 1.0 so a *flat* baseline (e.g. unique_dst_ports stuck
        # at 0) doesn't explode into infinite Z-scores on the first deviation.
        return (x - self.mean) / max(std, 1.0)


_FEATURE_LABELS = {
    "packet_count":     ("패킷 수",          "packets/window"),
    "bytes_total":      ("총 바이트",        "bytes/window"),
    "avg_payload_size": ("평균 페이로드",    "bytes"),
    "unique_src_ips":   ("고유 출발지 IP",   "IPs"),
    "unique_dst_ips":   ("고유 목적지 IP",   "IPs"),
    "unique_dst_ports": ("고유 목적지 포트", "ports"),
    "tcp_count":        ("TCP 패킷 수",      "packets/window"),
    "udp_count":        ("UDP 패킷 수",      "packets/window"),
    "icmp_count":       ("ICMP 패킷 수",     "packets/window"),
    "egress_ratio":     ("나가는 데이터 비율", "%"),
    "fan_out":          ("목적지 분산도",     "dst/src"),
}


def _format_value(x: float) -> str:
    if x >= 100:
        return f"{x:,.0f}"
    if x >= 1:
        return f"{x:,.1f}"
    return f"{x:.3f}"


def _explain(feature: str, value: float, mean: float, std: float, z: float, ctx: dict) -> str:
    label, unit = _FEATURE_LABELS.get(feature, (feature, ""))
    direction_kr = "초과" if z > 0 else "미만"
    parts = [
        f"{label} — 평소 대비 {abs(z):.1f}σ {direction_kr} "
        f"(현재 {_format_value(value)} {unit}, 기준 {_format_value(mean)} ±{_format_value(std)})."
    ]
    top_src = ctx.get("top_src_ips") or {}
    if top_src:
        ips = ", ".join(f"{ip}({cnt})" for ip, cnt in list(top_src.items())[:3])
        parts.append(f"주요 출발지: {ips}.")
    top_ports = ctx.get("top_dst_ports") or {}
    if top_ports:
        ports = ", ".join(f"{p}({c})" for p, c in list(top_ports.items())[:3])
        parts.append(f"주요 목적지 포트: {ports}.")
    return " ".join(parts)


class BaselineDetector:
    """Per-feature EWMA Z-score with consecutive-window confirmation.

    Two filters reduce false positives from bursty-but-legitimate traffic:
      - `confirm_windows`: a feature must breach the threshold for N consecutive
        windows before an alert is emitted (a 1-window blip won't trigger).
      - `cooldown_windows`: after an alert, the same feature is muted for M
        windows. EWMA continues to update during cooldown, so a sustained
        legitimate change (gaming + streaming) is absorbed into the baseline
        and stops re-firing.
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        alpha: float = 0.1,
        warmup_windows: int = 30,
        cooldown_windows: int = 10,
        confirm_windows: int = 3,
        features: Iterable[str] | None = None,
    ) -> None:
        self.z_threshold = z_threshold
        self.alpha = alpha
        self.warmup_windows = warmup_windows
        self.cooldown_windows = cooldown_windows
        self.confirm_windows = max(1, confirm_windows)
        self._stats: dict[str, _EwmaStat] = {}
        self._cooldown: dict[str, int] = {}
        self._streak: dict[str, int] = {}
        self._features = tuple(features) if features else None

    def update(self, window: WindowFeatures) -> list[Alert]:
        alerts: list[Alert] = []
        ctx_full = {
            "top_src_ips": window.top_src_ips,
            "top_dst_ips": window.top_dst_ips,
            "top_dst_ports": window.top_dst_ports,
            "window_start_ns": window.window_start_ns,
        }
        for name, value in window.numeric().items():
            if self._features and name not in self._features:
                continue
            stat = self._stats.setdefault(name, _EwmaStat(self.alpha))

            in_cooldown = self._cooldown.get(name, 0) > 0
            warm = stat.n >= self.warmup_windows
            update_stat = True

            if warm and not in_cooldown:
                z = stat.zscore(value)
                if abs(z) >= self.z_threshold:
                    self._streak[name] = self._streak.get(name, 0) + 1
                    if self._streak[name] >= self.confirm_windows:
                        std = math.sqrt(stat.var)
                        c = classify(name, value, stat.mean, z, window)
                        alerts.append(Alert(
                            timestamp_ns=window.window_end_ns,
                            feature=name,
                            value=value,
                            baseline_mean=stat.mean,
                            baseline_std=std,
                            z_score=z,
                            direction="above" if z > 0 else "below",
                            explanation=_explain(name, value, stat.mean, std, z, ctx_full),
                            context=ctx_full,
                            category=c.category,
                            severity=c.severity,
                            summary=c.summary,
                            recommendation=c.recommendation,
                        ))
                        self._cooldown[name] = self.cooldown_windows
                        self._streak[name] = 0
                    else:
                        # Mid-streak: freeze baseline so consecutive anomalous
                        # windows can keep the same Z-score and confirm.
                        update_stat = False
                else:
                    self._streak[name] = 0

            if in_cooldown:
                self._cooldown[name] -= 1
            if update_stat:
                stat.update(value)
        return alerts

    def state_snapshot(self) -> dict:
        return {
            name: {"mean": s.mean, "std": math.sqrt(s.var), "n": s.n}
            for name, s in self._stats.items()
        }
