"""Adaptive Stage-1 detector: time-bucketed baselines + self-tuning threshold.

Improves on :class:`nad.detect.BaselineDetector` along two axes (see
``docs/adaptive-detection-design.md``):

* **Time-of-day baselines.** A separate robust baseline per time bucket
  (default: weekday/weekend × hour, 48 buckets) so "Saturday-21h gaming" is
  judged against *its own* history, not a single global average that blends 3am
  idle with 9pm gaming. A cold bucket falls back to a fast-learning global
  baseline, so detection works from the first day and sharpens over time.

* **Self-tuning threshold.** Scores use a robust median/MAD Z (``RobustEwmaStat``)
  rather than mean/variance, and the cutoff is ``max(robust_k, rate_cutoff)``:
  a hard floor against noise, raised automatically by the P²-tracked high
  quantile of recent scores so alert volume stays near ``target_rate``.

Drop-in compatible with the service: same ``update() -> list[Alert]`` contract
and a JSON-serialisable ``state_snapshot()``.
"""
from __future__ import annotations

import math
from datetime import datetime, tzinfo
from typing import Iterable

from .classify import classify
from .detect import Alert, _explain
from .features import WindowFeatures
from .stats import Cusum, P2Quantile, RobustEwmaStat


def _bucketize(ts_ns: int, mode: str, tz: tzinfo | None) -> tuple[int, str]:
    """Map a window timestamp to (bucket_key, human_label) in local time."""
    dt = datetime.fromtimestamp(ts_ns / 1_000_000_000, tz)
    hour = dt.hour
    if mode == "hour":
        return hour, f"{hour:02d}h"
    if mode == "dow_hour":
        return dt.weekday() * 24 + hour, f"{_DOW[dt.weekday()]}·{hour:02d}h"
    # default: weekend_hour
    weekend = 1 if dt.weekday() >= 5 else 0
    label = "weekend" if weekend else "weekday"
    return weekend * 24 + hour, f"{label}·{hour:02d}h"


_DOW = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class AdaptiveDetector:
    """Per-(time-bucket, feature) robust baseline with an auto-tuned cutoff.

    Confirmation/cooldown filtering mirrors :class:`BaselineDetector`:
      - ``confirm_windows``: N consecutive breaches before an alert fires.
      - ``cooldown_windows``: same feature muted for M windows after an alert.
    Baselines keep learning during cooldown so a sustained legitimate shift is
    absorbed; they are *frozen* mid-streak so consecutive anomalous windows can
    confirm at a stable score.
    """

    def __init__(
        self,
        bucketing: str = "weekend_hour",      # "hour" | "weekend_hour" | "dow_hour"
        threshold_mode: str = "combined",     # "combined" | "robust" | "rate"
        target_rate: float = 0.005,
        robust_k: float = 3.5,
        alpha: float = 0.05,
        warmup_windows: int = 200,            # per-bucket warmup
        global_warmup: int = 30,              # fallback baseline warmup
        cooldown_windows: int = 10,
        confirm_windows: int = 3,
        floor: float = 1.0,
        cusum: bool = True,
        cusum_k: float = 1.0,        # slack in σ (visit-anchored residual)
        cusum_h: float = 6.0,        # decision interval: sustained drift fires
        cusum_ref_alpha: float = 0.05,  # visit-local reference tracking rate
        cusum_seed_windows: int = 8,    # windows to average into the visit anchor
        tz: tzinfo | None = None,
        features: Iterable[str] | None = None,
    ) -> None:
        self.bucketing = bucketing
        self.threshold_mode = threshold_mode
        self.target_rate = target_rate
        self.robust_k = robust_k
        self.alpha = alpha
        self.warmup_windows = warmup_windows
        self.global_warmup = global_warmup
        self.cooldown_windows = cooldown_windows
        self.confirm_windows = max(1, confirm_windows)
        self.floor = floor
        self.cusum = cusum
        self.cusum_k = cusum_k
        self.cusum_h = cusum_h
        self.cusum_ref_alpha = cusum_ref_alpha
        self.cusum_seed_windows = max(1, cusum_seed_windows)
        self.tz = tz
        self._features = tuple(features) if features else None

        self._buckets: dict[tuple[int, str], RobustEwmaStat] = {}
        self._global: dict[str, RobustEwmaStat] = {}
        self._cutoff: dict[str, P2Quantile] = {}
        self._cusum_stats: dict[tuple[int, str], Cusum] = {}
        self._cusum_ref: dict[tuple[int, str], float] = {}
        self._cusum_refscale: dict[tuple[int, str], float] = {}
        self._cusum_seed_n: dict[tuple[int, str], int] = {}
        self._prev_bucket_key: int | None = None
        self._cooldown: dict[str, int] = {}
        self._streak: dict[str, int] = {}

    # ----- internal helpers -----

    def _bucket_stat(self, bucket_key: int, name: str) -> RobustEwmaStat:
        key = (bucket_key, name)
        stat = self._buckets.get(key)
        if stat is None:
            stat = RobustEwmaStat(alpha=self.alpha, warmup=self.warmup_windows,
                                  floor=self.floor)
            self._buckets[key] = stat
        return stat

    def _global_stat(self, name: str) -> RobustEwmaStat:
        stat = self._global.get(name)
        if stat is None:
            stat = RobustEwmaStat(alpha=self.alpha, warmup=self.global_warmup,
                                  floor=self.floor)
            self._global[name] = stat
        return stat

    def _cutoff_q(self, name: str) -> P2Quantile:
        q = self._cutoff.get(name)
        if q is None:
            q = P2Quantile(1.0 - self.target_rate)
            self._cutoff[name] = q
        return q

    def _cusum_stat(self, bucket_key: int, name: str) -> Cusum:
        key = (bucket_key, name)
        cu = self._cusum_stats.get(key)
        if cu is None:
            cu = Cusum(k=self.cusum_k, h=self.cusum_h)
            self._cusum_stats[key] = cu
        return cu

    def _threshold(self, cutoff: P2Quantile) -> float:
        c = cutoff.value
        if self.threshold_mode == "robust" or math.isnan(c):
            return self.robust_k
        if self.threshold_mode == "rate":
            return max(2.5, c)          # small floor so a quiet stream isn't hair-trigger
        return max(self.robust_k, c)    # combined

    # ----- main entry -----

    def update(self, window: WindowFeatures) -> list[Alert]:
        alerts: list[Alert] = []
        bucket_key, bucket_label = _bucketize(window.window_end_ns, self.bucketing, self.tz)
        # First window after moving to a different time bucket: CUSUM re-anchors so
        # a constant day-to-day level shift isn't read as drift.
        entering_bucket = bucket_key != self._prev_bucket_key
        self._prev_bucket_key = bucket_key
        ctx_base = {
            "top_src_ips": window.top_src_ips,
            "top_dst_ips": window.top_dst_ips,
            "top_dst_ports": window.top_dst_ports,
            "window_start_ns": window.window_start_ns,
        }

        for name, value in window.numeric().items():
            if self._features and name not in self._features:
                continue

            bstat = self._bucket_stat(bucket_key, name)
            gstat = self._global_stat(name)
            cutoff = self._cutoff_q(name)

            use_fallback = not bstat.warm
            stat = gstat if use_fallback else bstat
            ready = stat.warm
            in_cooldown = self._cooldown.get(name, 0) > 0
            freeze = False

            if ready:
                z = stat.robust_z(value)
                threshold = self._threshold(cutoff)
                cutoff.update(abs(z))   # learn the score distribution every ready window

                if not in_cooldown:
                    # CUSUM tracks sub-threshold drift on the warm bucket's stream.
                    cu = (self._cusum_stat(bucket_key, name)
                          if self.cusum and not use_fallback else None)
                    if abs(z) >= threshold:
                        if cu is not None:
                            cu.reset()      # a real spike — handled by the instantaneous path
                        self._streak[name] = self._streak.get(name, 0) + 1
                        if self._streak[name] >= self.confirm_windows:
                            scale = stat.scale()
                            ctx = dict(ctx_base)
                            ctx.update({
                                "bucket": bucket_label,
                                "used_fallback": use_fallback,
                                "threshold_used": threshold,
                                "baseline_kind": "median/mad",
                            })
                            c = classify(name, value, stat.median, z, window, tz=self.tz)
                            alerts.append(Alert(
                                timestamp_ns=window.window_end_ns,
                                feature=name,
                                value=value,
                                baseline_mean=stat.median,
                                baseline_std=scale,
                                z_score=z,
                                direction="above" if z > 0 else "below",
                                explanation=_explain(name, value, stat.median, scale, z, ctx),
                                context=ctx,
                                category=c.category,
                                severity=c.severity,
                                summary=c.summary,
                                recommendation=c.recommendation,
                            ))
                            self._cooldown[name] = self.cooldown_windows
                            self._streak[name] = 0
                        else:
                            freeze = True   # hold baseline so the streak can confirm
                    else:
                        self._streak[name] = 0
                        if cu is not None:
                            key = (bucket_key, name)
                            if entering_bucket or key not in self._cusum_ref:
                                # Start a fresh anchor for this visit. A constant
                                # day-to-day level shift then yields ~zero residual;
                                # only real within-visit drift accumulates.
                                self._cusum_ref[key] = value
                                self._cusum_refscale[key] = 0.0
                                self._cusum_seed_n[key] = 1
                                cu.reset()
                            else:
                                n = self._cusum_seed_n.get(key, self.cusum_seed_windows)
                                ref = self._cusum_ref[key]
                                dev = abs(value - ref)
                                a = self.cusum_ref_alpha
                                if n < self.cusum_seed_windows:
                                    # Seeding: build the visit anchor (mean) and its
                                    # *within-visit* spread, then score later. Using
                                    # the local spread — not the mood-inflated bucket
                                    # scale — keeps drift detection consistent.
                                    self._cusum_ref[key] = ref + (value - ref) / (n + 1)
                                    rs = self._cusum_refscale[key]
                                    self._cusum_refscale[key] = rs + (dev - rs) / (n + 1)
                                    self._cusum_seed_n[key] = n + 1
                                else:
                                    scale = max(1.4826 * self._cusum_refscale[key],
                                                self.floor)
                                    zr = (value - ref) / scale
                                    cu.update(zr)
                                    self._cusum_ref[key] = ref + a * (value - ref)
                                    self._cusum_refscale[key] += a * (dev - self._cusum_refscale[key])
                                    if cu.breached:
                                        alerts.append(self._cusum_alert(
                                            name, value, stat, cu.direction, z,
                                            bucket_label, ctx_base, window))
                                        cu.reset()
                                        self._cooldown[name] = self.cooldown_windows

            if in_cooldown:
                self._cooldown[name] -= 1

            # Freeze only the baseline being *scored* (so a streak confirms at a
            # stable Z); the other keeps learning. Critically, a cold bucket must
            # keep warming up even while the global fallback is mid-streak, or it
            # would starve and never take over.
            if use_fallback:
                bstat.update(value)
                if not freeze:
                    gstat.update(value)
            else:
                if not freeze:
                    bstat.update(value)
                gstat.update(value)

        return alerts

    def _cusum_alert(self, name: str, value: float, stat: RobustEwmaStat,
                     direction: str, z: float, bucket_label: str,
                     ctx_base: dict, window: WindowFeatures) -> Alert:
        scale = stat.scale()
        ctx = dict(ctx_base)
        ctx.update({"bucket": bucket_label, "baseline_kind": "median/mad",
                    "detector": "cusum"})
        trend = "증가" if direction == "above" else "감소"
        summary = (
            f"한 번에 튀지는 않지만 평소보다 조금씩 높은(또는 낮은) 상태가 오래 "
            f"이어져 누적 변화가 감지됐습니다(완만한 {trend}). 순간값이 작아 일반 "
            f"탐지에는 안 걸리지만, 느린 데이터 유출이나 점진적 침입의 신호일 수 있습니다."
        )
        return Alert(
            timestamp_ns=window.window_end_ns,
            feature=name,
            value=value,
            baseline_mean=stat.median,
            baseline_std=scale,
            z_score=z,
            direction=direction,
            explanation=(f"CUSUM drift on {name}: sustained sub-threshold "
                         f"{trend} (current z={z:.2f}, bucket {bucket_label})"),
            context=ctx,
            category=f"완만한 지속 {trend}",
            severity="경고",
            summary=summary,
            recommendation="최근 통신량이 서서히 변한 원인(백그라운드 전송 등)을 확인하세요.",
        )

    def state_snapshot(self) -> dict:
        """JSON-serialisable view for the dashboard: per-bucket baselines,
        global fallbacks, and the current auto-tuned cutoff per feature."""
        buckets: dict[str, dict] = {}
        for (bkey, name), s in self._buckets.items():
            buckets.setdefault(str(bkey), {})[name] = {
                "median": s.median, "scale": s.scale(), "n": s.n, "warm": s.warm,
            }
        return {
            "mode": self.threshold_mode,
            "bucketing": self.bucketing,
            "global": {
                name: {"median": s.median, "scale": s.scale(), "n": s.n, "warm": s.warm}
                for name, s in self._global.items()
            },
            "cutoff": {
                name: (None if math.isnan(q.value) else q.value)
                for name, q in self._cutoff.items()
            },
            "buckets": buckets,
        }
