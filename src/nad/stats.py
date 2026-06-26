"""Streaming robust statistics for adaptive detection.

Two stdlib-only online estimators used by :mod:`nad.adaptive`:

* :class:`RobustEwmaStat` — EWMA median + MAD, giving a robust Z-score whose
  scale is *not* inflated by the very bursts we want to flag (unlike the
  mean/variance estimator in :mod:`nad.detect`).
* :class:`P2Quantile` — the P² algorithm (Jain & Chlamtac, 1985) for tracking a
  single quantile of a stream in O(1) memory. Feeds the false-alarm-rate
  controller: the q-quantile of recent |Z| scores becomes the alert cutoff.

Both are single-threaded; wrap from outside if you need concurrency.
"""
from __future__ import annotations

import math
from statistics import median as _exact_median


def _sign(x: float) -> float:
    if x > 0.0:
        return 1.0
    if x < 0.0:
        return -1.0
    return 0.0


class RobustEwmaStat:
    """Online robust location/scale via EWMA median and MAD.

    The first ``init_size`` samples are buffered and used to *seed* an exact
    median and MAD (avoids the cold-start where a zero MAD freezes the sign
    update). After that both location and scale use *sign* updates, so a single
    huge spike moves each by at most one bounded step regardless of its
    magnitude — that is what keeps the scale honest:

        step    = alpha * max(mad, floor)
        median += step * sign(x - median)
        mad    += step * sign(|x - median| - mad)   # tracks median(|x - median|)

    ``robust_z(x)`` is ``(x - median) / scale`` where ``scale = max(k*mad,
    floor)``. With ``k = 1.4826`` the scale matches the standard deviation for
    Gaussian data, so a threshold near 3.5 is comparable to the 3σ of the
    legacy detector — but robust to outliers.
    """

    __slots__ = ("alpha", "k", "floor", "warmup", "init_size",
                 "median", "mad", "n", "_buf")

    def __init__(
        self,
        alpha: float = 0.05,
        k: float = 1.4826,
        floor: float = 1.0,
        warmup: int = 200,
        init_size: int = 32,
    ) -> None:
        self.alpha = alpha
        self.k = k
        self.floor = floor
        self.warmup = warmup
        self.init_size = max(2, init_size)
        self.median = 0.0
        self.mad = 0.0
        self.n = 0
        self._buf: list[float] | None = []

    def update(self, x: float) -> None:
        self.n += 1
        if self._buf is not None:
            self._buf.append(x)
            # Provisional exact estimates while seeding.
            self.median = _exact_median(self._buf)
            self.mad = _exact_median([abs(v - self.median) for v in self._buf])
            if len(self._buf) >= self.init_size:
                self._buf = None  # switch to streaming updates
            return
        dev = abs(x - self.median)
        step = self.alpha * max(self.mad, self.floor)
        self.median += step * _sign(x - self.median)
        self.mad += step * _sign(dev - self.mad)
        if self.mad < 0.0:
            self.mad = 0.0

    def scale(self) -> float:
        """Robust 1σ-equivalent spread, floored to avoid div-by-zero."""
        return max(self.k * self.mad, self.floor)

    def robust_z(self, x: float) -> float:
        return (x - self.median) / self.scale()

    @property
    def warm(self) -> bool:
        return self.n >= self.warmup


class Cusum:
    """Two-sided tabular CUSUM control chart on a standardized residual stream.

    Detects a small *persistent* shift that an instantaneous threshold misses and
    a fast EWMA would absorb — the low-and-slow signature. Each standardized
    residual ``z`` nudges two accumulators:

        hi = max(0, hi + z - k)        # upward drift
        lo = max(0, lo - z - k)        # downward drift

    ``k`` (slack, in sigma) is the per-step allowance that absorbs noise; the
    chart only climbs when deviations are consistent. A breach is ``hi > h`` or
    ``lo > h`` (decision interval). One-off blips don't accumulate; a steady
    creep does.
    """

    __slots__ = ("k", "h", "hi", "lo")

    def __init__(self, k: float = 0.5, h: float = 5.0) -> None:
        self.k = k
        self.h = h
        self.hi = 0.0
        self.lo = 0.0

    def update(self, z: float) -> None:
        self.hi = max(0.0, self.hi + z - self.k)
        self.lo = max(0.0, self.lo - z - self.k)

    @property
    def breached(self) -> bool:
        return self.hi > self.h or self.lo > self.h

    @property
    def direction(self) -> str:
        return "above" if self.hi >= self.lo else "below"

    @property
    def active(self) -> bool:
        """True while accumulating — used to hold the baseline so EWMA doesn't
        quietly absorb the very drift we're trying to accumulate."""
        return self.hi > 0.0 or self.lo > 0.0

    def reset(self) -> None:
        self.hi = 0.0
        self.lo = 0.0


class P2Quantile:
    """Single-quantile estimator via the P² algorithm.

    Tracks the ``p``-quantile of a stream using five markers, no buffering. Used
    to set an adaptive alert cutoff: feed it |Z| scores and read ``value`` as
    the score below which ``p`` of traffic falls.
    """

    __slots__ = ("p", "_q", "_n", "_np", "_dn", "count", "_init")

    def __init__(self, p: float) -> None:
        if not 0.0 < p < 1.0:
            raise ValueError("p must be in (0, 1)")
        self.p = p
        self.count = 0
        self._init: list[float] = []
        self._q: list[float] = []
        self._n: list[int] = []
        self._np: list[float] = []
        self._dn: list[float] = []

    def update(self, x: float) -> None:
        self.count += 1
        if self._q == []:
            self._init.append(x)
            if len(self._init) == 5:
                self._init.sort()
                p = self.p
                self._q = list(self._init)
                self._n = [0, 1, 2, 3, 4]
                self._np = [0.0, 2.0 * p, 4.0 * p, 2.0 + 2.0 * p, 4.0]
                self._dn = [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0]
                self._init = []
            return

        q, n = self._q, self._n
        # Locate the cell k that x falls into, extending the min/max markers.
        if x < q[0]:
            q[0] = x
            k = 0
        elif x < q[1]:
            k = 0
        elif x < q[2]:
            k = 1
        elif x < q[3]:
            k = 2
        elif x <= q[4]:
            k = 3
        else:
            q[4] = x
            k = 3

        for i in range(k + 1, 5):
            n[i] += 1
        for i in range(5):
            self._np[i] += self._dn[i]

        for i in range(1, 4):
            d = self._np[i] - n[i]
            if (d >= 1.0 and n[i + 1] - n[i] > 1) or (d <= -1.0 and n[i - 1] - n[i] < -1):
                ds = 1 if d > 0 else -1
                qp = self._parabolic(i, ds)
                if q[i - 1] < qp < q[i + 1]:
                    q[i] = qp
                else:
                    q[i] = self._linear(i, ds)
                n[i] += ds

    def _parabolic(self, i: int, d: int) -> float:
        q, n = self._q, self._n
        return q[i] + d / (n[i + 1] - n[i - 1]) * (
            (n[i] - n[i - 1] + d) * (q[i + 1] - q[i]) / (n[i + 1] - n[i])
            + (n[i + 1] - n[i] - d) * (q[i] - q[i - 1]) / (n[i] - n[i - 1])
        )

    def _linear(self, i: int, d: int) -> float:
        q, n = self._q, self._n
        return q[i] + d * (q[i + d] - q[i]) / (n[i + d] - n[i])

    @property
    def value(self) -> float:
        """Current quantile estimate. During warmup (<5 samples) returns the
        running max of seen values, or NaN if empty."""
        if self._q:
            return self._q[2]
        if self._init:
            return max(self._init)
        return math.nan
