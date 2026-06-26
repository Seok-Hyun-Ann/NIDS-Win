"""Unsupervised test of the robust statistical core on UNSW-NB15.

These public datasets are *per-flow* feature tables, while the live system is a
*streaming, time-windowed, single-host* detector — different paradigms, so this
can't exercise the time-of-day buckets or CUSUM faithfully. What it *can* do is
test the heart of the engine — the robust median/MAD Z-score (``RobustEwmaStat``)
— as an unsupervised anomaly detector:

    1. learn a baseline from NORMAL flows only,
    2. freeze it,
    3. score held-out normal + attack flows by how far they deviate,
    4. measure how well that separates attack from normal (TPR / FPR / AUC),
       with a per-attack-category breakdown.

Only the columns that map to our notion of a flow are used; single-flow features
like unique-destination counts are meaningless here and excluded.

Run:  python scripts/eval_unsw.py
"""
from __future__ import annotations

import csv
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from nad.stats import RobustEwmaStat          # noqa: E402

CSV = Path(__file__).resolve().parent.parent / "Data" / "UNSWNB15_TEST1.csv"
THRESHOLD = 3.5     # our robust_k: flag a flow if any feature is >= this many robust-σ


def _f(x: str) -> float:
    try:
        return float(x)
    except (ValueError, TypeError):
        return 0.0


def _log(x: float) -> float:
    return math.log1p(max(0.0, x))   # heavy-tailed magnitudes span orders of mag


def features(row: dict) -> dict[str, float]:
    spkts, dpkts = _f(row["spkts"]), _f(row["dpkts"])
    sbytes, dbytes = _f(row["sbytes"]), _f(row["dbytes"])
    pkts, byt = spkts + dpkts, sbytes + dbytes
    return {
        "packet_count": _log(pkts),
        "bytes_total": _log(byt),
        "bytes_per_pkt": _log(byt / max(pkts, 1.0)),
        "egress_ratio": 100.0 * sbytes / byt if byt > 0 else 50.0,
        "rate": _log(_f(row["rate"])),
        "sload": _log(_f(row["sload"])),
        "dload": _log(_f(row["dload"])),
        "dur": _log(_f(row["dur"])),
    }
    # NB: TTL fields (sttl/dttl) are discrete/multimodal — their MAD collapses to
    # zero and breaks the robust Z; excluded as inappropriate for this estimator.


def main() -> None:
    rng = random.Random(42)
    normals, attacks = [], []
    with open(CSV, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            rec = (features(row), row["attack_cat"])
            (normals if row["label"] == "0" else attacks).append(rec)

    rng.shuffle(normals)
    n_train = int(len(normals) * 0.7)
    train = normals[:n_train]
    test = normals[n_train:] + attacks
    rng.shuffle(test)
    feat_names = list(train[0][0].keys())

    # 1-2) learn a baseline from NORMAL flows, then freeze.
    stats = {name: RobustEwmaStat(alpha=0.02, warmup=1) for name in feat_names}
    for f, _ in train:
        for name in feat_names:
            stats[name].update(f[name])

    import bisect

    def auc_of(atk_s: list[float], nrm_s: list[float]) -> float:
        """Rank-based AUC: P(random attack scores above a random normal)."""
        nrm_s = sorted(nrm_s)
        return sum(bisect.bisect_left(nrm_s, s) +
                   (bisect.bisect_right(nrm_s, s) - bisect.bisect_left(nrm_s, s)) * 0.5
                   for s in atk_s) / (len(atk_s) * len(nrm_s))

    # 3) score held-out flows: per-feature robust deviation + combined max.
    per_feat_atk = {n: [] for n in feat_names}
    per_feat_nrm = {n: [] for n in feat_names}
    comb_atk, comb_nrm = [], []
    for f, cat in test:
        zs = {n: abs(stats[n].robust_z(f[n])) for n in feat_names}
        is_atk = cat != "Normal"
        for n in feat_names:
            (per_feat_atk if is_atk else per_feat_nrm)[n].append(zs[n])
        (comb_atk if is_atk else comb_nrm).append(max(zs.values()))

    print(f"UNSW-NB15  train(normal)={len(train):,}  test={len(test):,} "
          f"(normal {len(comb_nrm):,} / attack {len(comb_atk):,})")
    print("Unsupervised: baseline learned from NORMAL flows only, then frozen.\n")

    print("per-feature separability (AUC — attack vs normal, threshold-free):")
    rows = sorted(((auc_of(per_feat_atk[n], per_feat_nrm[n]), n) for n in feat_names),
                  reverse=True)
    for a, n in rows:
        bar = "#" * int(40 * (a - 0.5) / 0.5)
        print(f"  {n:<16}{a:.3f}  {bar}")
    print(f"\ncombined (max over features) AUC: {auc_of(comb_atk, comb_nrm):.3f}")


if __name__ == "__main__":
    main()
