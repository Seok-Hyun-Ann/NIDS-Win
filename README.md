# NIDS-Win(네트워크 침입 탐지 시스템-윈도우용) — Network Anomaly Detector for Windows

[![CI](https://github.com/Seok-Hyun-Ann/NIDS-Win/actions/workflows/ci.yml/badge.svg)](https://github.com/Seok-Hyun-Ann/NIDS-Win/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Host-resident network anomaly detector for Windows with **explainable alerts**.
Captures live traffic on a chosen interface, learns a baseline of normal
behavior **separately for each time of day**, flags anomalies, and ships every
alert with both a plain-language verdict and the statistical reason behind it.
Runs entirely on your machine — no telemetry, no external services, no ML model
in the detection path. Pure standard-library statistics.

A live web dashboard (FastAPI + vanilla JS) shows current throughput, an alert
timeline, top talkers, and click-to-expand details for each alert.

## Why this project?

Most consumer-grade IDS/EDR tools give you alerts that boil down to "we noticed
something." They rarely tell you *why*, and a single fixed threshold either
floods you with false alarms or misses real attacks — because people don't use a
computer the same way every day. NIDS-Win takes the opposite approach:

- **Per-time-of-day baselines** — it learns a separate baseline for each hour
  bucket, so "9pm gaming" is normal at 9pm but the same traffic at 3am is not.
- **The threshold tunes itself** — instead of a hand-picked sigma, the cutoff is
  set from the data to target a false-alarm *rate*. No magic number to guess.
- **Robust to evasion** — median/MAD statistics mean a burst can't inflate the
  baseline and blind the next detection.
- **Every alert is explained twice** — an everyday-Korean verdict for anyone
  ("데이터 유출 의심 — 평소의 약 18배"), and the exact statistics for analysts.
- **On-device and inspectable** — the whole detection path is plain Python you
  can read; nothing leaves the machine.

## Detection capabilities

Two complementary axes, so an attack that hides from one is caught by the other:

| Attack pattern | How it's caught | Component |
|---|---|---|
| Sudden spike (port scan, volumetric exfil, DDoS) | per-time-bucket robust Z-score | `AdaptiveDetector` |
| Low-and-slow drift (gradual exfil, baseline poisoning) | cumulative-sum control chart | CUSUM (visit-anchored) |
| Burst-then-hide (masking) | median/MAD scale isn't inflated by the burst | robust statistics |
| Volume-normal but structurally off (one-directional exfil, fan-out) | shape features scored directly | `egress_ratio`, `fan_out` |
| Never-before-seen external server (quiet C2 / exfil) | persistent identity memory | `FirstSeenDetector` |
| Off-hours activity | the hour has its own baseline | time-of-day buckets |

## What you see

The dashboard is a single page served at `http://127.0.0.1:8000`. Five
sections, all on one screen:

| Section | What it shows |
|---|---|
| **Status pill** | `정상 감시중` (green) / `워밍업 N` (yellow) / `오류` (red), plus interface name and uptime |
| **KPI strip** | Alert counts (1h / 24h / total), top affected feature in the last hour, current packets-per-second |
| **Alert timeline** | 60-minute histogram of alert density, coloured by severity |
| **Detected anomalies** | Sortable table. Each row shows a named verdict (e.g. `포트 스캔 의심`) and severity; click to expand the plain-language summary, recommended action, top talkers, and the raw statistics |
| **Live network activity** | Top talkers (source / destination IPs, destination ports) and TCP / UDP / ICMP / OTHER protocol mix for the *current* 1-second window |

Each alert carries a plain-language verdict; the jargon is tucked into a
collapsible technical-detail section:

```text
[심각] 분산 공격(DDoS)/출발지 위조 의심
  갑자기 매우 많은 서로 다른 출발지에서 트래픽이 쏟아지고 있습니다
  (565곳, 평소의 약 185배). DDoS 공격이나 출발지 위조(spoofing)일 수 있습니다.
  → 권장: 지속되면 인터넷 연결을 차단하고 네트워크 관리자에게 알리세요.
  (기술 상세: unique_src_ips — 평소 대비 185배 ↑ ...)
```

## Status

| Component | State |
|---|---|
| Windows packet capture (Npcap via direct ctypes → `wpcap.dll`) | ✅ verified on Windows 11 |
| Time-window feature aggregation (incl. directional / shape features) | ✅ |
| Baseline detector (EWMA + Z-score, N-window confirm) | ✅ |
| Adaptive detector (per-time-bucket robust baselines + self-tuning threshold) | ✅ |
| CUSUM low-and-slow drift detection | ✅ |
| First-seen external-destination detection (persistent memory) | ✅ |
| Plain-language alert classifier (category / severity / recommendation) | ✅ |
| SQLite alert storage | ✅ |
| FastAPI live dashboard | ✅ |
| Beacon (periodicity) detection for C2 | ⏳ planned |
| Windows Service installer | ⏳ planned |

## Requirements

- **Windows 10 or 11** (64-bit) — for live capture
- **Python 3.11 or newer**
- **[Npcap](https://npcap.com/)**, installed in **WinPcap API-compatible Mode**
- **Administrator privileges** when running the capture commands

You do **not** need MSVC Build Tools or Visual Studio — capture talks to Npcap's
`wpcap.dll` directly through `ctypes`. The offline evaluation scripts below need
none of this and run on any OS.

## Installation

```powershell
git clone https://github.com/Seok-Hyun-Ann/NIDS-Win.git
cd NIDS-Win

python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Quick start

Open a terminal **as Administrator**, then:

```powershell
# 1. List available interfaces
nad list-interfaces
# →  \Device\NPF_{A5CB34C2-...}        (Realtek PCIe GbE)

# 2. Smoke-test capture (10 packets)
nad capture --interface "\Device\NPF_{A5CB34C2-...}" --limit 10

# 3. Launch the live dashboard with the adaptive engine
nad serve --interface "\Device\NPF_{A5CB34C2-...}" --detector adaptive
#   → http://127.0.0.1:8000
```

The first ~30 seconds are a warmup. Leave it running for hours/days so the
per-hour baselines settle and detection sharpens.

> **Tip — finding your interface:** the `\Device\NPF_{...}` strings are GUIDs.
> Match them against `Get-NetAdapter | Select Name, InterfaceGuid` in PowerShell.

### Try it without a NIC

The evaluation scripts need no Npcap and no Administrator. On a Korean console,
run `$env:PYTHONIOENCODING="utf-8"` first so Korean/emoji print correctly.

```powershell
# Synthetic labelled benchmark: 7 attacks vs. 3 detector stacks
python scripts/evaluate.py
python scripts/evaluate.py --sweep        # low-and-slow detection across ramp speeds

# Replay real pcaps through the full pipeline (chains files on one clock,
# so an attack capture can be appended after a normal one to build a baseline)
python scripts/replay_pcap.py normal.pcap attack.pcap

# Unsupervised separability on the UNSW-NB15 flow dataset
python scripts/eval_unsw.py
```

> Datasets and pcaps are **not** included (too large, gitignored). Sample pcaps
> are read via `dpkt`; UNSW-NB15 / CIC-IoT-2023 CSVs are downloaded into `Data/`.

## How it works

```
┌────────────┐  packets  ┌────────────┐ features ┌────────────────────────┐
│ Npcap      │ ────────▶ │ Window     │ ───────▶ │ AdaptiveDetector       │
│ (wpcap.dll)│           │ Aggregator │          │  robust Z per bucket   │─┐
└────────────┘           │ (1s)       │          │  + auto threshold      │ │
                         └─────┬──────┘          │  + CUSUM (slow drift)  │ │ alerts
                               │                 ├────────────────────────┤ ├─▶ classify ─▶ SQLite ─▶ dashboard
                               └────────────────▶│ FirstSeenDetector      │ │
                                                 │  new external dests    │─┘
                                                 └────────────────────────┘
```

For each 1-second window the aggregator computes 9 volume/count features (packet
count, byte total, average payload size, unique source/destination IPs, unique
destination ports, TCP/UDP/ICMP counts) plus 2 **shape** features —
`egress_ratio` (% of bytes outbound) and `fan_out` (destinations per source) —
and the top-K talkers for context.

The **adaptive detector** keeps a robust **EWMA median + MAD** per `(time-bucket,
feature)`; outliers barely move it, so a burst can't blind the next detection.
The threshold is self-tuning: a robust floor raised by a P²-tracked high quantile
of recent scores, targeting a false-alarm *rate*. A **CUSUM** control chart,
re-anchored on entering each bucket and scaled by the within-visit spread,
accumulates sustained sub-threshold drift (low-and-slow) without firing on normal
day-to-day regime shifts. Cold buckets fall back to a fast global baseline.

The **first-seen detector** remembers every external destination the host has
contacted (persisted in SQLite, survives restarts) and flags sustained traffic to
a brand-new public server — the tell of quiet exfiltration or C2.

Finally, a transparent **classifier** maps the deviating feature plus context
(direction, protocol mix, time, top talkers) to a named hypothesis, a severity
(관심 / 주의 / 경고 / 심각), an everyday-Korean summary, and a recommended action.

## CLI reference

```text
nad list-interfaces                     # print Npcap device names
nad capture -i <dev> [opts]             # raw packet print (debug)
nad serve   -i <dev> [opts]             # live dashboard

# serve — core options
  -i, --interface     Npcap device string (required)
  -f, --filter        BPF filter                         [default: ip]
  -p, --port          HTTP port                          [default: 8000]
      --window-seconds  aggregation window (s)           [default: 1.0]
      --warmup        windows before alerting            [default: 30]
      --confirm       consecutive windows to confirm     [default: 3]
      --cooldown      windows muted after an alert        [default: 10]

# serve — detector selection
      --detector      baseline | adaptive                [default: baseline]
      --bucketing     hour | weekend_hour | dow_hour     [default: weekend_hour]
      --threshold-mode  combined | robust | rate         [default: combined]
      --target-rate   target false-alarm fraction        [default: 0.005]
      --robust-k      robust-Z floor (~sigma)            [default: 3.5]
      --bucket-warmup windows before a bucket scores     [default: 200]

# serve — behavioral axis (first-seen destinations)
      --behavioral / --no-behavioral                     [default: on]
      --firstseen-learning      windows to learn first   [default: 3600]
      --firstseen-consecutive   windows to confirm new   [default: 5]
```

`--detector adaptive` is the recommended engine; `baseline` is the original
fixed-threshold EWMA detector, kept for comparison.

### Tuning false positives

| Knob | Range | Effect |
|---|---|---|
| `--robust-k` | 3.0 – 5.0 | higher = fewer alerts, miss subtle signals |
| `--target-rate` | 0.001 – 0.02 | lower = stricter auto-cutoff, fewer alerts |
| `--confirm` | 1 – 10 | higher = transient bursts ignored, slower to react |
| `--cooldown` | 0 – 30 | higher = less alert spam |
| `--no-behavioral` | — | disable first-seen alerts (noisy on short runs) |

## Tests

```powershell
pytest                          # full suite (no elevation needed)
pytest tests/test_adaptive.py   # one module
pytest -k "cusum"               # by name
```

Unit tests cover the OS-independent layers — streaming statistics, the adaptive
and behavioral detectors, the classifier, features, and storage. The capture
path is verified by manual smoke-test (`nad capture --limit ...`).

## Project layout

```
src/nad/
├── capture/              # Npcap binding (ctypes → wpcap.dll) + Packet/Capture types
├── features.py           # WindowAggregator → WindowFeatures (incl. shape features)
├── stats.py              # RobustEwmaStat, P2Quantile, Cusum  (streaming, stdlib)
├── detect.py             # BaselineDetector (original fixed-threshold EWMA)
├── adaptive.py           # AdaptiveDetector: time buckets + auto-threshold + CUSUM
├── behavioral.py         # FirstSeenDetector: never-before-seen destinations
├── classify.py           # anomaly → category / severity / plain-language / action
├── storage.py            # SQLite AlertStore + DestinationStore (persistent memory)
├── service.py            # capture → features → detect(+behavioral) → store loop
├── web/                  # FastAPI app + dashboard (index.html, style.css, app.js)
└── cli.py                # `nad` console script
scripts/
├── evaluate.py           # synthetic labelled benchmark (+ --sweep)
├── replay_pcap.py        # replay/chain pcaps through the real pipeline
└── eval_unsw.py          # unsupervised evaluation on UNSW-NB15
docs/adaptive-detection-design.md   # design notes
tests/
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `wpcap.dll not found` | Npcap missing or installed without WinPcap-compatible mode. |
| `pcap_open_live failed` | Terminal not running as Administrator. |
| `nad` runs old code | The `nad` command points at a different editable install. Run `pip install -e .` in *this* folder. |
| Many `처음 보는 외부 연결` early on | First-seen has no history yet — expected on short runs. Use `--no-behavioral` or let it learn. |
| Korean/emoji garbled in scripts | `$env:PYTHONIOENCODING="utf-8"` before running. |
| Alerts spam | Raise `--confirm` / `--robust-k`, or lower `--target-rate`. |

## Roadmap

- [x] Adaptive per-time-bucket baselines with self-tuning threshold
- [x] CUSUM for low-and-slow detection
- [x] First-seen-destination behavioral axis
- [x] Shape features + plain-language classifier
- [x] PCAP replay mode for repeatable testing
- [ ] Beacon (periodicity) detection for C2 channels
- [ ] Per-host scan features (scans against busy backgrounds)
- [ ] Windows Service installer; optional auth / TLS for remote dashboard

## Privacy

NIDS-Win never connects out (the evaluation scripts download only datasets you
choose). Packet headers, capped 256-byte payload prefixes, alerts, and the
learned destination memory stay in the local SQLite file you point `--db` at.
Delete the file to wipe history.

## License

[MIT](LICENSE).
