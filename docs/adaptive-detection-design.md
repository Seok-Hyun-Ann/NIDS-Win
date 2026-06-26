# 적응형 탐지 설계: 시간대별 기준선 + 자동 임계치

> 상태: 설계(구현 전) · 작성일 2026-06-22
> 목표: 고정 임계치(`z_threshold=3.0`)와 단일 전역 기준선을 걷어내고,
> "매일 다른 네트워크 행동"을 프로그램이 스스로 학습·판단하도록 만든다.

---

## 1. 현재 구조와 한계

### 1.1 지금 동작 방식
[detect.py](../src/nad/detect.py)의 `BaselineDetector`는 feature별로 **단일 전역 EWMA 평균/분산**(`_EwmaStat`, `alpha=0.1`)을 유지한다.

- 경보 조건: `|z| = |x - mean| / max(std, 1.0) >= z_threshold(3.0)`
- 오탐 억제: `confirm_windows`(연속 N윈도우 확인) + `cooldown_windows`(경보 후 묵음).
- `warmup_windows`(기본 30) 동안은 경보하지 않고 기준선만 학습. 이후에도 평균·분산은 **계속 갱신**된다.

즉 임계치 "밴드"(mean ± 3σ)는 이미 어느 정도 자동으로 움직인다. 고정된 것은 **배수 3과 "기준선이 하나뿐"이라는 구조**다.

### 1.2 한계 (이 설계가 겨냥하는 지점)

| # | 한계 | 결과 |
|---|------|------|
| L1 | **단일 전역 기준선** | 새벽 유휴와 밤 게임을 같은 평균에 섞는다. 밤 게임이 며칠 경보 → EWMA가 "정상"으로 흡수 → **새벽에 같은 트래픽이 와도 못 잡는다.** |
| L2 | **고정 3σ + 가우시안 가정** | 한쪽으로 치우치고 폭발적인 트래픽에서 feature마다 너무 둔감하거나 너무 예민. |
| L3 | **평균/분산 오염** | 잡으려는 스파이크가 mean/var를 부풀려 다음 진짜 이상치를 가린다(마스킹). |
| L4 | **느린 공격 흡수** | `alpha=0.1`이면 비정상 트래픽이 ~10–20윈도우 만에 기준선에 녹아 "정상"이 된다. |

---

## 2. 설계 목표

1. **B축 — 시간대별 기준선(우선):** "토요일 밤 9시 트래픽이 *토요일 밤 9시 기준으로* 비정상인가?"를 묻는다. → L1 해결.
2. **A축 — 자동 임계치(결합 채택):** 손으로 정한 `z=3`을 데이터가 정하게 한다. **강건 통계(MAD)로 점수를 깨끗하게 만들고 그 위에 목표 오경보율 튜닝으로 컷오프를 자동화**한다(둘 다 사용). → L2, L3 해결.
3. **향후 — 행동 모드 인식:** 시간대 위에 "유휴/웹/게임/스트리밍" 모드를 얹어 시계가 아닌 *행동*으로 기준을 잡는다.
4. **호환성:** 기존 `BaselineDetector`는 보존하고 나란히 비교 가능하게 한다(평가용).
5. **의존성:** 순수 stdlib 유지(현 프로젝트 철학).

---

## 3. A축 — 자동 임계치: 두 방식 비교

| | 강건 통계 (MAD/분위수) | 목표 오경보율 튜닝 |
|---|---|---|
| 고치는 층위 | 점수를 *재는 척도* | 점수에 *선을 긋는 위치* |
| 푸는 한계 | L2, L3 | L2(배수 수동 지정) |
| 남는 수동값 | 배수/분위수 | 목표율 |
| 가정 | 분위수면 분포 가정 없음 | 이상치가 드물다 |

→ **결합 채택(확정).** 강건 점수(MAD) 위에 오경보율 컷오프를 얹는다. 구현 순서는 MAD를 먼저 세워 검증한 뒤(1–2단계) 컷오프 층을 올린다(4단계) — 두 층이 합쳐진 상태가 **최종 기본 동작**이다.

### 3.1 강건 EWMA 통계 (`RobustEwmaStat`)
스트리밍 중앙값/MAD를 정확히 구하긴 비싸므로, **확률적 근사(stochastic approximation)** EWMA로 충분히 강건하게:

```
median += step * sign(x - median)         # EWMA 중앙값 (sign 업데이트)
mad     = (1-alpha)*mad + alpha*|x - median|   # EWMA 절대편차
robust_z = (x - median) / max(k * mad, floor)  # k = 1.4826 (정규분포에서 σ 등가)
```

- 소수의 큰 버스트가 `median`/`mad`를 거의 못 흔든다 → L3 해결.
- `step`은 적응적으로: 초기엔 크게(빠른 수렴), 이후 작게. 또는 `mad`에 비례.

### 3.2 목표 오경보율 튜닝 (2단계, `RateController`)
robust_z의 **상위 분위수를 스트리밍 추적**(P² 알고리즘, Jain & Chlamtac 1985 — stdlib 구현 가능)하여 그 값을 컷오프로 사용:

```
threshold = P²_estimate(robust_z 분포, q = 1 - target_rate)   # 예: target_rate=0.005 → 99.5분위
threshold = clamp(threshold, hard_floor=3.0, hard_ceiling=12.0)  # 가드레일
```

- 트래픽 레짐이 바뀌어도 경보량이 목표 근처로 유지.
- 가드레일로 "통째로 정상인 날에도 0.5% 강제 경보" / "통째로 이상한 날에 컷오프 폭주"를 막는다.

### 3.3 결합 모드 (`threshold_mode="combined"`, 기본·확정)
강건 점수 위에 자동 컷오프를 얹는다. 최종 임계치는 **둘 중 큰 값**:

```
threshold = max(robust_k, P²_cutoff[feature])
```

- `robust_k`(예: 3.5)는 **하한 가드** — 컷오프가 너무 낮게 떠도 정상 잡음을 경보로 만들지 않는다.
- `P²_cutoff`는 점수 분포가 넓어지면 **위로 떠올라** 오경보 폭주를 막는다.
- 즉 "강건 척도 + 하한 + 자동 상향"이 한 식에 들어간다. `"robust"`/`"rate"`는 디버깅·평가용 단독 모드로 남긴다.

---

## 4. B축 — 시간대별 기준선

### 4.1 버킷 키
윈도우 타임스탬프(`window.window_end_ns`)를 **로컬 시간**으로 변환해 버킷 ID 산출. 후보:

| 방식 | 버킷 수 | 콜드스타트 | 메모 |
|------|--------|-----------|------|
| hour-of-day | 24 | 빠름 | 평일/주말 차이 못 봄 |
| **weekday/weekend × hour** | **48** | **빠름(추천)** | 주중/주말 리듬 구분, 균형 좋음 |
| day-of-week × hour | 168 | 느림 | 가장 세밀하나 버킷당 데이터 적음 |

**콜드스타트는 걱정보다 가볍다:** `window_seconds=1`이면 한 시간에 윈도우가 ~3600개 생성된다. 48버킷이라도 각 버킷이 **하루 만에 수천 샘플**을 받아 따뜻해진다.

### 4.2 전역 폴백 (graceful degradation)
버킷이 아직 차갑다(`n < warmup`)면 그 버킷 대신 **전역 기준선**(현 단일 EWMA)을 사용. 따뜻해지면 버킷으로 전환. → 첫날부터 동작, 시간이 갈수록 시간대 인식이 살아난다.

### 4.3 L4(느린 공격 흡수) 완화
- 경보가 진행 중인(streak > 0) 버킷은 기준선 갱신을 **동결**(현 코드의 `update_stat=False` 패턴 확장).
- 또는 robust 통계 특성상 느린 램프도 중앙값을 천천히만 끌어 일정 기간 탐지 가능.

---

## 5. 제안 아키텍처

기존 코드를 깨지 않도록 **새 탐지기를 나란히** 추가한다.

```
src/nad/detect.py            # 기존 BaselineDetector 보존 (비교 기준선)
src/nad/stats.py             # (신규) _EwmaStat, RobustEwmaStat, P2Quantile
src/nad/adaptive.py          # (신규) AdaptiveDetector
```

### 5.1 클래스 스케치

```python
# stats.py
class RobustEwmaStat:
    """EWMA 중앙값 + MAD 기반 강건 z-score."""
    def update(self, x: float) -> None: ...
    def robust_z(self, x: float) -> float: ...
    @property
    def warm(self) -> bool: ...

class P2Quantile:
    """P² 스트리밍 분위수 추정기 (오경보율 튜닝용)."""
    def update(self, x: float) -> None: ...
    @property
    def value(self) -> float: ...

# adaptive.py
class AdaptiveDetector:
    def __init__(
        self,
        bucketing: str = "weekend_hour",   # "hour" | "weekend_hour" | "dow_hour"
        threshold_mode: str = "combined",  # "combined"(기본) | "robust" | "rate"
        target_rate: float = 0.005,        # rate 컷오프 목표 오경보율
        robust_k: float = 3.5,             # robust 하한 배수(컷오프 가드레일로도 사용)
        alpha: float = 0.05,
        warmup_windows: int = 200,         # 버킷별 워밍업
        confirm_windows: int = 3,
        cooldown_windows: int = 10,
        tz: str | None = None,             # 로컬 타임존
    ): ...

    def update(self, window: WindowFeatures) -> list[Alert]: ...
    def state_snapshot(self) -> dict: ...   # 대시보드: 버킷×feature 기준선
```

내부 상태:
```python
self._buckets: dict[tuple[int, str], RobustEwmaStat]   # (bucket_id, feature) -> stat
self._global:  dict[str, RobustEwmaStat]               # feature -> 전역 폴백
self._cutoff:  dict[str, P2Quantile]                   # rate 모드 컷오프
self._streak / self._cooldown                          # 기존과 동일
```

### 5.2 `update()` 흐름
```
bucket_id = bucketize(window.window_end_ns, mode, tz)
for feature, value in window.numeric():
    stat = bucket if warm else global_fallback
    z = stat.robust_z(value)                       # 강건 점수 (MAD 척도)
    threshold = max(robust_k, cutoff[feature].value)   # combined: 하한 가드 + 자동 컷오프 중 큰 값
    if |z| >= threshold: streak++ ; confirm/cooldown 로직 (기존 재사용)
    else: streak = 0
    cutoff[feature].update(|z|)      # rate 모드
    if not (streak 진행 중): stat.update(value)  # L4 동결
    global_fallback.update(value)    # 폴백 항상 학습
```

### 5.3 `Alert` 확장
`context`에 진단 필드 추가(스키마 무변경, JSON 컬럼 사용):
- `bucket_id`, `bucket_label`(예: `"weekend·21h"`), `used_fallback`(bool),
- `threshold_used`, `baseline_kind`("median/mad").

`baseline_mean`/`baseline_std` 컬럼은 호환 위해 각각 median/`k*mad`로 채운다.

---

## 6. 대시보드 영향
- [web/app.py](../src/nad/web/app.py)의 `baseline` 엔드포인트가 버킷별 기준선을 노출하도록 확장 → 24/48칸 히트맵으로 "시간대별 정상 트래픽 프로파일" 시각화 가능(차후).
- `warmup_remaining`을 "현재 버킷 기준"으로 계산.

---

## 7. 단계별 계획

| 단계 | 내용 | 산출물 |
|------|------|--------|
| 0 | (본 문서) 설계 합의 | `docs/adaptive-detection-design.md` |
| 1 | `stats.py`: `RobustEwmaStat` + 단위테스트 | 강건 점수 검증 |
| 2 | `adaptive.py`: 시간대 버킷 + 전역 폴백 (robust 모드) | `AdaptiveDetector` |
| 3 | 평가 스크립트: 합성/녹화 트래픽으로 기존 vs 신규 비교 | 오탐/미탐 수치 |
| 4 | `P2Quantile` + 결합 모드(`combined`) 활성화 | 임계치 완전 자동화(최종 기본) |
| 5 | CLI/서비스 배선(`--detector adaptive ...`), 대시보드 | 통합 |
| 6 | (향후) 행동 모드 클러스터링 | 모드 인식 탐지 |

> 선택된 범위: **0단계(설계 문서)까지.** 1단계 이후는 합의 후 진행.

---

## 8. 평가 방법 (3단계에서)
- **합성 시나리오:** 주야 리듬을 모사한 트래픽 + 주입 공격(포트스캔=`unique_dst_ports`↑, 비콘=주기적 소량, 유출=`bytes_total`↑).
- **지표:** 탐지율(주입 공격 잡음), 오경보율(정상 윈도우 경보 비율), 탐지 지연(윈도우 수).
- **비교 축:** 기존 `BaselineDetector` vs `AdaptiveDetector(robust)` vs `(rate)`.
- 핵심 질문: "밤 게임을 정상으로 흡수하면서도 새벽 동일 트래픽을 잡는가"(L1), "버스트 후 마스킹이 줄었는가"(L3).

---

## 9. 미해결 질문 / 리스크
- **타임존/DST:** 로컬 시간 기준 버킷팅. DST 전환 시 한 시간 중복/누락 → 일단 무시(영향 경미).
- **버킷 경계 불연속:** 20:59 → 21:00 버킷 전환 시 기준선 점프 가능 → 필요하면 인접 버킷 가중 평균(추후).
- **`step`/`alpha` 선택:** robust EWMA 수렴 속도. 1단계 테스트로 튜닝.
- **장기 미사용 버킷:** 새벽 시간대처럼 데이터는 많지만 변동이 적은 버킷의 `mad`가 0에 수렴 → `floor` 가드 필요(현 코드의 `max(std,1.0)`와 동일 취지).
- **모드 클러스터링과의 관계:** 시간대 버킷은 모드의 *근사*다. 6단계에서 모드를 도입하면 버킷 키를 (시간대 → 모드)로 일반화할지 결정.
