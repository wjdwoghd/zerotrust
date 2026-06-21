"""
Impossible Travel 입력 생성기 (L4-2)

기존: access_evaluator 에서 policy_context["impossible_travel"] = False 하드코딩.
신규: 세션의 last_location / last_location_time 과 현재 위치·시각을 비교해
      거리 구간별 평균 이동 시간 + 교통 마진 기준으로 판정.

거리 계산 방식 (§4-L4-2 갱신):
  - 각 위치명에 (위도, 경도) 좌표를 등록하고 Haversine 공식으로 km 산출.
  - 좌표가 등록되지 않은 위치는 inactive 사유와 함께 판정 보류.
  - 향후 GeoIP2(MaxMind GeoLite2) 도입 시 _coord_for() 가 IP→좌표 lookup 으로
    교체될 수 있도록 인터페이스를 격리한다.

판정 모델 (§4-L4-2 갱신):
  - 기존 단일 임계 속도 800km/h 는 도심 이동(예: 본청↔은평서 5km)이 무조건
    통과되어 시연 의도와 어긋났다. 거리 구간별 평균 속도 + 교통 마진 모델로
    교체. _TRAVEL_BANDS / _min_travel_minutes 참조.
  - 임계는 30분 단위로 올림(ceil) 한다. 시연/정책 가독성 + 보수적 차단.

위치 데이터:
  - 시드 사용자(`init_data.py`)가 사용하는 본청 / 강남서 / 판교센터 / 동대문서 /
    은평서 5곳 + 단위 테스트가 사용하는 지청-* 가상 위치 4곳 + 시뮬용 외국
    옵션 "해외"(도쿄 좌표) 1곳.
  - "비허용위치" 라벨은 좌표를 두지 않는다. 본질적으로 사용자 allowed_locations
    에 없는 위치라는 추상 분류이므로, LoginHandler 의 allowed_locations 게이트
    및 access_evaluator 의 LOCATION_NOT_ALLOWED 룰로 차단된다.
  - 좌표는 공개된 행정 위치 기준 근사값. 정밀 측위가 아닌 "도시간 거리" 수준의
    impossible-travel 판정에는 충분한 정확도(±수 km)이다.
"""
from __future__ import annotations

import datetime
import math
from typing import Optional, Tuple

# ── 임계 속도 (km/h). 호환용 잔존 — 새 모델은 _min_travel_minutes 사용.
#    REPORT.md, 일부 테스트 docstring 등이 이 이름을 참조하므로 남겨둔다.
#    evaluate() 는 더 이상 이 상수를 직접 사용하지 않는다.
IMPOSSIBLE_TRAVEL_KMH = 800.0

# ── 거리 구간별 최소 이동 시간 모델 (§4-L4-2 갱신) ────────────
#    각 구간은 (max_distance_km, avg_kmh, margin_minutes, label).
#    필요 시간(분) = distance / avg_kmh * 60 + margin_minutes
#    그 결과를 30분 단위로 ceil → 시연/정책 가독성.
#
#    추정 근거 (실증 보정 전):
#      - 도심 20km/h        — 서울 도심 평균 주행속도 (시간대 편차 큼)
#      - 광역 30km/h        — 시내↔근교 차량
#      - 시외 60km/h        — 국도+고속 혼합
#      - 장거리 100km/h     — 고속도로/철도 혼합
#      - 국제 800km/h + 180분 — 항공 + 출입국·공항 이동 마진
#
#    실 운영에선 policy_thresholds 외부화 또는 GeoIP+교통 API 로 교체 권장.
_TRAVEL_BANDS = [
    # (max_distance_km, avg_kmh, margin_minutes, label)
    (10.0,           20.0,  10.0,  "urban"),
    (30.0,           30.0,  15.0,  "metro"),
    (150.0,          60.0,  30.0,  "intercity"),
    (500.0,         100.0,  60.0,  "longhaul"),
    (float("inf"),  800.0, 180.0,  "international"),
]

_QUANTUM_MINUTES = 30.0


def _min_travel_minutes(distance_km: float):
    """
    거리 d(km) 가 필요로 하는 최소 이동 시간(분, 30분 단위 올림) 과 구간 라벨.

    산식: distance / avg_kmh * 60 + margin → 30분 단위 ceil.
    올림 이유: 시연/정책 가독성 + 보수적 차단.
    """
    if distance_km <= 0:
        return 0.0, "same"
    for max_d, kmh, margin, label in _TRAVEL_BANDS:
        if distance_km <= max_d:
            raw = distance_km / kmh * 60.0 + margin
            quantized = math.ceil(raw / _QUANTUM_MINUTES) * _QUANTUM_MINUTES
            return quantized, label
    return float("inf"), "out_of_range"


# ── 위치 좌표 (위도, 경도). Haversine 거리 계산의 원천. ──
_LOCATION_COORDS = {
    "본청":      (37.5750, 126.9783),  # 서울 광화문
    "강남서":    (37.5172, 127.0473),  # 강남경찰서
    "판교센터":  (37.3950, 127.1112),  # 성남 판교
    "동대문서":  (37.5722, 127.0398),  # 동대문경찰서
    "은평서":    (37.6024, 126.9291),  # 은평경찰서
    "지청-서울남부": (37.4843, 126.9293),
    "지청-인천":    (37.4563, 126.7052),
    "지청-부산":    (35.1796, 129.0756),
    "지청-제주":    (33.4996, 126.5312),
    "해외":     (35.6762, 139.6503),  # 도쿄 (시뮬용 대표 외국 좌표)
}

# 영문 alias (§5-3 테스트·외부 연계 호환)
_LOCATION_ALIAS = {
    "SEOUL_HQ":       "본청",
    "SEOUL_NAMBU":    "지청-서울남부",
    "INCHEON_BRANCH": "지청-인천",
    "BUSAN_BRANCH":   "지청-부산",
    "JEJU_BRANCH":    "지청-제주",
}


def _normalize_location(name: Optional[str]) -> Optional[str]:
    if not name:
        return name
    return _LOCATION_ALIAS.get(name, name)


def _coord_for(name: str) -> Optional[Tuple[float, float]]:
    n = _normalize_location(name)
    if not n:
        return None
    return _LOCATION_COORDS.get(n)


def _haversine_km(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    R = 6371.0088
    return 2 * R * math.asin(math.sqrt(h))


def _distance_km(a: str, b: str) -> Optional[float]:
    a_n = _normalize_location(a)
    b_n = _normalize_location(b)
    if not a_n or not b_n:
        return None
    if a_n == b_n:
        return 0.0
    ca = _LOCATION_COORDS.get(a_n)
    cb = _LOCATION_COORDS.get(b_n)
    if ca is None or cb is None:
        return None
    return _haversine_km(ca, cb)


def evaluate(last_location: Optional[str],
             last_location_time,
             current_location: str,
             current_time: Optional[datetime.datetime] = None,
             now_iso: Optional[str] = None,
             ) -> Tuple[bool, Optional[str]]:
    """
    Returns: (is_impossible, reason_or_None)

    - 데이터가 부족해 판정 불가면 (False, "inactive:...") 로 반환한다.
    - 새 모델: 거리 → _min_travel_minutes(거리 구간 × 평균 속도 + 교통 마진,
      30분 단위 ceil) 과 실제 경과 시간(분) 비교. 경과가 필요시간보다 짧으면
      impossible.
    """
    if not last_location or not last_location_time:
        return False, "inactive:no_previous_location"

    from core.session_guard import _parse_ts
    prev_t = _parse_ts(last_location_time)
    if prev_t is None:
        return False, "inactive:unparseable_last_location_time"

    if now_iso is not None:
        now = _parse_ts(now_iso)
        if now is None:
            return False, "inactive:unparseable_now_iso"
    else:
        now = current_time or datetime.datetime.now(tz=datetime.timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)

    elapsed_h = (now - prev_t).total_seconds() / 3600.0
    if elapsed_h <= 0:
        return False, "inactive:non_positive_elapsed"

    dist = _distance_km(last_location, current_location)
    if dist is None:
        return False, f"inactive:unknown_pair:{last_location}->{current_location}"

    if dist == 0.0:
        return False, None

    elapsed_min = elapsed_h * 60.0
    min_required_min, band = _min_travel_minutes(dist)
    if elapsed_min < min_required_min:
        return True, (
            f"band={band} dist={dist:.1f}km "
            f"required>={min_required_min:.0f}min "
            f"elapsed={elapsed_min:.1f}min"
        )
    return False, None
