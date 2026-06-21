"""
결정 엔진
민감도별 임계치 테이블 기반 5단계 접근 결과 생성

접근 레벨은 총 위험점수 구간으로만 결정된다.
confidence 는 진단 정보로 남길 수 있지만 레벨을 보정하지 않는다.
"""

# 민감도 등급별 임계치 테이블.
#
# 형식: {grade: [(score_max, level), ...]}  — score 가 누적적으로 score_max 이하이면 해당 level.
#
# 외부적인 5단계 정의:
#   1=완전허용 / 2=조회만(워터마크) / 3=추가인증 / 4=관리자승인 / 5=차단
#
# 점수 구간 (default — 015 마이그레이션 시드값):
#   0~25   → L1 (전체 승인)
#   26~50  → L2 (조회만)
#   51~75  → L3 (재인증)
#   76~90  → L4 (관리자 승인)
#   91+    → L5 (차단)
#
# 015 외부화: 경계값(25/50/75/90)은 policy_thresholds 의 DECISION_BAND_L*_MAX
# 에서 동적 조회된다. 결정 매트릭스 스냅샷 테스트가 매핑을 lock-down 하므로
# 변경 시 회귀 영향 사전 검토 필수.
from core import policy_thresholds as _pt

INF = float("inf")


def _get_unified_bands():
    """현재 임계값으로 band 리스트 구성. 매 결정마다 호출 (캐시 5분 TTL)."""
    return [
        (_pt.get("DECISION_BAND_L1_MAX", 25), 1),
        (_pt.get("DECISION_BAND_L2_MAX", 50), 2),
        (_pt.get("DECISION_BAND_L3_MAX", 75), 3),
        (_pt.get("DECISION_BAND_L4_MAX", 90), 4),
        (INF, 5),
    ]


# Backward-compat: 기존 코드가 직접 참조할 수 있는 default 매핑.
# 새 코드에선 _get_unified_bands() 사용 권장.
_UNIFIED_BANDS = [(25, 1), (50, 2), (75, 3), (90, 4), (INF, 5)]
THRESHOLD_TABLE = {g: list(_UNIFIED_BANDS) for g in (1, 2, 3, 4, 5)}

DECISION_SCORE_BANDS = {
    1: (0.0, 25.0),
    2: (26.0, 50.0),
    3: (51.0, 75.0),
    4: (76.0, 90.0),
    5: (91.0, 100.0),
}

DECISION_ACTION_PERMISSIONS = {
    1: {
        "can_view": True,
        "can_download": True,
        "can_copy": True,
        "can_print": True,
    },
    2: {
        "can_view": True,
        "can_download": False,
        "can_copy": False,
        "can_print": True,
    },
    3: {
        "can_view": False,
        "can_download": False,
        "can_copy": False,
        "can_print": False,
    },
    4: {
        "can_view": False,
        "can_download": False,
        "can_copy": False,
        "can_print": False,
    },
    5: {
        "can_view": False,
        "can_download": False,
        "can_copy": False,
        "can_print": False,
    },
}


def get_score_band_for_level(level: int) -> tuple[float, float]:
    """최종 접근 레벨에 대응하는 사용자 표시 점수 구간."""
    try:
        normalized = int(level)
    except (TypeError, ValueError):
        normalized = 5
    return DECISION_SCORE_BANDS.get(normalized, DECISION_SCORE_BANDS[5])


def get_action_permissions(level: int) -> dict:
    """최종 접근 레벨에서 허용되는 문서 행동 권한."""
    try:
        normalized = int(level)
    except (TypeError, ValueError):
        normalized = 5
    return dict(DECISION_ACTION_PERMISSIONS.get(
        normalized,
        DECISION_ACTION_PERMISSIONS[5],
    ))

DECISION_LABELS = {
    1: "완전 허용",
    2: "조회만 허용",
    3: "추가 인증 후 허용",
    4: "관리자 승인 후 허용",
    5: "차단",
}

DECISION_LABELS_EN = {
    1: "FULL_ACCESS",
    2: "VIEW_ONLY",
    3: "REAUTH_REQUIRED",
    4: "ADMIN_APPROVAL",
    5: "BLOCKED",
}

EXTERNAL_MESSAGES = {
    1: "접근이 허용되었습니다.",
    2: "조회만 허용됩니다. 다운로드/복사가 제한됩니다.",
    3: "추가 인증이 필요합니다.",
    4: "관리자 승인이 필요합니다. 승인 요청이 전송되었습니다.",
    5: "접근이 제한되었습니다.",
}


# ─── 확신도 산출 ─────────────────────────────────────────────────
# CONFIDENCE_THRESHOLD 는 015 마이그레이션으로 외부화됐다 (policy_thresholds).
# 아래는 default — DB miss 시 fallback 으로만 사용.
CONFIDENCE_THRESHOLD = 0.85   # default: 이 이하면 한 단계 조정


def _confidence_threshold() -> float:
    """현재 적용 중인 confidence 임계값. 외부화된 값 우선."""
    return _pt.get("CONFIDENCE_THRESHOLD", CONFIDENCE_THRESHOLD)


_BAND_BOUNDARY_MARGIN = 5.0   # 점수 단위. 경계 ±5 안이면 boundary effect 발동
_AXES_DISAGREEMENT_THRESHOLD = 25.0  # 4축 std 가 이 이상이면 축 불일치 페널티
_ANOMALY_PENALTY_PER_HIT = 0.15
_TRAVEL_INACTIVE_PENALTY = 0.20


def _band_distance_score(risk_score: float) -> float:
    """
    가장 가까운 band 경계까지의 거리를 [0, 1] 로 정규화.
    경계에 가까울수록 0, 중앙에 가까울수록 1.
    """
    boundaries = (25.0, 50.0, 75.0, 90.0)
    nearest = min(abs(risk_score - b) for b in boundaries)
    if nearest >= _BAND_BOUNDARY_MARGIN:
        return 1.0
    return nearest / _BAND_BOUNDARY_MARGIN


def _axes_consistency_score(axes_values) -> float:
    """
    4축 점수의 표준편차 기반 일관성 점수 [0, 1].
    축들이 비슷한 값이면 1, 한쪽으로 극단 치우치면 낮음.
    """
    vals = [float(v) for v in axes_values if v is not None]
    if len(vals) < 2:
        return 1.0
    mean = sum(vals) / len(vals)
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    std = variance ** 0.5
    if std >= _AXES_DISAGREEMENT_THRESHOLD:
        return 0.0
    return 1.0 - (std / _AXES_DISAGREEMENT_THRESHOLD)


def compute_confidence(*, risk_score: float, axes_values=None,
                       anomaly_hits: int = 0,
                       travel_inactive: bool = False) -> float:
    """
    결정 확신도 산출 [0.0, 1.0].

    구성:
      - 40%: band 경계 거리 (점수가 임계값 근처면 결정이 흔들리기 쉬움)
      - 30%: 4축 일관성 (한 축만 극단이면 그 축 측정에 의존하는 결정)
      - 20%: 이상행동 hits 페널티 (anomaly 1건당 -0.15)
      - 10%: 위치 탐지 비활성 페널티 (impossible_travel inactive 시 -0.20)

    임계값들은 보정 가능한 상수로 분리되어 있다(향후 정책 테이블화 가능).
    """
    boundary = _band_distance_score(risk_score)
    consistency = _axes_consistency_score(axes_values or [])
    anomaly = max(0.0, 1.0 - _ANOMALY_PENALTY_PER_HIT * max(0, anomaly_hits))
    travel = 1.0 - _TRAVEL_INACTIVE_PENALTY if travel_inactive else 1.0

    score = (
        0.40 * boundary +
        0.30 * consistency +
        0.20 * anomaly +
        0.10 * travel
    )
    # 안전 클램프
    return max(0.0, min(1.0, score))


def _adjust_level_for_confidence(level: int, confidence: float) -> int:
    """
    확신이 부족한 경우 level 을 검증 방향으로 한 단계 이동.
    임계값은 외부화(policy_thresholds.CONFIDENCE_THRESHOLD)되어 있어 운영 중
    조정 가능. 기본 0.85.
    """
    if confidence >= _confidence_threshold():
        return level
    if level >= 4:
        return level - 1   # DENY/ADMIN → 한 단계 완화
    if level <= 2:
        return level + 1   # ALLOW/VIEW_ONLY → 한 단계 강화
    return level           # level == 3 (재인증) 은 그대로 — 이미 검증 단계


# ─── 결정 산출 ───────────────────────────────────────────────────
def determine_access_level(risk_score: float, sensitivity_grade: int,
                           *, confidence: float = 1.0) -> dict:
    """
    최종 위험 점수 + 민감도 등급 → 5단계 접근 결과 (확신도 인지).

    Parameters
    ----------
    risk_score :
        0~100 누적 위험 점수.
    sensitivity_grade :
        1~5 자원 민감도 (현 정책에서 등급 차등은 scoring 단계에서 처리되므로
        결정 단계에서는 동일 매핑 적용 — UI 표 일치 목적).
    confidence :
        결정 확신도 [0,1]. 1.0 이면 base level 그대로, < 0.85 면 검증 방향
        한 단계 이동.

    Returns
    -------
    dict :
        level, label, label_en, external_message, risk_score, sensitivity_grade,
        confidence, level_pre_confidence (조정 전 base level),
        confidence_adjusted (조정 발생 여부), thresholds_applied, matched_band
    """
    # 015 외부화: 매 결정 시 현재 임계값으로 band 구성
    table = _get_unified_bands()

    base_level = 5
    matched = (INF, 5)
    for score_max, lvl in table:
        if risk_score <= score_max:
            base_level = lvl
            matched = (score_max, lvl)
            break

    final_level = base_level

    # JSON 직렬화 안전화
    serialized_table = [
        [(None if score_max == INF else score_max), lvl]
        for (score_max, lvl) in table
    ]

    return {
        "level": final_level,
        "label": DECISION_LABELS[final_level],
        "label_en": DECISION_LABELS_EN[final_level],
        "external_message": EXTERNAL_MESSAGES[final_level],
        "risk_score": round(risk_score, 1),
        "sensitivity_grade": sensitivity_grade,
        "confidence": round(confidence, 3),
        "level_pre_confidence": base_level,
        "confidence_adjusted": False,
        "thresholds_applied": serialized_table,
        "matched_band": {
            "score_max": (None if matched[0] == INF else matched[0]),
            "level": matched[1],
        },
    }


def get_external_response(level: int) -> str:
    """외부 응답 3단계 변환"""
    if level <= 2:
        return "접근 허용"
    elif level <= 4:
        return "추가 검증 필요"
    else:
        return "접근 제한"


# ─── §5-3 DE-01~08 호환 adapter ──────────────────────────────────
def make(context: dict) -> dict:
    """
    스펙(§5-3 DE) 호환 어댑터.

    context keys:
      - risk_score: float
      - resource_sensitivity (or sensitivity_grade): int (1~5)
      - confidence: float (0~1, default 1.0)
      - axes_values: list[float] (선택. confidence 자동 산출에 사용)
      - anomaly_hits: int (선택. confidence 자동 산출에 사용)
      - travel_inactive: bool (선택. confidence 자동 산출에 사용)

    Returns: determine_access_level 과 동일한 dict.
    """
    risk = float(context.get("risk_score", 0))
    sens = int(context.get("resource_sensitivity",
                           context.get("sensitivity_grade", 3)))

    if "confidence" in context:
        conf = float(context["confidence"])
    elif any(k in context for k in ("axes_values", "anomaly_hits", "travel_inactive")):
        conf = compute_confidence(
            risk_score=risk,
            axes_values=context.get("axes_values"),
            anomaly_hits=int(context.get("anomaly_hits", 0)),
            travel_inactive=bool(context.get("travel_inactive", False)),
        )
    else:
        conf = 1.0

    return determine_access_level(risk, sens, confidence=conf)
