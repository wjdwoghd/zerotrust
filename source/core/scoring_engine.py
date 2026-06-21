"""
점수 계산 엔진
4개 평가 축: 객체 민감도, 환경 위험도, 행위 위험도, 업무 적합도
최종 위험 점수 = 객체 민감도 + 환경 위험도 + 행위 위험도 - 업무 적합도

가중치 출처: 보고서 §7-3 Table 21 (캡스톤_4주차_최종2.docx)

임계값 외부화 (015 마이그레이션):
  모든 매직넘버는 `policy_thresholds` 테이블에 보관되며 5분 TTL 캐시로
  조회된다 (core.policy_thresholds 모듈). 운영 중 ROC 보정 시 코드 배포
  없이 DB row 갱신만으로 적용 가능. 시드 default 는 보고서 §7-3 그대로.
"""
from core import policy_thresholds as _pt


# ─── 보고서 §7-3 default (DB miss 시 fallback 으로만 사용) ────────
_DEFAULT_SENSITIVITY_BASE = {1: 10, 2: 20, 3: 30, 4: 40, 5: 50}
_DEFAULT_DATA_TYPE_BONUS = {
    "summary": 5, "original": 10, "evidence": 15, "internal_memo": 20,
}
_DEFAULT_IP_REP = {"clean": 0, "suspicious": 10, "tor": 25, "unknown": 5}


# ─── 동적 조회 헬퍼 ──────────────────────────────────────────────
def _t(name: str, default: float, categories=None) -> float:
    """policy_thresholds 캐시 조회 + 기본값 fallback + 부서별 multiplier 적용."""
    return _pt.get(name, default, categories=categories)


def _sens_base(grade: int) -> float:
    return _t(f"OBJECT_SENS_GRADE_{grade}",
              _DEFAULT_SENSITIVITY_BASE.get(grade, 30))


def _data_type_bonus(data_type: str) -> float:
    key_map = {
        "summary":       "OBJECT_DATA_TYPE_SUMMARY",
        "original":      "OBJECT_DATA_TYPE_ORIGINAL",
        "evidence":      "OBJECT_DATA_TYPE_EVIDENCE",
        "internal_memo": "OBJECT_DATA_TYPE_INTERNAL_MEMO",
    }
    name = key_map.get(data_type)
    if not name:
        return _DEFAULT_DATA_TYPE_BONUS.get(data_type, 5)
    return _t(name, _DEFAULT_DATA_TYPE_BONUS[data_type])


def score_object_sensitivity(sensitivity_grade: int, data_type: str) -> dict:
    base = _sens_base(sensitivity_grade)
    bonus = _data_type_bonus(data_type)
    total = base + bonus
    return {
        "score": total,
        "base": base,
        "data_type_bonus": bonus,
        "detail": f"등급{sensitivity_grade}(+{base}) + {data_type}(+{bonus}) = {total}"
    }


def score_environment_risk(device_registered: bool, location_allowed: bool,
                           is_night: bool,
                           relaxed_time: bool = False,
                           long_unused_device: bool = False,
                           exception_location: bool = False,
                           device_changed: bool = False,
                           impossible_travel: bool = False,
                           user_categories=None) -> dict:
    """환경 위험도 — 보고서 Table 21 기준.

    user_categories 가 전달되면 016 의 부서별 multiplier 가 적용된다.
    심야 페널티는 직무와 무관하게 기본 +15 를 그대로 적용한다.
    """
    cats = user_categories
    score = 0.0
    factors = []

    # 단말
    if not device_registered:
        v = _t("ENV_UNREGISTERED_DEVICE", 20, cats)
        score += v
        factors.append(f"미등록 단말(+{v:.0f})")
    elif long_unused_device:
        v = _t("ENV_LONG_UNUSED_DEVICE", 10, cats)
        score += v
        factors.append(f"장기 미사용 등록 단말(+{v:.0f})")

    # 위치
    if not location_allowed:
        v = _t("ENV_DISALLOWED_LOCATION", 20, cats)
        score += v
        factors.append(f"비허용 위치(+{v:.0f})")
    elif exception_location:
        v = _t("ENV_EXCEPTION_LOCATION", 10, cats)
        score += v
        factors.append(f"예외 허용 위치(+{v:.0f})")

    # 접속 시간
    if is_night:
        v = _t("ENV_NIGHT_TIME", 15, cats)
        score += v
        factors.append(f"심야 시간대(+{v:.0f})")
    elif relaxed_time:
        v = _t("ENV_RELAXED_TIME", 5, cats)
        score += v
        factors.append(f"완화구간(+{v:.0f})")

    # 접속 일관성
    if device_changed:
        v = _t("ENV_DEVICE_CHANGED", 10, cats)
        score += v
        factors.append(f"단말 변경(+{v:.0f})")
    if impossible_travel:
        v = _t("ENV_IMPOSSIBLE_TRAVEL", 15, cats)
        score += v
        factors.append(f"비현실적 위치 전환(+{v:.0f})")

    if not factors:
        factors.append("정상 환경(+0)")

    return {
        "score": score,
        "factors": factors,
        "detail": " / ".join(factors) + f" = {score:.0f}"
    }


def score_behavior_risk(access_count_5min: int = 0, download_attempt: bool = False,
                        copy_attempt: bool = False, bulk_query: bool = False,
                        auth_fail_repeat: bool = False,
                        unauthorized_access: bool = False,
                        high_sensitivity_unassigned: bool = False,
                        unassigned_click_count: int = 0) -> dict:
    """행위 위험도 — 보고서 Table 21 기준.

    auth_fail_repeat 는 보고서에 명시된 "인증 실패 누적(+15)" 항목을 위해 추가된다.
    """
    score = 0.0
    factors = []

    # 짧은 시간 기준: 5분.
    # 5회 이상은 시연·운영 모두에서 탐색성 접근을 보여주기 좋은 주의 기준,
    # 10회 이상은 더 강한 위험 기준으로 단계화한다.
    if access_count_5min >= 10:
        v = _t("BEH_HIGH_FREQ_ACCESS_CRITICAL", 20)
        score += v
        factors.append(f"고빈도 접근 위험({access_count_5min}회/5분, +{v:.0f})")
    elif access_count_5min >= 5:
        v = _t("BEH_HIGH_FREQ_ACCESS", 10)
        score += v
        factors.append(f"고빈도 접근 주의({access_count_5min}회/5분, +{v:.0f})")

    # 담당 사건이 아닌 사건을 여는 행위는 단일 실수 가능성을 고려해 소폭 가산한다.
    # 고등급 사건(4~5등급)일수록 정보 노출 위험이 크므로 추가 가산한다.
    if unauthorized_access:
        v = _t("BEH_UNAUTHORIZED_ACCESS", 10)
        score += v
        factors.append(f"비담당 사건 접근(+{v:.0f})")
    if unassigned_click_count > 0:
        unit = _t("BEH_UNAUTHORIZED_ACCESS", 10)
        v = unit * int(unassigned_click_count)
        score += v
        factors.append(f"비담당 사건 반복 클릭({int(unassigned_click_count)}회, +{v:.0f})")
    if high_sensitivity_unassigned:
        v = _t("BEH_HIGH_SENS_UNASSIGNED", 5)
        score += v
        factors.append(f"고민감 비담당 사건(+{v:.0f})")
    if download_attempt:
        v = _t("BEH_DOWNLOAD_SENSITIVE", 20)
        score += v
        factors.append(f"다운로드 시도(+{v:.0f})")
    if copy_attempt:
        v = _t("BEH_COPY_ATTEMPT", 20)
        score += v
        factors.append(f"복사 시도(+{v:.0f})")
    if bulk_query:
        v = _t("BEH_BULK_QUERY", 20)
        score += v
        factors.append(f"대량 조회(+{v:.0f})")
    if auth_fail_repeat:
        v = _t("BEH_AUTH_FAIL_REPEAT", 15)
        score += v
        factors.append(f"인증 실패 누적(+{v:.0f})")

    if not factors:
        factors.append("정상 행위(+0)")

    return {
        "score": score,
        "factors": factors,
        "detail": " / ".join(factors) + f" = {score:.0f}"
    }


def score_work_fitness(is_assigned_case: bool, same_department: bool,
                       jurisdiction_match: bool, pre_approved: bool,
                       job_relevance: bool = False) -> dict:
    """업무 적합도 — 보고서 Table 21 기준.

    job_relevance(직무 연관성, −10) 는 보고서에 명시된 신규 항목이다.
    """
    score = 0.0
    factors = []

    if is_assigned_case:
        v = _t("FIT_ASSIGNED_CASE", -20)
        score += v
        factors.append(f"담당 사건({v:.0f})")
    if same_department:
        v = _t("FIT_SAME_DEPARTMENT", -10)
        score += v
        factors.append(f"동일 부서({v:.0f})")
    if jurisdiction_match:
        v = _t("FIT_JURISDICTION", -5)
        score += v
        factors.append(f"관할 일치({v:.0f})")
    if job_relevance:
        v = _t("FIT_JOB_RELEVANCE", -10)
        score += v
        factors.append(f"직무 연관성({v:.0f})")
    if pre_approved:
        v = _t("FIT_PRE_APPROVED", -15)
        score += v
        factors.append(f"사전 승인({v:.0f})")

    if not factors:
        factors.append("업무 연관 없음(0)")

    return {
        "score": score,
        "factors": factors,
        "detail": " / ".join(factors) + f" = {score:.0f}"
    }


def calculate_total_risk(object_score: float, environment_score: float,
                         behavior_score: float, fitness_score: float) -> dict:
    """최종 위험 점수 산출"""
    total = object_score + environment_score + behavior_score - abs(fitness_score)
    total = max(0, total)

    return {
        "total_risk_score": round(total, 1),
        "object_sensitivity": object_score,
        "environment_risk": environment_score,
        "behavior_risk": behavior_score,
        "work_fitness": fitness_score,
        "formula": f"{object_score} + {environment_score} + {behavior_score} - {abs(fitness_score)} = {round(total, 1)}"
    }


# ─── §5-3 SC-01~12 호환 adapter ──────────────────────────────────
def _is_night_hour(hour: int) -> bool:
    """22:00 ~ 06:00 구간"""
    return hour >= 22 or hour < 6


def _ip_reputation_bonus(ip_rep: str) -> float:
    """IP 평판 → 환경 가산. 외부화된 임계값 사용."""
    key_map = {
        "clean":      "IP_REP_CLEAN",
        "suspicious": "IP_REP_SUSPICIOUS",
        "tor":        "IP_REP_TOR",
        "unknown":    "IP_REP_UNKNOWN",
    }
    name = key_map.get(ip_rep)
    if not name:
        return _DEFAULT_IP_REP.get(ip_rep, 0)
    return _t(name, _DEFAULT_IP_REP[ip_rep])


def evaluate(context: dict) -> dict:
    """
    스펙(§5-3 SC) 호환 어댑터.

    context keys (모두 optional):
      - resource_sensitivity: int (1~5), default 3
      - data_type: str, default "summary"
      - hour_of_day: int (0~23)
      - ip_reputation: "clean"|"suspicious"|"tor"|"unknown"
      - device_trust: "corporate_mdm"|"byod"|"unknown"
      - location_allowed: bool, default True
      - recent_downloads: int (5분 창 기준), default 0
      - download_attempt / copy_attempt / bulk_query: bool
      - is_assigned_case / same_department / jurisdiction_match / pre_approved: bool
    """
    sens = int(context.get("resource_sensitivity",
                           context.get("sensitivity_grade", 3)))
    data_type = str(context.get("data_type", "summary"))

    # 부서별 multiplier 적용을 위한 사용자 카테고리 (016 외부화)
    # context.user_categories 또는 context.job_scope 둘 다 받음
    user_categories = (context.get("user_categories")
                       or context.get("job_scope")
                       or None)

    # 1) 객체 축
    obj = score_object_sensitivity(sens, data_type)

    # 2) 환경 축
    hour = context.get("hour_of_day")
    is_night = _is_night_hour(int(hour)) if hour is not None else False

    device_trust = str(context.get("device_trust", "corporate_mdm"))
    device_registered = device_trust in ("corporate_mdm", "byod")

    location_allowed = bool(context.get("location_allowed", True))

    env = score_environment_risk(
        device_registered=device_registered,
        location_allowed=location_allowed,
        is_night=is_night,
        user_categories=user_categories,
    )

    # 2-가산) IP 평판 (비표준 축 → 환경 축에 가산)
    ip_rep = str(context.get("ip_reputation", "clean")).lower()
    ip_bonus = _ip_reputation_bonus(ip_rep)
    env_score = env["score"] + ip_bonus

    # 3) 행위 축
    recent_downloads = int(context.get("recent_downloads", 0))
    beh = score_behavior_risk(
        access_count_5min=recent_downloads,
        download_attempt=bool(context.get("download_attempt", False)) or recent_downloads > 0,
        copy_attempt=bool(context.get("copy_attempt", False)),
        bulk_query=bool(context.get("bulk_query", False)) or recent_downloads >= 20,
        unauthorized_access=bool(context.get("unauthorized_access", False)),
        high_sensitivity_unassigned=bool(context.get("high_sensitivity_unassigned", False)),
    )

    # 4) 적합성 축
    fit = score_work_fitness(
        is_assigned_case=bool(context.get("is_assigned_case", False)),
        same_department=bool(context.get("same_department", False)),
        jurisdiction_match=bool(context.get("jurisdiction_match", False)),
        pre_approved=bool(context.get("pre_approved", False)),
        job_relevance=bool(context.get("job_relevance", False)),
    )

    raw = obj["score"] + env_score + beh["score"] - abs(fit["score"])
    risk_score = max(0.0, min(100.0, float(raw)))

    return {
        "risk_score": round(risk_score, 1),
        "axes": {
            "object": obj["score"],
            "environment": env_score,
            "behavior": beh["score"],
            "fitness": fit["score"],
        },
        "breakdown": {
            "object": obj,
            "environment": {**env, "ip_bonus": ip_bonus, "score": env_score},
            "behavior": beh,
            "fitness": fit,
        },
    }
