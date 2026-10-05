"""합성 조건의 일회성 정책 계산. 실제 접근 평가나 상태 저장 경로를 호출하지 않는다.

필수: sensitivity_grade(정수 1~5), data_type(summary/original/evidence/
internal_memo), device_registered, location_allowed, is_assigned_case,
same_department(모두 bool). 선택: hour(정수 0~23), job_relevance,
bulk_query, download_attempt, impossible_travel, concurrent_session,
device_mismatch, auth_failure(bool), recent_access_count와
unassigned_click_count(각각 정수 0~1000). 그 외 필드는 거부한다.

입력의 행동 횟수와 보안 신호는 검증된 실제 상태가 아닌 합성 값이다.
승인, MFA, Break-Glass 등 상태 기반 최종 접근은 재현하지 않는다.
"""

from hashlib import sha256
import json

from core import policy_thresholds
from core.decision_engine import determine_access_level
from core.policy_engine import check_immediate_block
from core.scoring_engine import (
    calculate_total_risk, score_behavior_risk, score_environment_risk,
    score_object_sensitivity, score_work_fitness,
)


_REQUIRED_BOOL = {
    "device_registered", "location_allowed", "is_assigned_case",
    "same_department",
}
_OPTIONAL_BOOL = {
    "job_relevance", "bulk_query", "download_attempt", "impossible_travel",
    "concurrent_session", "device_mismatch", "auth_failure",
}
_REQUIRED = _REQUIRED_BOOL | {"sensitivity_grade", "data_type"}
_ALLOWED = _REQUIRED | _OPTIONAL_BOOL | {
    "hour", "recent_access_count", "unassigned_click_count",
}
_DATA_TYPES = {"summary", "original", "evidence", "internal_memo"}


def _validate(conditions: dict) -> dict:
    """합성 입력의 정확한 타입·범위를 확인하고 상태 기반 필드를 거부한다."""
    if not isinstance(conditions, dict):
        raise ValueError("conditions must be an object")
    if any(not isinstance(name, str) for name in conditions):
        raise ValueError("condition names must be strings")
    unknown = set(conditions) - _ALLOWED
    missing = _REQUIRED - set(conditions)
    if unknown or missing:
        raise ValueError(f"unsupported or missing conditions: {sorted(unknown | missing)}")
    for name in _REQUIRED_BOOL | _OPTIONAL_BOOL:
        if name in conditions and type(conditions[name]) is not bool:
            raise ValueError(f"{name} must be boolean")
    for name, low, high in (
        ("sensitivity_grade", 1, 5), ("hour", 0, 23),
        ("recent_access_count", 0, 1000), ("unassigned_click_count", 0, 1000),
    ):
        if name in conditions and (
            type(conditions[name]) is not int
            or not low <= conditions[name] <= high
        ):
            raise ValueError(f"{name} must be an integer from {low} to {high}")
    if not isinstance(conditions["data_type"], str) or conditions["data_type"] not in _DATA_TYPES:
        raise ValueError("unsupported data_type")
    return dict(conditions)


def simulate(conditions: dict) -> dict:
    """DB 정책 스냅샷으로 4축·즉시 차단·점수 기반 기본 레벨만 반환한다.

    DB 임계값 읽기에 실패하면 예외를 전파한다. 점수는 접근 평가기와 같은
    함수와 입력 매핑을 사용하며, 이 호출은 로그·세션·승인 상태를 쓰지 않는다.
    """
    c = _validate(conditions)
    grade = c["sensitivity_grade"]
    assigned = c["is_assigned_case"]
    hour = c.get("hour")
    is_night = hour is not None and (hour >= 22 or hour < 6)
    relaxed = hour is not None and not is_night and (6 <= hour < 9 or 18 <= hour < 22)
    with policy_thresholds.simulation_snapshot() as (values, overrides, defaults_used):
        obj = score_object_sensitivity(grade, c["data_type"])
        env = score_environment_risk(
            c["device_registered"], c["location_allowed"], is_night,
            relaxed_time=relaxed,
        )
        beh = score_behavior_risk(
            access_count_5min=c.get("recent_access_count", 0),
            bulk_query=c.get("bulk_query", False),
            unauthorized_access=not assigned,
            high_sensitivity_unassigned=not assigned and grade >= 4,
            unassigned_click_count=c.get("unassigned_click_count", 0),
        )
        fit = score_work_fitness(
            is_assigned_case=assigned,
            same_department=c["same_department"],
            jurisdiction_match=c["same_department"],
            pre_approved=False,
            job_relevance=c.get("job_relevance", False),
        )
        total = calculate_total_risk(
            obj["score"], env["score"], beh["score"], fit["score"],
        )
        block = check_immediate_block({
            "concurrent_session": c.get("concurrent_session", False),
            "device_mismatch": c.get("device_mismatch", False),
            "auth_failure": c.get("auth_failure", False),
            "location_allowed": c["location_allowed"],
            "device_registered": c["device_registered"],
            "sensitivity_grade": grade,
            "download_attempt": c.get("download_attempt", False),
            "impossible_travel": c.get("impossible_travel", False),
        })
        base = determine_access_level(total["total_risk_score"], grade)
        snapshot = {
            "thresholds": values,
            "defaults_used": sorted(defaults_used),
            "overrides": [
                {"category": category, "name": name, "multiplier": multiplier}
                for (category, name), multiplier in sorted(overrides.items())
            ],
        }
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        return {
            "axes": {
                "object": obj, "environment": env,
                "behavior": beh, "fitness": fit,
            },
            "total": total,
            "immediate_block": block,
            "score_level": base["level"],
            "base_decision": base,
            "policy_snapshot": {
                **snapshot, "sha256": sha256(encoded.encode("utf-8")).hexdigest(),
                "source": "policy_thresholds and policy_overrides DB read; named defaults if missing",
            },
            "support": {
                "evaluated": "four_axes, immediate_block, score_based_level",
                "not_evaluated": [
                    "MFA/reauth state", "admin approval state and requirement",
                    "Break-Glass", "session enforcement and locking",
                    "actual identity, resource, location and device verification",
                ],
                "final_access_level": None,
            },
        }
