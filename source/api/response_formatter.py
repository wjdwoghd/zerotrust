"""
외부 응답 포매터 (L5-3)

내부 decision/scoring/policy_check 객체를 외부 응답 바디로 변환한다.
일반 사건 API는 3단계 상태, 안내 문구, 허용 행동과 현재 총 위험점수를 공개한다.
상세의 본문·메타데이터는 서버의 열람 허용 후에만 포함한다.
상세·상태 응답은 해당 자료의 4축 점수 숫자만 추가하며 판단 근거는 감사 경로에 남긴다.
"""
from __future__ import annotations

from typing import Any, Dict
import math

from core.decision_engine import get_action_permissions


_EXTERNAL_STATUS_BY_LEVEL = {
    1: "ALLOW",
    2: "ALLOW",
    3: "VERIFY",
    4: "VERIFY",
    5: "DENY",
}


def external_status(level: int) -> str:
    """내부 5단계 접근 레벨을 외부 공개용 3단계 상태로 변환한다."""
    return _EXTERNAL_STATUS_BY_LEVEL.get(level, "DENY")


def format_evaluation_response(eval_result: Dict[str, Any], *,
                               include_resource: bool = False,
                               include_risk_axes: bool = False) -> Dict[str, Any]:
    """접근 평가 결과에서 사용자에게 허용된 상태와 문서 필드만 반환한다."""
    decision = eval_result.get("decision", {}) or {}
    try:
        level = int(decision.get("level", 5))
    except (TypeError, ValueError):
        level = 5
    if level not in _EXTERNAL_STATUS_BY_LEVEL:
        level = 5
    resource = eval_result.get("resource") or {}
    permissions = get_action_permissions(level)
    for action in permissions:
        if resource.get(action) is False:
            permissions[action] = False
    actions = {
        **permissions,
        "reauthenticate": level == 3,
        "request_approval": level == 4,
        "attempt_break_glass": (
            level >= 4 and int(resource.get("sensitivity_grade") or 0) >= 4
        ),
        "release_break_glass": bool(decision.get("break_glass")),
    }

    response = {
        "request_id": eval_result.get("request_id"),
        "status": external_status(level),
        "external_message": decision.get("external_message")
                            or eval_result.get("external_message")
                            or "",
        "actions": actions,
    }
    score = decision.get("risk_score")
    response["risk_score"] = (
        round(float(score), 1) if type(score) in (int, float)
        and math.isfinite(score) and 0 <= score <= 100 else None
    )
    if include_risk_axes:
        scoring = eval_result.get("scoring") or {}
        axes = {}
        for public_key, internal_key in (
            ("object_sensitivity", "object_sensitivity"),
            ("environment_risk", "environment_risk"),
            ("behavior_risk", "behavior_risk"),
            ("work_fitness", "work_fitness"),
        ):
            value = (scoring.get(internal_key) or {}).get("score")
            if type(value) in (int, float) and math.isfinite(value):
                axes[public_key] = round(float(value), 1)
        if len(axes) == 4:
            response["risk_axes"] = axes
    if include_resource:
        public_resource = {key: resource[key] for key in ("id", "title")
                           if key in resource}
        if permissions["can_view"]:
            public_resource.update({
                key: resource[key] for key in (
                    "case_number", "sensitivity_grade", "data_type",
                    "department", "content", "watermark",
                ) if key in resource
            })
        response["resource"] = public_resource
    return response
