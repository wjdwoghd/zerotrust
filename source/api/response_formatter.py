"""
외부 응답 포매터 (L5-3)

내부 decision/scoring/policy_check 객체를 외부 응답 바디로 변환한다.
운영 정책: 외부는 3단계(ALLOW|VERIFY|DENY) + external_message + request_id
만 노출하고, 내부 reason/risk_score/scoring 분해/정책 규칙명 등은
모두 제거한다.
"""
from __future__ import annotations

from typing import Any, Dict


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


def format_evaluation_response(eval_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    access_evaluator.evaluate_access() 의 반환값을 외부 응답 바디로 변환.

    Parameters
    ----------
    eval_result :
        evaluate_access() 가 돌려준 dict. `decision`, `scoring`, `policy_check`,
        `anomaly_check`, `resource`, `external_message`, `request_id` 포함.
    """
    decision = eval_result.get("decision", {}) or {}
    level = int(decision.get("level", 5))

    return {
        "request_id": eval_result.get("request_id"),
        "status": external_status(level),
        "external_message": eval_result.get("external_message")
                            or decision.get("external_message")
                            or "",
        "decision": {
            "level": level,
            "label_en": decision.get("label_en"),
            # confidence 는 [0.0, 1.0]. 운영 모드에선 두 자리 반올림만 노출
            # (정확한 계산식은 비공개 — 공격자가 임계값 부근 입력을 정밀하게
            #  맞추기 어렵게).
            "confidence": (
                round(float(decision.get("confidence", 1.0)), 2)
                if decision.get("confidence") is not None else None
            ),
        },
        "resource": eval_result.get("resource"),
    }


def format_case_response(eval_result: Dict[str, Any], *, include_body: bool = True) -> Dict[str, Any]:
    """자료 API 공개 응답. 최종 행동 권한으로 본문 공개 여부를 결정한다.

    점수와 정책 근거는 내부 평가 결과와 감사 로그에만 남긴다. 미허용
    응답은 허용 목록으로 구성해 새 DB 필드가 자동으로 노출되지 않게 한다.
    """
    decision = eval_result.get("decision") or {}
    resource = eval_result.get("resource") or {}
    level = int(decision.get("level", 5) or 5)
    can_view = (level <= 2 and decision.get("can_view") is True
                and resource.get("can_view") is True)
    can_download = can_view and decision.get("can_download") is True and resource.get("can_download") is True
    public_decision = {
        "level": level,
        "label": decision.get("label"),
        "label_en": decision.get("label_en"),
        "can_view": can_view,
        "can_download": can_download,
        "can_copy": can_view and decision.get("can_copy") is True and resource.get("can_copy") is True,
        "can_print": can_view and decision.get("can_print") is True and resource.get("can_print") is True,
    }
    public_decision["action_permissions"] = {
        key: public_decision[key]
        for key in ("can_view", "can_download", "can_copy", "can_print")
    }
    public_resource = {
        "id": resource.get("id"),
        "title": resource.get("title"),
        "sensitivity_grade": resource.get("sensitivity_grade"),
        "masking_level": level,
        **public_decision["action_permissions"],
    }
    if can_view:
        for key in ("case_number", "data_type", "department", "masking_name", "watermark"):
            if key in resource:
                public_resource[key] = resource[key]
        if include_body:
            for key in ("description", "content"):
                if key in resource:
                    public_resource[key] = resource[key]
    return {
        "request_id": eval_result.get("request_id"),
        "decision": public_decision,
        "resource": public_resource,
        "external_message": eval_result.get("external_message") or decision.get("external_message") or "",
    }
