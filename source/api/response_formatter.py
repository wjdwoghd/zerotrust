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
