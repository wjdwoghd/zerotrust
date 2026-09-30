"""자료 공개 응답은 최종 행동 권한에 따라 생성된다."""

import pytest

from api.response_formatter import format_case_response


@pytest.mark.parametrize("level", [3, 4, 5])
def test_unapproved_response_contains_only_minimum_fields(level):
    result = {
        "request_id": "req-1",
        "decision": {
            "level": level, "label": "인증 필요", "label_en": "VERIFY",
            "can_view": False, "can_download": False,
            "risk_score": 74, "reason": "internal rule",
        },
        "resource": {
            "id": 7, "title": "사건", "sensitivity_grade": 4,
            "content": "SECRET BODY", "description": "SECRET SUMMARY",
            "case_number": "SECRET CASE", "department": "SECRET DEPT",
            "can_view": False, "can_download": False,
        },
        "scoring": {"total": {"total_risk_score": 74}},
        "policy_check": {"rule": "internal rule"},
    }

    public = format_case_response(result)
    assert set(public) == {"request_id", "decision", "resource", "external_message"}
    assert set(public["resource"]) == {
        "id", "title", "sensitivity_grade", "masking_level",
        "can_view", "can_download", "can_copy", "can_print",
    }
    assert public["decision"]["can_view"] is False
    assert "SECRET" not in str(public)
    assert "74" not in str(public)
    assert "internal rule" not in str(public)


def test_allowed_view_contains_body_but_status_does_not():
    result = {
        "decision": {"level": 2, "can_view": True, "can_download": False},
        "resource": {
            "id": 8, "title": "허용", "sensitivity_grade": 2,
            "can_view": True, "can_download": False,
            "description": "SUMMARY", "content": "BODY", "attachment": "SECRET FILE",
        },
    }
    detail = format_case_response(result)
    status = format_case_response(result, include_body=False)
    assert detail["resource"]["content"] == "BODY"
    assert detail["resource"]["description"] == "SUMMARY"
    assert "attachment" not in detail["resource"]
    assert "content" not in status["resource"]
    assert "description" not in status["resource"]


def test_mismatched_permission_fails_closed():
    result = {
        "decision": {"level": 3, "can_view": False, "can_download": False},
        "resource": {"id": 9, "title": "사건", "sensitivity_grade": 3,
                     "can_view": True, "can_download": True, "content": "SECRET"},
    }
    public = format_case_response(result)
    assert public["decision"]["can_view"] is False
    assert public["decision"]["can_download"] is False
    assert "content" not in public["resource"]
