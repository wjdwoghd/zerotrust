"""사건 API가 권한 상태별 공개 필드만 응답하는지 검증한다."""

import pytest

from api import resource_handler
from api.response_formatter import format_evaluation_response
from core.decision_engine import get_action_permissions


def _evaluation(level):
    return {
        "request_id": "request-1",
        "decision": {
            "level": level, "risk_score": 72.5, "reason": "내부 판단",
            "override": {"rule": "INTERNAL_RULE"},
            "external_message": "접근 안내",
            "break_glass": None,
        },
        "scoring": {
            "object_sensitivity": {"score": 35},
            "environment_risk": {"score": 33},
            "behavior_risk": {"score": 15},
            "work_fitness": {"score": -10},
        },
        "policy_check": {"rule": "INTERNAL_RULE"},
        "anomaly_check": {"anomaly_types": ["INTERNAL"]},
        "resource": {
            "id": 7, "title": "사건 제목", "case_number": "2026-SEC-7",
            "sensitivity_grade": 4, "data_type": "original",
            "department": "수사", "description": "불필요한 설명",
            "content": "비공개 본문", "watermark": "사용자",
            "requires_approval": True, "job_tags": ["secret"],
            "can_download": True,
        },
    }


@pytest.mark.parametrize("level,status,required_action", [
    (1, "ALLOW", None), (2, "ALLOW", None),
    (3, "VERIFY", "reauthenticate"),
    (4, "VERIFY", "request_approval"),
    (5, "DENY", None),
])
def test_detail_fields_follow_view_permission(level, status, required_action):
    """허용 전에는 본문·등급이 없고 허용 후에도 필요한 필드만 남는다."""
    result = format_evaluation_response(_evaluation(level), include_resource=True)

    assert set(result) == {"request_id", "status", "external_message", "actions", "resource", "risk_score"}
    assert result["risk_score"] == 72.5
    assert result["status"] == status
    assert result["external_message"] == "접근 안내"
    assert {key: result["actions"][key] for key in get_action_permissions(level)} == (
        get_action_permissions(level)
    )
    assert result["actions"]["reauthenticate"] is (required_action == "reauthenticate")
    assert result["actions"]["request_approval"] is (required_action == "request_approval")
    assert result["actions"]["attempt_break_glass"] is (level >= 4)
    if level <= 2:
        assert set(result["resource"]) == {
            "id", "title", "case_number", "sensitivity_grade",
            "data_type", "department", "content", "watermark",
        }
        assert result["resource"]["content"] == "비공개 본문"
    else:
        assert result["resource"] == {"id": 7, "title": "사건 제목"}


def test_status_and_download_evaluation_only_add_public_total_score():
    """폴링은 총점 한 값만 공개하고 본문·축별 점수·판단 근거를 싣지 않는다."""
    result = format_evaluation_response(_evaluation(4))
    assert set(result) == {"request_id", "status", "external_message", "actions", "risk_score"}
    assert result["risk_score"] == 72.5
    assert "비공개 본문" not in str(result)
    assert "INTERNAL_RULE" not in str(result)


def test_resource_restriction_cannot_be_widened_by_public_formatter():
    """자료별 거부 플래그가 있으면 공개 행동 권한도 거부한다."""
    result = format_evaluation_response(_evaluation(1), include_resource=True)
    assert result["actions"]["can_download"] is True

    restricted = _evaluation(1)
    restricted["resource"]["can_download"] = False
    result = format_evaluation_response(restricted, include_resource=True)
    assert result["actions"]["can_download"] is False


class _Request:
    request_id = "handler-request"

    def __init__(self, role="user"):
        self.role = role
        self.payload = None
        self.status = None

    def require_auth(self):
        return {"user_id": 1, "session_id": 2, "role": self.role}

    def get_device_id(self):
        return "registered-001"

    def get_location(self):
        return "본청"

    def get_ip_address(self):
        return "127.0.0.1"

    def get_simulated_hour(self):
        return 14

    def write_json(self, payload, status=200):
        self.payload = payload
        self.status = status


@pytest.mark.parametrize("role", ["user", "admin", "superadmin", "deputy_admin"])
def test_detail_handler_applies_same_public_contract_to_roles(monkeypatch, role):
    """모든 계정이 현재 자료의 4축 숫자를 받고 내부 근거와 제한된 본문은 받지 않는다."""
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: _evaluation(4))
    request = _Request(role)

    resource_handler.CaseDetailHandler.get(request, "7")

    assert request.status == 200
    assert request.payload["resource"] == {"id": 7, "title": "사건 제목"}
    expected = {
        "request_id", "status", "external_message", "actions", "resource", "risk_score",
    }
    expected.add("risk_axes")
    assert request.payload["risk_axes"] == {
        "object_sensitivity": 35.0, "environment_risk": 33.0,
        "behavior_risk": 15.0, "work_fitness": -10.0,
    }
    assert set(request.payload) == expected
    assert "INTERNAL_RULE" not in str(request.payload)


@pytest.mark.parametrize("before,after", [(3, 1), (4, 2)])
def test_detail_handler_before_and_after_verification(monkeypatch, before, after):
    """재인증·승인 전후에 서버가 본문 공개 범위를 바꾼다."""
    results = iter((_evaluation(before), _evaluation(after)))
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: next(results))
    request = _Request()

    resource_handler.CaseDetailHandler.get(request, "7")
    assert request.payload["status"] == "VERIFY"
    assert request.payload["resource"] == {"id": 7, "title": "사건 제목"}

    resource_handler.CaseDetailHandler.get(request, "7")
    assert request.payload["status"] == "ALLOW"
    assert request.payload["resource"]["content"] == "비공개 본문"
    assert request.payload["actions"]["can_download"] is (after == 1)


def test_status_handler_keeps_audit_input_internal(monkeypatch):
    """감사에는 원본 평가가 남고 상태 응답에는 총점·4축 숫자만 남는다."""
    original = _evaluation(3)
    audit_inputs = []
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: original)
    monkeypatch.setattr(
        resource_handler, "_log_score_change_if_needed",
        lambda **kwargs: audit_inputs.append(kwargs["result"]),
    )
    request = _Request()

    resource_handler.CaseAccessStatusHandler.get(request, "7")

    assert audit_inputs == [original]
    assert set(request.payload) == {
        "request_id", "status", "external_message", "actions", "risk_score", "risk_axes",
    }


@pytest.mark.parametrize("role", ["user", "admin"])
def test_status_includes_axes_without_resource_or_reasons(monkeypatch, role):
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: _evaluation(3))
    monkeypatch.setattr(resource_handler, "_log_score_change_if_needed", lambda **kwargs: None)
    request = _Request(role)

    resource_handler.CaseAccessStatusHandler.get(request, "7")

    assert request.payload["risk_axes"]["behavior_risk"] == 15.0
    assert "resource" not in request.payload
    assert "INTERNAL_RULE" not in str(request.payload)


def test_download_handlers_do_not_echo_internal_decision(monkeypatch):
    """평가 POST와 파일 거부 403 모두 총점 외 내부 판단을 숨긴다."""
    original = _evaluation(5)
    original["resource"]["can_download"] = False
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: original)

    request = _Request()
    resource_handler.CaseDownloadHandler.post(request, "7")
    assert set(request.payload) == {
        "request_id", "status", "external_message", "actions", "risk_score",
    }

    request = _Request()
    resource_handler.CaseFileHandler.get(request, "7")
    assert request.status == 403
    assert set(request.payload) == {
        "error", "code", "request_id", "status", "external_message", "actions", "risk_score",
    }
    assert "비공개 본문" not in str(request.payload)


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0]


class _ListDb:
    def execute(self, statement, params=None):
        if "FROM resources" in statement:
            return _Rows([
                {"id": 7, "case_number": "SECRET-7", "title": "사건 제목"},
            ])
        return _Rows([{"assigned_cases": [7]}])

    def close(self):
        pass


def test_list_never_reveals_metadata_before_evaluation(monkeypatch):
    """담당 사건이라도 목록에는 제목·식별자·담당 여부만 남는다."""
    monkeypatch.setattr(resource_handler, "get_db", _ListDb)
    request = _Request()

    resource_handler.CaseListHandler.get(request)

    assert request.payload == {
        "cases": [{"id": 7, "title": "사건 제목", "is_assigned_case": True}],
        "total": 1,
    }


class _ClickDb:
    def execute(self, statement, params=None):
        if "FROM resources" in statement:
            return _Rows([{"id": 7, "case_number": "SECRET-7", "title": "사건"}])
        if "FROM users" in statement:
            return _Rows([{"assigned_cases": []}])
        return _Rows([{"c": 1}])

    def close(self):
        pass


def test_restricted_click_keeps_penalty_in_audit_only(monkeypatch):
    """반복 클릭 위험도는 기록하되 일반 응답에 점수를 보내지 않는다."""
    audits = []
    monkeypatch.setattr(resource_handler, "get_db", _ClickDb)
    monkeypatch.setattr(resource_handler, "audit_log", lambda **kw: audits.append(kw))
    request = _Request()

    resource_handler.CaseRestrictedClickHandler.post(request, "7")

    assert request.payload == {"recorded": True}
    assert audits[0]["details"]["behavior_penalty"] == 10
