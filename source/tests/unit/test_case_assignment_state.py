"""담당 등록 관리자 API의 대기 상태 가드를 DB 없이 검증한다."""

import pytest

from api import admin_handler, resource_handler


class _ReadOnlyAssignmentDb:
    def __init__(self, status):
        self.status = status
        self.closed = False

    def execute(self, statement, params):
        assert statement == "SELECT * FROM case_assignment_requests WHERE id=?"
        assert params == (17,)
        return self

    def fetchone(self):
        return {"id": 17, "requester_id": 1, "status": self.status}

    def close(self):
        self.closed = True


class _AdminRequest:
    def require_admin(self):
        return {"user_id": 2, "role": "admin"}

    def get_json_body(self):
        return {}

    def write_error_json(self, message, status, code):
        self.error = (status, code)
        return self.error


@pytest.mark.parametrize(
    ("handler", "request_status"),
    [
        (admin_handler.CaseAssignmentApproveHandler, "pending_admin"),
        (admin_handler.CaseAssignmentApproveHandler, "otp_required"),
        (admin_handler.CaseAssignmentApproveHandler, "approved"),
        (admin_handler.CaseAssignmentApproveHandler, "rejected"),
        (admin_handler.CaseAssignmentApproveHandler, "cancelled"),
        (admin_handler.CaseAssignmentRequireOtpHandler, "otp_required"),
        (admin_handler.CaseAssignmentRequireOtpHandler, "otp_verified"),
        (admin_handler.CaseAssignmentRequireOtpHandler, "cancelled"),
        (admin_handler.CaseAssignmentRejectHandler, "approved"),
        (admin_handler.CaseAssignmentRejectHandler, "rejected"),
        (admin_handler.CaseAssignmentRejectHandler, "cancelled"),
    ],
)
def test_assignment_admin_rejects_invalid_transition(
    monkeypatch, handler, request_status,
):
    """화면에서 막힌 상태를 직접 API로 호출해도 DB 변경 전에 거절한다."""
    db = _ReadOnlyAssignmentDb(request_status)
    monkeypatch.setattr(admin_handler, "get_db", lambda: db)
    request = _AdminRequest()

    handler.post(request, "17")

    assert request.error == (400, "invalid_status")
    assert db.closed


@pytest.mark.parametrize(
    ("handler", "request_status"),
    [
        (admin_handler.CaseAssignmentRequireOtpHandler, "pending_admin"),
        (admin_handler.CaseAssignmentApproveHandler, "otp_verified"),
        (admin_handler.CaseAssignmentRejectHandler, "pending_admin"),
    ],
)
def test_assignment_admin_cannot_process_own_request(
    monkeypatch, handler, request_status,
):
    """자기 요청은 OTP 요구·최종 승인·반려 모두 DB 변경 전에 막는다."""
    db = _ReadOnlyAssignmentDb(request_status)
    monkeypatch.setattr(admin_handler, "get_db", lambda: db)
    request = _AdminRequest()
    request.require_admin = lambda: {"user_id": 1, "role": "admin"}

    handler.post(request, "17")

    assert request.error == (403, "self_approval_forbidden")
    assert db.closed


@pytest.mark.parametrize("request_status", ["pending_admin", "otp_verified", "rejected", "cancelled"])
def test_assignment_otp_only_consumed_while_required(monkeypatch, request_status):
    """OTP 대기가 아닌 요청은 토큰 기기를 조회하거나 OTP를 소비하지 않는다."""
    db = _ReadOnlyAssignmentDb(request_status)
    monkeypatch.setattr(resource_handler, "get_db", lambda: db)

    class Request(_AdminRequest):
        def require_auth(self):
            return {"user_id": 1}

        def get_json_body(self):
            return {"otp": "000000"}

    request = Request()
    resource_handler.CaseAssignmentOtpVerifyHandler.post(request, "17")

    assert request.error == (400, "otp_not_required")
    assert db.closed
