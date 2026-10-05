"""일반 사용자 API가 내부 기록 필드를 응답으로 복사하지 않는지 검증한다."""

from api import admin_handler, auth_handler, break_glass_handler, resource_handler


def test_assignment_request_public_fields_only():
    """요청자에게 담당 등록 상태와 화면 제목만 반환한다."""
    row = {
        "id": 4, "resource_id": 8, "status": "otp_required",
        "resource_title": "사건 제목", "case_number": "비공개 번호",
        "reason": "내부 사유", "otp_required_by": 9,
        "otp_required_by_name": "관리자", "requested_at": "시각",
    }
    assert resource_handler._public_assignment_request(row) == {
        "id": 4, "resource_id": 8, "status": "otp_required",
        "resource_title": "사건 제목",
    }


def test_break_glass_public_fields_only():
    """발동자의 활성 범위는 유지하고 정당화·세션 정보는 제외한다."""
    record = {
        "id": 3, "scope": "resource", "resource_id": 8,
        "min_grade": 4, "expires_at": "만료 시각", "status": "active",
        "justification": "민감한 정당화 사유", "session_id": 11,
        "ip": "접속 주소", "user_agent": "단말 정보", "metadata": {},
    }
    assert break_glass_handler._public_activation(record) == {
        "id": 3, "scope": "resource", "resource_id": 8,
        "min_grade": 4, "expires_at": "만료 시각", "status": "active",
    }


class _ApprovalDb:
    def execute(self, statement, params):
        if "FROM users" in statement:
            return _Result({"id": 5})
        assert "FROM login_approval_requests" in statement
        return _Result({"status": "pending", "expires_at": "내부 만료", "id": 12})

    def close(self):
        pass


class _Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [self.row]


class _StatusRequest:
    def get_argument(self, name, default=""):
        return "known_user"

    def write_json(self, payload):
        self.payload = payload


def test_login_approval_status_omits_internal_request_fields(monkeypatch):
    """인증 전 폴링 응답은 상태만 제공한다."""
    monkeypatch.setattr(admin_handler, "get_db", _ApprovalDb)
    request = _StatusRequest()

    admin_handler.AdminApprovalStatusHandler.get(request)

    assert request.payload == {"state": "pending", "expires_at": None}


class _AuthenticatedRequest:
    def require_auth(self):
        return {"user_id": 5}

    def write_json(self, payload):
        self.payload = payload


class _AssignmentDb:
    def execute(self, statement, params):
        assert "SELECT r.id, r.resource_id, r.status" in statement
        assert "SELECT r.*" not in statement
        return _Result({
            "id": 4, "resource_id": 8, "status": "otp_required",
            "resource_title": "사건 제목", "case_number": "비공개 번호",
        })

    def close(self):
        pass


def test_my_assignment_endpoint_uses_public_fields(monkeypatch):
    """요청자 상태 조회가 내부 사건번호를 보내지 않는다."""
    monkeypatch.setattr(resource_handler, "get_db", _AssignmentDb)
    request = _AuthenticatedRequest()

    resource_handler.MyCaseAssignmentRequestsHandler.get(request)

    assert request.payload == {
        "requests": [{
            "id": 4, "resource_id": 8,
            "status": "otp_required", "resource_title": "사건 제목",
        }],
        "total": 1,
    }


class _CreateAssignmentDb:
    def execute(self, statement, params):
        if "FROM resources" in statement:
            return _Result({"id": 8, "case_number": "비공개 번호"})
        if "FROM users" in statement:
            return _Result({
                "id": 5, "role": "user", "assigned_cases": [],
            })
        if "FROM case_assignment_requests" in statement:
            return _Result(None)
        if "INSERT INTO case_assignment_requests" in statement:
            return _Result({
                "id": 4, "resource_id": 8, "status": "pending_admin",
                "reason": "내부 사유", "requested_at": "내부 처리 시각",
            })
        assert "INSERT INTO audit_logs" in statement
        return _Result(None)

    def commit(self):
        pass

    def close(self):
        pass


class _CreateAssignmentRequest(_AuthenticatedRequest):
    request_id = "public-request-id"

    def get_json_body(self):
        return {"reason": "내부 사유"}

    def write_json(self, payload, status=200):
        self.payload = payload
        self.status = status


def test_assignment_creation_endpoint_omits_internal_record(monkeypatch):
    """담당 등록 생성 응답에는 감사용 사유와 처리 시각을 싣지 않는다."""
    monkeypatch.setattr(resource_handler, "get_db", _CreateAssignmentDb)
    monkeypatch.setattr(
        resource_handler, "assignment_compatibility", lambda requester, resource: (True, "")
    )
    request = _CreateAssignmentRequest()

    resource_handler.CaseAssignmentRequestHandler.post(request, "8")

    assert request.status == 201
    assert request.payload == {
        "message": "담당 사건 등록 요청을 보냈습니다.",
        "assignment_request": {
            "id": 4, "resource_id": 8, "status": "pending_admin",
        },
    }


def test_my_break_glass_endpoint_uses_public_fields(monkeypatch):
    """본인 활성 조회가 정당화 사유와 세션 정보를 보내지 않는다."""
    monkeypatch.setattr(break_glass_handler, "get_db", _AssignmentDb)
    monkeypatch.setattr(
        break_glass_handler.bg, "get_active_for_user",
        lambda db, user_id: [{
            "id": 3, "scope": "broad", "resource_id": None,
            "min_grade": 4, "expires_at": "만료 시각", "status": "active",
            "justification": "민감한 정당화 사유", "session_id": 11,
        }],
    )
    request = _AuthenticatedRequest()

    break_glass_handler.BreakGlassMyActiveHandler.get(request)

    assert request.payload == {
        "activations": [{
            "id": 3, "scope": "broad", "resource_id": None,
            "min_grade": 4, "expires_at": "만료 시각", "status": "active",
        }],
        "total": 1,
    }


class _ActivationDb:
    def execute(self, statement, params):
        assert "UPDATE user_devices SET last_otp_step" in statement
        return _Result(None)

    def commit(self):
        pass

    def close(self):
        pass


class _ActivationRequest(_AuthenticatedRequest):
    request_id = "public-request-id"

    def require_auth(self):
        return {"user_id": 5, "session_id": 11}

    def get_json_body(self):
        return {
            "justification": "긴급한 업무상 접근 사유", "scope": "resource",
            "resource_id": 8, "mfa_code": "123456",
        }

    def get_ip_address(self):
        return "접속 주소"

    class _HttpRequest:
        headers = {"User-Agent": "단말 정보"}

    request = _HttpRequest()


def test_break_glass_activation_endpoint_omits_internal_record(monkeypatch):
    """발동 응답은 정당화·세션·접속 정보를 반환하지 않는다."""
    monkeypatch.setattr(break_glass_handler, "get_db", _ActivationDb)
    monkeypatch.setattr(
        break_glass_handler.bg, "get_token_device_for_otp",
        lambda db, user_id: {"id": 2, "mfa_secret": "secret", "last_otp_step": None},
    )
    monkeypatch.setattr(
        break_glass_handler, "verify_totp_consume", lambda *args, **kwargs: (True, 123)
    )
    monkeypatch.setattr(
        break_glass_handler.bg, "activate", lambda **kwargs: {
            "id": 3, "scope": "resource", "resource_id": 8,
            "min_grade": 4, "expires_at": "만료 시각", "status": "active",
            "justification": "긴급한 업무상 접근 사유", "session_id": 11,
            "ip": "접속 주소", "user_agent": "단말 정보",
            "created_at": "내부 처리 시각",
        },
    )
    request = _ActivationRequest()

    break_glass_handler.BreakGlassActivateHandler.post(request)

    assert request.payload == {
        "message": "Break-Glass 발동 완료",
        "activation": {
            "id": 3, "scope": "resource", "resource_id": 8,
            "min_grade": 4, "expires_at": "만료 시각", "status": "active",
        },
    }


class _MeRequest(_AuthenticatedRequest):
    def require_auth(self):
        return {"user_id": 5, "session_id": 11}


class _MeDb:
    def execute(self, statement, params):
        if "FROM users" in statement:
            return _Result({
                "id": 5, "username": "tester", "name": "사용자",
                "role": "user", "trust_score": 80,
                "violation_count": 0, "department": "내부 부서",
                "registered_devices": ["device"],
                "allowed_locations": ["location"], "assigned_cases": [8],
            })
        assert "FROM sessions" in statement
        return _Result({
            "id": 11, "device_id": "device", "location": "location",
            "login_at": "접속 시각", "last_activity": None,
            "absolute_expires_at": None, "idle_timeout_seconds": 900,
            "max_sensitivity_accessed": 5, "is_admin_gated": False,
        })

    def close(self):
        pass


def test_me_endpoint_returns_identity_and_timer_only(monkeypatch):
    """내 정보 조회는 화면 타이머를 유지하면서 내부 접속 이력을 제외한다."""
    monkeypatch.setattr(auth_handler, "get_db", _MeDb)
    request = _MeRequest()

    auth_handler.MeHandler.get(request)

    assert request.payload == {
        "user": {
            "id": 5, "username": "tester", "name": "사용자",
            "role": "user", "trust_score": 80, "violation_count": 0,
        },
        "session": {
            "idle_timeout_seconds": 900,
            "idle_remaining_seconds": None,
            "absolute_remaining_seconds": None,
            "is_admin_gated": False,
        },
    }
