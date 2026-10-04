"""명시적 문서 복사 요청의 서버 권한 검사 회귀 테스트."""

from api import resource_handler


class FakeRequest:
    def __init__(self):
        self.response = None

    def require_auth(self):
        return {"user_id": 7, "session_id": 9}

    def get_simulated_hour(self):
        return 14

    def get_device_id(self):
        return "registered-001"

    def get_ip_address(self):
        return "192.168.1.1"

    def get_location(self):
        return "본청"

    def write_json(self, body, status=200):
        self.response = (status, body)


def test_copy_denial_never_returns_document_body(monkeypatch):
    """클라이언트 권한값과 무관하게 서버 결정이 복사 본문을 막는다."""
    def evaluate(**kwargs):
        assert kwargs["action_type"] == "copy"
        return {"request_id": "r1", "decision": {"external_message": "거부"},
                "resource": {"can_copy": False, "content": "비밀 본문"}}

    monkeypatch.setattr(resource_handler, "evaluate_access", evaluate)
    request = FakeRequest()
    resource_handler.CaseCopyHandler.post(request, "3")
    status, body = request.response
    assert status == 403
    assert body["code"] == "copy_not_allowed"
    assert "비밀 본문" not in str(body)


def test_copy_allowed_returns_server_evaluated_content(monkeypatch):
    """허용된 복사는 서버 평가 결과의 본문만 제공한다."""
    monkeypatch.setattr(resource_handler, "evaluate_access", lambda **kwargs: {
        "request_id": "r2", "resource": {"can_copy": True, "content": "허용 본문"},
    })
    request = FakeRequest()
    resource_handler.CaseCopyHandler.post(request, "3")
    assert request.response == (200, {"content": "허용 본문", "request_id": "r2"})
