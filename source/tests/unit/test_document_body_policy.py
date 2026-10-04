"""열람 권한별 문서 본문 응답 경계 회귀 테스트."""

import pytest

from api import resource_handler
from core.masking_engine import apply_masking, mask_content


@pytest.mark.parametrize("level", [3, 4])
def test_pending_gate_never_exposes_body_fields(level):
    """재인증·승인 전에는 마스킹된 일부라도 본문성 필드가 없어야 한다."""
    source = {
        "id": 1,
        "case_number": "2026-TEST-0001",
        "title": "테스트 문서",
        "description": "비밀 설명",
        "content": "비밀 본문\n두 번째 줄",
    }

    masked = apply_masking(source, level)

    assert masked["can_view"] is False
    assert "content" not in masked
    assert "description" not in masked
    assert "비밀 본문" not in str(masked)
    assert source["content"] == "비밀 본문\n두 번째 줄"
    assert mask_content(source["content"], level) == ""


@pytest.mark.parametrize("level", [1, 2])
def test_view_grant_returns_description_and_content(level):
    """인증·승인 뒤 열람 가능한 단계는 설명과 본문을 받는다."""
    resource = apply_masking({
        "id": 1, "description": "허용 설명", "content": "허용 본문",
    }, level)

    assert resource["can_view"] is True
    assert resource["description"] == "허용 설명"
    assert resource["content"] == "허용 본문"


def test_case_list_never_returns_assigned_or_unassigned_description(monkeypatch):
    """담당 사건이라도 목록 API는 상세 접근 평가 전 설명을 내리지 않는다."""
    class Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0]

    class Database:
        def execute(self, query, params=None):
            if "FROM resources" in query:
                assert "description" not in query
                assert "content" not in query
                return Cursor([
                    {"id": 1, "case_number": "A-1", "title": "담당 문서",
                     "description": "담당 비밀 설명", "content": "담당 비밀 본문",
                     "sensitivity_grade": 3, "data_type": "original",
                     "department": "강력범죄수사대", "requires_approval": False},
                    {"id": 2, "case_number": "B-2", "title": "비담당 문서",
                     "description": "비담당 비밀 설명", "content": "비담당 비밀 본문",
                     "sensitivity_grade": 4, "data_type": "evidence",
                     "department": "타부서", "requires_approval": True},
                ])
            return Cursor([{"assigned_cases": [1]}])

        def close(self):
            pass

    class Request:
        def require_auth(self):
            return {"user_id": 7}

        def write_json(self, payload):
            self.payload = payload

    monkeypatch.setattr(resource_handler, "get_db", Database)
    request = Request()
    resource_handler.CaseListHandler.get(request)

    assert request.payload["total"] == 2
    assert request.payload["cases"][0]["is_assigned_case"] is True
    assert request.payload["cases"][1]["is_assigned_case"] is False
    assert all("description" not in case and "content" not in case
               for case in request.payload["cases"])
    assert "비밀" not in str(request.payload)
