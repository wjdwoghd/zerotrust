"""자료 HTTP 경로가 내부 평가 결과를 그대로 직렬화하지 않는지 확인한다."""

import json
from unittest.mock import patch

import tornado.web
from tornado.testing import AsyncHTTPTestCase

from api.base_handler import BaseHandler
from api import resource_handler as handlers
from core.masking_engine import apply_masking


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class _Db:
    def execute(self, query, params=()):
        if "FROM resources ORDER BY" in query:
            return _Rows([{"id": 1, "case_number": "SECRET-001", "title": "자료",
                           "sensitivity_grade": 4, "requires_approval": True}])
        if "SELECT assigned_cases FROM users" in query:
            return _Rows([{"assigned_cases": [1]}])
        if "SELECT case_number, title, content FROM resources" in query:
            return _Rows([{"case_number": "SECRET-001", "title": "자료",
                           "content": "SECRET BODY"}])
        raise AssertionError(query)

    def close(self):
        pass


class TestCaseHttpResponse(AsyncHTTPTestCase):
    def get_app(self):
        self.level = 3
        patches = [
            patch.object(BaseHandler, "require_auth", return_value={"user_id": 1, "session_id": 1}),
            patch.object(handlers, "get_db", return_value=_Db()),
            patch.object(handlers, "evaluate_access", side_effect=self._evaluate),
            patch.object(handlers, "_log_score_change_if_needed"),
        ]
        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)
        return tornado.web.Application([
            (r"/api/resources/cases", handlers.CaseListHandler),
            (r"/api/resources/cases/(\d+)/status", handlers.CaseAccessStatusHandler),
            (r"/api/resources/cases/(\d+)", handlers.CaseDetailHandler),
            (r"/api/resources/cases/(\d+)/download", handlers.CaseDownloadHandler),
            (r"/api/resources/cases/(\d+)/file", handlers.CaseFileHandler),
        ])

    def _evaluate(self, **kwargs):
        resource = apply_masking({
            "id": 1, "title": "자료", "sensitivity_grade": 4,
            "case_number": "SECRET-001", "description": "SECRET SUMMARY",
            "content": "SECRET BODY", "attachment": "SECRET FILE",
        }, self.level)
        permissions = {key: resource[key] for key in
                       ("can_view", "can_download", "can_copy", "can_print")}
        return {
            "request_id": "req-1", "resource": resource,
            "decision": {"level": self.level, "label": "조치 필요",
                         "label_en": "VERIFY", "risk_score": 72,
                         "reason": "SECRET RULE", **permissions},
            "scoring": {"total": {"total_risk_score": 72}},
            "policy_check": {"reason": "SECRET RULE"},
        }

    def _json(self, path, method="GET"):
        response = self.fetch(path, method=method, body=b"{}" if method == "POST" else None)
        return response.code, json.loads(response.body)

    def test_closed_routes_exclude_body_and_scores(self):
        code, listing = self._json("/api/resources/cases")
        assert code == 200
        assert "description" not in listing["cases"][0]
        for level in (3, 4):
            self.level = level
            for method, suffix in (("GET", ""), ("GET", "/status"),
                                   ("POST", "/download"), ("GET", "/file")):
                code, data = self._json(f"/api/resources/cases/1{suffix}", method)
                assert code == (403 if suffix == "/file" else 200)
                assert data["decision"]["can_view"] is False
                assert "SECRET" not in str(data)
                assert "scoring" not in data

    def test_open_and_reclose_rechecks_file(self):
        self.level = 1
        code, detail = self._json("/api/resources/cases/1")
        assert code == 200
        assert detail["resource"]["content"] == "SECRET BODY"
        assert "attachment" not in detail["resource"]
        code, status = self._json("/api/resources/cases/1/status")
        assert code == 200 and "content" not in status["resource"]
        response = self.fetch("/api/resources/cases/1/file")
        assert response.code == 200 and b"SECRET BODY" in response.body
        self.level = 4
        code, denied = self._json("/api/resources/cases/1/file")
        assert code == 403 and "content" not in denied["resource"]
