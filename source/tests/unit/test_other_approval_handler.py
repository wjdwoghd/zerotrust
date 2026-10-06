"""Phase 4 HTTP isolation checks; run with the final phase 6 suite."""
import json

import tornado.web
from tornado.testing import AsyncHTTPTestCase

from api import other_approval_review_handler as handler
from api.base_handler import BaseHandler
from tests.unit.test_other_approval_review import ReadDb
from integrations.openai_review_transport import ModelTimeoutError


class OtherReviewApiTest(AsyncHTTPTestCase):
    def get_app(self):
        self.calls = 0
        self.audits = []
        self.fail = False
        self.db = ReadDb("assignment")
        original = (BaseHandler.require_admin, handler.get_db,
                    handler.generate_review, handler.audit_log)

        def guard(instance):
            role = instance.request.headers.get("X-Role")
            if role != "admin":
                instance.write_error_json("forbidden", 403, code="forbidden")
                return None
            return {"user_id": int(instance.request.headers.get("X-User", "2")), "role": role}

        class Db:
            def execute(_, sql, params=()):
                return self.db.execute(sql, params)

            def close(_):
                pass

        def generate(**kwargs):
            self.calls += 1
            if self.fail:
                raise ModelTimeoutError("do not log provider content")
            return {"review_opinion": "check_further", "items": [],
                    "uncertainties": [], "evidence_refs": []}

        BaseHandler.require_admin = guard
        handler.get_db = lambda: Db()
        handler.generate_review = generate
        handler.audit_log = lambda _db, _event, **kwargs: self.audits.append(kwargs["details"])
        self.addCleanup(lambda: (
            setattr(BaseHandler, "require_admin", original[0]),
            setattr(handler, "get_db", original[1]),
            setattr(handler, "generate_review", original[2]),
            setattr(handler, "audit_log", original[3])))
        return tornado.web.Application([
            (r"/api/admin/reviews/(assignment)/(\d+)/facts", handler.OtherApprovalFactsHandler),
            (r"/api/admin/reviews/(assignment)/(\d+)/ai-review", handler.OtherApprovalAiHandler),
            (r"/api/admin/audit-candidates/emergency-access", handler.EmergencyAuditCandidatesHandler),
            (r"/api/admin/audit-candidates/repeated-unassigned", handler.RepeatedUnassignedCandidatesHandler),
        ])

    def request(self, ai=False, role="admin", user=2):
        return self.fetch("/api/admin/reviews/assignment/10/" +
                          ("ai-review" if ai else "facts"),
                          method="POST" if ai else "GET", body="" if ai else None,
                          headers={"X-Role": role, "X-User": str(user)})

    def test_role_self_and_manual_state_untouched(self):
        assert self.request(role="user").code == 403
        assert self.request(user=1).code == 403
        assert self.request().code == 200
        for _ in range(2):
            result = self.request(ai=True)
            assert result.code == 200
            assert json.loads(result.body)["ai_review"]["review_opinion"] == "check_further"
        assert self.calls == 2
        assert all("UPDATE " not in sql and "INSERT " not in sql for sql in self.db.statements)

    def test_provider_error_does_not_change_manual_path(self):
        self.fail = True
        response = self.request(ai=True)
        assert response.code == 504
        assert json.loads(response.body)["code"] == "model_timeout"
        assert self.request().code == 200
        assert self.audits[-1]["status"] == "failed"

    def test_candidates_are_admin_only_and_keep_evidence_ids(self):
        class CandidateDb(ReadDb):
            def execute(self, sql, params=()):
                if "JOIN LATERAL" in sql:
                    self.rows = [{"id": 40, "prior_id": 30,
                                  "created_at": __import__("datetime").datetime.now(
                                      __import__("datetime").timezone.utc)}]
                    return self
                return super().execute(sql, params)

        self.db = CandidateDb("assignment")
        path = "/api/admin/audit-candidates/repeated-unassigned"
        assert self.fetch(path, headers={"X-Role": "user"}).code == 403
        response = self.fetch(path, headers={"X-Role": "admin"})
        assert response.code == 200
        assert json.loads(response.body)["candidates"][0]["audit_ids"] == [30, 40]
