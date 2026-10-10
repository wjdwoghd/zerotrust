"""HTTP boundary and failure isolation for approval AI advice (phase 6 run)."""
import json

import tornado.web
from tornado.testing import AsyncHTTPTestCase

from api import admin_handler as admin
from api.base_handler import BaseHandler
from core.approval_review_facts import load_approval_review_facts
from integrations.openai_review_transport import MissingApiKeyError, ModelTimeoutError, ReviewApiError
from tests.unit.test_approval_review_facts import _ReadDb


class ApprovalAiApiTest(AsyncHTTPTestCase):
    def get_app(self):
        self.calls = []
        self.audits = []
        self.failure = None
        self.status = "pending"
        self.orig = (BaseHandler.require_admin, admin.get_db,
                     admin.load_approval_review_facts, admin.generate_approval_review,
                     admin.audit_log)

        def guard(handler):
            role = handler.request.headers.get("X-Test-Role")
            if role not in ("admin", "deputy_admin", "superadmin"):
                handler.write_error_json("forbidden", 401 if role is None else 403, code="forbidden")
                return None
            return {"user_id": int(handler.request.headers.get("X-Test-User", "2")), "role": role}

        class Db:
            def close(self):
                pass

        def load(_db, approval_id, reviewer_id):
            return load_approval_review_facts(_ReadDb(status=self.status), approval_id, reviewer_id)

        def generate(**kwargs):
            self.calls.append(kwargs)
            if self.failure:
                raise self.failure("provider response must not be logged")
            return {"reason_summary": "분석 불가: 요청 사유 원문 미전송",
                    "missing_items": [], "contradictions": [], "similar_decisions": [],
                    "review_opinion": "check_further", "uncertainties": [], "evidence_refs": []}

        BaseHandler.require_admin = guard
        admin.get_db = lambda: Db()
        admin.load_approval_review_facts = load
        admin.generate_approval_review = generate
        admin.audit_log = lambda _db, event, **kw: self.audits.append(kw["details"])
        self.addCleanup(self.restore)
        return tornado.web.Application([(r"/api/admin/approvals/(\d+)/ai-review", admin.ApprovalAiReviewHandler)])

    def restore(self):
        (BaseHandler.require_admin, admin.get_db,
         admin.load_approval_review_facts, admin.generate_approval_review,
         admin.audit_log) = self.orig

    def request_review(self, role="admin", user=2):
        headers = {"X-Test-User": str(user)}
        if role is not None:
            headers["X-Test-Role"] = role
        response = self.fetch("/api/admin/approvals/10/ai-review", method="POST", body="", headers=headers)
        return response.code, json.loads(response.body)

    def test_authorization_and_pending_state(self):
        assert self.request_review(None)[0] == 401
        assert self.request_review("user")[0] == 403
        assert self.request_review("admin", 1)[0] == 403
        self.status = "approved"
        assert self.request_review()[0] == 409
        assert self.calls == []

    def test_success_repeated_calls_do_not_write_approval(self):
        for role in ("admin", "deputy_admin", "superadmin"):
            status, data = self.request_review(role)
            assert status == 200
            assert data["ai_review"]["review_opinion"] == "check_further"
            assert data["policy_facts"]["request"]["status"]["value"] == "pending"
        assert len(self.calls) == 3
        assert all(a["status"] == "succeeded" for a in self.audits[-3:])

    def test_provider_errors_are_explicit_and_do_not_block_manual_path(self):
        for error, expected in ((MissingApiKeyError, "key_not_configured"),
                                (ModelTimeoutError, "model_timeout")):
            self.failure = error
            status, data = self.request_review()
            assert status in (503, 504) and data["code"] == expected
            assert "provider response" not in json.dumps(data)
        self.failure = None
        assert self.request_review()[0] == 200

    def test_exhausted_credits_are_explicit_without_provider_content(self):
        self.failure = lambda _: ReviewApiError(429, "credit_balance_exhausted")
        status, data = self.request_review()
        assert status == 503
        assert data["code"] == "ai_credits_exhausted"
        assert self.audits[-1]["error_code"] == "ai_credits_exhausted"
        assert "provider response" not in json.dumps(data)
