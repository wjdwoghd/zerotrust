"""Administrator policy lab API contract without external calls or a database."""

import json

import pytest
import tornado.web
from tornado.testing import AsyncHTTPTestCase

from api import policy_lab_handler as lab
from api.base_handler import BaseHandler
from integrations.openai_scenario_client import (
    MissingApiKeyError, ModelOutputError, ModelRefusalError,
    ModelTimeoutError, ScenarioGenerationError,
)


class ChallengeApiTest(AsyncHTTPTestCase):
    """Exercise Tornado request parsing, role guard, errors and audit boundaries."""

    def get_app(self):
        self.calls = []
        self.audits = []
        self.result = {"scenarios": [{"synthetic_conditions": {},
                                     "policy_engine_result": {"score_level": 2},
                                     "ai_explanation": "synthetic"}]}
        self.original_guard = BaseHandler.require_admin
        self.original_run = lab.run_configured_challenge
        self.original_db = lab.get_db
        self.original_audit = lab.audit_log

        def guard(handler):
            role = handler.request.headers.get("X-Test-Role")
            if role is None:
                handler.write_error_json("인증 필요", 401, code="token_invalid")
                return None
            if role not in ("admin", "superadmin", "deputy_admin"):
                handler.write_error_json("권한 없음", 403, code="forbidden")
                return None
            return {"user_id": 42, "role": role}

        class Db:
            def close(self):
                pass

        def run(**kwargs):
            self.calls.append(kwargs)
            return self.result

        BaseHandler.require_admin = guard
        lab.run_configured_challenge = run
        lab.get_db = lambda: Db()
        lab.audit_log = lambda _db, event, **kwargs: self.audits.append((event, kwargs))
        self.addCleanup(self._restore)
        return tornado.web.Application([
            (r"/api/admin/policy-lab/challenges", lab.PolicyLabChallengeHandler),
        ])

    def _restore(self):
        BaseHandler.require_admin = self.original_guard
        lab.run_configured_challenge = self.original_run
        lab.get_db = self.original_db
        lab.audit_log = self.original_audit

    def request(self, body, role="admin"):
        headers = {"Content-Type": "application/json"}
        if role is not None:
            headers["X-Test-Role"] = role
        response = self.fetch(
            "/api/admin/policy-lab/challenges", method="POST",
            headers=headers, body=json.dumps(body),
        )
        return response.code, json.loads(response.body)

    def test_roles_and_success(self):
        for role, expected in ((None, 401), ("user", 403),
                               ("admin", 200), ("deputy_admin", 200)):
            status, data = self.request({"goal": "boundary", "count": 1}, role)
            assert status == expected
            if status == 200:
                assert data["scenarios"][0]["ai_explanation"] == "synthetic"
        assert len(self.calls) == 2
        assert len(self.audits) == 2
        assert self.audits[0][1]["details"] == {
            "goal": "boundary", "count": 1,
            "status": "succeeded", "error_code": None,
        }

    def test_rejected_inputs_never_call_model(self):
        bad = [
            ({"goal": "approval_path", "count": 1}, "unsupported_goal"),
            ({"goal": "boundary", "count": 9}, "invalid_request"),
            ({"goal": "boundary", "count": True}, "invalid_request"),
            ({"goal": "boundary", "count": 1, "prompt": "secret"}, "invalid_request"),
            ({"goal": "boundary", "count": 1,
              "allowed_values": {"sensitivity_grade": [99]}}, "invalid_request"),
        ]
        for body, code in bad:
            status, data = self.request(body)
            assert status == 400 and data["code"] == code
        assert not self.calls
        assert len(self.audits) == len(bad)
        assert "secret" not in json.dumps(self.audits)

    def test_safe_error_mapping(self):
        cases = [
            (MissingApiKeyError, "key_not_configured", 503),
            (ModelRefusalError, "model_refusal", 502),
            (ModelTimeoutError, "model_timeout", 504),
            (ModelOutputError, "model_output_invalid", 502),
            (ScenarioGenerationError, "openai_error", 502),
        ]
        for error, code, expected_status in cases:
            def fail(**_kwargs):
                raise error("secret-key model response")
            lab.run_configured_challenge = fail
            status, data = self.request({"goal": "boundary", "count": 1})
            assert status == expected_status and data["code"] == code
            assert "secret-key" not in json.dumps(data)
        def out_of_range(**_kwargs):
            raise ModelOutputError("scenario condition is outside allowed_values: hour")
        lab.run_configured_challenge = out_of_range
        status, data = self.request({"goal": "boundary", "count": 1})
        assert status == 502 and data["code"] == "model_output_out_of_range"
        assert all(item[1]["details"]["status"] == "failed" for item in self.audits)
