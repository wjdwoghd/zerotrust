"""Phase 5 measurement checks; intentionally run with the phase 6 suite."""
import json
from datetime import datetime, timedelta, timezone

import tornado.web
from tornado.testing import AsyncHTTPTestCase

from api import approval_effect_handler as handler
from api.base_handler import BaseHandler
from core.approval_effect import measure


START = datetime(2026, 10, 1, tzinfo=timezone.utc)
END = START + timedelta(days=2)


class Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class ReadDb:
    def __init__(self):
        self.statements = []
        self.requests = {kind: [] for kind in ("approvals", "login_approval_requests",
                          "case_assignment_requests", "break_glass_activations")}
        self.decisions = {}
        self.ai = {}

    def execute(self, sql, params=()):
        self.statements.append(sql)
        if sql.startswith("SET TRANSACTION"):
            return Rows([])
        if "FROM audit_logs" in sql and "OTHER_APPROVAL_AI_REVIEW" in sql:
            return Rows(self.ai.get((params[0], int(params[1])), []))
        if "FROM audit_logs" in sql and "APPROVAL_AI_REVIEW" in sql:
            return Rows(self.ai.get(("resource", int(params[0])), []))
        if "FROM audit_logs" in sql:
            return Rows(self.decisions.get((params[0], int(params[2])), []))
        for table, rows in self.requests.items():
            if f"FROM {table} " in sql:
                return Rows(rows)
        raise AssertionError(sql)

    def close(self):
        pass


def request(request_id, status="approved", reviewer=7):
    return {"id": request_id, "status": status, "began": START,
            "finished": START + timedelta(minutes=20), "reviewer_id": reviewer,
            "resource_id": 33}


def audit(audit_id, resource_id="33"):
    return {"id": audit_id, "created_at": START + timedelta(minutes=20),
            "user_id": 7, "resource_id": resource_id}


def ai(audit_id, status="succeeded"):
    return {"id": audit_id, "created_at": START + timedelta(minutes=5),
            "user_id": 7, "status": status}


def test_waiting_time_ai_unused_and_duplicate_exclusion():
    db = ReadDb()
    db.requests["approvals"] = [request(1), request(2), request(3), request(4)]
    db.decisions = {("APPROVAL_GRANTED", 1): [audit(101)],
                    ("APPROVAL_GRANTED", 2): [audit(102)],
                    ("APPROVAL_GRANTED", 3): [audit(103), audit(104)],
                    ("APPROVAL_GRANTED", 4): [audit(106)]}
    db.ai = {("resource", 1): [ai(201), ai(202)],
             ("resource", 2): [ai(203, "failed")]}
    data = measure(db, START, END)["types"]["resource"]
    assert data["groups"]["ai_call_succeeded"]["denominator"] == 1
    assert data["groups"]["ai_call_succeeded"]["mean_wait_seconds"] == 1200
    assert data["groups"]["ai_call_succeeded"]["active_review_seconds"] is None
    assert data["groups"]["ai_call_succeeded"]["evidence"][0]["ai_audit_ids"] == [201, 202]
    assert data["groups"]["no_ai_call"]["denominator"] == 1
    assert {item["reason"] for item in data["unknown_evidence"]} == {
        "decision_audit_ambiguous", "ai_exposure_ambiguous"}
    assert all("INSERT " not in sql and "UPDATE " not in sql for sql in db.statements)


def test_missing_case_and_audit_are_candidates_not_confirmed_effects():
    db = ReadDb()
    db.requests["case_assignment_requests"] = [request(5), request(6)]
    db.decisions = {("CASE_ASSIGNMENT_APPROVED", 5): [audit(105, None)]}
    data = measure(db, START, END)["types"]["assignment"]
    assert data["audit_omission_candidates"] == 2
    assert data["audit_omission_denominator"] == 2
    assert {item["reason"] for item in data["unknown_evidence"]} == {
        "required_case_id_missing", "decision_audit_missing"}
    assert data["groups"]["ai_call_succeeded"]["denominator"] == 0


def test_login_and_break_glass_keep_distinct_lifecycle_clocks():
    db = ReadDb()
    db.requests["login_approval_requests"] = [request(8)]
    db.requests["break_glass_activations"] = [request(9, "reviewed_justified")]
    db.decisions = {("ADMIN_APPROVAL_GRANTED", 8): [audit(108, None)],
                    ("BREAK_GLASS_REVIEWED_JUSTIFIED", 9): [audit(109, None)]}
    data = measure(db, START, END)["types"]
    for kind, expected_audit in (("login", 108), ("break_glass", 109)):
        group = data[kind]["groups"]["no_ai_call"]
        assert group["denominator"] == 1
        assert group["evidence"][0]["decision_audit_id"] == expected_audit
        assert group["mean_wait_seconds"] == 1200


class EffectApiTest(AsyncHTTPTestCase):
    def get_app(self):
        original = (BaseHandler.require_admin, handler.get_db)
        self.db = ReadDb()

        def guard(instance):
            if instance.request.headers.get("X-Role") != "admin":
                instance.write_error_json("forbidden", 403, code="forbidden")
                return None
            return {"user_id": 7, "role": "admin"}

        BaseHandler.require_admin = guard
        handler.get_db = lambda: self.db
        self.addCleanup(lambda: (setattr(BaseHandler, "require_admin", original[0]),
                                 setattr(handler, "get_db", original[1])))
        return tornado.web.Application([(r"/api/admin/approval-effects", handler.ApprovalEffectHandler)])

    def test_permission_period_and_missing_values(self):
        path = "/api/admin/approval-effects?start=2026-10-01T00:00:00%2B00:00&end=2026-10-03T00:00:00%2B00:00"
        assert self.fetch(path).code == 403
        response = self.fetch(path, headers={"X-Role": "admin"})
        assert response.code == 200
        body = json.loads(response.body)
        assert body["types"]["login"]["groups"]["no_ai_call"]["mean_wait_seconds"] is None
        assert self.fetch("/api/admin/approval-effects", headers={"X-Role": "admin"}).code == 400
