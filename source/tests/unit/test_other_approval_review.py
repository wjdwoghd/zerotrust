"""Phase 4 contracts. Intentionally left for final phase 6 batch validation."""
from datetime import datetime, timezone

import pytest

from core.approval_review_facts import ReviewFactsError
from core.other_approval_review import load_review_facts, build_model_input, validate_review
from integrations.openai_scenario_client import ModelOutputError


NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


class ReadDb:
    def __init__(self, kind, status=None, owner=1, role="admin", event=True):
        self.kind, self.status, self.owner, self.role, self.event = kind, status, owner, role, event
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append(sql)
        if "SELECT CURRENT_TIMESTAMP" in sql:
            self.rows = [{"observed_at": NOW}]
        elif "FROM login_approval_requests" in sql:
            self.rows = [{"id": 10, "user_id": self.owner,
                          "status": self.status or "pending", "requested_at": NOW,
                          "expires_at": None}]
        elif "FROM case_assignment_requests" in sql:
            self.rows = [{"id": 10, "requester_id": self.owner, "resource_id": 9,
                          "reviewer_role": self.role, "status": self.status or "otp_verified",
                          "requested_at": NOW, "otp_required_at": NOW,
                          "otp_verified_at": NOW}]
        elif "FROM break_glass_activations" in sql:
            self.rows = [{"id": 10, "activator_id": self.owner,
                          "status": self.status or "released", "scope": "broad",
                          "min_grade": 4, "activated_at": NOW, "expires_at": NOW,
                          "reviewed_at": None}]
        elif "FROM audit_logs" in sql:
            self.rows = [{"id": 31, "created_at": NOW}] if self.event else []
        elif "FROM users" in sql:
            self.rows = [{"department": "secret department", "job_scope": ["cyber"]}]
        elif "FROM resources" in sql:
            self.rows = [{"department": "secret department", "job_tags": ["cyber"]}]
        else:
            self.rows = []
        return self

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.mark.parametrize("kind", ["login", "assignment", "break_glass"])
def test_projection_is_minimal_and_read_only(kind):
    db = ReadDb(kind)
    facts = load_review_facts(db, kind, 10, 2, "admin")
    payload, aliases = build_model_input(facts)
    assert payload["review_type"] == kind
    assert "secret department" not in str(payload)
    assert "requester_id" not in str(payload)
    assert "activation_id" not in str(payload)
    assert aliases
    assert not any("UPDATE " in sql or "INSERT " in sql for sql in db.statements)


@pytest.mark.parametrize("kind,status", [("login", "used"),
    ("assignment", "otp_required"), ("break_glass", "active")])
def test_type_state_and_self_review_guard(kind, status):
    if kind != "assignment":
        with pytest.raises(ReviewFactsError):
            load_review_facts(ReadDb(kind, status=status), kind, 10, 2, "admin")
    else:
        facts = load_review_facts(ReadDb(kind, status=status), kind, 10, 2, "admin")
        assert facts["fields"]["otp_state"]["value"] == "required"
    with pytest.raises(ReviewFactsError):
        load_review_facts(ReadDb(kind), kind, 10, 1, "admin")


def test_assignment_reviewer_role_and_missing_audit():
    with pytest.raises(ReviewFactsError):
        load_review_facts(ReadDb("assignment", role="deputy_admin"), "assignment", 10, 2, "admin")
    facts = load_review_facts(ReadDb("assignment", event=False), "assignment", 10, 2, "admin")
    payload, _ = build_model_input(facts)
    assert payload["fields"]["request_audit"]["unknown_reason"]


def test_missing_assignment_scope_is_unknown_not_mismatch():
    class MissingDepartment(ReadDb):
        def execute(self, sql, params=()):
            result = super().execute(sql, params)
            if "FROM users" in sql:
                self.rows[0]["department"] = None
            return result

    facts = load_review_facts(MissingDepartment("assignment"), "assignment", 10, 2, "admin")
    assert facts["fields"]["current_scope_compatible"]["value"] is None
    assert facts["fields"]["current_scope_compatible"]["unknown_reason"] == "current_scope_unavailable"


def test_unobserved_alias_and_invalid_decision_are_rejected():
    aliases = {"E1": ("audit_logs", 31)}
    raw = {"review_opinion": "check_further", "items": [], "uncertainties": [],
           "evidence_refs": ["E999"]}
    with pytest.raises(ModelOutputError):
        validate_review(raw, aliases)
    raw["evidence_refs"] = []
    raw["review_opinion"] = "approved"
    with pytest.raises(ModelOutputError):
        validate_review(raw, aliases)
