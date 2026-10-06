"""Review facts are evidence-linked and never invoke the access evaluator."""
from datetime import datetime, timezone

import pytest

from core.approval_review_facts import ReviewFactsError, load_approval_review_facts


NOW = datetime(2026, 10, 6, 1, tzinfo=timezone.utc)


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _ReadDb:
    def __init__(self, *, status="pending", reviewer_id=2, reason="case work",
                 events=None, access=None, prior=None, fail_access=False):
        self.statements = []
        self.row = {
            "id": 10, "requester_id": 1, "resource_id": 20,
            "reason": reason, "status": status, "requested_at": NOW,
            "user_department": "A", "assigned_cases": ["CASE-1"],
            "job_scope": ["investigation"], "case_number": "CASE-1",
            "resource_department": "A", "job_tags": ["investigation"],
            "sensitivity_grade": 4, "requires_approval": False,
        }
        self.events = events if events is not None else [self.event()]
        self.access = access if access is not None else [
            {"id": 50, "created_at": NOW, "risk_score": 75,
             "decision_level": 4}]
        self.prior = prior if prior is not None else []
        self.fail_access = fail_access

    def event(self, **changes):
        details = {"approval_id": 10, "resource_id": 20,
                   "reason": self.row["reason"], "origin": "user_explicit",
                   "reason_source": "user_input", "want_download": True}
        details.update(changes)
        return {"id": 30, "created_at": NOW, "details": details}

    def execute(self, sql, params=()):
        self.statements.append(sql)
        if sql.startswith("SET TRANSACTION"):
            return _Result([])
        if "CURRENT_TIMESTAMP AS observed_at" in sql:
            return _Result([{"observed_at": NOW}])
        if "FROM approvals a" in sql:
            return _Result([self.row])
        if "FROM operation_logs" in sql:
            return _Result(self.events)
        if "FROM access_logs" in sql:
            if self.fail_access:
                raise RuntimeError("access facts unavailable")
            return _Result(self.access)
        if "FROM approvals" in sql:
            return _Result(self.prior)
        raise AssertionError(sql)


def test_verified_facts_are_read_only_and_keep_policy_levels_separate():
    db = _ReadDb(prior=[{"id": 3, "status": "rejected", "resolved_at": NOW,
                         "approver_id": 9, "download_allowed": False}])
    result = load_approval_review_facts(db, 10, 2)
    assert result["request"]["want_download"]["value"] is True
    assert result["request"]["want_download"]["source"] == {"table": "operation_logs", "id": 30}
    assert result["request"]["reason_origin"]["value"] == "user_input"
    assert result["work_relation"]["assigned_case"]["value"] is True
    assert result["resource"]["approval_basis"]["value"]["grade_at_least_four"] is True
    assert result["policy_facts"]["last_observed_risk_score"]["value"] == 75.0
    assert result["policy_facts"]["last_observed_final_level"]["value"] == 4
    assert result["policy_facts"]["score_base_level"]["unknown_reason"]
    assert result["policy_facts"]["current_evaluation"]["unknown_reason"]
    assert result["past_decisions"]["records"][0]["approval_id"] == 3
    assert result["past_decisions"]["comparison"] == "unavailable"
    assert db.statements[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    assert all(s.strip().startswith(("SELECT", "SET TRANSACTION")) for s in db.statements)


def test_default_reason_and_legacy_reason_have_distinct_unknown_handling():
    db = _ReadDb(reason="사용자 명시 요청 - 고민감 자료 접근")
    db.events = [db.event(reason_source="server_default")]
    assert load_approval_review_facts(db, 10, 2)["request"]["reason_origin"]["value"] == "server_default"
    db.events = [db.event(reason_source=None)]
    result = load_approval_review_facts(db, 10, 2)
    assert result["request"]["reason_origin"]["unknown_reason"] == "legacy_reason_origin_not_recorded"
    db.events = [db.event(reason_source="server_default", reason="different")]
    assert load_approval_review_facts(db, 10, 2)["request"]["reason_origin"]["value"] is None


def test_audit_link_failure_and_no_prior_decision_are_explicit():
    db = _ReadDb(events=[])
    result = load_approval_review_facts(db, 10, 2)
    assert result["request"]["want_download"]["unknown_reason"] == "request_audit_missing_or_ambiguous"
    assert result["past_decisions"]["records"] == []
    assert result["past_decisions"]["unknown_reason"] == "no_prior_decision_for_exact_pair"
    db.events = [db.event(resource_id=999)]
    assert load_approval_review_facts(db, 10, 2)["request"]["want_download"]["value"] is None
    db.events = [db.event(), db.event()]
    assert load_approval_review_facts(db, 10, 2)["request"]["want_download"]["value"] is None


@pytest.mark.parametrize("status,reviewer,code", [
    ("approved", 2, "approval_not_pending"),
    ("pending", 1, "self_approval_forbidden"),
])
def test_ineligible_request_fails_before_evidence_reads(status, reviewer, code):
    db = _ReadDb(status=status)
    with pytest.raises(ReviewFactsError) as exc:
        load_approval_review_facts(db, 10, reviewer)
    assert exc.value.code == code
    assert not any("FROM access_logs" in s for s in db.statements)


def test_policy_query_failure_is_not_reported_as_success():
    with pytest.raises(RuntimeError, match="access facts unavailable"):
        load_approval_review_facts(_ReadDb(fail_access=True), 10, 2)


def test_missing_required_approval_basis_fails_closed():
    db = _ReadDb()
    db.row["sensitivity_grade"] = 2
    with pytest.raises(ReviewFactsError) as exc:
        load_approval_review_facts(db, 10, 2)
    assert exc.value.code == "approval_basis_missing"
