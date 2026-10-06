"""Read-only, server-observed facts for a pending resource approval.

This module never evaluates access. An access evaluation writes access/audit logs
and can change the behavior score used by later evaluations.
"""
from __future__ import annotations

import json

from database import row_to_dict


DEFAULT_REASON = "사용자 명시 요청 - 고민감 자료 접근"


class ReviewFactsError(ValueError):
    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code = code
        self.status = status


def _time(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _fact(value=None, table=None, row_id=None, observed_at=None,
          unknown_reason=None, related_sources=None):
    return {
        "value": value if unknown_reason is None else None,
        "source": {"table": table, "id": row_id} if table and row_id is not None else None,
        "related_sources": related_sources or [],
        "observed_at": _time(observed_at),
        "unknown_reason": unknown_reason,
    }


def _details(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def load_approval_review_facts(db, approval_id: int, reviewer_id: int) -> dict:
    """Read a consistent snapshot. Caller must already enforce administrator role."""
    db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    clock = db.execute("SELECT CURRENT_TIMESTAMP AS observed_at").fetchone()["observed_at"]
    row = db.execute("""
        SELECT a.id, a.requester_id, a.resource_id, a.reason, a.status,
               a.requested_at, u.department AS user_department,
               u.assigned_cases, u.job_scope, r.case_number,
               r.department AS resource_department, r.job_tags,
               r.sensitivity_grade, r.requires_approval
          FROM approvals a
          LEFT JOIN users u ON u.id = a.requester_id
          LEFT JOIN resources r ON r.id = a.resource_id
         WHERE a.id = ?
    """, (approval_id,)).fetchone()
    if row is None:
        raise ReviewFactsError("approval_not_found", 404)
    if row["status"] != "pending":
        raise ReviewFactsError("approval_not_pending", 409)
    if row["requester_id"] == reviewer_id:
        raise ReviewFactsError("self_approval_forbidden", 403)
    required = ("requester_id", "resource_id", "requested_at", "reason",
                "user_department", "sensitivity_grade",
                "requires_approval")
    if any(row[key] is None for key in required):
        raise ReviewFactsError("approval_facts_incomplete", 409)
    if not row["requires_approval"] and row["sensitivity_grade"] < 4:
        raise ReviewFactsError("approval_basis_missing", 409)
    row = row_to_dict(row)
    aid = row["id"]
    rid = row["resource_id"]
    uid = row["requester_id"]
    requested_at = row["requested_at"]
    source_time = requested_at

    assigned = row["assigned_cases"] or []
    if isinstance(assigned, list):
        assigned_case = _fact(
            rid in assigned or str(row["case_number"]) in [str(x) for x in assigned],
            "users", uid, clock,
            related_sources=[{"table": "resources", "id": rid}],
        )
    else:
        assigned_case = _fact(unknown_reason="invalid_assignment_data")
    job_scope = row["job_scope"] or []
    job_tags = row["job_tags"] or []
    if (not isinstance(job_scope, list) or not isinstance(job_tags, list)
            or not all(isinstance(value, str) for value in job_scope + job_tags)):
        job_related = _fact(unknown_reason="invalid_job_relation_data")
    else:
        job_related = _fact(bool(set(job_scope) & set(job_tags)), "users", uid, clock,
                            related_sources=[{"table": "resources", "id": rid}])

    # Both approval_id and the other request attributes must agree. A missing,
    # expired, or ambiguous operation event cannot establish want_download.
    events = db.execute("""
        SELECT id, created_at, details FROM operation_logs
         WHERE event_type='ADMIN_APPROVAL_REQUESTED' AND user_id=?
           AND details->>'approval_id'=? AND created_at>=?
           AND created_at<=? + INTERVAL '5 minutes'
         ORDER BY id
    """, (uid, str(aid), requested_at, requested_at)).fetchall()
    verified = []
    for event in events:
        details = _details(event["details"])
        if (details.get("resource_id") == rid
                and details.get("reason") == row["reason"]
                and details.get("origin") == "user_explicit"):
            verified.append((event, details))
    event, details = verified[0] if len(verified) == 1 else (None, {})
    if event is None:
        event_reason = "request_audit_missing_or_ambiguous"
        download = _fact(unknown_reason=event_reason)
    elif type(details.get("want_download")) is not bool:
        download = _fact(unknown_reason="request_audit_download_missing")
    else:
        download = _fact(details["want_download"], "operation_logs", event["id"], event["created_at"])

    # Older rows did not record whether the default text came from the user.
    # Equality with the default string alone does not prove its origin.
    reason_source = details.get("reason_source") if event is not None else None
    if reason_source == "user_input" or (reason_source == "server_default"
                                          and row["reason"] == DEFAULT_REASON):
        reason_origin = _fact(reason_source, "operation_logs", event["id"], event["created_at"])
    else:
        reason_origin = _fact(unknown_reason="legacy_reason_origin_not_recorded")

    # The current engine state is not reproducible without a new evaluation.
    # A prior access log is an observation at its own time, never a current result.
    access = db.execute("""
        SELECT id, created_at, risk_score, decision_level
          FROM access_logs
         WHERE user_id=? AND resource_id=? AND created_at<=?
         ORDER BY created_at DESC, id DESC LIMIT 1
    """, (uid, rid, clock)).fetchone()
    if access:
        score = _fact(float(access["risk_score"]), "access_logs", access["id"], access["created_at"]) if access["risk_score"] is not None else _fact(unknown_reason="score_not_logged")
        final_level = _fact(access["decision_level"], "access_logs", access["id"], access["created_at"]) if access["decision_level"] is not None else _fact(unknown_reason="level_not_logged")
    else:
        score = final_level = _fact(unknown_reason="no_prior_access_evaluation")

    prior = db.execute("""
        SELECT id, status, resolved_at, approver_id, download_allowed
          FROM approvals
         WHERE requester_id=? AND resource_id=? AND id<>?
           AND status IN ('approved','rejected') AND resolved_at<=?
         ORDER BY resolved_at DESC, id DESC LIMIT 10
    """, (uid, rid, aid, requested_at)).fetchall()
    prior_decisions = [
        {"approval_id": p["id"], "status": p["status"],
         "resolved_at": _time(p["resolved_at"]),
         "source": {"table": "approvals", "id": p["id"]}}
        for p in prior
    ]
    return {
        "approval_id": aid,
        "observed_at": _time(clock),
        "request": {
            "status": _fact(row["status"], "approvals", aid, clock),
            "requested_at": _fact(_time(requested_at), "approvals", aid, source_time),
            "reason_origin": reason_origin,
            "want_download": download,
        },
        "resource": {
            "sensitivity_grade": _fact(row["sensitivity_grade"], "resources", rid, clock),
            "requires_approval": _fact(row["requires_approval"], "resources", rid, clock),
            "approval_basis": _fact({"resource_flag": bool(row["requires_approval"]),
                                     "grade_at_least_four": row["sensitivity_grade"] >= 4},
                                    "resources", rid, clock),
        },
        "work_relation": {
            "assigned_case": assigned_case,
            "same_department": (_fact(row["user_department"] == row["resource_department"], "users", uid, clock,
                                      related_sources=[{"table": "resources", "id": rid}])
                                if row["resource_department"] is not None else
                                _fact(unknown_reason="resource_department_missing")),
            "job_relevance": job_related,
        },
        "policy_facts": {
            "last_observed_risk_score": score,
            "last_observed_final_level": final_level,
            "score_base_level": _fact(unknown_reason="not_recorded_separately"),
            "immediate_block": _fact(unknown_reason="not_recorded_separately"),
            "policy_version": _fact(unknown_reason="not_recorded_with_access_log"),
            "current_evaluation": _fact(unknown_reason="read_only_no_re_evaluation"),
        },
        "past_decisions": {
            "records": prior_decisions,
            "source": "approvals:same_requester_and_resource_before_request",
            "comparison": "unavailable",
            "unknown_reason": "similarity_and_comparison_criteria_unsettled" if prior else "no_prior_decision_for_exact_pair",
        },
    }
