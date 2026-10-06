"""Read-only approval process measures from existing rows and audit IDs.

These are descriptive counts, not a causal AI effect estimate. No reviewer
activity, model text, or independent adjudication is available here.
"""
from __future__ import annotations

from datetime import datetime


SOURCES = {
    "resource": ("approvals", "requested_at", "resolved_at", ("approved", "rejected")),
    "login": ("login_approval_requests", "requested_at", "resolved_at", ("approved", "rejected", "used")),
    "assignment": ("case_assignment_requests", "requested_at", "final_approved_at", ("approved", "rejected")),
    "break_glass": ("break_glass_activations", "activated_at", "reviewed_at",
                    ("reviewed_justified", "reviewed_unjustified", "reviewed_partial")),
}
DECISIONS = {
    "resource": {"approved": "APPROVAL_GRANTED", "rejected": "APPROVAL_REJECTED"},
    "login": {"approved": "ADMIN_APPROVAL_GRANTED", "rejected": "ADMIN_APPROVAL_REJECTED",
              "used": "ADMIN_APPROVAL_GRANTED"},
    "assignment": {"approved": "CASE_ASSIGNMENT_APPROVED", "rejected": "CASE_ASSIGNMENT_REJECTED"},
    "break_glass": {"reviewed_justified": "BREAK_GLASS_REVIEWED_JUSTIFIED",
                    "reviewed_unjustified": "BREAK_GLASS_REVIEWED_UNJUSTIFIED",
                    "reviewed_partial": "BREAK_GLASS_REVIEWED_PARTIAL"},
}
KEYS = {"resource": "approval_id", "login": "request_id",
        "assignment": "assignment_request_id", "break_glass": "activation_id"}


def _audit(db, event, key, target_id):
    # Fetch two to make duplicate evidence ambiguous rather than silently picking one.
    return db.execute(
        "SELECT id, created_at, user_id, details->>'resource_id' AS resource_id "
        "FROM audit_logs WHERE event_type=? "
        "AND details->>?=? ORDER BY id LIMIT 2", (event, key, str(target_id)),
    ).fetchall()


def _ai_events(db, kind, target_id):
    if kind == "resource":
        return db.execute(
            "SELECT id, created_at, user_id, details->>'status' AS status "
            "FROM audit_logs WHERE event_type='APPROVAL_AI_REVIEW' "
            "AND details->>'approval_id'=? ORDER BY id", (str(target_id),),
        ).fetchall()
    return db.execute(
        "SELECT id, created_at, user_id, details->>'status' AS status "
        "FROM audit_logs WHERE event_type='OTHER_APPROVAL_AI_REVIEW' "
        "AND details->>'review_type'=? AND details->>'target_id'=? ORDER BY id",
        (kind, str(target_id)),
    ).fetchall()


def measure(db, start: datetime, end: datetime) -> dict:
    """Measure fully processed requests created in [start, end), without writes.

    A successful AI call by the actual reviewer before processing defines the
    descriptive AI group. Unknown evidence excludes a row from either group.
    """
    db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    result = {
        "period": {"start": start.isoformat(), "end_exclusive": end.isoformat()},
        "metric_definitions": {
            "mean_wait_seconds": "total_wait_seconds / denominator; creation to final processing",
            "audit_omission_candidates": "missing decision audit or mismatched required case ID",
            "audit_omission_denominator": "all completed requests created and processed in period",
        },
        "limitations": ["AI call success does not prove advice was viewed or used",
                        "workload mix and reviewer activity are not measured",
                        "missing or ambiguous evidence is excluded from wait groups",
                        "no independent review of inappropriate approval or AI errors"],
        "unknown_metrics": ["active_review_seconds", "rework_count",
                            "inappropriate_approval_rate", "ai_false_positive_rate",
                            "ai_false_negative_rate", "reviewer_correction_rate"],
        "types": {},
    }
    for kind, (table, begin_col, finish_col, statuses) in SOURCES.items():
        rows = db.execute(
            f"SELECT id, status, {begin_col} AS began, {finish_col} AS finished, "
            f"{'resource_id,' if kind in ('resource', 'assignment') else ''} "
            f"{'reviewer_id' if kind == 'break_glass' else 'final_approved_by' if kind == 'assignment' else 'approver_id'} AS reviewer_id "
            f"FROM {table} WHERE {begin_col}>=? AND {begin_col}<? ORDER BY id",
            (start, end),
        ).fetchall()
        groups = {name: {"denominator": 0, "total_wait_seconds": 0, "evidence": []}
                  for name in ("ai_call_succeeded", "no_ai_call")}
        unknown = []
        incomplete = 0
        for row in rows:
            if row["status"] not in statuses or row["finished"] is None or not start <= row["finished"] < end:
                incomplete += 1
                continue
            key = KEYS[kind]
            decisions = _audit(db, DECISIONS[kind][row["status"]], key, row["id"])
            valid = [a for a in decisions if a["user_id"] == row["reviewer_id"]
                     and a["created_at"] >= row["finished"]]
            case_id_missing = (kind in ("resource", "assignment") and len(decisions) == 1
                               and len(valid) == 1
                               and valid[0]["resource_id"] != str(row["resource_id"]))
            if len(decisions) > 1 or len(valid) != 1 or row["reviewer_id"] is None or case_id_missing:
                unknown.append({"request_id": row["id"], "source": table,
                                "reason": "decision_audit_missing" if not decisions else
                                          "required_case_id_missing" if case_id_missing else "decision_audit_ambiguous",
                                "audit_ids": [a["id"] for a in decisions]})
                continue
            ai = _ai_events(db, kind, row["id"])
            # An audit row after the decision cannot establish exposure.
            eligible = [a for a in ai if row["began"] <= a["created_at"] <= row["finished"]]
            own_success = any(a["status"] == "succeeded" and a["user_id"] == row["reviewer_id"]
                              for a in eligible)
            if eligible and not own_success:
                unknown.append({"request_id": row["id"], "source": table,
                                "reason": "ai_exposure_ambiguous",
                                "audit_ids": [a["id"] for a in eligible]})
                continue
            group_name = "ai_call_succeeded" if own_success else "no_ai_call"
            group = groups[group_name]
            group["denominator"] += 1
            group["total_wait_seconds"] += (row["finished"] - row["began"]).total_seconds()
            group["evidence"].append({"request_id": row["id"], "request_table": table,
                                      "decision_audit_id": valid[0]["id"],
                                      "ai_audit_ids": [a["id"] for a in eligible]})
        for group in groups.values():
            n = group["denominator"]
            group["mean_wait_seconds"] = group["total_wait_seconds"] / n if n else None
            group["active_review_seconds"] = None
            group["rework_count"] = None
            group["inappropriate_approval_rate"] = None
            group["ai_false_positive_rate"] = None
            group["ai_false_negative_rate"] = None
            group["reviewer_correction_rate"] = None
        omission_count = sum(item["reason"] in ("decision_audit_missing", "required_case_id_missing")
                             for item in unknown)
        processed_count = sum(g["denominator"] for g in groups.values()) + len(unknown)
        result["types"][kind] = {"groups": groups, "excluded_incomplete": incomplete,
                                 "unknown_evidence": unknown,
                                 "audit_omission_candidates": omission_count,
                                 "audit_omission_denominator": processed_count,
                                 "audit_omission_candidate_rate": omission_count / processed_count if processed_count else None}
    return result
