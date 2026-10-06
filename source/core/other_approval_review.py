"""Read-only, type-specific facts and strict nonbinding advice validation."""
from __future__ import annotations

from datetime import datetime, timezone

from core.approval_review_facts import ReviewFactsError
from integrations.openai_scenario_client import ModelOutputError


TYPES = {"login", "assignment", "break_glass"}
OPINIONS = {"check_further", "request_more_information", "no_issue_identified"}


def _time(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _fact(value, source, observed_at, reason=None):
    return {"value": value if reason is None else None, "source": source,
            "observed_at": _time(observed_at), "unknown_reason": reason}


def _event(db, event_type, key, target_id, owner_id):
    """Use only an event whose structured ID and owner match this target."""
    rows = db.execute(
        "SELECT id, created_at FROM audit_logs WHERE event_type=? AND user_id=? "
        "AND details->>?=? ORDER BY id LIMIT 2",
        (event_type, owner_id, key, str(target_id)),
    ).fetchall()
    return rows[0] if len(rows) == 1 else None


def load_review_facts(db, review_type, target_id, reviewer_id, reviewer_role):
    """Read a consistent snapshot without evaluating access or changing state."""
    if review_type not in TYPES:
        raise ReviewFactsError("review_type_invalid", 404)
    db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    observed = db.execute("SELECT CURRENT_TIMESTAMP AS observed_at").fetchone()["observed_at"]
    if review_type == "login":
        row = db.execute(
            "SELECT id, user_id, status, requested_at, expires_at FROM login_approval_requests WHERE id=?",
            (target_id,),
        ).fetchone()
        if not row:
            raise ReviewFactsError("request_not_found", 404)
        if row["status"] != "pending":
            raise ReviewFactsError("request_not_pending", 409)
        if row["user_id"] == reviewer_id:
            # Manual login approval has a one-admin bootstrap exception. AI advice
            # never uses that exception to avoid advisory self review.
            raise ReviewFactsError("self_review_forbidden", 403)
        source = {"table": "login_approval_requests", "id": target_id}
        fields = {"status": _fact(row["status"], source, observed),
                  "requested_at": _fact(_time(row["requested_at"]), source, row["requested_at"]),
                  "otp_state": _fact(None, None, observed, "login_gate_otp_not_recorded"),
                  "expiry": _fact(None, None, observed, "pending_request_has_no_expiry")}
        evidence = [source]
    elif review_type == "assignment":
        row = db.execute(
            "SELECT id, requester_id, resource_id, reviewer_role, status, requested_at, "
            "otp_required_at, otp_verified_at FROM case_assignment_requests WHERE id=?",
            (target_id,),
        ).fetchone()
        if not row:
            raise ReviewFactsError("request_not_found", 404)
        if row["status"] not in ("pending_admin", "otp_required", "otp_verified"):
            raise ReviewFactsError("request_not_pending", 409)
        if row["requester_id"] == reviewer_id:
            raise ReviewFactsError("self_review_forbidden", 403)
        if reviewer_role != "superadmin" and row["reviewer_role"] != reviewer_role:
            raise ReviewFactsError("reviewer_role_forbidden", 403)
        source = {"table": "case_assignment_requests", "id": target_id}
        fields = {"status": _fact(row["status"], source, observed),
                  "reviewer_role": _fact(row["reviewer_role"], source, observed),
                  "requested_at": _fact(_time(row["requested_at"]), source, row["requested_at"]),
                  "otp_state": _fact("verified" if row["otp_verified_at"] else
                                     "required" if row["otp_required_at"] else "not_required", source, observed)}
        event = _event(db, "CASE_ASSIGNMENT_REQUESTED", "assignment_request_id", target_id, row["requester_id"])
        evidence = [source]
        if event:
            evidence.append({"table": "audit_logs", "id": event["id"]})
        else:
            fields["request_audit"] = _fact(None, None, observed, "request_audit_missing_or_ambiguous")
        # Current compatibility is a separate fact; never infer it from the request.
        user = db.execute("SELECT department, job_scope FROM users WHERE id=?", (row["requester_id"],)).fetchone()
        resource = db.execute("SELECT department, job_tags FROM resources WHERE id=?", (row["resource_id"],)).fetchone()
        if user and resource and user["department"] and resource["department"]:
            from core.case_assignment_rules import assignment_compatibility
            compatible, _ = assignment_compatibility(user, resource)
            scope_source = {"table": "users", "id": row["requester_id"]}
            evidence.extend((scope_source, {"table": "resources", "id": row["resource_id"]}))
            fields["current_scope_compatible"] = _fact(compatible, scope_source, observed)
        else:
            fields["current_scope_compatible"] = _fact(None, None, observed, "current_scope_unavailable")
    else:
        row = db.execute(
            "SELECT id, activator_id, status, scope, min_grade, activated_at, expires_at, "
            "reviewed_at FROM break_glass_activations WHERE id=?", (target_id,),
        ).fetchone()
        if not row:
            raise ReviewFactsError("activation_not_found", 404)
        if row["activator_id"] == reviewer_id:
            raise ReviewFactsError("self_review_forbidden", 403)
        if row["status"] not in ("expired", "revoked", "released") or row["reviewed_at"] is not None:
            raise ReviewFactsError("activation_not_reviewable", 409)
        source = {"table": "break_glass_activations", "id": target_id}
        fields = {"status": _fact(row["status"], source, observed),
                  "scope": _fact(row["scope"], source, observed),
                  "min_grade": _fact(row["min_grade"], source, observed),
                  "activated_at": _fact(_time(row["activated_at"]), source, row["activated_at"]),
                  "expires_at": _fact(_time(row["expires_at"]), source, row["expires_at"])}
        evidence = [source]
        event = _event(db, "BREAK_GLASS_ACTIVATED", "activation_id", target_id, row["activator_id"])
        if event:
            evidence.append({"table": "audit_logs", "id": event["id"]})
        else:
            fields["activation_audit"] = _fact(None, None, observed, "activation_audit_missing_or_ambiguous")
        uses = db.execute(
            "SELECT id, created_at FROM audit_logs WHERE event_type='BREAK_GLASS_USED' "
            "AND user_id=? AND details->>'activation_id'=? ORDER BY id LIMIT 101",
            (row["activator_id"], str(target_id)),
        ).fetchall()
        if len(uses) > 100:
            fields["use_count"] = _fact(None, None, observed, "use_audit_limit_exceeded")
        else:
            fields["use_count"] = _fact(len(uses), None, observed)
            evidence.extend({"table": "audit_logs", "id": use["id"]} for use in uses[:8])
    return {"review_type": review_type, "target_id": target_id,
            "observed_at": _time(observed), "fields": fields, "evidence_ids": evidence}


def build_model_input(facts):
    """Project a strict scalar allowlist and call-local evidence aliases."""
    aliases = {f"E{i}": (item["table"], item["id"])
               for i, item in enumerate(facts["evidence_ids"], 1)}
    source_alias = {value: key for key, value in aliases.items()}
    fields = {}
    for name, fact in facts["fields"].items():
        if name not in {"status", "requested_at", "otp_state", "expiry", "reviewer_role",
                        "current_scope_compatible", "request_audit", "scope", "min_grade",
                        "activated_at", "expires_at", "activation_audit", "use_count"}:
            raise ValueError("unexpected fact")
        value = fact["value"]
        reason = fact["unknown_reason"]
        if value is not None and (type(value) not in (str, int, bool) or
                                  isinstance(value, str) and len(value) > 48):
            raise ValueError("unsafe fact")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 80):
            raise ValueError("unsafe unknown reason")
        source = fact["source"]
        alias = source_alias.get((source["table"], source["id"])) if source else None
        if source and alias is None:
            raise ValueError("unverified source")
        fields[name] = {"value": value, "observed_at": fact["observed_at"],
                        "unknown_reason": reason, "evidence_ref": alias}
    return {"review_type": facts["review_type"], "observed_at": facts["observed_at"],
            "fields": fields, "evidence_refs": list(aliases)}, aliases


def validate_review(raw, aliases):
    """Reject unknown fields, executable decisions, and unobserved evidence."""
    if not isinstance(raw, dict) or set(raw) != {"review_opinion", "items", "uncertainties", "evidence_refs"}:
        raise ModelOutputError("invalid review fields")
    if not isinstance(raw["review_opinion"], str) or raw["review_opinion"] not in OPINIONS:
        raise ModelOutputError("invalid review opinion")
    result = {"review_opinion": raw["review_opinion"]}
    for name in ("items", "uncertainties"):
        items = raw[name]
        if not isinstance(items, list) or len(items) > 8:
            raise ModelOutputError("invalid item count")
        cleaned = []
        for item in items:
            if not isinstance(item, dict) or set(item) != {"text", "evidence_refs", "no_evidence_reason"}:
                raise ModelOutputError("invalid item fields")
            message, reason = item["text"], item["no_evidence_reason"]
            if not isinstance(message, str) or not 1 <= len(message) <= 300 or any(
                    word in message.lower() for word in ("approved", "rejected", "approve(", "reject(",
                                                        "승인하세요", "반려하세요", "차단하세요")):
                raise ModelOutputError("invalid item text")
            if reason is not None and (not isinstance(reason, str) or not 1 <= len(reason) <= 160):
                raise ModelOutputError("invalid no-evidence reason")
            refs = _refs(item["evidence_refs"], aliases)
            if not refs and reason is None:
                raise ModelOutputError("missing evidence reason")
            cleaned.append({"text": message, "evidence_ids": _ids(refs, aliases),
                            "no_evidence_reason": reason})
        result[name] = cleaned
    result["evidence_ids"] = _ids(_refs(raw["evidence_refs"], aliases), aliases)
    return result


def _refs(refs, aliases):
    if not isinstance(refs, list) or len(refs) > 8 or any(
            not isinstance(ref, str) or ref not in aliases for ref in refs) or len(set(refs)) != len(refs):
        raise ModelOutputError("invalid evidence_ref")
    return refs


def _ids(refs, aliases):
    return [{"table": aliases[ref][0], "id": aliases[ref][1]} for ref in refs]


def review_response(facts, raw, aliases, model):
    """Return server observations and AI advice in separate branches."""
    review = validate_review(raw, aliases)
    return {"server_facts": facts, "ai_review": {"review_opinion": review["review_opinion"],
            "items": review["items"]}, "uncertainties": {"server": [
                {"field": key, "reason": value["unknown_reason"]}
                for key, value in facts["fields"].items() if value["unknown_reason"]],
                "ai": review["uncertainties"]}, "evidence_ids": review["evidence_ids"],
            "model_status": "completed", "model": model,
            "generated_at": datetime.now(timezone.utc).isoformat()}
