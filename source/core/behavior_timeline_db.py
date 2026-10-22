"""D4-authorized PostgreSQL projection; no evaluation, AI or state transitions."""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
import hmac
import json

from config import SECRET_KEY
from core.behavior_timeline import (
    TimelineAccessDenied, TimelineError, TimelineGrant, TimelineLimits,
    TimelineSnapshot, _AUDIT_EVENTS, _time,
)
from core.session_guard import check_session


LIMITS = TimelineLimits(max_period=timedelta(days=31), max_page_size=200)
SOURCE_LIMIT = 5000
_ADMIN_ROLES = {"admin", "deputy_admin", "superadmin"}
_SOURCE_SQL = {
    "approvals": ("requester_id", "requested_at",
                  "id, requester_id, resource_id, status, requested_at, approver_id, resolved_at"),
    "login_approval_requests": ("user_id", "requested_at",
                               "id, user_id, status, requested_at, approver_id, resolved_at, used_session_id"),
    "case_assignment_requests": ("requester_id", "requested_at",
                                 "id, requester_id, resource_id, status, requested_at, otp_required_by, otp_required_at, otp_verified_at, final_approved_by"),
    "break_glass_activations": ("activator_id", "activated_at",
                                "id, activator_id, session_id, resource_id, scope, status, activated_at, reviewer_id, reviewed_at"),
    "sessions": ("user_id", "login_at", "id, user_id, login_at"),
    "access_logs": ("user_id", "created_at",
                    "id, user_id, session_id, resource_id, reason_code, action_type, decision_level, created_at"),
}
_LOGIN_EVENTS = {"ADMIN_APPROVAL_GRANTED", "ADMIN_APPROVAL_REJECTED", "ADMIN_GATED_SESSION_STARTED"}
_APPROVAL_EVENTS = {"ADMIN_APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_REJECTED"}
_ACTIONS = {"view", "download", "copy", "print", "login", "review"}


class TimelineSessionDenied(PermissionError):
    """Invalid, expired or reauthentication-pending session; no mutation needed."""


class TimelineSourceLimit(RuntimeError):
    """Bounded source scan cannot establish complete ownership and scope."""


def _positive_id(value):
    if isinstance(value, bool):
        return None
    if type(value) is int:
        return value if 0 < value < 2**63 else None
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 19:
        result = int(value)
        return result if 0 < result < 2**63 else None
    return None


def _ref(namespace, value):
    value = _positive_id(value)
    return f"{namespace}:{value}" if value else None


def _bounded(db, sql, params):
    rows = db.execute(sql + " LIMIT ?", (*params, SOURCE_LIMIT + 1)).fetchall()
    if len(rows) > SOURCE_LIMIT:
        raise TimelineSourceLimit("timeline source limit exceeded")
    return rows


def _authorize(db, reviewer_id, session_id, subject_id):
    reviewer = db.execute(
        "SELECT id, role, department, is_active, is_locked FROM users WHERE id=?", (reviewer_id,),
    ).fetchone()
    session = db.execute(
        "SELECT id, user_id, is_active, login_at, last_activity, absolute_expires_at, "
        "max_sensitivity_accessed, pending_reauth, pending_reauth_at FROM sessions WHERE id=?", (session_id,),
    ).fetchone()
    if (not session or session["user_id"] != reviewer_id or not check_session(session).ok
            or session["pending_reauth"]):
        raise TimelineSessionDenied("timeline session denied")
    subject = db.execute("SELECT id, role, department FROM users WHERE id=?", (subject_id,)).fetchone()
    if (not reviewer or not reviewer["is_active"] or reviewer["is_locked"]
            or reviewer["role"] not in _ADMIN_ROLES or not subject or subject_id == reviewer_id
            or subject["role"] not in _ADMIN_ROLES | {"user"}
            or not (reviewer["department"] or "").strip() or not (subject["department"] or "").strip()):
        raise TimelineAccessDenied("timeline scope denied")
    role = reviewer["role"]
    if (role == "admin" and subject["role"] != "user") or (
        role == "deputy_admin" and subject["role"] not in _ADMIN_ROLES
    ) or (role != "superadmin" and reviewer["department"] != subject["department"]):
        raise TimelineAccessDenied("timeline scope denied")
    return reviewer, subject


def _cursor_decode(cursor):
    try:
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise ValueError
        data = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
        if set(data) != {"payload", "signature"} or not isinstance(data["payload"], dict):
            raise ValueError
        payload = json.dumps(data["payload"], sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
        if not isinstance(data["signature"], str) or not hmac.compare_digest(expected, data["signature"]):
            raise ValueError
        if set(data["payload"]) != {"observed_at", "cursor", "scope"}:
            raise ValueError
        return data["payload"]
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise TimelineError("invalid cursor") from None


def _cursor_encode(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(SECRET_KEY.encode(), raw, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(json.dumps({"payload": payload, "signature": signature}).encode()).decode()


def _link(kind, details):
    if kind in _APPROVAL_EVENTS:
        return "approvals", _positive_id(details.get("approval_id"))
    if kind in _LOGIN_EVENTS:
        return "login_approval_requests", _positive_id(details.get("approval_request_id") or details.get("request_id"))
    if kind.startswith("CASE_ASSIGNMENT_"):
        return "case_assignment_requests", _positive_id(details.get("assignment_request_id"))
    if kind.startswith("BREAK_GLASS_") and kind != "BREAK_GLASS_ACTIVATION_REFUSED":
        return "break_glass_activations", _positive_id(details.get("activation_id"))
    return None, None


def _records(db, subject_id, observed_at, reviewer):
    # Static SQL identifiers and fixed JSON keys only. Never load source free text,
    # credentials, network context, sensitive_logs or resource content.
    rows = {}
    for table, (owner, clock, fields) in _SOURCE_SQL.items():
        rows[table] = _bounded(db, f"SELECT {fields} FROM {table} WHERE {owner}=? AND {clock}<=? ORDER BY id",
                               (subject_id, observed_at))
    linked = {table: {r["id"]: r for r in values} for table, values in rows.items()}
    audits = []
    for table in ("audit_logs", "operation_logs"):
        # A decision's actor can be its reviewer; attribute it to the verified
        # request owner, never merely to a details.target_user_id claim.
        audit_rows = _bounded(db, f"""
            SELECT a.id, a.user_id, a.event_type, a.request_id, a.created_at,
                   jsonb_build_object('approval_id', a.details->'approval_id',
                     'request_id', a.details->'request_id', 'approval_request_id', a.details->'approval_request_id',
                     'assignment_request_id', a.details->'assignment_request_id',
                     'activation_id', a.details->'activation_id', 'resource_id', a.details->'resource_id',
                     'session_id', a.details->'session_id', 'decision_level', a.details->'decision_level') AS links
              FROM {table} a
              LEFT JOIN approvals p ON a.event_type=ANY(?) AND a.details->>'approval_id'=p.id::text
              LEFT JOIN login_approval_requests l ON a.event_type=ANY(?) AND
                COALESCE(a.details->>'approval_request_id', a.details->>'request_id')=l.id::text
              LEFT JOIN case_assignment_requests c ON a.event_type=ANY(?)
                AND a.details->>'assignment_request_id'=c.id::text
              LEFT JOIN break_glass_activations b ON a.event_type=ANY(?)
                AND a.details->>'activation_id'=b.id::text
             WHERE a.event_type=ANY(?) AND a.created_at<=?
               AND (a.user_id=? OR p.requester_id=? OR l.user_id=? OR c.requester_id=? OR b.activator_id=?)
             ORDER BY a.id
        """, (sorted(_APPROVAL_EVENTS), sorted(_LOGIN_EVENTS),
              sorted(k for k in _AUDIT_EVENTS if k.startswith("CASE_ASSIGNMENT_")),
              sorted(k for k in _AUDIT_EVENTS if k.startswith("BREAK_GLASS_")),
              sorted(_AUDIT_EVENTS), observed_at,
              subject_id, subject_id, subject_id, subject_id, subject_id))
        audits.extend((table, row) for row in audit_rows)

    # Any known participation blocks all records of that request/activation,
    # including its current state, not just the decision audit itself.
    blocked = set()
    for table, values in rows.items():
        for row in values:
            participants = [row.get(k) for k in ("approver_id", "otp_required_by", "final_approved_by", "reviewer_id")]
            if reviewer["id"] in participants:
                blocked.add((table, row["id"]))
            if table in {"approvals", "login_approval_requests"} and row["status"] in {
                "approved", "rejected", "used", "expired"
            } and row.get("approver_id") is None:
                blocked.add((table, row["id"]))
            if table == "case_assignment_requests" and row["status"] in {"approved", "rejected"} and row.get("final_approved_by") is None:
                blocked.add((table, row["id"]))
            if table == "case_assignment_requests" and (
                row["status"] == "cancelled" or (
                    (row["otp_required_at"] is not None or row["otp_verified_at"] is not None
                     or row["status"] in {"otp_required", "otp_verified"}) and row["otp_required_by"] is None
                )
            ):
                blocked.add((table, row["id"]))
            if table == "break_glass_activations" and (
                row["reviewed_at"] is not None or row["status"].startswith("reviewed_")
            ) and row.get("reviewer_id") is None:
                blocked.add((table, row["id"]))
    for _, row in audits:
        key = _link(row["event_type"], row["links"])
        if (row["user_id"] is None or row["user_id"] == reviewer["id"]) and key[0]:
            blocked.add(key)
    known_revocations = {_positive_id(row["links"].get("activation_id")) for _, row in audits
                         if row["event_type"] == "BREAK_GLASS_REVOKED" and row["user_id"] is not None}
    for row in rows["break_glass_activations"]:
        if row["status"] == "revoked" and row["id"] not in known_revocations:
            blocked.add(("break_glass_activations", row["id"]))

    resources = {}
    sessions = linked["sessions"]

    def allowed_resource(resource_id):
        if resource_id is None:
            return True
        if resource_id not in resources:
            resources[resource_id] = db.execute("SELECT id, department FROM resources WHERE id=?", (resource_id,)).fetchone()
        resource = resources[resource_id]
        return bool(resource and (resource["department"] or "").strip() and (
            reviewer["role"] == "superadmin" or resource["department"] == reviewer["department"]))

    records, permitted = [], set()

    def add(table, row, *, kind, clock, resource_id=None, session_id=None, request_ref=None,
            activation_id=None, action=None, outcome=None, allowed=True):
        record = dict(table=table, id=row["id"], event_type=kind, occurred_at=row[clock],
                      signal_quality="server_recorded", actor_ref=f"user:{subject_id}",
                      resource_ref=_ref("resource", resource_id), session_ref=_ref("session", session_id),
                      request_ref=request_ref, activation_ref=_ref("activation", activation_id),
                      action=action, outcome=outcome)
        records.append(record)
        if allowed and allowed_resource(resource_id) and (session_id is None or session_id in sessions):
            permitted.add(f"{table}:{row['id']}")

    for table, values in rows.items():
        for row in values:
            if table == "access_logs":
                key = row["reason_code"]
                request = f"access-evaluation:{key}" if isinstance(key, str) and 0 < len(key) <= 128 else None
                level, action = row["decision_level"], row["action_type"]
                outcome = "allowed" if level == 1 or (level == 2 and action == "view") else (
                    "denied" if level == 5 or (level == 2 and action in {"download", "copy", "print"}) else "unknown")
                add(table, row, kind="ACCESS_DECISION", clock="created_at", resource_id=row["resource_id"],
                    session_id=row["session_id"], request_ref=request,
                    action=row["action_type"] if row["action_type"] in _ACTIONS else None,
                    outcome=outcome)
                continue
            namespace = {"approvals": "resource-approval", "login_approval_requests": "login-approval",
                         "case_assignment_requests": "assignment"}.get(table)
            session_id = row["id"] if table == "sessions" else row.get("session_id") or row.get("used_session_id")
            status = row.get("status")
            outcome = status if status in {"approved", "rejected", "pending"} else "unknown"
            add(table, row, kind="CURRENT_STATE", clock=_SOURCE_SQL[table][1],
                resource_id=row.get("resource_id"), session_id=session_id,
                request_ref=_ref(namespace, row["id"]) if namespace else None,
                activation_id=row["id"] if table == "break_glass_activations" else None,
                outcome=outcome,
                allowed=(table, row["id"]) not in blocked)

    for table, row in audits:
        kind, details = row["event_type"], row["links"]
        link_table, link_id = _link(kind, details)
        owner_row = linked.get(link_table, {}).get(link_id) if link_table else None
        allowed = (not link_table or owner_row is not None) and (link_table, link_id) not in blocked
        if link_table and not owner_row:
            # A row about a different owner must not appear on this subject's timeline.
            continue
        if row["user_id"] != subject_id and not owner_row:
            continue
        if row["user_id"] is None or row["user_id"] == reviewer["id"]:
            allowed = False
        resource_id = _positive_id(details.get("resource_id"))
        if owner_row:
            linked_resource = owner_row.get("resource_id")
            if link_table == "login_approval_requests" and resource_id is not None:
                allowed = False
            if resource_id is not None and linked_resource is not None and resource_id != linked_resource:
                allowed = False
            resource_id = resource_id or linked_resource
        if kind in {"ACCESS_DECISION", "ACCESS_SCORE_CHANGED", "UNASSIGNED_CASE_CLICK", "DOWNLOAD_ATTEMPT"} and resource_id is None:
            allowed = False
        namespace = {"approvals": "resource-approval", "login_approval_requests": "login-approval",
                     "case_assignment_requests": "assignment"}.get(link_table)
        request = _ref(namespace, link_id) if namespace else None
        if kind in {"ACCESS_DECISION", "BREAK_GLASS_USED"}:
            key = row["request_id"]
            request = f"access-evaluation:{key}" if isinstance(key, str) and 0 < len(key) <= 128 else None
        session_id = _positive_id(details.get("session_id"))
        if owner_row:
            linked_session = owner_row.get("session_id") or owner_row.get("used_session_id")
            if session_id and linked_session and session_id != linked_session:
                allowed = False
            session_id = session_id or linked_session
        level = details.get("decision_level")
        outcome = "allowed" if kind == "ACCESS_DECISION" and level == 1 else (
            "denied" if kind == "ACCESS_DECISION" and level == 5 else "unknown")
        add(table, row, kind=kind, clock="created_at", resource_id=resource_id, session_id=session_id,
            request_ref=request, activation_id=link_id if link_table == "break_glass_activations" else None,
            outcome=outcome, allowed=allowed)
    return records, permitted


def load_timeline(db, *, reviewer_id, session_id, subject_id, start, end, page_size=50,
                  cursor=None, evidence_ref=None):
    """Read an authorized snapshot with D4 checks repeated for every HTTP request.

    The caller supplies verified JWT identity, never a grant. One dedicated
    REPEATABLE READ, READ ONLY transaction covers auth, ownership and projection.
    Signed cursors pin observation time, query and reviewer scope; changed source
    state invalidates pagination rather than silently changing history.
    """
    start, end = _time(start), _time(end)
    if start >= end or end - start > LIMITS.max_period or type(page_size) is not int or not 1 <= page_size <= LIMITS.max_page_size:
        raise TimelineError("invalid query bounds")
    if any(_positive_id(v) is None for v in (reviewer_id, session_id, subject_id)):
        raise TimelineSessionDenied("timeline session denied")
    db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    now = db.execute("SELECT CURRENT_TIMESTAMP AS observed_at").fetchone()["observed_at"]
    reviewer, subject = _authorize(db, reviewer_id, session_id, subject_id)
    scope = [reviewer_id, session_id, reviewer["role"], reviewer["department"],
             subject_id, subject["role"], subject["department"], start.isoformat(), end.isoformat(), page_size]
    decoded = _cursor_decode(cursor) if cursor is not None else None
    if decoded and decoded["scope"] != scope:
        raise TimelineError("cursor scope changed")
    observed = _time(decoded["observed_at"]) if decoded else now
    if observed > now:
        raise TimelineError("invalid snapshot time")
    records, permitted = _records(db, subject_id, observed, reviewer)
    timeline = TimelineSnapshot(records, observed_at=observed)
    grant = TimelineGrant(frozenset({f"user:{subject_id}"}), frozenset(permitted))
    arguments = dict(actor_ref=f"user:{subject_id}", start=start, end=end, grant=grant, limits=LIMITS)
    if evidence_ref is not None:
        result = timeline.evidence(evidence_ref, **arguments)
        result["contract_version"] = "behavior-timeline-v1"
        result["unknown_reasons"] = ["scope_filtered_not_full_history", "source_completeness_not_verified",
                                     "environment_signals_not_independently_verified"]
        return result
    result = timeline.query(**arguments, page_size=page_size, cursor=decoded["cursor"] if decoded else None)
    if result["next_cursor"]:
        result["next_cursor"] = _cursor_encode(dict(observed_at=observed.isoformat(), cursor=result["next_cursor"], scope=scope))
    return result
