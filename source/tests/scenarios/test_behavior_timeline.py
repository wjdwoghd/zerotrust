"""S1 PostgreSQL/HTTP checks: D4 scope, real source links and read invariance."""
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import urlencode
from uuid import uuid4

import pytest


@pytest.fixture
def timeline_data(db):
    from security.jwt_handler import create_token

    users, tokens, sessions = {}, {}, {}
    for name, role, department in (
        ("user", "user", "S1-A"), ("admin", "admin", "S1-A"),
        ("deputy", "deputy_admin", "S1-A"), ("super", "superadmin", "S1-A"),
        ("other", "user", "S1-B"), ("peer", "deputy_admin", "S1-A"),
    ):
        user_id = db.execute(
            "INSERT INTO users (username,password_hash,name,department,rank,role) VALUES (?,?,?,?,?,?) RETURNING id",
            (f"s1_{name}", "test-unused-hash", f"synthetic {name}", department, "test", role),
        ).fetchone()["id"]
        session_id = db.execute(
            "INSERT INTO sessions (user_id,token,absolute_expires_at) VALUES (?,?,CURRENT_TIMESTAMP+INTERVAL '1 hour') RETURNING id",
            (user_id, uuid4().hex),
        ).fetchone()["id"]
        users[name], sessions[name] = user_id, session_id
        tokens[name] = create_token(user_id, f"s1_{name}", role, mfa_verified=True, session_id=session_id)
    resources = []
    for dept in ("S1-A", "S1-B", None):
        resources.append(db.execute(
            "INSERT INTO resources(case_number,title,sensitivity_grade,department,content) VALUES (?,?,1,?,?) RETURNING id",
            ("synthetic-private-case", "synthetic-private-title", dept, "private-content-marker"),
        ).fetchone()["id"])
    db.commit()
    now = datetime.now(timezone.utc)
    return dict(users=users, tokens=tokens, sessions=sessions, resources=resources,
                start=(now-timedelta(days=1)).isoformat(), end=(now+timedelta(days=1)).isoformat())


def _get(http, data, reviewer="admin", subject="user", evidence=None, **query):
    url = f"/api/admin/behavior-timeline/{data['users'][subject]}"
    if evidence is not None:
        url += f"/evidence/{evidence}"
    query = dict(start=data["start"], end=data["end"], **query)
    return http("GET", url + "?" + urlencode(query), token=data["tokens"][reviewer])


def _access(db, data, resource=0, subject="user", key=None, session_subject=None):
    user_id = data["users"][subject]
    resource_id = data["resources"][resource]
    key = key or uuid4().hex[:8]
    session_id = data["sessions"][session_subject or subject]
    access_id = db.execute(
        "INSERT INTO access_logs(user_id,resource_id,session_id,reason_code,action_type,decision_level,created_at) "
        "VALUES (?,?,?,?,'download',2,CURRENT_TIMESTAMP-INTERVAL '5 minutes') RETURNING id",
        (user_id, resource_id, session_id, key),
    ).fetchone()["id"]
    audit_id = db.execute(
        "INSERT INTO audit_logs(user_id,event_type,request_id,details,created_at) "
        "VALUES (?,'ACCESS_DECISION',?,?,CURRENT_TIMESTAMP-INTERVAL '5 minutes') RETURNING id",
        (user_id, key, json.dumps(dict(resource_id=resource_id, decision_level=2,
                                      reason="private-reason-marker", ip="private-ip-marker"))),
    ).fetchone()["id"]
    db.commit()
    return f"access_logs:{access_id}", f"audit_logs:{audit_id}"


def _snapshot(db):
    result = {}
    for table in ("users", "resources", "sessions", "access_logs", "audit_logs", "operation_logs",
                  "sensitive_logs", "approvals", "login_approval_requests", "case_assignment_requests",
                  "break_glass_activations", "policy_thresholds"):
        # Hash inside PG; test output must never contain raw secrets or log text.
        result[table] = db.execute(
            f"SELECT md5(COALESCE(string_agg(row_to_json(t)::text, ',' ORDER BY row_to_json(t)::text),'')) AS digest FROM {table} t"
        ).fetchone()["digest"]
    return result


@pytest.mark.parametrize("reviewer,subject,expected", [
    ("admin", "user", 200), ("admin", "admin", 403), ("admin", "deputy", 403),
    ("admin", "super", 403), ("deputy", "user", 403), ("deputy", "admin", 200),
    ("deputy", "super", 200), ("deputy", "peer", 200), ("deputy", "deputy", 403),
    ("super", "user", 200), ("super", "admin", 200), ("super", "super", 403),
    ("user", "other", 403), ("admin", "other", 403), ("super", "other", 200),
])
def test_d4_role_and_subject_scope(http, db, timeline_data, reviewer, subject, expected):
    code, _ = _get(http, timeline_data, reviewer, subject)
    assert code == expected


def test_real_sources_pagination_evidence_and_read_invariance(http, db, timeline_data):
    data = timeline_data
    refs = _access(db, data)
    # Same timestamp, repeated evaluation key and missing counterpart must remain
    # separate evidence, not disappear by time proximity or lossy de-duplication.
    duplicate = _access(db, data, key="duplicate-key")
    _access(db, data, key="duplicate-key")
    before = _snapshot(db)
    code, whole = _get(http, data)
    assert code == 200
    assert whole["contract_version"] == "behavior-timeline-v1"
    assert "synthetic_input_only" not in whole["unknown_reasons"]
    event = next(e for e in whole["events"] if refs[0] in e["evidence_refs"])
    assert set(event["evidence_refs"]) == set(refs)
    assert "download_completion_unrecorded" in event["unknown_reasons"]
    assert event["signal_quality"] == "server_recorded"
    assert event["outcome"] == "denied"  # L2 viewing does not authorize downloads.
    ambiguous = next(e for e in whole["events"] if duplicate[0] in e["evidence_refs"])
    assert "ambiguous_evaluation_key" in ambiguous["unknown_reasons"]
    collected, cursor = [], None
    while True:
        code, page = _get(http, data, page_size=1, **({"cursor": cursor} if cursor else {}))
        assert code == 200
        collected.extend(e["event_key"] for e in page["events"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert collected == [e["event_key"] for e in whole["events"]]
    for ref in refs:
        code, evidence = _get(http, data, evidence=ref)
        assert code == 200
        assert evidence["event"]["event_key"] == event["event_key"]
        assert evidence["source"]["evidence_ref"] == ref
    raw = json.dumps(whole)
    for secret in ("private-content-marker", "private-reason-marker", "private-ip-marker",
                   "synthetic-private-case", "synthetic-private-title", "password_hash", "mfa_secret"):
        assert secret not in raw
    assert _snapshot(db) == before


def test_resource_scope_missing_department_and_foreign_session(http, db, timeline_data):
    data = timeline_data
    visible = _access(db, data)
    foreign = _access(db, data, resource=1)
    unknown = _access(db, data, resource=2)
    wrong_session = _access(db, data, session_subject="other")
    code, page = _get(http, data)
    assert code == 200
    all_refs = {ref for e in page["events"] for ref in e["evidence_refs"]}
    assert set(visible) <= all_refs
    assert not set(foreign + unknown + wrong_session) & all_refs
    denials = []
    for ref in foreign + unknown + wrong_session + ("audit_logs:999999999", "sensitive_logs:1"):
        code, body = _get(http, data, evidence=ref)
        denials.append((code, body["code"], body["error"]))
    assert len(set(denials)) == 1 and denials[0][0] == 403
    code, global_page = _get(http, data, reviewer="super")
    assert code == 200
    global_refs = {ref for e in global_page["events"] for ref in e["evidence_refs"]}
    assert set(foreign) <= global_refs
    assert not set(unknown + wrong_session) & global_refs


def test_own_participation_all_request_types_and_active_bg_read_only(http, db, timeline_data):
    data = timeline_data
    uid, rid = data["users"]["user"], data["resources"][0]
    actor = data["users"]["admin"]
    blocked = []
    for reviewer in ("admin", "super"):
        reviewer_id = data["users"][reviewer]
        ap = db.execute(
            "INSERT INTO approvals(requester_id,resource_id,status,approver_id,resolved_at) "
            "VALUES (?,?,'approved',?,CURRENT_TIMESTAMP) RETURNING id", (uid, rid, reviewer_id),
        ).fetchone()["id"]
        login = db.execute(
            "INSERT INTO login_approval_requests(user_id,justification,status,approver_id,resolved_at) "
            "VALUES (?,'private-justification','approved',?,CURRENT_TIMESTAMP) RETURNING id", (uid, reviewer_id),
        ).fetchone()["id"]
        assignment = db.execute(
            "INSERT INTO case_assignment_requests(requester_id,resource_id,otp_required_by) VALUES (?,?,?) RETURNING id",
            (uid, rid, reviewer_id),
        ).fetchone()["id"]
        bg = db.execute(
            "INSERT INTO break_glass_activations(activator_id,session_id,scope,resource_id,justification,"
            "expires_at,status,reviewer_id,reviewed_at,review_verdict) "
            "VALUES (?,?,'resource',?,'private-bg',CURRENT_TIMESTAMP,'reviewed_justified',?,CURRENT_TIMESTAMP,'justified') RETURNING id",
            (uid, data["sessions"]["user"], rid, reviewer_id),
        ).fetchone()["id"]
        blocked.append((reviewer, (f"approvals:{ap}", f"login_approval_requests:{login}",
                                   f"case_assignment_requests:{assignment}", f"break_glass_activations:{bg}")))
    active_bg = db.execute(
        "INSERT INTO break_glass_activations(activator_id,session_id,scope,resource_id,justification,expires_at) "
        "VALUES (?,?,'resource',?,'private-bg',CURRENT_TIMESTAMP-INTERVAL '1 minute') RETURNING id",
        (uid, data["sessions"]["user"], rid),
    ).fetchone()["id"]
    pending_ap = db.execute(
        "INSERT INTO approvals(requester_id,resource_id,status) VALUES (?,?,'pending') RETURNING id", (uid, rid),
    ).fetchone()["id"]
    own_audit = db.execute(
        "INSERT INTO audit_logs(user_id,event_type,details) VALUES (?,'APPROVAL_REJECTED',?) RETURNING id",
        (actor, json.dumps(dict(approval_id=pending_ap))),
    ).fetchone()["id"]
    # Server-written operation logs and audit logs both contribute to S1.
    operation = db.execute(
        "INSERT INTO operation_logs(user_id,event_type,details) VALUES (?,'LOGIN_SUCCESS',?) RETURNING id",
        (uid, json.dumps(dict(reason="private-operation-marker"))),
    ).fetchone()["id"]
    db.commit()
    before = _snapshot(db)
    for reviewer, refs in blocked:
        for ref in refs:
            assert _get(http, data, reviewer=reviewer, evidence=ref)[0] == 403
    assert _get(http, data, evidence=f"approvals:{pending_ap}")[0] == 403
    assert _get(http, data, evidence=f"audit_logs:{own_audit}")[0] == 403
    assert _get(http, data, evidence=f"break_glass_activations:{active_bg}")[0] == 200
    assert _get(http, data, evidence=f"operation_logs:{operation}")[0] == 200
    assert _snapshot(db) == before  # Even an expired active BG is not transitioned.


def test_current_db_authority_cursor_tamper_and_revocation(http, db, timeline_data):
    from security.jwt_handler import create_token
    data = timeline_data
    _access(db, data)
    # JWT role is neither sufficient nor required; current DB role is authoritative.
    data["tokens"]["admin"] = create_token(data["users"]["admin"], "s1_admin", "user",
        mfa_verified=True, session_id=data["sessions"]["admin"])
    code, page = _get(http, data, page_size=1)
    assert code == 200 and page["next_cursor"]
    cursor = page["next_cursor"]
    assert _get(http, data, page_size=1, cursor=cursor + "x")[0] == 400
    assert _get(http, data, page_size=2, cursor=cursor)[0] == 400
    assert _get(http, data, reviewer="super", page_size=1, cursor=cursor)[0] == 400
    db.execute("UPDATE resources SET department='S1-B' WHERE id=?", (data["resources"][0],))
    db.commit()
    assert _get(http, data, page_size=1, cursor=cursor)[0] == 400
    db.execute("UPDATE users SET role='user' WHERE id=?", (data["users"]["admin"],))
    db.commit()
    assert _get(http, data, page_size=1, cursor=cursor)[0] == 403


@pytest.mark.parametrize("change,expected", [
    ("UPDATE sessions SET pending_reauth=TRUE WHERE id=?", 401),
    ("UPDATE sessions SET last_activity=CURRENT_TIMESTAMP-INTERVAL '2 days' WHERE id=?", 401),
    ("UPDATE sessions SET user_id=(SELECT id FROM users WHERE username='s1_other') WHERE id=?", 401),
    ("UPDATE sessions SET is_active=FALSE WHERE id=?", 401),
    ("UPDATE users SET is_locked=TRUE WHERE id=?", 403),
    ("UPDATE users SET is_active=FALSE WHERE id=?", 403),
    ("UPDATE users SET department='' WHERE id=?", 403),
])
def test_invalid_session_account_or_scope_denied_without_mutation(http, db, timeline_data, change, expected):
    data = timeline_data
    target_id = data["sessions"]["admin"] if "sessions" in change else data["users"]["admin"]
    db.execute(change, (target_id,))
    db.commit()
    before = _snapshot(db)
    assert _get(http, data)[0] == expected
    assert _snapshot(db) == before


def test_query_validation_auth_and_fail_closed_source_limit(http, db, timeline_data, monkeypatch):
    data = timeline_data
    url = f"/api/admin/behavior-timeline/{data['users']['user']}"
    assert http("GET", url)[0] == 401
    assert http("GET", url + "?" + urlencode(dict(start="invalid", end=data["end"])), token=data["tokens"]["admin"])[0] == 400
    for query in (dict(page_size=0), dict(page_size=201), dict(grant="all"), dict(order="desc")):
        assert _get(http, data, **query)[0] == 400
    from core import behavior_timeline_db
    monkeypatch.setattr(behavior_timeline_db, "SOURCE_LIMIT", 0)
    code, body = _get(http, data)
    assert code == 503 and body["code"] == "timeline_source_limit"


def test_read_only_transaction_enforced_and_timestamp_boundaries(db, timeline_data):
    from core.behavior_timeline_db import load_timeline
    data = timeline_data
    ref, _ = _access(db, data)
    # _access committed, so SET TRANSACTION must precede any other statement.
    result = load_timeline(db, reviewer_id=data["users"]["admin"], session_id=data["sessions"]["admin"],
                           subject_id=data["users"]["user"], start=data["start"], end=data["end"])
    assert db.execute("SHOW transaction_read_only").fetchone()["transaction_read_only"] == "on"
    event = next(e for e in result["events"] if ref in e["evidence_refs"])
    moment = datetime.fromisoformat(event["occurred_at"])
    db.rollback()
    excluded = load_timeline(db, reviewer_id=data["users"]["admin"], session_id=data["sessions"]["admin"],
        subject_id=data["users"]["user"], start=(moment-timedelta(seconds=1)).isoformat(), end=moment.isoformat())
    assert not excluded["events"]
    db.rollback()
    included = load_timeline(db, reviewer_id=data["users"]["admin"], session_id=data["sessions"]["admin"],
        subject_id=data["users"]["user"], start=moment.astimezone(timezone(timedelta(hours=9))).isoformat(),
        end=(moment+timedelta(seconds=1)).isoformat())
    assert len(included["events"]) == 1


def test_verified_review_owner_all_flows_missing_links_and_hidden_relations(http, db, timeline_data):
    data = timeline_data
    uid, rid = data["users"]["user"], data["resources"][0]
    processor = data["users"]["deputy"]
    approval = db.execute(
        "INSERT INTO approvals(requester_id,resource_id,status,approver_id,resolved_at) "
        "VALUES (?,?,'approved',?,CURRENT_TIMESTAMP) RETURNING id", (uid, rid, processor),
    ).fetchone()["id"]
    login = db.execute(
        "INSERT INTO login_approval_requests(user_id,justification,status,approver_id) "
        "VALUES (?,'private-login','approved',?) RETURNING id", (uid, processor),
    ).fetchone()["id"]
    assignment = db.execute(
        "INSERT INTO case_assignment_requests(requester_id,resource_id,status,final_approved_by) "
        "VALUES (?,?,'approved',?) RETURNING id", (uid, rid, processor),
    ).fetchone()["id"]
    bg = db.execute(
        "INSERT INTO break_glass_activations(activator_id,session_id,scope,resource_id,justification,expires_at) "
        "VALUES (?,?,'resource',?,'private-bg',CURRENT_TIMESTAMP) RETURNING id",
        (uid, data["sessions"]["user"], rid),
    ).fetchone()["id"]
    refs = []
    for kind, details, actor in (
        ("APPROVAL_GRANTED", dict(approval_id=approval, resource_id=rid), processor),
        ("ADMIN_APPROVAL_GRANTED", dict(request_id=login), processor),
        ("CASE_ASSIGNMENT_APPROVED", dict(assignment_request_id=assignment), processor),
        ("BREAK_GLASS_ACTIVATED", dict(activation_id=bg, resource_id=rid), uid),
        ("LOGIN_BLOCKED_LOCATION_NOT_ALLOWED", {}, uid),
    ):
        row = db.execute("INSERT INTO audit_logs(user_id,event_type,details) VALUES (?,?,?) RETURNING id",
                         (actor, kind, json.dumps(details))).fetchone()
        refs.append(f"audit_logs:{row['id']}")
    forged = db.execute(
        "INSERT INTO audit_logs(user_id,event_type,details) VALUES (?,'APPROVAL_GRANTED',?) RETURNING id",
        (uid, json.dumps(dict(approval_id=99999999, target_user_id=uid))),
    ).fetchone()["id"]
    missing_processor = db.execute(
        "INSERT INTO approvals(requester_id,resource_id,status) VALUES (?,?,'approved') RETURNING id", (uid, rid),
    ).fetchone()["id"]
    hidden_key = "hidden-session-key"
    hidden_access, hidden_audit = _access(db, data, key=hidden_key, session_subject="other")
    bg_used = db.execute(
        "INSERT INTO audit_logs(user_id,event_type,request_id,details) VALUES (?,'BREAK_GLASS_USED',?,?) RETURNING id",
        (uid, hidden_key, json.dumps(dict(activation_id=bg, resource_id=rid))),
    ).fetchone()["id"]
    db.commit()
    before = _snapshot(db)
    for ref in refs:
        code, body = _get(http, data, evidence=ref)
        assert code == 200
        assert body["event"]["actor_ref"] == f"user:{uid}"  # Reviewer actor is not the subject.
    for ref in (f"audit_logs:{forged}", f"approvals:{missing_processor}", hidden_access, hidden_audit):
        assert _get(http, data, evidence=ref)[0] == 403
    code, body = _get(http, data, evidence=f"audit_logs:{bg_used}")
    assert code == 200
    assert body["event"]["relations"] == []
    assert "related_evidence_outside_scope" in body["event"]["unknown_reasons"]
    assert _snapshot(db) == before


@pytest.mark.parametrize("change", ["UPDATE users SET role='unknown-role' WHERE id=?",
                                    "UPDATE users SET department='  ' WHERE id=?"])
def test_unknown_subject_authority_not_even_superadmin(http, db, timeline_data, change):
    db.execute(change, (timeline_data["users"]["user"],))
    db.commit()
    assert _get(http, timeline_data, reviewer="super")[0] == 403


def test_missing_processor_for_otp_or_bg_revocation_is_denied(http, db, timeline_data):
    data = timeline_data
    uid, rid = data["users"]["user"], data["resources"][0]
    assignment = db.execute(
        "INSERT INTO case_assignment_requests(requester_id,resource_id,status,otp_required_at) "
        "VALUES (?,?,'otp_required',CURRENT_TIMESTAMP) RETURNING id", (uid, rid),
    ).fetchone()["id"]
    bg = db.execute(
        "INSERT INTO break_glass_activations(activator_id,scope,resource_id,justification,expires_at,status) "
        "VALUES (?,'resource',?,'private-bg',CURRENT_TIMESTAMP,'revoked') RETURNING id", (uid, rid),
    ).fetchone()["id"]
    db.commit()
    assert _get(http, data, evidence=f"case_assignment_requests:{assignment}")[0] == 403
    assert _get(http, data, evidence=f"break_glass_activations:{bg}")[0] == 403
