"""The review endpoint must not mutate access or approval state."""
def test_review_facts_http_read_only_and_authorized(http, login_as, db):
    admin_token, status, _ = login_as("admin_lee")
    assert status == 200
    requester_token, status, _ = login_as("detective_kim")
    assert status == 200
    requester = db.execute("SELECT id, trust_score, violation_count FROM users WHERE username=?",
                           ("detective_kim",)).fetchone()
    resource = db.execute("SELECT id FROM resources WHERE sensitivity_grade>=4 ORDER BY id LIMIT 1").fetchone()
    approval = db.execute("""
        INSERT INTO approvals (requester_id, resource_id, reason, status)
        VALUES (?,?,?,'pending') RETURNING id
    """, (requester["id"], resource["id"], "review facts test")).fetchone()
    db.commit()
    approval_id = approval["id"]

    before = db.execute("""
        SELECT (SELECT COUNT(*) FROM access_logs) AS access_count,
               (SELECT COUNT(*) FROM audit_logs) AS audit_count,
               (SELECT COUNT(*) FROM operation_logs) AS operation_count
    """).fetchone()
    code, data = http("GET", f"/api/admin/approvals/{approval_id}/review-facts",
                      token=admin_token)
    assert code == 200, data
    assert data["approval_id"] == approval_id
    assert data["request"]["want_download"]["unknown_reason"]
    assert data["policy_facts"]["current_evaluation"]["unknown_reason"]
    code, _ = http("GET", f"/api/admin/approvals/{approval_id}/review-facts",
                   token=requester_token)
    assert code == 403
    after = db.execute("""
        SELECT (SELECT COUNT(*) FROM access_logs) AS access_count,
               (SELECT COUNT(*) FROM audit_logs) AS audit_count,
               (SELECT COUNT(*) FROM operation_logs) AS operation_count
    """).fetchone()
    assert after == before
    assert db.execute("SELECT status FROM approvals WHERE id=?", (approval_id,)).fetchone()["status"] == "pending"
    current_user = db.execute("SELECT trust_score, violation_count FROM users WHERE id=?",
                              (requester["id"],)).fetchone()
    assert current_user["trust_score"] == requester["trust_score"]
    assert current_user["violation_count"] == requester["violation_count"]


def test_review_facts_self_processing_blocked(http, login_as, db):
    token, status, _ = login_as("admin_lee")
    assert status == 200
    user_id = db.execute("SELECT id FROM users WHERE username=?", ("admin_lee",)).fetchone()["id"]
    resource_id = db.execute("SELECT id FROM resources ORDER BY id LIMIT 1").fetchone()["id"]
    row = db.execute("""
        INSERT INTO approvals (requester_id, resource_id, reason, status)
        VALUES (?,?,?,'pending') RETURNING id
    """, (user_id, resource_id, "self review test")).fetchone()
    db.commit()
    code, data = http("GET", f"/api/admin/approvals/{row['id']}/review-facts", token=token)
    assert code == 403
    assert data["code"] == "self_approval_forbidden"
