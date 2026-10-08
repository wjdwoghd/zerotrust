"""Score-driven L4 requests must reach manual approval and an actual view."""
from __future__ import annotations


def test_grade_three_score_l4_request_approval_and_expiry(http, login_as, db):
    requester, status, _ = login_as("detective_kim")
    assert status == 200
    reviewer, status, _ = login_as("admin_lee")
    assert status == 200
    rid = db.execute("SELECT id FROM resources WHERE case_number=?",
                     ("2026-CYB-0077",)).fetchone()["id"]

    code, before = http("GET", f"/api/resources/cases/{rid}/status",
                        token=requester, device="registered-001", location="본청")
    assert code == 200, before
    assert before["risk_score"] is not None
    current = before
    scores = [before["risk_score"]]
    for _ in range(8):
        if current["actions"]["request_approval"]:
            break
        code, click = http("POST", f"/api/resources/cases/{rid}/restricted-click",
                           token=requester, device="registered-001", location="본청", body={})
        assert code == 200, click
        code, current = http("GET", f"/api/resources/cases/{rid}/status",
                             token=requester, device="registered-001", location="본청")
        assert code == 200, current
        scores.append(current["risk_score"])
    assert any(later > earlier for earlier, later in zip(scores, scores[1:])), scores
    assert current["actions"]["request_approval"] is True, current

    code, requested = http("POST", f"/api/resources/cases/{rid}/request-approval",
                           token=requester, device="registered-001", location="본청", body={})
    assert code == 201, requested
    code, duplicate = http("POST", f"/api/resources/cases/{rid}/request-approval",
                           token=requester, device="registered-001", location="본청", body={})
    assert code == 200 and duplicate["approval_id"] == requested["approval_id"]

    code, approved = http("POST", f"/api/admin/approvals/{requested['approval_id']}/approve",
                          token=reviewer, body={"download_allowed": False})
    assert code == 200, approved
    code, detail = http("GET", f"/api/resources/cases/{rid}",
                        token=requester, device="registered-001", location="본청")
    assert code == 200, detail
    assert detail["actions"]["can_view"] is True
    assert detail["actions"]["can_download"] is False
    assert detail["resource"]["content"]

    db.execute("UPDATE approvals SET resolved_at=NOW() - INTERVAL '1 day' WHERE id=?",
               (requested["approval_id"],))
    db.commit()
    code, expired = http("GET", f"/api/resources/cases/{rid}/status",
                         token=requester, device="registered-001", location="본청")
    assert code == 200, expired
    assert expired["actions"]["can_view"] is False


def test_repeated_unassigned_score_and_polling_stability(http, login_as, db):
    token, status, _ = login_as("detective_kim")
    assert status == 200
    rid = db.execute("SELECT id FROM resources WHERE case_number=?",
                     ("2026-CYB-0077",)).fetchone()["id"]
    endpoint = f"/api/resources/cases/{rid}/status"
    options = {"token": token, "device": "registered-001", "location": "본청"}
    code, start = http("GET", endpoint, **options)
    assert code == 200, start
    for _ in range(3):
        code, same = http("GET", endpoint, **options)
        assert code == 200 and same["risk_score"] == start["risk_score"]
    scores = []
    for _ in range(4):
        code, _ = http("POST", f"/api/resources/cases/{rid}/restricted-click",
                       body={}, **options)
        assert code == 200
        code, response = http("GET", endpoint, **options)
        assert code == 200
        scores.append(response["risk_score"])
    assert scores == sorted(scores)
    assert scores[-1] > scores[0]


def test_existing_approval_does_not_override_score_l5(http, login_as, db):
    """A valid earlier grant cannot turn a newly L5 request into a view."""
    token, status, _ = login_as("detective_kim")
    assert status == 200
    requester = db.execute("SELECT id FROM users WHERE username=?",
                           ("detective_kim",)).fetchone()["id"]
    rid = db.execute("SELECT id FROM resources WHERE case_number=?",
                     ("2026-CYB-0077",)).fetchone()["id"]
    db.execute("INSERT INTO approvals (requester_id, resource_id, reason, status, "
               "resolved_at, download_allowed) VALUES (?, ?, 'prior grant', "
               "'approved', NOW(), TRUE)", (requester, rid))
    db.commit()
    options = {"token": token, "device": "registered-001", "location": "본청"}
    for _ in range(16):
        code, _ = http("POST", f"/api/resources/cases/{rid}/restricted-click",
                       body={}, **options)
        assert code == 200
    code, detail = http("GET", f"/api/resources/cases/{rid}", **options)
    assert code == 200, detail
    assert detail["status"] == "DENY"
    assert detail["actions"]["can_view"] is False
    assert set(detail["resource"]) == {"id", "title"}
