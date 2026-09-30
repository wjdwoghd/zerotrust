"""인증·승인 상태 전이마다 자료 API가 본문 권한을 다시 판단한다."""

import json

from config import PRE_APPROVAL_TTL_SEC, REAUTH_TTL_SEC
from security.mfa_service import generate_totp


def _assign(db, username, rid):
    row = db.execute("SELECT assigned_cases FROM users WHERE username=?", (username,)).fetchone()
    cases = row["assigned_cases"] or []
    if isinstance(cases, str):
        cases = json.loads(cases)
    db.execute("UPDATE users SET assigned_cases=? WHERE username=?",
               (json.dumps(list(cases) + [rid]), username))
    db.commit()


def _assert_closed(http, token, rid, device):
    headers = {"token": token, "device": device, "location": "본청"}
    for method, suffix, body in (
        ("GET", "", None), ("GET", "/status", None),
        ("POST", "/download", {}), ("GET", "/file", None),
    ):
        kwargs = dict(headers)
        if body is not None:
            kwargs["body"] = body
        code, response = http(method, f"/api/resources/cases/{rid}{suffix}", **kwargs)
        assert code == (403 if suffix == "/file" else 200), response
        assert response["decision"]["can_view"] is False
        assert response["resource"]["can_view"] is False
        assert "content" not in response["resource"]
        assert "description" not in response["resource"]
        assert "scoring" not in response
        assert "risk_score" not in response["decision"]


def test_l3_otp_and_expiry_recheck_body(http, login_as, db, monkeypatch):
    import core.access_evaluator as evaluator

    token, code, data = login_as("detective_kim")
    assert code == 200, data
    rid = db.execute("SELECT id FROM resources WHERE case_number='2026-ADM-0099'").fetchone()["id"]
    _assign(db, "detective_kim", rid)

    original = evaluator.determine_access_level

    def force_l3(*args, **kwargs):
        decision = original(*args, **kwargs)
        decision.update(level=3, label="추가 인증 후 허용", label_en="REAUTH_REQUIRED")
        return decision

    monkeypatch.setattr(evaluator, "determine_access_level", force_l3)
    _assert_closed(http, token, rid, "registered-001")

    otp_row = db.execute(
        "SELECT mfa_secret FROM user_devices WHERE device_id='token-001'"
    ).fetchone()
    # 로그인 MFA에서 쓴 시간 창을 테스트에서만 초기화한다.
    db.execute("UPDATE user_devices SET last_otp_step=NULL WHERE device_id='token-001'")
    db.commit()
    code, response = http(
        "POST", "/api/auth/reauth", token=token,
        body={"otp_code": generate_totp(otp_row["mfa_secret"]),
              "device_id": "registered-001"},
    )
    assert code == 200, response
    code, detail = http("GET", f"/api/resources/cases/{rid}",
                        token=token, device="registered-001", location="본청")
    assert code == 200 and detail["decision"]["can_view"] is True, detail
    assert detail["resource"]["content"]

    db.execute(
        "UPDATE sessions SET reauth_at=CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
        "WHERE user_id=(SELECT id FROM users WHERE username='detective_kim')",
        (REAUTH_TTL_SEC + 60,),
    )
    db.commit()
    _assert_closed(http, token, rid, "registered-001")


def test_l4_approval_scope_expiry_and_cancel(http, login_as, db):
    token, code, data = login_as("detective_kim")
    assert code == 200, data
    rid = db.execute("SELECT id FROM resources WHERE case_number='2026-ADM-0200'").fetchone()["id"]
    _assign(db, "detective_kim", rid)

    code, listing = http("GET", "/api/resources/cases", token=token)
    assert code == 200, listing
    card = next(item for item in listing["cases"] if item["id"] == rid)
    assert "description" not in card and "content" not in card
    _assert_closed(http, token, rid, "registered-001")

    code, requested = http("POST", f"/api/resources/cases/{rid}/request-approval",
                           token=token, body={"reason": "자료 확인"})
    assert code == 201, requested
    admin_token, code, data = login_as("admin_lee")
    assert code == 200, data
    approval_id = requested["approval_id"]
    code, approved = http("POST", f"/api/admin/approvals/{approval_id}/approve",
                          token=admin_token, body={"download_allowed": False})
    assert code == 200, approved

    code, detail = http("GET", f"/api/resources/cases/{rid}",
                        token=token, device="registered-001", location="본청")
    assert code == 200 and detail["decision"]["can_view"] is True, detail
    assert detail["decision"]["can_download"] is False
    assert detail["resource"]["content"]
    code, denied = http("GET", f"/api/resources/cases/{rid}/file",
                        token=token, device="registered-001", location="본청")
    assert code == 403 and "content" not in denied["resource"]

    db.execute("UPDATE approvals SET resolved_at=CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
               "WHERE id=?", (PRE_APPROVAL_TTL_SEC + 60, approval_id))
    db.commit()
    _assert_closed(http, token, rid, "registered-001")

    db.execute("UPDATE approvals SET resolved_at=CURRENT_TIMESTAMP, status='cancelled' "
               "WHERE id=?", (approval_id,))
    db.commit()
    _assert_closed(http, token, rid, "registered-001")
