"""담당 등록 요청은 요청자 OTP 인증 뒤에만 최종 승인된다."""

import json

from core.case_assignment_rules import assignment_compatibility
from security.mfa_service import generate_totp


def test_case_assignment_requires_requester_otp_before_approval(http, login_as, db):
    """직접 API 호출도 화면과 같은 상태 전이를 따라야 한다."""
    requester_token, code, data = login_as("detective_kim")
    assert code == 200, data
    admin_token, code, data = login_as("admin_lee")
    assert code == 200, data

    requester = db.execute(
        "SELECT id, department, job_scope, assigned_cases FROM users WHERE username=?",
        ("detective_kim",),
    ).fetchone()
    assigned_before = requester["assigned_cases"]
    if isinstance(assigned_before, str):
        assigned_before = json.loads(assigned_before)
    assigned_ids = {int(value) for value in assigned_before}
    resources = db.execute(
        "SELECT id, department, job_tags FROM resources ORDER BY id"
    ).fetchall()
    resource = next(
        row for row in resources
        if int(row["id"]) not in assigned_ids
        and assignment_compatibility(requester, row)[0]
    )
    resource_id = int(resource["id"])

    code, data = http(
        "POST", f"/api/resources/cases/{resource_id}/assignment-request",
        token=requester_token, body={"reason": "OTP 상태 전이 검증"},
    )
    assert code == 201, data
    request_id = data["assignment_request"]["id"]
    admin_path = f"/api/admin/case-assignment-requests/{request_id}"
    requester_path = f"/api/resources/case-assignment-requests/{request_id}"

    for status in ("pending_admin", "otp_required"):
        code, data = http("POST", f"{admin_path}/approve", token=admin_token)
        assert code == 400, data
        assert data["code"] == "invalid_status"
        row = db.execute(
            "SELECT status FROM case_assignment_requests WHERE id=?", (request_id,)
        ).fetchone()
        assert row["status"] == status
        current = db.execute(
            "SELECT assigned_cases FROM users WHERE id=?", (requester["id"],)
        ).fetchone()["assigned_cases"]
        if isinstance(current, str):
            current = json.loads(current)
        assert resource_id not in {int(value) for value in current}
        if status == "pending_admin":
            code, data = http("POST", f"{admin_path}/require-otp", token=admin_token)
            assert code == 200, data

    code, data = http("POST", f"{admin_path}/require-otp", token=admin_token)
    assert code == 400, data
    assert data["code"] == "invalid_status"

    code, data = http(
        "POST", f"{requester_path}/verify-otp", token=requester_token,
        body={"otp": "invalid"},
    )
    assert code == 401, data
    code, data = http("POST", f"{admin_path}/approve", token=admin_token)
    assert code == 400, data

    token_device = db.execute(
        "SELECT id, mfa_secret FROM user_devices "
        "WHERE user_id=? AND device_type='totp_token' AND is_active",
        (requester["id"],),
    ).fetchone()
    # 로그인 MFA와 같은 30초 구간에서 별도 인증을 검증할 수 있도록 테스트 DB만 초기화한다.
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL WHERE id=?", (token_device["id"],)
    )
    db.commit()
    code, data = http(
        "POST", f"{requester_path}/verify-otp", token=requester_token,
        body={"otp": generate_totp(token_device["mfa_secret"])},
    )
    assert code == 200, data
    assert data["assignment_request"]["status"] == "otp_verified"

    code, data = http("POST", f"{admin_path}/approve", token=requester_token)
    assert code == 403, data
    code, data = http("POST", f"{admin_path}/approve", token=admin_token)
    assert code == 200, data
    assert data["assignment_request"]["status"] == "approved"
    current = db.execute(
        "SELECT assigned_cases FROM users WHERE id=?", (requester["id"],)
    ).fetchone()["assigned_cases"]
    if isinstance(current, str):
        current = json.loads(current)
    assert resource_id in {int(value) for value in current}

    code, data = http("POST", f"{admin_path}/reject", token=admin_token, body={})
    assert code == 400, data
    assert data["code"] == "invalid_status"
