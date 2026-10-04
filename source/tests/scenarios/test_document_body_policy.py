"""L3 재인증·L4 승인 전후의 실제 HTTP 문서 응답 회귀 시나리오."""
from __future__ import annotations

import pytest

from config import PRE_APPROVAL_TTL_SEC, REAUTH_TTL_SEC
from security.mfa_service import generate_totp


def _resource(db, *, number: str, grade: int, data_type: str,
              requires_approval: bool) -> int:
    """접근 점수가 예측 가능한 격리 DB 전용 문서를 만든다."""
    row = db.execute(
        "INSERT INTO resources "
        "(case_number, title, description, content, sensitivity_grade, "
        " data_type, department, requires_approval) "
        "VALUES (?, '테스트 문서', '비밀 설명', '비밀 본문', ?, ?, "
        "        '격리테스트부서', ?) RETURNING id",
        (number, grade, data_type, requires_approval),
    ).fetchone()
    db.commit()
    return int(row["id"])


def _assert_no_body(payload: dict) -> None:
    resource = payload.get("resource") or {}
    assert "content" not in resource
    assert "description" not in resource
    assert "비밀 본문" not in str(payload)
    assert "비밀 설명" not in str(payload)


def _call(http, method: str, path: str, token: str, **kwargs):
    return http(
        method, path, token=token, device="registered-001",
        location="본청", sim_hour=14, **kwargs,
    )


def test_l3_reauth_opens_body_only_after_valid_otp(http, login_as, db):
    """L3의 목록·상세·상태·다운로드 평가에는 본문이 없고 OTP 후 열린다."""
    token, code, data = login_as("detective_kim")
    assert code == 200, data
    rid = _resource(db, number="TEST-L3-0001", grade=3,
                    data_type="evidence", requires_approval=False)
    path = f"/api/resources/cases/{rid}"

    code, listing = _call(http, "GET", "/api/resources/cases", token)
    assert code == 200, listing
    assert all("description" not in item and "content" not in item
               for item in listing["cases"])

    for suffix in ("/status", ""):
        code, payload = _call(http, "GET", path + suffix, token)
        assert code == 200, payload
        assert payload["decision"]["level"] == 3
        assert payload["resource"]["can_view"] is False
        _assert_no_body(payload)

    code, denied_file = _call(http, "GET", path + "/file", token)
    assert code == 403, denied_file
    _assert_no_body(denied_file)
    code, download_result = _call(http, "POST", path + "/download", token)
    assert code == 200, download_result
    assert download_result["resource"]["can_download"] is False
    _assert_no_body(download_result)

    token_device = db.execute(
        "SELECT mfa_secret FROM user_devices "
        "WHERE device_id='token-001' AND "
        "user_id=(SELECT id FROM users WHERE username='detective_kim')",
    ).fetchone()
    assert token_device and token_device["mfa_secret"]
    # 로그인 MFA에서 소비한 현재 TOTP step을 테스트 세션에서만 해제한다.
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL "
        "WHERE device_id='token-001' AND "
        "user_id=(SELECT id FROM users WHERE username='detective_kim')",
    )
    db.commit()
    code, reauth = _call(
        http, "POST", "/api/auth/reauth", token,
        body={"otp_code": generate_totp(token_device["mfa_secret"])},
    )
    assert code == 200, reauth

    code, opened = _call(http, "GET", path, token)
    assert code == 200, opened
    assert opened["decision"]["level"] == 1
    assert opened["resource"]["can_view"] is True
    assert opened["resource"]["description"] == "비밀 설명"
    assert opened["resource"]["content"] == "비밀 본문"
    code, file_response = _call(http, "GET", path + "/file", token)
    assert code == 200, file_response
    assert "비밀 본문" in file_response["_raw"]

    # 시도 횟수 가산을 분리하고 재인증 유효기간이 끝난 상태를 확인한다.
    db.execute(
        "UPDATE access_logs SET created_at=CURRENT_TIMESTAMP - INTERVAL '301 seconds' "
        "WHERE user_id=(SELECT id FROM users WHERE username='detective_kim')",
    )
    db.execute(
        "UPDATE sessions SET reauth_at=CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
        "WHERE user_id=(SELECT id FROM users WHERE username='detective_kim') "
        "AND is_active=TRUE",
        (REAUTH_TTL_SEC + 1,),
    )
    db.commit()
    code, expired = _call(http, "GET", path, token)
    assert code == 200, expired
    assert expired["decision"]["level"] == 3
    assert expired["resource"]["can_view"] is False
    _assert_no_body(expired)


@pytest.mark.parametrize("download_allowed,expected_level", [(False, 2), (True, 1)])
def test_l4_approval_controls_body_and_actions(
        http, login_as, db, download_allowed, expected_level):
    """L4 승인 전 본문이 없고, 승인 범위에 따라 열람·반출이 열린다."""
    token, code, data = login_as("detective_kim")
    assert code == 200, data
    rid = _resource(db, number="TEST-L4-0001", grade=2,
                    data_type="summary", requires_approval=True)
    path = f"/api/resources/cases/{rid}"

    for suffix in ("/status", ""):
        code, payload = _call(http, "GET", path + suffix, token)
        assert code == 200, payload
        assert payload["decision"]["level"] == 4
        assert payload["resource"]["can_view"] is False
        _assert_no_body(payload)

    code, denied_file = _call(http, "GET", path + "/file", token)
    assert code == 403, denied_file
    _assert_no_body(denied_file)
    code, denied_copy = _call(http, "POST", path + "/copy", token)
    assert code == 403, denied_copy
    assert "content" not in denied_copy
    assert "비밀 본문" not in str(denied_copy)
    code, download_result = _call(http, "POST", path + "/download", token)
    assert code == 200, download_result
    assert download_result["resource"]["can_download"] is False
    _assert_no_body(download_result)

    code, request = _call(
        http, "POST", path + "/request-approval", token,
        body={"reason": "격리 DB 정책 회귀", "want_download": download_allowed},
    )
    assert code == 201, request
    admin_token, code, data = login_as("admin_lee")
    assert code == 200, data
    code, approval = http(
        "POST", f"/api/admin/approvals/{request['approval_id']}/approve",
        token=admin_token, body={"download_allowed": download_allowed},
    )
    assert code == 200, approval

    code, opened = _call(http, "GET", path, token)
    assert code == 200, opened
    assert opened["decision"]["level"] == expected_level
    assert opened["resource"]["can_view"] is True
    assert opened["resource"]["description"] == "비밀 설명"
    assert opened["resource"]["content"] == "비밀 본문"
    code, status = _call(http, "GET", path + "/status", token)
    assert code == 200, status
    assert status["decision"]["level"] == expected_level
    _assert_no_body(status)

    code, file_response = _call(http, "GET", path + "/file", token)
    if download_allowed:
        assert code == 200, file_response
        assert "비밀 본문" in file_response["_raw"]
    else:
        assert code == 403, file_response
        _assert_no_body(file_response)
        code, denied_copy = _call(http, "POST", path + "/copy", token)
        assert code == 403, denied_copy
        assert "content" not in denied_copy

    db.execute(
        "UPDATE approvals "
        "SET resolved_at=CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
        "WHERE id=?",
        (PRE_APPROVAL_TTL_SEC + 1, request["approval_id"]),
    )
    db.commit()
    code, expired = _call(http, "GET", path, token)
    assert code == 200, expired
    assert expired["decision"]["level"] == 4
    assert expired["resource"]["can_view"] is False
    _assert_no_body(expired)
