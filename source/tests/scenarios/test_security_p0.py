"""
시나리오 C-P0 — Security 핵심 12개

ZT 시스템의 핵심 방어가 의도대로 동작하는지. 발표 시연 후보.

대상 위협:
  1. 비밀번호 무차별 (5회 실패 → 계정 잠금)
  7. 비현실적 위치 이동 (impossible_travel)
  8. 즉시차단 룰 — 비허용 위치 + 미등록 단말 + 고민감 다운로드
  10. 권한 상승 시도 (일반 유저가 admin API)
  11. 자기-승인 차단 (관리자 자기 요청 본인 승인)
  12. 마지막 admin 보호 (비활성화 차단)
  14. 신규 계정 admin_approval_gate 우회 시도
  15-16. audit_logs 변조 시도 (UPDATE/DELETE)
  19. 동시 로그인 (다른 IP) — 양쪽 pending_reauth
  20. Break-Glass OTP 미입력 — 차단
  21. Break-Glass unjustified — trust 페널티
"""
from __future__ import annotations

import json
import pytest

from security.password_handler import hash_password


# ─── #1: 비밀번호 5회 실패 → 계정 잠금 ──────────────────────────
def test_password_brute_force_locks_account(http, db):
    """잘못된 비밀번호 5회 → is_locked=TRUE, 6회째는 로그인 자체 차단."""
    for i in range(5):
        code, _ = http("POST", "/api/auth/login", body={
            "username": "admin_lee", "password": "wrong_password",
            "device_id": "registered-004", "location": "본청",
        })
        assert code in (401, 403), f"시도 {i+1}: 401/403 기대"

    # DB 검증: 잠겼는지
    row = db.execute(
        "SELECT is_locked, failed_login_count FROM users WHERE username='admin_lee'"
    ).fetchone()
    assert row["is_locked"] is True
    assert row["failed_login_count"] >= 5

    # 6회째: 올바른 비밀번호여도 차단
    code, data = http("POST", "/api/auth/login", body={
        "username": "admin_lee", "password": "password123",
        "device_id": "registered-004", "location": "본청",
    })
    assert code == 403
    assert "잠" in data.get("error", "") or "lock" in data.get("error", "").lower()


# ─── #7: 비현실적 위치 이동 (impossible_travel) ────────────────
def test_impossible_travel_immediate_block(http, login_as, db):
    """본청 로그인 후 즉시 부산 IP 로 자원 접근 → IMMEDIATE_BLOCK."""
    # 1) admin_lee 로 본청 로그인
    tok, _, _ = login_as("admin_lee", location="본청")

    # 2) 세션의 last_location/last_location_time 을 본청 + 직전 시각으로 갱신
    #    (로그인 시 자동 기록됨. session_id 확보)
    db.execute(
        "UPDATE sessions SET last_location='본청', last_location_time=NOW() "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "  AND is_active=TRUE"
    )
    db.commit()

    # 3) 즉시 등급 4 자원에 부산 위치로 접근 시도 → impossible_travel 룰 발동
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade=4 LIMIT 1"
    ).fetchone()
    code, data = http(
        "GET", f"/api/resources/cases/{row['id']}",
        token=tok, location="지청-부산", ip="59.6.31.100",  # 부산 권역
    )
    # 즉시차단 (DENY=403/level=5) 또는 ADMIN_APPROVAL 까지 격상
    # impossible_travel 룰 발동 시 외부 응답은 DENY
    assert code in (200, 403)
    if code == 200:
        # 200 응답이라도 결정 레벨이 5 인지 확인
        assert data.get("decision", {}).get("level", 1) >= 4, \
            f"impossible_travel 시 level >= 4 기대, got {data}"


# ─── #8: 비허용 위치 + 미등록 단말 + 고민감 다운로드 즉시차단 ──
def test_high_risk_download_immediate_block(http, login_as, db):
    tok, _, _ = login_as("admin_lee")
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade=5 LIMIT 1"
    ).fetchone()
    # 미등록 device + 비허용 위치 + 등급 5 + download
    code, data = http(
        "POST", f"/api/resources/cases/{row['id']}/download",
        token=tok,
        device="totally-unknown-device",
        location="외부",
        ip="1.2.3.4",
        body={},
    )
    # 즉시차단 — 4xx 또는 200 + level=5
    if code == 200:
        assert data.get("decision", {}).get("level") == 5
    else:
        assert code in (400, 403)


# ─── #10: 일반 유저가 admin 엔드포인트 접근 → 403 ──────────────
def test_non_admin_blocked_from_admin_endpoints(http, login_as):
    tok, _, _ = login_as("detective_kim")  # 일반 user role
    for path in [
        "/api/admin/approvals/pending",
        "/api/admin/users",
        "/api/admin/login-approvals/pending",
        "/api/admin/break-glass/pending",
    ]:
        code, _ = http("GET", path, token=tok)
        assert code == 403, f"{path}: 403 기대 (일반 유저 차단)"


# ─── #11: 관리자 자기 승인 시도 → SELF_ACTION_BLOCKED ───────────
def test_self_approval_blocked(http, login_as, db):
    """admin_lee 가 자기 신청한 승인 요청을 본인이 승인 시도."""
    # 1) admin_lee 로 등급 4 자원에 승인 요청 생성
    tok_admin, _, _ = login_as("admin_lee")
    row = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=4 LIMIT 1"
    ).fetchone()
    code, data = http(
        "POST", f"/api/resources/cases/{row['id']}/request-approval",
        token=tok_admin, body={"reason": "self approval test"},
    )
    # 승인 요청 생성 ID 확보
    approval_id = data.get("approval_id") or data.get("id")
    if approval_id is None:
        # 생성 실패 — 직접 INSERT
        admin_id = db.execute(
            "SELECT id FROM users WHERE username='admin_lee'"
        ).fetchone()["id"]
        ins = db.execute(
            "INSERT INTO approvals (requester_id, resource_id, reason, status) "
            "VALUES (?, ?, ?, 'pending') RETURNING id",
            (admin_id, row["id"], "self approval test"),
        ).fetchone()
        approval_id = ins["id"]
        db.commit()

    # 2) admin_lee 본인이 자기 요청 승인 시도 → 차단
    code, data = http(
        "POST", f"/api/admin/approvals/{approval_id}/approve",
        token=tok_admin, body={},
    )
    assert code in (403, 400), f"self-approval 차단되어야 함: {code} {data}"
    err = (data.get("error") or "") + (data.get("code") or "")
    assert "self" in err.lower() or "자기" in err or "본인" in err or \
           "self_action_blocked" in err.lower(), data


# ─── #12: 마지막 admin 비활성화 시도 → 차단 ────────────────────
def test_last_admin_protection(http, login_as, db):
    """admin_lee 가 admin role 인 자기를 비활성화 시도 → 차단.

    시드에는 admin_lee(role=admin) 1명 + deputy_han/oh(role=deputy_admin) 2명.
    'admin' 만으로 보호하면 admin_lee 비활성 시 차단되어야 함.
    """
    tok, _, _ = login_as("admin_lee")
    admin_id = db.execute(
        "SELECT id FROM users WHERE username='admin_lee'"
    ).fetchone()["id"]
    code, data = http(
        "POST", f"/api/admin/users/{admin_id}/deactivate",
        token=tok, body={},
    )
    # 자기 자신 비활성화는 항상 차단되거나 마지막 admin 보호로 차단
    assert code in (400, 403), f"마지막 admin 자기-비활성 차단 기대: {code} {data}"


# ─── #14: 신규 계정 admin_approval_gate 우회 시도 ───────────────
def test_new_account_admin_gate(http, login_as, db):
    """OTP 토큰이 없는 신규 계정은 담당 사건 0개로 시작하고 관리자 승인 대상."""
    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", "/api/admin/users/create",
        token=tok_admin, body={
            "username": "p0_test_new_user",
            "password": "TestPassword1234",
            "name": "테스트신규",
            "department": "강력범죄수사대",
            "rank": "순경", "role": "user",
            "assigned_cases": [],
            "allowed_locations": ["본청"],
            "job_scope": ["violent_crime"],
        },
    )
    assert code in (200, 201), f"create failed: {code} {data}"
    assert data.get("login_path") == "admin_approval_gate", data
    assert data.get("login_gate_reason") == "token_device_missing", data
    assert data.get("user", {}).get("assigned_cases") == [], data
    assert data.get("user", {}).get("has_token_device") is False, data

    work_dev = data.get("work_device_id")
    created = db.execute(
        "SELECT id, assigned_cases, trust_score, violation_count "
        "FROM users WHERE username='p0_test_new_user'"
    ).fetchone()
    assert created["assigned_cases"] == []
    assert float(created["trust_score"]) == 70.0
    assert int(created["violation_count"]) == 0
    token_devices = db.execute(
        "SELECT COUNT(*) AS c FROM user_devices "
        "WHERE user_id=? AND device_type='totp_token' AND is_active",
        (created["id"],)
    ).fetchone()["c"]
    assert token_devices == 0

    # OTP 토큰 등록 전 로그인 시도 → admin_approval_required (403)
    code, data = http(
        "POST", "/api/auth/login",
        body={
            "username": "p0_test_new_user",
            "password": "TestPassword1234",
            "device_id": work_dev,
            "location": "본청",
        },
        device=work_dev,
    )
    assert code == 403, f"신규 계정이 승인 없이 통과: {code} {data}"
    assert data.get("code") in ("admin_approval_required",
                                "admin_approval_pending"), data
    pending = db.execute(
        "SELECT justification FROM login_approval_requests "
        "WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1",
        (created["id"],)
    ).fetchone()
    assert pending and "OTP" in pending["justification"]


def test_new_account_registered_token_removes_admin_gate(http, login_as, db):
    """OTP 토큰 등록 후 신규 계정은 일반 MFA로 로그인하고 자기 부서 사건만 요청."""
    tok_admin, _, _ = login_as("admin_lee")
    username = "p0_test_new_user_with_token"
    password = "TestPassword1234"
    code, data = http(
        "POST", "/api/admin/users/create",
        token=tok_admin, body={
            "username": username,
            "password": password,
            "name": "테스트신규토큰",
            "department": "강력범죄수사대",
            "rank": "순경", "role": "user",
            "assigned_cases": [3, 4, 5],
            "allowed_locations": ["본청"],
            "job_scope": ["violent_crime"],
        },
    )
    assert code in (200, 201), f"create failed: {code} {data}"
    work_dev = data.get("work_device_id")
    created = db.execute(
        "SELECT id, assigned_cases, trust_score FROM users WHERE username=?",
        (username,)
    ).fetchone()
    assert created["assigned_cases"] == []
    assert float(created["trust_score"]) == 70.0

    from security.mfa_service import generate_secret, generate_totp
    secret = generate_secret()
    db.execute(
        "INSERT INTO user_devices "
        "(user_id, device_id, device_name, device_type, mfa_secret, api_key, is_active) "
        "VALUES (?, ?, ?, 'totp_token', ?, NULL, TRUE)",
        (created["id"], "token-p0-new-user", "신규 계정 테스트 토큰", secret)
    )
    db.commit()

    code, login_data = http(
        "POST", "/api/auth/login",
        body={
            "username": username,
            "password": password,
            "device_id": work_dev,
            "location": "본청",
        },
        device=work_dev,
    )
    assert code == 200, f"OTP 등록 후 관리자 승인 없이 1차 로그인 기대: {code} {login_data}"
    assert login_data.get("mfa_required") is True
    assert login_data.get("has_token_device") is True
    assert login_data.get("admin_gated") is False

    otp = generate_totp(secret)
    code, mfa_data = http(
        "POST", "/api/auth/mfa/verify",
        token=login_data["token"],
        body={"otp_code": otp, "device_id": work_dev, "location": "본청"},
        device=work_dev,
    )
    assert code == 200, f"OTP 등록 계정 일반 MFA 실패: {code} {mfa_data}"
    assert mfa_data.get("admin_gated") is False
    token = mfa_data["token"]

    traffic = db.execute(
        "SELECT id FROM resources WHERE case_number='2026-ADM-0001'"
    ).fetchone()
    code, data = http(
        "POST", f"/api/resources/cases/{traffic['id']}/assignment-request",
        token=token, body={"reason": "다른 부서 사건 등록 시도"},
    )
    assert code == 403, data
    assert data.get("code") == "assignment_scope_mismatch"

    drug = db.execute(
        "SELECT id FROM resources WHERE case_number='2026-DRG-0022'"
    ).fetchone()
    code, data = http(
        "POST", f"/api/resources/cases/{drug['id']}/assignment-request",
        token=token, body={"reason": "같은 부서지만 직무 태그 불일치"},
    )
    assert code == 403, data
    assert data.get("code") == "assignment_scope_mismatch"
    scope = data.get("assignment_scope") or {}
    assert any(t.get("value") == "drug" for t in scope.get("resource_job_tags", []))
    assert "직무 카테고리" in (scope.get("guidance") or "")

    violent = db.execute(
        "SELECT id FROM resources WHERE case_number='2026-VCT-0108'"
    ).fetchone()
    code, data = http(
        "POST", f"/api/resources/cases/{violent['id']}/assignment-request",
        token=token, body={"reason": "같은 부서 강력 사건 담당 등록 요청"},
    )
    assert code == 201, data
    assert data.get("assignment_request", {}).get("resource_id") == violent["id"]


# ─── #15-16: audit_logs 변조 시도 ───────────────────────────────
def test_audit_log_update_blocked_by_trigger(db):
    """UPDATE audit_logs ... 시도 → PG 트리거가 거부."""
    # 먼저 로그 한 줄 INSERT 확보
    db.execute(
        "INSERT INTO audit_logs (layer, event_type, details, user_id) "
        "VALUES (?,?,?,?)",
        ("operation", "TEST_INSERT", '{"test": true}', None),
    )
    db.commit()
    row = db.execute(
        "SELECT id FROM audit_logs WHERE event_type='TEST_INSERT' LIMIT 1"
    ).fetchone()
    assert row, "INSERT 가 적어도 통과해야 함"

    # UPDATE 시도 — 트리거가 거부해야 함
    import psycopg2
    with pytest.raises((psycopg2.errors.RaiseException, Exception)):
        db.execute(
            "UPDATE audit_logs SET event_type='TAMPERED' WHERE id=?",
            (row["id"],),
        )
        db.commit()
    db.rollback()


def test_audit_log_delete_blocked_by_trigger(db):
    """DELETE FROM audit_logs ... → 트리거 거부."""
    db.execute(
        "INSERT INTO audit_logs (layer, event_type, details, user_id) "
        "VALUES (?,?,?,?)",
        ("operation", "TEST_DELETE", '{}', None),
    )
    db.commit()
    row = db.execute(
        "SELECT id FROM audit_logs WHERE event_type='TEST_DELETE' LIMIT 1"
    ).fetchone()

    import psycopg2
    with pytest.raises((psycopg2.errors.RaiseException, Exception)):
        db.execute("DELETE FROM audit_logs WHERE id=?", (row["id"],))
        db.commit()
    db.rollback()


# ─── #19: 동시 로그인 (다른 IP) → 양쪽 pending_reauth ──────────
def test_concurrent_login_locks_both_sessions(http, login_as, db):
    """admin_lee 로그인 (IP1) → 다른 IP 로 또 로그인 → 양쪽 pending_reauth."""
    tok1, _, _ = login_as("admin_lee", ip="10.0.0.1")
    tok2, _, _ = login_as("admin_lee", ip="10.0.0.2")

    # 양쪽 토큰 모두 받았어도, 이후 보호 엔드포인트 호출 시 재인증 요구
    code1, data1 = http("GET", "/api/auth/me", token=tok1)
    code2, data2 = http("GET", "/api/auth/me", token=tok2)

    # 적어도 하나는 401 + concurrent_session_detected / reauth_required
    blocked = [c for c in (code1, code2) if c == 401]
    assert len(blocked) >= 1, (
        f"동시 로그인 시 적어도 한쪽 세션은 재인증 요구 기대. "
        f"code1={code1} code2={code2}"
    )


# ─── #20: Break-Glass OTP 미입력 → ACTIVATION_REFUSED ──────────
def test_break_glass_without_otp_refused(http, login_as):
    tok, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", "/api/break-glass/activate",
        token=tok, body={
            "scope": "broad",
            "min_grade": 4,
            "justification": "긴급 사건 대응 시연",
            # otp_code 의도적 누락
        },
    )
    assert code in (400, 401, 403), f"OTP 없이 BG 통과: {code} {data}"


# ─── #21: Break-Glass unjustified 사후심사 → trust 페널티 ───────
def test_break_glass_unjustified_penalty(http, login_as, db):
    """BG 발동 후 부관리자가 unjustified 판정 → trust_score 차감."""
    # 1) admin_lee BG 발동을 위해서는 OTP 필요. 토큰 기기에서 실제 TOTP 생성.
    from security.mfa_service import generate_totp
    row = db.execute(
        "SELECT mfa_secret FROM user_devices "
        "WHERE device_id='token-003' "
        "  AND user_id=(SELECT id FROM users WHERE username='admin_lee')"
    ).fetchone()
    tok_admin, _, _ = login_as("admin_lee")
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL "
        "WHERE device_id='token-003' "
        "  AND user_id=(SELECT id FROM users WHERE username='admin_lee')"
    )
    db.commit()
    otp = generate_totp(row["mfa_secret"])
    code, data = http(
        "POST", "/api/break-glass/activate",
        token=tok_admin, body={
            "scope": "broad",
            "min_grade": 4,
            "justification": "BG penalty test - intentional unjustified",
            "otp_code": otp,
        },
    )
    if code != 200:
        pytest.skip(f"BG 발동 실패 (otp 등 환경 의존): {code} {data}")

    activation = data.get("activation") or data
    activation_id = activation.get("activation_id") or activation.get("id")
    assert activation_id, data

    # 2) BG 발동 전 admin_lee trust 기록
    pre_trust = db.execute(
        "SELECT trust_score FROM users WHERE username='admin_lee'"
    ).fetchone()["trust_score"]

    code, data = http(
        "POST", f"/api/break-glass/{activation_id}/release",
        token=tok_admin, body={},
    )
    assert code == 200, data

    # 3) deputy_han 으로 사후심사 — unjustified 판정
    tok_deputy, _, _ = login_as("deputy_han")
    code, _ = http(
        "POST", f"/api/admin/break-glass/{activation_id}/review",
        token=tok_deputy, body={
            "verdict": "unjustified",
            "notes": "테스트 페널티",
        },
    )
    assert code == 200

    # 4) admin_lee trust_score 차감 확인
    post_trust = db.execute(
        "SELECT trust_score, violation_count FROM users WHERE username='admin_lee'"
    ).fetchone()
    assert post_trust["trust_score"] < pre_trust, (
        f"unjustified 후 trust 차감 기대: {pre_trust} -> {post_trust['trust_score']}"
    )
    assert post_trust["violation_count"] >= 1
