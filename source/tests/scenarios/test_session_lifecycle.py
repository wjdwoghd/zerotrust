"""
세션 라이프사이클 — TZ 함정 / pending_reauth 만료 도달성 회귀.

ITEM 7·8 의 감사 결함 회귀 보호.
"""
from __future__ import annotations

import os

import pytest


# ─── ITEM 7 / TEST 8 — sessions.absolute_expires_at TZ ─────────────
# 결함 (감사 #7): naive strftime 문자열을 TIMESTAMPTZ 에 바인딩하면 PG
# 세션 TZ 기준으로 해석. KST 서버 + UTC PG 세션이면 9시간 미래로 해석되어
# 쓰기 (실 만료 시각이 +9h 로 어긋남) 또는 9시간 과거로 해석되어 즉시
# 만료(0/음수). 후자가 발생하면 로그인 직후 `/api/auth/me` 의
# absolute_remaining_seconds 가 즉시 0 또는 음수로 떨어진다.
#
# 매트릭스 테스트 — KST 환경에서만 의미 있으므로 다른 TZ 에선 skip.
@pytest.mark.skipif(
    os.environ.get("TZ") not in ("Asia/Seoul", "KST", "Asia/Tokyo"),
    reason="TZ 함정 매트릭스 — KST/+09:00 환경에서만 실행",
)
def test_session_absolute_remaining_positive_under_kst(http, login_as):
    """KST 서버에서 로그인 직후 absolute_remaining_seconds 가 양수여야 함."""
    tok, code, data = login_as("admin_lee")
    assert code == 200, f"login_as 실패: {data}"

    code, me = http("GET", "/api/auth/me", token=tok)
    assert code == 200, f"me 호출 실패: {me}"
    sess = me.get("session") or {}
    abs_remain = sess.get("absolute_remaining_seconds")
    assert abs_remain is not None, f"absolute_remaining_seconds 누락: {sess}"
    assert abs_remain > 60, (
        f"로그인 직후 absolute_remaining_seconds={abs_remain} — "
        f"TZ 함정으로 즉시 만료 처리됐을 가능성 (ITEM 7 회귀)"
    )


def test_admin_login_approval_expires_at_consistent(http, login_as, db):
    """admin 이 발급한 login_approval_requests.expires_at 이 미래 시각 +근접 일치."""
    # patrol_jung 의심 계정 → 로그인 시도 → approval 요청 자동 생성
    code, data = http(
        "POST", "/api/auth/login",
        body={
            "username": "patrol_jung", "password": "password123",
            "device_id": "registered-007", "location": "본청",
        },
        device="registered-007",
    )
    # admin_approval_required (403) 응답이 정상
    if code != 403:
        pytest.skip(f"admin gate 미발동: {code} {data}")

    # 가장 최근 pending 요청 찾기
    target = db.execute(
        "SELECT id FROM login_approval_requests "
        "WHERE user_id=(SELECT id FROM users WHERE username='patrol_jung') "
        "  AND status='pending' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not target:
        pytest.skip("login_approval_requests pending 행이 없음")
    req_id = target["id"]

    # admin 으로 승인
    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/login-approvals/{req_id}/approve",
        token=tok_admin, body={},
    )
    assert code == 200, f"승인 실패: {code} {data}"

    # DB 의 expires_at 이 미래 시각이고 TTL 근사치인지
    row = db.execute(
        "SELECT expires_at, "
        "       EXTRACT(EPOCH FROM (expires_at - CURRENT_TIMESTAMP)) AS remain "
        "FROM login_approval_requests WHERE id=?",
        (req_id,)
    ).fetchone()
    assert row["remain"] is not None
    remain = float(row["remain"])
    # ADMIN_APPROVAL_TTL_SEC=1800 (30m). 방금 발급했으니 그 근방.
    assert 60 < remain <= 1800 + 60, (
        f"expires_at 잔여 {remain:.0f}s — TTL(1800s) 근접이 아니면 "
        f"TZ 함정으로 +9h/-9h 어긋났을 가능성 (ITEM 7)"
    )


# ─── ITEM 8 / TEST 2 — pending_reauth 시한 초과 후 만료 응답 ───────
# 결함 (감사 #8): require_auth 가 pending_reauth=TRUE 면 즉시 401
# concurrent_session_detected 를 반환해, core/session_guard.py:98-111 의
# SESSION_EXPIRED_PENDING_REAUTH 만료 분기에 도달하지 못했다.
# 수정: check_session() 을 먼저 호출 → 만료 분기 도달 가능.
def test_pending_reauth_expires_after_timeout(http, login_as, db):
    """pending_reauth_at 이 시한 초과인 세션은 만료 처리된다."""
    from config import SESSION_PENDING_REAUTH_TIMEOUT_SEC

    # admin_lee 로그인 → 세션 1건
    tok, _, _ = login_as("admin_lee")

    # pending_reauth=TRUE + pending_reauth_at 을 시한 초과 시점으로 강제
    db.execute(
        "UPDATE sessions "
        "SET pending_reauth=TRUE, "
        "    pending_reauth_at = CURRENT_TIMESTAMP - INTERVAL '1 second' * ? "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "  AND is_active=TRUE",
        (SESSION_PENDING_REAUTH_TIMEOUT_SEC + 60,)
    )
    db.commit()

    # /api/auth/me 호출 → 시한 초과 만료 분기로 들어가야 함
    code, data = http("GET", "/api/auth/me", token=tok)
    assert code == 401, (
        f"pending_reauth 시한 초과 → 401 만료 응답 기대: {code} {data}"
    )
    err_code = (data.get("code") or "").lower()
    # SESSION_EXPIRED_PENDING_REAUTH 또는 그에 해당하는 만료 코드 기대
    # (concurrent_session_detected 로 끊기면 ITEM 8 회귀)
    assert "expired" in err_code or "pending_reauth" in err_code, (
        f"만료 분기 도달 실패 — code={err_code}, data={data}"
    )
