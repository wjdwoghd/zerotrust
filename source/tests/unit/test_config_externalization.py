"""
config.py 외부화 변수가 핸들러에서 실제로 반영되는지의 회귀 테스트.

기존에는 `from config import ACCOUNT_MAX_FAILED_LOGIN` 누락 + 5 하드코딩으로
환경변수 변경이 무효화되었다 (ITEM 3).
"""
from __future__ import annotations


# ─── ITEM 3 / TEST 3 — ACCOUNT_MAX_FAILED_LOGIN 반영 ────────────
def test_account_max_failed_login_externalized(monkeypatch, http, db):
    """
    ACCOUNT_MAX_FAILED_LOGIN 을 3 으로 패치 후 잘못된 비밀번호 3회 시도 →
    users.is_locked == TRUE 단언. 5 가 박혀 있다면 3회로는 잠기지 않으므로
    이 테스트가 실패해 회귀를 잡는다.
    """
    import api.auth_handler as ah
    monkeypatch.setattr(ah, "ACCOUNT_MAX_FAILED_LOGIN", 3, raising=False)

    for i in range(3):
        code, _ = http("POST", "/api/auth/login", body={
            "username": "admin_lee",
            "password": "wrong_password_attempt",
            "device_id": "registered-004",
            "location": "본청",
        })
        assert code in (401, 403), f"시도 {i+1}: 401/403 기대, got {code}"

    row = db.execute(
        "SELECT is_locked, failed_login_count FROM users WHERE username='admin_lee'"
    ).fetchone()
    assert row is not None
    assert row["is_locked"] is True, (
        f"3회 실패 후 is_locked 기대 — failed_login_count={row['failed_login_count']}"
    )
    assert row["failed_login_count"] >= 3
