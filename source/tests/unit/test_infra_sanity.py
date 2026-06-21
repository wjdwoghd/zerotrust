"""
인프라 sanity — conftest 의 fixture 들이 정상 동작하는지 빠른 검증.
"""
from __future__ import annotations


def test_db_fixture_has_seed_users(db):
    """reset_db 가 시드 7명을 매번 보장해야 함."""
    rows = db.execute("SELECT username FROM users ORDER BY id").fetchall()
    usernames = [r["username"] for r in rows]
    assert "admin_lee" in usernames
    assert "deputy_han" in usernames
    assert len(usernames) == 7


def test_db_fixture_has_seed_resources(db):
    cnt = db.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"]
    assert cnt == 15


def test_db_fixture_has_token_devices(db):
    rows = db.execute(
        "SELECT u.username FROM user_devices d "
        "JOIN users u ON u.id = d.user_id "
        "WHERE d.device_type = 'totp_token' "
        "ORDER BY u.id"
    ).fetchall()
    # 시드 사용자 7명 중 patrol_jung 제외 6명이 토큰 기기 보유
    assert len(rows) == 6


def test_reset_db_isolation(db):
    """이전 테스트가 만든 흔적이 남지 않는다."""
    db.execute(
        "INSERT INTO users (username, password_hash, name, department, rank, role) "
        "VALUES ('temp_pollution_user','x','temp','dept','rank','user')"
    )
    db.commit()
    cnt = db.execute(
        "SELECT COUNT(*) AS c FROM users WHERE username='temp_pollution_user'"
    ).fetchone()["c"]
    assert cnt == 1
    # 이 테스트가 끝나면 reset_db 가 다음 테스트 시작 시 정리해야 함


def test_reset_db_isolation_followup(db):
    """직전 테스트가 만든 temp_pollution_user 가 사라졌어야 함."""
    cnt = db.execute(
        "SELECT COUNT(*) AS c FROM users WHERE username='temp_pollution_user'"
    ).fetchone()["c"]
    assert cnt == 0


def test_live_server_healthz(http):
    code, data = http("GET", "/healthz")
    assert code == 200
    assert data["status"] == "ok"


def test_live_server_readyz(http):
    code, data = http("GET", "/readyz")
    assert code == 200
    assert data["status"] == "ready"
    assert data["db"] == "up"


def test_login_as_admin(login_as):
    """admin_lee 로그인 + MFA 까지 통과해 토큰 발급."""
    tok, code, data = login_as("admin_lee")
    assert code == 200, f"login failed: {data}"
    assert tok is not None
    assert data.get("user", {}).get("username") == "admin_lee"


def test_login_with_token_protected_endpoint(http, login_as):
    """발급된 토큰으로 보호된 엔드포인트 접근."""
    tok, _, _ = login_as("admin_lee")
    code, data = http("GET", "/api/auth/me", token=tok)
    assert code == 200, data
    # /api/auth/me 응답은 {"user": {...}, "session": {...}}
    assert data.get("user", {}).get("username") == "admin_lee"
