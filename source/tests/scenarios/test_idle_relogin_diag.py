"""
임시 진단 — idle 만료 후 같은 계정 재로그인이 409 already_logged_in 으로
차단되는 사용자 보고 재현.

본 파일은 진단 후 삭제 가능. 결과를 보고 후 처리한다.
"""
from __future__ import annotations


def test_idle_expiry_relogin_path(http, login_as, db):
    """
    1) admin_lee 로그인 + MFA 통과 → 세션 생성
    2) sessions.last_activity 를 NOW-16m 로 강제 (idle 15m 초과)
    3) /api/auth/me 호출 → 401 만료 응답 + sessions.is_active=FALSE 기대
    4) 다시 login_as("admin_lee") → 어떤 응답?
    """
    print("\n=== STEP 1: 첫 로그인 ===")
    tok1, code1, data1 = login_as("admin_lee")
    print(f"  login_as: code={code1}, token_len={len(tok1) if tok1 else 0}")

    # 첫 세션 id 조회
    sess_row = db.execute(
        "SELECT id, is_active, last_activity FROM sessions "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    sess_id = sess_row["id"]
    print(f"  session: id={sess_id}, is_active={sess_row['is_active']}, "
          f"last_activity={sess_row['last_activity']}")

    print("\n=== STEP 2: idle 만료 강제 (last_activity = NOW-16m) ===")
    db.execute(
        "UPDATE sessions SET last_activity = CURRENT_TIMESTAMP - INTERVAL '16 minutes' "
        "WHERE id=?",
        (sess_id,)
    )
    db.commit()
    sess_row = db.execute(
        "SELECT is_active, last_activity FROM sessions WHERE id=?", (sess_id,)
    ).fetchone()
    print(f"  forced last_activity={sess_row['last_activity']} "
          f"is_active={sess_row['is_active']}")

    print("\n=== STEP 3: /api/auth/me 호출 — 만료 처리 트리거 ===")
    code, data = http("GET", "/api/auth/me", token=tok1)
    print(f"  me: code={code}, data={data}")

    sess_row = db.execute(
        "SELECT is_active FROM sessions WHERE id=?", (sess_id,)
    ).fetchone()
    print(f"  after-me sessions.is_active={sess_row['is_active']}")

    print("\n=== STEP 4: 다시 로그인 시도 ===")
    # login_as 는 첫 단계 login + mfa/verify 까지 진행. mfa/verify 단계
    # zombie cleanup + live_ids 검사가 핵심.
    tok2, code2, data2 = login_as("admin_lee")
    print(f"  re-login_as: code={code2}, data={data2}")

    # 모든 세션 상태 한 번 더
    print("\n=== STEP 5: 최종 세션 테이블 상태 ===")
    rows = db.execute(
        "SELECT id, is_active, last_activity, login_at, "
        "       pending_reauth, pending_reauth_at "
        "FROM sessions "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "ORDER BY id DESC LIMIT 5"
    ).fetchall()
    for r in rows:
        print(f"  id={r['id']} active={r['is_active']} "
              f"last_act={r['last_activity']} "
              f"login_at={r['login_at']} "
              f"pending_reauth={r['pending_reauth']}")
