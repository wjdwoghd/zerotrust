"""
로그아웃 후 물리적 이동 불가능한 위치 재로그인 차단 (cross-session impossible travel)

배경 (시연 시나리오):
  1. 사용자가 '본청' 위치로 로그인 → MFA 통과 → 정상 세션
  2. 로그아웃 (세션 is_active=FALSE)
  3. 동일 계정으로 위치만 '해외' 등 물리적 이동 불가능한 곳으로 바꿔 재로그인 시도
  → 차단되어야 한다 (기존엔 LoginHandler 가 위치 무검증으로 통과시켰음)

검증 지점:
  - 두 번째 로그인 응답 status=403, code=impossible_travel_login_blocked
  - 감사 이벤트 IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED 가 남는다
  - 회귀 방지: 같은 위치 재로그인 / 합리적 시간 경과 후 다른 위치 재로그인은 통과

travel_service 의 _LOCATION_COORDS 는 시뮬 옵션 7종 (본청·강남서·판교센터·
동대문서·은평서·해외·비허용위치) 좌표를 모두 갖는다.
판정 모델은 거리 구간 × 평균 속도 + 교통 마진 (urban/metro/intercity/
longhaul/international). 본청-해외 임계 ≈ 266분, 본청-은평서 임계 ≈ 26분.
"""
from __future__ import annotations

import datetime
import json


# ─── A. 본청 → 해외 즉시 재로그인 → 차단 ─────────────────────────
def test_login_blocked_when_immediate_relocation_to_overseas(
    http, login_as, db
):
    """본청 로그인 → 로그아웃 → 즉시 해외 위치 재로그인 시 403 으로 차단된다."""
    # 1) 본청으로 정상 로그인
    tok1, code1, data1 = login_as("admin_lee", location="본청")
    assert code1 == 200 and tok1, f"본청 첫 로그인 실패: {data1}"

    # 2) 로그아웃 (is_active=FALSE 로 마킹되고 세션 행은 남음 → impossible_travel
    #    게이트가 직전 위치/시각을 그 행에서 가져온다)
    code_lo, _ = http("POST", "/api/auth/logout", token=tok1)
    assert code_lo == 200, "로그아웃이 실패해선 안 됨"

    # 3) 동일 계정으로 위치만 '해외' 로 바꿔 재로그인 시도
    code2, data2 = http(
        "POST", "/api/auth/login",
        body={
            "username": "admin_lee", "password": "password123",
            "device_id": "registered-004", "location": "해외",
        },
        device="registered-004", location="해외",
    )
    assert code2 == 403, (
        f"본청 직후 해외 재로그인은 403 이어야 함 (실제 {code2}): {data2}"
    )
    assert data2.get("code") == "impossible_travel_login_blocked", (
        f"차단 코드가 다름: {data2}"
    )

    # 4) 감사 이벤트 확인 — IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED 가 남았는지
    row = db.execute(
        "SELECT details FROM audit_logs "
        "WHERE event_type='IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED' "
        "  AND user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None, (
        "IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED 감사 이벤트가 남지 않음 — "
        "LoginHandler 의 게이트가 발동하지 않은 것"
    )
    details = json.loads(row["details"]) if isinstance(row["details"], str) \
        else row["details"]
    assert details.get("current_location") == "해외"
    assert details.get("prev_location") in ("본청",), (
        f"직전 위치 기록이 본청이어야 함: {details}"
    )


# ─── B. 같은 위치 재로그인은 통과 (회귀 방지) ────────────────────
def test_login_same_location_relogin_passes(http, login_as, db):
    """본청 → 로그아웃 → 본청 재로그인은 정상 통과해야 한다 (거리 0)."""
    tok1, code1, _ = login_as("admin_lee", location="본청")
    assert code1 == 200 and tok1

    code_lo, _ = http("POST", "/api/auth/logout", token=tok1)
    assert code_lo == 200

    # OTP replay 방지는 의도된 보안 기능이다. 여기서는 위치 게이트만 보려는
    # 테스트이므로, 실사용자가 다음 TOTP 코드를 입력한 상황을 명시적으로 만든다.
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee')"
    )
    db.commit()

    tok2, code2, data2 = login_as("admin_lee", location="본청")
    assert code2 == 200 and tok2, (
        f"같은 위치 재로그인이 차단됨 — 회귀: {data2}"
    )


# ─── C. 직전 세션 없음 (첫 로그인) → 통과 ────────────────────────
def test_first_login_no_history_passes(http, login_as):
    """직전 세션이 없는 첫 로그인은 (대상 사용자 본인이 이전에 한 번도 로그인한 적
    없는 상태) 위치 무관 통과한다. _reset_db_state 픽스처가 매 테스트마다 wipe+
    seed 하므로 admin_lee 의 세션 이력은 비어 있다."""
    tok, code, data = login_as("admin_lee", location="본청")
    assert code == 200 and tok, f"첫 로그인 통과해야 함: {data}"


# ─── D. 충분히 시간이 경과한 뒤 위치 변경은 통과 ─────────────────
def test_login_passes_after_enough_time_to_travel(http, login_as, db):
    """직전 세션의 last_activity 를 과거(예: 6시간 전)로 강제 조정한 뒤
    해외 재로그인은 통과해야 한다 — 임계속도 800km/h 기준 본청-도쿄 1158km 는
    1.5h 만에 이동 가능, 6h 면 여유."""
    # 이 테스트는 impossible-travel 만 격리 검증한다. allowed_locations
    # 게이트가 별도 차단하지 않도록 해외를 허용 위치에 포함한다.
    db.execute(
        "UPDATE users SET allowed_locations=? WHERE username='admin_lee'",
        (json.dumps(["본청", "해외"], ensure_ascii=False),)
    )
    db.commit()

    tok1, code1, _ = login_as("admin_lee", location="본청")
    assert code1 == 200 and tok1

    code_lo, _ = http("POST", "/api/auth/logout", token=tok1)
    assert code_lo == 200

    # 직전 세션의 시각을 6시간 전으로 옮긴다 (last_location_time / last_activity 둘 다)
    six_h_ago = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(hours=6))
    db.execute(
        "UPDATE sessions SET last_location_time=?, last_activity=? "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "  AND is_active=FALSE",
        (six_h_ago, six_h_ago)
    )
    db.commit()

    # 첫 로그인 때 사용한 OTP step 과 다른 코드를 입력한 상황.
    db.execute(
        "UPDATE user_devices SET last_otp_step=NULL "
        "WHERE user_id=(SELECT id FROM users WHERE username='admin_lee')"
    )
    db.commit()

    tok2, code2, data2 = login_as("admin_lee", location="해외")
    assert code2 == 200 and tok2, (
        f"6시간 경과 후 해외 재로그인은 통과해야 함 (실제 {code2}): {data2}"
    )


# ─── E. allowed_locations 게이트 — "비허용위치" 로그인 차단 ───────
def test_login_blocked_when_location_not_in_allowed(http, db):
    """사용자의 allowed_locations 에 없는 위치(시뮬 패널의 "비허용위치"
    옵션)로 로그인 시도하면 403 차단된다. 직전 세션이 없는 첫 로그인이면
    impossible-travel 판정 대상이 아니므로 allowed_locations 게이트가 잡는다."""
    code, data = http(
        "POST", "/api/auth/login",
        body={
            "username": "admin_lee", "password": "password123",
            "device_id": "registered-004", "location": "비허용위치",
        },
        device="registered-004", location="비허용위치",
    )
    assert code == 403, f"비허용 위치 첫 로그인은 403 이어야 함: {code} {data}"
    assert data.get("code") == "location_not_allowed_login", (
        f"차단 코드가 다름: {data}"
    )
    row = db.execute(
        "SELECT details FROM audit_logs "
        "WHERE event_type='LOGIN_BLOCKED_LOCATION_NOT_ALLOWED' "
        "  AND user_id=(SELECT id FROM users WHERE username='admin_lee') "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None, (
        "LOGIN_BLOCKED_LOCATION_NOT_ALLOWED 감사 이벤트가 남지 않음"
    )
