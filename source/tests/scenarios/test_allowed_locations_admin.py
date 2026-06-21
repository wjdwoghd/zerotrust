"""
허용 위치(allowed_locations) 관리자 갱신 API 권한 분리 시나리오

권한 매트릭스:
  대상 role        │ 수정 가능 주체
  ─────────────────┼───────────────────────
  user             │ admin / superadmin
  deputy_admin     │ admin / superadmin
  admin            │ deputy_admin
  superadmin       │ deputy_admin

추가 안전장치:
  - 자기 자신 수정 금지 (403 self_action_blocked)
  - 빈 배열 거부 (400 missing_allowed_locations)

엔드포인트: PUT /api/admin/users/<id>/allowed_locations
Body: {"allowed_locations": ["본청", "강남서", ...]}
"""
from __future__ import annotations

import json


def _user_id(db, username):
    row = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    assert row, f"시드에 {username} 없음"
    return int(row["id"])


def _allowed(db, username):
    row = db.execute(
        "SELECT allowed_locations FROM users WHERE username=?", (username,)
    ).fetchone()
    val = row["allowed_locations"]
    return json.loads(val) if isinstance(val, str) else val


# ─── A. admin 이 user 의 위치 변경 → 허용 ──────────────────────
def test_admin_updates_user_locations_ok(http, login_as, db):
    tok, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "detective_kim")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "강남서", "판교센터"]},
        token=tok,
    )
    assert code2 == 200, f"admin → user 갱신은 통과해야 함: {code2} {data}"
    assert data["allowed_locations"] == ["본청", "강남서", "판교센터"]
    assert _allowed(db, "detective_kim") == ["본청", "강남서", "판교센터"]


# ─── B. admin 이 deputy_admin 의 위치 변경 → 허용 ──────────────
def test_admin_updates_deputy_locations_ok(http, login_as, db):
    tok, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "deputy_han")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "동대문서"]},
        token=tok,
    )
    assert code2 == 200, f"admin → deputy 갱신은 통과해야 함: {code2} {data}"
    assert _allowed(db, "deputy_han") == ["본청", "동대문서"]


# ─── C. admin 이 admin(다른 admin) 의 위치 변경 → 거부 ─────────
def test_admin_cannot_update_admin_locations(http, login_as, db):
    # admin_lee 외에 다른 admin 이 없으므로 admin_lee → admin_lee 가 되는데,
    # 그건 자기 자신 차단으로 잡힌다. 권한 매트릭스 자체 검증은 D 케이스에서.
    # 여기선 자기 자신 차단을 확인.
    tok, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok

    self_id = _user_id(db, "admin_lee")
    code2, data = http(
        "PUT", f"/api/admin/users/{self_id}/allowed_locations",
        body={"allowed_locations": ["본청"]},
        token=tok,
    )
    assert code2 == 403, f"자기 자신 수정은 403 이어야 함: {code2} {data}"
    assert data.get("code") == "self_action_blocked"


# ─── D. deputy_admin 이 admin 의 위치 변경 → 허용 ─────────────
def test_deputy_updates_admin_locations_ok(http, login_as, db):
    tok, code, _ = login_as("deputy_han", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "admin_lee")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "판교센터"]},
        token=tok,
    )
    assert code2 == 200, f"deputy → admin 갱신은 통과해야 함: {code2} {data}"
    assert _allowed(db, "admin_lee") == ["본청", "판교센터"]


# ─── E. deputy_admin 이 user 의 위치 변경 → 거부 ──────────────
def test_deputy_cannot_update_user_locations(http, login_as, db):
    tok, code, _ = login_as("deputy_han", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "detective_kim")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "은평서"]},
        token=tok,
    )
    assert code2 == 403, f"deputy → user 갱신은 거부되어야 함: {code2} {data}"
    assert data.get("code") == "role_permission_denied"


# ─── F. deputy_admin 이 다른 deputy_admin 위치 변경 → 거부 ────
def test_deputy_cannot_update_deputy_locations(http, login_as, db):
    tok, code, _ = login_as("deputy_han", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "deputy_oh")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청"]},
        token=tok,
    )
    assert code2 == 403, f"deputy → deputy 갱신은 거부되어야 함: {code2} {data}"
    assert data.get("code") == "role_permission_denied"


# ─── G. user 가 호출 → 403 (require_admin 단계에서 차단) ──────
def test_user_cannot_call_endpoint(http, login_as, db):
    tok, code, _ = login_as("detective_kim", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "officer_choi")
    code2, _ = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청"]},
        token=tok,
    )
    assert code2 == 403, "일반 user 는 엔드포인트 호출 자체가 차단"


# ─── H. 빈 배열 거부 ─────────────────────────────────────────
def test_empty_locations_rejected(http, login_as, db):
    tok, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "detective_kim")
    code2, data = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": []},
        token=tok,
    )
    assert code2 == 400 and data.get("code") == "missing_allowed_locations"


# ─── I. 갱신 후 로그인 게이트 동작 확인 — 추가된 위치로 로그인 통과 ─
def test_user_can_login_at_newly_allowed_location(http, login_as, db):
    """admin 이 detective_kim 의 allowed_locations 에 '판교센터' 를 추가한 뒤
    detective_kim 이 판교센터에서 로그인하면 통과해야 한다."""
    # 1) admin 으로 판교센터 추가
    tok_admin, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok_admin

    target_id = _user_id(db, "detective_kim")
    code2, _ = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "강남서", "판교센터"]},
        token=tok_admin,
    )
    assert code2 == 200

    # 2) detective_kim 판교센터 로그인 → 통과 (이전엔 game)
    tok_user, code3, data = login_as("detective_kim", location="판교센터")
    assert code3 == 200 and tok_user, f"판교센터 로그인 통과해야 함: {data}"


# ─── J. audit 이벤트 ALLOWED_LOCATIONS_UPDATED 가 남는다 ───────
def test_audit_log_left(http, login_as, db):
    tok, code, _ = login_as("admin_lee", location="본청")
    assert code == 200 and tok

    target_id = _user_id(db, "officer_choi")
    code2, _ = http(
        "PUT", f"/api/admin/users/{target_id}/allowed_locations",
        body={"allowed_locations": ["본청", "동대문서", "은평서"]},
        token=tok,
    )
    assert code2 == 200

    row = db.execute(
        "SELECT details FROM audit_logs "
        "WHERE event_type='ALLOWED_LOCATIONS_UPDATED' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row, "ALLOWED_LOCATIONS_UPDATED audit 이벤트 없음"
    details = json.loads(row["details"]) if isinstance(row["details"], str) \
        else row["details"]
    assert details["target_user_id"] == target_id
    assert details["after"] == ["본청", "동대문서", "은평서"]
    assert details["actor_role"] == "admin"
