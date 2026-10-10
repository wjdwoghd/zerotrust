"""일반 사건 API의 공개 상태와 행동 권한 일관성 회귀 테스트."""
from __future__ import annotations

import json

from security.mfa_service import generate_secret, generate_totp


def _assert_consistent(payload: dict) -> None:
    assert set(payload) in ({"request_id", "status", "external_message", "actions", "risk_score", "risk_axes"},
                            {"request_id", "status", "external_message", "actions", "resource", "risk_score", "risk_axes"})
    assert payload["risk_score"] is None or 0 <= payload["risk_score"] <= 100
    assert set(payload["risk_axes"]) == {
        "object_sensitivity", "environment_risk", "behavior_risk", "work_fitness",
    }
    assert all(isinstance(score, (int, float)) for score in payload["risk_axes"].values())
    status = payload["status"]
    actions = payload["actions"]
    assert set(actions) == {
        "can_view", "can_download", "can_copy", "can_print",
        "reauthenticate", "request_approval", "attempt_break_glass",
        "release_break_glass",
    }
    assert all(isinstance(value, bool) for value in actions.values())
    assert not actions["can_download"] or actions["can_view"]
    assert not actions["can_copy"] or actions["can_view"]
    assert not actions["can_print"] or actions["can_view"]
    if status == "ALLOW":
        assert actions["can_view"] is True
        assert not actions["reauthenticate"] and not actions["request_approval"]
    elif status == "VERIFY":
        assert actions["can_view"] is False
        assert actions["reauthenticate"] != actions["request_approval"]
    else:
        assert status == "DENY"
        assert actions["can_view"] is False
        assert not actions["reauthenticate"] and not actions["request_approval"]
    if "resource" in payload:
        if actions["can_view"]:
            assert "content" in payload["resource"]
        else:
            assert set(payload["resource"]) == {"id", "title"}


def _assign_case(db, username: str, resource_id: int) -> None:
    row = db.execute(
        "SELECT assigned_cases FROM users WHERE username=?",
        (username,),
    ).fetchone()
    assigned = row["assigned_cases"] or []
    if isinstance(assigned, str):
        assigned = json.loads(assigned)
    assigned = list(assigned or [])
    if resource_id not in [int(v) for v in assigned if str(v).isdigit()]:
        assigned.append(resource_id)
    db.execute(
        "UPDATE users SET assigned_cases=? WHERE username=?",
        (json.dumps(assigned), username),
    )
    db.commit()


def _seed_session_location(db, username: str, *, location: str = "본청") -> None:
    """테스트의 첫 접근을 위치 이력 부재 confidence 보정에서 분리한다."""
    db.execute(
        "UPDATE sessions "
        "SET last_location=?, last_location_time=now() "
        "WHERE user_id=(SELECT id FROM users WHERE username=?) "
        "  AND is_active=TRUE",
        (location, username),
    )
    db.commit()


def test_level1_assigned_resource_allows_file_download(http, login_as, db):
    """L1 완전허용이면 파일 다운로드 권한도 실제 다운로드 API와 일치해야."""
    tok, code, data = login_as("detective_kim")
    assert code == 200, data
    _seed_session_location(db, "detective_kim")

    rid = db.execute(
        "SELECT id FROM resources WHERE case_number='2026-ADM-0099'",
    ).fetchone()["id"]
    _assign_case(db, "detective_kim", rid)

    code, detail = http(
        "GET", f"/api/resources/cases/{rid}",
        token=tok, device="registered-001", location="본청",
    )
    assert code == 200, detail
    _assert_consistent(detail)
    assert detail["status"] == "ALLOW"
    assert detail["actions"]["can_download"] is True

    code, downloaded = http(
        "GET", f"/api/resources/cases/{rid}/file",
        token=tok, device="registered-001", location="본청",
    )
    assert code == 200, downloaded
    assert "2026-ADM-0099" in downloaded.get("_raw", "")


def test_realtime_status_moves_permissions_with_dynamic_score(http, login_as, db):
    """동적 점수 변화에도 공개 상태와 허용 행동은 일관되어야 한다."""
    tok, code, data = login_as("officer_choi")
    assert code == 200, data

    user_id = db.execute(
        "SELECT id FROM users WHERE username='officer_choi'",
    ).fetchone()["id"]
    rid = db.execute(
        "SELECT id FROM resources WHERE case_number='2026-PTR-0001'",
    ).fetchone()["id"]

    code, before = http(
        "GET", f"/api/resources/cases/{rid}/status",
        token=tok, device="registered-006", location="본청",
    )
    assert code == 200, before
    _assert_consistent(before)

    for _ in range(10):
        db.execute(
            "INSERT INTO access_logs "
            "(user_id, resource_id, decision_label, decision_level, action_type, created_at) "
            "VALUES (?, ?, 'ALLOW', 1, 'view', NOW())",
            (user_id, rid),
        )
    db.commit()

    code, after = http(
        "GET", f"/api/resources/cases/{rid}/status",
        token=tok, device="registered-006", location="본청",
    )
    assert code == 200, after
    _assert_consistent(after)
    assert after["actions"]["can_view"] <= before["actions"]["can_view"]
    assert after["actions"]["can_download"] <= before["actions"]["can_download"]


def test_all_seed_accounts_all_documents_have_consistent_status(http, login_as, db):
    """7개 시드 계정 x 전체 문서의 공개 상태·행동권한 일치."""
    accounts = {
        "detective_kim": "registered-001",
        "investigator_park": "registered-003",
        "admin_lee": "registered-004",
        "officer_choi": "registered-006",
        "patrol_jung": "registered-007",
        "deputy_han": "registered-008",
        "deputy_oh": "registered-009",
    }

    # patrol_jung 은 로그인 승인 게이트/비허용 위치 시연 계정이다. 이 회귀
    # 테스트는 접근 매트릭스 자체를 보려는 목적이므로 테스트 안에서만 정상화한다.
    db.execute(
        "UPDATE users SET trust_score=70, violation_count=0, "
        "allowed_locations='[\"본청\"]' "
        "WHERE username='patrol_jung'"
    )
    patrol_secret = generate_secret()
    db.execute(
        """
        INSERT INTO user_devices
            (user_id, device_id, device_name, device_type, mfa_secret, api_key)
        SELECT id, 'token-005', 'patrol_jung 테스트 토큰 기기',
               'totp_token', ?, NULL
          FROM users
         WHERE username='patrol_jung'
        """,
        (patrol_secret,)
    )
    db.commit()

    resource_ids = [
        int(r["id"])
        for r in db.execute("SELECT id FROM resources ORDER BY id").fetchall()
    ]
    assert resource_ids, "seed resources missing"

    for username, device_id in accounts.items():
        otp_code = generate_totp(patrol_secret) if username == "patrol_jung" else None
        tok, code, data = login_as(
            username, device_id=device_id, location="본청", otp_code=otp_code
        )
        assert code == 200, {"username": username, "response": data}

        for rid in resource_ids:
            code, payload = http(
                "GET", f"/api/resources/cases/{rid}/status",
                token=tok, device=device_id, location="본청",
            )
            assert code == 200, {
                "username": username,
                "resource_id": rid,
                "response": payload,
            }
            _assert_consistent(payload)
