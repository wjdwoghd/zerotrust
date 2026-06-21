"""접근 점수 - 레벨 - 행동 권한 일관성 회귀 테스트."""
from __future__ import annotations

import json

from core.decision_engine import get_action_permissions, get_score_band_for_level
from security.mfa_service import generate_secret, generate_totp


def _assert_consistent(payload: dict) -> None:
    decision = payload.get("decision") or {}
    resource = payload.get("resource") or {}
    scoring = payload.get("scoring") or {}
    level = int(decision.get("level", 5) or 5)
    score_level = int(decision.get("score_level", level) or level)
    override = decision.get("override")
    expected_permissions = get_action_permissions(level)

    score = float(decision.get("display_risk_score", decision.get("risk_score", 0)) or 0)
    lo, hi = get_score_band_for_level(score_level)
    assert lo <= score <= hi, (
        f"score-level mismatch: score_level={score_level}, score={score}, band=({lo}, {hi}), "
        f"decision={decision}"
    )
    assert float(decision.get("risk_score", score)) == score
    assert decision.get("display_risk_score") == score
    if not override:
        assert level == score_level, f"non-override level mismatch: {decision}"

    assert decision.get("action_permissions") == expected_permissions
    for key, expected in expected_permissions.items():
        assert decision.get(key) is expected, f"decision {key} mismatch: {decision}"
        if resource:
            assert resource.get(key) is expected, f"resource {key} mismatch: {resource}"

    if resource:
        assert int(resource.get("masking_level", level) or level) == level

    total = scoring.get("total") or {}
    if total:
        assert float(total.get("total_risk_score", score)) == score
        assert int(total.get("score_level", score_level) or score_level) == score_level
        assert int(total.get("decision_level", level) or level) == level
        assert total.get("action_permissions") == expected_permissions


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
    assert detail["decision"]["level"] == 1
    assert detail["resource"]["can_download"] is True

    code, downloaded = http(
        "GET", f"/api/resources/cases/{rid}/file",
        token=tok, device="registered-001", location="본청",
    )
    assert code == 200, downloaded
    assert "2026-ADM-0099" in downloaded.get("_raw", "")


def test_realtime_status_moves_permissions_with_dynamic_score(http, login_as, db):
    """동적 점수 변화에도 status 의 점수/레벨/행동권한은 한 매트릭스를 따라야."""
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
    assert after["decision"]["level"] >= before["decision"]["level"]


def test_all_seed_accounts_all_documents_have_consistent_status(http, login_as, db):
    """7개 시드 계정 x 전체 문서의 표시점수/레벨/행동권한 밴드 일치."""
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
