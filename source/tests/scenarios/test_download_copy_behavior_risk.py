"""다운로드·복사 시도 위험도의 실제 HTTP/격리 PostgreSQL 회귀 시나리오."""
from __future__ import annotations

import json


def _case_id(db, number):
    return db.execute(
        "SELECT id FROM resources WHERE case_number=?", (number,),
    ).fetchone()["id"]


def _assigned(db, user_id, resource_id):
    row = db.execute(
        "SELECT assigned_cases FROM users WHERE id=?", (user_id,),
    ).fetchone()
    cases = row["assigned_cases"] or []
    if isinstance(cases, str):
        cases = json.loads(cases)
    db.execute(
        "UPDATE users SET assigned_cases=? WHERE id=?",
        (json.dumps([*cases, resource_id]), user_id),
    )
    db.commit()


def _status(http, token, resource_id):
    code, data = http(
        "GET", f"/api/resources/cases/{resource_id}/status",
        token=token, device="registered-001", location="본청", sim_hour=14,
    )
    assert code == 200, data
    assert "content" not in data["resource"]
    return data


def _score(payload):
    decision = payload["decision"]
    score = decision["risk_score"]
    assert decision["display_risk_score"] == score
    assert decision["raw_risk_score"] == score
    assert payload["scoring"]["total"]["total_risk_score"] == score
    assert payload["scoring"]["total"]["score_level"] == decision["score_level"]
    assert payload["scoring"]["total"]["decision_level"] == decision["level"]
    return score


def test_allowed_attempts_count_once_from_next_request_and_expire(http, login_as, db):
    """현재 시도 제외, 유형별 1회, L1/L2 경계, 폴링, 5분 만료를 확인한다."""
    token, code, data = login_as("detective_kim")
    assert code == 200, data
    user_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'",
    ).fetchone()["id"]
    resource_id = _case_id(db, "2026-ADM-0099")
    _assigned(db, user_id, resource_id)
    path = f"/api/resources/cases/{resource_id}"
    kwargs = {"token": token, "device": "registered-001",
              "location": "본청", "sim_hour": 14}

    before = _status(http, token, resource_id)
    base_score = _score(before)
    assert before["decision"]["level"] == 1

    code, file_response = http("GET", path + "/file", **kwargs)
    assert code == 200, file_response
    assert "2026-ADM-0099" in file_response["_raw"]
    first_log = db.execute(
        "SELECT risk_score FROM access_logs WHERE user_id=? AND action_type='download'",
        (user_id,),
    ).fetchone()
    assert float(first_log["risk_score"]) == base_score

    after_download = _status(http, token, resource_id)
    assert _score(after_download) == base_score + 20
    assert after_download["decision"]["can_copy"] is True

    code, copied = http("POST", path + "/copy", **kwargs)
    assert code == 200, copied
    assert "2026-ADM-0099" in copied["content"]
    after_copy = _status(http, token, resource_id)
    assert _score(after_copy) == base_score + 40
    assert after_copy["decision"]["score_level"] == 2
    assert after_copy["decision"]["level"] == 2
    assert after_copy["decision"]["can_copy"] is False
    assert after_copy["decision"]["can_download"] is False

    code, denied_copy = http("POST", path + "/copy", **kwargs)
    assert code == 403, denied_copy
    assert denied_copy["code"] == "copy_not_allowed"
    assert "content" not in denied_copy
    assert "2026-ADM-0099" not in str(denied_copy)
    code, denied_file = http("GET", path + "/file", **kwargs)
    assert code == 403, denied_file
    assert denied_file["code"] == "download_not_allowed"
    assert _score(_status(http, token, resource_id)) == base_score + 40

    count = db.execute(
        "SELECT COUNT(*) AS n FROM access_logs WHERE user_id=?", (user_id,),
    ).fetchone()["n"]
    assert count == 4
    for _ in range(3):
        assert _score(_status(http, token, resource_id)) == base_score + 40
    assert db.execute(
        "SELECT COUNT(*) AS n FROM access_logs WHERE user_id=?", (user_id,),
    ).fetchone()["n"] == count

    db.execute(
        "UPDATE access_logs SET created_at=CURRENT_TIMESTAMP - INTERVAL '301 seconds' "
        "WHERE user_id=?", (user_id,),
    )
    db.commit()
    expired = _status(http, token, resource_id)
    assert _score(expired) == base_score
    assert expired["decision"]["level"] == 1
    assert expired["decision"]["can_copy"] is True


def test_denied_attempts_and_approval_keep_score_and_final_level_distinct(
        http, login_as, db):
    """정책 거부도 다음 평가에 반영하고 승인 예외는 원 점수를 보존한다."""
    token, code, data = login_as("detective_kim")
    assert code == 200, data
    resource_id = _case_id(db, "2026-ADM-0200")
    path = f"/api/resources/cases/{resource_id}"
    kwargs = {"token": token, "device": "registered-001",
              "location": "본청", "sim_hour": 14}
    before = _status(http, token, resource_id)
    base_score = _score(before)
    assert before["decision"]["level"] >= 4

    code, denied_file = http("GET", path + "/file", **kwargs)
    assert code == 403, denied_file
    assert denied_file["code"] == "download_not_allowed"
    assert _score(denied_file) == base_score
    assert _score(_status(http, token, resource_id)) == base_score + 20

    code, denied_copy = http("POST", path + "/copy", **kwargs)
    assert code == 403, denied_copy
    assert denied_copy["code"] == "copy_not_allowed"
    assert "content" not in denied_copy
    after = _status(http, token, resource_id)
    assert _score(after) == base_score + 40
    assert after["decision"]["level"] >= 4

    user_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'",
    ).fetchone()["id"]
    types = db.execute(
        "SELECT action_type, COUNT(*) AS n FROM access_logs WHERE user_id=? "
        "GROUP BY action_type ORDER BY action_type", (user_id,),
    ).fetchall()
    assert [(r["action_type"], r["n"]) for r in types] == [
        ("copy", 1), ("download", 1),
    ]

    # 승인 결과는 접근 레벨만 바꿔야 하며, 그 시점의 총점/점수 레벨은 보존한다.
    admin_id = db.execute(
        "SELECT id FROM users WHERE username='admin_lee'",
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO approvals (requester_id, resource_id, approver_id, "
        "reason, status, resolved_at, download_allowed) "
        "VALUES (?, ?, ?, '격리 테스트 승인', 'approved', CURRENT_TIMESTAMP, TRUE)",
        (user_id, resource_id, admin_id),
    )
    db.commit()
    approved = _status(http, token, resource_id)
    assert _score(approved) <= _score(after)
    assert approved["decision"]["score_level"] > 1
    assert approved["decision"]["level"] == 1
    assert approved["decision"]["override"]["type"] == "ADMIN_APPROVAL_GRANTED"
    assert approved["decision"]["can_download"] is True
    assert approved["decision"]["can_copy"] is True
