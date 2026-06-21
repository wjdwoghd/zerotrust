"""
Day 3-4 시나리오 — 결정 사후 라벨 + trust 양방향 자동 조정.

검증:
  1) admin 라벨 false_positive → 사용자 trust +5
  2) admin 라벨 false_negative → trust -10, violation +1
  3) admin 라벨 justified → 변동 없음
  4) 비-admin 사용자가 review 엔드포인트 접근 → 403
  5) 본인 결정 본인이 라벨 시도 → SELF_ACTION_BLOCKED
  6) trust_recalibration.py 의 회복/감쇠 동작
"""
from __future__ import annotations

import pytest


def _create_access_log(db, user_id: int, decision_label: str = "ALLOW",
                      level: int = 2) -> int:
    """access_logs 한 행 INSERT 후 id 반환."""
    row = db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type) "
        "VALUES (?, ?, ?, ?, ?) RETURNING id",
        (user_id, 1, decision_label, level, "view"),
    ).fetchone()
    db.commit()
    return row["id"]


# ─── 1. False Positive 라벨 → trust +5 ──────────────────────────
def test_false_positive_review_recovers_trust(http, login_as, db):
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    pre_trust = float(db.execute(
        "SELECT trust_score FROM users WHERE id=?", (target_id,)
    ).fetchone()["trust_score"])

    log_id = _create_access_log(db, target_id, "REAUTH", 3)

    # 다른 admin 이 라벨 (자기-라벨이 아니어야 함)
    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={
            "label": "false_positive",
            "notes": "정당한 접근이었음",
        },
    )
    assert code == 200, data

    post_trust = float(db.execute(
        "SELECT trust_score FROM users WHERE id=?", (target_id,)
    ).fetchone()["trust_score"])
    assert post_trust == min(100, pre_trust + 5), (
        f"FP 라벨 후 trust 회복 기대: {pre_trust} → {pre_trust + 5}, "
        f"실제 {post_trust}"
    )


# ─── 2. False Negative 라벨 → trust -10, violation +1 ───────────
def test_false_negative_review_penalizes(http, login_as, db):
    target_id = db.execute(
        "SELECT id FROM users WHERE username='investigator_park'"
    ).fetchone()["id"]
    pre = db.execute(
        "SELECT trust_score, violation_count FROM users WHERE id=?",
        (target_id,),
    ).fetchone()
    pre_trust = float(pre["trust_score"])
    pre_violation = int(pre["violation_count"])

    log_id = _create_access_log(db, target_id, "ALLOW", 2)

    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "false_negative", "notes": "의심됨"},
    )
    assert code == 200, data

    post = db.execute(
        "SELECT trust_score, violation_count FROM users WHERE id=?",
        (target_id,),
    ).fetchone()
    assert float(post["trust_score"]) == max(0, pre_trust - 10)
    assert int(post["violation_count"]) == pre_violation + 1


# ─── 3. Justified 라벨 → 변동 없음 ──────────────────────────────
def test_justified_review_no_change(http, login_as, db):
    target_id = db.execute(
        "SELECT id FROM users WHERE username='officer_choi'"
    ).fetchone()["id"]
    pre = db.execute(
        "SELECT trust_score, violation_count FROM users WHERE id=?",
        (target_id,),
    ).fetchone()
    log_id = _create_access_log(db, target_id, "ALLOW", 2)

    tok_admin, _, _ = login_as("admin_lee")
    code, _ = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "justified", "notes": "정상"},
    )
    assert code == 200

    post = db.execute(
        "SELECT trust_score, violation_count FROM users WHERE id=?",
        (target_id,),
    ).fetchone()
    assert float(post["trust_score"]) == float(pre["trust_score"])
    assert int(post["violation_count"]) == int(pre["violation_count"])


# ─── 4. 비-admin 접근 → 403 ─────────────────────────────────────
def test_non_admin_cannot_review(http, login_as, db):
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    log_id = _create_access_log(db, target_id, "ALLOW", 2)

    tok_user, _, _ = login_as("officer_choi")
    code, _ = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_user, body={"label": "false_positive"},
    )
    assert code == 403


# ─── 5. 본인이 자기 결정 라벨 → SELF_ACTION_BLOCKED ─────────────
def test_self_review_blocked(http, login_as, db):
    admin_id = db.execute(
        "SELECT id FROM users WHERE username='admin_lee'"
    ).fetchone()["id"]
    log_id = _create_access_log(db, admin_id, "ALLOW", 2)

    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "false_positive"},
    )
    assert code == 403
    assert data.get("code") == "self_action_blocked"


# ─── 6. 잘못된 label 거부 ───────────────────────────────────────
def test_invalid_label_rejected(http, login_as, db):
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    log_id = _create_access_log(db, target_id, "ALLOW", 2)

    tok_admin, _, _ = login_as("admin_lee")
    code, data = http(
        "POST", f"/api/admin/access-logs/{log_id}/review",
        token=tok_admin, body={"label": "garbage_value"},
    )
    assert code == 400
    assert data.get("code") == "invalid_label"


# ─── 7. trust_recalibration 회복 동작 ──────────────────────────
def test_trust_recalibration_recovers_active_clean_user(db):
    """최근 활동 + violation=0 + 잠금 없음 → trust +1."""
    # 사용자 trust 를 인위적으로 낮춤
    db.execute(
        "UPDATE users SET trust_score=70 WHERE username='detective_kim'"
    )
    # 가짜 access_log 한 줄 (최근 활동 시뮬)
    target_id = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO access_logs (user_id, resource_id, decision_label, "
        "decision_level, action_type, created_at) "
        "VALUES (?, 1, 'ALLOW', 2, 'view', NOW())",
        (target_id,)
    )
    db.commit()

    from scripts.trust_recalibration import recalibrate
    result = recalibrate()
    assert result["recovered"] >= 1

    new_trust = float(db.execute(
        "SELECT trust_score FROM users WHERE id=?", (target_id,)
    ).fetchone()["trust_score"])
    assert new_trust == 71, f"기대 71, 실제 {new_trust}"


# ─── 8. trust_recalibration 감쇠 동작 ──────────────────────────
def test_trust_recalibration_decays_stale_user(db):
    """30일 무활동 → trust *0.95."""
    # patrol_jung 은 시드에서 trust=40. 무활동이면 감쇠.
    pre = float(db.execute(
        "SELECT trust_score FROM users WHERE username='patrol_jung'"
    ).fetchone()["trust_score"])

    from scripts.trust_recalibration import recalibrate
    result = recalibrate()
    # 시드 직후엔 access_logs 가 없으므로 patrol_jung 도 stale 로 분류 → 감쇠
    assert result["decayed"] >= 1

    post = float(db.execute(
        "SELECT trust_score FROM users WHERE username='patrol_jung'"
    ).fetchone()["trust_score"])
    assert post < pre, f"감쇠 기대: {pre} → 더 낮음, 실제 {post}"
