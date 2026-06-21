"""
위치 이상(비허용 위치 / impossible_travel) → 동시 로그인 정책과 통일된 처리 검증

배경:
  시뮬 패널에서 위치를 비허용 값으로 바꾸거나 물리적 이동 불가능한 위치로
  바꾸면, 그 세션은 동시 로그인 케이스와 같은 신뢰 보류 상태가 되어야 한다.
  구체적으로:
    - sessions.pending_reauth = TRUE 마킹
    - CONCURRENT_SESSION_LOCKED 감사 이벤트 + LOCATION_ANOMALY_LOCKED 보조 이벤트
    - decision.level == 5, decision.rule in
      ("LOCATION_NOT_ALLOWED", "IMPOSSIBLE_TRAVEL")
  → base_handler.require_auth() 가 후속 요청을 401 concurrent_session_detected
    로 끊어, OTP 재인증 모달이 그대로 떠야 한다 (별도 검증은 base_handler 단의
    기존 분기에 의존 — 코드 라인 192~203).

이 테스트는 DB 만 거치고 라이브 서버는 띄우지 않는다.
"""
from __future__ import annotations

import datetime

import pytest


def _make_session(db, user_id, *, location="본청", device_id="registered-001"):
    """테스트용 활성 세션 1개를 생성하고 id 반환."""
    expires = datetime.datetime.now(datetime.timezone.utc) + \
              datetime.timedelta(hours=1)
    row = db.execute(
        """
        INSERT INTO sessions
            (user_id, token, device_id, ip_address, location,
             expires_at, absolute_expires_at, idle_timeout_seconds,
             is_admin_gated)
        VALUES (?,?,?,?,?,?,?,?,?) RETURNING id
        """,
        (user_id, f"test-token-{user_id}", device_id, "127.0.0.1",
         location, expires, expires, 900, False)
    ).fetchone()
    db.commit()
    return int(row["id"] if isinstance(row, dict) or hasattr(row, "keys") else row[0])


def _seed_user_resource(db, *, location_allowed_only=("본청",)):
    """비허용 위치 케이스에 적합한 사용자/자원 한 쌍 픽업."""
    user = db.execute(
        "SELECT id, registered_devices FROM users "
        "WHERE username='officer_choi'"
    ).fetchone()
    res = db.execute(
        "SELECT id FROM resources WHERE sensitivity_grade>=2 LIMIT 1"
    ).fetchone()
    assert user is not None and res is not None
    return int(user["id"]), int(res["id"])


# ─── A. 비허용 위치 단독 → 세션 잠금 ──────────────────────────────
def test_unallowed_location_locks_session_pending_reauth(db):
    """시뮬 패널에서 비허용 위치로 바꾼 evaluate_access 호출이
    그 세션을 pending_reauth=TRUE 로 만들어야 한다."""
    from core.access_evaluator import evaluate_access

    user_id, res_id = _seed_user_resource(db)
    # officer_choi 의 allowed_locations 에 없는 임의의 비허용 위치
    sid = _make_session(db, user_id, location="본청")

    result = evaluate_access(
        user_id=user_id,
        resource_id=res_id,
        session_id=sid,
        device_id="registered-006",
        location="해외",     # 시뮬 패널의 '비허용' 옵션을 모사
        action_type="view",
    )

    # 결정: 즉시 차단
    assert result["decision"]["level"] == 5, (
        f"비허용 위치인데 차단이 아님: {result['decision']}"
    )
    assert result["decision"].get("rule") == "LOCATION_NOT_ALLOWED"

    # 세션이 pending_reauth=TRUE 로 잠겼는지
    row = db.execute(
        "SELECT pending_reauth, pending_reauth_at FROM sessions WHERE id=?",
        (sid,)
    ).fetchone()
    assert bool(row["pending_reauth"]) is True, (
        "비허용 위치 차단이 세션을 pending_reauth 로 잠그지 못함 — "
        "동시 로그인 정책과 결과 통일 실패"
    )
    assert row["pending_reauth_at"] is not None


# ─── B. impossible_travel → 세션 잠금 ────────────────────────────
def test_impossible_travel_locks_session_pending_reauth(db):
    """세션의 last_location_time 이 직전이고, 현재 위치가 멀리 떨어진 곳이면
    impossible_travel 이 감지되어 차단 + 세션 잠금."""
    from core.access_evaluator import evaluate_access

    user_id, res_id = _seed_user_resource(db)
    sid = _make_session(db, user_id, location="본청")

    # last_location='본청', last_location_time = 5분 전 → 부산은 같은 시간에 도달 불가
    db.execute(
        "UPDATE sessions SET last_location=?, last_location_time=? WHERE id=?",
        ("본청",
         datetime.datetime.now(datetime.timezone.utc) -
            datetime.timedelta(minutes=5),
         sid)
    )
    db.commit()

    # officer_choi 의 allowed_locations 가 '본청' 만이라 부산도 비허용일 수 있다.
    # 우리는 impossible_travel 분기를 명확히 검증하기 위해 allowed_locations 에
    # '지청-부산' 을 한시적으로 추가한다.
    db.execute(
        "UPDATE users SET allowed_locations = '[\"본청\", \"지청-부산\"]' "
        "WHERE id=?", (user_id,)
    )
    db.commit()

    result = evaluate_access(
        user_id=user_id,
        resource_id=res_id,
        session_id=sid,
        device_id="registered-006",
        location="지청-부산",
        action_type="view",
    )

    assert result["decision"]["level"] == 5, (
        f"impossible_travel 인데 차단되지 않음: {result['decision']}"
    )
    assert result["decision"].get("rule") == "IMPOSSIBLE_TRAVEL"

    row = db.execute(
        "SELECT pending_reauth FROM sessions WHERE id=?", (sid,)
    ).fetchone()
    assert bool(row["pending_reauth"]) is True, (
        "impossible_travel 차단이 세션을 잠그지 못함"
    )


# ─── C. 허용 위치는 영향 없음 (회귀 방지) ────────────────────────
def test_allowed_location_does_not_lock_session(db):
    """정상 허용 위치로 평가한 세션은 pending_reauth=FALSE 유지."""
    from core.access_evaluator import evaluate_access

    user_id, res_id = _seed_user_resource(db)
    sid = _make_session(db, user_id, location="본청")

    result = evaluate_access(
        user_id=user_id,
        resource_id=res_id,
        session_id=sid,
        device_id="registered-006",
        location="본청",
        action_type="view",
    )

    # 허용 위치인 만큼 LOCATION_NOT_ALLOWED 룰은 발동하면 안 됨
    rule = (result["decision"].get("rule") or "")
    assert rule != "LOCATION_NOT_ALLOWED"

    row = db.execute(
        "SELECT pending_reauth FROM sessions WHERE id=?", (sid,)
    ).fetchone()
    assert not bool(row["pending_reauth"]), (
        "정상 위치 접근이 세션을 잠금 — 회귀 결함"
    )


# ─── D. 감사 로그 흔적 ───────────────────────────────────────────
def test_lock_emits_concurrent_session_locked_audit(db):
    """동시 로그인 정책과 통일된 형태로 CONCURRENT_SESSION_LOCKED 이벤트가
    남아야 한다 (감사 분석에서 두 케이스를 같은 단서로 추적 가능)."""
    from core.access_evaluator import evaluate_access

    user_id, res_id = _seed_user_resource(db)
    sid = _make_session(db, user_id, location="본청")

    evaluate_access(
        user_id=user_id, resource_id=res_id, session_id=sid,
        device_id="registered-006", location="해외", action_type="view",
    )

    cnt_row = db.execute(
        "SELECT COUNT(*) AS c FROM audit_logs "
        "WHERE user_id=? AND event_type='CONCURRENT_SESSION_LOCKED'",
        (user_id,)
    ).fetchone()
    assert int(cnt_row["c"]) >= 1, "CONCURRENT_SESSION_LOCKED 감사 누락"

    loc_row = db.execute(
        "SELECT COUNT(*) AS c FROM audit_logs "
        "WHERE user_id=? AND event_type='LOCATION_ANOMALY_LOCKED'",
        (user_id,)
    ).fetchone()
    assert int(loc_row["c"]) >= 1, "LOCATION_ANOMALY_LOCKED 보조 감사 누락"
