"""
core/anomaly_service.py — TZ 함정 회귀 테스트 (ITEM 9).

기존엔 time.localtime(time.time()-300) 으로 만든 naive 로컬 TZ 문자열을
PG TIMESTAMPTZ 와 비교했다. 서버 KST + PG 세션 UTC 인 환경에서는 cutoff
가 9시간 미래로 해석되어 모든 행이 cutoff 이전이 되고 카운트가 항상 0.

수정 후: SQL 측 CURRENT_TIMESTAMP - INTERVAL 으로 cutoff 를 계산하므로
TZ 와 무관하게 정확.
"""
from __future__ import annotations


def test_recent_access_count_excludes_old_rows(db):
    """5분 윈도우 안의 행만 카운트되는지 — TZ 함정이 있다면 0 반환됨."""
    from core.anomaly_service import get_recent_access_count

    det = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()
    user_id = det["id"]

    # 1) 윈도우 안: NOW-60s 시점에 access_log 1건
    db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type, "
        " created_at) "
        "VALUES (?, 1, 'ALLOW', 2, 'view', "
        "        CURRENT_TIMESTAMP - INTERVAL '60 seconds')",
        (user_id,)
    )
    # 2) 윈도우 밖: NOW-10m 시점에 access_log 1건
    db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type, "
        " created_at) "
        "VALUES (?, 1, 'ALLOW', 2, 'view', "
        "        CURRENT_TIMESTAMP - INTERVAL '10 minutes')",
        (user_id,)
    )
    db.commit()

    cnt = get_recent_access_count(user_id, window_seconds=300)
    # 윈도우 안 1건만 카운트. TZ 함정이면 0 으로 빠짐.
    assert cnt == 1, (
        f"5분 윈도우 안 행 1개를 못 잡음 — cnt={cnt}. "
        "TZ 함정 (cutoff 9h 어긋남) 회귀 가능성."
    )


def test_recent_access_count_zero_when_no_rows(db):
    """윈도우 안에 행이 없으면 0 — fail-closed 검증."""
    from core.anomaly_service import get_recent_access_count

    # admin_lee 는 시드 직후 access_logs 가 없음
    adm = db.execute(
        "SELECT id FROM users WHERE username='admin_lee'"
    ).fetchone()
    cnt = get_recent_access_count(adm["id"], window_seconds=300)
    assert cnt == 0, f"빈 카운트 기대, got {cnt}"


def test_recent_access_count_window_boundary(db):
    """window=10s 로 좁히면 60s 전 행이 빠지는지 — 윈도우 동작 검증."""
    from core.anomaly_service import get_recent_access_count

    det = db.execute(
        "SELECT id FROM users WHERE username='detective_kim'"
    ).fetchone()
    user_id = det["id"]

    db.execute(
        "INSERT INTO access_logs "
        "(user_id, resource_id, decision_label, decision_level, action_type, "
        " created_at) "
        "VALUES (?, 1, 'ALLOW', 2, 'view', "
        "        CURRENT_TIMESTAMP - INTERVAL '60 seconds')",
        (user_id,)
    )
    db.commit()

    # 10초 윈도우 → 60s 전 행은 제외
    cnt_narrow = get_recent_access_count(user_id, window_seconds=10)
    # 300초 윈도우 → 60s 전 행 포함
    cnt_wide = get_recent_access_count(user_id, window_seconds=300)
    assert cnt_narrow == 0, f"10s 윈도우에 60s 전 행이 잡힘: {cnt_narrow}"
    assert cnt_wide == 1, f"300s 윈도우에 60s 전 행이 빠짐: {cnt_wide}"
