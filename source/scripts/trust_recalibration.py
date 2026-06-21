#!/usr/bin/env python3
"""
주기적 trust_score 자연 감쇠 / 회복 (cron 후보).

권장 cron: 매주 1회 (예: 일요일 03:00).

동작:
  - 최근 7일 내 활동 + 위반 0 + 잠금 없음 사용자: trust +1 (회복, 100 상한)
  - 최근 30일 무활동 사용자: trust *= 0.95 (stale 감쇠)
  - 변경 결과는 operation_logs 에 TRUST_RECALIBRATED 이벤트로 기록.

근거:
  trust_score 가 정적이면 한번 정해진 값이 stale 됨. 클린 사용자는 회복,
  휴면 사용자는 자동 의심도 ↑ — "시간 변화에 무대응" 결함 보완.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database import get_db  # noqa: E402


def recalibrate() -> dict:
    """trust 회복 + 감쇠 1회 적용. 영향 받은 행 수 반환."""
    db = get_db()
    try:
        # 019: trust_changes timeline — recover/decay 두 단계 각각 SET LOCAL
        # 으로 컨텍스트 전달. trg_track_trust_change 가 사용자별 변동 자동 INSERT.

        # 1) 활성 클린 사용자 trust +1
        db.execute("SELECT set_config('app.trust_reason', 'recalibration_recover', true)")
        recovered = db.execute("""
            UPDATE users
               SET trust_score = LEAST(100, trust_score + 1)
             WHERE failed_login_count = 0
               AND violation_count = 0
               AND is_locked = FALSE
               AND is_active = TRUE
               AND id IN (
                   SELECT DISTINCT user_id FROM access_logs
                    WHERE created_at > NOW() - INTERVAL '7 days'
                      AND user_id IS NOT NULL
               )
               AND trust_score < 100
        """)
        recovered_count = (
            recovered._raw.rowcount
            if hasattr(recovered, "_raw") else 0
        )

        # 2) 30일 무활동 사용자 stale 감쇠 (5%)
        db.execute("SELECT set_config('app.trust_reason', 'recalibration_decay', true)")
        decayed = db.execute("""
            UPDATE users
               SET trust_score = trust_score * 0.95
             WHERE is_active = TRUE
               AND id NOT IN (
                   SELECT DISTINCT user_id FROM access_logs
                    WHERE created_at > NOW() - INTERVAL '30 days'
                      AND user_id IS NOT NULL
               )
               AND trust_score > 10
        """)
        decayed_count = (
            decayed._raw.rowcount
            if hasattr(decayed, "_raw") else 0
        )

        # 3) audit 기록
        db.execute(
            "INSERT INTO operation_logs (event_type, details, user_id) "
            "VALUES (?, ?, ?)",
            (
                "TRUST_RECALIBRATED",
                json.dumps({
                    "recovered": recovered_count,
                    "decayed": decayed_count,
                }, ensure_ascii=False),
                None,
            ),
        )
        db.commit()
    finally:
        db.close()

    return {"recovered": recovered_count, "decayed": decayed_count}


def main() -> int:
    result = recalibrate()
    print(f"[trust_recalibration] recovered={result['recovered']} "
          f"decayed={result['decayed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
