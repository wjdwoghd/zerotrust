#!/usr/bin/env python3
"""
사용 흔적 청소 (재실행 / 발표 리허설용)

운영 모드 재기동 시 이전 세션 동안 쌓인 모든 사용 흔적을 비운다.

청소 대상:
  - 접근 로그 (access_logs)
  - 감사 / 운영 / 민감 로그 (audit_logs / operation_logs / sensitive_logs)
  - 세션 / OTP 요청 / 승인 요청 / Break-Glass 발동 이력
  - 시드 외 사용자 (관리자가 만든 신규 계정 포함)
  - 시드 외 또는 시드 사용자가 추가 등록한 토큰/업무 기기
  - 자원(resources) — 시연 본문 갱신을 위해 같이 비움

보존 대상:
  - 스키마 자체와 schema_migrations (마이그레이션 적용 이력)

이후 `init_data.py` 가 시드를 재삽입하는 흐름이 전제다. wipe 직후엔 모든
운영 데이터 테이블이 비어있으므로 시드 함수는 항상 INSERT 분기로 진입한다.

빈 DB(첫 실행) 에서는 TRUNCATE 가 no-op 이라 호출 비용이 사실상 0이다.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database import get_db  # noqa: E402


# 비울 테이블 — TRUNCATE … CASCADE 가 FK 의존을 자동 해소한다.
# 명시적으로 나열하는 이유:
#   1) RESTART IDENTITY 가 빠뜨리지 않도록
#   2) 의도하지 않은 테이블이 CASCADE 로 휩쓸리지 않도록 (스키마 변경 회귀
#      방지 — 새 테이블이 추가되면 여기 한 줄도 같이 추가)
_TABLES_TO_WIPE = (
    "sensitive_logs",
    "audit_logs",
    "operation_logs",
    "access_logs",
    "otp_requests",
    "sessions",
    "break_glass_activations",
    "login_approval_requests",
    "policy_override_requests",
    "approvals",
    "user_devices",
    "users",
    "resources",
)


def main() -> int:
    conn = get_db()
    raw = conn._raw  # psycopg2 raw connection (트리거 토글에 필요)
    cur = raw.cursor()
    try:
        # audit_logs 의 append-only 트리거가 TRUNCATE 도 차단할 수 있으므로
        # 사용자 정의 트리거만 잠시 비활성. (FK / 시스템 트리거는 그대로.)
        cur.execute("ALTER TABLE audit_logs DISABLE TRIGGER USER")
        cur.execute(
            "TRUNCATE TABLE "
            + ", ".join(_TABLES_TO_WIPE)
            + " RESTART IDENTITY CASCADE"
        )
        cur.execute("ALTER TABLE audit_logs ENABLE TRIGGER USER")
        raw.commit()
        print(f"[wipe] truncated {len(_TABLES_TO_WIPE)} table(s) - "
              "ready for fresh seed.")
        return 0
    except Exception as e:
        # 실패 경로에서도 트리거를 다시 켜 두려고 시도
        try:
            cur.execute("ALTER TABLE audit_logs ENABLE TRIGGER USER")
            raw.commit()
        except Exception:
            pass
        print(f"[wipe] FAILED: {e}", file=sys.stderr)
        try:
            raw.rollback()
        except Exception:
            pass
        return 1
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
