#!/usr/bin/env python3
"""
production 첫 관리자 부트스트랩 스크립트 (L1-4)

용도:
  빈 운영 DB 에서 로그인 가능한 최초 관리자 1명과 그의 업무 기기·토큰 기기를
  한 번에 생성한다. `init_data.py seed()` 와 달리 데모 계정(password123)을
  심지 않는다.

필요 환경변수 (필수):
  ADMIN_USERNAME    최초 관리자 username
  ADMIN_PASSWORD    최초 관리자 평문 비밀번호 (32자 이상 권장, 스크립트 종료 후 변경 권장)

선택 환경변수:
  ADMIN_NAME        표시 이름 (기본 "시스템 관리자")
  ADMIN_DEPT        소속 부서 (기본 "정보보안과")
  ADMIN_RANK        계급 (기본 "관리자")
  ADMIN_WORK_DEVICE_ID  초기 업무 기기 device_id (기본 "work-admin-001")
  ADMIN_LOCATION    기본 허용 위치 (기본 "본청", 콤마 구분 복수 가능)

동작:
  1. DB 에 이미 사용자가 있으면 아무것도 하지 않고 exit 0 (idempotent)
  2. 관리자 row INSERT (role='admin', job_scope=모든 카테고리)
  3. 관리자 업무 기기(device_type='work') INSERT
  4. 관리자 토큰 기기(device_type='totp_token') INSERT + api_key 생성
  5. 표준 출력에 device_id / api_key / 토큰 앱 실행 커맨드 1회 출력
     → 이 출력은 로그에 남지 않도록 주의, 복사 즉시 화면 지울 것.

사용 예 (운영):
  ADMIN_USERNAME=sec_admin ADMIN_PASSWORD='<32자 이상>' \\
      python3 scripts/bootstrap_admin.py
"""
from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database import get_db  # noqa: E402
from security.password_handler import hash_password  # noqa: E402
from security.mfa_service import generate_secret  # noqa: E402


# 관리자는 모든 직무 카테고리를 커버한다 (init_data.seed() 와 동일한 목록).
_ADMIN_JOB_SCOPE = [
    "infosec", "audit", "violent_crime", "drug", "organized_crime",
    "cyber", "forensic", "traffic", "national_security", "patrol",
]


def _require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        print(f"[bootstrap_admin] FATAL: 환경변수 {name} 이 필요합니다.",
              file=sys.stderr)
        sys.exit(2)
    return v


def main() -> int:
    username = _require_env("ADMIN_USERNAME")
    password = _require_env("ADMIN_PASSWORD")

    # 캡스톤 발표 시드(password123, 11자) 와 일치시키기 위해 11자로 완화.
    # 실 운영 환경에서는 12자 이상으로 다시 상향 권장.
    if len(password) < 11:
        print("[bootstrap_admin] FATAL: ADMIN_PASSWORD 는 최소 11자 이상이어야 합니다.",
              file=sys.stderr)
        return 2

    name = os.environ.get("ADMIN_NAME", "시스템 관리자")
    dept = os.environ.get("ADMIN_DEPT", "정보보안과")
    rank = os.environ.get("ADMIN_RANK", "관리자")
    work_device_id = os.environ.get("ADMIN_WORK_DEVICE_ID", "work-admin-001")
    locations = [
        s.strip() for s in os.environ.get("ADMIN_LOCATION", "본청").split(",")
        if s.strip()
    ]

    db = get_db()
    try:
        # 이미 사용자가 있으면 skip — 실수로 두 번 돌려도 안전하게.
        existing = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        existing_count = existing["c"] if hasattr(existing, "__getitem__") else existing[0]
        if existing_count and int(existing_count) > 0:
            print(f"[bootstrap_admin] skip — users 테이블에 이미 {existing_count}명이 있습니다.")
            return 0

        # 1) 관리자 사용자
        pw_hash = hash_password(password)
        db.execute(
            """
            INSERT INTO users
                (username, password_hash, name, department, rank, role,
                 registered_devices, allowed_locations, assigned_cases,
                 job_scope,
                 mfa_secret, trust_score, violation_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                username, pw_hash, name, dept, rank, "admin",
                json.dumps([work_device_id]),
                json.dumps(locations),
                json.dumps([]),
                json.dumps(_ADMIN_JOB_SCOPE),
                generate_secret(), 95.0, 0,
            ),
        )
        db.commit()

        row = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()
        user_id = row["id"] if hasattr(row, "__getitem__") else row[0]

        # 2) 업무 기기 (work) — MFA 검증에는 쓰이지 않지만 로그인 화이트리스트에 필요
        db.execute(
            """
            INSERT INTO user_devices
                (user_id, device_id, device_name, device_type, mfa_secret, api_key)
            VALUES (?,?,?,?,?,?)
            """,
            (user_id, work_device_id, f"{username} 업무 PC", "work", None, None),
        )

        # 3) 토큰 기기 (totp_token) — Tkinter 앱이 api_key 로 폴링
        token_device_id = f"token-admin-{secrets.token_hex(3)}"
        token_mfa_secret = generate_secret()
        token_api_key = secrets.token_hex(24)
        db.execute(
            """
            INSERT INTO user_devices
                (user_id, device_id, device_name, device_type, mfa_secret, api_key)
            VALUES (?,?,?,?,?,?)
            """,
            (user_id, token_device_id, f"{username} 토큰 기기",
             "totp_token", token_mfa_secret, token_api_key),
        )

        # 감사: 관리자 부트스트랩 사실을 audit_logs 에 남김. append-only 트리거가
        # 걸려 있는 운영 환경에서도 INSERT 는 허용되므로 그대로 기록된다.
        db.execute(
            """
            INSERT INTO audit_logs (layer, event_type, details, user_id)
            VALUES (?,?,?,?)
            """,
            (
                "operation",
                "ADMIN_BOOTSTRAPPED",
                json.dumps(
                    {
                        "username": username,
                        "department": dept,
                        "work_device_id": work_device_id,
                        "token_device_id": token_device_id,
                    },
                    ensure_ascii=False,
                ),
                user_id,
            ),
        )
        db.commit()
    finally:
        db.close()

    # 출력 — api_key 는 이 순간이 유일한 평문 노출 기회.
    print()
    print("=" * 64)
    print(" 관리자 부트스트랩 완료")
    print("=" * 64)
    print(f"  username        : {username}")
    print(f"  department      : {dept}")
    print(f"  work_device_id  : {work_device_id}")
    print(f"  token_device_id : {token_device_id}")
    print(f"  api_key         : {token_api_key}")
    print()
    print("토큰 앱 실행 커맨드 (이 api_key 는 이 출력 이후 다시 볼 수 없습니다):")
    print(
        f"  python apps/virtual_device.py --account {username} "
        f"--device-id {token_device_id} \\"
    )
    print(
        f"      --api-key {token_api_key} --base-url http://127.0.0.1:8000"
    )
    print()
    print("다음 단계:")
    print(
        "  1. 위 api_key 를 안전한 비밀 저장소에 보관하고 화면을 지우세요."
    )
    print(
        "  2. 웹 UI 로그인 → '📱 기기 설정' 에서 실제 운영 기기를 추가 등록하세요."
    )
    print(
        "  3. 필요 시 ADMIN_PASSWORD 를 변경하고 bootstrap_admin 은 더 이상 실행하지 마세요."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
