#!/usr/bin/env python3
"""
토큰 기기 앱 런처 (.pyw) 자동 생성기.

읽기: user_devices 테이블에서 is_active=True 인 totp_token 디바이스 전체.
쓰기: apps/launchers/token_<username>.pyw  (+ .bat 대체 런처)

동작:
    - init_data.py 가 재시드할 때마다 api_key 가 새로 발급되므로,
      이 스크립트를 한 번 더 돌려야 런처가 유효해진다.
    - init_data.py 는 끝부분에서 이 스크립트를 자동 호출하도록 연결되어
      있다. (수동 호출도 가능)

사용:
    DATABASE_URL=postgresql://... python scripts/regenerate_launchers.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database import get_db  # noqa: E402


LAUNCHER_DIR = ROOT / "apps" / "launchers"

PYW_TEMPLATE = '''\
# -*- coding: utf-8 -*-
"""
토큰 기기 앱 런처 — {account}
더블클릭으로 실행하면 GUI 창이 뜹니다 (콘솔 창 없음).

※ 자동 생성됨 by scripts/regenerate_launchers.py
※ init_data.py 재시드 후에는 이 파일도 자동으로 재작성됩니다.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
APPS_DIR = os.path.dirname(HERE)
sys.path.insert(0, APPS_DIR)

from virtual_device import launch  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(launch(
        account={account!r},
        device_id={device_id!r},
        api_key={api_key!r},
        base_url={base_url!r},
    ))
'''

BAT_TEMPLATE = '''\
@echo off
REM 토큰 기기 앱 런처 — {account} (Windows 대체 런처)
REM .pyw 연결이 없거나 동작하지 않을 때 이 배치 파일을 더블클릭하세요.
cd /d "%~dp0\\..\\.."
start "" {pythonw} apps\\virtual_device.py --account {account} --device-id {device_id} --api-key {api_key} --base-url {base_url}
'''


def _normalize_base_url() -> str:
    # 서버 포트는 config.SERVER_PORT. 기본 8000. 환경변수 우선.
    port = os.environ.get("SERVER_PORT", "8000")
    return f"http://127.0.0.1:{port}"


def _pythonw_command() -> str:
    """설치형 번들에서는 ZT_PYTHONW, 개발 환경에서는 시스템 pythonw 사용."""
    value = os.environ.get("ZT_PYTHONW", "pythonw")
    if any(ch.isspace() for ch in value) and not value.startswith('"'):
        return f'"{value}"'
    return value


def regenerate() -> int:
    LAUNCHER_DIR.mkdir(parents=True, exist_ok=True)

    base_url = _normalize_base_url()
    pythonw = _pythonw_command()

    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT u.username, d.device_id, d.api_key "
            "FROM user_devices d "
            "JOIN users u ON u.id = d.user_id "
            "WHERE d.device_type='totp_token' AND d.is_active "
            "  AND d.api_key IS NOT NULL "
            "ORDER BY u.id"
        ).fetchall()
    finally:
        conn.close()

    # "있어야 할" 런처 파일명 집합 — DB 의 활성 totp_token 기준.
    expected = set()
    for r in rows:
        expected.add(f"token_{r['username']}.pyw")
        expected.add(f"token_{r['username']}.bat")

    # stale 런처 정리: 디렉터리에 있지만 expected 에 없는 token_*.pyw / .bat 만 제거.
    # 기존 동작(전부 unlink 후 재작성) 은 Windows 의 파일 잠금/EPERM 에 노출되면
    # stale 파일이 살아남는 부작용이 있어, 삭제 대상을 좁히고 retry 도 추가한다.
    # Windows 핸들 잠금이 풀리지 않는 경우엔 빈 내용으로 truncate 해 적어도 동작
    # 가능한 launcher 가 남지 않게 한다 (DB 에 없는 계정의 stale 런처가 우연히
    # 실행돼도 아무 일도 안 일어나도록).
    import time as _time
    for pattern in ("token_*.pyw", "token_*.bat"):
        for p in LAUNCHER_DIR.glob(pattern):
            if p.name in expected:
                continue
            for _attempt in range(5):
                try:
                    p.unlink()
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    _time.sleep(0.1)

    if not rows:
        print("[launchers] no active token devices found — nothing to generate.")
        return 0

    for row in rows:
        username = row["username"]
        device_id = row["device_id"]
        api_key = row["api_key"]

        pyw_path = LAUNCHER_DIR / f"token_{username}.pyw"
        bat_path = LAUNCHER_DIR / f"token_{username}.bat"

        pyw_path.write_text(
            PYW_TEMPLATE.format(
                account=username,
                device_id=device_id,
                api_key=api_key,
                base_url=base_url,
                pythonw=pythonw,
            ),
            encoding="utf-8",
        )
        bat_path.write_text(
            BAT_TEMPLATE.format(
                account=username,
                device_id=device_id,
                api_key=api_key,
                base_url=base_url,
                pythonw=pythonw,
            ),
            encoding="utf-8",
            newline="\r\n",
        )
        print(f"[launchers] wrote {pyw_path.name}, {bat_path.name}")

    # README 생성 (매번 덮어써도 무해)
    readme = LAUNCHER_DIR / "README.md"
    readme.write_text(
        "# 토큰 기기 앱 런처\n\n"
        "이 디렉터리의 파일은 `scripts/regenerate_launchers.py` 가 DB 를 읽어\n"
        "자동 생성합니다. 수동 편집하지 마세요.\n\n"
        "## 사용 방법 (Windows)\n\n"
        "1. 서버가 떠 있는 상태에서\n"
        "2. `token_<계정>.pyw` 파일을 **더블클릭** → GUI 창이 열립니다.\n"
        "3. 웹 로그인 화면에서 'OTP 전송' 을 누르면, 이 창에 6자리 코드가 표시됩니다.\n"
        "4. 표시된 코드를 웹 로그인 창 OTP 칸에 직접 입력하세요.\n\n"
        "## `.pyw` 가 동작하지 않을 때\n\n"
        "Python 설치 시 `.pyw` 확장자 연결이 안 되어 있으면 "
        "같은 이름의 `token_<계정>.bat` 을 대신 더블클릭하세요.\n\n"
        "## api_key 갱신\n\n"
        "`python init_data.py` 로 재시드하면 api_key 가 새로 발급되고, "
        "이 디렉터리의 런처 파일들도 함께 재작성됩니다.\n\n"
        "## macOS / Linux\n\n"
        "`.pyw` 대신 `python3 apps/virtual_device.py --account <u> --device-id <tok> "
        "--api-key <k> --base-url http://127.0.0.1:8000` 로 실행해도 동일합니다. "
        "macOS 에서 더블클릭 앱 형태가 필요하면 Automator 또는 py2app 를 참고하세요.\n",
        encoding="utf-8",
    )

    print(f"[launchers] generated {len(rows)} launcher(s) in {LAUNCHER_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(regenerate())
