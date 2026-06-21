#!/usr/bin/env python3
"""
토큰 기기 앱 .exe 빌드 도우미 (Windows 전용).

동작:
    1) apps/launchers/ 의 token_<계정>.pyw 파일 목록을 읽는다.
       (regenerate_launchers.py 가 먼저 돌아 있어야 함)
    2) 각 .pyw 를 PyInstaller 로 --onefile --noconsole 빌드한다.
    3) 산출물:
           dist/TokenDevice_<계정>.exe      (배포용 단일 파일)
       빌드 부산물(build/, *.spec)은 남아도 무해.

사용:
    # 1) 런처부터 재생성 (DB 의 최신 api_key 반영)
    python scripts\\regenerate_launchers.py

    # 2) PyInstaller 설치 (최초 1회)
    pip install pyinstaller

    # 3) .exe 4개 빌드
    python scripts\\build_exe_launchers.py

    # 4) dist\\TokenDevice_<계정>.exe 더블클릭

주의:
    - Windows 에서 실행해야 Windows .exe 가 나옵니다.
      Linux/macOS 에서 돌리면 해당 OS 용 실행파일이 생깁니다(크로스 빌드 불가).
    - init_data.py 재시드로 api_key 가 바뀌면 .exe 도 다시 빌드해야 합니다.
      (api_key 가 .pyw 소스에 박혀 있고, .exe 는 그 .pyw 스냅샷이기 때문)
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER_DIR = ROOT / "apps" / "launchers"
DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"


def _check_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(
            "[build] PyInstaller 가 설치되어 있지 않습니다.\n"
            "        먼저 다음 명령으로 설치하세요:\n"
            "            pip install pyinstaller",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _build_one(pyw_path: Path) -> int:
    """단일 .pyw 를 --onefile --noconsole 빌드."""
    account = pyw_path.stem.removeprefix("token_")
    exe_name = f"TokenDevice_{account}"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--noconsole",
        "--clean",
        "--name", exe_name,
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        "--specpath", str(BUILD_DIR),
        # apps/virtual_device.py 가 import 되므로 search path 에 추가
        "--paths", str(ROOT / "apps"),
        str(pyw_path),
    ]
    print(f"[build] → {exe_name}.exe  (source: {pyw_path.name})")
    result = subprocess.run(cmd, cwd=ROOT)
    return result.returncode


def main() -> int:
    _check_pyinstaller()

    if not LAUNCHER_DIR.exists():
        print(f"[build] {LAUNCHER_DIR} 가 없습니다. 먼저:", file=sys.stderr)
        print("        python scripts/regenerate_launchers.py", file=sys.stderr)
        return 1

    pyws = sorted(LAUNCHER_DIR.glob("token_*.pyw"))
    if not pyws:
        print(
            f"[build] {LAUNCHER_DIR} 에 token_*.pyw 가 없습니다.\n"
            "        먼저 regenerate_launchers.py 를 실행하세요.",
            file=sys.stderr,
        )
        return 1

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    failed = []
    for pyw in pyws:
        rc = _build_one(pyw)
        if rc != 0:
            failed.append(pyw.name)

    # 빌드 부산물 정리 (실패해도 무해)
    try:
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    except Exception:
        pass

    if failed:
        print(f"\n[build] 일부 빌드 실패: {failed}", file=sys.stderr)
        return 1

    print(f"\n[build] ✓ 완료. 산출물 위치: {DIST_DIR}")
    for pyw in pyws:
        account = pyw.stem.removeprefix("token_")
        exe = DIST_DIR / f"TokenDevice_{account}.exe"
        marker = "✓" if exe.exists() else "?"
        print(f"        {marker}  {exe.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
