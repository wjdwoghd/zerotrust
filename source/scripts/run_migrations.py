#!/usr/bin/env python3
"""
마이그레이션 러너 (L2-2)

사용:
  DATABASE_URL=postgresql://... python scripts/run_migrations.py
  python scripts/run_migrations.py --down 1   # 마지막 1개 down
  python scripts/run_migrations.py --down 3   # 마지막 3개 down

동작:
  - up: migrations/ 디렉토리의 *.sql 파일을 파일명 순서대로 적용
  - down: schema_migrations 의 가장 최근 N 개를 역순으로 되돌림 (DOWN 섹션 필요)
  - 적용 이력은 schema_migrations 테이블에 기록해 중복 실행을 방지

SQL 파일 형식 (015 부터):
  -- ====== UP ======
  ...
  -- ====== DOWN ======
  ...

  DOWN 섹션이 없는 마이그레이션은 down 시 거부된다.
"""
from __future__ import annotations

import argparse
import os
import sys
import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from database import get_db  # noqa: E402


MIGRATIONS_DIR = ROOT / "migrations"
_UP_MARKER = "-- ====== UP ======"
_DOWN_MARKER = "-- ====== DOWN ======"


def _ensure_migration_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    conn.commit()


def _already_applied(conn, filename: str) -> bool:
    row = conn.execute(
        "SELECT filename FROM schema_migrations WHERE filename = ?",
        (filename,)
    ).fetchone()
    return row is not None


def _split_up_down(sql: str) -> tuple[str, str | None]:
    """SQL 파일을 UP / DOWN 섹션으로 분리.

    Returns (up_sql, down_sql or None).
    DOWN 섹션이 없으면 down_sql=None.
    UP 섹션 마커가 없으면 전체를 UP 으로 간주 (구버전 호환).
    """
    if _DOWN_MARKER not in sql:
        # DOWN 섹션 없음 — 전체 또는 UP 부분만 반환
        if _UP_MARKER in sql:
            up = sql.split(_UP_MARKER, 1)[1].strip()
        else:
            up = sql
        return up, None

    # DOWN 섹션 있음
    parts = sql.split(_DOWN_MARKER, 1)
    up_part = parts[0]
    down_part = parts[1].strip()

    if _UP_MARKER in up_part:
        up_sql = up_part.split(_UP_MARKER, 1)[1].strip()
    else:
        up_sql = up_part.strip()

    return up_sql, down_part


def _apply_sql(conn, sql: str) -> None:
    """raw psycopg2 연결로 SQL 한 번에 실행."""
    raw = conn._raw  # type: ignore
    try:
        raw.rollback()
    except Exception:
        pass
    raw.autocommit = False
    cur = raw.cursor()
    cur.execute(sql)
    raw.commit()
    cur.close()


def cmd_up() -> int:
    files = sorted(glob.glob(str(MIGRATIONS_DIR / "*.sql")))
    if not files:
        print("[migrations] no migration files found.", file=sys.stderr)
        return 0

    conn = get_db()
    try:
        _ensure_migration_table(conn)

        applied = 0
        for path in files:
            name = os.path.basename(path)

            if _already_applied(conn, name):
                print(f"[migrations] -- {name} already applied")
                continue

            with open(path, "r", encoding="utf-8") as f:
                raw_sql = f.read()
            up_sql, _down_sql = _split_up_down(raw_sql)

            print(f"[migrations] applying {name} …")
            try:
                _apply_sql(conn, up_sql)
            except Exception as e:
                print(f"[migrations] FAILED {name}: {e}", file=sys.stderr)
                conn.rollback()
                return 1

            conn.execute(
                "INSERT INTO schema_migrations (filename) VALUES (?)",
                (name,)
            )
            conn.commit()
            applied += 1

        print(f"[migrations] done. applied={applied}")
        return 0
    finally:
        conn.close()


def cmd_down(steps: int) -> int:
    """가장 최근 적용된 N 개 마이그레이션을 역순으로 down."""
    if steps < 1:
        print("[migrations] --down N (N >= 1) 필요", file=sys.stderr)
        return 2

    conn = get_db()
    try:
        _ensure_migration_table(conn)
        rows = conn.execute(
            "SELECT filename FROM schema_migrations "
            "ORDER BY applied_at DESC, filename DESC LIMIT ?",
            (steps,)
        ).fetchall()
        if not rows:
            print("[migrations] no applied migrations to roll back.")
            return 0

        # 1) 사전 검증 — 모든 N 개에 DOWN 섹션이 있는지 먼저 확인.
        #    중간에 DOWN 없는 게 있으면 "부분 down" 을 막기 위해 시작 전 거부.
        plan = []
        for r in rows:
            name = r["filename"]
            path = MIGRATIONS_DIR / name
            if not path.exists():
                print(f"[migrations] FAILED 사전 검증: {name} 파일 없음 — down 불가",
                      file=sys.stderr)
                return 1
            with open(path, "r", encoding="utf-8") as f:
                raw_sql = f.read()
            _up_sql, down_sql = _split_up_down(raw_sql)
            if not down_sql:
                print(f"[migrations] 사전 검증 실패: {name} 에 DOWN 섹션 없음 — "
                      f"전체 down 작업 거부 (부분 진행 방지)",
                      file=sys.stderr)
                return 1
            plan.append((name, down_sql))

        # 2) 검증 통과 — 순서대로 down
        rolled_back = 0
        for name, down_sql in plan:
            print(f"[migrations] reverting {name} …")
            try:
                _apply_sql(conn, down_sql)
            except Exception as e:
                print(f"[migrations] FAILED reverting {name}: {e}",
                      file=sys.stderr)
                conn.rollback()
                return 1

            conn.execute(
                "DELETE FROM schema_migrations WHERE filename=?", (name,)
            )
            conn.commit()
            rolled_back += 1

        print(f"[migrations] down done. reverted={rolled_back}")
        return 0
    finally:
        conn.close()


def main(argv=None) -> int:
    """마이그레이션 진입점.

    argv=None 이면 sys.argv 사용 (CLI 호출 시 기본). 코드에서 직접 호출 시
    빈 리스트 [] 또는 ['--down', '1'] 형태로 명시 전달 (pytest 등이 자기
    sys.argv 로 오염시키지 않도록).
    """
    parser = argparse.ArgumentParser(description="마이그레이션 러너")
    parser.add_argument(
        "--down", type=int, default=0,
        help="N: 마지막 N 개 마이그레이션을 역순으로 되돌림"
    )
    args = parser.parse_args(argv)

    if args.down > 0:
        return cmd_down(args.down)
    return cmd_up()


if __name__ == "__main__":
    raise SystemExit(main())
