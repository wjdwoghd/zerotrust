"""
데이터베이스 드라이버 (PostgreSQL 전용, L2-1)

본 모듈은 psycopg2 위에 얇은 래퍼를 두어 호출부가 `?` 플레이스홀더를
계속 사용할 수 있게 한다. (`?` → `%s` 자동 변환.)

스키마 관리:
  - DDL 은 `migrations/` 디렉터리 SQL 파일이 책임진다.
  - `scripts/run_migrations.py` 가 적용 이력(`schema_migrations`) 을
    추적하며 멱등성을 보장한다.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, List, Optional

import psycopg2
import psycopg2.extras

from config import DATABASE_URL


# ─── Placeholder 변환 ────────────────────────────────────────────
def _translate_placeholders(sql: str) -> tuple[str, int]:
    """
    `?` → `%s` 변환. ANSI SQL 문자열 리터럴(작은따옴표) 내부의 `?` 는 보존.

    예) ``SELECT 'what?' AS q WHERE id = ?`` →
        ``SELECT 'what?' AS q WHERE id = %s`` (count=1)
    """
    out: list[str] = []
    in_single = False
    count = 0
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if in_single:
            # '' 는 SQL 에서 이스케이프된 작은따옴표 — 리터럴 내부 유지
            if ch == "'" and i + 1 < n and sql[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        # 리터럴 바깥
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == "?":
            out.append("%s")
            count += 1
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), count


# ─── 얇은 Connection 래퍼 ────────────────────────────────────────
class _ConnectionWrapper:
    """
    psycopg2 connection 의 단순 어댑터.
      - execute(sql, params) — `?` → `%s` 자동 치환
      - fetchone/fetchall    — RealDictCursor 로 dict 반환
      - commit / rollback / close
    """

    def __init__(self, raw_conn):
        self._raw = raw_conn

    def execute(self, sql: str, params: Iterable = ()) -> "_CursorWrapper":
        translated, _ = _translate_placeholders(sql)
        cur = self._raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(translated, tuple(params))
        return _CursorWrapper(cur)

    def executemany(self, sql: str, seq_of_params: Iterable) -> None:
        translated, _ = _translate_placeholders(sql)
        cur = self._raw.cursor()
        cur.executemany(translated, seq_of_params)
        cur.close()

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    # 컨텍스트 매니저 지원
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.rollback()
        self.close()
        return False


class _CursorWrapper:
    """RealDictCursor 결과를 일관된 dict 인터페이스로 노출."""

    def __init__(self, raw_cursor):
        self._raw = raw_cursor

    def fetchone(self) -> Optional[dict]:
        row = self._raw.fetchone()
        if row is None:
            return None
        return dict(row)  # RealDictCursor 는 이미 dict-like

    def fetchall(self) -> List[dict]:
        return [dict(r) for r in self._raw.fetchall()]

    @property
    def lastrowid(self):
        # PostgreSQL 은 lastrowid 개념이 없다. id 가 필요하면 RETURNING id 사용.
        return None


# ─── 연결 헬퍼 ────────────────────────────────────────────────────
def get_db() -> _ConnectionWrapper:
    """
    호출부는 기존과 동일한 인터페이스(`conn.execute(sql, params).fetchone()`)로
    사용한다. placeholder 는 호출부에서 `?` 를 그대로 쓰면 자동 변환된다.
    """
    conn = psycopg2.connect(DATABASE_URL)
    return _ConnectionWrapper(conn)


# ─── 행(row) 변환 헬퍼 ────────────────────────────────────────────
# DB 에 JSON 문자열로 저장하는 컬럼들 — 읽을 때 dict/list 로 자동 역직렬화.
# (PG JSONB 는 psycopg2 가 이미 dict/list 로 디코딩해 주지만, 마이그레이션
#  중 TEXT 로 남아있는 잔여 컬럼이나 다른 경로로 들어온 문자열도 안전하게
#  처리하기 위해 동일 처리를 유지한다.)
_JSON_FIELDS = frozenset({
    "password_history",
    "registered_devices",
    "job_scope",
    "allowed_locations",
    "job_tags",
    "assigned_cases",
})


def row_to_dict(row):
    """row 를 dict 로 변환 + JSON 컬럼 역직렬화."""
    if row is None:
        return None
    d = dict(row)
    for key in _JSON_FIELDS:
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                d[key] = []
    return d


def rows_to_list(rows):
    """fetchall() 결과 리스트를 일괄 변환."""
    return [row_to_dict(r) for r in rows]
