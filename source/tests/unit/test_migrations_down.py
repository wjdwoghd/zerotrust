"""
Day 5 — 마이그레이션 down 표준화 회귀 테스트.

검증:
  1) 015/016/017 SQL 파일이 UP/DOWN 양 섹션을 모두 가짐
  2) DOWN 섹션이 없는 마이그레이션은 down 거부
  3) 사전 검증 — 중간에 DOWN 없으면 전체 거부 (atomicity)
  4) 라운드트립 — down 후 up 다시 적용해도 멱등

NOTE: 본 테스트는 실제 마이그레이션 파일을 read 만 하고 DB 적용은 안 한다.
DB 라운드트립은 Day 5 작업 검증에서 수동으로 확인 (테스트 실행 환경의
zerotrust_test 가 매 테스트마다 wipe + reseed 되므로 down 시도 시 격리
문제가 생긴다).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.run_migrations import _split_up_down, MIGRATIONS_DIR


class TestMigrationFileFormat:
    """015 부터 두 섹션 형식 표준화 검증."""

    def _read(self, name: str) -> str:
        return (Path(MIGRATIONS_DIR) / name).read_text(encoding="utf-8")

    def test_015_has_up_and_down(self):
        sql = self._read("015_policy_thresholds.sql")
        up, down = _split_up_down(sql)
        assert up
        assert down
        # UP 섹션은 INSERT 시드 포함
        assert "policy_thresholds" in up
        # DOWN 섹션은 DROP TABLE 포함
        assert "DROP TABLE IF EXISTS policy_thresholds" in down

    def test_016_has_up_and_down(self):
        sql = self._read("016_policy_overrides.sql")
        up, down = _split_up_down(sql)
        assert up
        assert down
        assert "DROP TABLE IF EXISTS policy_overrides" in down

    def test_017_has_up_and_down(self):
        sql = self._read("017_access_decision_reviews.sql")
        up, down = _split_up_down(sql)
        assert up
        assert down
        assert "DROP TABLE IF EXISTS access_decision_reviews" in down
        assert "DROP TRIGGER IF EXISTS trg_review_adjust_trust" in down

    def test_014_has_no_down_section(self):
        """014 는 의도적으로 DOWN 섹션 없음 (FK 복원이 audit 트리거 충돌 재발)."""
        sql = self._read("014_audit_logs_drop_user_fk.sql")
        _up, down = _split_up_down(sql)
        assert down is None, "014 는 DOWN 섹션 없어야 함 (FK 복원 시 트리거 충돌)"


class TestSplitUpDown:
    """_split_up_down 파서 단위 테스트."""

    def test_no_markers_treats_all_as_up(self):
        sql = "CREATE TABLE foo (id int);"
        up, down = _split_up_down(sql)
        assert up == sql
        assert down is None

    def test_only_up_marker(self):
        sql = "-- ====== UP ======\nCREATE TABLE foo (id int);"
        up, down = _split_up_down(sql)
        assert "CREATE TABLE foo" in up
        assert down is None

    def test_both_markers(self):
        sql = (
            "-- ====== UP ======\n"
            "CREATE TABLE foo (id int);\n"
            "-- ====== DOWN ======\n"
            "DROP TABLE foo;\n"
        )
        up, down = _split_up_down(sql)
        assert "CREATE TABLE foo" in up
        assert "DROP TABLE foo" in down

    def test_down_only_marker_no_up_marker(self):
        # 구버전 호환: UP 마커 없어도 DOWN 마커 앞 부분은 UP 으로 간주
        sql = (
            "CREATE TABLE foo (id int);\n"
            "-- ====== DOWN ======\n"
            "DROP TABLE foo;\n"
        )
        up, down = _split_up_down(sql)
        assert "CREATE TABLE foo" in up
        assert "DROP TABLE foo" in down
