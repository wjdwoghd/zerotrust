"""
016/023 마이그레이션 — 현재 시드 정책과 범용 multiplier 동작의 회귀 테스트.

검증:
  1) override 시드 row 정확히 입력
  2) 023 이후 수사 직무도 야간 기본 위험도 전부 적용
  3) 카테고리 미매칭이면 base 임계값 그대로
  4) 여러 카테고리 매칭 시 가장 작은 multiplier (사용자 유리한 쪽)
  5) score_environment_risk 가 user_categories 를 받아 결과에 반영
  6) audit 카테고리의 1.5 배 패널티 (긴축 방향) 도 정상
"""
from __future__ import annotations

import pytest

from core import policy_thresholds as pt
from core import scoring_engine as se


@pytest.fixture
def test_night_overrides(db):
    """테스트 전용 배율 행과 캐시를 정리해 같은 DB에서 재실행을 보장한다."""
    def cleanup():
        db.rollback()
        db.execute(
            "DELETE FROM policy_overrides WHERE threshold_name=? "
            "AND job_category IN (?, ?, ?)",
            ("ENV_NIGHT_TIME", "test_night_a", "test_night_b", "test_night_policy"),
        )
        db.commit()
        pt.clear_cache()

    cleanup()
    try:
        yield
    finally:
        cleanup()


class TestOverrideSeed:
    @pytest.mark.parametrize("category", ["violent_crime", "organized_crime", "national_security"])
    def test_night_seed_uses_full_risk(self, db, category):
        row = db.execute(
            "SELECT multiplier FROM policy_overrides "
            "WHERE job_category=? AND threshold_name=?",
            (category, "ENV_NIGHT_TIME"),
        ).fetchone()
        assert row is not None
        assert float(row["multiplier"]) == 1.0

    def test_audit_long_unused_strict(self, db):
        row = db.execute(
            "SELECT multiplier FROM policy_overrides "
            "WHERE job_category=? AND threshold_name=?",
            ("audit", "ENV_LONG_UNUSED_DEVICE"),
        ).fetchone()
        assert row is not None
        assert float(row["multiplier"]) == 1.5


class TestMultiplierApplication:
    def test_no_categories_returns_base(self, db):
        pt.clear_cache()
        # categories 없음 → base 15
        v = pt.get("ENV_NIGHT_TIME", 0)
        assert v == 15

    @pytest.mark.parametrize("category", ["violent_crime", "organized_crime", "national_security"])
    def test_night_category_keeps_full_risk(self, db, category):
        pt.clear_cache()
        # 023: 직무와 무관하게 1.0 * 15 = 15.
        v = pt.get("ENV_NIGHT_TIME", 0, categories=[category])
        assert v == 15

    def test_unmatched_category_keeps_base(self, db):
        pt.clear_cache()
        # 매칭 없는 카테고리 → base 그대로
        v = pt.get("ENV_NIGHT_TIME", 0, categories=["traffic"])
        assert v == 15

    def test_multiple_matches_use_smallest_multiplier(self, db, test_night_overrides):
        # 시드 정책을 바꾸지 않고 별도 테스트 범주로 범용 선택 규칙을 검증한다.
        db.executemany(
            "INSERT INTO policy_overrides (job_category, threshold_name, multiplier, reason) "
            "VALUES (?, 'ENV_NIGHT_TIME', ?, 'test only')",
            [("test_night_a", 0.8), ("test_night_b", 0.5)],
        )
        db.commit()
        pt.clear_cache()
        v = pt.get("ENV_NIGHT_TIME", 0,
                   categories=["test_night_a", "test_night_b"])
        assert v == 7.5

    def test_audit_category_amplifies(self, db):
        pt.clear_cache()
        # audit + ENV_LONG_UNUSED_DEVICE: base 10 * 1.5 = 15
        v = pt.get("ENV_LONG_UNUSED_DEVICE", 0, categories=["audit"])
        assert v == 15.0

    def test_get_multiplier_helper(self, db):
        pt.clear_cache()
        assert pt.get_multiplier("violent_crime", "ENV_NIGHT_TIME") == 1.0
        assert pt.get_multiplier("traffic", "ENV_NIGHT_TIME") is None


class TestScoringEngineIntegration:
    @pytest.mark.parametrize("category", ["violent_crime", "organized_crime", "national_security"])
    def test_night_penalty_is_full_for_all_seed_categories(self, db, category):
        """023 정책: 수사 직무도 야간 환경 점수는 기본 15점."""
        pt.clear_cache()
        # 일반 사용자 (categories 없음)
        normal = se.score_environment_risk(
            device_registered=True, location_allowed=True, is_night=True,
        )
        # 수사 직무 사용자
        violent = se.score_environment_risk(
            device_registered=True, location_allowed=True, is_night=True,
            user_categories=[category],
        )
        assert normal["score"] == 15
        assert violent["score"] == normal["score"]

    def test_evaluate_picks_up_job_scope_from_context(self, db, test_night_overrides):
        """evaluate(context) 가 context.job_scope 를 자동으로 multiplier 에 반영."""
        # 현재 시드의 야간 예외는 모두 1.0이므로 별도 범주로 전달 경로를 확인한다.
        db.execute(
            "INSERT INTO policy_overrides (job_category, threshold_name, multiplier, reason) "
            "VALUES ('test_night_policy', 'ENV_NIGHT_TIME', 0.5, 'test only')"
        )
        db.commit()
        pt.clear_cache()
        # 일반 사용자 야간 접근: env=15
        normal = se.evaluate({
            "resource_sensitivity": 3, "hour_of_day": 2,
            "location_allowed": True, "device_trust": "corporate_mdm",
        })
        # 테스트 범주 야간 접근: env=7.5
        with_job = se.evaluate({
            "resource_sensitivity": 3, "hour_of_day": 2,
            "location_allowed": True, "device_trust": "corporate_mdm",
            "job_scope": ["test_night_policy"],
        })
        assert with_job["axes"]["environment"] < normal["axes"]["environment"]
        assert with_job["axes"]["environment"] == 7.5
        assert normal["axes"]["environment"] == 15
