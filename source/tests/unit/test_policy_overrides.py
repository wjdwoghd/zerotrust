"""
016 마이그레이션 — 부서별 정책 multiplier 회귀 테스트.

검증:
  1) override 시드 row 정확히 입력
  2) 매칭 카테고리 사용자에게 multiplier 적용 (예: violent_crime 야간 0.5)
  3) 카테고리 미매칭이면 base 임계값 그대로
  4) 여러 카테고리 매칭 시 가장 작은 multiplier (사용자 유리한 쪽)
  5) score_environment_risk 가 user_categories 를 받아 결과에 반영
  6) audit 카테고리의 1.5 배 패널티 (긴축 방향) 도 정상
"""
from __future__ import annotations

from core import policy_thresholds as pt
from core import scoring_engine as se


class TestOverrideSeed:
    def test_violent_crime_night_half(self, db):
        row = db.execute(
            "SELECT multiplier FROM policy_overrides "
            "WHERE job_category=? AND threshold_name=?",
            ("violent_crime", "ENV_NIGHT_TIME"),
        ).fetchone()
        assert row is not None
        assert float(row["multiplier"]) == 0.5

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

    def test_violent_crime_user_gets_half(self, db):
        pt.clear_cache()
        # violent_crime job_scope → 0.5 * 15 = 7.5
        v = pt.get("ENV_NIGHT_TIME", 0, categories=["violent_crime"])
        assert v == 7.5

    def test_unmatched_category_keeps_base(self, db):
        pt.clear_cache()
        # 매칭 없는 카테고리 → base 그대로
        v = pt.get("ENV_NIGHT_TIME", 0, categories=["traffic"])
        assert v == 15

    def test_multiple_matches_use_smallest_multiplier(self, db):
        pt.clear_cache()
        # violent_crime(0.5) + organized_crime(0.5) → 0.5 (가장 관대)
        v = pt.get("ENV_NIGHT_TIME", 0,
                   categories=["violent_crime", "organized_crime"])
        assert v == 7.5

    def test_audit_category_amplifies(self, db):
        pt.clear_cache()
        # audit + ENV_LONG_UNUSED_DEVICE: base 10 * 1.5 = 15
        v = pt.get("ENV_LONG_UNUSED_DEVICE", 0, categories=["audit"])
        assert v == 15.0

    def test_get_multiplier_helper(self, db):
        pt.clear_cache()
        assert pt.get_multiplier("violent_crime", "ENV_NIGHT_TIME") == 0.5
        assert pt.get_multiplier("traffic", "ENV_NIGHT_TIME") is None


class TestScoringEngineIntegration:
    def test_violent_crime_user_night_half_penalty(self, db):
        """violent_crime 카테고리 사용자의 야간 환경 점수 = 절반."""
        pt.clear_cache()
        # 일반 사용자 (categories 없음)
        normal = se.score_environment_risk(
            device_registered=True, location_allowed=True, is_night=True,
        )
        # violent_crime 사용자
        violent = se.score_environment_risk(
            device_registered=True, location_allowed=True, is_night=True,
            user_categories=["violent_crime"],
        )
        assert normal["score"] == 15
        assert violent["score"] == 7.5
        assert violent["score"] < normal["score"]

    def test_evaluate_picks_up_job_scope_from_context(self, db):
        """evaluate(context) 가 context.job_scope 를 자동으로 multiplier 에 반영."""
        pt.clear_cache()
        # 일반 사용자 야간 접근: env=15
        normal = se.evaluate({
            "resource_sensitivity": 3, "hour_of_day": 2,
            "location_allowed": True, "device_trust": "corporate_mdm",
        })
        # violent_crime 카테고리 야간 접근: env=7.5
        with_job = se.evaluate({
            "resource_sensitivity": 3, "hour_of_day": 2,
            "location_allowed": True, "device_trust": "corporate_mdm",
            "job_scope": ["violent_crime"],
        })
        assert with_job["axes"]["environment"] < normal["axes"]["environment"]
        assert with_job["axes"]["environment"] == 7.5
        assert normal["axes"]["environment"] == 15
