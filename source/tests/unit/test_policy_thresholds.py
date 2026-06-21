"""
015 마이그레이션 — 임계값 외부화 회귀 테스트.

검증:
  1) 39개 시드 row 가 모두 존재 + default 값 일치
  2) policy_thresholds.get() 캐시 동작 (TTL, fallback, force_reload)
  3) 임계값을 DB 에서 변경하면 force_reload 후 scoring 결과가 바뀜
  4) DB row 가 없어도(`name` 미일치) default fallback 동작
  5) 기존 결정 매트릭스가 외부화 후에도 동일 매핑 (회귀 안전망)
"""
from __future__ import annotations

import pytest

from core import policy_thresholds as pt
from core import scoring_engine as se
from core import decision_engine as de


# ─── 1. 시드 row 검증 ────────────────────────────────────────────
class TestSeedValues:
    """015 마이그레이션이 보고서 §7-3 default 를 정확히 시드했는지."""

    def test_object_sensitivity_grades(self, db):
        # 캐시 초기화 — DB 직접 조회로 시드 검증
        for grade, expected in [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50)]:
            row = db.execute(
                "SELECT value FROM policy_thresholds WHERE name=?",
                (f"OBJECT_SENS_GRADE_{grade}",),
            ).fetchone()
            assert row is not None
            assert float(row["value"]) == expected

    def test_environment_keys(self, db):
        expected = {
            "ENV_RELAXED_TIME": 5, "ENV_NIGHT_TIME": 15,
            "ENV_UNREGISTERED_DEVICE": 20, "ENV_LONG_UNUSED_DEVICE": 10,
            "ENV_EXCEPTION_LOCATION": 10, "ENV_DISALLOWED_LOCATION": 20,
            "ENV_DEVICE_CHANGED": 10, "ENV_IMPOSSIBLE_TRAVEL": 15,
        }
        for name, value in expected.items():
            row = db.execute(
                "SELECT value FROM policy_thresholds WHERE name=?", (name,)
            ).fetchone()
            assert row is not None, f"{name} 시드 누락"
            assert float(row["value"]) == value, f"{name} default 어긋남"

    def test_fitness_negative_values(self, db):
        # 음수가 정확히 보존되었는지
        for name, expected in [
            ("FIT_ASSIGNED_CASE", -20), ("FIT_SAME_DEPARTMENT", -10),
            ("FIT_JURISDICTION", -5), ("FIT_JOB_RELEVANCE", -10),
            ("FIT_PRE_APPROVED", -15),
        ]:
            row = db.execute(
                "SELECT value FROM policy_thresholds WHERE name=?", (name,)
            ).fetchone()
            assert float(row["value"]) == expected

    def test_decision_bands(self, db):
        for name, expected in [
            ("DECISION_BAND_L1_MAX", 25), ("DECISION_BAND_L2_MAX", 50),
            ("DECISION_BAND_L3_MAX", 75), ("DECISION_BAND_L4_MAX", 90),
        ]:
            row = db.execute(
                "SELECT value FROM policy_thresholds WHERE name=?", (name,)
            ).fetchone()
            assert float(row["value"]) == expected

    def test_confidence_threshold(self, db):
        row = db.execute(
            "SELECT value FROM policy_thresholds WHERE name='CONFIDENCE_THRESHOLD'"
        ).fetchone()
        assert float(row["value"]) == 0.85

    def test_total_row_count(self, db):
        # 015 기본 36개 + 020 접근 튜닝 3개 = 39
        cnt = db.execute(
            "SELECT COUNT(*) AS c FROM policy_thresholds"
        ).fetchone()["c"]
        assert cnt == 39

    def test_access_tuning_thresholds(self, db):
        expected = {
            "BEH_UNAUTHORIZED_ACCESS": 10,
            "BEH_HIGH_SENS_UNASSIGNED": 5,
            "BEH_HIGH_FREQ_ACCESS_CRITICAL": 20,
        }
        for name, value in expected.items():
            row = db.execute(
                "SELECT value FROM policy_thresholds WHERE name=?", (name,)
            ).fetchone()
            assert row is not None, f"{name} 시드 누락"
            assert float(row["value"]) == value


# ─── 2. 캐시 동작 ─────────────────────────────────────────────────
class TestCacheBehavior:
    def test_get_returns_seed_value(self, db):
        pt.clear_cache()
        assert pt.get("ENV_NIGHT_TIME", 999) == 15

    def test_unknown_name_returns_default(self, db):
        pt.clear_cache()
        assert pt.get("NOT_A_REAL_KEY", 42.5) == 42.5

    def test_force_reload_picks_up_changes(self, db):
        """DB 에서 값 바꾸면 force_reload 후 즉시 적용."""
        pt.clear_cache()
        original = pt.get("ENV_NIGHT_TIME", 0)
        assert original == 15

        # DB 직접 변경 (운영자가 임계값 조정한 시나리오)
        db.execute(
            "UPDATE policy_thresholds SET value=99 WHERE name='ENV_NIGHT_TIME'"
        )
        db.commit()

        # 캐시는 아직 옛 값
        assert pt.get("ENV_NIGHT_TIME", 0) == 15

        # force_reload 후 새 값
        pt.force_reload()
        assert pt.get("ENV_NIGHT_TIME", 0) == 99

        # 원복 (다른 테스트 영향 방지) — reset_db 가 처리하지만 명시적 안전)
        db.execute(
            "UPDATE policy_thresholds SET value=15 WHERE name='ENV_NIGHT_TIME'"
        )
        db.commit()
        pt.force_reload()


# ─── 3. scoring 통합 ────────────────────────────────────────────
class TestScoringIntegration:
    """외부화 후에도 scoring 결과가 보고서 §7-3 default 와 일치해야 함."""

    def test_grade_5_internal_memo_matches_default(self, db):
        pt.clear_cache()
        result = se.score_object_sensitivity(5, "internal_memo")
        # 50 (등급) + 20 (internal_memo) = 70
        assert result["score"] == 70

    def test_environment_full_score(self, db):
        pt.clear_cache()
        result = se.score_environment_risk(
            device_registered=False,    # +20
            location_allowed=False,     # +20
            is_night=True,              # +15
            device_changed=True,        # +10
            impossible_travel=True,     # +15
        )
        # 20 + 20 + 15 + 10 + 15 = 80
        assert result["score"] == 80

    def test_fitness_assigned_full(self, db):
        pt.clear_cache()
        result = se.score_work_fitness(
            is_assigned_case=True,    # -20
            same_department=True,     # -10
            jurisdiction_match=True,  # -5
            pre_approved=True,        # -15
            job_relevance=True,       # -10
        )
        # -20 - 10 - 5 - 15 - 10 = -60
        assert result["score"] == -60


# ─── 4. 결정 경계 동적 적용 ─────────────────────────────────────
class TestDecisionBandDynamic:
    def test_default_bands_unchanged(self, db):
        pt.clear_cache()
        # 점수 30 → L2 (26~50)
        d = de.determine_access_level(30, sensitivity_grade=3, confidence=1.0)
        assert d["level"] == 2

    def test_band_change_via_db_takes_effect(self, db):
        """DECISION_BAND_L1_MAX 를 25 → 35 로 올리면, 점수 30 이 L1 으로 떨어짐."""
        pt.clear_cache()
        db.execute(
            "UPDATE policy_thresholds SET value=35 WHERE name='DECISION_BAND_L1_MAX'"
        )
        db.commit()
        pt.force_reload()

        d = de.determine_access_level(30, sensitivity_grade=3, confidence=1.0)
        assert d["level"] == 1, "L1 경계 35 까지 확장됐는데 30 이 L2 로 남음"

        # 원복
        db.execute(
            "UPDATE policy_thresholds SET value=25 WHERE name='DECISION_BAND_L1_MAX'"
        )
        db.commit()
        pt.force_reload()


# ─── 5. 전체 매트릭스 회귀 — 외부화 전후 동일성 ─────────────────
class TestMatrixRegressionAfterExternalization:
    """외부화 자체가 결정 매트릭스를 깨지 않았는지."""

    @pytest.mark.parametrize("ctx, expected_level_min, expected_level_max", [
        (
            {"resource_sensitivity": 1, "hour_of_day": 14,
             "device_trust": "corporate_mdm", "location_allowed": True,
             "is_assigned_case": True},
            1, 2
        ),
        (
            {"resource_sensitivity": 5, "hour_of_day": 2,
             "device_trust": "unknown", "location_allowed": False,
             "is_assigned_case": False},
            4, 5
        ),
        (
            {"resource_sensitivity": 3, "hour_of_day": 14,
             "device_trust": "corporate_mdm", "location_allowed": True,
             "is_assigned_case": True, "same_department": True,
             "jurisdiction_match": True, "job_relevance": True},
            1, 2
        ),
    ])
    def test_matrix_anchor_cases(self, db, ctx, expected_level_min, expected_level_max):
        """외부화 후 anchor 케이스가 같은 구간에 있어야 한다."""
        pt.clear_cache()
        scored = se.evaluate(ctx)
        decision = de.make({
            "risk_score": scored["risk_score"],
            "resource_sensitivity": ctx["resource_sensitivity"],
            "axes_values": list(scored["axes"].values()),
        })
        assert expected_level_min <= decision["level"] <= expected_level_max, (
            f"외부화 후 매트릭스 회귀: ctx={ctx}, level={decision['level']}, "
            f"기대 [{expected_level_min}, {expected_level_max}], "
            f"risk={scored['risk_score']}"
        )
